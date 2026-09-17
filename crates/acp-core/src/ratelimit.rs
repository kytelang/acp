//! Token-bucket rate limiting and per-tenant quotas (decision H1.1 / F10).
//!
//! The public API and the proxy dial path need per-tenant rate limits so one noisy tenant cannot
//! starve the control plane (noisy-neighbour protection) and so a burst backs off cleanly. This is
//! a standard token bucket: it refills at a steady rate up to a capacity, and each request consumes
//! a token. Pure and time-injected so the limiter is deterministic under test.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_ms: f64,
    last_ms: u64,
}

impl TokenBucket {
    /// `capacity` tokens, refilling `rate_per_sec` tokens per second.
    pub fn new(capacity: f64, rate_per_sec: f64, now_ms: u64) -> Self {
        TokenBucket {
            capacity,
            tokens: capacity,
            refill_per_ms: rate_per_sec / 1000.0,
            last_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_ms) as f64;
        self.tokens = (self.tokens + elapsed * self.refill_per_ms).min(self.capacity);
        self.last_ms = now_ms;
    }

    /// Try to consume one token. True = allowed, false = rate-limited (caller returns retry-after).
    pub fn allow(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-tenant limiter: each tenant gets its own bucket, so one tenant's burst does not affect
/// another (noisy-neighbour isolation).
#[derive(Debug)]
pub struct TenantLimiter {
    capacity: f64,
    rate_per_sec: f64,
    buckets: HashMap<String, TokenBucket>,
}

impl TenantLimiter {
    pub fn new(capacity: f64, rate_per_sec: f64) -> Self {
        TenantLimiter {
            capacity,
            rate_per_sec,
            buckets: HashMap::new(),
        }
    }

    pub fn allow(&mut self, tenant: &str, now_ms: u64) -> bool {
        let cap = self.capacity;
        let rate = self.rate_per_sec;
        self.buckets
            .entry(tenant.to_string())
            .or_insert_with(|| TokenBucket::new(cap, rate, now_ms))
            .allow(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_capped_then_refills_over_time() {
        let mut b = TokenBucket::new(3.0, 10.0, 0); // 3 tokens, 10/sec
        assert!(
            b.allow(0) && b.allow(0) && b.allow(0),
            "3 immediate requests fit the capacity"
        );
        assert!(!b.allow(0), "the 4th in the same instant is limited");
        // 10/sec = 1 token per 100ms; after 100ms one request is allowed again.
        assert!(b.allow(100), "refilled after 100ms");
        assert!(!b.allow(100), "but only one");
    }

    #[test]
    fn tenants_are_isolated_from_each_others_bursts() {
        let mut l = TenantLimiter::new(2.0, 1.0);
        assert!(l.allow("acme", 0) && l.allow("acme", 0));
        assert!(!l.allow("acme", 0), "acme is now limited");
        // globex is unaffected by acme exhausting its bucket.
        assert!(l.allow("globex", 0) && l.allow("globex", 0));
    }
}
