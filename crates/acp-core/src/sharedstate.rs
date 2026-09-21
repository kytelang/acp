//! Shared state for budgets and tool-integrity pins across PEP instances (pending.md P1 #3, the code
//! half of production hardening; see docs/design/p2-operations.md).
//!
//! Each gateway or proxy keeps rate-limit budgets and tool pins in process, which splits them when
//! several replicas run. These traits let the same logic run against a shared store instead. The
//! in-process implementations here are the single-instance default and the test double; a Redis or
//! Postgres implementation of the same traits is the deployment step (keyed `budget:{app}:{resource}`
//! and `pin:{server}:{tool}`, with the check-and-decrement done atomically, e.g. a Lua script).

use crate::ratelimit::TokenBucket;
use crate::toolintegrity::PinResult;
use std::collections::HashMap;
use std::sync::Mutex;

/// A rate-limit / cost budget store. `allow` consumes one unit for `key` and returns whether it was
/// within budget, refilling by elapsed time. Interior mutability so it can sit behind an Arc.
pub trait BudgetStore: Send + Sync {
    fn allow(&self, key: &str, capacity: f64, rate_per_sec: f64, now_ms: u64) -> bool;
}

/// A tool-integrity pin store. `check_and_pin` pins a fingerprint on first sight and reports whether
/// a later fingerprint is unchanged or changed (rug-pull / poisoning).
pub trait PinStore: Send + Sync {
    fn check_and_pin(&self, key: &str, fingerprint: &str) -> PinResult;
}

/// In-process budget store (the single-instance default). Backed by per-key token buckets.
#[derive(Default)]
pub struct MemBudgetStore {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl MemBudgetStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BudgetStore for MemBudgetStore {
    fn allow(&self, key: &str, capacity: f64, rate_per_sec: f64, now_ms: u64) -> bool {
        let mut m = self.buckets.lock().unwrap();
        let b = m
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, rate_per_sec, now_ms));
        b.allow(now_ms)
    }
}

/// In-process pin store (the single-instance default).
#[derive(Default)]
pub struct MemPinStore {
    pins: Mutex<HashMap<String, String>>,
}

impl MemPinStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PinStore for MemPinStore {
    fn check_and_pin(&self, key: &str, fingerprint: &str) -> PinResult {
        let mut m = self.pins.lock().unwrap();
        match m.get(key) {
            None => {
                m.insert(key.to_string(), fingerprint.to_string());
                PinResult::New
            }
            Some(p) if p == fingerprint => PinResult::Unchanged,
            Some(_) => PinResult::Changed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_allows_up_to_capacity_then_denies_then_refills() {
        let s = MemBudgetStore::new();
        // capacity 2, refill 1 per second.
        assert!(s.allow("budget:app:db", 2.0, 1.0, 0));
        assert!(s.allow("budget:app:db", 2.0, 1.0, 0));
        assert!(!s.allow("budget:app:db", 2.0, 1.0, 0), "capacity exhausted");
        // after 1s, one token refilled.
        assert!(s.allow("budget:app:db", 2.0, 1.0, 1000));
    }

    #[test]
    fn budgets_are_isolated_by_key() {
        let s = MemBudgetStore::new();
        assert!(s.allow("budget:a:x", 1.0, 1.0, 0));
        assert!(!s.allow("budget:a:x", 1.0, 1.0, 0));
        assert!(s.allow("budget:b:x", 1.0, 1.0, 0), "different key has its own budget");
    }

    #[test]
    fn pin_reports_new_unchanged_changed() {
        let s = MemPinStore::new();
        assert_eq!(s.check_and_pin("pin:srv:tool", "fp1"), PinResult::New);
        assert_eq!(s.check_and_pin("pin:srv:tool", "fp1"), PinResult::Unchanged);
        assert_eq!(s.check_and_pin("pin:srv:tool", "fp2"), PinResult::Changed);
    }
}
