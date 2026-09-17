//! Usage metering that never reads customer arguments (decision X.3).
//!
//! Billing must not become a side channel into customer data, and quota must never become a
//! way to silently switch the gate off. This meter counts a billable unit per decision using
//! only non-sensitive fields (tenant, tool name, verdict) and is safe-by-default on overage:
//! over quota it flags for billing but the caller keeps gating. It never reads args.

use std::collections::HashMap;

/// What the caller should do once a tenant is over quota. Gating continues in every case; the
/// only choice is billing posture, never enforcement posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overage {
    /// Under quota: bill normally.
    WithinQuota,
    /// Over quota: meter and bill the overage, but keep gating (safe default).
    BillOverage,
}

#[derive(Debug, Default, Clone)]
pub struct TenantUsage {
    pub decisions: u64,
}

/// Per-tenant billable-unit counter. One decision equals one unit; arguments are never touched.
#[derive(Debug, Default)]
pub struct Meter {
    usage: HashMap<String, TenantUsage>,
    quota: HashMap<String, u64>,
}

impl Meter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_quota(&mut self, tenant: &str, units: u64) {
        self.quota.insert(tenant.to_string(), units);
    }

    /// Count one decision for a tenant. `tool` and `verdict` are accepted only to make the call
    /// site explicit that no argument payload is required; they are not stored.
    pub fn meter(&mut self, tenant: &str, _tool: &str, _verdict: &str) -> Overage {
        let u = self.usage.entry(tenant.to_string()).or_default();
        u.decisions += 1;
        let count = u.decisions;
        match self.quota.get(tenant) {
            Some(&q) if count > q => Overage::BillOverage,
            _ => Overage::WithinQuota,
        }
    }

    pub fn usage(&self, tenant: &str) -> TenantUsage {
        self.usage.get(tenant).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_one_unit_per_decision() {
        let mut m = Meter::new();
        m.meter("acme", "fs.write", "deny");
        m.meter("acme", "http.post", "allow");
        assert_eq!(m.usage("acme").decisions, 2);
    }

    #[test]
    fn overage_is_billed_but_never_stops_gating() {
        let mut m = Meter::new();
        m.set_quota("acme", 2);
        assert_eq!(m.meter("acme", "t", "allow"), Overage::WithinQuota);
        assert_eq!(m.meter("acme", "t", "allow"), Overage::WithinQuota);
        // Third call is over quota: the meter flags overage, but the API returns a value the
        // caller uses only for billing. There is no variant that says "stop gating".
        assert_eq!(m.meter("acme", "t", "allow"), Overage::BillOverage);
        assert_eq!(m.usage("acme").decisions, 3, "still counted, still gated");
    }
}
