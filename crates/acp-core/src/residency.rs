//! Multi-region data residency (decision H2.2).
//!
//! A tenant with a residency requirement (EU data stays in the EU) must have its evidence placed
//! only in permitted regions, and a misconfigured placement must be refused, not silently accepted.
//! This is the residency policy the placement path consults: default-deny, so a region that was not
//! explicitly allowed for a tenant is rejected.

use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Default)]
pub struct ResidencyPolicy {
    allowed: HashMap<String, BTreeSet<String>>,
}

impl ResidencyPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(&mut self, tenant: &str, region: &str) {
        self.allowed
            .entry(tenant.to_string())
            .or_default()
            .insert(region.to_string());
    }

    /// Whether a tenant's data may be placed in a region. Default-deny: an un-configured tenant or
    /// a region not on its allowlist is refused.
    pub fn placement_ok(&self, tenant: &str, region: &str) -> bool {
        self.allowed
            .get(tenant)
            .map(|s| s.contains(region))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_is_restricted_to_allowed_regions() {
        let mut p = ResidencyPolicy::new();
        p.allow("eu-bank", "eu-west-1");
        p.allow("eu-bank", "eu-central-1");
        assert!(p.placement_ok("eu-bank", "eu-west-1"));
        assert!(
            !p.placement_ok("eu-bank", "us-east-1"),
            "out-of-region placement refused"
        );
        assert!(
            !p.placement_ok("unknown-tenant", "eu-west-1"),
            "default-deny for un-configured tenant"
        );
    }
}
