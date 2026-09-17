//! Tenant offboarding at scale (decision v3.6).
//!
//! When a customer leaves, their evidence must be either verifiably deleted or handed over as a
//! self-contained, still-verifiable archive, with a certificate of what was destroyed, and with no
//! impact to any other tenant (isolation is enforced by the store, see acp-pgstore FORCE RLS). This
//! produces the offboarding manifest (the final verifiable snapshot the departing customer keeps)
//! and a deterministic certificate of destruction.

use crate::canonical::sha256_hex_bytes;

/// The final verifiable state handed to (or destroyed for) a departing tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffboardingManifest {
    pub tenant: String,
    /// Hex of the final signed-tree-head root: proves the exact evidence set at handover.
    pub final_root_hex: String,
    pub record_count: u64,
    pub closed_ms: u64,
}

impl OffboardingManifest {
    pub fn new(tenant: &str, final_root: &[u8; 32], record_count: u64, closed_ms: u64) -> Self {
        OffboardingManifest {
            tenant: tenant.to_string(),
            final_root_hex: hex::encode(final_root),
            record_count,
            closed_ms,
        }
    }

    /// A certificate of destruction: a content hash over the manifest, so the customer holds a
    /// tamper-evident record of exactly what evidence set was destroyed or handed over.
    pub fn certificate_of_destruction(&self) -> String {
        let payload = format!(
            "{}|{}|{}|{}",
            self.tenant, self.final_root_hex, self.record_count, self.closed_ms
        );
        format!("cod:{}", sha256_hex_bytes(payload.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_captures_the_final_verifiable_state() {
        let m = OffboardingManifest::new("acme", &[7u8; 32], 12345, 1_700);
        assert_eq!(m.record_count, 12345);
        assert!(m.final_root_hex.starts_with("0707"));
    }

    #[test]
    fn the_destruction_certificate_is_deterministic_and_tenant_specific() {
        let a = OffboardingManifest::new("acme", &[7u8; 32], 10, 1).certificate_of_destruction();
        let a2 = OffboardingManifest::new("acme", &[7u8; 32], 10, 1).certificate_of_destruction();
        let b = OffboardingManifest::new("globex", &[7u8; 32], 10, 1).certificate_of_destruction();
        assert_eq!(a, a2, "same offboarding -> same certificate");
        assert_ne!(a, b, "different tenant -> different certificate");
    }
}
