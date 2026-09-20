//! Shadow-AI enrollment loop (gap-closure, section 4).
//!
//! `discovery.rs` classifies ungoverned endpoints but ends at a list. This closes the loop: every
//! discovered endpoint gets an explicit, signed disposition, so an ungoverned path is a deliberate,
//! recorded decision rather than an oversight. Dispositions feed two things: the governed set the
//! coverage report joins against, and an allowlist/blocklist ACP hands to the org's MDM or CASB to
//! enforce on the device (ACP is the policy and evidence authority; the endpoint tools are the reach).

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

/// What an operator decided about a discovered endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "kebab-case")]
pub enum Disposition {
    /// Register and route through ACP: now counts as governed.
    Enroll,
    /// Add to the network deny list until reviewed.
    Quarantine,
    /// A deliberate, expiring exception: an ungoverned path accepted on the record.
    AcceptRisk { expires_ms: u64 },
}

/// One signed disposition over a discovered endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointDisposition {
    pub endpoint: String,
    pub kind: String,
    pub disposition: Disposition,
    pub operator: String,
    pub reason: String,
    pub decided_ms: u64,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

fn signing_value(
    endpoint: &str,
    kind: &str,
    disposition: &Disposition,
    operator: &str,
    reason: &str,
    decided_ms: u64,
) -> serde_json::Value {
    json!({
        "endpoint": endpoint,
        "kind": kind,
        "disposition": disposition,
        "operator": operator,
        "reason": reason,
        "decided_ms": decided_ms,
    })
}

impl EndpointDisposition {
    /// Verify this disposition's signature under its embedded public key. Fail-closed on decode error.
    pub fn verify(&self) -> bool {
        let pk = match hex::decode(&self.pubkey_hex) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let sig = match hex::decode(&self.sig_hex) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let bytes = crate::canonical::canonical_bytes(&signing_value(
            &self.endpoint,
            &self.kind,
            &self.disposition,
            &self.operator,
            &self.reason,
            self.decided_ms,
        ));
        verify_ed25519(&pk, &bytes, &sig)
    }

    fn is_active(&self, now_ms: u64) -> bool {
        match self.disposition {
            Disposition::AcceptRisk { expires_ms } => now_ms < expires_ms,
            _ => true,
        }
    }
}

/// The append-only log of endpoint dispositions. The latest signed disposition per endpoint wins.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnrollmentLog {
    pub dispositions: Vec<EndpointDisposition>,
}

impl EnrollmentLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a signed disposition. The signature covers the decision fields, so it cannot be
    /// altered after the fact without detection.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        signer: &dyn Signer,
        endpoint: &str,
        kind: &str,
        disposition: Disposition,
        operator: &str,
        reason: &str,
        decided_ms: u64,
    ) -> &EndpointDisposition {
        let bytes = crate::canonical::canonical_bytes(&signing_value(
            endpoint,
            kind,
            &disposition,
            operator,
            reason,
            decided_ms,
        ));
        let sig = signer.sign(&bytes);
        self.dispositions.push(EndpointDisposition {
            endpoint: endpoint.to_string(),
            kind: kind.to_string(),
            disposition,
            operator: operator.to_string(),
            reason: reason.to_string(),
            decided_ms,
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        });
        self.dispositions.last().unwrap()
    }

    /// The latest disposition for each endpoint (append-only, last write wins).
    fn latest(&self) -> Vec<&EndpointDisposition> {
        let mut by_ep: std::collections::BTreeMap<&str, &EndpointDisposition> =
            std::collections::BTreeMap::new();
        for d in &self.dispositions {
            match by_ep.get(d.endpoint.as_str()) {
                Some(existing) if existing.decided_ms >= d.decided_ms => {}
                _ => {
                    by_ep.insert(&d.endpoint, d);
                }
            }
        }
        by_ep.into_values().collect()
    }

    /// The governed set (enrolled endpoints), for the coverage report to join against.
    pub fn governed(&self) -> BTreeSet<String> {
        self.latest()
            .into_iter()
            .filter(|d| matches!(d.disposition, Disposition::Enroll))
            .map(|d| d.endpoint.clone())
            .collect()
    }

    /// The blocklist (quarantined endpoints), for MDM/CASB to enforce.
    pub fn blocklist(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .latest()
            .into_iter()
            .filter(|d| matches!(d.disposition, Disposition::Quarantine))
            .map(|d| d.endpoint.clone())
            .collect();
        v.sort();
        v
    }

    /// Accepted-risk exceptions still in force at `now_ms`.
    pub fn active_exceptions(&self, now_ms: u64) -> Vec<&EndpointDisposition> {
        self.latest()
            .into_iter()
            .filter(|d| matches!(d.disposition, Disposition::AcceptRisk { .. }) && d.is_active(now_ms))
            .collect()
    }

    /// Export the allowlist/blocklist artifact ACP hands to an MDM or CASB.
    pub fn export_mdm(&self, now_ms: u64) -> serde_json::Value {
        let allow: Vec<String> = self.governed().into_iter().collect();
        let block = self.blocklist();
        let exceptions: Vec<serde_json::Value> = self
            .active_exceptions(now_ms)
            .into_iter()
            .map(|d| json!({"endpoint": d.endpoint, "operator": d.operator, "reason": d.reason}))
            .collect();
        json!({
            "generated_ms": now_ms,
            "allow": allow,
            "block": block,
            "accepted_risk": exceptions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    #[test]
    fn dispositions_are_signed_and_verify() {
        let s = Ed25519Signer::generate();
        let mut log = EnrollmentLog::new();
        let d = log
            .record(&s, "api.openai.com", "model-api", Disposition::Enroll, "alice", "sanctioned", 1000)
            .clone();
        assert!(d.verify());
        let mut bad = d.clone();
        bad.operator = "mallory".into();
        assert!(!bad.verify(), "tampered operator must not verify");
    }

    #[test]
    fn governed_and_blocklist_reflect_latest_disposition() {
        let s = Ed25519Signer::generate();
        let mut log = EnrollmentLog::new();
        log.record(&s, "api.openai.com", "model-api", Disposition::Enroll, "a", "", 1000);
        log.record(&s, "evil.example/mcp", "mcp", Disposition::Quarantine, "a", "shadow", 1000);
        // later, the enrolled one is quarantined instead
        log.record(&s, "api.openai.com", "model-api", Disposition::Quarantine, "a", "revoked", 2000);
        assert!(log.governed().is_empty());
        assert_eq!(log.blocklist(), vec!["api.openai.com".to_string(), "evil.example/mcp".to_string()]);
    }

    #[test]
    fn accept_risk_expires() {
        let s = Ed25519Signer::generate();
        let mut log = EnrollmentLog::new();
        log.record(&s, "x/mcp", "mcp", Disposition::AcceptRisk { expires_ms: 5000 }, "a", "temp", 1000);
        assert_eq!(log.active_exceptions(3000).len(), 1);
        assert_eq!(log.active_exceptions(6000).len(), 0);
    }

    #[test]
    fn mdm_export_has_allow_and_block() {
        let s = Ed25519Signer::generate();
        let mut log = EnrollmentLog::new();
        log.record(&s, "api.openai.com", "model-api", Disposition::Enroll, "a", "", 1000);
        log.record(&s, "evil/mcp", "mcp", Disposition::Quarantine, "a", "", 1000);
        let mdm = log.export_mdm(2000);
        assert_eq!(mdm["allow"].as_array().unwrap().len(), 1);
        assert_eq!(mdm["block"].as_array().unwrap().len(), 1);
    }
}
