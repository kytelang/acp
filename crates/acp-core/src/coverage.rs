//! Coverage attestation: is anything talking to a model or a tool without going through ACP?
//! (gap-closure, containment plane).
//!
//! `posture.rs` gates the flip to default-deny on a coverage float, but nothing computes that float.
//! This module computes it, by cross-referencing what is observed (the discovery inventory of every
//! known model-API and MCP endpoint) against what is governed (the set of endpoints actually routed
//! through ACP), and lists the ungoverned or leaky paths explicitly. The result is a report that can
//! be signed and written to the ledger, so the enforcement posture over time is itself evidence.
//!
//! Pure: the caller gathers the inputs (discovery output, the enrolled/governed set, and any leaky
//! signals such as a fail-open gateway) and this joins them. No sockets, no files.

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One observed endpoint and whether it is under ACP enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointStatus {
    pub endpoint: String,
    pub kind: String,
    pub governed: bool,
    pub reason: String,
}

/// The coverage of the AI estate at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub generated_ms: u64,
    pub total: usize,
    pub governed: usize,
    /// governed / total, in [0.0, 1.0]. 1.0 when there are no observed endpoints.
    pub coverage_pct: u32,
    /// Every observed endpoint with its status, sorted for a stable, signable document.
    pub endpoints: Vec<EndpointStatus>,
    /// Non-endpoint containment weaknesses, e.g. a gateway running with --fail-open, or a tool
    /// server reachable without the guard. These do not lower coverage_pct but must be surfaced.
    pub leaky: Vec<String>,
}

/// A signed coverage report: the report plus the signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCoverage {
    pub report: CoverageReport,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

/// Compute coverage. `observed` is (endpoint, kind) pairs (typically from discovery); `governed` is
/// the set of endpoints routed through ACP (typically the enrolled set). `leaky` carries containment
/// weaknesses the caller detected. `now_ms` stamps the report.
pub fn compute(
    observed: &[(String, String)],
    governed: &BTreeSet<String>,
    leaky: Vec<String>,
    now_ms: u64,
) -> CoverageReport {
    // De-duplicate observed endpoints, keeping the first-seen kind, for a stable count.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut endpoints: Vec<EndpointStatus> = Vec::new();
    for (ep, kind) in observed {
        if !seen.insert(ep.clone()) {
            continue;
        }
        let is_gov = governed.contains(ep);
        endpoints.push(EndpointStatus {
            endpoint: ep.clone(),
            kind: kind.clone(),
            governed: is_gov,
            reason: if is_gov {
                "routed through ACP".into()
            } else {
                "no ACP route (ungoverned)".into()
            },
        });
    }
    endpoints.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
    let total = endpoints.len();
    let governed_n = endpoints.iter().filter(|e| e.governed).count();
    let coverage_pct = if total == 0 {
        100
    } else {
        ((governed_n as f64 / total as f64) * 100.0).round() as u32
    };
    let mut leaky = leaky;
    leaky.sort();
    leaky.dedup();
    CoverageReport {
        generated_ms: now_ms,
        total,
        governed: governed_n,
        coverage_pct,
        endpoints,
        leaky,
    }
}

impl CoverageReport {
    /// The endpoints not under ACP enforcement (the worklist to enroll or quarantine).
    pub fn ungoverned(&self) -> Vec<&EndpointStatus> {
        self.endpoints.iter().filter(|e| !e.governed).collect()
    }

    /// True when every observed endpoint is governed and there are no leaky signals.
    pub fn fully_contained(&self) -> bool {
        self.coverage_pct == 100 && self.leaky.is_empty()
    }

    /// Sign the report under the given key, producing a verifiable coverage attestation.
    pub fn sign(self, signer: &dyn Signer) -> SignedCoverage {
        let bytes = crate::canonical::canonical_bytes(&self);
        let sig = signer.sign(&bytes);
        SignedCoverage {
            report: self,
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

/// Verify a signed coverage report: recompute the canonical bytes of the report and check the
/// signature under the embedded public key. Fail-closed on any decode error.
pub fn verify(signed: &SignedCoverage) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bytes = crate::canonical::canonical_bytes(&signed.report);
    verify_ed25519(&pk, &bytes, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    fn obs() -> Vec<(String, String)> {
        vec![
            ("api.openai.com".into(), "model-api".into()),
            ("api.anthropic.com".into(), "model-api".into()),
            ("mcp.internal/tools".into(), "mcp".into()),
        ]
    }

    #[test]
    fn coverage_counts_governed_over_total() {
        let mut gov = BTreeSet::new();
        gov.insert("api.openai.com".to_string());
        gov.insert("api.anthropic.com".to_string());
        let r = compute(&obs(), &gov, vec![], 1000);
        assert_eq!(r.total, 3);
        assert_eq!(r.governed, 2);
        assert_eq!(r.coverage_pct, 67);
        assert_eq!(r.ungoverned().len(), 1);
        assert_eq!(r.ungoverned()[0].endpoint, "mcp.internal/tools");
        assert!(!r.fully_contained());
    }

    #[test]
    fn full_coverage_with_no_leaks_is_contained() {
        let gov: BTreeSet<String> = obs().into_iter().map(|(e, _)| e).collect();
        let r = compute(&obs(), &gov, vec![], 1000);
        assert_eq!(r.coverage_pct, 100);
        assert!(r.fully_contained());
    }

    #[test]
    fn leaky_signals_break_containment_without_lowering_pct() {
        let gov: BTreeSet<String> = obs().into_iter().map(|(e, _)| e).collect();
        let r = compute(&obs(), &gov, vec!["gateway running --fail-open".into()], 1000);
        assert_eq!(r.coverage_pct, 100);
        assert!(!r.fully_contained());
        assert_eq!(r.leaky.len(), 1);
    }

    #[test]
    fn empty_estate_is_fully_covered() {
        let r = compute(&[], &BTreeSet::new(), vec![], 1000);
        assert_eq!(r.coverage_pct, 100);
        assert!(r.fully_contained());
    }

    #[test]
    fn a_signed_report_verifies_and_tamper_is_caught() {
        let gov: BTreeSet<String> = obs().into_iter().map(|(e, _)| e).collect();
        let signed = compute(&obs(), &gov, vec![], 1000).sign(&Ed25519Signer::generate());
        assert!(verify(&signed));
        let mut bad = signed.clone();
        bad.report.coverage_pct = 100; // was already 100; change something material instead
        bad.report.governed = 999;
        assert!(!verify(&bad), "tampered report must not verify");
    }
}
