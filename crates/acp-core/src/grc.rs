//! GRC / IRM control-evidence export (decision F6).
//!
//! A GRC platform (ServiceNow IRM, Archer, OneTrust) wants to pull per-control evidence with stable
//! ids, and a re-pull must be idempotent: the same underlying decisions must always map to the same
//! control-evidence ids, so the platform does not see duplicates. This maps decision records to the
//! controls they evidence and emits a deterministic, stably-identified evidence set.

use crate::canonical::sha256_hex;
use std::collections::BTreeMap;

/// A decision distilled to what a control mapping needs (no argument payload).
#[derive(Debug, Clone)]
pub struct DecisionRef {
    pub decision_id: String,
    pub tool: String,
    pub verdict: String,
    pub rule_id: Option<String>,
}

/// One piece of control evidence with a stable id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEvidence {
    pub evidence_id: String,
    pub control_id: String,
    pub decision_id: String,
}

/// Map a decision to the controls it evidences. In production this is a configured mapping; here a
/// small default demonstrates the shape: enforced denies/step-ups evidence access-control controls.
fn controls_for(d: &DecisionRef) -> Vec<&'static str> {
    match d.verdict.as_str() {
        "deny" | "step_up" => vec!["AC-3", "AU-2"], // access enforcement + auditable event
        "allow" | "shadow" => vec!["AU-2"],
        _ => vec![],
    }
}

/// Produce the control-evidence set for a batch of decisions. The evidence id is a content hash of
/// (control_id, decision_id), so re-pulling the same decisions yields identical ids (idempotent).
pub fn export_evidence(decisions: &[DecisionRef]) -> Vec<ControlEvidence> {
    let mut seen: BTreeMap<String, ControlEvidence> = BTreeMap::new();
    for d in decisions {
        for control in controls_for(d) {
            let evidence_id = sha256_hex(&format!("{control}|{}", d.decision_id));
            seen.entry(evidence_id.clone()).or_insert(ControlEvidence {
                evidence_id,
                control_id: control.to_string(),
                decision_id: d.decision_id.clone(),
            });
        }
    }
    seen.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<DecisionRef> {
        vec![
            DecisionRef {
                decision_id: "d1".into(),
                tool: "payments.charge".into(),
                verdict: "deny".into(),
                rule_id: Some("cap".into()),
            },
            DecisionRef {
                decision_id: "d2".into(),
                tool: "catalog.read".into(),
                verdict: "allow".into(),
                rule_id: None,
            },
        ]
    }

    #[test]
    fn evidence_maps_decisions_to_controls() {
        let ev = export_evidence(&sample());
        assert!(ev
            .iter()
            .any(|e| e.control_id == "AC-3" && e.decision_id == "d1"));
        assert!(ev
            .iter()
            .any(|e| e.control_id == "AU-2" && e.decision_id == "d2"));
    }

    #[test]
    fn re_pull_is_idempotent() {
        let a = export_evidence(&sample());
        let b = export_evidence(&sample());
        assert_eq!(
            a, b,
            "same decisions -> identical evidence ids, no duplicates on re-pull"
        );
    }
}
