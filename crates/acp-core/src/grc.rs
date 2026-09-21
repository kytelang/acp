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


/// A distilled summary of what the tamper-evident ledger + policy currently evidence. Built by the
/// caller from the ledger export; the report maps it to framework controls.
#[derive(Debug, Clone, Default)]
pub struct EvidenceSummary {
    pub total_decisions: usize,
    pub denies: usize,
    pub step_ups: usize,
    pub kill_switch_events: usize,
    pub redactions: usize,
    pub signed_ledger: bool,
    pub policy_in_force: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Satisfied,
    Partial,
    Gap,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Satisfied => "satisfied",
            Status::Partial => "partial",
            Status::Gap => "gap",
        }
    }
}

/// One framework control and whether the runtime evidence satisfies it.
#[derive(Debug, Clone)]
pub struct ControlStatus {
    pub framework: &'static str,
    pub control_id: &'static str,
    pub title: &'static str,
    pub status: Status,
    pub rationale: String,
}

/// Satisfied if `strong`; Partial if only the capability (`capable`) is present; else Gap.
fn grade(strong: bool, capable: bool, strong_why: &str, partial_why: &str, gap_why: &str) -> (Status, String) {
    if strong {
        (Status::Satisfied, strong_why.to_string())
    } else if capable {
        (Status::Partial, partial_why.to_string())
    } else {
        (Status::Gap, gap_why.to_string())
    }
}

/// Project the evidence summary onto framework controls. This is what makes ACP evidence-BACKED
/// rather than questionnaire-backed: each control is graded by the signed runtime record, not a
/// self-attestation. Evidence-BACKED, not a legal compliance opinion.
pub fn report(s: &EvidenceSummary) -> Vec<ControlStatus> {
    let mut out = Vec::new();
    let mut add = |framework, control_id, title, st: (Status, String)| {
        out.push(ControlStatus { framework, control_id, title, status: st.0, rationale: st.1 });
    };

    // EU AI Act
    add("EU AI Act", "Art.14", "Human oversight",
        grade(s.step_ups > 0 || s.kill_switch_events > 0, s.policy_in_force,
            &format!("{} step-up approval(s) + {} kill-switch event(s) recorded", s.step_ups, s.kill_switch_events),
            "oversight controls in force (step-up + kill-switch) but not yet exercised",
            "no human-oversight controls evidenced"));
    add("EU AI Act", "Art.12", "Record-keeping / logging",
        grade(s.signed_ledger && s.total_decisions > 0, s.signed_ledger,
            &format!("{} decisions in a signed, tamper-evident ledger", s.total_decisions),
            "signed ledger present but no decisions recorded yet",
            "no tamper-evident logging"));
    add("EU AI Act", "Art.9", "Risk management (enforcement)",
        grade(s.policy_in_force && s.total_decisions > 0, s.policy_in_force,
            &format!("policy enforced inline; {} denies of {} decisions", s.denies, s.total_decisions),
            "policy in force but no decisions yet",
            "no enforcement evidenced"));

    // NIST AI RMF
    add("NIST AI RMF", "MANAGE-2.3", "Incident response / stop",
        grade(s.kill_switch_events > 0, s.policy_in_force,
            &format!("{} kill-switch engagement(s) recorded", s.kill_switch_events),
            "kill-switch available but never engaged",
            "no stop capability evidenced"));
    add("NIST AI RMF", "MEASURE-2.7", "Monitoring / logging",
        grade(s.signed_ledger, false,
            "every decision streamed to the tamper-evident ledger (and SIEM)",
            "", "no monitoring evidenced"));
    add("NIST AI RMF", "GOVERN-1.2", "Access control / policy",
        grade(s.policy_in_force, false,
            "signed policy enforced at the tool/model call boundary",
            "", "no policy in force"));

    // ISO 42001
    add("ISO 42001", "A.8", "Operational controls",
        grade(s.policy_in_force && s.signed_ledger, s.policy_in_force,
            "policy enforced and decisions recorded verifiably",
            "policy in force; verifiable recording incomplete",
            "no operational AI controls"));
    add("ISO 42001", "A.9", "Data governance (redaction)",
        grade(s.redactions > 0, s.policy_in_force,
            &format!("{} redaction obligation(s) applied to protect data in calls", s.redactions),
            "redaction available via obligations but not exercised",
            "no data-governance controls evidenced"));

    out
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
    fn report_grades_controls_from_evidence() {
        let s = EvidenceSummary {
            total_decisions: 10, denies: 3, step_ups: 2, kill_switch_events: 1,
            redactions: 0, signed_ledger: true, policy_in_force: true,
        };
        let r = report(&s);
        let get = |id: &str| r.iter().find(|c| c.control_id == id).unwrap().status;
        assert_eq!(get("Art.14"), Status::Satisfied, "step-ups + kill-switch -> oversight satisfied");
        assert_eq!(get("Art.12"), Status::Satisfied, "signed ledger + decisions -> logging satisfied");
        assert_eq!(get("MANAGE-2.3"), Status::Satisfied, "kill-switch engaged");
        assert_eq!(get("A.9"), Status::Partial, "no redactions yet -> partial");
        // An empty deployment: mostly gaps.
        let empty = report(&EvidenceSummary::default());
        assert_eq!(empty.iter().find(|c| c.control_id == "Art.12").unwrap().status, Status::Gap);
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
