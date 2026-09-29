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

/// One framework control and whether the runtime evidence satisfies it. Framework and id are the
/// canonical library slug and control id (see `crate::controls`), and the title is pulled from the
/// library so this grader shares one source of truth with the rest of ACP.
#[derive(Debug, Clone)]
pub struct ControlStatus {
    pub framework: String,
    pub control_id: String,
    pub title: String,
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
///
/// Every graded control is keyed by its canonical `(framework, id)` in `crate::controls`, and its
/// title is pulled from the library. A control id that is not in the library is skipped, so this
/// grader can never emit a control that disagrees with the catalogue (decision B.8-1).
pub fn report(s: &EvidenceSummary) -> Vec<ControlStatus> {
    let mut out = Vec::new();
    // (framework, id, grade). The grade closure returns (Status, rationale).
    let specs: Vec<(&str, &str, (Status, String))> = vec![
        ("eu-ai-act", "art-14",
            grade(s.step_ups > 0 || s.kill_switch_events > 0, s.policy_in_force,
                &format!("{} step-up approval(s) + {} kill-switch event(s) recorded", s.step_ups, s.kill_switch_events),
                "oversight controls in force (step-up + kill-switch) but not yet exercised",
                "no human-oversight controls evidenced")),
        ("eu-ai-act", "art-12",
            grade(s.signed_ledger && s.total_decisions > 0, s.signed_ledger,
                &format!("{} decisions in a signed, tamper-evident ledger", s.total_decisions),
                "signed ledger present but no decisions recorded yet",
                "no tamper-evident logging")),
        ("eu-ai-act", "art-9",
            grade(s.policy_in_force && s.total_decisions > 0, s.policy_in_force,
                &format!("policy enforced inline; {} denies of {} decisions", s.denies, s.total_decisions),
                "policy in force but no decisions yet",
                "no enforcement evidenced")),
        ("eu-ai-act", "art-15",
            grade(s.redactions > 0, s.policy_in_force,
                &format!("{} redaction obligation(s) applied; policy enforced in path", s.redactions),
                "content-firewall/redaction available but not exercised",
                "no accuracy/robustness controls evidenced")),
        // Cross-framework runtime grades. Resolved against the library and skipped if the id is absent.
        ("nist-ai-rmf", "govern-1.2",
            grade(s.policy_in_force, false,
                "signed policy enforced at the tool/model call boundary", "",
                "no policy in force")),
        ("nist-ai-rmf", "measure-2.7",
            grade(s.signed_ledger, false,
                "every decision streamed to the tamper-evident ledger (and SIEM)", "",
                "no monitoring evidenced")),
        ("iso-42001", "clause-9.1",
            grade(s.policy_in_force && s.signed_ledger, s.policy_in_force,
                "AI performance monitored: policy enforced and decisions recorded verifiably",
                "policy in force; verifiable recording incomplete",
                "no monitoring/measurement evidenced")),
        ("soc-2", "cc7.2",
            grade(s.signed_ledger, s.policy_in_force,
                "security monitoring: every decision recorded to the ledger/SIEM",
                "monitoring capability in place but no records yet",
                "no security monitoring evidenced")),
        ("soc-2", "cc7.3",
            grade(s.kill_switch_events > 0, s.policy_in_force,
                &format!("{} incident-response engagement(s) (break-glass/kill-switch)", s.kill_switch_events),
                "incident-response controls available but not exercised",
                "no incident-response capability evidenced")),
    ];
    for (fw, id, st) in specs {
        // Title comes from the library; an unknown id is skipped so we never emit a non-library control.
        if let Some(c) = crate::controls::get(fw, id) {
            out.push(ControlStatus {
                framework: fw.to_string(),
                control_id: id.to_string(),
                title: c.title,
                status: st.0,
                rationale: st.1,
            });
        }
    }
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
        assert_eq!(get("art-14"), Status::Satisfied, "step-ups + kill-switch -> oversight satisfied");
        assert_eq!(get("art-12"), Status::Satisfied, "signed ledger + decisions -> logging satisfied");
        // Every graded control resolves to a real library control (canonical framework+id).
        for c in &r {
            assert!(crate::controls::get(&c.framework, &c.control_id).is_some(),
                "{}:{} must be a library control", c.framework, c.control_id);
        }
        // An empty deployment: record-keeping is a gap.
        let empty = report(&EvidenceSummary::default());
        assert_eq!(empty.iter().find(|c| c.control_id == "art-12").unwrap().status, Status::Gap);
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
