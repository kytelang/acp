//! Control library (complete-platform GRC build).
//!
//! `grc.rs` maps ledger evidence to a control STATUS, but there was no library of the controls
//! themselves. This is that reference library: for each framework, the controls, what each requires,
//! and the evidence that satisfies it. Assessments (see `assessment.rs`) and reports draw from it, so
//! control ids are one source of truth across ACP.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    pub framework: String,
    pub id: String,
    pub title: String,
    pub description: String,
    pub required_evidence: String,
}

/// The full built-in control library across EU AI Act, NIST AI RMF and ISO 42001.
pub fn library() -> Vec<Control> {
    let c = |framework: &str, id: &str, title: &str, description: &str, ev: &str| Control {
        framework: framework.into(),
        id: id.into(),
        title: title.into(),
        description: description.into(),
        required_evidence: ev.into(),
    };
    vec![
        // EU AI Act (high-risk obligations, Chapter III Section 2).
        c("eu-ai-act", "art-9", "Risk management system", "Establish, operate and document a risk management system across the lifecycle.", "risk register entries with treatment and review"),
        c("eu-ai-act", "art-10", "Data governance", "Training, validation and testing data meet quality and governance criteria.", "data governance records"),
        c("eu-ai-act", "art-11", "Technical documentation", "Maintain up-to-date technical documentation.", "system technical documentation"),
        c("eu-ai-act", "art-12", "Record-keeping", "Automatic recording of events (logs) over the system lifetime.", "tamper-evident ledger of decisions"),
        c("eu-ai-act", "art-13", "Transparency", "Provide information enabling users to interpret and use output.", "user-facing transparency notice"),
        c("eu-ai-act", "art-14", "Human oversight", "Enable effective oversight by natural persons, including stop/override.", "approvals, step-up and kill-switch records"),
        c("eu-ai-act", "art-15", "Accuracy, robustness, cybersecurity", "Appropriate accuracy, robustness and cybersecurity across the lifecycle.", "content firewall, tool-integrity and coverage evidence"),
        // NIST AI RMF (functions).
        c("nist-ai-rmf", "govern", "Govern", "A culture of risk management is cultivated and present.", "policy, roles (RBAC/SoD), signed evidence"),
        c("nist-ai-rmf", "map", "Map", "Context is recognised and risks are identified.", "use-case registry, discovery, risk register"),
        c("nist-ai-rmf", "measure", "Measure", "Risks are assessed, analysed and tracked.", "assessments, coverage, drift metrics"),
        c("nist-ai-rmf", "manage", "Manage", "Risks are prioritised and acted upon.", "enforcement decisions, kill-switch, attestations"),
        // ISO/IEC 42001 (AIMS clauses).
        c("iso-42001", "6.1", "Actions to address risks and opportunities", "Plan actions to address AI risks and opportunities.", "risk register with treatment"),
        c("iso-42001", "8.1", "Operational planning and control", "Plan, implement and control the processes for AI.", "signed policy, enforcement in path"),
        c("iso-42001", "9.1", "Monitoring, measurement, analysis, evaluation", "Evaluate AI performance and the AIMS.", "coverage, SIEM export, evidence reports"),
        c("iso-42001", "10.1", "Continual improvement", "Continually improve the AIMS.", "tuning/shadow-eval, posture progression"),
    ]
}

/// Controls for one framework.
pub fn for_framework(framework: &str) -> Vec<Control> {
    library().into_iter().filter(|c| c.framework == framework).collect()
}

/// Look up a control by (framework, id).
pub fn get(framework: &str, id: &str) -> Option<Control> {
    library().into_iter().find(|c| c.framework == framework && c.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_covers_three_frameworks() {
        let fws: std::collections::BTreeSet<String> = library().into_iter().map(|c| c.framework).collect();
        assert!(fws.contains("eu-ai-act") && fws.contains("nist-ai-rmf") && fws.contains("iso-42001"));
    }

    #[test]
    fn lookup_and_filter_work() {
        assert_eq!(for_framework("eu-ai-act").len(), 7);
        assert_eq!(get("eu-ai-act", "art-14").unwrap().title, "Human oversight");
        assert!(get("eu-ai-act", "art-999").is_none());
    }
}
