//! MITRE ATLAS enrichment (R4).
//!
//! ATLAS (Adversarial Threat Landscape for AI Systems) is MITRE's ATT&CK-style knowledge base of
//! real-world attacks on AI. ACP does not run a model scanner or a content classifier of its own for
//! this: it stays neutral and calls a specialist (see `docs/scan-hook-contract.md`). What it adds here
//! is enrichment: it maps a scanner's or the content engine's finding kinds to ATLAS technique ids so
//! an AI-BOM entry and the console carry the standard adversarial-technique language an auditor or a
//! SOC already speaks, instead of vendor-specific finding strings.
//!
//! The mapping is deliberately conservative: it matches on well-understood finding-kind substrings and
//! returns the closest published ATLAS technique. Unknown kinds map to nothing rather than guessing.

use serde::{Deserialize, Serialize};

/// One MITRE ATLAS technique reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasTechnique {
    /// The ATLAS technique id, for example "AML.T0051".
    pub id: String,
    /// The technique name.
    pub name: String,
    /// The ATLAS tactic the technique sits under.
    pub tactic: String,
}

impl AtlasTechnique {
    fn new(id: &str, name: &str, tactic: &str) -> Self {
        AtlasTechnique { id: id.into(), name: name.into(), tactic: tactic.into() }
    }
}

/// The static rule table: (substrings that a finding kind may contain, technique). The first rule whose
/// any-substring matches (case-insensitive) wins for a given kind. Substrings are lower-case.
fn rules() -> Vec<(&'static [&'static str], AtlasTechnique)> {
    vec![
        // Model-artifact scan findings.
        (
            &["pickle", "deserial", "code-exec", "code_exec", "arbitrary-code", "unsafe-artifact", "unsafe_artifact", "rce"],
            AtlasTechnique::new("AML.T0011.000", "User Execution: Unsafe ML Artifacts", "Execution"),
        ),
        (
            &["backdoor", "trojan", "poison"],
            AtlasTechnique::new("AML.T0018", "Manipulate AI Model: Poison AI Model", "Persistence"),
        ),
        (
            &["supply-chain", "supply_chain", "provenance", "unsigned", "tampered-provenance"],
            AtlasTechnique::new("AML.T0010", "AI Supply Chain Compromise", "Initial Access"),
        ),
        (
            &["integrity", "tampered", "format-mismatch", "format_mismatch", "modified-weights"],
            AtlasTechnique::new("AML.T0031", "Erode AI Model Integrity", "Impact"),
        ),
        // Content-engine / runtime findings.
        (
            &["prompt-injection", "prompt_injection", "injection"],
            AtlasTechnique::new("AML.T0051", "LLM Prompt Injection", "Initial Access"),
        ),
        (
            &["jailbreak"],
            AtlasTechnique::new("AML.T0054", "LLM Jailbreak", "Privilege Escalation"),
        ),
        (
            &["secret", "pii", "data-leak", "data_leak", "exfil", "sensitive"],
            AtlasTechnique::new("AML.T0057", "LLM Data Leakage", "Exfiltration"),
        ),
        (
            &["denied-topic", "denied_topic", "toxicity", "harmful", "abuse"],
            AtlasTechnique::new("AML.T0048", "External Harms", "Impact"),
        ),
    ]
}

/// Map one finding-kind string to its ATLAS technique, if any is known.
pub fn technique_for(kind: &str) -> Option<AtlasTechnique> {
    let k = kind.to_ascii_lowercase();
    for (subs, tech) in rules() {
        if subs.iter().any(|s| k.contains(s)) {
            return Some(tech);
        }
    }
    None
}

/// Map a set of finding-kind / issue strings to their ATLAS techniques, de-duplicated by id and in a
/// stable order (first-seen wins). Kinds with no known mapping are dropped.
pub fn techniques_for_issues(issues: &[String]) -> Vec<AtlasTechnique> {
    let mut out: Vec<AtlasTechnique> = Vec::new();
    for issue in issues {
        if let Some(t) = technique_for(issue) {
            if !out.iter().any(|e| e.id == t.id) {
                out.push(t);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_model_finding_maps_to_atlas() {
        let t = technique_for("malicious pickle opcode").unwrap();
        assert_eq!(t.id, "AML.T0011.000");
    }

    #[test]
    fn prompt_injection_maps_to_t0051() {
        assert_eq!(technique_for("prompt-injection").unwrap().id, "AML.T0051");
        assert_eq!(technique_for("injection").unwrap().id, "AML.T0051");
    }

    #[test]
    fn unknown_kind_maps_to_nothing() {
        assert!(technique_for("some-benign-note").is_none());
    }

    #[test]
    fn issues_dedupe_by_id_and_keep_order() {
        let ts = techniques_for_issues(&[
            "prompt injection detected".into(),
            "another injection".into(),
            "secret api key".into(),
            "harmless".into(),
        ]);
        assert_eq!(ts.len(), 2);
        assert_eq!(ts[0].id, "AML.T0051");
        assert_eq!(ts[1].id, "AML.T0057");
    }
}
