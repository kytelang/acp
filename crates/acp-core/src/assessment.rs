//! AI system assessment (complete-platform GRC build): EU AI Act risk tiering and a conformity
//! checklist. Turns the "impact / conformity assessment workflow" that used to belong only to a GRC
//! platform into a first-party, signable step. Deterministic rules over a small questionnaire, not a
//! legal opinion: it produces the tier and the obligations to satisfy, which an assessor then works.

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};

/// EU AI Act risk tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    Unacceptable,
    High,
    Limited,
    Minimal,
}

impl RiskTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskTier::Unacceptable => "unacceptable",
            RiskTier::High => "high",
            RiskTier::Limited => "limited",
            RiskTier::Minimal => "minimal",
        }
    }
}

/// The screening questionnaire. Each flag maps to an EU AI Act trigger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Screening {
    /// Prohibited practice (social scoring, manipulative or exploitative AI, untargeted scraping...).
    pub prohibited_practice: bool,
    /// Safety component of a product, or Annex III high-risk use.
    pub safety_component: bool,
    pub biometric_identification: bool,
    pub critical_infrastructure: bool,
    pub employment_or_education: bool,
    pub essential_services: bool, // credit scoring, benefits, insurance
    pub law_enforcement: bool,
    /// Interacts directly with people (chatbot) -> transparency duty.
    pub interacts_with_humans: bool,
    /// Generates or manipulates content (gen-AI, deepfakes) -> transparency duty.
    pub generates_content: bool,
}

/// One obligation to satisfy, keyed to a control in the library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligation {
    pub framework: String,
    pub control_id: String,
    pub title: String,
}

/// The assessment result for a system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    pub system: String,
    pub tier: RiskTier,
    pub reasons: Vec<String>,
    pub obligations: Vec<Obligation>,
    pub assessed_ms: u64,
}

/// A signed assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAssessment {
    pub assessment: Assessment,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

/// Classify the risk tier from the screening (EU AI Act structure).
pub fn classify_tier(s: &Screening) -> (RiskTier, Vec<String>) {
    let mut reasons = Vec::new();
    if s.prohibited_practice {
        reasons.push("prohibited practice under Article 5".into());
        return (RiskTier::Unacceptable, reasons);
    }
    let high = [
        (s.safety_component, "safety component / Annex III use"),
        (s.biometric_identification, "biometric identification"),
        (s.critical_infrastructure, "critical infrastructure"),
        (s.employment_or_education, "employment or education decisions"),
        (s.essential_services, "access to essential services (credit, benefits)"),
        (s.law_enforcement, "law enforcement"),
    ];
    let mut is_high = false;
    for (flag, why) in high {
        if flag {
            reasons.push(why.into());
            is_high = true;
        }
    }
    if is_high {
        return (RiskTier::High, reasons);
    }
    if s.interacts_with_humans {
        reasons.push("interacts directly with people (transparency duty)".into());
    }
    if s.generates_content {
        reasons.push("generates or manipulates content (transparency duty)".into());
    }
    if s.interacts_with_humans || s.generates_content {
        return (RiskTier::Limited, reasons);
    }
    reasons.push("no high-risk or transparency trigger".into());
    (RiskTier::Minimal, reasons)
}

/// The obligations (controls) a tier must satisfy. High-risk pulls the full EU AI Act high-risk set;
/// limited pulls the transparency obligation; minimal has none mandated.
fn obligations_for(tier: RiskTier) -> Vec<Obligation> {
    let pull = |ids: &[&str]| -> Vec<Obligation> {
        ids.iter()
            .filter_map(|id| crate::controls::get("eu-ai-act", id))
            .map(|c| Obligation { framework: c.framework, control_id: c.id, title: c.title })
            .collect()
    };
    match tier {
        RiskTier::Unacceptable => vec![],
        RiskTier::High => pull(&["art-9", "art-10", "art-11", "art-12", "art-13", "art-14", "art-15"]),
        RiskTier::Limited => pull(&["art-13"]),
        RiskTier::Minimal => vec![],
    }
}

/// Run the full assessment for a named system.
pub fn assess(system: &str, screening: &Screening, now_ms: u64) -> Assessment {
    let (tier, reasons) = classify_tier(screening);
    Assessment {
        system: system.to_string(),
        tier,
        reasons,
        obligations: obligations_for(tier),
        assessed_ms: now_ms,
    }
}

impl Assessment {
    pub fn sign(self, signer: &dyn Signer) -> SignedAssessment {
        let bytes = crate::canonical::canonical_bytes(&self);
        let sig = signer.sign(&bytes);
        SignedAssessment {
            assessment: self,
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

pub fn verify(signed: &SignedAssessment) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verify_ed25519(&pk, &crate::canonical::canonical_bytes(&signed.assessment), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    #[test]
    fn prohibited_is_unacceptable() {
        let s = Screening { prohibited_practice: true, ..Default::default() };
        assert_eq!(classify_tier(&s).0, RiskTier::Unacceptable);
    }

    #[test]
    fn annex_iii_is_high_with_full_obligations() {
        let s = Screening { employment_or_education: true, ..Default::default() };
        let a = assess("hiring-screener", &s, 1000);
        assert_eq!(a.tier, RiskTier::High);
        assert_eq!(a.obligations.len(), 7);
        assert!(a.obligations.iter().any(|o| o.control_id == "art-14"));
    }

    #[test]
    fn chatbot_is_limited() {
        let s = Screening { interacts_with_humans: true, ..Default::default() };
        let a = assess("support-bot", &s, 1000);
        assert_eq!(a.tier, RiskTier::Limited);
        assert_eq!(a.obligations.len(), 1);
        assert_eq!(a.obligations[0].control_id, "art-13");
    }

    #[test]
    fn plain_tool_is_minimal() {
        let a = assess("spellchecker", &Screening::default(), 1000);
        assert_eq!(a.tier, RiskTier::Minimal);
        assert!(a.obligations.is_empty());
    }

    #[test]
    fn assessment_signs_and_verifies() {
        let a = assess("hiring-screener", &Screening { employment_or_education: true, ..Default::default() }, 1000);
        let signed = a.sign(&Ed25519Signer::generate());
        assert!(verify(&signed));
        let mut bad = signed.clone();
        bad.assessment.tier = RiskTier::Minimal;
        assert!(!verify(&bad));
    }
}
