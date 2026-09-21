//! Conformity assessment workflow (pending.md P1 #2: GRC depth).
//!
//! `assessment.rs` produces a risk tier and the list of obligations (controls) a system must satisfy.
//! This turns that static list into a WORKED checklist: each control is tracked through a status with
//! evidence links (ledger decision ids, attestation ids) and an owner, so an assessor can drive a
//! system from "assessed" to "conformant" and report progress. Pure and signable.

use crate::assessment::Assessment;
use crate::grc::Status;
use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};

/// One control being worked towards conformity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformityItem {
    pub framework: String,
    pub control_id: String,
    pub title: String,
    pub status: Status,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub owner: String,
}

/// The conformity assessment for a system: its controls and their worked status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformityAssessment {
    pub system: String,
    pub tier: String,
    pub items: Vec<ConformityItem>,
    pub updated_ms: u64,
}

/// A signed conformity assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedConformity {
    pub conformity: ConformityAssessment,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

impl ConformityAssessment {
    /// Seed a conformity checklist from a risk assessment: every obligation becomes a Gap to work.
    pub fn from_assessment(a: &Assessment, now_ms: u64) -> ConformityAssessment {
        let items = a
            .obligations
            .iter()
            .map(|o| ConformityItem {
                framework: o.framework.clone(),
                control_id: o.control_id.clone(),
                title: o.title.clone(),
                status: Status::Gap,
                evidence: Vec::new(),
                owner: String::new(),
            })
            .collect();
        ConformityAssessment {
            system: a.system.clone(),
            tier: a.tier.as_str().to_string(),
            items,
            updated_ms: now_ms,
        }
    }

    /// Update one control's status, evidence and owner. Returns false if the control is unknown.
    pub fn set_status(
        &mut self,
        control_id: &str,
        status: Status,
        evidence: Vec<String>,
        owner: &str,
        now_ms: u64,
    ) -> bool {
        if let Some(it) = self.items.iter_mut().find(|i| i.control_id == control_id) {
            it.status = status;
            if !evidence.is_empty() {
                it.evidence = evidence;
            }
            if !owner.is_empty() {
                it.owner = owner.to_string();
            }
            self.updated_ms = now_ms;
            true
        } else {
            false
        }
    }

    /// (satisfied, total, percent).
    pub fn completeness(&self) -> (usize, usize, u32) {
        let total = self.items.len();
        let sat = self.items.iter().filter(|i| i.status == Status::Satisfied).count();
        let pct = if total == 0 { 100 } else { ((sat as f64 / total as f64) * 100.0).round() as u32 };
        (sat, total, pct)
    }

    /// True only when every control is Satisfied.
    pub fn is_conformant(&self) -> bool {
        !self.items.is_empty() && self.items.iter().all(|i| i.status == Status::Satisfied)
    }

    /// Controls still open (Partial or Gap), the worklist.
    pub fn open_items(&self) -> Vec<&ConformityItem> {
        self.items.iter().filter(|i| i.status != Status::Satisfied).collect()
    }

    pub fn sign(&self, signer: &dyn Signer) -> SignedConformity {
        let bytes = crate::canonical::canonical_bytes(self);
        let sig = signer.sign(&bytes);
        SignedConformity {
            conformity: self.clone(),
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

pub fn verify(signed: &SignedConformity) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verify_ed25519(&pk, &crate::canonical::canonical_bytes(&signed.conformity), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::{assess, Screening};
    use crate::sign::Ed25519Signer;

    fn high_risk() -> Assessment {
        assess("hiring-screener", &Screening { employment_or_education: true, ..Default::default() }, 1000)
    }

    #[test]
    fn seeds_from_assessment_as_gaps() {
        let c = ConformityAssessment::from_assessment(&high_risk(), 1000);
        assert_eq!(c.items.len(), 7);
        assert!(c.items.iter().all(|i| i.status == Status::Gap));
        assert_eq!(c.completeness(), (0, 7, 0));
        assert!(!c.is_conformant());
    }

    #[test]
    fn working_controls_moves_towards_conformant() {
        let mut c = ConformityAssessment::from_assessment(&high_risk(), 1000);
        for o in ["art-9","art-10","art-11","art-12","art-13","art-14","art-15"] {
            assert!(c.set_status(o, Status::Satisfied, vec!["dec-1".into()], "carol", 2000));
        }
        assert!(c.is_conformant());
        assert_eq!(c.completeness().2, 100);
        assert!(c.open_items().is_empty());
    }

    #[test]
    fn unknown_control_is_rejected() {
        let mut c = ConformityAssessment::from_assessment(&high_risk(), 1000);
        assert!(!c.set_status("art-999", Status::Satisfied, vec![], "x", 2000));
    }

    #[test]
    fn signed_conformity_verifies_and_tamper_caught() {
        let c = ConformityAssessment::from_assessment(&high_risk(), 1000);
        let signed = c.sign(&Ed25519Signer::generate());
        assert!(verify(&signed));
        let mut bad = signed.clone();
        bad.conformity.system = "other".into();
        assert!(!verify(&bad));
    }
}
