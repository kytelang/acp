//! Signed attestations / sign-offs (complete-platform GRC build).
//!
//! A GRC programme needs named humans to attest that a control, an assessment or a use-case has been
//! reviewed and approved, non-repudiably. This is that: an attestation binds an attestor and role to
//! a subject with a signature, and the log verifies each one. Distinct from break-glass approvals
//! (which gate a live action); this is governance sign-off on the record.

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// What is attested: an assessment id, a control id, or a use-case id.
    pub subject: String,
    /// The statement being made, e.g. "conformity assessment approved".
    pub statement: String,
    pub attestor: String,
    pub role: String,
    pub attested_ms: u64,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

fn signing_value(subject: &str, statement: &str, attestor: &str, role: &str, ms: u64) -> serde_json::Value {
    json!({"subject": subject, "statement": statement, "attestor": attestor, "role": role, "attested_ms": ms})
}

/// Create a signed attestation.
pub fn attest(
    signer: &dyn Signer,
    subject: &str,
    statement: &str,
    attestor: &str,
    role: &str,
    now_ms: u64,
) -> Attestation {
    let bytes = crate::canonical::canonical_bytes(&signing_value(subject, statement, attestor, role, now_ms));
    let sig = signer.sign(&bytes);
    Attestation {
        subject: subject.to_string(),
        statement: statement.to_string(),
        attestor: attestor.to_string(),
        role: role.to_string(),
        attested_ms: now_ms,
        pubkey_hex: hex::encode(signer.public_key()),
        sig_hex: hex::encode(sig),
    }
}

impl Attestation {
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
            &self.subject,
            &self.statement,
            &self.attestor,
            &self.role,
            self.attested_ms,
        ));
        verify_ed25519(&pk, &bytes, &sig)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationLog {
    pub attestations: Vec<Attestation>,
}

impl AttestationLog {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, a: Attestation) {
        self.attestations.push(a);
    }
    pub fn for_subject(&self, subject: &str) -> Vec<&Attestation> {
        self.attestations.iter().filter(|a| a.subject == subject).collect()
    }
    /// True when at least one valid attestation exists for the subject.
    pub fn has_valid(&self, subject: &str) -> bool {
        self.for_subject(subject).into_iter().any(|a| a.verify())
    }
    /// True when every stored attestation verifies.
    pub fn verify_all(&self) -> bool {
        self.attestations.iter().all(|a| a.verify())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    #[test]
    fn attestation_signs_and_verifies() {
        let s = Ed25519Signer::generate();
        let a = attest(&s, "assess-hiring", "conformity assessment approved", "carol", "compliance", 1000);
        assert!(a.verify());
        let mut bad = a.clone();
        bad.attestor = "mallory".into();
        assert!(!bad.verify());
    }

    #[test]
    fn log_finds_valid_attestations_by_subject() {
        let s = Ed25519Signer::generate();
        let mut log = AttestationLog::new();
        log.add(attest(&s, "uc-1", "approved for deployment", "carol", "risk-owner", 1000));
        assert!(log.has_valid("uc-1"));
        assert!(!log.has_valid("uc-2"));
        assert!(log.verify_all());
    }
}
