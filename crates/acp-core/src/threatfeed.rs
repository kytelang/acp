//! Signed threat-intelligence packs for the content firewall (B5).
//!
//! Static signatures and denied topics go stale. A threat pack is a versioned, signed list of
//! additional firewall signatures (denied substrings or regexes) that an organisation loads into the
//! control plane; every acp-agent picks them up on its next firewall fetch. Signing gives provenance:
//! a tampered pack (its body no longer matches the signature) is rejected.

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A threat pack: a monotonically versioned set of firewall signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatPack {
    pub version: u64,
    pub signatures: Vec<String>,
    pub generated_ms: u64,
}

/// A signed threat pack: the canonical document plus an Ed25519 signature over its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedThreatPack {
    pub pack: Value,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

impl ThreatPack {
    pub fn document(&self) -> Value {
        json!({"version": self.version, "signatures": self.signatures, "generated_ms": self.generated_ms})
    }
    pub fn sign(&self, signer: &dyn Signer) -> SignedThreatPack {
        let pack = self.document();
        let bytes = crate::canonical::canonical_bytes(&pack);
        let sig = signer.sign(&bytes);
        SignedThreatPack {
            pack,
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

/// Verify a signed threat pack against its embedded key. Fail-closed on any decode error.
pub fn verify(signed: &SignedThreatPack) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verify_ed25519(&pk, &crate::canonical::canonical_bytes(&signed.pack), &sig)
}

/// A small built-in sample threat pack, so the feed can be exercised out of the box.
pub fn builtin_threat_pack(version: u64, generated_ms: u64) -> ThreatPack {
    ThreatPack {
        version,
        signatures: vec![
            "ignore all safety".to_string(),
            "exfiltrate credentials".to_string(),
            "disable the firewall".to_string(),
        ],
        generated_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    #[test]
    fn threat_pack_signs_and_verifies_and_tamper_fails() {
        let signer = Ed25519Signer::from_seed(&[3u8; 32]);
        let mut signed = builtin_threat_pack(7, 1000).sign(&signer);
        assert!(verify(&signed));
        signed.pack["version"] = json!(999);
        assert!(!verify(&signed), "a tampered threat pack is rejected");
    }
}
