//! Signed control packs (A4): a versioned, signed bundle of a control library and its framework
//! mappings, so an organisation can load continuously-updated compliance content into the control
//! plane and verify its provenance. The three built-in packs (EU AI Act, NIST AI RMF, ISO 42001)
//! are derived from `crate::controls`, so a loaded pack's controls are exactly the ones the
//! assessment engine (`crate::assessment`) draws on.

use crate::controls::Control;
use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A control pack: a named, versioned set of frameworks and their controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPack {
    pub id: String,
    pub version: String,
    pub frameworks: Vec<String>,
    pub controls: Vec<Control>,
    pub generated_ms: u64,
}

/// A signed control pack: the canonical pack document plus an Ed25519 signature over its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPack {
    pub pack: Value,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

impl ControlPack {
    /// The canonical JSON document that is signed and verified.
    pub fn document(&self) -> Value {
        json!({
            "id": self.id,
            "version": self.version,
            "frameworks": self.frameworks,
            "controls": self.controls,
            "generated_ms": self.generated_ms,
        })
    }

    /// Sign the pack (canonical bytes + Ed25519).
    pub fn sign(&self, signer: &dyn Signer) -> SignedPack {
        let pack = self.document();
        let bytes = crate::canonical::canonical_bytes(&pack);
        let sig = signer.sign(&bytes);
        SignedPack {
            pack,
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

/// Verify a signed pack against its embedded public key. Fail-closed on any decode error, so a
/// tampered pack (its `pack` body no longer matches the signature) is rejected.
pub fn verify(signed: &SignedPack) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bytes = crate::canonical::canonical_bytes(&signed.pack);
    verify_ed25519(&pk, &bytes, &sig)
}

/// The built-in packs, one per framework, derived from the control library. Loading these makes the
/// assessment engine's controls available in the control plane as verifiable, versioned content.
pub fn builtin_packs(generated_ms: u64) -> Vec<ControlPack> {
    let frameworks = [
        ("eu-ai-act", "EU AI Act"),
        ("nist-ai-rmf", "NIST AI RMF"),
        ("iso-42001", "ISO/IEC 42001"),
    ];
    frameworks
        .iter()
        .map(|(fw, _label)| ControlPack {
            id: format!("pack-{fw}"),
            version: "2026.09".to_string(),
            frameworks: vec![fw.to_string()],
            controls: crate::controls::for_framework(fw),
            generated_ms,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    #[test]
    fn builtin_packs_cover_three_frameworks_and_verify() {
        let packs = builtin_packs(1000);
        assert_eq!(packs.len(), 3);
        let signer = Ed25519Signer::from_seed(&[7u8; 32]);
        for p in &packs {
            assert!(!p.controls.is_empty(), "{} has controls", p.id);
            let signed = p.sign(&signer);
            assert!(verify(&signed), "{} verifies", p.id);
        }
    }

    #[test]
    fn tampered_pack_is_rejected() {
        let signer = Ed25519Signer::from_seed(&[9u8; 32]);
        let mut signed = builtin_packs(1000)[0].sign(&signer);
        // Mutate the signed body after signing: verification must fail.
        signed.pack["version"] = json!("tampered");
        assert!(!verify(&signed), "a tampered pack is rejected");
    }
}
