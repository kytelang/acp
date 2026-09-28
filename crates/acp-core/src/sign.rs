//! Signing seam for the signed tree head (STH).
//!
//! Decision D3: v0 signs with Ed25519 (`ed25519-dalek`) behind this `Signer` trait so a
//! KMS/HSM backend is a drop-in later. Until the ed25519 backend is wired, a `NoopSigner`
//! keeps the trust core compiling and testable; it MUST NOT ship in a release build.

use crate::merkle::Hash;
use serde::{Deserialize, Serialize};

/// The head of the verifiable log at a point in time. Its canonical bytes are what gets
/// signed (see `acp_core::canonical`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    #[serde(with = "hex_hash")]
    pub root_hash: Hash,
    pub timestamp_ms: u64,
}

/// Abstract signer. Real backend: Ed25519. Future: KMS/HSM.
pub trait Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn public_key(&self) -> Vec<u8>;
    fn algorithm(&self) -> &'static str;
}

/// Placeholder signer for the skeleton. Never use in production.
#[derive(Debug, Default)]
pub struct NoopSigner;

impl Signer for NoopSigner {
    fn sign(&self, _msg: &[u8]) -> Vec<u8> {
        Vec::new()
    }
    fn public_key(&self) -> Vec<u8> {
        Vec::new()
    }
    fn algorithm(&self) -> &'static str {
        "noop"
    }
}

mod hex_hash {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(h: &Hash, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(h))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Hash, D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: Hash = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hash"))?;
        Ok(arr)
    }
}

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

/// A real Ed25519 signer (decision D3). v0 holds the seed in a strict-perm file; the trait lets a
/// KMS/HSM backend drop in later (H0).
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    /// Generate a fresh keypair from the OS RNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("os rng");
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Load from a 32-byte seed (as stored in the key file).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte seed, for persisting the key (0600 file in v0).
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg).to_bytes().to_vec()
    }
    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }
    fn algorithm(&self) -> &'static str {
        "ed25519"
    }
}

/// Verify an Ed25519 signature over `msg` under a 32-byte public key.
pub fn verify_ed25519(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let vk_bytes: [u8; 32] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&vk_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match sig.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    vk.verify(msg, &Signature::from_bytes(&sig_bytes)).is_ok()
}

/// Canonical bytes of a signed tree head (what actually gets signed), via JCS-style canonical JSON.
pub fn sth_bytes(sth: &SignedTreeHead) -> Vec<u8> {
    crate::canonical::canonical_bytes(sth)
}

/// Sign a tree head with any Signer.
pub fn sign_sth<S: Signer + ?Sized>(signer: &S, sth: &SignedTreeHead) -> Vec<u8> {
    signer.sign(&sth_bytes(sth))
}

/// Verify a tree head signature (Ed25519) under a public key.
pub fn verify_sth(public_key: &[u8], sth: &SignedTreeHead, sig: &[u8]) -> bool {
    verify_ed25519(public_key, &sth_bytes(sth), sig)
}

/// Verify a detached-signature pack `{body, pubkey_hex, sig_hex}`: an Ed25519 signature over the
/// canonical bytes of `body`, checkable with the embedded public key alone. This is the offline
/// verification behind the signed audit pack (`GET /audit/pack`) and the framework compliance pack
/// (`GET /report/framework/:name/pack`), and what `acp verify-pack` runs on those artifacts.
pub fn verify_detached_pack(pack: &serde_json::Value) -> Result<(), String> {
    let body = pack.get("body").ok_or("missing body")?;
    let pk_hex = pack.get("pubkey_hex").and_then(|v| v.as_str()).ok_or("missing pubkey_hex")?;
    let sig_hex = pack.get("sig_hex").and_then(|v| v.as_str()).ok_or("missing sig_hex")?;
    let pk = hex::decode(pk_hex).map_err(|e| format!("bad pubkey_hex: {e}"))?;
    let sig = hex::decode(sig_hex).map_err(|e| format!("bad sig_hex: {e}"))?;
    let msg = crate::canonical::canonical_bytes(body);
    if verify_ed25519(&pk, &msg, &sig) {
        Ok(())
    } else {
        Err("signature does not verify against the embedded public key".into())
    }
}

#[cfg(test)]
mod detached_pack_tests {
    use super::*;

    #[test]
    fn detached_pack_round_trips_and_is_tamper_evident() {
        let signer = Ed25519Signer::generate();
        let body = serde_json::json!({"@type": "acp:ComplianceReport", "conformsTo": "EU AI Act", "coverage": 0.4});
        let sig = Signer::sign(&signer, &crate::canonical::canonical_bytes(&body));
        let pack = serde_json::json!({
            "body": body,
            "pubkey_hex": hex::encode(Signer::public_key(&signer)),
            "sig_hex": hex::encode(sig),
        });
        assert!(verify_detached_pack(&pack).is_ok(), "a freshly signed pack verifies");

        // Tamper the body: verification must fail (the signature no longer matches).
        let mut bad = pack.clone();
        bad["body"]["coverage"] = serde_json::json!(0.99);
        assert!(verify_detached_pack(&bad).is_err(), "a tampered body must not verify");

        // Missing fields are rejected, not panicked.
        assert!(verify_detached_pack(&serde_json::json!({"body": {}})).is_err());
    }
}
