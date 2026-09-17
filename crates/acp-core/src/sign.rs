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
