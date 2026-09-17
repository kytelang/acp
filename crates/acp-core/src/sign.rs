//! Signing seam for the signed tree head (STH).
//!
//! Decision D3: v0 signs with Ed25519 (`ed25519-dalek`) behind this `Signer` trait so a
//! KMS/HSM backend is a drop-in later. Until the ed25519 backend is wired, a `NoopSigner`
//! keeps the trust core compiling and testable; it MUST NOT ship in a release build.

use crate::merkle::Hash;
use serde::{Deserialize, Serialize};

/// The head of the verifiable log at a point in time. Its canonical bytes are what gets
/// signed (see `acp_core::canonical`).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
