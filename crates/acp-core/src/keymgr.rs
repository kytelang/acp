//! Key management with rotation and historical verification (decision H0.3).
//!
//! Signing keys must rotate, and rotation must never strand old evidence: a record signed under
//! the key that was current last quarter has to keep verifying after this quarter's rotation. We
//! achieve that by tagging every signature with the key id that produced it and keeping the full
//! public-key history, so a verifier resolves the right key by id.
//!
//! The backend is an interface. `LocalKms` is a self-contained backend (keys held in-process,
//! suitable for tests and single-node dev) that implements the exact contract a cloud KMS/HSM
//! backend implements: generate, sign-by-key-id, fetch-public-key-by-id, rotate. Swapping to AWS
//! KMS, GCP KMS, or a PKCS#11 HSM is a new `KmsBackend` impl and a config change, not a code
//! change anywhere above this seam.

use crate::sign::{verify_sth, Ed25519Signer, SignedTreeHead, Signer};
use std::collections::HashMap;

/// A signature plus the provenance needed to verify it after later rotations.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyedSignature {
    pub key_id: String,
    pub algorithm: String,
    pub sig: Vec<u8>,
}

/// The contract every signing backend satisfies. A cloud KMS implements the same four operations
/// against a remote service; `LocalKms` implements them in-process.
pub trait KmsBackend {
    /// The key id that new signatures should use.
    fn current_key_id(&self) -> String;
    /// Sign `msg` with a specific key id. Returns None if that key id is unknown.
    fn sign_with(&self, key_id: &str, msg: &[u8]) -> Option<Vec<u8>>;
    /// The public key for a key id, for verification. None if unknown.
    fn public_key(&self, key_id: &str) -> Option<Vec<u8>>;
    /// The signature algorithm (e.g. "ed25519").
    fn algorithm(&self) -> &'static str;
    /// Rotate to a fresh key and return its id. Old keys are retained for verification.
    fn rotate(&mut self) -> String;
}

/// An in-process backend: keeps every key ever generated so historical signatures still verify.
/// This is the local/dev/test backend; production points the same interface at a real KMS/HSM.
pub struct LocalKms {
    keys: HashMap<String, Ed25519Signer>,
    order: Vec<String>,
    current: String,
    counter: u64,
}

impl LocalKms {
    pub fn new() -> Self {
        let signer = Ed25519Signer::generate();
        let id = "key-1".to_string();
        let mut keys = HashMap::new();
        keys.insert(id.clone(), signer);
        LocalKms {
            keys,
            order: vec![id.clone()],
            current: id,
            counter: 1,
        }
    }

    /// Key ids in generation order, oldest first (the key history an auditor inspects).
    pub fn history(&self) -> &[String] {
        &self.order
    }
}

impl Default for LocalKms {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsBackend for LocalKms {
    fn current_key_id(&self) -> String {
        self.current.clone()
    }
    fn sign_with(&self, key_id: &str, msg: &[u8]) -> Option<Vec<u8>> {
        self.keys.get(key_id).map(|s| s.sign(msg))
    }
    fn public_key(&self, key_id: &str) -> Option<Vec<u8>> {
        self.keys.get(key_id).map(|s| s.public_key())
    }
    fn algorithm(&self) -> &'static str {
        "ed25519"
    }
    fn rotate(&mut self) -> String {
        self.counter += 1;
        let id = format!("key-{}", self.counter);
        self.keys.insert(id.clone(), Ed25519Signer::generate());
        self.order.push(id.clone());
        self.current = id.clone();
        id
    }
}

/// Signs and verifies tree heads over a rotating key set, tagging each signature with its key id.
pub struct KeyManager<B: KmsBackend> {
    backend: B,
}

impl<B: KmsBackend> KeyManager<B> {
    pub fn new(backend: B) -> Self {
        KeyManager { backend }
    }

    /// Sign a tree head with the current key, recording which key id signed it.
    pub fn sign_sth(&self, sth: &SignedTreeHead) -> KeyedSignature {
        let key_id = self.backend.current_key_id();
        let msg = crate::sign::sth_bytes(sth);
        let sig = self
            .backend
            .sign_with(&key_id, &msg)
            .expect("current key id must be signable");
        KeyedSignature {
            key_id,
            algorithm: self.backend.algorithm().to_string(),
            sig,
        }
    }

    /// Verify a keyed signature by resolving the historical public key for its key id. A signature
    /// made under an old key still verifies after any number of rotations.
    pub fn verify_sth(&self, sth: &SignedTreeHead, signed: &KeyedSignature) -> bool {
        match self.backend.public_key(&signed.key_id) {
            Some(pk) => verify_sth(&pk, sth, &signed.sig),
            None => false,
        }
    }

    pub fn rotate(&mut self) -> String {
        self.backend.rotate()
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(size: u64) -> SignedTreeHead {
        SignedTreeHead {
            tree_size: size,
            root_hash: [7u8; 32],
            timestamp_ms: 1_000 + size,
        }
    }

    #[test]
    fn a_signature_verifies_under_its_own_key() {
        let km = KeyManager::new(LocalKms::new());
        let h = head(1);
        let s = km.sign_sth(&h);
        assert!(km.verify_sth(&h, &s));
        assert_eq!(s.key_id, "key-1");
    }

    #[test]
    fn rotation_preserves_verification_of_historical_records() {
        let mut km = KeyManager::new(LocalKms::new());
        let h_old = head(1);
        let sig_old = km.sign_sth(&h_old); // signed under key-1

        let new_id = km.rotate();
        assert_eq!(new_id, "key-2");

        let h_new = head(2);
        let sig_new = km.sign_sth(&h_new); // signed under key-2
        assert_eq!(sig_new.key_id, "key-2");

        // The pre-rotation signature still verifies: the key id resolves the historical key.
        assert!(
            km.verify_sth(&h_old, &sig_old),
            "historical record must still verify"
        );
        assert!(km.verify_sth(&h_new, &sig_new));
        assert_eq!(km.backend().history(), &["key-1", "key-2"]);
    }

    #[test]
    fn a_tampered_head_fails_verification() {
        let km = KeyManager::new(LocalKms::new());
        let s = km.sign_sth(&head(1));
        assert!(
            !km.verify_sth(&head(2), &s),
            "signature must not verify over a different head"
        );
    }

    #[test]
    fn an_unknown_key_id_fails_closed() {
        let km = KeyManager::new(LocalKms::new());
        let h = head(1);
        let mut s = km.sign_sth(&h);
        s.key_id = "key-does-not-exist".into();
        assert!(!km.verify_sth(&h, &s));
    }
}
