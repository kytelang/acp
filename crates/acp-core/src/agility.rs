//! Crypto-agility for long-term evidence validity (decision v3.3).
//!
//! Evidence must stay verifiable for years, across a change of hash or signature scheme. Because
//! every record stamps the algorithms that produced it (provenance.algo_hash/algo_sig), verification
//! dispatches on the stamped id rather than assuming one fixed scheme. Introducing a second scheme is
//! then additive: new records use it, old records keep verifying under their original id. This is the
//! verifier registry that makes that property concrete and testable.

use std::collections::HashMap;

/// A signature verifier for one named algorithm: (public_key, message, signature) -> valid.
type VerifyFn = fn(&[u8], &[u8], &[u8]) -> bool;

#[derive(Default)]
pub struct AgileVerifier {
    by_alg: HashMap<String, VerifyFn>,
}

impl AgileVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the verifier for an algorithm id.
    pub fn register(&mut self, alg: &str, f: VerifyFn) {
        self.by_alg.insert(alg.to_string(), f);
    }

    /// Verify a record's signature using the algorithm it was stamped with. An unknown algorithm is
    /// a clean `false` (fail-closed), never a panic, so an old record never crashes a new verifier.
    pub fn verify(&self, alg: &str, public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        match self.by_alg.get(alg) {
            Some(f) => f(public_key, msg, sig),
            None => false,
        }
    }

    pub fn knows(&self, alg: &str) -> bool {
        self.by_alg.contains_key(alg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{verify_ed25519, Ed25519Signer, Signer};

    // A stand-in "future" scheme registered alongside ed25519 to prove additivity. It is a distinct
    // algorithm id with its own verify function; the point is that adding it does not disturb the
    // existing one.
    fn always_false(_pk: &[u8], _m: &[u8], _s: &[u8]) -> bool {
        false
    }

    #[test]
    fn an_old_record_verifies_after_a_new_scheme_is_added() {
        let signer = Ed25519Signer::generate();
        let msg = b"tree head bytes";
        let sig = signer.sign(msg);

        let mut v = AgileVerifier::new();
        v.register("ed25519", verify_ed25519);
        assert!(
            v.verify("ed25519", &signer.public_key(), msg, &sig),
            "verifies under ed25519"
        );

        // Introduce a second scheme. The old ed25519 record must still verify unchanged.
        v.register("future-sig-v2", always_false);
        assert!(v.knows("future-sig-v2"));
        assert!(
            v.verify("ed25519", &signer.public_key(), msg, &sig),
            "old record still verifies"
        );
    }

    #[test]
    fn an_unknown_algorithm_fails_closed_not_panics() {
        let v = AgileVerifier::new();
        assert!(!v.verify("nonexistent", b"", b"", b""));
    }
}
