//! Signed policy provenance and who-can-push control (decision H0.6).
//!
//! A policy is enforcement code: if an attacker can push a policy, they can disable the gate. So a
//! policy must be signed by an authorised author and verified before it is loaded, and only an
//! allowlisted principal may push. This signs the policy content hash and checks the pusher against
//! an allowlist. It composes with the meta-audit log (a policy change is a meta event).

use crate::sign::{verify_ed25519, Signer};
use std::collections::BTreeSet;

/// A policy hash signed by its author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPolicy {
    pub policy_hash: String,
    pub author: String,
    pub sig: Vec<u8>,
}

/// Sign a policy's content hash as `author`. The signed message binds author + hash so a signature
/// cannot be moved to a different policy or author.
pub fn sign_policy<S: Signer + ?Sized>(
    signer: &S,
    policy_hash: &str,
    author: &str,
) -> SignedPolicy {
    let msg = format!("{author}|{policy_hash}");
    SignedPolicy {
        policy_hash: policy_hash.to_string(),
        author: author.to_string(),
        sig: signer.sign(msg.as_bytes()),
    }
}

/// Verify the signature over (author, policy_hash) under the author's public key.
pub fn verify_policy(public_key: &[u8], signed: &SignedPolicy) -> bool {
    let msg = format!("{}|{}", signed.author, signed.policy_hash);
    verify_ed25519(public_key, msg.as_bytes(), &signed.sig)
}

/// Who may push a policy. Loading a policy checks both a valid signature AND membership here.
#[derive(Debug, Default)]
pub struct PushAllowlist(BTreeSet<String>);

impl PushAllowlist {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn authorise(&mut self, principal: &str) {
        self.0.insert(principal.to_string());
    }
    pub fn revoke(&mut self, principal: &str) {
        self.0.remove(principal);
    }
    pub fn can_push(&self, principal: &str) -> bool {
        self.0.contains(principal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    #[test]
    fn a_validly_signed_policy_from_an_allowed_author_is_accepted() {
        let signer = Ed25519Signer::generate();
        let signed = sign_policy(&signer, "deadbeef", "alice");
        assert!(verify_policy(&signer.public_key(), &signed));
        let mut allow = PushAllowlist::new();
        allow.authorise("alice");
        assert!(allow.can_push("alice"));
    }

    #[test]
    fn a_signature_cannot_be_moved_to_a_different_policy() {
        let signer = Ed25519Signer::generate();
        let mut signed = sign_policy(&signer, "hashA", "alice");
        signed.policy_hash = "hashB".into(); // attacker swaps the policy
        assert!(
            !verify_policy(&signer.public_key(), &signed),
            "signature no longer matches"
        );
    }

    #[test]
    fn a_revoked_pusher_cannot_push() {
        let mut allow = PushAllowlist::new();
        allow.authorise("bob");
        allow.revoke("bob");
        assert!(!allow.can_push("bob"));
    }
}
