//! Enforcement attestation: cryptographic proof that a tool call passed through the governing proxy
//! (model v2, phase 4b).
//!
//! Governance is only real if it cannot be skipped. Two transports give different guarantees:
//!   - stdio: the proxy SPAWNS the tool server and owns its stdio (kill_on_drop), so the agent has
//!     no out-of-band path to the server. Unavoidability is structural; no token is needed.
//!   - HTTP: the agent talks to the proxy over the network. Nothing structurally stops it pointing
//!     at the tool server directly. To close that, the proxy stamps a short-lived, signed
//!     attestation on every forwarded request, and the tool server (or a thin guard in front of it)
//!     rejects any request without a fresh, valid one. The proxy holds the signing key; the agent
//!     never does, so it cannot forge the proof and cannot reach a guarded server un-governed.
//!
//! The token is deliberately tiny and stateless: `<issued_ms>.<session>.<sig_hex>`, signed over
//! `<issued_ms>.<session>`. Verification checks the signature under the pinned proxy key and that the
//! token is fresh (bounded age), so a captured token cannot be replayed indefinitely.

use crate::sign::{verify_ed25519, Signer};

fn signing_bytes(issued_ms: u64, session: &str) -> Vec<u8> {
    format!("{issued_ms}.{session}").into_bytes()
}

/// Issue an attestation token for a session at `issued_ms`, signed by the proxy key.
pub fn issue(signer: &dyn Signer, session: &str, issued_ms: u64) -> String {
    let sig = signer.sign(&signing_bytes(issued_ms, session));
    format!("{issued_ms}.{session}.{}", hex::encode(sig))
}

/// Verify an attestation token against the pinned proxy public key: the signature must check out and
/// the token must be no older than `max_age_ms` (replay bound). Fail-closed on any parse error.
pub fn verify(pubkey: &[u8], token: &str, now_ms: u64, max_age_ms: u64) -> bool {
    // Split into exactly three parts from the right, since a session may itself contain dots is not
    // allowed here: sessions are proxy-generated ids without dots, so a plain 3-way split is safe.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let issued_ms: u64 = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let session = parts[1];
    let sig = match hex::decode(parts[2]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Freshness: reject a token issued in the future (clock skew tolerance is the caller's max_age)
    // or older than the allowed window.
    if now_ms.saturating_sub(issued_ms) > max_age_ms {
        return false;
    }
    verify_ed25519(pubkey, &signing_bytes(issued_ms, session), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{Ed25519Signer, Signer};

    #[test]
    fn a_fresh_token_verifies_under_the_proxy_key() {
        let signer = Ed25519Signer::generate();
        let pk = signer.public_key();
        let tok = issue(&signer, "sess-1", 1000);
        assert!(verify(&pk, &tok, 1500, 5000), "fresh, correctly signed");
    }

    #[test]
    fn a_stale_token_is_rejected() {
        let signer = Ed25519Signer::generate();
        let pk = signer.public_key();
        let tok = issue(&signer, "sess-1", 1000);
        assert!(!verify(&pk, &tok, 1000 + 6000, 5000), "older than max_age");
    }

    #[test]
    fn a_forged_or_wrong_key_token_is_rejected() {
        let signer = Ed25519Signer::generate();
        let tok = issue(&signer, "sess-1", 1000);
        // Different key: no verification.
        let other = Ed25519Signer::generate().public_key();
        assert!(!verify(&other, &tok, 1500, 5000));
        // Tampered session: signature no longer matches.
        let tampered = tok.replace("sess-1", "sess-evil");
        assert!(!verify(&signer.public_key(), &tampered, 1500, 5000));
    }

    #[test]
    fn a_malformed_token_fails_closed() {
        let pk = Ed25519Signer::generate().public_key();
        assert!(!verify(&pk, "not-a-token", 1000, 5000));
        assert!(!verify(&pk, "1000.sess", 1000, 5000));
    }
}
