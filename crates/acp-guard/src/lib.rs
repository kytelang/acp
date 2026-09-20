//! acp-guard: the enforcement guard sidecar (gap-closure, containment plane).
//!
//! `docs/design/enforcement.md` describes a thin guard that sits in front of a tool server and
//! verifies the `x-acp-enforcement` attestation the governing proxy stamps on every forwarded
//! request. Without a fresh, valid token the request is refused, so an agent that points at the
//! tool server directly (bypassing the proxy) cannot reach it. This crate ships that guard as a
//! first-class sidecar instead of leaving it for each deployment to build.
//!
//! The decision itself is a pure function so it is unit-testable without a socket: given the pinned
//! proxy public key, the header value (if any) and the clock, it returns forward or reject.

/// The guard's decision for one request.
#[derive(Debug, Clone, PartialEq)]
pub enum GuardDecision {
    /// The attestation is present, fresh and correctly signed: forward to the tool server.
    Forward,
    /// Refuse with a reason (recorded and returned as 401). Fail-closed on any absence or error.
    Reject(String),
}

/// Decide whether a request carrying `header` (the `x-acp-enforcement` value, if present) may pass.
/// Fail-closed: a missing or malformed or stale or wrongly-signed token is always a reject.
pub fn decide(
    pubkey: &[u8],
    header: Option<&str>,
    now_ms: u64,
    max_age_ms: u64,
) -> GuardDecision {
    match header {
        None => GuardDecision::Reject("missing x-acp-enforcement attestation".into()),
        Some(tok) if tok.is_empty() => {
            GuardDecision::Reject("empty x-acp-enforcement attestation".into())
        }
        Some(tok) => {
            if acp_core::attest::verify(pubkey, tok, now_ms, max_age_ms) {
                GuardDecision::Forward
            } else {
                GuardDecision::Reject(
                    "invalid or stale x-acp-enforcement attestation (fail-closed)".into(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_core::attest::issue;
    use acp_core::sign::{Ed25519Signer, Signer};

    #[test]
    fn a_fresh_stamped_request_is_forwarded() {
        let s = Ed25519Signer::generate();
        let tok = issue(&s, "sess-1", 1000);
        assert_eq!(decide(&s.public_key(), Some(&tok), 1200, 5000), GuardDecision::Forward);
    }

    #[test]
    fn a_request_without_the_header_is_refused() {
        let s = Ed25519Signer::generate();
        assert!(matches!(decide(&s.public_key(), None, 1200, 5000), GuardDecision::Reject(_)));
        assert!(matches!(decide(&s.public_key(), Some(""), 1200, 5000), GuardDecision::Reject(_)));
    }

    #[test]
    fn a_stale_or_forged_token_is_refused() {
        let s = Ed25519Signer::generate();
        let tok = issue(&s, "sess-1", 1000);
        // stale
        assert!(matches!(decide(&s.public_key(), Some(&tok), 1000 + 6000, 5000), GuardDecision::Reject(_)));
        // wrong key
        let other = Ed25519Signer::generate().public_key();
        assert!(matches!(decide(&other, Some(&tok), 1200, 5000), GuardDecision::Reject(_)));
    }
}
