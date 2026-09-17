//! External transparency anchoring (decision H0.2).
//!
//! Signing proves who wrote a head; anchoring proves *when* and to a party outside our trust
//! boundary, so we cannot silently rewrite history even if our own signing key is compromised.
//! The production anchor is a public transparency log (Rekor) or an RFC 3161 timestamp authority.
//! Both satisfy the same contract: submit a signed head, get back a receipt carrying an anchored
//! timestamp and a proof, and later verify a head against that receipt.
//!
//! `LocalAnchor` is a self-contained backend that implements the contract for tests and offline
//! dev: it records each submitted head under a monotonic anchor id and a caller-supplied trusted
//! time, and re-checks a head against its receipt by content hash. Pointing at real Rekor or a TSA
//! is a new `Anchor` impl, not a change above this seam.

use crate::canonical::sha256_hex_bytes;
use crate::sign::{sth_bytes, SignedTreeHead};
use std::collections::HashMap;

/// Proof that a head was anchored: an id in the external log and the trusted anchor time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceipt {
    pub anchor_id: String,
    /// Trusted time from the external anchor, the RFC 3161-class time reference.
    pub anchored_ms: u64,
    /// Content hash of the head as anchored, so a later head can be cross-checked.
    pub head_hash: String,
}

/// The contract a transparency anchor satisfies (Rekor, a TSA, or the local backend).
pub trait Anchor {
    /// Submit a head for anchoring at trusted time `now_ms`; returns the receipt.
    fn submit(&mut self, sth: &SignedTreeHead, now_ms: u64) -> AnchorReceipt;
    /// Confirm the head matches what was anchored under this receipt.
    fn verify(&self, sth: &SignedTreeHead, receipt: &AnchorReceipt) -> bool;
}

fn head_hash(sth: &SignedTreeHead) -> String {
    sha256_hex_bytes(&sth_bytes(sth))
}

/// In-process anchor: keeps every submitted head so receipts stay checkable. Local/dev/test only.
#[derive(Debug, Default)]
pub struct LocalAnchor {
    log: HashMap<String, (u64, String)>,
    counter: u64,
}

impl LocalAnchor {
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of heads anchored so far (the external log size an auditor could cross-check).
    pub fn len(&self) -> usize {
        self.log.len()
    }
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }
}

impl Anchor for LocalAnchor {
    fn submit(&mut self, sth: &SignedTreeHead, now_ms: u64) -> AnchorReceipt {
        self.counter += 1;
        let anchor_id = format!("anchor-{}", self.counter);
        let hash = head_hash(sth);
        self.log.insert(anchor_id.clone(), (now_ms, hash.clone()));
        AnchorReceipt {
            anchor_id,
            anchored_ms: now_ms,
            head_hash: hash,
        }
    }

    fn verify(&self, sth: &SignedTreeHead, receipt: &AnchorReceipt) -> bool {
        match self.log.get(&receipt.anchor_id) {
            // The head must hash to what was anchored, and the receipt must not have been edited.
            Some((ts, hash)) => {
                *ts == receipt.anchored_ms
                    && *hash == receipt.head_hash
                    && receipt.head_hash == head_hash(sth)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(size: u64) -> SignedTreeHead {
        SignedTreeHead {
            tree_size: size,
            root_hash: [3u8; 32],
            timestamp_ms: size,
        }
    }

    #[test]
    fn an_anchored_head_is_cross_checkable_with_a_trusted_time() {
        let mut a = LocalAnchor::new();
        let h = head(5);
        let r = a.submit(&h, 1_700_000_000_000);
        assert!(a.verify(&h, &r));
        assert_eq!(r.anchored_ms, 1_700_000_000_000, "trusted time reference");
    }

    #[test]
    fn a_rewritten_head_does_not_match_its_anchor() {
        let mut a = LocalAnchor::new();
        let r = a.submit(&head(5), 1_000);
        // Attacker presents a different head under the same receipt.
        assert!(!a.verify(&head(6), &r), "a different head must not verify");
    }

    #[test]
    fn a_forged_receipt_time_is_rejected() {
        let mut a = LocalAnchor::new();
        let h = head(5);
        let mut r = a.submit(&h, 1_000);
        r.anchored_ms = 999; // backdate the receipt
        assert!(!a.verify(&h, &r));
    }
}
