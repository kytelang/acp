//! F12 air-gapped profile: the full gate -> evidence -> verify chain must work with egress
//! disabled. This test composes the real building blocks (Merkle log, signed tree head via the KMS
//! seam, offline transparency anchor) and verifies inclusion, signature, and anchor with zero
//! network calls, which is exactly the air-gapped operating mode: an internal anchor, offline
//! signing, and evidence that verifies without reaching any external service.

use acp_core::anchor::{Anchor, LocalAnchor};
use acp_core::canonical::canonical_bytes;
use acp_core::keymgr::{KeyManager, LocalKms};
use acp_core::merkle::{verify_inclusion, MerkleLog};
use acp_core::sign::SignedTreeHead;
use serde_json::json;

#[test]
fn gate_evidence_and_verify_work_fully_offline() {
    // 1. Gate: record a few decisions as Merkle leaves (no network).
    let mut log = MerkleLog::new();
    let records: Vec<_> = (0..5)
        .map(|i| json!({"seq": i, "tool": "payments.charge", "verdict": "deny"}))
        .collect();
    for r in &records {
        log.append(&canonical_bytes(r));
    }
    let root = log.root();

    // 2. Evidence: sign the tree head with the KMS seam (LocalKms = internal signer, no cloud).
    let km = KeyManager::new(LocalKms::new());
    let sth = SignedTreeHead {
        tree_size: log.size() as u64,
        root_hash: root,
        timestamp_ms: 1_700,
    };
    let signed = km.sign_sth(&sth);

    // 3. Anchor: submit the head to an internal (offline) transparency anchor.
    let mut anchor = LocalAnchor::new();
    let receipt = anchor.submit(&sth, 1_700);

    // 4. Verify the whole chain offline: signature, an inclusion proof, and the anchor receipt.
    assert!(
        km.verify_sth(&sth, &signed),
        "STH signature verifies offline"
    );

    let idx = 2;
    let proof = log.inclusion_proof(idx).unwrap();
    let leaf = log.leaf(idx).unwrap();
    assert!(
        verify_inclusion(leaf, idx, log.size(), &proof, root),
        "inclusion verifies offline"
    );

    assert!(
        anchor.verify(&sth, &receipt),
        "anchor receipt verifies offline"
    );

    // A tampered head must fail every check, proving the chain is load-bearing, not decorative.
    let bad = SignedTreeHead {
        tree_size: sth.tree_size,
        root_hash: [9u8; 32],
        timestamp_ms: sth.timestamp_ms,
    };
    assert!(
        !km.verify_sth(&bad, &signed),
        "tampered head fails signature"
    );
    assert!(
        !anchor.verify(&bad, &receipt),
        "tampered head fails the anchor"
    );
}
