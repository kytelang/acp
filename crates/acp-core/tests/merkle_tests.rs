//! The trust suite: the verifiable log must catch edits and rewrites.

use acp_core::canonical::canonical_bytes;
use acp_core::merkle::{leaf_hash, root_of, verify_consistency, verify_inclusion, MerkleLog};

fn record_bytes(seq: u64, verdict: &str) -> Vec<u8> {
    // A stand-in evidence record; canonical bytes are what the log commits to.
    let v = serde_json::json!({ "seq": seq, "verdict": verdict, "tool": "payments.charge" });
    canonical_bytes(&v)
}

#[test]
fn root_is_deterministic() {
    let mut a = MerkleLog::new();
    let mut b = MerkleLog::new();
    for i in 0..7 {
        a.append(&record_bytes(i, "allow"));
        b.append(&record_bytes(i, "allow"));
    }
    assert_eq!(a.root(), b.root());
    assert_eq!(a.size(), 7);
}

#[test]
fn inclusion_proof_verifies_every_leaf() {
    let mut log = MerkleLog::new();
    for i in 0..11 {
        log.append(&record_bytes(i, "allow"));
    }
    let root = log.root();
    let size = log.size();
    for i in 0..size {
        let leaf = log.leaf(i).unwrap();
        let proof = log.inclusion_proof(i).unwrap();
        assert!(
            verify_inclusion(leaf, i, size, &proof, root),
            "leaf {i} should verify"
        );
        // A wrong leaf at the same index must not verify.
        let bogus = leaf_hash(b"not the real record");
        assert!(!verify_inclusion(bogus, i, size, &proof, root));
    }
}

#[test]
fn tamper_changes_the_root() {
    // Build a log, remember its signed root, then edit one record's bytes.
    let mut log = MerkleLog::new();
    let mut leaves = Vec::new();
    for i in 0..9 {
        let bytes = record_bytes(i, "allow");
        leaves.push(leaf_hash(&bytes));
        log.append(&bytes);
    }
    let committed_root = log.root();

    // An auditor later recomputes the root from the (tampered) stored records.
    leaves[4] = leaf_hash(&record_bytes(4, "deny")); // someone flipped a verdict
    let recomputed = root_of(&leaves);

    assert_ne!(
        committed_root, recomputed,
        "editing a record must change the Merkle root"
    );
}

#[test]
fn consistency_proof_confirms_append_only() {
    let mut log = MerkleLog::new();
    for i in 0..6 {
        log.append(&record_bytes(i, "allow"));
    }
    let old_size = log.size();
    let old_root = log.root();

    // Append more evidence.
    for i in 6..13 {
        log.append(&record_bytes(i, "allow"));
    }
    let new_size = log.size();
    let new_root = log.root();

    let proof = log.consistency_proof(old_size).unwrap();
    assert!(
        verify_consistency(old_size, new_size, &proof, old_root, new_root),
        "a genuine append must produce a valid consistency proof"
    );

    // A tampered second root must fail the consistency check.
    let mut bad = new_root;
    bad[0] ^= 0xff;
    assert!(!verify_consistency(
        old_size, new_size, &proof, old_root, bad
    ));
}

#[test]
fn rfc6962_known_answers() {
    use acp_core::merkle::{leaf_hash, root_of};
    // MTH of the empty tree is SHA-256("") per RFC 6962.
    assert_eq!(
        hex::encode(root_of(&[])),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // Leaf hash uses the 0x00 domain prefix: leaf_hash("") == SHA-256(0x00).
    assert_eq!(
        hex::encode(leaf_hash(b"")),
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    );
    // A one-leaf tree's root is that leaf's hash.
    assert_eq!(root_of(&[leaf_hash(b"")]), leaf_hash(b""));
}
