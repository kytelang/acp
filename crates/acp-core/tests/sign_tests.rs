use acp_core::merkle::MerkleLog;
use acp_core::sign::{sign_sth, verify_sth, Ed25519Signer, SignedTreeHead, Signer};

#[test]
fn ed25519_signs_and_verifies_a_tree_head() {
    let signer = Ed25519Signer::generate();
    let mut log = MerkleLog::new();
    for i in 0..5u64 {
        log.append(format!("record {i}").as_bytes());
    }
    let sth = SignedTreeHead {
        tree_size: log.size() as u64,
        root_hash: log.root(),
        timestamp_ms: 1_700_000_000_000,
    };
    let sig = sign_sth(&signer, &sth);
    let pk = signer.public_key();
    assert!(
        verify_sth(&pk, &sth, &sig),
        "valid STH signature must verify"
    );

    // tampered root must not verify under the same signature
    let mut bad = sth.clone();
    bad.root_hash[0] ^= 0xff;
    assert!(!verify_sth(&pk, &bad, &sig));
}

#[test]
fn seed_roundtrip_is_stable() {
    let s = Ed25519Signer::generate();
    let seed = s.seed();
    let s2 = Ed25519Signer::from_seed(&seed);
    assert_eq!(s.public_key(), s2.public_key());
}
