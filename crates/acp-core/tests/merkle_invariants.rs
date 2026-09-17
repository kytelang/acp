//! H2.4 property/invariant tests for the Merkle log. Rather than a fuzzer, these exhaustively check
//! the two core transparency invariants across many tree sizes and every leaf index, which is
//! deterministic and catches structural regressions in proof generation/verification.

use acp_core::merkle::{root_of, verify_consistency, verify_inclusion, MerkleLog};

fn log_of(n: usize) -> MerkleLog {
    let mut m = MerkleLog::new();
    for i in 0..n {
        m.append(format!("leaf-{i}").as_bytes());
    }
    m
}

#[test]
fn inclusion_holds_for_every_leaf_of_every_size() {
    for size in 1..=64usize {
        let m = log_of(size);
        let root = m.root();
        for i in 0..size {
            let proof = m.inclusion_proof(i).expect("proof exists");
            let leaf = m.leaf(i).expect("leaf exists");
            assert!(
                verify_inclusion(leaf, i, size, &proof, root),
                "inclusion must hold for leaf {i} of size {size}"
            );
            // A wrong index must not verify (proof is index-bound).
            if size > 1 {
                let bad_index = (i + 1) % size;
                assert!(
                    !verify_inclusion(leaf, bad_index, size, &proof, root) || bad_index == i,
                    "proof for leaf {i} must not verify at index {bad_index} (size {size})"
                );
            }
        }
    }
}

#[test]
fn consistency_holds_between_every_prefix_and_the_full_tree() {
    for size in 1..=48usize {
        let full = log_of(size);
        let second_root = full.root();
        for first in 1..=size {
            let prefix = log_of(first);
            let first_root = prefix.root();
            let proof = full.consistency_proof(first).expect("consistency proof");
            assert!(
                verify_consistency(first, size, &proof, first_root, second_root),
                "consistency must hold from {first} to {size}"
            );
        }
    }
}

#[test]
fn a_changed_leaf_changes_the_root() {
    let a = log_of(10);
    let mut leaves: Vec<_> = (0..10).map(|i| a.leaf(i).unwrap()).collect();
    let r1 = root_of(&leaves);
    // Flip one leaf; the root must differ (tamper-evidence).
    leaves[3] = acp_core::merkle::leaf_hash(b"tampered");
    let r2 = root_of(&leaves);
    assert_ne!(r1, r2, "changing any leaf must change the root");
}

#[test]
fn inclusion_proof_cost_scales_logarithmically() {
    // H2.1 (cost model): the per-record proof cost must grow with log2(n), not n, which is what
    // makes hundreds of millions of records tractable. Validate the scaling on tractable sizes;
    // the full 100M wall-clock validation is a separate load run.
    for pow in [10u32, 12, 14, 16] {
        let size = 1usize << pow;
        let m = log_of(size);
        let proof = m.inclusion_proof(size / 2).expect("proof");
        // An RFC 6962 inclusion proof is at most ceil(log2(n)) hashes.
        assert!(
            proof.len() as u32 <= pow + 1,
            "proof for size 2^{pow} was {} hashes, expected <= {}",
            proof.len(),
            pow + 1
        );
    }
}
