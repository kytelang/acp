//! Continuous export to a customer warehouse (decision F7).
//!
//! Customers want redacted evidence streamed into their own object store / warehouse (S3 with
//! object-lock, Snowflake, BigQuery) and they must be able to re-verify it independently against
//! the exported signed tree head, without trusting our service. An export row carries the leaf
//! record (which never holds raw arguments, only the args hash) plus its position; re-verification
//! recomputes the leaf hash and checks inclusion against the STH root.

use crate::canonical::canonical_bytes;
use crate::merkle::{leaf_hash, verify_inclusion, Hash};
use serde_json::Value;

/// One exported evidence row.
#[derive(Debug, Clone)]
pub struct ExportRow {
    pub record: Value,
    pub index: usize,
    pub tree_size: usize,
}

/// Re-verify an exported row against an inclusion proof and the STH root. This is what a customer
/// runs on their own to confirm the warehouse copy is authentic and complete for that leaf.
pub fn verify_row(row: &ExportRow, proof: &[Hash], sth_root: Hash) -> bool {
    let leaf = leaf_hash(&canonical_bytes(&row.record));
    verify_inclusion(leaf, row.index, row.tree_size, proof, sth_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleLog;
    use serde_json::json;

    #[test]
    fn an_exported_row_reverifies_against_the_sth() {
        // Build a log exactly as the ledger would: leaves are canonical record bytes.
        let mut log = MerkleLog::new();
        let records: Vec<Value> = (0..6)
            .map(|i| json!({"seq": i, "tool": "payments.charge", "verdict": "deny"}))
            .collect();
        for r in &records {
            log.append(&canonical_bytes(r));
        }
        let root = log.root();
        let idx = 3;
        let proof = log.inclusion_proof(idx).unwrap();
        let row = ExportRow {
            record: records[idx].clone(),
            index: idx,
            tree_size: log.size(),
        };
        assert!(
            verify_row(&row, &proof, root),
            "authentic export row must re-verify"
        );

        // A row whose record was altered in the warehouse must not verify.
        let mut tampered = row.clone();
        tampered.record = json!({"seq": 3, "tool": "payments.charge", "verdict": "allow"});
        assert!(
            !verify_row(&tampered, &proof, root),
            "tampered export row must fail"
        );
    }
}
