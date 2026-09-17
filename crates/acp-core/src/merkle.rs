//! RFC 6962-style verifiable log (Certificate Transparency Merkle tree).
//!
//! v0 uses a hand-checked implementation over `sha2` (decision D3's stated fallback if the
//! young `ct-merkle` crate does not vet out). Domain separation follows RFC 6962:
//! leaves are prefixed `0x00`, internal nodes `0x01`. Supports inclusion proofs and
//! consistency proofs (the append-only guarantee).

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// Leaf hash of raw record bytes: `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(data);
    h.finalize().into()
}

/// Internal node hash: `SHA-256(0x01 || left || right)`.
fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (n >= 2).
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle Tree Hash of a slice of leaf hashes (RFC 6962 MTH).
pub fn root_of(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::new().finalize().into(), // MTH({}) = SHA-256("")
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

/// An append-only log of leaf hashes.
#[derive(Debug, Default, Clone)]
pub struct MerkleLog {
    leaves: Vec<Hash>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append raw record bytes; returns the 0-based leaf index.
    pub fn append(&mut self, record_bytes: &[u8]) -> usize {
        self.leaves.push(leaf_hash(record_bytes));
        self.leaves.len() - 1
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    pub fn root(&self) -> Hash {
        root_of(&self.leaves)
    }

    pub fn leaf(&self, index: usize) -> Option<Hash> {
        self.leaves.get(index).copied()
    }

    /// Inclusion (audit) proof for `index` in the current tree (RFC 6962 PATH).
    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<Hash>> {
        if index >= self.leaves.len() {
            return None;
        }
        Some(path(index, &self.leaves))
    }

    /// Consistency proof between an earlier size `m` and the current size (RFC 6962 PROOF).
    pub fn consistency_proof(&self, m: usize) -> Option<Vec<Hash>> {
        let n = self.leaves.len();
        if m == 0 || m > n {
            return None;
        }
        if m == n {
            return Some(vec![]);
        }
        Some(subproof(m, &self.leaves, true))
    }
}

fn path(index: usize, leaves: &[Hash]) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = split_point(n);
    if index < k {
        let mut p = path(index, &leaves[..k]);
        p.push(root_of(&leaves[k..]));
        p
    } else {
        let mut p = path(index - k, &leaves[k..]);
        p.push(root_of(&leaves[..k]));
        p
    }
}

fn subproof(m: usize, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if b { vec![] } else { vec![root_of(leaves)] };
    }
    let k = split_point(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(root_of(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root_of(&leaves[..k]));
        p
    }
}

/// Verify an inclusion proof: does `leaf` at `index` in a tree of `size` produce `root`?
pub fn verify_inclusion(leaf: Hash, index: usize, size: usize, proof: &[Hash], root: Hash) -> bool {
    if index >= size {
        return false;
    }
    match reconstruct(leaf, index, size, proof) {
        Some(h) => h == root,
        None => false,
    }
}

fn reconstruct(leaf: Hash, index: usize, size: usize, proof: &[Hash]) -> Option<Hash> {
    if size == 1 {
        return if index == 0 && proof.is_empty() {
            Some(leaf)
        } else {
            None
        };
    }
    let (top, rest) = proof.split_last()?;
    let k = split_point(size);
    if index < k {
        let left = reconstruct(leaf, index, k, rest)?;
        Some(node_hash(&left, top))
    } else {
        let right = reconstruct(leaf, index - k, size - k, rest)?;
        Some(node_hash(top, &right))
    }
}

/// Verify a consistency proof between `(first, first_root)` and `(second, second_root)`.
/// Proves the first `first` leaves were neither altered nor reordered (append-only).
pub fn verify_consistency(
    first: usize,
    second: usize,
    proof: &[Hash],
    first_root: Hash,
    second_root: Hash,
) -> bool {
    if first == 0 {
        return true;
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    if first > second {
        return false;
    }

    let mut fnr = first - 1;
    let mut sn = second - 1;
    while fnr & 1 == 1 {
        fnr >>= 1;
        sn >>= 1;
    }

    let mut it = proof.iter();
    let (mut fr, mut sr) = if fnr != 0 {
        let seed = match it.next() {
            Some(h) => *h,
            None => return false,
        };
        (seed, seed)
    } else {
        (first_root, first_root)
    };

    while fnr != 0 {
        if fnr & 1 == 1 || fnr == sn {
            let c = match it.next() {
                Some(h) => *h,
                None => return false,
            };
            fr = node_hash(&c, &fr);
            sr = node_hash(&c, &sr);
            while fnr != 0 && fnr & 1 == 0 {
                fnr >>= 1;
                sn >>= 1;
            }
        } else {
            let c = match it.next() {
                Some(h) => *h,
                None => return false,
            };
            sr = node_hash(&sr, &c);
        }
        fnr >>= 1;
        sn >>= 1;
    }

    while sn != 0 {
        let c = match it.next() {
            Some(h) => *h,
            None => return false,
        };
        sr = node_hash(&sr, &c);
        sn >>= 1;
    }

    fr == first_root && sr == second_root && it.next().is_none()
}
