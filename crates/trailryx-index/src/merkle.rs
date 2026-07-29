//! Merkle trees, RFC 6962 shape.
//!
//! Certificate Transparency's tree is used rather than a padded binary one for
//! a specific reason: it supports a **consistency proof**, the statement that a
//! tree of size n contains everything a tree of size m contained, in the same
//! order. That is the machine-checkable form of "the log was only appended to",
//! which is the first of the three things this store has to prove.
//!
//! # Domain separation
//!
//! Leaves hash with a `0x00` prefix and internal nodes with `0x01`. Without it,
//! an attacker could present an internal node as if it were a leaf and a tree
//! could be reinterpreted with different contents but the same root. The prefix
//! costs one byte and closes a whole class of second-preimage attacks.
//!
//! # Shape
//!
//! The tree is not padded to a power of two. For `n > 1` the left subtree holds
//! the largest power of two below `n` and the right holds the remainder, which
//! is what makes append cheap and consistency proofs possible.

use trailryx_crypto::{Digest, Hash, Sha384, digests_equal};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Hash of an empty tree.
pub fn empty_root() -> Hash {
    Sha384::digest(&[])
}

pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha384::new();
    h.update(&[LEAF_PREFIX]);
    h.update(data);
    h.finish()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha384::new();
    h.update(&[NODE_PREFIX]);
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    h.finish()
}

/// Largest power of two strictly less than `n`. Defined for `n >= 2`.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// An append-only Merkle tree over a list of leaves.
///
/// Leaves are kept rather than only their hashes so proofs can be produced on
/// demand. Recomputing from leaves is O(n) per proof, which is the deliberate
/// stage-3 trade: correctness first, and a cached node layer later once there
/// is something to measure regressions against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MerkleTree {
    leaves: Vec<Hash>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn from_leaf_hashes(leaves: Vec<Hash>) -> Self {
        Self { leaves }
    }

    pub fn push_data(&mut self, data: &[u8]) -> usize {
        self.leaves.push(leaf_hash(data));
        self.leaves.len() - 1
    }

    pub fn push_leaf(&mut self, leaf: Hash) -> usize {
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaf(&self, i: usize) -> Option<Hash> {
        self.leaves.get(i).copied()
    }

    pub fn root(&self) -> Hash {
        Self::mth(&self.leaves)
    }

    /// Root of a prefix, which is the root the tree had when it was that size.
    pub fn root_at(&self, size: usize) -> Option<Hash> {
        if size > self.leaves.len() {
            return None;
        }
        Some(Self::mth(&self.leaves[..size]))
    }

    fn mth(leaves: &[Hash]) -> Hash {
        match leaves.len() {
            0 => empty_root(),
            1 => leaves[0],
            n => {
                let k = split(n);
                node_hash(&Self::mth(&leaves[..k]), &Self::mth(&leaves[k..]))
            }
        }
    }

    /// The sibling path proving leaf `index` belongs to the tree of size `size`.
    pub fn inclusion_proof(&self, index: usize, size: usize) -> Option<InclusionProof> {
        if index >= size || size > self.leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        Self::path(&self.leaves[..size], index, &mut path);
        Some(InclusionProof { index, size, path })
    }

    fn path(leaves: &[Hash], m: usize, out: &mut Vec<Hash>) {
        let n = leaves.len();
        if n <= 1 {
            return;
        }
        let k = split(n);
        if m < k {
            Self::path(&leaves[..k], m, out);
            out.push(Self::mth(&leaves[k..]));
        } else {
            Self::path(&leaves[k..], m - k, out);
            out.push(Self::mth(&leaves[..k]));
        }
    }

    /// Proof that the tree of size `new_size` extends the one of size `old_size`.
    pub fn consistency_proof(&self, old_size: usize, new_size: usize) -> Option<ConsistencyProof> {
        if old_size == 0 || old_size > new_size || new_size > self.leaves.len() {
            return None;
        }
        let mut nodes = Vec::new();
        Self::subproof(&self.leaves[..new_size], old_size, true, &mut nodes);
        Some(ConsistencyProof {
            old_size,
            new_size,
            nodes,
        })
    }

    fn subproof(leaves: &[Hash], m: usize, b: bool, out: &mut Vec<Hash>) {
        let n = leaves.len();
        if m == n {
            if !b {
                out.push(Self::mth(leaves));
            }
            return;
        }
        let k = split(n);
        if m <= k {
            Self::subproof(&leaves[..k], m, b, out);
            out.push(Self::mth(&leaves[k..]));
        } else {
            Self::subproof(&leaves[k..], m - k, false, out);
            out.push(Self::mth(&leaves[..k]));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: usize,
    pub size: usize,
    pub path: Vec<Hash>,
}

impl InclusionProof {
    /// Recompute the root from a leaf and the sibling path.
    pub fn verify(&self, leaf: Hash, root: Hash) -> bool {
        if self.index >= self.size {
            return false;
        }
        let mut fn_ = self.index;
        let mut sn = self.size - 1;
        let mut acc = leaf;
        let mut it = self.path.iter();

        while sn > 0 {
            let Some(sibling) = it.next() else {
                return false;
            };
            if fn_ & 1 == 1 || fn_ == sn {
                acc = node_hash(sibling, &acc);
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            } else {
                acc = node_hash(&acc, sibling);
            }
            fn_ >>= 1;
            sn >>= 1;
        }

        it.next().is_none() && digests_equal(&acc, &root)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub old_size: usize,
    pub new_size: usize,
    pub nodes: Vec<Hash>,
}

impl ConsistencyProof {
    /// Check that `new_root` is the root of a tree that extends the one whose
    /// root was `old_root`, with nothing rewritten in between.
    pub fn verify(&self, old_root: Hash, new_root: Hash) -> bool {
        if self.old_size == 0 || self.old_size > self.new_size {
            return false;
        }
        if self.old_size == self.new_size {
            return self.nodes.is_empty() && digests_equal(&old_root, &new_root);
        }

        let mut node = self.old_size - 1;
        let mut last = self.new_size - 1;
        // Climb out of the right spine: those nodes are implied, not sent.
        while node & 1 == 1 {
            node >>= 1;
            last >>= 1;
        }

        let mut it = self.nodes.iter();
        // When the old size is a power of two, its root is the first node and
        // is not transmitted.
        let (mut fr, mut sr) = if node > 0 {
            let Some(first) = it.next() else {
                return false;
            };
            (*first, *first)
        } else {
            (old_root, old_root)
        };

        while node > 0 {
            if node & 1 == 1 {
                let Some(s) = it.next() else { return false };
                fr = node_hash(s, &fr);
                sr = node_hash(s, &sr);
            } else if node < last {
                let Some(s) = it.next() else { return false };
                sr = node_hash(&sr, s);
            }
            node >>= 1;
            last >>= 1;
        }

        while last > 0 {
            let Some(s) = it.next() else { return false };
            sr = node_hash(&sr, s);
            last >>= 1;
        }

        it.next().is_none() && digests_equal(&fr, &old_root) && digests_equal(&sr, &new_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(n: usize) -> MerkleTree {
        let mut t = MerkleTree::new();
        for i in 0..n {
            t.push_data(format!("record-{i}").as_bytes());
        }
        t
    }

    #[test]
    fn an_empty_tree_has_a_defined_root() {
        assert_eq!(MerkleTree::new().root(), empty_root());
    }

    #[test]
    fn a_single_leaf_tree_is_its_leaf() {
        let t = tree(1);
        assert_eq!(t.root(), leaf_hash(b"record-0"));
    }

    #[test]
    fn leaves_and_nodes_cannot_be_confused() {
        // Without domain separation an internal node could be replayed as a
        // leaf, and a tree reinterpreted with different contents.
        let l = leaf_hash(b"x");
        let n = node_hash(&l, &l);
        assert_ne!(l, n);
        assert_ne!(leaf_hash(&[]), empty_root());
    }

    #[test]
    fn inclusion_holds_for_every_leaf_of_every_size() {
        for size in 1..=33usize {
            let t = tree(size);
            let root = t.root();
            for i in 0..size {
                let p = t.inclusion_proof(i, size).expect("proof exists");
                let leaf = t.leaf(i).unwrap();
                assert!(p.verify(leaf, root), "size {size} index {i}");
            }
        }
    }

    #[test]
    fn an_inclusion_proof_does_not_verify_for_another_leaf() {
        let t = tree(17);
        let root = t.root();
        let p = t.inclusion_proof(5, 17).unwrap();
        assert!(p.verify(t.leaf(5).unwrap(), root));
        assert!(!p.verify(t.leaf(6).unwrap(), root));
        assert!(!p.verify(leaf_hash(b"forged"), root));
    }

    #[test]
    fn a_tampered_path_is_rejected() {
        let t = tree(20);
        let root = t.root();
        let mut p = t.inclusion_proof(7, 20).unwrap();
        p.path[0] = leaf_hash(b"swapped");
        assert!(!p.verify(t.leaf(7).unwrap(), root));
    }

    #[test]
    fn a_proof_with_extra_nodes_is_rejected() {
        let t = tree(12);
        let root = t.root();
        let mut p = t.inclusion_proof(3, 12).unwrap();
        p.path.push(leaf_hash(b"extra"));
        assert!(!p.verify(t.leaf(3).unwrap(), root));
    }

    #[test]
    fn consistency_holds_for_every_pair_of_sizes() {
        // The property the whole append-only claim rests on, checked
        // exhaustively rather than sampled.
        for new_size in 1..=33usize {
            let t = tree(new_size);
            let new_root = t.root();
            for old_size in 1..=new_size {
                let old_root = t.root_at(old_size).unwrap();
                let p = t
                    .consistency_proof(old_size, new_size)
                    .expect("proof exists");
                assert!(
                    p.verify(old_root, new_root),
                    "old {old_size} new {new_size}"
                );
            }
        }
    }

    #[test]
    fn consistency_fails_when_history_is_rewritten() {
        // Two trees that agree on a prefix length but not on its contents.
        let honest = tree(16);
        let mut rewritten = MerkleTree::new();
        for i in 0..16 {
            if i == 3 {
                rewritten.push_data(b"record-tampered");
            } else {
                rewritten.push_data(format!("record-{i}").as_bytes());
            }
        }
        let p = honest.consistency_proof(8, 16).unwrap();
        assert!(!p.verify(rewritten.root_at(8).unwrap(), honest.root()));
        assert!(!p.verify(honest.root_at(8).unwrap(), rewritten.root()));
    }

    #[test]
    fn consistency_fails_when_the_prefix_shrinks() {
        let t = tree(10);
        assert!(t.consistency_proof(11, 10).is_none());
        assert!(t.consistency_proof(0, 10).is_none());
    }

    #[test]
    fn a_tampered_consistency_proof_is_rejected() {
        let t = tree(24);
        let old_root = t.root_at(9).unwrap();
        let new_root = t.root();
        let mut p = t.consistency_proof(9, 24).unwrap();
        assert!(p.verify(old_root, new_root));
        p.nodes[0] = leaf_hash(b"swapped");
        assert!(!p.verify(old_root, new_root));
    }

    #[test]
    fn root_at_matches_a_tree_actually_built_that_size() {
        for size in 0..=20usize {
            let big = tree(20);
            let small = tree(size);
            assert_eq!(big.root_at(size).unwrap(), small.root(), "size {size}");
        }
    }
}
