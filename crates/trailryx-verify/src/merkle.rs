//! RFC 6962 Merkle roots, recomputed rather than trusted.
//!
//! Two rules and nothing else. A leaf hashes with a `0x00` prefix, an internal
//! node with `0x01`, and the split point of `n` leaves is the largest power of
//! two strictly below `n`.
//!
//! The prefixes are what stop a leaf from being passed off as a node. Without
//! them an attacker who controls a leaf's contents can present an internal
//! node's preimage as a leaf and produce a second tree with the same root.

use crate::sha384::{Hash, Sha384};

pub fn empty_root() -> Hash {
    Sha384::digest(&[])
}

pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha384::new();
    h.update(&[0x00]);
    h.update(data);
    h.finish()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha384::new();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    h.finish()
}

/// The root over leaves that are already hashed.
pub fn root_of(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let mut k = 1;
            while k << 1 < n {
                k <<= 1;
            }
            let left = root_of(&leaves[..k]);
            let right = root_of(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shapes_rfc_6962_specifies() {
        assert_eq!(root_of(&[]), Sha384::digest(&[]));
        let a = leaf_hash(b"a");
        assert_eq!(root_of(&[a]), a);
        let b = leaf_hash(b"b");
        assert_eq!(root_of(&[a, b]), node_hash(&a, &b));
        // Three leaves split 2 + 1, not 1 + 2.
        let c = leaf_hash(b"c");
        assert_eq!(root_of(&[a, b, c]), node_hash(&node_hash(&a, &b), &c));
    }

    #[test]
    fn a_leaf_cannot_stand_in_for_a_node() {
        // The reason for the prefixes. Hashing an internal node's preimage as a
        // leaf must not produce the node's hash.
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);
        assert_ne!(leaf_hash(&concat), node_hash(&a, &b));
    }

    #[test]
    fn order_is_part_of_the_root() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        assert_ne!(root_of(&[a, b]), root_of(&[b, a]));
    }
}
