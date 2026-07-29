//! The hash chain.
//!
//! One chain per shard. Each link binds the previous link, the position, and
//! the bytes of the record, so a record cannot be altered, moved, removed or
//! duplicated without the chain from that point on disagreeing.
//!
//! # Why the position is in the link
//!
//! Hashing only `(prev, bytes)` leaves a gap: two identical records adjacent in
//! the log produce identical links, and an attacker who removes one and leaves
//! the other keeps a chain that still verifies. Binding `seq` closes it, and
//! duplicate suppression stops being load-bearing for integrity.
//!
//! # What it does and does not prove
//!
//! It proves that the sequence has not been edited **in place**. It does not
//! prove that the whole file was not rewritten from scratch by whoever holds
//! the signing key, which is what segment signatures and, later, external
//! anchoring are for. Tamper-evident, not tamper-proof, and the difference is
//! worth stating in the code rather than only in the marketing.

use crate::{Digest, Hash, Sha384};

/// Domain separator, so a chain link can never be confused with a hash of
/// something else that happened to be built from the same bytes.
const DOMAIN: &[u8] = b"trailryx/chain/v1\0";

/// Compute the next link.
pub fn chain_step(prev: Hash, seq: u64, record_bytes: &[u8]) -> Hash {
    let mut h = Sha384::new();
    h.update(DOMAIN);
    h.update(prev.as_bytes());
    h.update(&seq.to_be_bytes());
    h.update(&(record_bytes.len() as u64).to_be_bytes());
    h.update(record_bytes);
    h.finish()
}

/// A chain being built or replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    head: Hash,
    length: u64,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::genesis()
    }
}

impl ChainState {
    /// An empty chain. The genesis link is all zeroes, which is a value no
    /// digest will produce, so "no records yet" is distinguishable from any
    /// real state.
    pub fn genesis() -> Self {
        Self {
            head: Hash::ZERO,
            length: 0,
        }
    }

    /// Resume a chain read back from disk.
    pub fn resume(head: Hash, length: u64) -> Self {
        Self { head, length }
    }

    pub fn head(&self) -> Hash {
        self.head
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    /// Extend the chain. Returns the link that now covers this record.
    pub fn append(&mut self, record_bytes: &[u8]) -> Hash {
        let seq = self.length + 1;
        self.head = chain_step(self.head, seq, record_bytes);
        self.length = seq;
        self.head
    }

    /// Check a record against the link it claims to have produced.
    pub fn verify_step(prev: Hash, seq: u64, record_bytes: &[u8], claimed: Hash) -> bool {
        crate::digests_equal(&chain_step(prev, seq, record_bytes), &claimed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_of(records: &[&[u8]]) -> ChainState {
        let mut c = ChainState::genesis();
        for r in records {
            c.append(r);
        }
        c
    }

    #[test]
    fn an_empty_chain_is_recognisable() {
        let c = ChainState::genesis();
        assert!(c.head().is_zero());
        assert_eq!(c.length(), 0);
    }

    #[test]
    fn the_same_records_produce_the_same_chain() {
        let a = chain_of(&[b"one", b"two", b"three"]);
        let b = chain_of(&[b"one", b"two", b"three"]);
        assert_eq!(a, b);
    }

    #[test]
    fn editing_a_record_breaks_the_chain() {
        let good = chain_of(&[b"one", b"two", b"three"]);
        let edited = chain_of(&[b"one", b"TWO", b"three"]);
        assert_ne!(good.head(), edited.head());
    }

    #[test]
    fn removing_a_record_breaks_the_chain() {
        let good = chain_of(&[b"one", b"two", b"three"]);
        let short = chain_of(&[b"one", b"three"]);
        assert_ne!(good.head(), short.head());
    }

    #[test]
    fn reordering_breaks_the_chain() {
        let good = chain_of(&[b"one", b"two"]);
        let swapped = chain_of(&[b"two", b"one"]);
        assert_ne!(good.head(), swapped.head());
    }

    #[test]
    fn removing_one_of_two_identical_records_is_detected() {
        // The reason seq is bound into the link. Without it these two chains
        // would agree, and an attacker could delete a duplicate for free.
        let both = chain_of(&[b"same", b"same"]);
        let one = chain_of(&[b"same"]);
        assert_ne!(both.head(), one.head());
        assert_eq!(both.length(), 2);
    }

    #[test]
    fn a_link_verifies_only_against_its_own_input() {
        let mut c = ChainState::genesis();
        let prev = c.head();
        let link = c.append(b"payload");
        assert!(ChainState::verify_step(prev, 1, b"payload", link));
        assert!(!ChainState::verify_step(prev, 1, b"payloaX", link));
        assert!(!ChainState::verify_step(prev, 2, b"payload", link));
        let wrong_prev = Sha384::digest(b"not the genesis link");
        assert!(!ChainState::verify_step(wrong_prev, 1, b"payload", link));
    }

    #[test]
    fn resuming_continues_where_it_stopped() {
        let mut a = chain_of(&[b"one", b"two"]);
        let mut b = ChainState::resume(a.head(), a.length());
        assert_eq!(a.append(b"three"), b.append(b"three"));
    }

    #[test]
    fn the_domain_separator_keeps_chains_distinct() {
        // A bare digest of the same bytes must not collide with a chain link.
        let link = chain_step(Hash::ZERO, 1, b"x");
        let plain = Sha384::digest(b"x");
        assert_ne!(link, plain);
    }
}
