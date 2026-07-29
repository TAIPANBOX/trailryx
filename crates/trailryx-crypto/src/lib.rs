//! Digests, and the seam where a validated module replaces them.
//!
//! Everything that hashes goes through [`Digest`]. Today the only implementation
//! is a portable SHA-384 written from the specification; from stage 7 the
//! production path is **aws-lc-rs**, and this one stays as the fallback for
//! platforms it does not cover.
//!
//! The seam exists now, before anything depends on a concrete type, because the
//! architecture calls for isolating each algorithm separately: they differ in
//! maturity and they will be replaced at different times. ML-KEM has a
//! FIPS-validated path today, ML-DSA is behind an unstable flag, and SLH-DSA has
//! no audited Rust implementation at all, which is why epoch anchoring is not in
//! v1.

pub mod chain;
pub mod sha384;

pub use chain::{ChainState, chain_step};
pub use sha384::Sha384;
pub use trailryx_record::{HASH_BYTES, Hash};

/// A cryptographic digest, consumed to produce its result.
///
/// `finish` takes `self` so a hasher cannot be read twice and quietly reused
/// with leftover state, which is a classic source of chains that verify against
/// nothing.
pub trait Digest {
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> Hash;
}

/// Constant-time equality for digests.
///
/// Comparing hashes with `==` is fine when both sides are public, which is the
/// usual case here. This exists for the paths where one side arrives from a
/// caller who is allowed to guess: verification endpoints, evidence checks.
pub fn digests_equal(a: &Hash, b: &Hash) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_equality_agrees_with_the_ordinary_kind() {
        let a = Sha384::digest(b"one");
        let b = Sha384::digest(b"one");
        let c = Sha384::digest(b"two");
        assert!(digests_equal(&a, &b));
        assert!(!digests_equal(&a, &c));
        assert_eq!(digests_equal(&a, &c), a == c);
    }
}
