//! The cryptographic provider: a validated cipher, and the post-quantum half.
//!
//! # Why this crate exists, and why it is the only one that may have this shape
//!
//! Everything else in this workspace is written here. This is not, and the reason
//! is written in `crates/trailryx-erasure/src/aead.rs`: an authenticated cipher and
//! a key generator are where a subtle mistake is invisible in every test and fatal
//! in production, and what is being sold includes the validation. A hand-rolled
//! primitive cannot be validated, no matter how carefully it is written or how many
//! oracles it agrees with.
//!
//! Until this crate existed the consequence was concrete and bad: the only [`Aead`]
//! in the tree answers `is_validated() == false`, `Vault::new` refuses it, and so
//! crypto-erasure, the thing this store is bought for, did not run in a deployment
//! at all.
//!
//! # What is validated, and what "validated" means here
//!
//! [`AwsAead::is_validated`] answers `true` only when this crate is built with the
//! `fips` feature, because that is the build that uses AWS-LC's FIPS 140-3 module.
//! The same code without the feature is the same algorithm and is **not** the
//! validated module, so it says so. That distinction is the entire point of the
//! seam, and a provider that answered `true` because the algorithm name was right
//! would be worse than the stand-in it replaced.
//!
//! # The hybrid KEM, and where it now runs
//!
//! The record format has carried `KemAlg::X25519MlKem768` since the format was
//! frozen. Until 7 August 2026 it had **nothing behind it**: [`hybrid`] was the
//! ML-KEM-768 half alone, no X25519 existed anywhere in the workspace, and neither
//! was called by anything outside this crate's own tests, while the README and
//! `CLAUDE.md` described hybrid key wrapping in the present tense.
//!
//! Both halves are now here and they are joined by a published combiner rather than
//! by a concatenation: see [`hybrid`] for the construction and what was followed.
//! [`custody`] is what puts it on the path that actually wraps a payload key, as the
//! first implementation of `KeyProvider` in this workspace that is not a fake.
//!
//! The urgency is one-sided and worth stating. A signature that weakens can be
//! re-issued. Ciphertext copied today is decrypted whenever the copier acquires the
//! means, so for a store whose retention is measured in years, the key exchange is
//! the part that cannot wait and the signature is the part that can. That is why
//! this crate ships a KEM and no post-quantum signature: `trailryx-verify` has to
//! stay readable in an hour, and it cannot verify ML-DSA without becoming something
//! an auditor has to trust instead of read.

#![forbid(unsafe_code)]

pub mod custody;
pub mod hybrid;

pub use custody::HybridKeyProvider;

use aws_lc_rs::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use trailryx_erasure::aead::{Aead, Dek, KeySource, NONCE_BYTES};

/// AES-256-GCM from AWS-LC.
///
/// The cipher itself is not a post-quantum question: a 256-bit symmetric key keeps
/// 128 bits of security against Grover, which is not the part anybody needs to
/// migrate. What was missing here was never the algorithm, it was a module somebody
/// certified.
#[derive(Debug)]
pub struct AwsAead;

/// A nonce handed over exactly once.
///
/// AWS-LC's API takes a sequence rather than a value, and it is right to: reusing a
/// nonce under one key in GCM does not degrade the cipher, it destroys it, and an
/// API that took a plain array would let a caller do that by accident. This wrapper
/// yields its nonce a single time and then refuses.
struct OneNonce(Option<[u8; NONCE_BYTES]>);

impl NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let bytes = self.0.take().ok_or(Unspecified)?;
        Nonce::try_assume_unique_for_key(&bytes)
    }
}

impl Aead for AwsAead {
    fn name(&self) -> &'static str {
        "aes-256-gcm"
    }

    fn is_validated(&self) -> bool {
        // True only in the build that links the FIPS 140-3 module. The algorithm
        // being correct is not the claim being made.
        cfg!(feature = "fips")
    }

    fn seal(&self, key: &Dek, nonce: &[u8; NONCE_BYTES], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let unbound = UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_bytes())
            .expect("a 32-byte key is the right length for AES-256-GCM");
        let mut sealing = SealingKey::new(unbound, OneNonce(Some(*nonce)));
        let mut in_out = plaintext.to_vec();
        sealing
            .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
            .expect("sealing fails only on a nonce reuse this type prevents");
        in_out
    }

    fn open(
        &self,
        key: &Dek,
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let unbound = UnboundKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_bytes()).ok()?;
        let mut opening = OpeningKey::new(unbound, OneNonce(Some(*nonce)));
        let mut in_out = ciphertext.to_vec();
        // One `None` for every failure. A caller that could tell a wrong key from a
        // wrong tag would be an oracle, and there is nothing useful to do with the
        // difference anyway.
        let plaintext = opening.open_in_place(Aad::from(aad), &mut in_out).ok()?;
        Some(plaintext.to_vec())
    }
}

/// Keys and nonces from the operating system, through AWS-LC.
///
/// Deliberately not the simulator's RNG, which documents itself as unfit for keys
/// and is right to: a simulation wants reproducibility and a key wants
/// unpredictability, and one source cannot honestly be both.
pub struct AwsKeySource {
    rng: SystemRandom,
}

impl std::fmt::Debug for AwsKeySource {
    /// Written rather than derived, and it prints nothing about the source. A
    /// derived `Debug` on anything near key material is how a secret reaches a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AwsKeySource(<system entropy>)")
    }
}

impl Default for AwsKeySource {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsKeySource {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
}

impl KeySource for AwsKeySource {
    fn is_validated(&self) -> bool {
        cfg!(feature = "fips")
    }

    fn fresh_dek(&mut self) -> Dek {
        let mut bytes = [0u8; 32];
        self.rng
            .fill(&mut bytes)
            .expect("the system entropy source failing is not a condition to continue past");
        Dek::new(bytes)
    }

    fn fresh_nonce(&mut self) -> [u8; NONCE_BYTES] {
        let mut bytes = [0u8; NONCE_BYTES];
        self.rng
            .fill(&mut bytes)
            .expect("the system entropy source failing is not a condition to continue past");
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Dek {
        Dek::new([7u8; 32])
    }

    #[test]
    fn a_sealed_payload_opens_to_what_went_in() {
        let aead = AwsAead;
        let nonce = [1u8; NONCE_BYTES];
        let sealed = aead.seal(&key(), &nonce, b"record-id", b"the payload");
        assert_ne!(
            sealed, b"the payload",
            "the payload must not be in the clear"
        );
        assert_eq!(
            aead.open(&key(), &nonce, b"record-id", &sealed).as_deref(),
            Some(&b"the payload"[..])
        );
    }

    /// The associated data is what binds a payload to the record that commits to
    /// it. Opening it under a different record's id must fail, or a payload could
    /// be moved between records without either of them noticing.
    #[test]
    fn a_payload_cannot_be_moved_to_another_record() {
        let aead = AwsAead;
        let nonce = [2u8; NONCE_BYTES];
        let sealed = aead.seal(&key(), &nonce, b"record-a", b"the payload");
        assert_eq!(aead.open(&key(), &nonce, b"record-b", &sealed), None);
    }

    #[test]
    fn a_wrong_key_a_wrong_nonce_and_a_flipped_bit_all_fail_the_same_way() {
        let aead = AwsAead;
        let nonce = [3u8; NONCE_BYTES];
        let sealed = aead.seal(&key(), &nonce, b"aad", b"the payload");

        assert_eq!(
            aead.open(&Dek::new([8u8; 32]), &nonce, b"aad", &sealed),
            None
        );
        assert_eq!(
            aead.open(&key(), &[4u8; NONCE_BYTES], b"aad", &sealed),
            None
        );
        for bit in 0..8 {
            let mut torn = sealed.clone();
            torn[0] ^= 1 << bit;
            assert_eq!(
                aead.open(&key(), &nonce, b"aad", &torn),
                None,
                "a flipped bit must not open"
            );
        }
    }

    /// The guard the whole seam exists for. This build is not the FIPS module, so
    /// the provider says so, and `Vault::new` will refuse it exactly as it refuses
    /// the stand-in. A provider that claimed otherwise because the algorithm name
    /// was right would be worse than no provider.
    #[test]
    fn validation_is_claimed_only_by_the_build_that_has_it() {
        assert_eq!(AwsAead.is_validated(), cfg!(feature = "fips"));
        assert_eq!(AwsKeySource::new().is_validated(), cfg!(feature = "fips"));
    }

    #[test]
    fn two_fresh_keys_are_not_the_same_key() {
        let mut source = AwsKeySource::new();
        let a = source.fresh_dek();
        let b = source.fresh_dek();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(source.fresh_nonce(), source.fresh_nonce());
    }
}
