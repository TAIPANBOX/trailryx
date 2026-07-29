//! The two primitives this crate does not implement, behind a seam.
//!
//! Everything else in Trailryx is written here on purpose. These two are not,
//! and the reason is the same reason a bank does not write its own AES: an
//! authenticated cipher and a key generator are where a subtle mistake is
//! invisible in every test and fatal in production. What is being sold includes
//! the validation, and a hand-rolled primitive cannot be validated.
//!
//! So the crate depends on a trait, and a deployment supplies a FIPS-validated
//! module behind it. The mechanics above the seam are ours: the envelope, the
//! key hierarchy, the ledger, erasure. Those are the parts nobody else has.
//!
//! # The guard
//!
//! [`Aead::is_validated`] exists so a stand-in cannot reach a deployment by
//! accident. [`crate::Vault::new`] refuses anything that answers `false`, and
//! the only way past it is [`crate::Vault::unvalidated`], named so that reading
//! the line tells you what is wrong with it.

use trailryx_crypto::Sha384;
use trailryx_record::Hash;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;

/// A data-encryption key: one payload's worth of secret.
///
/// Cleared on drop, best effort. Best effort because a real wipe wants a
/// volatile write and this workspace forbids `unsafe`, so the zeroing is a
/// plain loop the optimiser is asked not to remove. That is weaker than a
/// dedicated crate and it is stated rather than glossed over.
pub struct Dek([u8; KEY_BYTES]);

impl Dek {
    pub fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl Drop for Dek {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// Deliberately says nothing. A key that prints itself is a key in a log file.
impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

/// An authenticated cipher with associated data.
pub trait Aead {
    fn name(&self) -> &'static str;

    /// Whether this is a validated implementation fit for a deployment.
    ///
    /// Not "is it correct". A correct implementation nobody has certified still
    /// answers `false`, because the certificate is part of what an auditor is
    /// buying.
    fn is_validated(&self) -> bool;

    fn seal(&self, key: &Dek, nonce: &[u8; NONCE_BYTES], aad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// `None` on any failure, without saying which.
    ///
    /// A decrypt that distinguishes "wrong key" from "wrong tag" hands an
    /// attacker an oracle, and the caller has nothing useful to do with the
    /// difference anyway.
    fn open(
        &self,
        key: &Dek,
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>>;
}

/// Where data keys come from.
///
/// Separate from [`trailryx_sim::Rng`] deliberately, which documents itself as
/// unfit for keys and is right to: a simulation wants reproducibility and a key
/// wants unpredictability, and one source cannot honestly be both.
///
/// [`trailryx_sim::Rng`]: https://docs.rs/trailryx-sim
pub trait KeySource {
    fn is_validated(&self) -> bool;
    fn fresh_dek(&mut self) -> Dek;
    fn fresh_nonce(&mut self) -> [u8; NONCE_BYTES];
}

// ---------------------------------------------------------------------------
// Stand-ins
// ---------------------------------------------------------------------------

/// A cipher built from the hash we already have. **Not for a deployment.**
///
/// It is a counter-mode stream over SHA-384 with an encrypt-then-MAC tag, which
/// is a reasonable construction and entirely beside the point: it is
/// unreviewed, unvalidated, and its nonce discipline is the caller's problem in
/// a way a real AEAD's is not. It exists so the mechanics above it can be
/// tested end to end without pulling in a dependency before that decision is
/// taken deliberately.
#[derive(Debug, Default)]
pub struct Sha384Ctr;

impl Sha384Ctr {
    fn keystream(key: &Dek, nonce: &[u8; NONCE_BYTES], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut counter: u64 = 0;
        while out.len() < len {
            let mut block = Vec::with_capacity(KEY_BYTES + NONCE_BYTES + 16);
            block.extend_from_slice(b"trailryx.ctr.v1");
            block.extend_from_slice(key.as_bytes());
            block.extend_from_slice(nonce);
            block.extend_from_slice(&counter.to_le_bytes());
            out.extend_from_slice(Sha384::digest(&block).as_bytes());
            counter += 1;
        }
        out.truncate(len);
        out
    }

    fn tag(key: &Dek, nonce: &[u8; NONCE_BYTES], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_BYTES] {
        let mut block = Vec::new();
        block.extend_from_slice(b"trailryx.tag.v1");
        block.extend_from_slice(key.as_bytes());
        block.extend_from_slice(nonce);
        // Lengths before contents, so a byte moved between the two fields
        // changes the tag. Without them, `aad="ab", ct="c"` and `aad="a",
        // ct="bc"` hash identically and one message authenticates another.
        block.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        block.extend_from_slice(aad);
        block.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        block.extend_from_slice(ciphertext);
        let digest = Sha384::digest(&block);
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&digest.as_bytes()[..TAG_BYTES]);
        tag
    }
}

impl Aead for Sha384Ctr {
    fn name(&self) -> &'static str {
        "sha384-ctr-unvalidated"
    }

    fn is_validated(&self) -> bool {
        false
    }

    fn seal(&self, key: &Dek, nonce: &[u8; NONCE_BYTES], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Self::keystream(key, nonce, plaintext.len())
            .iter()
            .zip(plaintext)
            .map(|(k, p)| k ^ p)
            .collect();
        out.extend_from_slice(&Self::tag(key, nonce, aad, &out));
        out
    }

    fn open(
        &self,
        key: &Dek,
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let split = ciphertext.len().checked_sub(TAG_BYTES)?;
        let (body, tag) = ciphertext.split_at(split);
        if !constant_time_eq(tag, &Self::tag(key, nonce, aad, body)) {
            return None;
        }
        Some(
            Self::keystream(key, nonce, body.len())
                .iter()
                .zip(body)
                .map(|(k, c)| k ^ c)
                .collect(),
        )
    }
}

/// Compare without leaking where the difference is.
///
/// A tag check that returns early tells an attacker how many leading bytes were
/// right, and that is enough to forge one byte at a time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Reproducible keys, for tests. **Not for a deployment.**
///
/// A key you can predict is not a key. This exists so a test can assert what
/// happens to a specific payload, and it answers `false` to the only question
/// that decides whether it may be used.
#[derive(Debug)]
pub struct PredictableKeys {
    counter: u64,
}

impl PredictableKeys {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    fn next_block(&mut self, label: &str) -> Hash {
        self.counter += 1;
        let mut seed = Vec::new();
        seed.extend_from_slice(b"trailryx.predictable.v1");
        seed.extend_from_slice(label.as_bytes());
        seed.extend_from_slice(&self.counter.to_le_bytes());
        Sha384::digest(&seed)
    }
}

impl Default for PredictableKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl KeySource for PredictableKeys {
    fn is_validated(&self) -> bool {
        false
    }

    fn fresh_dek(&mut self) -> Dek {
        let block = self.next_block("dek");
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&block.as_bytes()[..KEY_BYTES]);
        Dek::new(key)
    }

    fn fresh_nonce(&mut self) -> [u8; NONCE_BYTES] {
        let block = self.next_block("nonce");
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&block.as_bytes()[..NONCE_BYTES]);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek() -> Dek {
        Dek::new([7u8; KEY_BYTES])
    }

    #[test]
    fn what_was_sealed_comes_back() {
        let aead = Sha384Ctr;
        let sealed = aead.seal(&dek(), &[1u8; NONCE_BYTES], b"aad", b"the plaintext");
        assert_ne!(&sealed[..13], b"the plaintext");
        assert_eq!(
            aead.open(&dek(), &[1u8; NONCE_BYTES], b"aad", &sealed)
                .unwrap(),
            b"the plaintext"
        );
    }

    #[test]
    fn a_changed_bit_anywhere_fails_the_open() {
        let aead = Sha384Ctr;
        let sealed = aead.seal(&dek(), &[1u8; NONCE_BYTES], b"aad", b"the plaintext");
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(
                aead.open(&dek(), &[1u8; NONCE_BYTES], b"aad", &tampered)
                    .is_none(),
                "byte {i} was changed and the open succeeded"
            );
        }
    }

    #[test]
    fn the_associated_data_is_actually_associated() {
        let aead = Sha384Ctr;
        let sealed = aead.seal(&dek(), &[1u8; NONCE_BYTES], b"record-1", b"secret");
        assert!(
            aead.open(&dek(), &[1u8; NONCE_BYTES], b"record-2", &sealed)
                .is_none(),
            "the ciphertext would move between records"
        );
    }

    #[test]
    fn a_byte_moved_between_aad_and_ciphertext_does_not_authenticate() {
        // The reason the tag hashes lengths before contents. Without them these
        // two produce the same tag and one message stands in for the other.
        let a = Sha384Ctr::tag(&dek(), &[0u8; NONCE_BYTES], b"ab", b"c");
        let b = Sha384Ctr::tag(&dek(), &[0u8; NONCE_BYTES], b"a", b"bc");
        assert_ne!(a, b);
    }

    #[test]
    fn a_truncated_ciphertext_is_refused_rather_than_panicking() {
        let aead = Sha384Ctr;
        assert!(aead.open(&dek(), &[0u8; NONCE_BYTES], b"", &[]).is_none());
        assert!(
            aead.open(&dek(), &[0u8; NONCE_BYTES], b"", &[1, 2, 3])
                .is_none()
        );
    }

    #[test]
    fn nothing_here_claims_to_be_deployable() {
        assert!(!Sha384Ctr.is_validated());
        assert!(!PredictableKeys::new().is_validated());
    }

    #[test]
    fn a_key_does_not_print_itself() {
        assert_eq!(format!("{:?}", dek()), "Dek(<redacted>)");
    }
}
