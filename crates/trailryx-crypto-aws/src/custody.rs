//! A key custodian that wraps a payload key with the hybrid KEM the format names.
//!
//! # Why this file exists
//!
//! [`crate::hybrid`] can produce a shared secret. That is not the same as the store
//! using one, and until 7 August 2026 nothing did: every implementation of
//! [`KeyProvider`] in this workspace was a fake in `trailryx_contracts::fakes`,
//! `Vault::seal` called `provider.wrap(kek, dek.as_bytes())`, and the wrap path had no
//! key exchange in it at all. The README and `CLAUDE.md` described hybrid key wrapping
//! anyway. [`HybridKeyProvider`] is the first implementation of that seam that
//! performs the exchange the identifier on every record has always named.
//!
//! # What a wrapped key is
//!
//! One encapsulation to the key-encryption key's own recipient key pair, and the
//! payload key sealed under the secret it produces:
//!
//! ```text
//! version | ML-KEM-768 ciphertext | ephemeral X25519 key | nonce | AES-256-GCM(dek)
//!    1    |         1088          |          32          |  12   |   len(dek) + 16
//! ```
//!
//! The cipher is `AwsAead`, the same AES-256-GCM the payload itself is sealed with, so
//! there is one cipher call site in this crate and not two. Its associated data is the
//! key id, which is what stops a wrapped key being moved from one key-encryption key
//! to another: that swap is otherwise undetectable and it is exactly what an attacker
//! with write access to an object store would try, because it is how a payload
//! survives the erasure of its own key.
//!
//! # What makes erasure real here, and what does not
//!
//! **This custodian holds its recipient key pairs in memory and writes them nowhere.**
//! [`KeyProvider::destroy`] drops both private halves and answers [`Destroyed::Now`],
//! which is the truthful answer for this custodian and is *not* the answer a real key
//! management service can give: AWS KMS and GCP Cloud KMS both schedule, both leave
//! the material recoverable for weeks, and `Destroyed::Scheduled` exists for them.
//!
//! The cost of that honesty is the limitation, and it is stated here rather than
//! discovered: **a restart destroys every key this custodian holds**, so every payload
//! wrapped by the previous process is unreadable afterwards. That is safe in the
//! direction erasure cares about and useless in the direction durability cares about.
//! A deployment that needs payloads to outlive a process needs a custodian that
//! persists the recipient keys somewhere an operator controls, and this is not it. It
//! is the KEM, wired to the seam, with the custody question answered in the one way
//! that requires no key ever to be written down.
//!
//! # What it is still not built with
//!
//! `Vault::new` refuses any provider whose `Aead` and `KeySource` answer
//! `is_validated() == false`, and both answer `cfg!(feature = "fips")`. Nothing in
//! this repository compiled that feature until this branch, so the configuration a
//! deployment would actually run has never executed this code. The tests below
//! therefore reach the vault through `Vault::unvalidated`, and say so where they do.

use std::collections::{BTreeMap, BTreeSet};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use trailryx_contracts::contracts::{AdapterError, AdapterResult, Destroyed, KeyId, KeyProvider};
use trailryx_erasure::aead::{Aead, Dek, NONCE_BYTES};

use crate::AwsAead;
use crate::hybrid::{self, CIPHERTEXT_BYTES, Recipient};

/// The shape of the blob below. A byte, so a later shape is refused rather than
/// read as this one.
///
/// Shared with [`crate::persisted`] rather than copied: the two custodians differ in
/// where the recipient key pair lives and in nothing a stored envelope can see, so a
/// second spelling of this layout would be two answers to one question, which is what
/// invariant 16 is about.
pub(crate) const WRAP_VERSION: u8 = 1;

/// Everything before the sealed key: version, both ciphertexts, nonce.
pub(crate) const HEADER_BYTES: usize = 1 + CIPHERTEXT_BYTES + NONCE_BYTES;

/// What a wrapped key is bound to.
///
/// Without this a wrapped key would be interchangeable between key-encryption keys,
/// and moving one is how a payload outlives the destruction of its own key.
pub(crate) fn wrap_aad(kek: KeyId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20 + 48);
    aad.extend_from_slice(b"trailryx.kek.wrap.v1");
    aad.extend_from_slice(kek.0.as_bytes());
    aad
}

/// Custody of key-encryption keys, with the hybrid KEM behind each one.
///
/// One recipient key pair per key id, generated on the first `wrap` and destroyed
/// once. A destroyed id is never reissued, which is the guarantee
/// [`KeyProvider`] exists to preserve: erasure here is the destruction of a key, so a
/// custodian that could resurrect one has quietly turned "erased" into "hidden".
pub struct HybridKeyProvider {
    live: BTreeMap<KeyId, Recipient>,
    /// Ids that have been destroyed. Kept for ever, and small: a key id is 48 bytes.
    tombstones: BTreeSet<KeyId>,
    rng: SystemRandom,
}

impl std::fmt::Debug for HybridKeyProvider {
    /// Written rather than derived, and it prints counts and nothing else. A derived
    /// `Debug` on a map of decapsulation keys is how a secret reaches a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HybridKeyProvider {{ live: {}, destroyed: {} }}",
            self.live.len(),
            self.tombstones.len()
        )
    }
}

impl Default for HybridKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridKeyProvider {
    pub fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            tombstones: BTreeSet::new(),
            rng: SystemRandom::new(),
        }
    }

    /// How many key-encryption keys this custodian can still open payloads under.
    pub fn live_keys(&self) -> usize {
        self.live.len()
    }
}

impl KeyProvider for HybridKeyProvider {
    fn wrap(&mut self, kek: KeyId, dek: &[u8]) -> AdapterResult<Vec<u8>> {
        if self.tombstones.contains(&kek) {
            return Err(AdapterError::Rejected("key id was destroyed"));
        }
        // An entry rather than a lookup and an insert, because generating a key pair
        // is fallible and must not run for an id that already has one: a second key
        // pair under a live id would strand every payload already wrapped under it.
        let recipient = match self.live.entry(kek) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => e.insert(
                Recipient::generate()
                    .ok_or(AdapterError::Unavailable("no key pair could be generated"))?,
            ),
        };

        let public = recipient
            .public_key()
            .ok_or(AdapterError::Unavailable("the public key is unreadable"))?;
        let sent = hybrid::encapsulate(&public)
            .ok_or(AdapterError::Unavailable("the encapsulation failed"))?;

        let mut nonce = [0u8; NONCE_BYTES];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| AdapterError::Unavailable("the system entropy source failed"))?;

        // A fresh nonce under a fresh key: `sent.shared_secret` comes from an
        // encapsulation performed just now, so this key has sealed nothing before and
        // the nonce is belt and braces rather than the only thing holding it.
        let key = Dek::new(*sent.shared_secret.as_bytes());
        let sealed = AwsAead.seal(&key, &nonce, &wrap_aad(kek), dek);

        let mut out = Vec::with_capacity(HEADER_BYTES + sealed.len());
        out.push(WRAP_VERSION);
        out.extend_from_slice(&sent.ciphertext);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn unwrap(&mut self, kek: KeyId, wrapped: &[u8]) -> AdapterResult<Vec<u8>> {
        let recipient = self
            .live
            .get(&kek)
            .ok_or(AdapterError::Rejected("no such key"))?;

        if wrapped.len() <= HEADER_BYTES || wrapped[0] != WRAP_VERSION {
            return Err(AdapterError::Rejected("not a wrapped key this build wrote"));
        }
        let ciphertext = &wrapped[1..1 + CIPHERTEXT_BYTES];
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&wrapped[1 + CIPHERTEXT_BYTES..HEADER_BYTES]);
        let sealed = &wrapped[HEADER_BYTES..];

        // ML-KEM's implicit rejection means a forged ciphertext decapsulates to a
        // wrong secret rather than to an error, so what actually refuses one is the
        // tag below. One `Rejected` for every failure, for the same reason
        // `Aead::open` returns one `None`: a caller that could tell them apart is an
        // oracle, and there is nothing useful to do with the difference.
        let secret = recipient
            .decapsulate(ciphertext)
            .ok_or(AdapterError::Rejected("the wrapped key did not open"))?;
        let key = Dek::new(*secret.as_bytes());
        AwsAead
            .open(&key, &nonce, &wrap_aad(kek), sealed)
            .ok_or(AdapterError::Rejected("the wrapped key did not open"))
    }

    fn destroy(&mut self, kek: KeyId) -> AdapterResult<Destroyed> {
        // Both private halves go here, and there is no other copy: this custodian
        // never wrote them anywhere. That is what makes `Now` the honest answer and
        // it is also this custodian's whole limitation, stated in the module docs.
        let existed = self.live.remove(&kek).is_some();
        self.tombstones.insert(kek);
        Ok(if existed {
            Destroyed::Now
        } else {
            Destroyed::Already
        })
    }

    fn exists(&self, kek: KeyId) -> bool {
        self.live.contains_key(&kek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::conformance;
    use trailryx_record::Hash;

    fn kek(byte: u8) -> KeyId {
        KeyId(Hash([byte; 48]))
    }

    /// Invariant 14: every adapter passes the conformance suite before it enters a
    /// build. This is the suite that decides whether a destroyed key stays destroyed.
    #[test]
    fn the_hybrid_custodian_conforms() {
        let mut provider = HybridKeyProvider::new();
        let report = conformance::key_provider(&mut provider);
        assert!(report.passed(), "{}", report.summary());
    }

    #[test]
    fn a_wrapped_key_comes_back_and_the_wrapped_form_is_not_the_key() {
        let mut provider = HybridKeyProvider::new();
        let dek = [7u8; 32];
        let wrapped = provider.wrap(kek(1), &dek).expect("a wrap");
        assert_ne!(&wrapped[..], &dek[..]);
        assert_eq!(provider.unwrap(kek(1), &wrapped).expect("an unwrap"), dek);
    }

    /// **Goes red if the wrap path falls back to anything that is not the hybrid.**
    ///
    /// A wrapped key is a fixed shape and its size is the evidence: an ML-KEM-768
    /// ciphertext and an ephemeral X25519 key, both present, in a blob that is 1133
    /// bytes rather than the 32 a symmetric wrap would produce. The check is on the
    /// length **and** on the two halves being distinct regions, because a
    /// zero-filled placeholder of the right size would satisfy a length check alone.
    #[test]
    fn a_wrapped_key_carries_both_ciphertexts_and_neither_is_a_placeholder() {
        let mut provider = HybridKeyProvider::new();
        let dek = [7u8; 32];
        let wrapped = provider.wrap(kek(1), &dek).expect("a wrap");

        assert_eq!(wrapped.len(), HEADER_BYTES + dek.len() + 16);
        assert_eq!(wrapped[0], WRAP_VERSION);

        let ml_kem = &wrapped[1..1 + hybrid::ML_KEM_768_CIPHERTEXT_BYTES];
        let x25519 = &wrapped[1 + hybrid::ML_KEM_768_CIPHERTEXT_BYTES..1 + CIPHERTEXT_BYTES];
        assert_eq!(ml_kem.len(), 1088);
        assert_eq!(x25519.len(), 32);
        assert!(
            ml_kem.iter().any(|b| *b != 0),
            "the ml-kem ciphertext is zeroes"
        );
        assert!(x25519.iter().any(|b| *b != 0), "the x25519 key is zeroes");

        // Two wraps under the same key id share no ciphertext: the ML-KEM
        // encapsulation and the X25519 key are both fresh per wrap, so a build that
        // cached either would show up here.
        let again = provider.wrap(kek(1), &dek).expect("a second wrap");
        assert_ne!(
            &wrapped[1..1 + CIPHERTEXT_BYTES],
            &again[1..1 + CIPHERTEXT_BYTES]
        );
    }

    /// A wrapped key cannot be moved from one key-encryption key to another.
    ///
    /// The swap this refuses is the one that would let a payload outlive the
    /// destruction of its own key, which is the only thing erasure here is.
    ///
    /// **What actually refuses it here is the key pair, not the associated data**, and
    /// that is worth saying because the test name suggests otherwise. Each key id has
    /// its own recipient, so the second one decapsulates to a different secret and the
    /// tag fails before the associated data is consulted. Measured: removing the key
    /// id from `wrap_aad` entirely leaves this test green. The associated data is the
    /// second lock, for the day two ids share a recipient, and it is held by
    /// [`the_wrap_is_bound_to_its_key_id`] rather than by this.
    #[test]
    fn a_wrapped_key_does_not_open_under_another_key_id() {
        let mut provider = HybridKeyProvider::new();
        let wrapped = provider.wrap(kek(1), &[7u8; 32]).expect("a wrap");
        provider.wrap(kek(2), &[9u8; 32]).expect("a second key");
        assert!(provider.unwrap(kek(2), &wrapped).is_err());
    }

    /// The second lock, held directly because behaviour cannot reach it.
    ///
    /// Goes red the moment `wrap_aad` stops reading the key id, which the
    /// behavioural test above does not.
    #[test]
    fn the_wrap_is_bound_to_its_key_id() {
        assert_ne!(wrap_aad(kek(1)), wrap_aad(kek(2)));
        assert!(
            wrap_aad(kek(1)).ends_with(kek(1).0.as_bytes()),
            "the key id is not in the associated data"
        );
    }

    #[test]
    fn a_torn_wrapped_key_is_refused_rather_than_panicking() {
        let mut provider = HybridKeyProvider::new();
        let wrapped = provider.wrap(kek(1), &[7u8; 32]).expect("a wrap");
        for n in 0..wrapped.len() {
            assert!(provider.unwrap(kek(1), &wrapped[..n]).is_err(), "{n}");
        }
        for i in [0usize, 1, 600, HEADER_BYTES, wrapped.len() - 1] {
            let mut torn = wrapped.clone();
            torn[i] ^= 0x01;
            assert!(provider.unwrap(kek(1), &torn).is_err(), "byte {i} opened");
        }
    }

    #[test]
    fn a_destroyed_key_never_comes_back_and_its_id_is_never_reissued() {
        let mut provider = HybridKeyProvider::new();
        let wrapped = provider.wrap(kek(1), &[7u8; 32]).expect("a wrap");
        assert_eq!(provider.destroy(kek(1)), Ok(Destroyed::Now));
        assert!(!provider.exists(kek(1)));
        assert!(provider.unwrap(kek(1), &wrapped).is_err());
        // Not merely absent: refused, so a second write under the same id cannot
        // quietly create a new key pair that the old ciphertext no longer matches.
        assert!(provider.wrap(kek(1), &[7u8; 32]).is_err());
        assert_eq!(provider.destroy(kek(1)), Ok(Destroyed::Already));
    }

    #[test]
    fn the_custodian_does_not_print_its_keys() {
        let mut provider = HybridKeyProvider::new();
        provider.wrap(kek(1), &[7u8; 32]).expect("a wrap");
        assert_eq!(
            format!("{provider:?}"),
            "HybridKeyProvider { live: 1, destroyed: 0 }"
        );
    }
}
