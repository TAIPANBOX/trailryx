//! The hybrid key exchange the record format has always named: X25519 and ML-KEM-768.
//!
//! # What this is, and what it was
//!
//! The format has carried `KemAlg::X25519MlKem768` since it was frozen. Until
//! 7 August 2026 this module was the ML-KEM-768 half alone, the X25519 half was
//! written nowhere in the workspace, and nothing outside this file's own tests called
//! either. The README and `CLAUDE.md` meanwhile described hybrid key wrapping in the
//! present tense. This module is the other half and the combiner that joins them;
//! `crate::custody` is what calls it on the path that wraps a payload key.
//!
//! # Why hybrid at all
//!
//! The urgency is one-sided. A signature that weakens can be re-issued. Ciphertext
//! copied today is decrypted whenever the copier acquires the means, so for a store
//! whose retention is measured in years the key exchange is the part that cannot
//! wait. Crypto-erasure lasts exactly as long as the KEM that wrapped the key, which
//! is why this is the one place in Trailryx where a post-quantum primitive is not
//! optional.
//!
//! And hybrid rather than ML-KEM alone because ML-KEM is young. X25519 is not
//! post-quantum and is thirty years of analysis; ML-KEM is post-quantum and is not.
//! Taking both, so that breaking either one changes nothing, is what every serious
//! deployment of ML-KEM has settled on.
//!
//! # The combiner, which is the part that is not a free choice
//!
//! Concatenating two shared secrets and using the result as a key is the mistake this
//! construction exists to avoid: it gives an attacker who breaks one half a key with
//! a known half, and it binds nothing about which ciphertexts produced it.
//!
//! What is used here instead is the **`UniversalCombiner`** of
//! [draft-irtf-cfrg-hybrid-kems-12] (6 July 2026), the conservative of the two
//! frameworks that document defines, verbatim in its input order:
//!
//! ```text
//! UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
//!     = KDF(concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label))
//! ```
//!
//! The draft's own words for why it is the one to copy: it "explicitly computes over
//! shared secrets, ciphertexts, and encapsulation keys from both components. This
//! allows the resulting hybrid KEM to be secure as long as either component is
//! secure, with no further assumptions on the components."
//!
//! The other framework in that draft, and X-Wing with it, drops the post-quantum
//! ciphertext and encapsulation key from the preimage. That is sound and it is sound
//! **because of specific proved properties of ML-KEM-768**, which makes it a
//! construction that has to be adopted whole, with its key generation and its
//! randomness, or not cited at all. Deriving one input differently from X-Wing and
//! keeping the name would be worse than not using it, so this takes the generic one.
//!
//! Two instantiation choices are ours and are written here rather than left implicit,
//! because the draft leaves both to the implementation:
//!
//! - **The KDF is HKDF-SHA-384**, from AWS-LC, the same module the ML-KEM comes from.
//!   Not a second cryptographic supplier for the sake of one hash.
//! - **The label is `trailryx.kem.x25519-ml-kem-768.v1`**, which names the format's
//!   own KEM identifier and the version of this construction. A different label is a
//!   different KEM and must be a different identifier.
//!
//! Every element of the preimage is fixed-length here (32, 32, 1088, 32, 1184, 32),
//! so the concatenation is unambiguous without length prefixes. That is a property of
//! this instantiation, not a general licence: a variable-length element would need
//! them, and the lengths are asserted by a test rather than assumed.
//!
//! [draft-irtf-cfrg-hybrid-kems-12]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/
//!
//! # What this module is not
//!
//! It is not a key custodian. It has no notion of a key id, no store, and no
//! erasure. [`crate::custody`] is where those live.

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf::{HKDF_SHA384, KeyType, Salt};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};

/// ML-KEM-768's encapsulation key, FIPS 203 table 3.
pub const ML_KEM_768_ENCAPSULATION_KEY_BYTES: usize = 1184;
/// ML-KEM-768's ciphertext, FIPS 203 table 3.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
/// An X25519 public key, RFC 7748. Also the size of an ephemeral one on the wire.
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
/// What both halves produce and what the combiner produces.
pub const SHARED_SECRET_BYTES: usize = 32;

/// A recipient's published key: the ML-KEM encapsulation key, then the X25519 one.
pub const PUBLIC_KEY_BYTES: usize = ML_KEM_768_ENCAPSULATION_KEY_BYTES + X25519_PUBLIC_KEY_BYTES;

/// What a sender transmits: the ML-KEM ciphertext, then the ephemeral X25519 key.
pub const CIPHERTEXT_BYTES: usize = ML_KEM_768_CIPHERTEXT_BYTES + X25519_PUBLIC_KEY_BYTES;

/// The domain separator, and half of what makes this construction identifiable.
///
/// It is in the combiner's preimage where the draft puts it and again as the salt.
/// Changing it changes every key this KEM derives, which is why it carries a version.
const LABEL: &[u8] = b"trailryx.kem.x25519-ml-kem-768.v1";

/// The 32 bytes both sides end up holding.
///
/// Cleared on drop, best effort, and for the same reason and with the same limit as
/// `trailryx_erasure::aead::Dek`: a real wipe wants a volatile write and this
/// workspace forbids `unsafe`, so the zeroing is a plain loop the optimiser is asked
/// not to remove.
pub struct SharedSecret([u8; SHARED_SECRET_BYTES]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// Deliberately says nothing. A secret that prints itself is a secret in a log file.
impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// The length `Prk::expand` is asked for. AWS-LC takes a type rather than a number.
#[derive(Debug, Clone, Copy)]
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// `UniversalCombiner` from draft-irtf-cfrg-hybrid-kems-12, in its own input order.
///
/// The order is the draft's and is load-bearing: two of the six inputs are the same
/// length as each other in three separate pairs, so a transposition would not be a
/// length error, it would be a different KEM that still round-trips against itself.
/// That is exactly the class of change a pinned vector catches and nothing else does.
fn combine(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_pq: &[u8],
    ct_t: &[u8],
    ek_pq: &[u8],
    ek_t: &[u8],
) -> Option<SharedSecret> {
    let mut preimage = Vec::with_capacity(
        ss_pq.len()
            + ss_t.len()
            + ct_pq.len()
            + ct_t.len()
            + ek_pq.len()
            + ek_t.len()
            + LABEL.len(),
    );
    preimage.extend_from_slice(ss_pq);
    preimage.extend_from_slice(ss_t);
    preimage.extend_from_slice(ct_pq);
    preimage.extend_from_slice(ct_t);
    preimage.extend_from_slice(ek_pq);
    preimage.extend_from_slice(ek_t);
    preimage.extend_from_slice(LABEL);

    let prk = Salt::new(HKDF_SHA384, LABEL).extract(&preimage);
    let mut out = [0u8; SHARED_SECRET_BYTES];
    let filled = prk
        .expand(&[LABEL], Len(SHARED_SECRET_BYTES))
        .ok()
        .and_then(|okm| okm.fill(&mut out).ok());
    // The preimage holds both shared secrets in the clear until this returns.
    preimage.fill(0);
    std::hint::black_box(&preimage);
    filled?;
    Some(SharedSecret(out))
}

/// A recipient's two private halves. Neither ever leaves the holder.
///
/// Both are needed to recover a shared secret, which is the whole point: destroying
/// this value destroys the ability to unwrap anything encapsulated to it, and one
/// surviving half is worth nothing.
pub struct Recipient {
    pq: DecapsulationKey,
    classical: PrivateKey,
}

impl std::fmt::Debug for Recipient {
    /// Both halves are secret. Neither is printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Recipient(<ml-kem-768 + x25519 secrets>)")
    }
}

/// What a sender transmits, and the secret both sides end up with.
pub struct Encapsulated {
    /// The ML-KEM-768 ciphertext, then the sender's ephemeral X25519 public key.
    pub ciphertext: Vec<u8>,
    pub shared_secret: SharedSecret,
}

impl std::fmt::Debug for Encapsulated {
    /// The ciphertext is public and the shared secret is not, so this prints the
    /// length of one and nothing of the other.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Encapsulated {{ ciphertext: {} bytes, shared_secret: <redacted> }}",
            self.ciphertext.len()
        )
    }
}

/// The X25519 half of an agreement, copied out of AWS-LC's scratch buffer.
///
/// `agreement::agree` hands the raw secret to a closure and takes it back. Copying it
/// into a [`SharedSecret`] rather than a `Vec` is what gives it a `Drop` that clears.
fn agree(private: &PrivateKey, peer: &[u8]) -> Option<SharedSecret> {
    if peer.len() != X25519_PUBLIC_KEY_BYTES {
        return None;
    }
    // AWS-LC refuses an agreement whose result is the all-zero value, which is what
    // stops a peer forcing a known shared secret with a low-order point. RFC 7748
    // §6.1 is the reason that check exists and this relies on it rather than
    // repeating it here badly.
    agreement::agree(
        private,
        UnparsedPublicKey::new(&X25519, peer),
        Unspecified,
        |secret| {
            if secret.len() != SHARED_SECRET_BYTES {
                return Err(Unspecified);
            }
            let mut out = [0u8; SHARED_SECRET_BYTES];
            out.copy_from_slice(secret);
            Ok(SharedSecret(out))
        },
    )
    .ok()
}

impl Recipient {
    /// A fresh key pair, both halves at once.
    pub fn generate() -> Option<Self> {
        Some(Self {
            pq: DecapsulationKey::generate(&ML_KEM_768).ok()?,
            classical: PrivateKey::generate(&X25519).ok()?,
        })
    }

    /// The public halves, to be published or sent: `ek_PQ || ek_T`.
    pub fn public_key(&self) -> Option<Vec<u8>> {
        let (pq, classical) = self.public_halves()?;
        let mut out = Vec::with_capacity(PUBLIC_KEY_BYTES);
        out.extend_from_slice(&pq);
        out.extend_from_slice(&classical);
        Some(out)
    }

    fn public_halves(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let pq = self
            .pq
            .encapsulation_key()
            .ok()?
            .key_bytes()
            .ok()?
            .as_ref()
            .to_vec();
        let classical = self.classical.compute_public_key().ok()?.as_ref().to_vec();
        Some((pq, classical))
    }

    /// Recover the shared secret from what a sender transmitted.
    ///
    /// `None` on any failure, without saying which, for the same reason
    /// `Aead::open` does: a caller that could tell a malformed ciphertext from a
    /// ciphertext meant for somebody else is an oracle.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Option<SharedSecret> {
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return None;
        }
        let (ct_pq, ct_t) = ciphertext.split_at(ML_KEM_768_CIPHERTEXT_BYTES);

        // ML-KEM is designed so a wrong ciphertext yields a wrong secret rather than
        // an error, which is what stops an attacker learning anything from failure.
        // So this half almost never returns `None`, and what actually refuses a
        // forged ciphertext is the tag on whatever the derived key opens.
        let ss_pq = self.pq.decapsulate(Ciphertext::from(ct_pq)).ok()?;
        let ss_t = agree(&self.classical, ct_t)?;
        let (ek_pq, ek_t) = self.public_halves()?;

        combine(ss_pq.as_ref(), ss_t.as_bytes(), ct_pq, ct_t, &ek_pq, &ek_t)
    }
}

/// Produce a shared secret for a recipient's published key.
///
/// The X25519 private key here is ephemeral and is dropped when this returns, so the
/// classical half of a stored ciphertext cannot be re-derived by the sender either.
pub fn encapsulate(public_key: &[u8]) -> Option<Encapsulated> {
    if public_key.len() != PUBLIC_KEY_BYTES {
        return None;
    }
    let (ek_pq, ek_t) = public_key.split_at(ML_KEM_768_ENCAPSULATION_KEY_BYTES);

    let pq = EncapsulationKey::new(&ML_KEM_768, ek_pq).ok()?;
    let (ct_pq, ss_pq) = pq.encapsulate().ok()?;

    let ephemeral = PrivateKey::generate(&X25519).ok()?;
    let ct_t = ephemeral.compute_public_key().ok()?;
    let ss_t = agree(&ephemeral, ek_t)?;

    let shared_secret = combine(
        ss_pq.as_ref(),
        ss_t.as_bytes(),
        ct_pq.as_ref(),
        ct_t.as_ref(),
        ek_pq,
        ek_t,
    )?;

    let mut ciphertext = Vec::with_capacity(CIPHERTEXT_BYTES);
    ciphertext.extend_from_slice(ct_pq.as_ref());
    ciphertext.extend_from_slice(ct_t.as_ref());
    Some(Encapsulated {
        ciphertext,
        shared_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lengths the whole construction rests on, taken from the library rather
    /// than from the constants that claim them.
    ///
    /// It matters more here than it looks: the combiner concatenates six fixed-length
    /// fields with no length prefixes, and that is only unambiguous while these hold.
    #[test]
    fn the_lengths_this_construction_assumes_are_the_lengths_it_gets() {
        let recipient = Recipient::generate().expect("a key pair");
        let public = recipient.public_key().expect("a public key");
        assert_eq!(public.len(), PUBLIC_KEY_BYTES);

        let sent = encapsulate(&public).expect("an encapsulation");
        assert_eq!(sent.ciphertext.len(), CIPHERTEXT_BYTES);
        assert_eq!(sent.shared_secret.as_bytes().len(), SHARED_SECRET_BYTES);

        let (pq, classical) = recipient.public_halves().expect("both halves");
        assert_eq!(pq.len(), ML_KEM_768_ENCAPSULATION_KEY_BYTES);
        assert_eq!(classical.len(), X25519_PUBLIC_KEY_BYTES);
    }

    #[test]
    fn both_sides_of_the_exchange_reach_the_same_secret() {
        let recipient = Recipient::generate().expect("a key pair");
        let public = recipient.public_key().expect("a public key");
        let sent = encapsulate(&public).expect("an encapsulation");
        let received = recipient
            .decapsulate(&sent.ciphertext)
            .expect("a decapsulation");
        assert_eq!(sent.shared_secret.as_bytes(), received.as_bytes());
    }

    #[test]
    fn a_ciphertext_meant_for_somebody_else_yields_a_different_secret() {
        let ours = Recipient::generate().expect("a key pair");
        let theirs = Recipient::generate().expect("a key pair");
        let sent = encapsulate(&theirs.public_key().expect("a key")).expect("sent");
        // ML-KEM's implicit rejection means this returns a secret rather than
        // failing, and the classical half agrees with any well-formed ephemeral key,
        // so a secret is demanded rather than tolerated. An `if let` here would let
        // the test pass by not looking, which is what the whole gate exists against.
        let ours_secret = ours
            .decapsulate(&sent.ciphertext)
            .expect("a secret, wrong but present");
        assert_ne!(ours_secret.as_bytes(), sent.shared_secret.as_bytes());
    }

    /// **The test that goes red if the classical half is dropped.**
    ///
    /// Two recipients that share an ML-KEM key pair and differ only in their X25519
    /// one. A combiner that ignored the classical half would let the second open the
    /// first's ciphertext, which is precisely "hybrid" being a name on a byte.
    ///
    /// **What it does not catch, measured rather than assumed:** dropping `ss_T` alone
    /// while leaving `ek_T` in the preimage leaves this green, because the two
    /// recipients then still differ by their encapsulation keys. That mutation is
    /// caught by [`every_input_the_combiner_names_changes_the_secret`], which is why
    /// the two exist beside each other rather than one standing in for the other.
    /// The mixed recipient is built by MOVING one half out of each of two recipients,
    /// which is worth a sentence because the obvious way does not work.
    /// `DecapsulationKey::key_bytes()` round-trips through `DecapsulationKey::new()`
    /// and the key that comes back cannot produce its own `encapsulation_key()`:
    /// measured against aws-lc-rs 1.17.3, `Err(Unspecified)`. So a test built that way
    /// decapsulates to `None`, and the first version of this test had an arm that
    /// accepted `None`, which made it pass against every mutation including a
    /// combiner with the classical half deleted. Neither the arm nor the round trip
    /// is here now.
    #[test]
    fn the_x25519_half_is_in_the_secret_and_not_only_in_the_name() {
        let a = Recipient::generate().expect("a key pair");
        let b = Recipient::generate().expect("a second key pair");

        let sent = encapsulate(&a.public_key().expect("a key")).expect("sent");
        let by_a = a.decapsulate(&sent.ciphertext).expect("a's secret");
        assert_eq!(by_a.as_bytes(), sent.shared_secret.as_bytes());

        // A's ML-KEM key beside B's X25519 key.
        let mixed = Recipient {
            pq: a.pq,
            classical: b.classical,
        };
        let by_mixed = mixed
            .decapsulate(&sent.ciphertext)
            .expect("the mixed recipient reaches some secret");
        assert_ne!(
            by_mixed.as_bytes(),
            sent.shared_secret.as_bytes(),
            "the same ml-kem key with a different x25519 key reached the same \
             secret, so the classical half is not in the combiner"
        );
    }

    /// **The test that goes red if the post-quantum half is dropped.**
    ///
    /// The mirror of the one above, and it is the one that matters in 2035: two
    /// recipients sharing an X25519 key pair and differing only in ML-KEM.
    #[test]
    fn the_ml_kem_half_is_in_the_secret_and_not_only_in_the_name() {
        // Both recipients hold the same X25519 private key, so it is built from
        // bytes rather than generated twice. RFC 7748's own test scalar.
        const SCALAR: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let a = Recipient {
            pq: DecapsulationKey::generate(&ML_KEM_768).expect("an ml-kem key"),
            classical: PrivateKey::from_private_key(&X25519, &SCALAR).expect("an x25519 key"),
        };
        let mixed = Recipient {
            pq: DecapsulationKey::generate(&ML_KEM_768).expect("a second ml-kem key"),
            classical: PrivateKey::from_private_key(&X25519, &SCALAR).expect("the same x25519 key"),
        };

        let sent = encapsulate(&a.public_key().expect("a key")).expect("sent");
        assert_eq!(
            a.decapsulate(&sent.ciphertext)
                .expect("a's secret")
                .as_bytes(),
            sent.shared_secret.as_bytes()
        );

        let by_mixed = mixed
            .decapsulate(&sent.ciphertext)
            .expect("the mixed recipient reaches some secret");
        assert_ne!(
            by_mixed.as_bytes(),
            sent.shared_secret.as_bytes(),
            "the same x25519 key with a different ml-kem key reached the same \
             secret, so the post-quantum half is not in the combiner"
        );
    }

    /// Every input the draft names, one at a time.
    ///
    /// Goes red if any of the six is dropped from the preimage, which is the failure
    /// that would leave the construction looking correct in every round trip.
    #[test]
    fn every_input_the_combiner_names_changes_the_secret() {
        let base: [Vec<u8>; 6] = [
            vec![1u8; SHARED_SECRET_BYTES],
            vec![2u8; SHARED_SECRET_BYTES],
            vec![3u8; ML_KEM_768_CIPHERTEXT_BYTES],
            vec![4u8; X25519_PUBLIC_KEY_BYTES],
            vec![5u8; ML_KEM_768_ENCAPSULATION_KEY_BYTES],
            vec![6u8; X25519_PUBLIC_KEY_BYTES],
        ];
        let call = |a: &[Vec<u8>; 6]| {
            *combine(&a[0], &a[1], &a[2], &a[3], &a[4], &a[5])
                .expect("a combined secret")
                .as_bytes()
        };
        let expected = call(&base);

        let names = ["ss_PQ", "ss_T", "ct_PQ", "ct_T", "ek_PQ", "ek_T"];
        for (i, name) in names.iter().enumerate() {
            let mut changed = base.clone();
            changed[i][0] ^= 0xff;
            assert_ne!(
                call(&changed),
                expected,
                "{name} is not in the combiner's preimage"
            );
        }
    }

    /// Goes red if the combiner is replaced by anything that merely joins the halves.
    ///
    /// Each of these is a real construction somebody has shipped, and each one is a
    /// key an attacker who breaks one half knows something about.
    #[test]
    fn the_combiner_is_a_derivation_and_not_a_join() {
        let ss_pq = vec![1u8; SHARED_SECRET_BYTES];
        let ss_t = vec![2u8; SHARED_SECRET_BYTES];
        let ct_pq = vec![3u8; ML_KEM_768_CIPHERTEXT_BYTES];
        let ct_t = vec![4u8; X25519_PUBLIC_KEY_BYTES];
        let ek_pq = vec![5u8; ML_KEM_768_ENCAPSULATION_KEY_BYTES];
        let ek_t = vec![6u8; X25519_PUBLIC_KEY_BYTES];
        let got = *combine(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t)
            .expect("a combined secret")
            .as_bytes();

        let xored: Vec<u8> = ss_pq.iter().zip(&ss_t).map(|(a, b)| a ^ b).collect();
        let joined: Vec<u8> = ss_pq.iter().chain(&ss_t).copied().collect();
        for (what, bytes) in [
            ("the post-quantum secret alone", ss_pq.clone()),
            ("the classical secret alone", ss_t.clone()),
            ("the two exclusive-ored", xored),
            ("the first half of the two joined", joined[..32].to_vec()),
            ("the second half of the two joined", joined[32..].to_vec()),
        ] {
            assert_ne!(
                got.as_slice(),
                bytes.as_slice(),
                "the combiner returned {what}"
            );
        }
    }

    /// A pinned vector, and it is a change detector rather than a correctness oracle.
    ///
    /// The same thing `sim/corpus.tsv` is and says it is: a wrong construction
    /// reproduces its own output perfectly, so this proves nothing about whether the
    /// combiner is right. What it proves is that it cannot change quietly, which is
    /// the property the two tests above cannot give, because a transposed pair of
    /// same-length inputs passes both of them and is a different KEM.
    ///
    /// Produced by this implementation on 7 August 2026 and pinned. If it moves, the
    /// construction moved, and every key ever derived by the old one is unreachable
    /// by the new one: that is a format change, not a refactor.
    #[test]
    fn the_combiner_still_derives_what_it_derived_when_it_was_written() {
        let got = *combine(
            &[1u8; SHARED_SECRET_BYTES],
            &[2u8; SHARED_SECRET_BYTES],
            &[3u8; ML_KEM_768_CIPHERTEXT_BYTES],
            &[4u8; X25519_PUBLIC_KEY_BYTES],
            &[5u8; ML_KEM_768_ENCAPSULATION_KEY_BYTES],
            &[6u8; X25519_PUBLIC_KEY_BYTES],
        )
        .expect("a combined secret")
        .as_bytes();
        assert_eq!(hex(&got), PINNED_VECTOR);
    }

    const PINNED_VECTOR: &str = "c7e3ca8929559cdaee0ce770c6223e0f6011bc814a1ff16b6c6adffe6ddce0f6";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_ciphertext_of_the_wrong_length_is_refused_rather_than_panicking() {
        let recipient = Recipient::generate().expect("a key pair");
        let public = recipient.public_key().expect("a public key");
        let sent = encapsulate(&public).expect("an encapsulation");
        for n in [0, 1, ML_KEM_768_CIPHERTEXT_BYTES, CIPHERTEXT_BYTES - 1] {
            assert!(
                recipient.decapsulate(&sent.ciphertext[..n]).is_none(),
                "{n}"
            );
        }
        assert!(encapsulate(&[]).is_none());
        assert!(encapsulate(&public[..PUBLIC_KEY_BYTES - 1]).is_none());
    }

    #[test]
    fn neither_secret_prints_itself() {
        let recipient = Recipient::generate().expect("a key pair");
        let sent = encapsulate(&recipient.public_key().expect("a key")).expect("sent");
        assert_eq!(
            format!("{:?}", sent.shared_secret),
            "SharedSecret(<redacted>)"
        );
        assert!(!format!("{sent:?}").contains("shared_secret: ["));
        assert_eq!(
            format!("{recipient:?}"),
            "Recipient(<ml-kem-768 + x25519 secrets>)"
        );
    }
}
