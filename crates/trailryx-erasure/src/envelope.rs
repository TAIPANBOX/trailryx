//! What actually sits in the object store.
//!
//! An envelope holds a payload's ciphertext, the nonce, and the payload's data
//! key wrapped under a key-encryption key. It holds no plaintext and no key
//! material that is usable on its own: without the KEK, the wrapped data key is
//! a blob, and destroying the KEK is what makes erasure real.
//!
//! # Why the ciphertext cannot be moved
//!
//! The associated data binds the envelope to exactly one record: the record id,
//! the class, the hash of the plaintext, and the KEK it was wrapped under. An
//! attacker with write access to the object store can therefore replace an
//! envelope with garbage, which is detected, but cannot swap one record's
//! payload for another's, which would otherwise be an undetectable way to make
//! a record say something it never said.
//!
//! Binding the plaintext hash matters most. That hash is in the record, the
//! record is in the chain, and the chain is signed. So the ciphertext is
//! transitively bound to a signed root, and an envelope that opens to different
//! bytes than the record claims cannot exist.

use crate::aead::NONCE_BYTES;
use trailryx_contracts::contracts::KeyId;
use trailryx_record::{Hash, PayloadClass, RecordId};

const MAGIC: &[u8; 4] = b"TRXP";
pub const VERSION: u8 = 1;

/// The most a wrapped data key may be. Generous for any KEM in use, and
/// bounded because the length is read from bytes somebody else may have
/// written.
const MAX_WRAPPED_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    BadMagic,
    UnknownVersion(u8),
    Truncated,
    WrappedKeyTooLong(usize),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a Trailryx payload envelope"),
            Self::UnknownVersion(v) => write!(f, "envelope version {v} is not one we wrote"),
            Self::Truncated => write!(f, "envelope ends mid-field"),
            Self::WrappedKeyTooLong(n) => write!(f, "wrapped key claims {n} bytes"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kek: KeyId,
    pub nonce: [u8; NONCE_BYTES],
    pub wrapped_dek: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MAGIC.len() + 1 + 48 + NONCE_BYTES + 2 + self.wrapped_dek.len() + self.ciphertext.len(),
        );
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(self.kek.0.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.wrapped_dek.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.wrapped_dek);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Read an envelope written by somebody, possibly not us.
    ///
    /// Every length is checked against what is actually there. The object store
    /// is the one place in the system where bytes can be replaced without
    /// touching the journal, so nothing read here is assumed to be well formed.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut at = 0usize;
        let mut take = |n: usize| -> Result<&[u8], EnvelopeError> {
            let end = at.checked_add(n).ok_or(EnvelopeError::Truncated)?;
            let slice = bytes.get(at..end).ok_or(EnvelopeError::Truncated)?;
            at = end;
            Ok(slice)
        };

        if take(4)? != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let version = take(1)?[0];
        if version != VERSION {
            return Err(EnvelopeError::UnknownVersion(version));
        }

        let mut kek = [0u8; 48];
        kek.copy_from_slice(take(48)?);
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(take(NONCE_BYTES)?);

        let mut len = [0u8; 2];
        len.copy_from_slice(take(2)?);
        let len = usize::from(u16::from_le_bytes(len));
        if len > MAX_WRAPPED_BYTES {
            return Err(EnvelopeError::WrappedKeyTooLong(len));
        }
        let wrapped_dek = take(len)?.to_vec();
        let ciphertext = bytes[at..].to_vec();

        Ok(Self {
            kek: KeyId(Hash(kek)),
            nonce,
            wrapped_dek,
            ciphertext,
        })
    }
}

/// What the ciphertext is bound to, and therefore what it cannot be moved to.
///
/// The KEK is included so that re-wrapping a payload under a different key
/// changes the associated data. Without it, an old envelope and a new one would
/// be interchangeable, and the old one is exactly what erasure has to reach.
pub fn associated_data(
    record: RecordId,
    class: PayloadClass,
    plaintext_hash: Hash,
    kek: KeyId,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(b"trailryx.payload.v1");
    aad.extend_from_slice(&record.0.to_le_bytes());
    // The name, not the discriminant. A cast to `u8` would make the meaning of
    // every envelope ever written depend on the order of an enum's variants,
    // and reordering an enum is not supposed to be a format change.
    aad.extend_from_slice(class.as_str().as_bytes());
    aad.push(0);
    aad.extend_from_slice(plaintext_hash.as_bytes());
    aad.extend_from_slice(kek.0.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        Envelope {
            kek: KeyId(Hash([9u8; 48])),
            nonce: [3u8; NONCE_BYTES],
            wrapped_dek: vec![1, 2, 3, 4],
            ciphertext: vec![5; 100],
        }
    }

    #[test]
    fn an_envelope_survives_the_round_trip() {
        assert_eq!(Envelope::decode(&sample().encode()).unwrap(), sample());
    }

    #[test]
    fn every_prefix_is_refused_rather_than_panicking() {
        // The object store is where somebody else's bytes arrive. Truncation is
        // the cheapest thing to try and must never be an index out of range.
        let bytes = sample().encode();
        for n in 0..bytes.len() {
            let decoded = Envelope::decode(&bytes[..n]);
            if n >= 4 + 1 + 48 + NONCE_BYTES + 2 + 4 {
                // Past the header the remainder is ciphertext, whose length is
                // not declared: a short read is a wrong tag, not a bad shape.
                assert!(decoded.is_ok(), "{n}");
            } else {
                assert!(decoded.is_err(), "{n} bytes decoded as an envelope");
            }
        }
    }

    #[test]
    fn somebody_elses_bytes_are_not_an_envelope() {
        assert_eq!(
            Envelope::decode(b"not ours at all, no").unwrap_err(),
            EnvelopeError::BadMagic
        );
    }

    #[test]
    fn a_future_version_is_refused_rather_than_guessed_at() {
        let mut bytes = sample().encode();
        bytes[4] = 99;
        assert_eq!(
            Envelope::decode(&bytes).unwrap_err(),
            EnvelopeError::UnknownVersion(99)
        );
    }

    #[test]
    fn a_wrapped_key_length_is_bounded() {
        let mut bytes = sample().encode();
        let at = 4 + 1 + 48 + NONCE_BYTES;
        bytes[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            Envelope::decode(&bytes),
            Err(EnvelopeError::WrappedKeyTooLong(_)) | Err(EnvelopeError::Truncated)
        ));
    }

    #[test]
    fn associated_data_separates_everything_it_binds() {
        let base = associated_data(
            RecordId(1),
            PayloadClass::Prompt,
            Hash([1u8; 48]),
            KeyId(Hash([2u8; 48])),
        );
        let variants = [
            associated_data(
                RecordId(2),
                PayloadClass::Prompt,
                Hash([1u8; 48]),
                KeyId(Hash([2u8; 48])),
            ),
            associated_data(
                RecordId(1),
                PayloadClass::Completion,
                Hash([1u8; 48]),
                KeyId(Hash([2u8; 48])),
            ),
            associated_data(
                RecordId(1),
                PayloadClass::Prompt,
                Hash([3u8; 48]),
                KeyId(Hash([2u8; 48])),
            ),
            associated_data(
                RecordId(1),
                PayloadClass::Prompt,
                Hash([1u8; 48]),
                KeyId(Hash([4u8; 48])),
            ),
        ];
        for v in variants {
            assert_ne!(base, v);
        }
    }
}
