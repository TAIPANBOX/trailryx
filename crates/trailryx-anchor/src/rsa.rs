//! RSA PKCS#1 v1.5 signature verification.
//!
//! # The one design decision that matters
//!
//! The padded block is **constructed and compared, never parsed**.
//!
//! A verifier that parses the recovered block, skipping `0xFF` bytes until it
//! finds a zero and then reading a DigestInfo out of whatever follows, is the
//! Bleichenbacher 2006 signature forgery. Extra bytes after the digest, a
//! shorter padding string than the specification requires, a DigestInfo with an
//! absent rather than `NULL` parameter: each is a place where a lenient parser
//! accepts a block an attacker can build without the private key, for a key with
//! a small public exponent. Whole TLS stacks shipped with this.
//!
//! So there is no parser here. The expected block is built from the algorithm
//! and the digest, and the recovered block must equal it byte for byte. There is
//! exactly one acceptable encoding of any given signed digest, which is what
//! PKCS#1 says and what a parser quietly stops enforcing.
//!
//! # What is not here
//!
//! - **No PSS.** RFC 3161 tokens in the wild are v1.5.
//! - **No certificate chain validation, no revocation, no EKU checking.** The
//!   trust model is a pinned key: see the crate documentation for why that is a
//!   deliberate reduction rather than an omission.
//! - **No signing.** [`crate::bignum`] is public-operand arithmetic only and says
//!   so.

use trailryx_asn1::{Asn1Error, Der, tag};

use crate::bignum::{BigError, Modulus};
use crate::oid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaError {
    /// The key did not parse as a SubjectPublicKeyInfo holding an RSAPublicKey.
    BadKey(Asn1Error),
    /// The key parsed but its numbers are unusable.
    BadModulus(BigError),
    /// A public exponent this implementation will not use: even, one, or wider
    /// than a `u64`. An exponent of one makes the signature the message.
    BadExponent,
    /// The algorithm in the SubjectPublicKeyInfo is not `rsaEncryption`.
    NotAnRsaKey,
    /// The signature is not exactly as long as the modulus. RFC 8017 requires
    /// it, and accepting a short one means accepting a left-padding an attacker
    /// chose.
    WrongSignatureLength { expected: usize, found: usize },
    /// The signature is not less than the modulus, so it is not a valid element.
    NotReduced,
    /// The modulus is too small to hold the padding this digest needs. Not a
    /// verification failure: such a key cannot sign this digest at all.
    KeyTooSmall,
    /// A digest algorithm this implementation does not have.
    UnsupportedDigest,
    /// The recovered block is not the block the digest and algorithm produce.
    /// The ordinary "this signature is wrong" answer.
    Mismatch,
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey(e) => write!(f, "the public key does not parse: {e}"),
            Self::BadModulus(e) => write!(f, "the modulus is unusable: {e}"),
            Self::BadExponent => f.write_str("a public exponent this implementation will not use"),
            Self::NotAnRsaKey => f.write_str("the key is not an rsaEncryption key"),
            Self::WrongSignatureLength { expected, found } => write!(
                f,
                "the signature is {found} bytes and the modulus is {expected}"
            ),
            Self::NotReduced => f.write_str("the signature is not less than the modulus"),
            Self::KeyTooSmall => f.write_str("the modulus is too small for this digest's padding"),
            Self::UnsupportedDigest => f.write_str("an unsupported digest algorithm"),
            Self::Mismatch => f.write_str("the signature does not match"),
        }
    }
}

impl std::error::Error for RsaError {}

/// Which digest a signature covers, and therefore which DigestInfo the padded
/// block must contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestKind {
    Sha256,
    Sha384,
}

impl DigestKind {
    /// The digest OID, encoded.
    pub fn oid(self) -> &'static [u8] {
        match self {
            Self::Sha256 => oid::SHA256,
            Self::Sha384 => oid::SHA384,
        }
    }

    /// The digest's width in bytes. Named `byte_len` rather than `len` because a
    /// digest is not a collection and an `is_empty` beside it would be nonsense.
    pub fn byte_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// The bare digest OID, as it appears in a CMS `digestAlgorithm`.
    pub fn from_digest_oid(algorithm: &[u8]) -> Option<Self> {
        match algorithm {
            a if a == oid::SHA256 => Some(Self::Sha256),
            a if a == oid::SHA384 => Some(Self::Sha384),
            _ => None,
        }
    }
}

/// What a CMS `signatureAlgorithm` says, which is less than one might expect.
///
/// RFC 5652 and RFC 8933 settled on `rsaEncryption` here for PKCS#1 v1.5, with
/// the digest named separately by `digestAlgorithm`. OpenSSL emits exactly that,
/// so a verifier that only recognised `sha256WithRSAEncryption` would reject every
/// real timestamp token while reporting an unsupported algorithm. Measured against
/// a token `openssl ts -reply` produced, which is how this variant came to exist.
///
/// Both spellings are accepted and the difference is kept rather than flattened:
/// when the digest is named twice it must agree with itself, and that check only
/// exists if the two cases are distinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// `rsaEncryption`. The digest comes from `digestAlgorithm` and nowhere else.
    Pkcs1Unnamed,
    /// `sha256WithRSAEncryption` or `sha384WithRSAEncryption`: the digest is named
    /// here as well, and must be the same one.
    Pkcs1Named(DigestKind),
}

impl SignatureAlgorithm {
    pub fn from_oid(algorithm: &[u8]) -> Option<Self> {
        match algorithm {
            a if a == oid::RSA_ENCRYPTION => Some(Self::Pkcs1Unnamed),
            a if a == oid::SHA256_WITH_RSA => Some(Self::Pkcs1Named(DigestKind::Sha256)),
            a if a == oid::SHA384_WITH_RSA => Some(Self::Pkcs1Named(DigestKind::Sha384)),
            _ => None,
        }
    }

    /// Whether this algorithm may be used with the digest the CMS names.
    ///
    /// Unnamed agrees with anything, because it names nothing. Named must match:
    /// a token whose two algorithm fields disagree is one where two algorithms are
    /// each half-trusted, and there is no safe way to pick.
    pub fn agrees_with(self, digest: DigestKind) -> bool {
        match self {
            Self::Pkcs1Unnamed => true,
            Self::Pkcs1Named(named) => named == digest,
        }
    }
}

/// A parsed RSA public key. Public numbers only, and no private counterpart
/// exists anywhere in this workspace.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    modulus: Modulus,
    exponent: u64,
}

impl RsaPublicKey {
    /// From a DER `SubjectPublicKeyInfo`, which is what
    /// `openssl x509 -pubkey` and every PEM `PUBLIC KEY` block hold.
    pub fn from_spki(der: &[u8]) -> Result<Self, RsaError> {
        let mut outer = Der::new(der);
        let mut spki = outer.take_nested(tag::SEQUENCE).map_err(RsaError::BadKey)?;
        let (algorithm, _parameters) = spki.algorithm_identifier().map_err(RsaError::BadKey)?;
        if algorithm.as_bytes() != oid::RSA_ENCRYPTION {
            return Err(RsaError::NotAnRsaKey);
        }
        let bits = spki.bit_string().map_err(RsaError::BadKey)?;
        spki.expect_end().map_err(RsaError::BadKey)?;
        outer.expect_end().map_err(RsaError::BadKey)?;
        Self::from_pkcs1(bits)
    }

    /// From a DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    pub fn from_pkcs1(der: &[u8]) -> Result<Self, RsaError> {
        let mut outer = Der::new(der);
        let mut key = outer.take_nested(tag::SEQUENCE).map_err(RsaError::BadKey)?;
        let modulus = key.integer_bytes().map_err(RsaError::BadKey)?;
        let exponent = key.integer_bytes().map_err(RsaError::BadKey)?;
        key.expect_end().map_err(RsaError::BadKey)?;
        outer.expect_end().map_err(RsaError::BadKey)?;

        if exponent.len() > 8 {
            return Err(RsaError::BadExponent);
        }
        let e = exponent
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        // An even exponent is not coprime with an even part of phi(n) and is not
        // a real key. An exponent of one makes s^e == s, so the "signature" is
        // the padded digest itself and anybody can write one.
        if e < 3 || e % 2 == 0 {
            return Err(RsaError::BadExponent);
        }
        Ok(Self {
            modulus: Modulus::new(modulus).map_err(RsaError::BadModulus)?,
            exponent: e,
        })
    }

    pub fn size_bytes(&self) -> usize {
        self.modulus.byte_len()
    }

    /// Verify `signature` over `digest`, which must be the digest named by `kind`.
    ///
    /// The digest is passed in already computed, because the caller knows what
    /// range of bytes was signed and this function should not be able to disagree
    /// with it.
    pub fn verify(
        &self,
        kind: DigestKind,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), RsaError> {
        if digest.len() != kind.byte_len() {
            return Err(RsaError::UnsupportedDigest);
        }
        let width = self.modulus.byte_len();
        if signature.len() != width {
            return Err(RsaError::WrongSignatureLength {
                expected: width,
                found: signature.len(),
            });
        }
        let expected = expected_block(kind, digest, width)?;
        let recovered = self
            .modulus
            .pow(signature, self.exponent)
            .map_err(|e| match e {
                BigError::NotReduced => RsaError::NotReduced,
                other => RsaError::BadModulus(other),
            })?;
        // Byte for byte against a constructed block. No parsing, so there is no
        // leniency for an attacker to build a second valid encoding inside.
        if recovered == expected {
            Ok(())
        } else {
            Err(RsaError::Mismatch)
        }
    }
}

/// `EM = 0x00 || 0x01 || 0xFF * (k - tLen - 3) || 0x00 || T`, RFC 8017 §9.2.
fn expected_block(kind: DigestKind, digest: &[u8], width: usize) -> Result<Vec<u8>, RsaError> {
    let t = digest_info(kind, digest);
    // The specification requires at least eight padding bytes. A key too small
    // to hold them cannot sign this digest, which is a different answer from a
    // signature that does not match.
    if width < t.len() + 11 {
        return Err(RsaError::KeyTooSmall);
    }
    let mut em = Vec::with_capacity(width);
    em.push(0x00);
    em.push(0x01);
    em.resize(width - t.len() - 1, 0xFF);
    em.push(0x00);
    em.extend_from_slice(&t);
    debug_assert_eq!(em.len(), width);
    Ok(em)
}

/// `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`
///
/// The parameters are `NULL` and present. RFC 8017 says so, and an absent
/// parameter is the other encoding a lenient parser would also accept, which is
/// precisely the leniency this module refuses to have.
fn digest_info(kind: DigestKind, digest: &[u8]) -> Vec<u8> {
    trailryx_asn1::sequence(&[
        trailryx_asn1::sequence(&[trailryx_asn1::oid(kind.oid()), trailryx_asn1::null()]),
        trailryx_asn1::octet_string(digest),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_crypto::{Sha256, Sha384};

    /// The expected block's shape, checked against the specification by hand
    /// because everything else in this module is compared against it.
    #[test]
    fn the_expected_block_has_the_shape_rfc_8017_specifies() {
        let digest = [0xAAu8; 48];
        let em = expected_block(DigestKind::Sha384, &digest, 256).expect("a 2048-bit key");
        assert_eq!(em.len(), 256);
        assert_eq!(&em[..2], &[0x00, 0x01]);
        // The DigestInfo for SHA-384 is 19 + 48 = 67 bytes, so padding runs to
        // 256 - 67 - 1 = 188, and byte 188 is the separator zero.
        assert_eq!(em[188], 0x00);
        assert!(
            em[2..188].iter().all(|b| *b == 0xFF),
            "the padding string must be all ones"
        );
        assert!(em[2..188].len() >= 8, "at least eight padding bytes");
        assert_eq!(&em[em.len() - 48..], &digest);
    }

    #[test]
    fn a_key_too_small_for_the_padding_is_named_rather_than_reported_as_a_mismatch() {
        // 67 bytes of DigestInfo needs 78 bytes of modulus. 77 cannot work.
        assert_eq!(
            expected_block(DigestKind::Sha384, &[0u8; 48], 77),
            Err(RsaError::KeyTooSmall)
        );
        assert!(expected_block(DigestKind::Sha384, &[0u8; 48], 78).is_ok());
    }

    /// The DigestInfo prefixes are fixed constants that every RSA
    /// implementation hard-codes. Reproducing the published bytes is how this
    /// one is checked without trusting the encoder that produced them.
    #[test]
    fn the_digest_info_prefixes_match_the_published_constants() {
        let sha256 = digest_info(DigestKind::Sha256, &[0u8; 32]);
        assert_eq!(
            &sha256[..19],
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20
            ]
        );
        let sha384 = digest_info(DigestKind::Sha384, &[0u8; 48]);
        assert_eq!(
            &sha384[..19],
            &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30
            ]
        );
    }

    #[test]
    fn an_exponent_of_one_or_an_even_one_is_refused_at_parse_time() {
        // SEQUENCE { INTEGER n, INTEGER e }
        let key = |e: u64| {
            trailryx_asn1::sequence(&[
                trailryx_asn1::integer_u64(0xC0FF_EE01),
                trailryx_asn1::integer_u64(e),
            ])
        };
        for bad in [0u64, 1, 2, 4, 65_536] {
            assert_eq!(
                RsaPublicKey::from_pkcs1(&key(bad)).err(),
                Some(RsaError::BadExponent),
                "an exponent of {bad} must be refused"
            );
        }
        assert!(RsaPublicKey::from_pkcs1(&key(3)).is_ok());
        assert!(RsaPublicKey::from_pkcs1(&key(65_537)).is_ok());
    }

    #[test]
    fn a_digest_of_the_wrong_length_for_its_kind_is_refused() {
        let key = RsaPublicKey::from_pkcs1(&trailryx_asn1::sequence(&[
            trailryx_asn1::integer_u64(0xC0FF_EE01),
            trailryx_asn1::integer_u64(65_537),
        ]))
        .expect("a parseable key");
        assert_eq!(
            key.verify(DigestKind::Sha384, &Sha256::digest(b"x"), &[0; 4]),
            Err(RsaError::UnsupportedDigest)
        );
        assert_eq!(
            key.verify(DigestKind::Sha256, Sha384::digest(b"x").as_bytes(), &[0; 4]),
            Err(RsaError::UnsupportedDigest)
        );
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused_before_any_arithmetic() {
        let key = RsaPublicKey::from_pkcs1(&trailryx_asn1::sequence(&[
            trailryx_asn1::integer_u64(0xC0FF_EE01),
            trailryx_asn1::integer_u64(65_537),
        ]))
        .expect("a parseable key");
        assert_eq!(key.size_bytes(), 4);
        let digest = Sha256::digest(b"anything");
        assert!(matches!(
            key.verify(DigestKind::Sha256, &digest, &[0; 3]),
            Err(RsaError::WrongSignatureLength {
                expected: 4,
                found: 3
            })
        ));
        assert!(matches!(
            key.verify(DigestKind::Sha256, &digest, &[0; 5]),
            Err(RsaError::WrongSignatureLength {
                expected: 4,
                found: 5
            })
        ));
    }

    #[test]
    fn a_key_that_is_not_rsa_encryption_is_named_as_such() {
        // An EC public key's SubjectPublicKeyInfo.
        let spki = trailryx_asn1::sequence(&[
            trailryx_asn1::sequence(&[
                trailryx_asn1::oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
                trailryx_asn1::oid(&[0x2B, 0x81, 0x04, 0x00, 0x22]),
            ]),
            trailryx_asn1::tlv(tag::BIT_STRING, &[0x00, 0x04]),
        ]);
        assert_eq!(
            RsaPublicKey::from_spki(&spki).err(),
            Some(RsaError::NotAnRsaKey)
        );
    }

    /// `rsaEncryption` is what a real token carries, and the case that was
    /// missing until a token from `openssl ts -reply` was put through this code.
    #[test]
    fn a_cms_signature_algorithm_may_name_the_digest_or_leave_it_to_the_digest_field() {
        assert_eq!(
            SignatureAlgorithm::from_oid(oid::RSA_ENCRYPTION),
            Some(SignatureAlgorithm::Pkcs1Unnamed)
        );
        assert_eq!(
            SignatureAlgorithm::from_oid(oid::SHA256_WITH_RSA),
            Some(SignatureAlgorithm::Pkcs1Named(DigestKind::Sha256))
        );
        assert_eq!(
            SignatureAlgorithm::from_oid(oid::SHA384_WITH_RSA),
            Some(SignatureAlgorithm::Pkcs1Named(DigestKind::Sha384))
        );
        // sha1WithRSAEncryption, which this implementation does not have and
        // must not silently treat as something else.
        assert_eq!(
            SignatureAlgorithm::from_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
            None
        );
    }

    /// Unnamed agrees with anything; named must match. A token whose two fields
    /// disagree has two half-trusted algorithms in it and no safe way to choose.
    #[test]
    fn a_named_signature_algorithm_must_agree_with_the_digest_field() {
        assert!(SignatureAlgorithm::Pkcs1Unnamed.agrees_with(DigestKind::Sha256));
        assert!(SignatureAlgorithm::Pkcs1Unnamed.agrees_with(DigestKind::Sha384));
        assert!(SignatureAlgorithm::Pkcs1Named(DigestKind::Sha384).agrees_with(DigestKind::Sha384));
        assert!(
            !SignatureAlgorithm::Pkcs1Named(DigestKind::Sha384).agrees_with(DigestKind::Sha256)
        );
        assert!(
            !SignatureAlgorithm::Pkcs1Named(DigestKind::Sha256).agrees_with(DigestKind::Sha384)
        );
    }

    #[test]
    fn digest_oids_map_to_the_digest_they_are() {
        assert_eq!(
            DigestKind::from_digest_oid(oid::SHA384),
            Some(DigestKind::Sha384)
        );
        assert_eq!(
            DigestKind::from_digest_oid(oid::SHA256),
            Some(DigestKind::Sha256)
        );
        assert_eq!(DigestKind::from_digest_oid(oid::RSA_ENCRYPTION), None);
    }
}
