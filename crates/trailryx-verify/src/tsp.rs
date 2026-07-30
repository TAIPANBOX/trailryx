//! Reading what a timestamp token says about a root, and nothing more.
//!
//! # What this checks, and what it deliberately does not
//!
//! **Checks:** that the token commits to this root. A token's `messageImprint`
//! is a hash, this crate computes the same hash from the root it holds, and the
//! two either match or they do not. That answer needs no key, no certificate and
//! nobody's word for anything.
//!
//! **Does not check:** the authority's signature. That needs CMS, RSA, a
//! certificate chain and a trust store, and this crate's whole value is that a
//! person can read it in an hour and decide whether to believe it. The full
//! verification lives in `trailryx-anchor`, outside the verifier, and any auditor
//! can also do it with one `openssl ts -verify`, which the report prints.
//!
//! That split is the honest one. A store must not be the thing that says its own
//! third-party evidence is valid; the auditor checks the token with the
//! authority's own PKI. What the verifier adds is the part the auditor cannot do
//! without the pack: confirming the token is about **this** root and not some
//! other one.
//!
//! # Why there is a second DER reader in this repository
//!
//! `trailryx-asn1` exists and is better. It is also a dependency, and this crate
//! has none by design: an auditor reads these files and nothing else. Ninety
//! lines duplicated is the price of that property, and it is a price worth
//! naming rather than quietly avoiding by adding the dependency.
//!
//! The two are pinned to agree by `trailryx-store/tests/anchored.rs`, which puts
//! a token from a real authority through both and compares what each read out of
//! it.

use crate::sha384::{HASH_BYTES, Hash, Sha384};

/// 1.2.840.113549.1.7.2, id-signedData.
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// 1.2.840.113549.1.9.16.1.4, id-ct-TSTInfo.
const OID_TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
/// 2.16.840.1.101.3.4.2.2, id-sha384.
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xA0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// The encoding ended inside a value, or a length ran past the buffer.
    Truncated,
    /// An indefinite length, or a length written in more bytes than it needs.
    /// Legal BER, never DER, and a value with two spellings is a value two
    /// readers can disagree about.
    NotDer,
    /// A tag where another was required.
    Unexpected,
    /// The token is not a `SignedData` wrapping a `TSTInfo`.
    NotATimestamp,
    /// The token stamped a digest other than SHA-384, so it cannot be about a
    /// root of this store.
    WrongDigest,
    /// A `GeneralizedTime` this reader will not interpret: not UTC, no seconds,
    /// or an impossible date.
    BadTime,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("the token ends inside a value"),
            Self::NotDer => f.write_str("the token is not DER"),
            Self::Unexpected => f.write_str("the token has a field where another was required"),
            Self::NotATimestamp => f.write_str("the token does not hold a timestamp"),
            Self::WrongDigest => f.write_str("the token did not stamp a SHA-384 digest"),
            Self::BadTime => f.write_str("the token's time is not one this reader will interpret"),
        }
    }
}

/// What a token says, read but not believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamped {
    /// The digest the authority stamped.
    pub imprint: Hash,
    /// `genTime`, seconds since the Unix epoch.
    pub at: i64,
}

impl Stamped {
    /// Whether this token is about `root`.
    ///
    /// The imprint is SHA-384 of the root's bytes, which is the rule
    /// `trailryx-anchor` uses when it builds the request. Both sides computing it
    /// the same way is what `trailryx-store/tests/anchored.rs` pins.
    pub fn covers(&self, root: &Hash) -> bool {
        self.imprint == Sha384::digest(root)
    }
}

/// Read a token's imprint and time.
pub fn read(token: &[u8]) -> Result<Stamped, TokenError> {
    // ContentInfo ::= SEQUENCE { contentType OID, [0] content }
    let ci = nested(token, TAG_SEQUENCE)?;
    let (content_type, after_type) = tlv(ci, TAG_OID)?;
    if content_type != OID_SIGNED_DATA {
        return Err(TokenError::NotATimestamp);
    }
    let (explicit, _) = tlv(after_type, TAG_CONTEXT_0)?;

    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
    let sd = nested(explicit, TAG_SEQUENCE)?;
    let (_, after_version) = tlv(sd, TAG_INTEGER)?;
    let after_algorithms = skip(after_version)?;

    // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, [0] eContent }
    //
    // `tlv` and not `nested`: `certificates` and `signerInfos` follow this inside
    // SignedData. Demanding that it fill its container rejected every real token
    // as not-DER, which is how this line came to say what it says.
    let (eci, _) = tlv(after_algorithms, TAG_SEQUENCE)?;
    let (econtent_type, after_econtent_type) = tlv(eci, TAG_OID)?;
    if econtent_type != OID_TST_INFO {
        return Err(TokenError::NotATimestamp);
    }
    let (wrapper, _) = tlv(after_econtent_type, TAG_CONTEXT_0)?;
    let (content, _) = tlv(wrapper, TAG_OCTET_STRING)?;

    // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serial, genTime, ... }
    let info = nested(content, TAG_SEQUENCE)?;
    let (_, after_info_version) = tlv(info, TAG_INTEGER)?;
    let (_, after_policy) = tlv(after_info_version, TAG_OID)?;

    // Likewise: `serialNumber` and `genTime` follow the imprint, and the hash
    // follows the algorithm inside it.
    let (mi, _) = tlv(after_policy, TAG_SEQUENCE)?;
    let (algorithm, _) = tlv(mi, TAG_SEQUENCE)?;
    let (algorithm_oid, _) = tlv(algorithm, TAG_OID)?;
    if algorithm_oid != OID_SHA384 {
        return Err(TokenError::WrongDigest);
    }
    let (hashed, _) = tlv(after_field(mi)?, TAG_OCTET_STRING)?;
    // The algorithm said SHA-384, so the width is not negotiable. A token naming
    // SHA-384 over a shorter value is malformed, not a shorter hash.
    if hashed.len() != HASH_BYTES {
        return Err(TokenError::WrongDigest);
    }
    let mut imprint = [0u8; HASH_BYTES];
    imprint.copy_from_slice(hashed);

    let after_imprint = skip(after_policy)?;
    let (_, after_serial) = tlv(after_imprint, TAG_INTEGER)?;
    let (time, _) = tlv(after_serial, TAG_GENERALIZED_TIME)?;

    Ok(Stamped {
        imprint,
        at: generalized_time(time)?,
    })
}

/// The contents of the one TLV that fills `bytes`, refusing anything after it.
fn nested(bytes: &[u8], want: u8) -> Result<&[u8], TokenError> {
    let (body, rest) = tlv(bytes, want)?;
    if !rest.is_empty() {
        return Err(TokenError::NotDer);
    }
    Ok(body)
}

/// Split one TLV of the required tag: its contents, and what follows it.
fn tlv(bytes: &[u8], want: u8) -> Result<(&[u8], &[u8]), TokenError> {
    let (tag, body, rest) = split(bytes)?;
    if tag != want {
        return Err(TokenError::Unexpected);
    }
    Ok((body, rest))
}

/// What follows the first TLV, whatever it was.
fn skip(bytes: &[u8]) -> Result<&[u8], TokenError> {
    let (_, _, rest) = split(bytes)?;
    Ok(rest)
}

/// What follows the first TLV inside `bytes`. Named for the one place it reads
/// clearly: stepping over the algorithm to reach the hash beside it.
fn after_field(bytes: &[u8]) -> Result<&[u8], TokenError> {
    skip(bytes)
}

fn split(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), TokenError> {
    let (&tag, after_tag) = bytes.split_first().ok_or(TokenError::Truncated)?;
    if tag & 0x1F == 0x1F {
        return Err(TokenError::NotDer);
    }
    let (&first, after_first) = after_tag.split_first().ok_or(TokenError::Truncated)?;
    let (length, after_length) = if first < 0x80 {
        (usize::from(first), after_first)
    } else if first == 0x80 || first == 0xFF {
        // Indefinite, and the reserved byte. Both are BER at best.
        return Err(TokenError::NotDer);
    } else {
        let count = usize::from(first & 0x7F);
        if count > 8 {
            return Err(TokenError::NotDer);
        }
        let (digits, rest) = after_first
            .split_at_checked(count)
            .ok_or(TokenError::Truncated)?;
        if digits[0] == 0 {
            return Err(TokenError::NotDer);
        }
        let mut length = 0usize;
        for digit in digits {
            length = length
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(*digit)))
                .ok_or(TokenError::NotDer)?;
        }
        if length < 0x80 {
            return Err(TokenError::NotDer);
        }
        (length, rest)
    };
    // A slice, never an allocation. A length that lies is a truncation here and
    // not a request for four gigabytes.
    let (body, rest) = after_length
        .split_at_checked(length)
        .ok_or(TokenError::Truncated)?;
    Ok((tag, body, rest))
}

/// `YYYYMMDDHHMMSS[.fff]Z`, UTC, and nothing else.
fn generalized_time(body: &[u8]) -> Result<i64, TokenError> {
    if body.len() < 15 {
        return Err(TokenError::BadTime);
    }
    let (&last, head) = body.split_last().ok_or(TokenError::BadTime)?;
    if last != b'Z' {
        return Err(TokenError::BadTime);
    }
    let (fixed, fraction) = head.split_at(14);
    match fraction {
        [] => {}
        [b'.', digits @ ..] if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) => {}
        _ => return Err(TokenError::BadTime),
    }
    if !fixed.iter().all(u8::is_ascii_digit) {
        return Err(TokenError::BadTime);
    }
    let n = |from: usize, to: usize| -> i64 {
        fixed[from..to]
            .iter()
            .fold(0i64, |acc, d| acc * 10 + i64::from(*d - b'0'))
    };
    let (year, month, day) = (n(0, 4), n(4, 6), n(6, 8));
    let (hour, minute, second) = (n(8, 10), n(10, 12), n(12, 14));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(TokenError::BadTime),
    };
    if day < 1 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err(TokenError::BadTime);
    }
    // Hinnant's days_from_civil: exact for every date, and no loop over years
    // where a leap rule can be applied one time too many.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let civil = era * 146_097 + doe - 719_468;
    Ok(civil * 86_400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv_out(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(contents.len() as u8);
        } else {
            let bytes = contents.len().to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
            out.push(0x80 | (bytes.len() - first) as u8);
            out.extend_from_slice(&bytes[first..]);
        }
        out.extend_from_slice(contents);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv_out(TAG_SEQUENCE, &parts.concat())
    }

    /// A token of the shape a real one has, built here so the reader can be
    /// exercised without a network. The real thing is checked in
    /// `tests/anchor.rs` against a token OpenSSL signed.
    fn token(imprint: &[u8], algorithm: &[u8], time: &str) -> Vec<u8> {
        let info = seq(&[
            tlv_out(TAG_INTEGER, &[1]),
            tlv_out(TAG_OID, &[0x2A, 0x03, 0x04]),
            seq(&[
                seq(&[tlv_out(TAG_OID, algorithm), tlv_out(0x05, &[])]),
                tlv_out(TAG_OCTET_STRING, imprint),
            ]),
            tlv_out(TAG_INTEGER, &[0x2A]),
            tlv_out(TAG_GENERALIZED_TIME, time.as_bytes()),
        ]);
        let signed_data = seq(&[
            tlv_out(TAG_INTEGER, &[3]),
            tlv_out(0x31, &[]),
            seq(&[
                tlv_out(TAG_OID, OID_TST_INFO),
                tlv_out(TAG_CONTEXT_0, &tlv_out(TAG_OCTET_STRING, &info)),
            ]),
            tlv_out(0x31, &[]),
        ]);
        seq(&[
            tlv_out(TAG_OID, OID_SIGNED_DATA),
            tlv_out(TAG_CONTEXT_0, &signed_data),
        ])
    }

    #[test]
    fn a_token_yields_its_imprint_and_its_time() {
        let imprint = [0x5Au8; HASH_BYTES];
        let stamped = read(&token(&imprint, OID_SHA384, "20260730143000Z")).expect("a token");
        assert_eq!(stamped.imprint, imprint);
        assert_eq!(stamped.at, 1_785_421_800);
    }

    /// The one question this reader exists to answer.
    #[test]
    fn covers_is_true_for_the_root_the_token_stamped_and_false_for_any_other() {
        let root: Hash = [0x11u8; HASH_BYTES];
        let other: Hash = [0x12u8; HASH_BYTES];
        let imprint = Sha384::digest(&root);
        let stamped = read(&token(&imprint, OID_SHA384, "20260730143000Z")).expect("a token");
        assert!(stamped.covers(&root));
        assert!(
            !stamped.covers(&other),
            "a token must not be read as covering a root it did not stamp"
        );
    }

    #[test]
    fn a_token_stamped_with_another_digest_is_refused() {
        let sha256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert_eq!(
            read(&token(&[0u8; 32], &sha256, "20260730143000Z")),
            Err(TokenError::WrongDigest)
        );
    }

    /// A token claiming SHA-384 over 32 bytes is malformed. Accepting it would
    /// mean comparing a 48-byte root imprint against something shorter.
    #[test]
    fn an_imprint_narrower_than_its_algorithm_is_refused() {
        assert_eq!(
            read(&token(&[0u8; 32], OID_SHA384, "20260730143000Z")),
            Err(TokenError::WrongDigest)
        );
    }

    #[test]
    fn something_that_is_not_a_timestamp_is_named_as_such() {
        let not_signed_data = seq(&[
            tlv_out(TAG_OID, &[0x2A, 0x03, 0x04]),
            tlv_out(TAG_CONTEXT_0, &[]),
        ]);
        assert_eq!(read(&not_signed_data), Err(TokenError::NotATimestamp));
    }

    #[test]
    fn every_truncation_of_a_valid_token_is_an_error_and_never_a_panic() {
        let whole = token(&[0x22u8; HASH_BYTES], OID_SHA384, "20260730143000Z");
        for cut in 0..whole.len() {
            assert!(
                read(&whole[..cut]).is_err(),
                "a prefix of {cut} bytes parsed as a whole token"
            );
        }
        assert!(read(&whole).is_ok());
    }

    /// A length that lies must be a truncation, never a capacity. The peer here
    /// is the party being audited.
    #[test]
    fn a_length_that_lies_never_becomes_an_allocation() {
        assert_eq!(
            split(&[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2]),
            Err(TokenError::Truncated)
        );
    }

    #[test]
    fn ber_encodings_are_refused_rather_than_normalised() {
        // An indefinite length.
        assert_eq!(split(&[0x30, 0x80, 0x00, 0x00]), Err(TokenError::NotDer));
        // Five, written in the long form.
        assert_eq!(
            split(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]),
            Err(TokenError::NotDer)
        );
        // A leading zero digit in a long length.
        assert_eq!(split(&[0x04, 0x82, 0x00, 0x80]), Err(TokenError::NotDer));
    }

    #[test]
    fn a_time_that_is_not_utc_with_seconds_is_refused() {
        for text in [
            "20260730143000",
            "20260730143000+0200",
            "202607301430Z",
            "20260230143000Z",
            "20261330143000Z",
            "20260730146000Z",
        ] {
            assert_eq!(
                generalized_time(text.as_bytes()),
                Err(TokenError::BadTime),
                "{text} should not have parsed"
            );
        }
        assert_eq!(generalized_time(b"19700101000000Z"), Ok(0));
        assert_eq!(generalized_time(b"20000229120000Z"), Ok(951_825_600));
        assert_eq!(generalized_time(b"20240229000000Z"), Ok(1_709_164_800));
    }
}
