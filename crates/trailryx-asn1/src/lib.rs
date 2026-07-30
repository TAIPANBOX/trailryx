//! A bounded DER reader and a minimal writer.
//!
//! Enough for RFC 3161 timestamp tokens and deliberately nothing more. This is
//! not an ASN.1 library: there is no schema compiler, no BER, no indefinite
//! lengths, no `ANY DEFINED BY`, no object identifier registry. It reads the
//! handful of shapes a timestamp response is made of and refuses everything
//! else, because a parser at a trust boundary is judged by what it will not do.
//!
//! # Why DER and not BER
//!
//! BER lets the same value be spelled several ways: indefinite lengths, a
//! length encoded in more bytes than it needs, a constructed string split into
//! chunks. Every one of those is a way for two parsers to disagree about what a
//! message says, which is the same defect class as request smuggling one layer
//! up. DER is the canonical subset, and this reader enforces the canonical
//! spelling rather than accepting the others and normalising them:
//!
//! - A definite length only. `0x80` (indefinite) is [`Asn1Error::Indefinite`].
//! - The **shortest** length encoding. `0x81 0x05` says five in two bytes when
//!   one would do, and is refused as [`Asn1Error::NonMinimalLength`], because a
//!   value with two spellings is a value two parsers can read differently.
//! - No trailing bytes after the outermost value the caller asked for. A
//!   signature that covers a prefix of what was delivered is a signature over
//!   something the recipient did not read.
//!
//! # Why the reader never allocates from a length field
//!
//! Every length in this input was chosen by the party being audited. The reader
//! only ever *slices* the buffer it was handed, so a length that lies is a
//! truncation error rather than a request for four gigabytes. Nothing in here
//! calls `Vec::with_capacity` on a number that came off the wire.
//!
//! # Depth
//!
//! Bounded at [`MAX_DEPTH`]. The reader is iterative where it can be and the
//! callers in `trailryx-anchor` recurse only as deep as the structures they
//! name, but a nesting bound is cheap and a stack overflow is not a parse
//! error, it is the process dying.

#![forbid(unsafe_code)]

/// Deeper than any structure RFC 3161 and its CMS wrapper define.
///
/// Measured against the deepest real path, ContentInfo to SignedData to
/// SignerInfo to the signed attribute set to an attribute value, which is
/// seven. Sixteen leaves room without leaving room for a stack overflow.
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asn1Error {
    /// The buffer ended inside a tag, a length, or a value.
    Truncated,
    /// A length byte of `0x80`. Legal BER, never DER.
    Indefinite,
    /// A length that could have been written in fewer bytes.
    NonMinimalLength,
    /// A length spanning more bytes than a `usize` on this machine.
    LengthTooLarge,
    /// A tag this reader does not implement: multi-byte tag numbers.
    HighTagNumber,
    /// Asked for one tag, found another.
    UnexpectedTag { expected: u8, found: u8 },
    /// Bytes remain after the value the caller said was the whole input.
    TrailingBytes,
    /// More nesting than [`MAX_DEPTH`].
    TooDeep,
    /// An INTEGER with a leading `0x00` or `0xFF` that DER forbids, an empty
    /// INTEGER, or one wider than the caller's type.
    BadInteger,
    /// A BOOLEAN that is neither `0x00` nor `0xFF`.
    BadBoolean,
    /// An OBJECT IDENTIFIER that is empty, ends mid-arc, or has a non-minimal
    /// arc encoding.
    BadOid,
    /// A BIT STRING whose unused-bits count is missing or above seven.
    BadBitString,
    /// A GeneralizedTime this reader will not interpret.
    BadTime,
}

impl std::fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("the encoding ends inside a value"),
            Self::Indefinite => f.write_str("an indefinite length: legal BER, never DER"),
            Self::NonMinimalLength => f.write_str("a length written in more bytes than it needs"),
            Self::LengthTooLarge => f.write_str("a length wider than this machine's usize"),
            Self::HighTagNumber => f.write_str("a multi-byte tag number is not implemented"),
            Self::UnexpectedTag { expected, found } => {
                write!(f, "expected tag {expected:#04x}, found {found:#04x}")
            }
            Self::TrailingBytes => f.write_str("bytes remain after the outermost value"),
            Self::TooDeep => f.write_str("nested deeper than this reader allows"),
            Self::BadInteger => f.write_str("an INTEGER DER does not permit"),
            Self::BadBoolean => f.write_str("a BOOLEAN that is neither 0x00 nor 0xFF"),
            Self::BadOid => f.write_str("a malformed OBJECT IDENTIFIER"),
            Self::BadBitString => f.write_str("a malformed BIT STRING"),
            Self::BadTime => f.write_str("a GeneralizedTime this reader will not interpret"),
        }
    }
}

impl std::error::Error for Asn1Error {}

pub type Result<T> = std::result::Result<T, Asn1Error>;

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
    pub const GENERALIZED_TIME: u8 = 0x18;

    /// `[n]` context-specific, constructed. The form an EXPLICIT tag takes.
    pub const fn context_constructed(n: u8) -> u8 {
        0xA0 | n
    }

    /// `[n]` context-specific, primitive. The form an IMPLICIT tag over a
    /// primitive type takes.
    pub const fn context_primitive(n: u8) -> u8 {
        0x80 | n
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// A cursor over DER, borrowing its input.
///
/// Every accessor either consumes exactly one TLV or reports why it could not.
/// There is no rewind: a reader that could be backed up is a reader whose
/// caller can check a field twice and get two answers.
#[derive(Debug, Clone)]
pub struct Der<'a> {
    bytes: &'a [u8],
    depth: usize,
}

impl<'a> Der<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, depth: 0 }
    }

    /// What has not been consumed. For a caller that needs to know a structure
    /// was exhausted.
    pub fn rest(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The tag of the next value, without consuming it.
    ///
    /// `None` at the end of the input. This is how an OPTIONAL field is read:
    /// look, then decide. It is the only lookahead in the reader, and it cannot
    /// see past one tag byte.
    pub fn peek_tag(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    /// Consume one TLV with the given tag, returning its contents.
    pub fn take(&mut self, expected: u8) -> Result<&'a [u8]> {
        let (tag, body, rest) = split_tlv(self.bytes)?;
        if tag != expected {
            return Err(Asn1Error::UnexpectedTag {
                expected,
                found: tag,
            });
        }
        self.bytes = rest;
        Ok(body)
    }

    /// Consume one TLV of any tag, returning both.
    pub fn take_any(&mut self) -> Result<(u8, &'a [u8])> {
        let (tag, body, rest) = split_tlv(self.bytes)?;
        self.bytes = rest;
        Ok((tag, body))
    }

    /// Consume one TLV with the given tag and return a reader over its
    /// contents, one level deeper.
    pub fn take_nested(&mut self, expected: u8) -> Result<Der<'a>> {
        if self.depth + 1 > MAX_DEPTH {
            return Err(Asn1Error::TooDeep);
        }
        let body = self.take(expected)?;
        Ok(Der {
            bytes: body,
            depth: self.depth + 1,
        })
    }

    /// Consume one TLV and return it **whole**: tag, length and contents.
    ///
    /// For a value that has to be kept exactly as it arrived. A signed structure
    /// re-encoded from its parsed fields is a different byte string, and its
    /// signature no longer verifies over it, so anything that will be stored and
    /// checked later has to come out of here rather than out of a re-encode.
    pub fn take_raw(&mut self) -> Result<&'a [u8]> {
        let before = self.bytes;
        let (_, _, rest) = split_tlv(before)?;
        self.bytes = rest;
        Ok(&before[..before.len() - rest.len()])
    }

    /// Consume the TLV without looking at it. For a field whose meaning this
    /// reader has no opinion about.
    pub fn skip(&mut self) -> Result<()> {
        let (_, _, rest) = split_tlv(self.bytes)?;
        self.bytes = rest;
        Ok(())
    }

    /// Skip a TLV if it carries this tag; report whether it did.
    pub fn skip_if(&mut self, tag: u8) -> Result<bool> {
        if self.peek_tag() == Some(tag) {
            self.skip()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// A non-negative INTEGER small enough for a `u64`.
    ///
    /// Negative values are refused rather than wrapped: nothing this crate
    /// parses has a legitimate negative integer, and a serial number read as a
    /// huge positive would compare equal to nothing while looking plausible.
    pub fn integer_u64(&mut self) -> Result<u64> {
        let body = self.take(tag::INTEGER)?;
        integer_bytes(body)?;
        if body[0] & 0x80 != 0 {
            return Err(Asn1Error::BadInteger);
        }
        let significant = if body[0] == 0 { &body[1..] } else { body };
        if significant.len() > 8 {
            return Err(Asn1Error::BadInteger);
        }
        let mut value = 0u64;
        for byte in significant {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    /// An INTEGER's magnitude bytes, big-endian, with the DER sign byte
    /// stripped and no leading zeros.
    ///
    /// For values too large for a `u64`: an RSA modulus, an exponent, a
    /// certificate serial number.
    pub fn integer_bytes(&mut self) -> Result<&'a [u8]> {
        let body = self.take(tag::INTEGER)?;
        integer_bytes(body)?;
        if body[0] & 0x80 != 0 {
            return Err(Asn1Error::BadInteger);
        }
        Ok(if body[0] == 0 && body.len() > 1 {
            &body[1..]
        } else {
            body
        })
    }

    pub fn boolean(&mut self) -> Result<bool> {
        let body = self.take(tag::BOOLEAN)?;
        match body {
            [0x00] => Ok(false),
            // DER pins TRUE to all-ones. BER allows any non-zero, which is
            // another value with several spellings.
            [0xFF] => Ok(true),
            _ => Err(Asn1Error::BadBoolean),
        }
    }

    pub fn octet_string(&mut self) -> Result<&'a [u8]> {
        self.take(tag::OCTET_STRING)
    }

    /// An OBJECT IDENTIFIER, still encoded.
    ///
    /// Returned as the raw arc bytes rather than a dotted string: this crate
    /// compares OIDs against constants and never renders them, so decoding
    /// would be work done only to be undone. The encoding is validated, so a
    /// comparison against a constant is a comparison of two well-formed OIDs.
    pub fn oid(&mut self) -> Result<Oid<'a>> {
        let body = self.take(tag::OID)?;
        validate_oid(body)?;
        Ok(Oid(body))
    }

    /// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`
    ///
    /// The parameters are returned unparsed. For every algorithm this crate
    /// cares about they are either absent or `NULL`, and a caller that needs to
    /// insist on that can.
    pub fn algorithm_identifier(&mut self) -> Result<AlgorithmIdentifier<'a>> {
        let mut inner = self.take_nested(tag::SEQUENCE)?;
        let algorithm = inner.oid()?;
        let parameters = if inner.is_empty() {
            None
        } else {
            Some(inner.take_any()?)
        };
        if !inner.is_empty() {
            return Err(Asn1Error::TrailingBytes);
        }
        Ok((algorithm, parameters))
    }

    /// A BIT STRING with no unused bits, which is the only shape this crate
    /// needs: a signature or a packed public key.
    pub fn bit_string(&mut self) -> Result<&'a [u8]> {
        let body = self.take(tag::BIT_STRING)?;
        let (unused, bits) = body.split_first().ok_or(Asn1Error::BadBitString)?;
        if *unused != 0 {
            return Err(Asn1Error::BadBitString);
        }
        Ok(bits)
    }

    /// A GeneralizedTime, as whole seconds since the Unix epoch.
    ///
    /// Only the form RFC 5280 and RFC 3161 require: four-digit year, UTC, `Z`,
    /// no offset, seconds present, optional fractional seconds which are
    /// **discarded rather than rounded**. Anything else is [`Asn1Error::BadTime`],
    /// because a local-time timestamp with no offset is a time nobody can place
    /// and an anchor's whole value is the instant it names.
    pub fn generalized_time(&mut self) -> Result<i64> {
        let body = self.take(tag::GENERALIZED_TIME)?;
        parse_generalized_time(body)
    }

    /// Refuse to finish while bytes remain.
    ///
    /// Called at the end of every structure this crate claims to have read
    /// completely. Without it, a value appended after a field the reader stops
    /// at travels inside a signed blob nobody looked at.
    pub fn expect_end(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(Asn1Error::TrailingBytes)
        }
    }
}

/// An `AlgorithmIdentifier`: the algorithm, and its parameters if it has any.
///
/// The parameters are the raw `(tag, contents)` because every algorithm this crate
/// meets either omits them or writes `NULL`, and a type that interpreted them
/// would be interpreting something nobody reads.
pub type AlgorithmIdentifier<'a> = (Oid<'a>, Option<(u8, &'a [u8])>);

/// An encoded OBJECT IDENTIFIER, validated on construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oid<'a>(pub &'a [u8]);

impl Oid<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }
}

/// Split one TLV off the front: tag, contents, remainder.
fn split_tlv(bytes: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = bytes.split_first().ok_or(Asn1Error::Truncated)?;
    // A tag number of 31 means the number continues in following bytes. Nothing
    // in RFC 3161 or CMS uses one, so it is refused rather than skipped.
    if tag & 0x1F == 0x1F {
        return Err(Asn1Error::HighTagNumber);
    }
    let (&first, after_first) = after_tag.split_first().ok_or(Asn1Error::Truncated)?;
    let (length, after_length) = if first < 0x80 {
        (usize::from(first), after_first)
    } else if first == 0x80 {
        return Err(Asn1Error::Indefinite);
    } else if first == 0xFF {
        // Reserved by X.690. Never a valid long form.
        return Err(Asn1Error::NonMinimalLength);
    } else {
        let count = usize::from(first & 0x7F);
        if count > core::mem::size_of::<usize>() {
            return Err(Asn1Error::LengthTooLarge);
        }
        let (digits, rest) = after_first
            .split_at_checked(count)
            .ok_or(Asn1Error::Truncated)?;
        // DER: the long form is only for lengths that need it, and the first
        // digit is never zero. Both are spellings of a value that already has
        // one.
        if digits[0] == 0 {
            return Err(Asn1Error::NonMinimalLength);
        }
        let mut length = 0usize;
        for digit in digits {
            length = length
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(*digit)))
                .ok_or(Asn1Error::LengthTooLarge)?;
        }
        if length < 0x80 {
            return Err(Asn1Error::NonMinimalLength);
        }
        (length, rest)
    };
    // A slice, never an allocation: a length that lies fails here.
    let (body, rest) = after_length
        .split_at_checked(length)
        .ok_or(Asn1Error::Truncated)?;
    Ok((tag, body, rest))
}

/// The DER rules an INTEGER's contents must satisfy, whatever its width.
fn integer_bytes(body: &[u8]) -> Result<()> {
    match body {
        // An INTEGER always has at least one content byte, even for zero.
        [] => Err(Asn1Error::BadInteger),
        // A leading 0x00 is only allowed to clear a sign bit, and a leading
        // 0xFF only to set one. Anything else is a padded spelling of a value
        // that already had one.
        [0x00, next, ..] if next & 0x80 == 0 => Err(Asn1Error::BadInteger),
        [0xFF, next, ..] if next & 0x80 != 0 => Err(Asn1Error::BadInteger),
        _ => Ok(()),
    }
}

fn validate_oid(body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(Asn1Error::BadOid);
    }
    let mut start_of_arc = true;
    for (i, byte) in body.iter().enumerate() {
        // A continuation byte of 0x80 at the start of an arc encodes a leading
        // zero in base 128, which is a second spelling of the same number.
        if start_of_arc && *byte == 0x80 {
            return Err(Asn1Error::BadOid);
        }
        start_of_arc = byte & 0x80 == 0;
        if i == body.len() - 1 && byte & 0x80 != 0 {
            // The last byte says the arc continues, and nothing follows.
            return Err(Asn1Error::BadOid);
        }
    }
    Ok(())
}

/// `YYYYMMDDHHMMSS[.fff]Z` and nothing else.
fn parse_generalized_time(body: &[u8]) -> Result<i64> {
    // The shortest legal form is 15 bytes; the check is here so the digit reads
    // below cannot be out of range.
    if body.len() < 15 {
        return Err(Asn1Error::BadTime);
    }
    let (&last, head) = body.split_last().ok_or(Asn1Error::BadTime)?;
    if last != b'Z' {
        return Err(Asn1Error::BadTime);
    }
    let (fixed, fraction) = head.split_at(14);
    match fraction {
        [] => {}
        // Discarded, not rounded: a fractional second cannot change which
        // second an anchor names, and rounding up would let a token claim an
        // instant it did not say.
        [b'.', digits @ ..] if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) => {}
        _ => return Err(Asn1Error::BadTime),
    }
    if !fixed.iter().all(u8::is_ascii_digit) {
        return Err(Asn1Error::BadTime);
    }
    let n = |from: usize, to: usize| -> i64 {
        fixed[from..to]
            .iter()
            .fold(0i64, |acc, d| acc * 10 + i64::from(*d - b'0'))
    };
    let (year, month, day) = (n(0, 4), n(4, 6), n(6, 8));
    let (hour, minute, second) = (n(8, 10), n(10, 12), n(12, 14));
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err(Asn1Error::BadTime);
    }
    // 60 is refused. A leap second in a timestamp token is a second this
    // arithmetic cannot place, and guessing would put the anchor a second away
    // from where it said it was.
    if hour > 23 || minute > 59 || second > 59 {
        return Err(Asn1Error::BadTime);
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil`, which is exact for every date in range
/// and needs no table. Chosen over a month-accumulation loop because a loop
/// over years is where an off-by-one in leap handling hides.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Encode one TLV.
///
/// The length is always written in the shortest form, so this writer produces
/// exactly what the reader above demands. That symmetry is the point: a
/// round-trip test then means something.
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 6);
    out.push(tag);
    write_length(&mut out, contents.len());
    out.extend_from_slice(contents);
    out
}

fn write_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let digits = &bytes[first..];
    out.push(0x80 | digits.len() as u8);
    out.extend_from_slice(digits);
}

pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &parts.concat())
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, bytes)
}

pub fn null() -> Vec<u8> {
    tlv(tag::NULL, &[])
}

pub fn boolean(value: bool) -> Vec<u8> {
    tlv(tag::BOOLEAN, &[if value { 0xFF } else { 0x00 }])
}

/// An OID from its already-encoded arc bytes.
pub fn oid(arcs: &[u8]) -> Vec<u8> {
    tlv(tag::OID, arcs)
}

/// A non-negative INTEGER, minimally encoded with a sign byte where the top bit
/// would otherwise make it negative.
pub fn integer_u64(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    let mut body = Vec::with_capacity(9);
    if bytes[first] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(&bytes[first..]);
    tlv(tag::INTEGER, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Lengths, which is where a DER parser is usually wrong
    // -----------------------------------------------------------------------

    #[test]
    fn a_short_form_length_reads() {
        let mut d = Der::new(&[0x04, 0x03, 1, 2, 3]);
        assert_eq!(d.octet_string(), Ok(&[1u8, 2, 3][..]));
        assert_eq!(d.expect_end(), Ok(()));
    }

    #[test]
    fn a_long_form_length_reads() {
        let mut encoded = vec![0x04, 0x81, 0x80];
        encoded.extend(std::iter::repeat_n(7u8, 128));
        let mut d = Der::new(&encoded);
        assert_eq!(d.octet_string().map(<[u8]>::len), Ok(128));
    }

    /// The whole reason this reader exists rather than a permissive one: a
    /// length with two spellings is a value two parsers can disagree about.
    #[test]
    fn a_length_written_longer_than_it_needs_is_refused() {
        // 5, in the long form, which the short form encodes in one byte.
        assert_eq!(
            Der::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).octet_string(),
            Err(Asn1Error::NonMinimalLength)
        );
        // 0x0080 with a leading zero digit.
        let mut encoded = vec![0x04, 0x82, 0x00, 0x80];
        encoded.extend(std::iter::repeat_n(0u8, 128));
        assert_eq!(
            Der::new(&encoded).octet_string(),
            Err(Asn1Error::NonMinimalLength)
        );
    }

    #[test]
    fn an_indefinite_length_is_refused_by_name() {
        assert_eq!(
            Der::new(&[0x30, 0x80, 0x04, 0x00, 0x00, 0x00]).take(tag::SEQUENCE),
            Err(Asn1Error::Indefinite)
        );
    }

    #[test]
    fn a_length_that_lies_is_a_truncation_and_never_an_allocation() {
        // Claims four gigabytes in eight bytes of input.
        let encoded = [0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2];
        assert_eq!(
            Der::new(&encoded).octet_string(),
            Err(Asn1Error::Truncated),
            "a length field must never become a capacity"
        );
    }

    #[test]
    fn the_reserved_length_byte_is_refused() {
        assert_eq!(
            Der::new(&[0x04, 0xFF, 0x01]).octet_string(),
            Err(Asn1Error::NonMinimalLength)
        );
    }

    #[test]
    fn a_high_tag_number_is_refused_rather_than_skipped() {
        assert_eq!(
            Der::new(&[0x1F, 0x81, 0x00, 0x00]).take_any(),
            Err(Asn1Error::HighTagNumber)
        );
    }

    #[test]
    fn every_truncation_point_of_a_valid_encoding_is_an_error_and_never_a_panic() {
        let whole = sequence(&[integer_u64(1), octet_string(b"hello"), null()]);
        for cut in 0..whole.len() {
            let mut d = Der::new(&whole[..cut]);
            let outcome = d.take_nested(tag::SEQUENCE).and_then(|mut inner| {
                let v = inner.integer_u64()?;
                let s = inner.octet_string()?;
                inner.take(tag::NULL)?;
                inner.expect_end()?;
                Ok((v, s.to_vec()))
            });
            assert!(outcome.is_err(), "a prefix of {cut} bytes parsed as whole");
        }
        let mut d = Der::new(&whole);
        assert!(d.take_nested(tag::SEQUENCE).is_ok());
    }

    // -----------------------------------------------------------------------
    // INTEGER
    // -----------------------------------------------------------------------

    #[test]
    fn integers_round_trip_through_the_writer_and_the_reader() {
        for value in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            0x7FFF,
            0x8000,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let encoded = integer_u64(value);
            let mut d = Der::new(&encoded);
            assert_eq!(d.integer_u64(), Ok(value), "{value} did not round-trip");
            assert_eq!(d.expect_end(), Ok(()));
        }
    }

    /// A padded integer is a second spelling of a number that already had one,
    /// and DER forbids it. A reader that accepted it would let the same
    /// serial number arrive as two different byte strings.
    #[test]
    fn a_padded_integer_is_refused() {
        assert_eq!(
            Der::new(&[0x02, 0x02, 0x00, 0x01]).integer_u64(),
            Err(Asn1Error::BadInteger)
        );
        assert_eq!(
            Der::new(&[0x02, 0x02, 0xFF, 0xFF]).integer_u64(),
            Err(Asn1Error::BadInteger)
        );
        // A legitimate sign byte, which must still be accepted.
        assert_eq!(Der::new(&[0x02, 0x02, 0x00, 0x80]).integer_u64(), Ok(128));
    }

    #[test]
    fn an_empty_integer_is_refused_rather_than_read_as_zero() {
        assert_eq!(
            Der::new(&[0x02, 0x00]).integer_u64(),
            Err(Asn1Error::BadInteger)
        );
    }

    /// A negative integer read as a large positive one would compare equal to
    /// nothing while looking like a plausible serial number.
    #[test]
    fn a_negative_integer_is_refused_rather_than_wrapped() {
        assert_eq!(
            Der::new(&[0x02, 0x01, 0xFF]).integer_u64(),
            Err(Asn1Error::BadInteger)
        );
        assert_eq!(
            Der::new(&[0x02, 0x01, 0xFF]).integer_bytes(),
            Err(Asn1Error::BadInteger)
        );
    }

    #[test]
    fn an_integer_too_wide_for_u64_is_refused_but_its_bytes_are_available() {
        // Eight significant bytes are exactly a u64, sign byte and all.
        let fits = [0x02, 0x09, 0x00, 0xFF, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(Der::new(&fits).integer_u64(), Ok(0xFF01_0203_0405_0607));

        // Nine are not, and the boundary is where a silent truncation would
        // live: this expectation was wrong by one byte when first written, and
        // the test is what said so.
        let wide = [0x02, 0x0A, 0x00, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            Der::new(&wide).integer_u64(),
            Err(Asn1Error::BadInteger),
            "nine significant bytes must not silently truncate"
        );
        assert_eq!(
            Der::new(&wide).integer_bytes(),
            Ok(&[0xFF, 1, 2, 3, 4, 5, 6, 7, 8][..]),
            "the sign byte is stripped and the magnitude kept"
        );
    }

    // -----------------------------------------------------------------------
    // OID, BOOLEAN, BIT STRING
    // -----------------------------------------------------------------------

    #[test]
    fn a_well_formed_oid_reads_and_a_malformed_one_does_not() {
        // 1.2.840.113549.1.1.11, sha256WithRSAEncryption.
        let good = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        assert!(Der::new(&good).oid().is_ok());
        // Ends mid-arc.
        assert_eq!(
            Der::new(&[0x06, 0x02, 0x2A, 0x86]).oid(),
            Err(Asn1Error::BadOid)
        );
        // Empty.
        assert_eq!(Der::new(&[0x06, 0x00]).oid(), Err(Asn1Error::BadOid));
        // A leading 0x80 in an arc: base-128 with a leading zero, a second
        // spelling of the same arc.
        assert_eq!(
            Der::new(&[0x06, 0x03, 0x2A, 0x80, 0x01]).oid(),
            Err(Asn1Error::BadOid)
        );
    }

    #[test]
    fn a_boolean_must_be_der_and_not_merely_ber() {
        assert_eq!(Der::new(&boolean(true)).boolean(), Ok(true));
        assert_eq!(Der::new(&boolean(false)).boolean(), Ok(false));
        // BER allows any non-zero. DER does not, and neither does this.
        assert_eq!(
            Der::new(&[0x01, 0x01, 0x01]).boolean(),
            Err(Asn1Error::BadBoolean)
        );
    }

    #[test]
    fn a_bit_string_with_unused_bits_is_refused() {
        assert_eq!(
            Der::new(&[0x03, 0x02, 0x00, 0xAB]).bit_string(),
            Ok(&[0xAB][..])
        );
        assert_eq!(
            Der::new(&[0x03, 0x02, 0x04, 0xA0]).bit_string(),
            Err(Asn1Error::BadBitString)
        );
        assert_eq!(
            Der::new(&[0x03, 0x00]).bit_string(),
            Err(Asn1Error::BadBitString)
        );
    }

    // -----------------------------------------------------------------------
    // Structure
    // -----------------------------------------------------------------------

    #[test]
    fn trailing_bytes_inside_a_structure_are_refused() {
        let encoded = sequence(&[integer_u64(1), integer_u64(2)]);
        let mut inner = Der::new(&encoded)
            .take_nested(tag::SEQUENCE)
            .expect("a sequence");
        assert_eq!(inner.integer_u64(), Ok(1));
        assert_eq!(
            inner.expect_end(),
            Err(Asn1Error::TrailingBytes),
            "a field left unread must not pass for a complete structure"
        );
    }

    /// The bytes out of `take_raw` must be exactly the bytes that went in, so a
    /// value can be stored and re-verified. A re-encode would differ and its
    /// signature would stop verifying, which fails closed and looks like a bad
    /// signer.
    #[test]
    fn take_raw_returns_the_delivered_bytes_and_not_a_reencoding() {
        let first = octet_string(b"one");
        let second = sequence(&[integer_u64(2)]);
        let mut buffer = first.clone();
        buffer.extend_from_slice(&second);

        let mut d = Der::new(&buffer);
        assert_eq!(d.take_raw(), Ok(&first[..]));
        assert_eq!(d.take_raw(), Ok(&second[..]));
        assert_eq!(d.expect_end(), Ok(()));

        // Including a long-form length, where a re-encoder is most likely to
        // choose different bytes.
        let big = octet_string(&vec![0x7Eu8; 300]);
        let mut d = Der::new(&big);
        assert_eq!(d.take_raw(), Ok(&big[..]));
    }

    #[test]
    fn peeking_is_how_an_optional_field_is_read_and_it_consumes_nothing() {
        let encoded = sequence(&[integer_u64(7)]);
        let mut inner = Der::new(&encoded)
            .take_nested(tag::SEQUENCE)
            .expect("a sequence");
        assert_eq!(inner.peek_tag(), Some(tag::INTEGER));
        assert_eq!(inner.peek_tag(), Some(tag::INTEGER));
        assert_eq!(inner.integer_u64(), Ok(7));
        assert_eq!(inner.peek_tag(), None);
    }

    #[test]
    fn nesting_past_the_bound_is_refused_rather_than_overflowing_the_stack() {
        let mut encoded = octet_string(b"leaf");
        for _ in 0..MAX_DEPTH + 4 {
            encoded = sequence(&[encoded]);
        }
        let mut d = Der::new(&encoded);
        let mut depth = 0usize;
        let error = loop {
            match d.take_nested(tag::SEQUENCE) {
                Ok(next) => {
                    d = next;
                    depth += 1;
                }
                Err(e) => break e,
            }
        };
        assert_eq!(error, Asn1Error::TooDeep);
        assert_eq!(depth, MAX_DEPTH);
    }

    #[test]
    fn an_algorithm_identifier_reads_with_and_without_parameters() {
        let sha384 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        let with = sequence(&[oid(&sha384), null()]);
        let (algorithm, parameters) = Der::new(&with)
            .algorithm_identifier()
            .expect("an algorithm identifier");
        assert_eq!(algorithm.as_bytes(), &sha384);
        assert_eq!(parameters, Some((tag::NULL, &[][..])));

        let without = sequence(&[oid(&sha384)]);
        let (algorithm, parameters) = Der::new(&without)
            .algorithm_identifier()
            .expect("an algorithm identifier");
        assert_eq!(algorithm.as_bytes(), &sha384);
        assert_eq!(parameters, None);
    }

    // -----------------------------------------------------------------------
    // GeneralizedTime, which is what an anchor's whole claim rests on
    // -----------------------------------------------------------------------

    #[test]
    fn a_generalized_time_reads_as_seconds_since_the_epoch() {
        let cases = [
            ("19700101000000Z", 0i64),
            ("19700101000001Z", 1),
            ("20000229120000Z", 951_825_600),
            ("20260730143000Z", 1_785_421_800),
            ("20261231235959Z", 1_798_761_599),
            // A fraction is discarded, never rounded.
            ("20260730143000.500Z", 1_785_421_800),
        ];
        for (text, expected) in cases {
            let encoded = tlv(tag::GENERALIZED_TIME, text.as_bytes());
            assert_eq!(
                Der::new(&encoded).generalized_time(),
                Ok(expected),
                "{text} did not read as {expected}"
            );
        }
    }

    /// A local time with no offset is a time nobody can place, and a token that
    /// carried one would name an instant up to a day away from the one an
    /// auditor reads. Refused rather than assumed to be UTC.
    #[test]
    fn a_time_without_z_or_with_an_offset_is_refused() {
        for text in [
            "20260730143000",
            "20260730143000+0200",
            "202607301430Z",
            "20260730143000z",
            "2026073014300Z",
            "20260730143060Z",
            "20260732143000Z",
            "20260230143000Z",
            "20261330143000Z",
            "20260730243000Z",
            "20260730146000Z",
            "20260730000000.Z",
            "20260730000000.xZ",
            "2026x730143000Z",
        ] {
            let encoded = tlv(tag::GENERALIZED_TIME, text.as_bytes());
            assert_eq!(
                Der::new(&encoded).generalized_time(),
                Err(Asn1Error::BadTime),
                "{text} should not have parsed"
            );
        }
    }

    /// 29 February exists in 2000 and 2024 and does not in 1900 or 2023. A leap
    /// rule that gets the century wrong is the classic way to be one day out.
    #[test]
    fn the_leap_year_rule_covers_the_century_cases() {
        for (text, ok) in [
            ("20000229000000Z", true),
            ("20240229000000Z", true),
            ("19000229000000Z", false),
            ("20230229000000Z", false),
            ("21000229000000Z", false),
            ("24000229000000Z", true),
        ] {
            let encoded = tlv(tag::GENERALIZED_TIME, text.as_bytes());
            assert_eq!(
                Der::new(&encoded).generalized_time().is_ok(),
                ok,
                "{text} should {}have parsed",
                if ok { "" } else { "not " }
            );
        }
    }

    // -----------------------------------------------------------------------
    // The writer produces what the reader demands
    // -----------------------------------------------------------------------

    #[test]
    fn every_length_the_writer_emits_is_one_the_reader_calls_minimal() {
        for size in [0usize, 1, 127, 128, 129, 255, 256, 257, 65_535, 65_536] {
            let encoded = octet_string(&vec![0x5A; size]);
            let mut d = Der::new(&encoded);
            assert_eq!(
                d.octet_string().map(<[u8]>::len),
                Ok(size),
                "a {size}-byte string did not round-trip"
            );
            assert_eq!(d.expect_end(), Ok(()));
        }
    }
}
