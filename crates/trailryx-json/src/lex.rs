//! Bytes: whitespace, strings, escapes, and UTF-8.
//!
//! # The rules that are easy to get subtly wrong
//!
//! - **Whitespace is exactly four bytes**: space, tab, LF, CR. Not
//!   `u8::is_ascii_whitespace`, which includes form feed, and not
//!   `char::is_whitespace`, which includes U+00A0 and U+2028.
//! - **A control character is `b < 0x20`**, full stop. U+007F DEL and
//!   U+0080..U+009F are *not* JSON control characters and are legal raw inside a
//!   string, so `char::is_control` is the wrong predicate and would reject
//!   documents every other parser accepts.
//! - **U+2028 and U+2029 are ordinary characters** inside a string. They are
//!   line separators in JavaScript and not in JSON, and treating them as record
//!   separators here would let a value split a line.
//! - **An unescaped LF inside a string is an error**, which is what makes one
//!   logical record impossible to split across two lines. Twenty of the
//!   sixty-seven parsers in the reference suite accept it; each of them lets an
//!   attacker inject a synthetic record between the halves of a real one.
//! - **Unescaping only shrinks.** `\uXXXX` is six bytes in and at most three
//!   out, a surrogate pair twelve in and four out, `\n` two in and one out, and
//!   a raw character is unchanged. That is why there is no separate cap on a
//!   string, and a property test asserts it rather than assuming it.
//! - **Invalid UTF-8 is refused with an offset, never repaired.** No
//!   `from_utf8_lossy` anywhere in this crate: U+FFFD substitution changes the
//!   bytes this store hashes.

use crate::{Encoding, JsonError, JsonResult, Syntax};
use std::borrow::Cow;

/// The four bytes RFC 8259 allows between tokens.
pub const WHITESPACE: [u8; 4] = [0x20, 0x09, 0x0A, 0x0D];

pub fn is_whitespace(b: u8) -> bool {
    b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D
}

/// Advance past whitespace. Returns the new offset.
pub fn skip_whitespace(bytes: &[u8], mut at: usize) -> usize {
    while at < bytes.len() && is_whitespace(bytes[at]) {
        at += 1;
    }
    at
}

/// Check that a whole slice is UTF-8, reporting the offset of the first bad byte.
///
/// Rejects overlong encodings, surrogates encoded as UTF-8 (`ED A0 80`) and
/// anything above U+10FFFF, because `std::str::from_utf8` already does and
/// because a hand-rolled check that missed one would be the interesting kind of
/// bug. The offset comes from the error's own `valid_up_to`.
pub fn check_utf8(bytes: &[u8], line: u64) -> JsonResult<&str> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => {
            // `error_len() == None` means the bytes ran out inside a sequence that
            // was still valid, which for the last line of a file a producer is
            // appending to is not a fault. Anything else is a sequence that cannot
            // be completed. Reporting both as the same thing made an ordinary
            // flush read as corruption.
            let kind = if e.error_len().is_none() {
                Encoding::IncompleteUtf8
            } else {
                Encoding::InvalidUtf8
            };
            Err(JsonError::encoding(kind, line, e.valid_up_to() as u64))
        }
    }
}

/// Scan one string, starting at the opening quote.
///
/// Returns the unescaped value and the offset just past the closing quote.
/// Borrowed when the string held no escape, which is the common case and the
/// reason the return type is a `Cow`: a span name copied for no reason is a
/// copy per span per line.
///
/// The caller has already established that the whole line is valid UTF-8, so
/// this looks only for the JSON-level faults: an unescaped control character, an
/// escape that is not in the alphabet, a `\u` without four hex digits, and an
/// unpaired surrogate.
pub fn scan_string<'a>(
    bytes: &'a [u8],
    at: usize,
    line: u64,
    scratch: &mut String,
) -> JsonResult<(Cow<'a, str>, usize)> {
    debug_assert_eq!(bytes.get(at), Some(&b'"'));
    let body = at + 1;
    let first = plain_run(bytes, body, line)?;
    match bytes.get(first) {
        None => return Err(JsonError::syntax(Syntax::UnexpectedEof, line, first as u64)),
        // Nothing to unescape, so the producer's own bytes are the value and a
        // span name costs no copy at all.
        Some(&b'"') => return Ok((Cow::Borrowed(text(bytes, body, first, line)?), first + 1)),
        Some(_) => {}
    }
    scratch.clear();
    scratch.push_str(text(bytes, body, first, line)?);
    let mut i = unescape_at(bytes, first, line, scratch)?;
    loop {
        let end = plain_run(bytes, i, line)?;
        if end > i {
            scratch.push_str(text(bytes, i, end, line)?);
        }
        match bytes.get(end) {
            None => return Err(JsonError::syntax(Syntax::UnexpectedEof, line, end as u64)),
            // One right-sized allocation per string that had an escape in it.
            // The unescaping itself builds into the caller's buffer, so a line
            // of ten thousand escaped strings grows one buffer and not ten
            // thousand.
            Some(&b'"') => return Ok((Cow::Owned(scratch.clone()), end + 1)),
            Some(_) => i = unescape_at(bytes, end, line, scratch)?,
        }
    }
}

/// Advance to the byte that ends a run of ordinary string content: the closing
/// quote, a backslash, or the end of the input.
///
/// The control check is the one that makes a record impossible to split: a raw
/// LF here would end the line in the framer above and turn the two halves of one
/// string into two records, and an attacker who can put a newline in a span name
/// can then write the second one.
fn plain_run(bytes: &[u8], mut at: usize, line: u64) -> JsonResult<usize> {
    while let Some(&b) = bytes.get(at) {
        if b == b'"' || b == b'\\' {
            break;
        }
        if b < 0x20 {
            return Err(JsonError::syntax(Syntax::ControlInString, line, at as u64));
        }
        at += 1;
    }
    Ok(at)
}

/// Borrow a range of the input as text.
///
/// Every range handed here starts and ends on an ASCII byte the scanner just
/// matched, so it cannot split a character, and the caller has already checked
/// the line. Reporting rather than unwrapping means a caller that skips
/// [`check_utf8`] gets a refusal with an offset instead of a panic.
fn text(bytes: &[u8], from: usize, to: usize, line: u64) -> JsonResult<&str> {
    match std::str::from_utf8(&bytes[from..to]) {
        Ok(s) => Ok(s),
        Err(e) => Err(JsonError::encoding(
            Encoding::InvalidUtf8,
            line,
            (from + e.valid_up_to()) as u64,
        )),
    }
}

/// Unescape the sequence starting at the backslash at `at`, appending to `out`.
/// Returns the offset just past what it consumed.
///
/// A surrogate is never substituted and never dropped. `"superadmin\ud888"` has
/// to be a refusal, because U+FFFD would change the bytes this store hashes and
/// truncation would hand back `superadmin`.
fn unescape_at(bytes: &[u8], at: usize, line: u64, out: &mut String) -> JsonResult<usize> {
    let Some(&esc) = bytes.get(at + 1) else {
        return Err(JsonError::syntax(
            Syntax::UnexpectedEof,
            line,
            (at + 1) as u64,
        ));
    };
    if let Some(b) = unescape_simple(esc) {
        out.push(char::from(b));
        return Ok(at + 2);
    }
    if esc != b'u' {
        return Err(JsonError::syntax(Syntax::BadEscape, line, (at + 1) as u64));
    }
    let lone = JsonError::syntax(Syntax::LoneSurrogate, line, at as u64);
    let high = hex4_at(bytes, at + 2)
        .ok_or_else(|| JsonError::syntax(Syntax::BadEscape, line, (at + 2) as u64))?;
    if is_low_surrogate(high) {
        return Err(lone);
    }
    if !is_high_surrogate(high) {
        // Not a surrogate, so this is a whole scalar value, including U+0000,
        // which stays one code unit in the middle of the string rather than
        // ending it.
        let c = char::from_u32(u32::from(high)).ok_or(lone)?;
        out.push(c);
        return Ok(at + 6);
    }
    let pair = at + 6;
    if bytes.get(pair) != Some(&b'\\') || bytes.get(pair + 1) != Some(&b'u') {
        return Err(lone);
    }
    let low = hex4_at(bytes, pair + 2)
        .ok_or_else(|| JsonError::syntax(Syntax::BadEscape, line, (pair + 2) as u64))?;
    if !is_low_surrogate(low) {
        return Err(lone);
    }
    let c = char::from_u32(combine_surrogates(high, low)).ok_or(lone)?;
    out.push(c);
    Ok(pair + 6)
}

fn hex4_at(bytes: &[u8], at: usize) -> Option<u16> {
    hex4(bytes.get(at..)?)
}

/// The escape alphabet, exactly: `" \ / b f n r t u`. Anything else is
/// [`Syntax::BadEscape`], including `\'` and `\0`, which several languages allow
/// and JSON does not.
pub fn unescape_simple(b: u8) -> Option<u8> {
    match b {
        b'"' => Some(b'"'),
        b'\\' => Some(b'\\'),
        b'/' => Some(b'/'),
        b'b' => Some(0x08),
        b'f' => Some(0x0C),
        b'n' => Some(0x0A),
        b'r' => Some(0x0D),
        b't' => Some(0x09),
        _ => None,
    }
}

/// Four hex digits to a `u16`, or `None`. ASCII only, by numeric range.
pub fn hex4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 4 {
        return None;
    }
    let mut v: u16 = 0;
    for &b in &bytes[..4] {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | u16::from(d);
    }
    Some(v)
}

pub fn is_high_surrogate(u: u16) -> bool {
    (0xD800..=0xDBFF).contains(&u)
}

pub fn is_low_surrogate(u: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&u)
}

/// Combine a surrogate pair into a scalar value.
pub fn combine_surrogates(high: u16, low: u16) -> u32 {
    0x1_0000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(low) - 0xDC00)
}

/// The three errors this module raises, so the implementation cannot invent
/// others for the same conditions.
#[allow(dead_code)]
fn errors(line: u64, at: usize) -> [JsonError; 3] {
    [
        JsonError::syntax(Syntax::ControlInString, line, at as u64),
        JsonError::syntax(Syntax::BadEscape, line, at as u64),
        JsonError::syntax(Syntax::LoneSurrogate, line, at as u64),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kind;

    /// The line number is arbitrary and only travels into the error, so every
    /// test here uses the same one and asserts on the offset instead.
    const LINE: u64 = 7;

    fn scan(src: &[u8]) -> JsonResult<(String, usize)> {
        let mut scratch = String::new();
        let (value, end) = scan_string(src, 0, LINE, &mut scratch)?;
        Ok((value.into_owned(), end))
    }

    fn kind(src: &[u8]) -> Kind {
        let mut scratch = String::new();
        scan_string(src, 0, LINE, &mut scratch)
            .expect_err("these bytes must be refused")
            .kind
    }

    #[test]
    fn whitespace_is_exactly_four_bytes_and_form_feed_is_not_one_of_them() {
        for b in 0u8..=255 {
            let expected = WHITESPACE.contains(&b);
            assert_eq!(is_whitespace(b), expected, "byte {b:#04x}");
        }
        // The two that a careless predicate would add: form feed is in
        // `u8::is_ascii_whitespace`, and U+00A0's lead byte is in
        // `char::is_whitespace`.
        assert!(!is_whitespace(0x0C));
        assert!(!is_whitespace(0xC2));
    }

    #[test]
    fn skipping_whitespace_stops_on_the_first_byte_that_is_not_whitespace() {
        assert_eq!(skip_whitespace(b" \t\r\n{", 0), 4);
        assert_eq!(skip_whitespace(b"{", 0), 0);
        assert_eq!(skip_whitespace(b"  ", 0), 2);
    }

    #[test]
    fn del_and_the_c1_range_are_ordinary_characters_inside_a_string() {
        // U+007F and U+0080..U+009F are not JSON control characters, so
        // `char::is_control` is the wrong predicate: using it would refuse
        // documents every other parser accepts.
        let (value, end) = scan(b"\"\x7f\xc2\x80\xc2\x9f\"").unwrap();
        assert_eq!(value, "\u{7f}\u{80}\u{9f}");
        assert_eq!(end, 7);
    }

    #[test]
    fn the_line_separators_javascript_has_are_ordinary_characters_here() {
        let src = "\"a\u{2028}b\u{2029}c\"";
        let (value, _) = scan(src.as_bytes()).unwrap();
        assert_eq!(value, "a\u{2028}b\u{2029}c");
    }

    #[test]
    fn a_raw_newline_inside_a_string_is_refused_so_a_record_cannot_be_split() {
        assert_eq!(
            kind(b"\"a\nb\""),
            Kind::Syntax(Syntax::ControlInString),
            "LF"
        );
        assert_eq!(
            kind(b"\"a\rb\""),
            Kind::Syntax(Syntax::ControlInString),
            "CR"
        );
        assert_eq!(
            kind(b"\"a\tb\""),
            Kind::Syntax(Syntax::ControlInString),
            "tab"
        );
        assert_eq!(
            kind(b"\"a\0b\""),
            Kind::Syntax(Syntax::ControlInString),
            "NUL"
        );
    }

    #[test]
    fn a_control_character_is_reported_where_it_sits_not_at_the_end() {
        let err = scan_string(b"\"abc\nd\"", 0, LINE, &mut String::new()).unwrap_err();
        assert_eq!(err.kind, Kind::Syntax(Syntax::ControlInString));
        assert_eq!(err.byte_in_line, 4);
        assert_eq!(err.line, LINE);
    }

    #[test]
    fn a_control_character_after_an_escape_is_refused_too() {
        // The second pass has its own copy of the run scanner, and an early
        // version of this checked only in the first.
        assert_eq!(kind(b"\"a\\nb\nc\""), Kind::Syntax(Syntax::ControlInString));
    }

    #[test]
    fn the_escape_alphabet_is_exactly_the_nine_the_grammar_names() {
        for (src, want) in [
            (br#""\"""#.as_slice(), "\""),
            (br#""\\""#, "\\"),
            (br#""\/""#, "/"),
            (br#""\b""#, "\u{08}"),
            (br#""\f""#, "\u{0c}"),
            (br#""\n""#, "\n"),
            (br#""\r""#, "\r"),
            (br#""\t""#, "\t"),
            (br#""\u0041""#, "A"),
        ] {
            let (value, _) = scan(src).unwrap_or_else(|e| panic!("{src:?}: {e}"));
            assert_eq!(value, want, "{src:?}");
        }
    }

    #[test]
    fn an_escape_the_grammar_does_not_have_is_refused() {
        // Every one of these is legal in some other language's string literal,
        // which is exactly why a lenient reader accepts them.
        for src in [
            br#""\'""#.as_slice(),
            br#""\0""#,
            br#""\a""#,
            br#""\v""#,
            br#""\x41""#,
            br#""\U0041""#,
            // A backslash before a real newline. Several languages read that as
            // a line continuation; JSON does not have one.
            b"\"\\\n\"",
        ] {
            assert_eq!(kind(src), Kind::Syntax(Syntax::BadEscape), "{src:?}");
        }
    }

    #[test]
    fn a_u_escape_needs_four_ascii_hex_digits() {
        for src in [
            br#""\u""#.as_slice(),
            br#""\u12""#,
            br#""\u123""#,
            br#""\u123g""#,
            br#""\u 123""#,
            br#""\u+123""#,
        ] {
            assert_eq!(kind(src), Kind::Syntax(Syntax::BadEscape), "{src:?}");
        }
        // Fullwidth digits are digits to `char::is_numeric` and not to the
        // grammar.
        let wide = "\"\\u\u{ff11}\u{ff11}\u{ff11}\u{ff11}\"";
        assert_eq!(kind(wide.as_bytes()), Kind::Syntax(Syntax::BadEscape));
    }

    #[test]
    fn hex4_reads_both_cases_and_refuses_anything_else() {
        assert_eq!(hex4(b"0041"), Some(0x0041));
        assert_eq!(hex4(b"abcd"), Some(0xabcd));
        assert_eq!(hex4(b"ABCD"), Some(0xabcd));
        assert_eq!(hex4(b"ffff"), Some(0xffff));
        assert_eq!(hex4(b"00"), None);
        assert_eq!(hex4(b"00g0"), None);
        assert_eq!(hex4(b"-100"), None);
    }

    #[test]
    fn a_nul_escape_is_one_code_unit_and_does_not_end_the_string() {
        let (value, end) = scan(br#""a\u0000b""#).unwrap();
        assert_eq!(value.as_bytes(), b"a\0b");
        assert_eq!(value.chars().count(), 3);
        assert_eq!(end, 10);
    }

    #[test]
    fn a_surrogate_pair_decodes_including_the_last_scalar_value() {
        let (value, end) = scan(br#""\udbff\udfff""#).unwrap();
        assert_eq!(value, "\u{10ffff}");
        assert_eq!(end, 14);
        let (emoji, _) = scan(br#""\ud83d\ude00""#).unwrap();
        assert_eq!(emoji, "\u{1f600}");
        // Upper case in the escape is the same character.
        let (upper, _) = scan(br#""\uD83D\uDE00""#).unwrap();
        assert_eq!(upper, "\u{1f600}");
    }

    #[test]
    fn a_lone_surrogate_is_refused_rather_than_substituted_or_truncated() {
        // The published escalation is the truncation: this must never hand back
        // "superadmin".
        for src in [
            br#""superadmin\ud888""#.as_slice(),
            br#""\ud888""#,
            br#""\ud888x""#,
            br#""\ud888\u0041""#,
            br#""\ud888\ud888""#,
            br#""\udc00""#,
            br#""\udfff\udbff""#,
        ] {
            assert_eq!(kind(src), Kind::Syntax(Syntax::LoneSurrogate), "{src:?}");
        }
    }

    #[test]
    fn a_string_with_no_escape_is_borrowed_and_one_with_an_escape_is_owned() {
        let mut scratch = String::new();
        let (plain, _) = scan_string(b"\"span.name\"", 0, LINE, &mut scratch).unwrap();
        assert!(matches!(plain, Cow::Borrowed(_)));
        let (escaped, _) = scan_string(br#""span\tname""#, 0, LINE, &mut scratch).unwrap();
        assert!(matches!(escaped, Cow::Owned(_)));
        assert_eq!(escaped, "span\tname");
    }

    #[test]
    fn unescaping_only_ever_shrinks_which_is_why_there_is_no_cap_on_a_string() {
        for src in [
            br#""\u0041""#.as_slice(),
            br#""\udbff\udfff""#,
            br#""\n\t\\\"""#,
            br#""\uffff""#,
            br#""plain""#,
            br#""mixed \u00e9 text\n""#,
        ] {
            let (value, end) = scan(src).unwrap();
            assert_eq!(end, src.len(), "{src:?}");
            assert!(
                value.len() <= src.len() - 2,
                "{src:?} unescaped to {} bytes from a {}-byte literal",
                value.len(),
                src.len()
            );
        }
    }

    #[test]
    fn an_unterminated_string_is_the_document_ending_not_a_bad_escape() {
        assert_eq!(kind(b"\"abc"), Kind::Syntax(Syntax::UnexpectedEof));
        assert_eq!(kind(b"\""), Kind::Syntax(Syntax::UnexpectedEof));
        assert_eq!(kind(b"\"abc\\"), Kind::Syntax(Syntax::UnexpectedEof));
        assert_eq!(kind(br#""abc\n"#), Kind::Syntax(Syntax::UnexpectedEof));
    }

    #[test]
    fn the_empty_string_is_a_string() {
        let (value, end) = scan(b"\"\"").unwrap();
        assert!(value.is_empty());
        assert_eq!(end, 2);
    }

    #[test]
    fn the_offset_returned_is_just_past_the_closing_quote() {
        let (_, end) = scan(b"\"ab\":1").unwrap();
        assert_eq!(end, 4);
    }

    #[test]
    fn checking_utf8_names_the_offset_of_the_first_bad_byte() {
        // Each of these is a byte sequence a lenient decoder has historically
        // accepted, and each one is a different way to smuggle a character past
        // a filter that looked at the bytes.
        for (bytes, at, what) in [
            (b"ab\xc0\xaf".as_slice(), 2, "overlong solidus"),
            (b"\xc0\xaf", 0, "overlong solidus at the start"),
            (b"x\xed\xa0\x80", 1, "a surrogate encoded as UTF-8"),
            (b"\xf4\xbf\xbf\xbf", 0, "above U+10FFFF"),
            (b"\x80", 0, "a lone continuation byte"),
            (b"ok\xff", 2, "never a UTF-8 byte"),
        ] {
            let err = check_utf8(bytes, LINE).expect_err(what);
            assert_eq!(err.kind, Kind::Encoding(Encoding::InvalidUtf8), "{what}");
            assert_eq!(err.byte_in_line, at, "{what}");
            assert_eq!(err.line, LINE, "{what}");
        }
    }

    #[test]
    fn a_sequence_that_merely_ran_out_of_bytes_is_told_apart_from_a_broken_one() {
        // The distinction exists for one reason: the last line of a file a
        // collector is appending to ends wherever the flush ended, which is as
        // likely to be inside a character as between two members. Reporting both
        // as invalid made an ordinary flush produce a warning record claiming a
        // line had been lost. Measured over every truncation point of one
        // Ukrainian-language line, nineteen of two hundred and ninety-nine did it.
        for (bytes, what) in [
            (b"\xe2\x82".as_slice(), "two bytes of the euro sign"),
            (b"\xd0", "the lead byte of a Cyrillic letter"),
            (b"ab\xf0\x9d\x84", "three bytes of an astral character"),
        ] {
            let err = check_utf8(bytes, LINE).expect_err(what);
            assert_eq!(
                err.kind,
                Kind::Encoding(Encoding::IncompleteUtf8),
                "{what}: these bytes are a prefix, not a fault"
            );
        }
        // And a sequence that cannot be completed stays invalid however few bytes
        // of it there are, because no continuation makes `C0` legal.
        assert_eq!(
            check_utf8(b"\xc0", LINE).unwrap_err().kind,
            Kind::Encoding(Encoding::InvalidUtf8)
        );
    }

    #[test]
    fn checking_utf8_accepts_the_characters_that_are_only_odd() {
        for bytes in [
            "\u{7f}".as_bytes(),
            "\u{80}".as_bytes(),
            "\u{2028}".as_bytes(),
            "\u{10ffff}".as_bytes(),
            "\u{fffd}".as_bytes(),
            b"",
        ] {
            assert!(check_utf8(bytes, LINE).is_ok(), "{bytes:?}");
        }
    }

    #[test]
    fn combining_a_pair_covers_the_whole_supplementary_range() {
        assert_eq!(combine_surrogates(0xD800, 0xDC00), 0x1_0000);
        assert_eq!(combine_surrogates(0xDBFF, 0xDFFF), 0x10_FFFF);
        assert!(is_high_surrogate(0xD800) && is_high_surrogate(0xDBFF));
        assert!(!is_high_surrogate(0xDC00));
        assert!(is_low_surrogate(0xDC00) && is_low_surrogate(0xDFFF));
        assert!(!is_low_surrogate(0xDBFF));
        assert!(!is_high_surrogate(0xE000) && !is_low_surrogate(0xE000));
    }

    #[test]
    fn the_scratch_buffer_is_reused_across_strings() {
        // The point of handing one in: a line of escaped strings must not
        // allocate a buffer per string.
        let mut scratch = String::new();
        for _ in 0..8 {
            let (value, _) = scan_string(br#""a\tb\tc""#, 0, LINE, &mut scratch).unwrap();
            assert_eq!(value, "a\tb\tc");
        }
        assert_eq!(scratch, "a\tb\tc");
        assert!(scratch.capacity() >= 5);
    }
}
