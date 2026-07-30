//! Numbers, validated as bytes and converted only when asked.
//!
//! # Why nothing is converted eagerly
//!
//! An OTLP timestamp is a 64-bit integer and routinely larger than 2^53, so a
//! reader that parsed every number into an `f64` and narrowed later would lose
//! the low bits of every timestamp in the file and produce records that sort
//! wrongly against themselves. Keeping the producer's digits until an accessor
//! asks means the integer path never touches a float at all.
//!
//! # What goes wrong if `str::parse` is trusted
//!
//! It is not a JSON grammar and it should not be mistaken for one. Verified
//! locally: `"01"`, `"+1"`, `".5"`, `"5."`, `"inf"`, `"NaN"` and `"-Infinity"`
//! all parse `Ok` as `f64`, and `"01"` and `"+1"` parse `Ok` as `i64`. So
//! [`scan`] checks the grammar first and `parse` is only ever handed a slice it
//! cannot misread.
//!
//! And the hazards on the other side, each verified and each avoided here:
//! `"9223372036854775808".parse::<u64>()` succeeds and `as i64` then gives
//! `i64::MIN`; wrapping accumulation of `18446744073709551616` gives 0; `NaN as
//! i64` gives 0; `f64::INFINITY as i64` and `1e19 as i64` both give `i64::MAX`.
//! Every one of those is a plausible-looking value standing in for a refusal, so
//! there is no float-to-integer cast anywhere on this path and a test greps for
//! one.

use crate::{Bound, JsonError, JsonResult, Syntax};

/// A number as the producer wrote it.
///
/// Borrowed, so scanning allocates nothing. Copy, because it is two words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Number<'a> {
    raw: &'a [u8],
    /// Whether the literal has a fraction or an exponent. An integer literal can
    /// be read exactly; the others have to go through `f64` and say so.
    integral: bool,
}

impl<'a> Number<'a> {
    /// The bytes exactly as they appeared. What a test compares, and what an
    /// oracle is handed.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Whether the literal was written without a fraction or an exponent.
    pub fn is_integer_literal(&self) -> bool {
        self.integral
    }

    /// The value as a `u64`, exactly, or `None`.
    ///
    /// `None` for a negative number, for anything above `u64::MAX`, and for a
    /// literal that is not an exact integer. Never a saturated or wrapped stand
    /// -in: a caller that gets `None` has to decide what to do, and every caller
    /// in the tree counts it.
    ///
    /// An exponent is accepted when it scales to an exact integer by checked
    /// integer multiplication, because `1e3` and `1000` are the same number and
    /// a producer is allowed to write either.
    pub fn as_u64(&self) -> Option<u64> {
        let magnitude = self.magnitude()?;
        // `-0` is zero, and zero is a `u64`. Any other minus sign is not.
        if self.negative() && magnitude != 0 {
            return None;
        }
        Some(magnitude)
    }

    /// The value as an `i64`, exactly, or `None`. Same rules as [`Self::as_u64`].
    pub fn as_i64(&self) -> Option<i64> {
        let magnitude = self.magnitude()?;
        if !self.negative() {
            return i64::try_from(magnitude).ok();
        }
        // `i64::MIN` has no positive counterpart, so `try_from` then negate
        // would refuse the one value that is legal. `try_from` rather than a
        // cast throughout: `9223372036854775808u64 as i64` is `i64::MIN`, which
        // is a wrong answer that looks like a right one.
        if magnitude == i64::MIN.unsigned_abs() {
            return Some(i64::MIN);
        }
        i64::try_from(magnitude).ok()?.checked_neg()
    }

    /// The value as a finite `f64`, or `None` if it overflows to infinity.
    ///
    /// Underflow to zero is accepted, overflow to infinity is refused, and the
    /// asymmetry is deliberate rather than tidy: `123.456e-789` is a number so
    /// small we cannot tell it from zero, while `1e999` is a *finite* number the
    /// type cannot hold, and storing infinity for it would be a repair. This
    /// tree does not repair.
    pub fn as_f64_finite(&self) -> Option<f64> {
        // Safe to hand to `parse` only because [`scan`] has already refused
        // everything `parse` would misread. See the module doc for the list.
        let value: f64 = std::str::from_utf8(self.raw).ok()?.parse().ok()?;
        if value.is_finite() { Some(value) } else { None }
    }

    fn negative(&self) -> bool {
        self.raw.first() == Some(&b'-')
    }

    /// The magnitude as a `u64`, exactly, or `None` when the literal is not an
    /// exact integer or does not fit.
    ///
    /// Accumulated from the digits with checked arithmetic. Nothing here goes
    /// near an `f64`: `1e19 as i64` is `i64::MAX` and wrapping accumulation of
    /// `18446744073709551616` is 0, and both of those are a refusal wearing a
    /// plausible value's clothes.
    fn magnitude(&self) -> Option<u64> {
        let (_, mantissa, exponent) = decompose(self.raw);
        let mut count = mantissa.count();
        // Zero is zero at every exponent, and answering that first is what keeps
        // `0e1000000000` from asking for a billion multiplications.
        if (0..count).all(|i| mantissa.digit(i) == b'0') {
            return Some(0);
        }
        let mut scale = exponent.checked_sub(i64::try_from(mantissa.frac.len()).ok()?)?;
        // Trailing zeros pay for a negative exponent: `1000e-2` is the integer
        // 10, and a reader that refused it would refuse a number a producer is
        // entitled to write.
        while scale < 0 && count > 0 && mantissa.digit(count - 1) == b'0' {
            count -= 1;
            scale += 1;
        }
        if scale < 0 {
            return None;
        }
        let mut value: u64 = 0;
        for i in 0..count {
            value = value
                .checked_mul(10)?
                .checked_add(u64::from(mantissa.digit(i) - b'0'))?;
        }
        // At least one digit was not a zero, so `value` is at least 1 and the
        // multiplication overflows within twenty steps. A thousand-digit
        // exponent therefore costs twenty multiplications and not a thousand.
        for _ in 0..scale {
            value = value.checked_mul(10)?;
        }
        Some(value)
    }
}

/// The digits of a mantissa, as one sequence across the decimal point.
///
/// Two slices rather than one buffer because `1.5` keeps its digits either side
/// of a byte that is not one, and copying them together to read them would be an
/// allocation per number.
#[derive(Debug)]
struct Mantissa<'a> {
    int: &'a [u8],
    frac: &'a [u8],
}

impl Mantissa<'_> {
    fn count(&self) -> usize {
        self.int.len() + self.frac.len()
    }

    /// The `i`th digit, counting the integer part first. Callers only ever ask
    /// for indices below [`Self::count`].
    fn digit(&self, i: usize) -> u8 {
        match self.int.get(i) {
            Some(&b) => b,
            None => self.frac[i - self.int.len()],
        }
    }
}

/// Beyond this the exponent's exact value stops mattering: ten to the millionth
/// is neither a `u64` nor a finite `f64`. Clamping is what keeps a
/// thousand-digit exponent from overflowing the accumulator that reads it.
const EXPONENT_CAP: i64 = 1_000_000;

/// Split a literal [`scan`] has already accepted into sign, mantissa and
/// exponent.
fn decompose(raw: &[u8]) -> (bool, Mantissa<'_>, i64) {
    let negative = raw.first() == Some(&b'-');
    let mut at = usize::from(negative);
    let int_from = at;
    while matches!(raw.get(at), Some(b'0'..=b'9')) {
        at += 1;
    }
    let int = &raw[int_from..at];
    let mut frac: &[u8] = &[];
    if raw.get(at) == Some(&b'.') {
        at += 1;
        let frac_from = at;
        while matches!(raw.get(at), Some(b'0'..=b'9')) {
            at += 1;
        }
        frac = &raw[frac_from..at];
    }
    let mut exponent: i64 = 0;
    if matches!(raw.get(at), Some(b'e' | b'E')) {
        at += 1;
        let mut exponent_negative = false;
        match raw.get(at) {
            Some(&b'-') => {
                exponent_negative = true;
                at += 1;
            }
            Some(&b'+') => at += 1,
            _ => {}
        }
        while let Some(&b) = raw.get(at) {
            // `is_ascii_digit` is the same `b'0'..=b'9'` range check as
            // everywhere else here, and not `char::is_numeric`, which would make
            // U+FF11 FULLWIDTH DIGIT ONE a digit.
            if !b.is_ascii_digit() {
                break;
            }
            exponent = exponent
                .saturating_mul(10)
                .saturating_add(i64::from(b - b'0'))
                .min(EXPONENT_CAP);
            at += 1;
        }
        if exponent_negative {
            exponent = -exponent;
        }
    }
    (negative, Mantissa { int, frac }, exponent)
}

/// Scan one number from the front of `bytes`.
///
/// Returns the number and how many bytes it used. The grammar is RFC 8259's
/// exactly: an optional `-`, then `0` or a nonzero digit followed by digits, then
/// an optional `.` with at least one digit, then an optional `e` or `E` with an
/// optional sign and at least one digit. Leading `+`, a leading zero before
/// another digit, a bare `.5`, a bare `5.`, a truncated exponent, a hex literal
/// and a digit separator are all [`Syntax::BadNumber`].
///
/// Digits are classified by numeric range, never by `char::is_numeric`, so
/// U+FF11 FULLWIDTH DIGIT ONE is not a digit.
pub fn scan<'a>(
    bytes: &'a [u8],
    at: usize,
    line: u64,
    max_bytes: usize,
) -> JsonResult<(Number<'a>, usize)> {
    let bad = |offset: usize| JsonError::syntax(Syntax::BadNumber, line, offset as u64);
    let mut i = at;
    if bytes.get(i) == Some(&b'-') {
        i += 1;
    }
    match bytes.get(i) {
        // A leading zero before another digit is refused because the producer
        // and the reader would otherwise disagree about `0123`: octal to one,
        // 123 to the other, and neither is what JSON says.
        Some(b'0') => {
            i += 1;
            if matches!(bytes.get(i), Some(b'0'..=b'9')) {
                return Err(bad(i));
            }
        }
        Some(b'1'..=b'9') => {
            while matches!(bytes.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        // A leading `+`, a bare `.5`, `Infinity` and a `-` with nothing behind
        // it all land here.
        _ => return Err(bad(i)),
    }
    let mut integral = true;
    if bytes.get(i) == Some(&b'.') {
        integral = false;
        i += 1;
        let from = i;
        while matches!(bytes.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        // `5.` is not a number here. Accepting it would mean the store's bytes
        // and the producer's bytes differ by a digit nobody wrote.
        if i == from {
            return Err(bad(i));
        }
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        integral = false;
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let from = i;
        while matches!(bytes.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == from {
            return Err(bad(i));
        }
    }
    // Only whitespace or punctuation may follow a number, so anything else is
    // part of a literal the producer thought they were writing. Without this,
    // `0x1f`, `1_000`, `1f` and `1e1e1` would each read as the number in front
    // of them and the rest would surface as content after the value, which names
    // the wrong fault in the wrong place. A colon counts as punctuation even
    // though no number is ever legally followed by one: `[1:2]` is a container
    // fault, and the container driver names it better than this can.
    if let Some(&b) = bytes.get(i) {
        let punctuation = matches!(b, b',' | b':' | b']' | b'}');
        if !punctuation && !crate::lex::is_whitespace(b) {
            return Err(bad(i));
        }
    }
    let used = i - at;
    // Checked after the scan rather than during it, because the line above is
    // already capped at `Limits::max_line_bytes`, so the walk is bounded either
    // way. The bound is a `Limit` and not a `Syntax`: a thousand-digit number is
    // JSON and we are declining to read it.
    if used > max_bytes {
        return Err(JsonError::limit(Bound::NumberDigits, line, at as u64));
    }
    Ok((
        Number {
            raw: &bytes[at..i],
            integral,
        },
        used,
    ))
}

/// The two errors this module raises, so the implementation cannot invent others.
#[allow(dead_code)]
fn errors(line: u64, at: usize) -> (JsonError, JsonError) {
    (
        JsonError::syntax(Syntax::BadNumber, line, at as u64),
        JsonError::limit(Bound::NumberDigits, line, at as u64),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kind;

    const LINE: u64 = 3;
    const MAX: usize = 1024;

    fn number(src: &str) -> Number<'_> {
        let (value, used) = scan(src.as_bytes(), 0, LINE, MAX)
            .unwrap_or_else(|e| panic!("{src} must be a number: {e}"));
        assert_eq!(used, src.len(), "{src} used {used} of {} bytes", src.len());
        value
    }

    fn refusal(src: &str) -> Kind {
        scan(src.as_bytes(), 0, LINE, MAX)
            .expect_err("these bytes must be refused")
            .kind
    }

    #[test]
    fn every_shape_the_grammar_has_is_accepted() {
        for src in [
            "0",
            "-0",
            "1",
            "-1",
            "42",
            "1234567890",
            "0.0",
            "1.5",
            "-1.5",
            "0e1",
            "0e+1",
            "0E-1",
            "1e2",
            "1E2",
            "1e+2",
            "1e-2",
            "123.456e-789",
            "-0.0e-0",
            "9223372036854775807",
            "18446744073709551616",
        ] {
            let value = number(src);
            assert_eq!(value.raw(), src.as_bytes(), "{src}");
        }
    }

    #[test]
    fn every_shape_the_grammar_does_not_have_is_refused() {
        // Rust's own `f64` parser accepts five of these and its `i64` parser two
        // of them, which is the whole reason the grammar is checked here first.
        for src in [
            "01",
            "00",
            "-01",
            "+1",
            ".5",
            "5.",
            "1.",
            "1.e5",
            "-.5",
            "1e",
            "1e+",
            "1e-",
            "1ee1",
            "-",
            "-e1",
            "NaN",
            "nan",
            "Infinity",
            "-Infinity",
            "inf",
            "e1",
            "--1",
            "٣",
            "0.e1",
        ] {
            assert_eq!(refusal(src), Kind::Syntax(Syntax::BadNumber), "{src}");
        }
    }

    #[test]
    fn a_number_ends_at_a_delimiter_and_anything_else_behind_it_is_a_bad_number() {
        // Each of these is one literal a producer meant to write, so the fault
        // is the number and not content after a complete value.
        for src in [
            "0x1f", "1_000", "1.2.3", "1f", "1+", "1e1e1", "0e1x", "1.0d",
        ] {
            assert_eq!(refusal(src), Kind::Syntax(Syntax::BadNumber), "{src}");
        }
        // The four things that may legally follow one.
        for (src, used) in [("1,2", 1), ("1]", 1), ("1}", 1), ("1 2", 1), ("12", 2)] {
            let (value, got) = scan(src.as_bytes(), 0, LINE, MAX).unwrap();
            assert_eq!(got, used, "{src}");
            assert_eq!(value.raw(), &src.as_bytes()[..used], "{src}");
        }
    }

    #[test]
    fn a_scan_reads_from_the_offset_it_was_given() {
        let (value, used) = scan(b"[42]", 1, LINE, MAX).unwrap();
        assert_eq!(value.raw(), b"42");
        assert_eq!(used, 2);
    }

    #[test]
    fn a_number_longer_than_the_bound_is_a_limit_and_not_a_syntax_error() {
        // 1025 digits is JSON and we are declining to read it, so an operator
        // can tell "raise the bound" from "fix the producer".
        let long = "1".repeat(1025);
        assert_eq!(
            refusal(&long),
            Kind::Limit(Bound::NumberDigits),
            "1025 digits"
        );
        let at_the_bound = "1".repeat(1024);
        assert_eq!(number(&at_the_bound).raw().len(), 1024);
        // The exponent-expansion class the bound exists for.
        let expanded = format!("9.223372E+{}", "1".repeat(1020));
        assert_eq!(refusal(&expanded), Kind::Limit(Bound::NumberDigits));
    }

    #[test]
    fn the_sign_and_the_shape_of_the_literal_are_both_remembered() {
        assert!(number("42").is_integer_literal());
        assert!(number("-42").is_integer_literal());
        assert!(!number("42.0").is_integer_literal());
        assert!(!number("42e1").is_integer_literal());
        assert!(!number("42E1").is_integer_literal());
    }

    #[test]
    fn a_sixty_four_bit_integer_survives_the_trip_exactly() {
        // The bit that a float path loses: 9223372036854775807 as an f64 is
        // 9223372036854775808.
        assert_eq!(number("9223372036854775807").as_i64(), Some(i64::MAX));
        assert_eq!(
            number("9223372036854775807").as_u64(),
            Some(9_223_372_036_854_775_807)
        );
        assert_eq!(number("-9223372036854775808").as_i64(), Some(i64::MIN));
        assert_eq!(number("18446744073709551615").as_u64(), Some(u64::MAX));
        assert_eq!(
            number("1755100000000000000").as_u64(),
            Some(1_755_100_000_000_000_000)
        );
    }

    #[test]
    fn a_value_that_does_not_fit_is_none_and_never_a_stand_in() {
        // Each of these has a plausible-looking wrong answer: `as i64` gives
        // i64::MIN for the first, wrapping accumulation gives 0 for the second,
        // and saturation gives i64::MAX for the third.
        assert_eq!(number("9223372036854775808").as_i64(), None);
        assert_eq!(
            number("9223372036854775808").as_u64(),
            Some(9_223_372_036_854_775_808)
        );
        assert_eq!(number("18446744073709551616").as_u64(), None);
        assert_eq!(number("18446744073709551616").as_i64(), None);
        assert_eq!(number("-9223372036854775809").as_i64(), None);
        assert_eq!(number("1e19").as_i64(), None);
        assert_eq!(number("1e19").as_u64(), Some(10_000_000_000_000_000_000));
        assert_eq!(number("1e20").as_u64(), None);
        assert_eq!(number("1e1000000").as_u64(), None);
    }

    #[test]
    fn a_negative_literal_is_not_a_u64_but_negative_zero_is_zero() {
        assert_eq!(number("-1").as_u64(), None);
        assert_eq!(number("-1").as_i64(), Some(-1));
        assert_eq!(number("-0").as_u64(), Some(0));
        assert_eq!(number("-0").as_i64(), Some(0));
        assert_eq!(number("-0.0").as_u64(), Some(0));
        assert_eq!(number("-0e999").as_u64(), Some(0));
    }

    #[test]
    fn an_exponent_is_accepted_when_it_scales_to_an_exact_integer() {
        // `1e3` and `1000` are the same number and a producer may write either.
        assert_eq!(number("1e3").as_u64(), Some(1000));
        assert_eq!(number("1E3").as_i64(), Some(1000));
        assert_eq!(number("-1e3").as_i64(), Some(-1000));
        assert_eq!(number("1000e-2").as_u64(), Some(10));
        assert_eq!(number("10e-1").as_u64(), Some(1));
        assert_eq!(number("1.500e1").as_u64(), Some(15));
        assert_eq!(number("0e1").as_u64(), Some(0));
        assert_eq!(number("0e+1").as_u64(), Some(0));
        assert_eq!(number("0e1000000000").as_u64(), Some(0));
    }

    #[test]
    fn a_literal_that_is_not_a_whole_number_is_not_an_integer() {
        for src in ["1.5", "-1.5", "1e-1", "12e-1", "0.001", "123.456e-789"] {
            assert_eq!(number(src).as_u64(), None, "{src}");
            assert_eq!(number(src).as_i64(), None, "{src}");
        }
    }

    #[test]
    fn a_fraction_that_is_a_whole_number_still_reads_as_an_integer() {
        // `1.0` is the integer 1, whatever its spelling, and
        // `is_integer_literal` is the accessor for a caller that cares which
        // spelling arrived.
        assert_eq!(number("1.0").as_u64(), Some(1));
        assert_eq!(number("0.0").as_u64(), Some(0));
        assert_eq!(number("-2.00").as_i64(), Some(-2));
        assert!(!number("1.0").is_integer_literal());
    }

    #[test]
    fn a_float_that_overflows_is_refused_and_one_that_underflows_is_zero() {
        // The asymmetry is the point: 1e999 is a finite number this type cannot
        // hold, and storing infinity for it would be a repair.
        assert_eq!(number("1e999").as_f64_finite(), None);
        assert_eq!(number("-1e999").as_f64_finite(), None);
        assert_eq!(number("1e309").as_f64_finite(), None);
        assert_eq!(number("123.456e-789").as_f64_finite(), Some(0.0));
        assert_eq!(number("1e-999").as_f64_finite(), Some(0.0));
        assert_eq!(number("1.5").as_f64_finite(), Some(1.5));
        assert_eq!(number("-0.25e1").as_f64_finite(), Some(-2.5));
        assert!(number("1e308").as_f64_finite().is_some_and(f64::is_finite));
    }

    #[test]
    fn the_raw_bytes_are_the_producers_own() {
        // What the oracle compares, so nothing may be normalised on the way in.
        assert_eq!(number("1E+02").raw(), b"1E+02");
        assert_eq!(number("-0.0").raw(), b"-0.0");
    }
}
