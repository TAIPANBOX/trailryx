//! Read a whole document and check nothing else.
//!
//! Exists for one reason: the conformance corpus. Every case in it is a question
//! of the form "is this JSON", and answering it through the pull reader means
//! walking a structure nobody cares about. This walks it generically and returns
//! only the verdict.
//!
//! It is also the entry point the oracle drives, so what it accepts is exactly
//! what the crate accepts, and no case can pass here and fail in the reader.

use crate::reader::{Event, Reader};
use crate::{JsonResult, Limits};

/// Whether these bytes are one JSON text, within the bounds.
///
/// `line` is carried into the error position only.
///
/// Accepts a bare top-level scalar, because RFC 8259 says a JSON text is any
/// value. Whether a *line* is allowed to be a bare scalar is a question about
/// the shape above, not about the grammar, and keeping the two apart is what lets
/// an operator tell a malformed feed from a mis-shaped one.
pub fn validate(bytes: &[u8], limits: Limits, line: u64) -> JsonResult<()> {
    let mut r = Reader::new(bytes, limits, line);
    let opened = r.value()?;
    if opened.is_container() {
        r.skip_rest(&opened)?;
    }
    r.finish()?;
    Ok(())
}

/// Read a document and hand back every scalar it held, in document order, as
/// canonical text.
///
/// The value oracle compares against this: object member names are emitted with
/// their values so a reordering is visible, numbers are emitted as the producer's
/// own digits so nothing is rounded before the comparison, and a string is
/// emitted unescaped so an escape-handling difference shows up as a different
/// character rather than a different spelling.
pub fn scalars(bytes: &[u8], limits: Limits, line: u64) -> JsonResult<Vec<String>> {
    let mut reader = Reader::new(bytes, limits, line);
    let mut out: Vec<String> = Vec::new();
    // One entry per open container, true for an object, so the walk knows which
    // of the reader's two drivers to call. It cannot grow past
    // `Limits::max_depth`, because the reader refuses the push that would.
    // Iterative for the same reason `skip_rest` is: a document nested as deep as
    // the bound allows must cost heap and not stack.
    let mut in_object: Vec<bool> = Vec::new();
    let mut pending = Some(reader.value()?);
    while let Some(event) = pending.take() {
        match event {
            Event::ArrayStart => in_object.push(false),
            Event::ObjectStart => in_object.push(true),
            Event::Null => out.push("null".to_owned()),
            Event::Bool(b) => out.push(if b { "true" } else { "false" }.to_owned()),
            Event::Number(n) => out.push(format!("num:{}", digits(n.raw()))),
            Event::Str(s) => out.push(format!("str:{s}")),
        }
        while let Some(&object) = in_object.last() {
            if object {
                if let Some(name) = reader.next_name()? {
                    out.push(format!("name:{name}"));
                    pending = Some(reader.value()?);
                    break;
                }
            } else if reader.next_element()? {
                pending = Some(reader.value()?);
                break;
            }
            in_object.pop();
        }
    }
    reader.finish()?;
    Ok(out)
}

/// A number's own digits as text.
///
/// [`crate::number::scan`] admits nothing outside `-0123456789.eE`, so byte per
/// character is exact and no value is rounded before the oracle has compared it.
fn digits(raw: &[u8]) -> String {
    raw.iter().map(|&b| char::from(b)).collect()
}

/// The deepest nesting in a document, for the depth tests.
pub fn depth_of(bytes: &[u8], limits: Limits, line: u64) -> JsonResult<u32> {
    let mut r = Reader::new(bytes, limits, line);
    let opened = r.value()?;
    if opened.is_container() {
        r.skip_rest(&opened)?;
    }
    let stats = r.finish()?;
    Ok(stats.max_depth_seen)
}

/// Whether an event is a scalar, for a caller walking generically.
pub fn is_scalar(e: &Event<'_>) -> bool {
    !e.is_container()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bound, Kind, Syntax};

    const LINE: u64 = 5;

    fn read(src: &[u8]) -> Vec<String> {
        scalars(src, Limits::default(), LINE).unwrap_or_else(|e| panic!("{src:?}: {e}"))
    }

    #[test]
    fn a_bare_top_level_scalar_is_a_json_text() {
        for src in [
            b"null".as_slice(),
            b"true",
            b"false",
            b"1",
            b"\"x\"",
            b" 1 ",
        ] {
            assert!(validate(src, Limits::default(), LINE).is_ok(), "{src:?}");
        }
    }

    #[test]
    fn every_scalar_arrives_in_document_order_with_its_member_name_in_front() {
        // This exact format is what the CPython oracle in tests/oracle/values.py
        // emits, so a reordering or a rounding shows up as a different line.
        let src = br#"{"a":1,"b":[true,null,"x"],"c":{"d":-0.5e2}}"#;
        assert_eq!(
            read(src),
            [
                "name:a",
                "num:1",
                "name:b",
                "true",
                "null",
                "str:x",
                "name:c",
                "name:d",
                "num:-0.5e2",
            ]
        );
    }

    #[test]
    fn a_number_is_emitted_as_the_digits_the_producer_wrote() {
        // CPython's own parser would hand back 1.0 for the third of these, which
        // is why the oracle hijacks its number hooks and why this keeps the
        // bytes.
        assert_eq!(
            read(b"[1E+02,-0,1.000000000000000005,18446744073709551616]"),
            [
                "num:1E+02",
                "num:-0",
                "num:1.000000000000000005",
                "num:18446744073709551616",
            ]
        );
    }

    #[test]
    fn a_string_is_emitted_unescaped_so_a_difference_is_a_character() {
        assert_eq!(read(br#""A""#), ["str:A"]);
        assert_eq!(read(br#""a\nb""#), ["str:a\nb"]);
        assert_eq!(read(br#""\udbff\udfff""#), ["str:\u{10ffff}"]);
        assert_eq!(read(br#"{"a":1}"#), ["name:a", "num:1"]);
        assert_eq!(read(br#""""#), ["str:"]);
    }

    #[test]
    fn container_boundaries_are_deliberately_absent() {
        // Two documents with the same scalars in the same order and different
        // nesting produce the same line, and the format was built knowing that:
        // what it catches is a reordering and a rounding.
        assert_eq!(read(b"[1,[2,[3]]]"), read(b"[[1,2],3]"));
        assert!(read(b"[]").is_empty());
        assert!(read(b"[[],{},[[]]]").is_empty());
    }

    #[test]
    fn the_walk_refuses_everything_the_reader_refuses() {
        let limits = Limits::default();
        for (src, kind) in [
            (
                b"{\"a\":1,\"a\":2}".as_slice(),
                Kind::Syntax(Syntax::DuplicateName),
            ),
            (b"[1,]", Kind::Syntax(Syntax::TrailingComma)),
            (b"", Kind::Syntax(Syntax::UnexpectedEof)),
            (b"1 2", Kind::Syntax(Syntax::TrailingContent)),
        ] {
            assert_eq!(
                scalars(src, limits, LINE).unwrap_err().kind,
                kind,
                "{src:?}"
            );
            assert_eq!(
                validate(src, limits, LINE).unwrap_err().kind,
                kind,
                "{src:?}"
            );
        }
    }

    #[test]
    fn the_depth_a_document_reached_counts_every_container() {
        let limits = Limits::default();
        for (src, depth) in [
            (b"1".as_slice(), 0),
            (b"[]", 1),
            (b"[[[1]]]", 3),
            (b"{\"a\":{\"b\":[1]}}", 3),
        ] {
            assert_eq!(depth_of(src, limits, LINE).unwrap(), depth, "{src:?}");
        }
        let bound = limits.max_depth;
        let deepest = "[".repeat(bound) + &"]".repeat(bound);
        assert_eq!(
            depth_of(deepest.as_bytes(), limits, LINE).unwrap(),
            bound as u32
        );
        let too_deep = "[".repeat(bound + 1) + &"]".repeat(bound + 1);
        assert_eq!(
            depth_of(too_deep.as_bytes(), limits, LINE)
                .unwrap_err()
                .kind,
            Kind::Limit(Bound::Depth)
        );
    }

    #[test]
    fn a_scalar_is_anything_that_did_not_open_a_container() {
        assert!(is_scalar(&Event::Null));
        assert!(is_scalar(&Event::Bool(true)));
        assert!(is_scalar(&Event::Str(std::borrow::Cow::Borrowed("x"))));
        assert!(!is_scalar(&Event::ArrayStart));
        assert!(!is_scalar(&Event::ObjectStart));
    }

    /// The lines of a source file that are code rather than prose, so a grep for
    /// a hazard does not match the comment that explains the hazard.
    fn code_lines(src: &str) -> impl Iterator<Item = &str> {
        src.lines().map(str::trim).filter(|l| !l.starts_with("//"))
    }

    #[test]
    fn nothing_in_this_crate_casts_a_float_to_an_integer_or_repairs_a_string() {
        // number.rs promises the first and lex.rs the second, and a promise
        // nobody checks is a comment. Verified locally: `f64::INFINITY` cast to
        // i64 is i64::MAX and NaN cast to i64 is 0, so a single cast would turn a
        // refusal into a plausible-looking value; `from_utf8_lossy` would change
        // the bytes this store hashes.
        //
        // The needles live in this file because a file that greps itself matches
        // its own needles. This one greps the other three.
        let needles = [
            "f64 as",
            "f32 as",
            "as i64",
            "parse::<i64>",
            "parse::<u64>",
            "from_utf8_lossy",
        ];
        for (name, src) in [
            ("lex.rs", include_str!("lex.rs")),
            ("number.rs", include_str!("number.rs")),
            ("reader.rs", include_str!("reader.rs")),
        ] {
            for line in code_lines(src) {
                for needle in needles {
                    assert!(!line.contains(needle), "{name}: `{needle}` in `{line}`");
                }
            }
        }
    }
}
