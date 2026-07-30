//! Input written to break the reader rather than to be read.
//!
//! # Why every test here runs on its own thread
//!
//! 128 KiB, which is `trailryx_ingest::Config::thread_stack_bytes`, the stack a
//! request is actually served on. The test harness hands a test thread eight
//! megabytes, so a hundred thousand nested brackets would walk fine on the
//! harness's stack whether the walk were iterative or not, and the claim in
//! `reader.rs` that depth costs heap and not stack would go unproven. The number
//! is written down rather than imported because this crate depends on nothing,
//! including on the crate that serves the requests.
//!
//! # What the timing test measures
//!
//! Ratios, never absolute times. An absolute budget is a machine's speed dressed
//! up as a property, and it fails on a loaded laptop and passes on a fast one with
//! quadratic code in it. Ten times the input at ten times the cost is linear and at
//! a hundred times the cost is quadratic, and no amount of noise turns one into the
//! other.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use trailryx_json::frame::{Framer, Line};
use trailryx_json::validate::scalars;
use trailryx_json::{
    Bound, Encoding, Event, JsonResult, Kind, Limits, Reader, Syntax, lex, number, validate,
};

const LINE: u64 = 1;

/// The stack an ingest request is served on, and therefore the stack every claim
/// about iteration in this crate has to hold on.
const REQUEST_STACK_BYTES: usize = 128 * 1024;

/// What a literal's three accessors must answer: `as_u64`, `as_i64`, and a finite
/// `f64`. One tuple so the expected and the measured answers are compared in one
/// assertion and a test cannot check two of the three and forget the last.
type Conversions = (Option<u64>, Option<i64>, Option<f64>);

/// Run `work` on a request-sized stack.
fn on_a_request_sized_stack<T, F>(work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(REQUEST_STACK_BYTES)
        .spawn(work)
        .expect("a thread")
        .join()
        .expect("the work must fit in a 128 KiB stack")
}

#[test]
fn a_hundred_thousand_open_brackets_does_not_take_the_process_down() {
    let err = on_a_request_sized_stack(|| {
        let bytes = vec![b'['; 100_000];
        validate(&bytes, Limits::default(), LINE).expect_err("depth 100000 is past the bound")
    });
    // A bound and not a syntax error, even though the document is also truncated:
    // depth is reached one bracket past the bound, tens of thousands of bytes
    // before the missing close. A recursive parser never gets far enough to say
    // so, because it is already off the end of its stack.
    assert_eq!(err.kind, Kind::Limit(Bound::Depth));
    assert_eq!(
        err.byte_in_line,
        Limits::default().max_depth as u64,
        "the bracket that was refused"
    );
}

#[test]
fn depth_built_from_alternating_containers_is_counted_too() {
    let err = on_a_request_sized_stack(|| {
        let bytes = b"[{\"\":".repeat(50_000);
        validate(&bytes, Limits::default(), LINE).expect_err("depth 100000 is past the bound")
    });
    // A depth counter that only counted brackets, or only counted braces, would
    // admit twice the nesting from these bytes. Each repeat opens two containers,
    // so the bound is passed halfway through the repeat that reaches it: the `[`
    // takes the stack to the bound and the `{` beside it is refused. Derived from
    // the bound rather than written down, because the bound is a backstop that may
    // move and this test is about the counting, not the number.
    let bound = Limits::default().max_depth;
    let repeat = b"[{\"\":".len();
    // Each repeat adds two, so an even bound is reached exactly by the brace of
    // repeat number bound/2 - 1, and the byte refused is the bracket that opens
    // the next one. Derived rather than written down, because the bound is a
    // backstop that may move and this test is about the counting, not the number.
    assert!(
        bound.is_multiple_of(2),
        "the arithmetic below assumes an even bound"
    );
    let refused_at = (bound / 2) * repeat;
    assert_eq!(err.kind, Kind::Limit(Bound::Depth));
    assert_eq!(
        err.byte_in_line, refused_at as u64,
        "the bracket that opened one container past the bound"
    );
}

#[test]
fn a_huge_exponent_is_refused_in_microseconds() {
    // The exponent-expansion class, which has taken parsers down by asking them to
    // materialise ten to the billionth before noticing it does not fit. Every one
    // of these is grammar-conformant and inside `max_number_bytes`, so the document
    // is read: what is refused is the *conversion*, and it is refused by clamping
    // the exponent and by checked multiplication that overflows within twenty
    // steps, not by expanding anything.
    //
    // The budget is three orders of magnitude above what these cost, because the
    // defect it catches is not slowness. An implementation that expanded the
    // exponent would not finish at all.
    const BUDGET: Duration = Duration::from_secs(1);
    on_a_request_sized_stack(|| {
        let limits = Limits::default();
        let cases: [(&str, Conversions); 4] = [
            ("[123e-10000000]", (None, None, Some(0.0))),
            ("[123123e100000]", (None, None, None)),
            ("[-1e+9999]", (None, None, None)),
            ("[9.223372E+1010671858]", (None, None, None)),
        ];
        for (document, want) in cases {
            let started = Instant::now();
            let read = validate(document.as_bytes(), limits, LINE);
            let literal = &document[1..document.len() - 1];
            let (value, used) = number::scan(literal.as_bytes(), 0, LINE, limits.max_number_bytes)
                .unwrap_or_else(|e| panic!("{literal} is a JSON number: {e}"));
            let got: Conversions = (value.as_u64(), value.as_i64(), value.as_f64_finite());
            let elapsed = started.elapsed();

            assert!(read.is_ok(), "{document} is grammar-conformant: {read:?}");
            assert_eq!(used, literal.len(), "{literal} was not read whole");
            assert_eq!(got, want, "{literal}");
            assert!(
                elapsed <= BUDGET,
                "{literal} took {elapsed:?}, over the {BUDGET:?} budget, which means \
                 the exponent was expanded somewhere"
            );
        }
    });
}

#[test]
fn a_number_out_of_range_never_becomes_a_plausible_value() {
    on_a_request_sized_stack(|| {
        // Each of these has a plausible-looking wrong answer, and every one of them
        // was verified: `9223372036854775808u64 as i64` is `i64::MIN`, wrapping
        // accumulation of `18446744073709551616` is 0, `1e19 as i64` and
        // `f64::INFINITY as i64` are both `i64::MAX`, and `NaN as i64` is 0. A
        // refusal wearing a plausible value's clothes is worse than a refusal,
        // because nothing downstream can tell.
        //
        // literal, as_u64, as_i64, a finite f64
        let cases: [(&str, Option<u64>, Option<i64>, bool); 10] = [
            (
                "9223372036854775808",
                Some(9_223_372_036_854_775_808),
                None,
                true,
            ),
            ("-9223372036854775809", None, None, true),
            ("18446744073709551616", None, None, true),
            ("1e19", Some(10_000_000_000_000_000_000), None, true),
            ("1e20", None, None, true),
            ("1e309", None, None, false),
            ("1e999", None, None, false),
            ("-1e999", None, None, false),
            ("1e1000000", None, None, false),
            ("0.5", None, None, true),
        ];
        for (literal, want_u64, want_i64, finite) in cases {
            let (value, _) = number::scan(literal.as_bytes(), 0, LINE, 1024)
                .unwrap_or_else(|e| panic!("{literal} is a JSON number: {e}"));
            let (u, i, f) = (value.as_u64(), value.as_i64(), value.as_f64_finite());
            assert_eq!(u, want_u64, "{literal} as_u64");
            assert_eq!(i, want_i64, "{literal} as_i64");
            assert_eq!(f.is_some(), finite, "{literal} as_f64_finite");

            // None of these literals is zero, `i64::MIN` or `i64::MAX`, so any of
            // those coming back is a stand-in and not an answer.
            assert_ne!(u, Some(0), "{literal} wrapped to zero");
            assert_ne!(i, Some(0), "{literal} wrapped to zero");
            assert_ne!(i, Some(i64::MIN), "{literal} was cast, not converted");
            assert_ne!(i, Some(i64::MAX), "{literal} saturated");
            assert!(
                f.is_none_or(f64::is_finite),
                "{literal} produced a non-finite f64 from a finite accessor"
            );
        }
    });
}

#[test]
fn a_lone_surrogate_is_refused_rather_than_truncated() {
    on_a_request_sized_stack(|| {
        let limits = Limits::default();
        // The published escalation. Truncating at the unpaired surrogate hands the
        // caller `superadmin`, and substituting U+FFFD changes the bytes this store
        // hashes and publishes a Merkle root over. Rust cannot hold a lone
        // surrogate in a `String`, so there is no lossless lenient answer and the
        // only honest one is a refusal.
        let escalation: &[u8] = br#"{"roles":["superadmin\ud888"]}"#;

        // Driven by hand rather than through `validate`, because what has to be
        // proved is that no `Event::Str` carrying the truncated name is ever
        // produced: a refusal that happens after the value was handed over is not a
        // refusal.
        let mut reader = Reader::new(escalation, limits, LINE);
        assert_eq!(reader.value().expect("an object"), Event::ObjectStart);
        assert_eq!(
            reader.next_name().expect("a name").as_deref(),
            Some("roles")
        );
        assert_eq!(reader.value().expect("an array"), Event::ArrayStart);
        assert!(reader.next_element().expect("an element"));
        let err = reader
            .value()
            .expect_err("the unpaired surrogate must be refused here, not after");
        assert_eq!(err.kind, Kind::Syntax(Syntax::LoneSurrogate));

        // And nothing comes back through either whole-document entry point, so
        // there is no path by which `superadmin` reaches a caller.
        assert!(scalars(escalation, limits, LINE).is_err());

        for document in [
            escalation,
            br#"["\ud800"]"#,
            br#"["\udc00"]"#,
            br#"["\ud888\u1234"]"#,
            br#"["\ud834\ud834"]"#,
            br#"["\udc00\ud800"]"#,
            br#"{"\ud800":1}"#,
            br#"["\udbff"]"#,
        ] {
            let err = validate(document, limits, LINE).expect_err("an unpaired surrogate");
            assert_eq!(
                err.kind,
                Kind::Syntax(Syntax::LoneSurrogate),
                "{:?}",
                String::from_utf8_lossy(document)
            );
        }
    });
}

#[test]
fn overlong_and_out_of_range_utf8_is_refused_with_an_offset() {
    on_a_request_sized_stack(|| {
        // Each of these is a byte sequence a lenient decoder has historically
        // accepted, and each is a different way to smuggle a character past a
        // filter that looked at the bytes. The overlong solidus is the classic:
        // `C0 AF` is a `/` to a decoder that does not check minimality, so a path
        // separator survives a check for `/`.
        //
        // The offset matters as much as the refusal. An encoding error with no
        // position is a file an operator cannot fix.
        let cases: [(&[u8], u64); 10] = [
            (b"[\"\xc0\xaf\"]", 2),
            (b"[\"\xc0\x80\"]", 2),
            (b"[\"\xe0\x80\xaf\"]", 2),
            (b"[\"\xed\xa0\x80\"]", 2),
            (b"[\"\xed\xa0\xbd\xed\xb8\x80\"]", 2),
            (b"[\"\xf4\xbf\xbf\xbf\"]", 2),
            (b"[\"\xf8\x88\x80\x80\x80\"]", 2),
            (b"[\"\x80\"]", 2),
            (b"[\"\xe2\x82\"]", 2),
            (b"[1] \xff", 4),
        ];
        for (bytes, at) in cases {
            let err = validate(bytes, Limits::default(), LINE).expect_err("not UTF-8");
            assert_eq!(
                err.kind,
                Kind::Encoding(Encoding::InvalidUtf8),
                "{bytes:?} must be an encoding refusal and not a syntax one"
            );
            assert_eq!(err.byte_in_line, at, "{bytes:?}");
            assert_eq!(err.line, LINE, "{bytes:?}");
        }

        // A surrogate encoded as UTF-8 is refused as bytes, before any surrogate
        // rule applies, which is why the class above is `InvalidUtf8` and not
        // `LoneSurrogate`: the whole line is checked once, first.
        let err = validate(b"[\"\xed\xa0\x80\"]", Limits::default(), LINE).unwrap_err();
        assert_ne!(err.kind, Kind::Syntax(Syntax::LoneSurrogate));
    });
}

#[test]
fn an_unescaped_newline_cannot_forge_a_record() {
    on_a_request_sized_stack(|| {
        let limits = Limits::default();
        // Twenty of the sixty-seven parsers in the reference survey accept a raw LF
        // inside a string. Each of them lets these bytes become two records: the
        // first half is discarded as unterminated by whatever reads it next, and the
        // second half is a complete, well-formed record the attacker wrote.
        let forged: &[u8] = b"{\"actor\":\"alice\n{\"actor\":\"root\"}\"}";

        let err = validate(forged, limits, LINE).expect_err("a raw LF inside a string");
        assert_eq!(err.kind, Kind::Syntax(Syntax::ControlInString));
        assert_eq!(err.byte_in_line, 15, "the newline itself");

        // And by the other route: the framer does cut these bytes in two, because
        // LF is the separator and it cannot know what a later parse will make of the
        // halves. Neither half parses, so the forgery produces no record either way.
        let mut framer = Framer::new(limits);
        let mut lines: Vec<Vec<u8>> = Vec::new();
        {
            let mut sink = |l: Line<'_>| -> JsonResult<()> {
                lines.push(l.bytes.to_vec());
                Ok(())
            };
            framer.push(forged, &mut sink).expect("no mark");
            framer.finish(&mut sink).expect("no mark");
        }
        assert_eq!(lines.len(), 2, "the LF split the record");
        for (i, line) in lines.iter().enumerate() {
            assert!(
                validate(line, limits, LINE).is_err(),
                "half {i} of a split record parsed on its own: {:?}",
                String::from_utf8_lossy(line)
            );
        }

        // The same check protects a member name, and an escaped LF is a character
        // in the string rather than a separator, which is the whole reason the raw
        // one has to go.
        assert_eq!(
            validate(b"{\"a\nb\":1}", limits, LINE).unwrap_err().kind,
            Kind::Syntax(Syntax::ControlInString)
        );
        assert!(validate(br#"["a\nb"]"#, limits, LINE).is_ok());
    });
}

#[test]
fn a_del_character_is_not_a_control_character() {
    on_a_request_sized_stack(|| {
        let limits = Limits::default();
        // A JSON control character is `b < 0x20`, full stop. `char::is_control` says
        // U+007F DEL and U+0080..U+009F are control characters, and using it here
        // would refuse documents that every other parser accepts, which is a
        // compatibility break dressed up as strictness.
        for document in [
            "[\"\u{7f}\"]",
            "[\"\u{80}\u{85}\u{9f}\"]",
            "{\"\u{7f}\":1}",
            "[\"\u{2028}\u{2029}\"]",
        ] {
            assert!(
                validate(document.as_bytes(), limits, LINE).is_ok(),
                "{document:?} holds no JSON control character"
            );
        }
        // One byte lower is the boundary, and it is refused.
        assert_eq!(
            validate(b"[\"\x1f\"]", limits, LINE).unwrap_err().kind,
            Kind::Syntax(Syntax::ControlInString)
        );
        assert!(validate(b"[\"\x20\"]", limits, LINE).is_ok(), "space");
    });
}

#[test]
fn duplicate_keys_are_fatal_and_compared_unescaped() {
    on_a_request_sized_stack(|| {
        let limits = Limits::default();
        // CVE-2017-12635 is last-wins seen from the outside: which parser looked at
        // the document decided who was an administrator. A winner picked by an
        // implementation detail must not be baked into evidence, so the document is
        // refused instead of resolved.
        //
        // The comparison happens after unescaping, which is what stops the spelling
        // of a name smuggling a second copy of it past the check.
        for document in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":1,"a":1}"#,
            br#"{"":1,"":2}"#,
            br#"{"a":1,"\u0061":2}"#,
            br#"{"a\\b":1,"a\u005cb":2}"#,
            br#"{"a\/b":1,"a/b":2}"#,
            br#"{"a":{"b":1},"a":2}"#,
            br#"[{"a":1,"a":2}]"#,
            br#"{"o":{"b":1,"b":2}}"#,
        ] {
            assert_eq!(
                validate(document, limits, LINE).unwrap_err().kind,
                Kind::Syntax(Syntax::DuplicateName),
                "{:?}",
                String::from_utf8_lossy(document)
            );
        }

        // Byte for byte after unescaping, and never normalised. An NFC and an NFD
        // spelling of the same word are two different names: folding them would be
        // this crate making a linguistic decision about evidence, and the check is
        // per object, so the same name in two objects is two names.
        for document in [
            "{\"\u{e9}\":1,\"e\u{301}\":2}",
            "{\"\u{fb01}\":1,\"fi\":2}",
            "{\"a\":1,\"A\":2}",
            "{\"a\":{\"b\":1},\"c\":{\"b\":2}}",
            "[{\"b\":1},{\"b\":2}]",
        ] {
            assert!(
                validate(document.as_bytes(), limits, LINE).is_ok(),
                "{document:?} holds no duplicate name"
            );
        }
    });
}

#[test]
fn unescaping_never_grows_a_string() {
    // The claim `Limits` rests on: there is deliberately no separate cap on a
    // string, because `\uXXXX` is six bytes in and at most three out, a surrogate
    // pair is twelve in and four out, `\n` is two in and one out, and a raw
    // character is unchanged. If any escape grew, `max_line_bytes` would stop
    // bounding the memory a line costs and a 16 MiB line could unescape into
    // something larger.
    //
    // Asserted over the corpus rather than over a chosen list, and at every quote
    // in every case rather than at the ones that start a string: scanning from a
    // quote in the middle of a literal is a different input and the property has to
    // hold there too.
    let Some(cases) = corpus() else {
        return;
    };
    let (scanned, longest) = on_a_request_sized_stack(move || {
        let mut scratch = String::new();
        let mut scanned = 0usize;
        let mut longest = 0usize;
        for (name, bytes) in &cases {
            for (at, &b) in bytes.iter().enumerate() {
                if b != b'"' {
                    continue;
                }
                let Ok((value, end)) = lex::scan_string(bytes, at, LINE, &mut scratch) else {
                    continue;
                };
                // The two quotes are two of the bytes the literal spent, so a value
                // that used all the rest of them has not grown.
                assert!(
                    value.len() + 2 <= end - at,
                    "{name}: the literal at {at} is {} bytes and unescaped to {}",
                    end - at,
                    value.len()
                );
                scanned = scanned.saturating_add(1);
                longest = longest.max(value.len());
            }
        }
        (scanned, longest)
    });
    assert!(scanned > 0, "no string literal was found in the corpus");
    println!("{scanned} string literals unescaped, none grew, longest was {longest} bytes");
}

#[test]
fn quadratic_behaviour_is_absent() {
    on_a_request_sized_stack(|| {
        let limits = Limits::default();

        // Escapes. Ten times as many must cost about ten times as much: a scanner
        // that copied the buffer per escape, or rescanned the string to find the
        // next one, is a hundred times as much at this ratio.
        for (what, escape) in [
            ("\\n", "\\n"),
            ("\\u0041", "\\u0041"),
            ("a surrogate pair", "\\ud83d\\ude00"),
        ] {
            let small = escaped_line(escape, 100_000);
            let big = escaped_line(escape, 1_000_000);
            assert!(big.len() < limits.max_line_bytes, "{what} fits in one line");
            let one = best_of_three(|| {
                validate(&small, limits, LINE).expect("a hundred thousand escapes");
            });
            let ten = best_of_three(|| {
                validate(&big, limits, LINE).expect("a million escapes");
            });
            scales_no_worse_than_linearly(&format!("{what} escapes"), one, ten, 10);
        }

        // The same member name over and over, in a hundred thousand sibling
        // objects. Duplicate detection holds one bounded vector per open object, so
        // the cost of the check is per object and not per document: a document-wide
        // set of names would make this quadratic and would also make `{"b":1}` twice
        // a duplicate, which it is not.
        let thousand = repeated_key(1_000);
        let ten_thousand = repeated_key(10_000);
        let hundred_thousand = repeated_key(100_000);
        let a = best_of_three(|| {
            validate(&thousand, limits, LINE).expect("a thousand objects");
        });
        let b = best_of_three(|| {
            validate(&ten_thousand, limits, LINE).expect("ten thousand objects");
        });
        let c = best_of_three(|| {
            validate(&hundred_thousand, limits, LINE).expect("a hundred thousand objects");
        });
        scales_no_worse_than_linearly("the same key ten thousand times", a, b, 10);
        scales_no_worse_than_linearly("the same key a hundred thousand times", b, c, 10);
        scales_no_worse_than_linearly("the same key, a thousand to a hundred thousand", a, c, 100);

        // A hundred thousand consecutive bad lines. This is the one that proves
        // error positions are carried as the reader advances rather than recovered
        // afterwards by rescanning: recovering them would make a file of refusals
        // cost the file once per refusal, and a log of nothing but broken lines is
        // exactly what a misconfigured producer sends.
        let ten_k = bad_lines(10_000);
        let hundred_k = bad_lines(100_000);
        let small = best_of_three(|| assert_eq!(refuse_all(&ten_k, limits), 10_000));
        let large = best_of_three(|| assert_eq!(refuse_all(&hundred_k, limits), 100_000));
        scales_no_worse_than_linearly("a hundred thousand bad lines", small, large, 10);
    });
}

/// One line holding `count` copies of `escape` inside a single string.
fn escaped_line(escape: &str, count: usize) -> Vec<u8> {
    let mut line = Vec::with_capacity(escape.len() * count + 4);
    line.extend_from_slice(b"[\"");
    for _ in 0..count {
        line.extend_from_slice(escape.as_bytes());
    }
    line.extend_from_slice(b"\"]");
    line
}

/// One line holding `count` sibling objects that all use the same member name.
fn repeated_key(count: usize) -> Vec<u8> {
    let mut line = Vec::with_capacity(count * 9 + 2);
    line.push(b'[');
    for i in 0..count {
        if i > 0 {
            line.push(b',');
        }
        line.extend_from_slice(br#"{"k":0}"#);
    }
    line.push(b']');
    line
}

/// `count` lines, every one of them malformed in the same place.
fn bad_lines(count: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(count * 9);
    for _ in 0..count {
        buf.extend_from_slice(b"{\"a\":1,}\n");
    }
    buf
}

/// Frame `bytes` and refuse every line, returning how many were refused.
///
/// The sink returns `Ok` so the framer keeps going, which is what a caller that
/// records a refusal and reads on does.
fn refuse_all(bytes: &[u8], limits: Limits) -> u64 {
    let mut refused = 0u64;
    let mut framer = Framer::new(limits);
    {
        let mut sink = |l: Line<'_>| -> JsonResult<()> {
            if validate(l.bytes, limits, l.number).is_err() {
                refused = refused.saturating_add(1);
            }
            Ok(())
        };
        framer.push(bytes, &mut sink).expect("no mark");
        framer.finish(&mut sink).expect("no mark");
    }
    refused
}

/// The cheapest of three runs.
///
/// A single reading on a machine that is doing something else is arbitrarily
/// large, and the smallest of a few is the closest to what the code costs. Nothing
/// here is a benchmark: the only question is whether the cost per byte grows with
/// the input.
fn best_of_three(mut work: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        work();
        best = best.min(started.elapsed());
    }
    best
}

/// Assert the bigger input cost no more than `growth` times the smaller one.
///
/// A factor of three of slack over the linear expectation, plus a five millisecond
/// floor for timer noise when both readings are tiny. Generous on purpose, and said
/// so here rather than discovered later by whoever the flake wakes up: linear code
/// at ten times the input is ten times the time and quadratic code is a hundred
/// times, so three cannot hide the defect this exists to catch and does keep the
/// test from failing on a busy machine.
fn scales_no_worse_than_linearly(what: &str, small: Duration, big: Duration, growth: u32) {
    const SLACK: u32 = 3;
    let allowed = small * growth * SLACK + Duration::from_millis(5);
    // Printed, because a ratio test that only ever says "ok" tells nobody whether
    // the two readings were big enough to mean anything.
    println!("{what}: {small:?} then {big:?} at {growth} times the input");
    assert!(
        big <= allowed,
        "{what}: {small:?} at one size and {big:?} at {growth} times it. \
         A linear cost with a factor of {SLACK} of slack allows {allowed:?}, \
         so something here is not linear."
    );
}

/// The corpus as `(name, bytes)`, or `None` when python3 is absent.
///
/// Each integration test file is its own binary, so this loader is repeated in
/// each of them rather than shared through a module.
fn corpus() -> Option<Vec<(String, Vec<u8>)>> {
    let tsv = oracle_output("python3", "cases.py")?;
    let mut cases = Vec::new();
    for line in tsv.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let name = fields.next().expect("a name");
        let hex = fields
            .next()
            .unwrap_or_else(|| panic!("{name}: no hex field"));
        assert!(
            hex.len() % 2 == 0,
            "{name}: {} hex digits is not a whole number of bytes",
            hex.len()
        );
        let bytes = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let digits = std::str::from_utf8(pair).expect("hex is ASCII");
                u8::from_str_radix(digits, 16).unwrap_or_else(|e| panic!("{name}: {digits}: {e}"))
            })
            .collect();
        cases.push((name.to_owned(), bytes));
    }
    assert!(!cases.is_empty(), "cases.py produced no cases");
    Some(cases)
}

fn script(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("oracle")
        .join(file)
}

/// Run one oracle script and hand back its standard output, or `None` when the
/// tool that runs it is not installed.
///
/// A script that runs and fails is a hard failure, not a skip: it is checked in
/// next to the corpus, so a non-zero exit means it is broken rather than absent.
fn oracle_output(tool: &str, file: &str) -> Option<String> {
    let spawned = Command::new(tool)
        .arg(script(file))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            println!("skipped: {tool} is not on this machine, so {file} was not run ({e})");
            return None;
        }
    };
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let writer = std::thread::spawn(move || stdin.write_all(b""));
    let out = child.wait_with_output().expect("the script should finish");
    writer
        .join()
        .expect("the stdin writer should not panic")
        .expect("the script reads no input");
    assert!(
        out.status.success(),
        "{tool} {file} failed: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("the oracle scripts write UTF-8"))
}
