//! The conformance corpus against the answer pinned for each case.
//!
//! The bytes come from `tests/oracle/cases.py` because a corpus stored as text
//! loses exactly the cases that matter: invalid UTF-8 cannot round-trip through a
//! text file, a NUL is dropped by half the tools that would touch it, and a
//! byte-order mark is eaten by editors. What we are expected to do with each case
//! is in `tests/oracle/EXPECTATIONS.tsv`, included at compile time, so the pin
//! travels with the crate and only the bytes need python.
//!
//! # Why every case goes through the framer first
//!
//! A UTF-8 byte-order mark at absolute offset 0 is the framer's job, and
//! `reader.rs` deliberately does not skip one: away from offset 0 a mark is bytes
//! inside a line and therefore a syntax error, and a reader that skipped one
//! anywhere would accept `[\xEF\xBB\xBF1]`. So a test that called `validate` on
//! the raw bytes would refuse `i_encoding_utf8_bom_then_object` and
//! `i_encoding_utf8_bom_then_scalar`, which EXPECTATIONS.tsv says we accept, and
//! it would refuse them for a reason that is not a defect.
//!
//! The framer also answers the four UTF-16 and UTF-32 cases by sniffing the mark,
//! which is the path a stream actually takes. Routing through it means the verdict
//! this file compares is the verdict a caller gets, not the verdict of a component.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use trailryx_json::frame::{FrameReport, Framer, Line};
use trailryx_json::{Bound, JsonError, JsonResult, Kind, Limits, Syntax, validate};

/// The line number every case is reported against. Arbitrary: a case is one line
/// and the number only travels into the error position.
const LINE: u64 = 1;

/// The UTF-8 mark, in the length the framer strips at offset 0. `frame.rs` keeps
/// its own copy private, so this is written down rather than imported.
const BOM_UTF8: usize = 3;

/// One row of the corpus.
#[derive(Debug)]
struct Case {
    name: String,
    bytes: Vec<u8>,
}

/// What the crate did with a case, in the vocabulary EXPECTATIONS.tsv uses.
///
/// A string rather than the `Kind` itself, because the pin is a class and not a
/// variant: `n_encoding_utf16le_bom` is `Utf16Le` through the framer and
/// `InvalidUtf8` through `validate`, and the claim being pinned is that either
/// way it is an encoding refusal and never a syntax error.
fn verdict_of(result: JsonResult<()>) -> &'static str {
    match result {
        Ok(()) => "accept",
        Err(e) => match e.kind {
            Kind::Syntax(_) => "reject_syntax",
            Kind::Limit(_) => "reject_limit",
            Kind::Encoding(_) => "reject_encoding",
        },
    }
}

/// Every line the framer produced from `bytes`, or the refusal of the stream.
fn frame(bytes: &[u8], limits: Limits) -> Result<(Vec<Vec<u8>>, FrameReport), JsonError> {
    let mut framer = Framer::new(limits);
    let mut lines: Vec<Vec<u8>> = Vec::new();
    {
        let mut sink = |l: Line<'_>| -> JsonResult<()> {
            lines.push(l.bytes.to_vec());
            Ok(())
        };
        framer.push(bytes, &mut sink)?;
        framer.finish(&mut sink)?;
    }
    Ok((lines, framer.report()))
}

/// The bytes the grammar question is asked about, having let the framer answer
/// the encoding and the line splitting first.
enum Body {
    /// The stream itself was refused, by the byte-order-mark sniff.
    Refused(JsonError),
    /// Exactly one line reached the grammar, which is the ordinary case.
    One(Vec<u8>),
    /// The framer produced nothing, because the case is empty, blank, or only a
    /// mark. The bytes that would have been handed over are what `validate` is
    /// asked about, so the case still gets an answer instead of vanishing.
    Nothing(Vec<u8>),
    /// A raw LF split the case. Which is the whole point of refusing a raw LF
    /// inside a string, so the grammar question is asked about the case as one
    /// line and the split is asserted separately.
    Split(Vec<Vec<u8>>),
}

fn body_of(case: &Case, limits: Limits) -> Body {
    match frame(&case.bytes, limits) {
        Err(e) => Body::Refused(e),
        Ok((mut lines, report)) => match lines.len() {
            0 => {
                let from = if report.leading_bom { BOM_UTF8 } else { 0 };
                Body::Nothing(case.bytes[from..].to_vec())
            }
            1 => Body::One(lines.pop().expect("one line")),
            _ => Body::Split(lines),
        },
    }
}

#[test]
fn every_case_gets_the_pinned_answer() {
    let Some(cases) = corpus() else {
        return;
    };
    let expectations = expectations();
    let limits = Limits::default();

    let names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
    for name in expectations.keys() {
        assert!(
            names.contains(&name.as_str()),
            "EXPECTATIONS.tsv pins {name}, which is not a case cases.py produces"
        );
    }

    let mut unsure: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut split = 0usize;
    for case in &cases {
        let (want, reason) = expectations
            .get(&case.name)
            .unwrap_or_else(|| panic!("{} has no row in EXPECTATIONS.tsv", case.name));

        // A reason carrying UNSURE was an open question for the implementation
        // pass rather than a claim, so it is not asserted. It is printed instead:
        // a skipped check that says so is honest, one that quietly passes is what
        // this project is against.
        if reason.contains("UNSURE") {
            unsure.push(format!("{}: {reason}", case.name));
            continue;
        }

        let got = match body_of(case, limits) {
            Body::Refused(e) => verdict_of(Err(e)),
            Body::One(line) => verdict_of(validate(&line, limits, LINE)),
            Body::Nothing(body) => verdict_of(validate(&body, limits, LINE)),
            Body::Split(lines) => {
                // One logical record cannot survive being cut in two, and that is
                // the property a raw LF inside a string exists to protect. The
                // halves are not both required to fail: `{\n"a"\n:\n1\n}` cuts
                // into five lines of which `"a"` and `1` are each a JSON text on
                // their own. What must not happen is all of them parsing.
                assert!(
                    lines.len() > 1,
                    "{} was classified as split but produced {} lines",
                    case.name,
                    lines.len()
                );
                assert!(
                    lines.iter().any(|l| validate(l, limits, LINE).is_err()),
                    "{}: every one of the {} lines the framer cut it into parsed, \
                     so a record was forged out of one",
                    case.name,
                    lines.len()
                );
                split += 1;
                verdict_of(validate(&case.bytes, limits, LINE))
            }
        };

        assert_eq!(
            got, want,
            "{}: expected {want}, got {got}. {reason}",
            case.name
        );
        checked += 1;
    }

    for row in &unsure {
        println!("UNSURE, not asserted: {row}");
    }
    assert!(
        unsure.len() <= 1,
        "{} rows in EXPECTATIONS.tsv still say UNSURE; the implementation pass \
         resolved all but at most one:\n{}",
        unsure.len(),
        unsure.join("\n")
    );
    assert_eq!(
        checked + unsure.len(),
        cases.len(),
        "every case is accounted for"
    );
    println!(
        "{checked} of {} corpus cases checked, {} carried a raw LF and were also \
         framed, {} left UNSURE",
        cases.len(),
        split,
        unsure.len()
    );
}

#[test]
fn a_limit_is_never_reported_as_a_syntax_error() {
    // RFC 8259 section 9 puts both requirements in one paragraph: accept every
    // grammar-conformant text, and you may set limits on what you accept. A
    // parser that resolves that by reporting a bound as a syntax error tells an
    // operator to fix a producer that is not broken.
    let limits = Limits::default();

    // Read from the default, so the number moves in one place. The property is
    // that the bound is accepted and one past it is a `Limit`, whatever it is.
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert!(
        validate(deep(limits.max_depth).as_bytes(), limits, LINE).is_ok(),
        "depth {}",
        limits.max_depth
    );
    let err = validate(deep(limits.max_depth + 1).as_bytes(), limits, LINE)
        .expect_err("one past the depth bound");
    assert_eq!(err.kind, Kind::Limit(Bound::Depth));

    let number = |digits: usize| format!("[{}]", "1".repeat(digits));
    assert!(
        validate(number(1024).as_bytes(), limits, LINE).is_ok(),
        "1024 digits"
    );
    let err = validate(number(1025).as_bytes(), limits, LINE).expect_err("1025 digits");
    assert_eq!(err.kind, Kind::Limit(Bound::NumberDigits));

    let object = |members: usize| {
        let body: Vec<String> = (0..members).map(|i| format!("\"k{i}\":{i}")).collect();
        format!("{{{}}}", body.join(","))
    };
    assert!(
        validate(object(256).as_bytes(), limits, LINE).is_ok(),
        "256 members"
    );
    let err = validate(object(257).as_bytes(), limits, LINE).expect_err("257 members");
    assert_eq!(err.kind, Kind::Limit(Bound::ObjectMembers));

    // The line cap belongs to the framer, and the framer reports it as a count
    // rather than as an error: `Bound::LineTooLong` is declared in lib.rs and is
    // never constructed anywhere in the tree. So what is asserted here is the
    // behaviour that exists, which still carries the property this test is named
    // for: an oversize line never reaches `validate`, so it can never come back
    // as a syntax error. A caller that wants a `Kind::Limit` for it has to build
    // one from `oversize_lines`.
    let cap = limits.max_line_bytes;
    let at_the_cap = {
        let mut line = vec![b'"'; cap];
        line[1..cap - 1].fill(b'a');
        line
    };
    assert_eq!(at_the_cap.len(), cap);
    let (lines, report) = frame(&at_the_cap, limits).expect("no mark in these bytes");
    assert_eq!(lines.len(), 1, "a line of exactly the cap is handed over");
    assert_eq!(report.oversize_lines, 0);
    assert!(validate(&lines[0], limits, LINE).is_ok(), "a 16 MiB string");

    let mut one_over = at_the_cap;
    one_over.push(b'a');
    let (lines, report) = frame(&one_over, limits).expect("no mark in these bytes");
    assert!(
        lines.is_empty(),
        "one byte over the cap must not reach the grammar"
    );
    assert_eq!(report.oversize_lines, 1);
}

#[test]
fn no_grammatically_valid_document_is_refused_as_syntax() {
    // The claim in the crate doc: `Kind::Syntax` is never returned for a document
    // that conforms to the grammar. There is exactly one declared exception, and
    // it is the only one this asserts: a duplicate member name. RFC 8259 is
    // genuinely undecidable there (section 4 blesses reporting an error, section 9
    // says accept every conformant text) and CVE-2017-12635 is what the last-wins
    // answer looks like from the outside.
    let Some(cases) = corpus() else {
        return;
    };
    let limits = Limits::default();
    let mut duplicates = 0usize;
    let mut accepted = 0usize;
    for case in cases.iter().filter(|c| c.name.starts_with("y_")) {
        let result = match body_of(case, limits) {
            Body::Refused(e) => Err(e),
            Body::One(line) => validate(&line, limits, LINE),
            Body::Nothing(body) => validate(&body, limits, LINE),
            Body::Split(_) => validate(&case.bytes, limits, LINE),
        };
        match result {
            Ok(()) => accepted += 1,
            Err(e) if e.kind == Kind::Syntax(Syntax::DuplicateName) => {
                assert!(
                    case.name.starts_with("y_object_duplicate"),
                    "{} was refused as a duplicate name and is not a duplicate-name case",
                    case.name
                );
                duplicates += 1;
            }
            Err(e) => panic!(
                "{}: a document RFC 8259 requires a parser to accept was refused as {:?}",
                case.name, e.kind
            ),
        }
    }
    assert!(
        accepted > 0,
        "no `y_` case was found, so nothing was checked"
    );
    println!(
        "{accepted} grammar-conformant cases accepted, {duplicates} refused as the \
         declared duplicate-name divergence"
    );
}

/// The corpus, or `None` when python3 is absent.
///
/// Each integration test file is its own binary, so this loader is repeated in
/// each of them rather than shared through a module.
fn corpus() -> Option<Vec<Case>> {
    let tsv = oracle_output("python3", "cases.py", "")?;
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
        cases.push(Case {
            name: name.to_owned(),
            bytes: from_hex(name, hex),
        });
    }
    assert!(!cases.is_empty(), "cases.py produced no cases");
    Some(cases)
}

fn from_hex(name: &str, hex: &str) -> Vec<u8> {
    assert!(
        hex.len() % 2 == 0,
        "{name}: {} hex digits is not a whole number of bytes",
        hex.len()
    );
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(digits, 16).unwrap_or_else(|e| panic!("{name}: {digits}: {e}"))
        })
        .collect()
}

/// Our verdict for each case, and the reason next to it.
fn expectations() -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for line in include_str!("oracle/EXPECTATIONS.tsv").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut fields = line.splitn(3, '\t');
        let name = fields.next().expect("a name").to_owned();
        let verdict = fields
            .next()
            .unwrap_or_else(|| panic!("{name}: no verdict field"))
            .to_owned();
        let reason = fields.next().unwrap_or("").to_owned();
        assert!(
            matches!(
                verdict.as_str(),
                "accept" | "reject_syntax" | "reject_limit" | "reject_encoding"
            ),
            "{name}: {verdict} is not one of the four verdicts"
        );
        assert!(
            out.insert(name.clone(), (verdict, reason)).is_none(),
            "{name} is pinned twice in EXPECTATIONS.tsv"
        );
    }
    out
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
/// A script that runs and fails is a hard failure, not a skip. The scripts are
/// checked in next to the corpus, so a non-zero exit means one of them is broken
/// rather than absent, and calling that "skipped" is how a broken oracle survives.
fn oracle_output(tool: &str, file: &str, input: &str) -> Option<String> {
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
    // Written from another thread because the corpus is most of a megabyte, which
    // is more than a pipe buffer holds: writing it inline would block until the
    // child read it, while the child blocks writing output nobody is reading yet.
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let owned = input.to_owned();
    let writer = std::thread::spawn(move || stdin.write_all(owned.as_bytes()));
    let out = child.wait_with_output().expect("the script should finish");
    writer
        .join()
        .expect("the stdin writer should not panic")
        .expect("the script should read its whole input");
    assert!(
        out.status.success(),
        "{tool} {file} failed: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("the oracle scripts write UTF-8"))
}
