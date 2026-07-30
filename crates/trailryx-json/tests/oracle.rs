//! Two parsers with no shared ancestry, asked the same questions.
//!
//! CPython's `json` and V8's `JSON.parse` were chosen because they share no code
//! and no lineage: two parsers derived from the same reference implementation
//! agreeing proves only that the reference is self-consistent. What an oracle
//! proves is narrow and worth stating: that our answer for a given input differs
//! from a mainstream parser's answer, or does not. It does not prove we are right.
//! Where we differ from both at once it is one of four declared positions, and the
//! argument for each is in `lib.rs`, not here.
//!
//! # Where the pins live
//!
//! Nowhere in this file is a case name written down. Our verdict per case comes
//! from `EXPECTATIONS.tsv`, the two rows the oracles split on come from
//! `DISAGREEMENTS.tsv`, and the rest of each oracle's behaviour is derived from
//! the corpus's own `y`/`n`/`i` column by the rule in [`oracle_accepts`]. A list
//! of names in here would be a third place to update and the one that got
//! forgotten would be the one that mattered.
//!
//! Both tables are dated measurements against specific builds (CPython 3.14.6 and
//! node v22.23.1), so an upgrade can move a row. This file is the thing that
//! notices.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use trailryx_json::frame::{FrameReport, Framer, Line};
use trailryx_json::validate::scalars;
use trailryx_json::{JsonError, JsonResult, Limits, number, validate};

const LINE: u64 = 1;

/// The UTF-8 mark, in the length the framer strips at offset 0. `frame.rs` keeps
/// its own copy private, so this is written down rather than imported.
const BOM_UTF8: usize = 3;

/// One row of the corpus: the bytes, and RFC 8259's own verdict for them.
#[derive(Debug)]
struct Case {
    name: String,
    bytes: Vec<u8>,
    /// `y` a conforming parser must accept, `n` must reject, `i` the grammar is
    /// satisfied and the answer is the implementation's. Not our verdict.
    rfc: char,
}

impl Case {
    /// Whether the bytes open with a UTF-8 byte-order mark.
    ///
    /// Read from the bytes rather than from the name, because it is a property of
    /// the case and not of what somebody called it.
    fn leading_bom(&self) -> bool {
        self.bytes.starts_with(&[0xEF, 0xBB, 0xBF])
    }
}

/// Whether a mainstream parser accepts this case, derived rather than listed.
///
/// The rule, and the three parts of it are the whole content of this file:
///
/// 1. A row in `DISAGREEMENTS.tsv` is a measurement of one oracle departing from
///    the grammar, and the table records which way each went. Those rows use the
///    recorded answer.
/// 2. Both oracles refuse a leading byte-order mark, and we deliberately skip one.
///    That is the fourth declared divergence and the only one that makes us *more*
///    permissive than both.
/// 3. Otherwise a conforming parser accepts exactly the texts the grammar admits,
///    which is the `y` and `i` rows. `i` means the grammar is satisfied and only
///    the bounds are in question, and neither oracle has a bound this corpus
///    reaches except the one already covered by rule 1.
///
/// A sixth CPython-versus-node divergence, or an oracle that starts refusing a
/// bound it used to admit, breaks rule 3 and fails the build. That is the point.
fn oracle_accepts(case: &Case, oracle: Oracle, split: &BTreeMap<String, (bool, bool)>) -> bool {
    if let Some(&(cpython, node)) = split.get(&case.name) {
        return match oracle {
            Oracle::CPython => cpython,
            Oracle::Node => node,
        };
    }
    if case.leading_bom() {
        return false;
    }
    case.rfc != 'n'
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Oracle {
    CPython,
    Node,
}

impl Oracle {
    fn tool(self) -> &'static str {
        match self {
            Self::CPython => "python3",
            Self::Node => "node",
        }
    }

    fn script(self) -> &'static str {
        match self {
            Self::CPython => "classify.py",
            Self::Node => "classify.js",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::CPython => "CPython",
            Self::Node => "node",
        }
    }
}

#[test]
fn we_agree_with_cpython_and_node_except_where_we_chose_not_to() {
    let Some(python) = tool("python3") else {
        return;
    };
    let Some(node) = tool("node") else {
        return;
    };
    let Some((cases, tsv)) = corpus(&python) else {
        return;
    };
    let expectations = expectations();
    let split = disagreements();
    let limits = Limits::default();

    let classified = |oracle: Oracle| -> BTreeMap<String, bool> {
        let tool = match oracle {
            Oracle::CPython => &python,
            Oracle::Node => &node,
        };
        let out = oracle_output(tool, oracle.script(), &tsv)
            .unwrap_or_else(|| panic!("{} was found and then would not run", oracle.tool()));
        let mut map = BTreeMap::new();
        for line in out.lines() {
            if line.is_empty() {
                continue;
            }
            let (name, verdict) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("{}: {line:?} is not two fields", oracle.script()));
            assert!(
                matches!(verdict, "accept" | "reject"),
                "{}: {verdict} is not accept or reject",
                oracle.script()
            );
            map.insert(name.to_owned(), verdict == "accept");
        }
        assert_eq!(
            map.len(),
            cases.len(),
            "{} answered {} of {} cases",
            oracle.script(),
            map.len(),
            cases.len()
        );
        map
    };

    let measured = [
        (Oracle::CPython, classified(Oracle::CPython)),
        (Oracle::Node, classified(Oracle::Node)),
    ];

    // The disagreement map first, on its own, because it is the measurement the
    // two tables were built from and a sixth row in it means one of the oracles
    // moved under us.
    let mut disagreed = BTreeSet::new();
    for case in &cases {
        if measured[0].1[&case.name] != measured[1].1[&case.name] {
            disagreed.insert(case.name.clone());
        }
    }
    let pinned: BTreeSet<String> = split.keys().cloned().collect();
    assert_eq!(
        disagreed, pinned,
        "CPython and node no longer disagree on exactly the pinned set. \
         Measured: {disagreed:?}. Pinned in DISAGREEMENTS.tsv: {pinned:?}"
    );

    for (oracle, answers) in &measured {
        let mut want: BTreeSet<String> = BTreeSet::new();
        let mut got: BTreeSet<String> = BTreeSet::new();
        for case in &cases {
            let ours = expectations
                .get(&case.name)
                .unwrap_or_else(|| panic!("{} has no row in EXPECTATIONS.tsv", case.name))
                == "accept";
            if ours != oracle_accepts(case, *oracle, &split) {
                want.insert(case.name.clone());
            }
            // Our live answer, not the table's: the table is pinned against the
            // crate in tests/corpus.rs, and taking it from the crate here means a
            // divergence cannot hide behind a stale row.
            if verdict(case, limits).is_ok() != answers[&case.name] {
                got.insert(case.name.clone());
            }
        }
        assert_eq!(
            got,
            want,
            "the set of cases where we differ from {} has changed.\n  only in the \
             measured set: {:?}\n  only in the pinned set: {:?}",
            oracle.name(),
            got.difference(&want).collect::<Vec<_>>(),
            want.difference(&got).collect::<Vec<_>>()
        );
        println!(
            "{} of {} cases differ from {}, exactly the pinned set",
            got.len(),
            cases.len(),
            oracle.name()
        );
    }
}

#[test]
fn we_agree_with_cpython_on_every_value_digit_for_digit() {
    let Some(python) = tool("python3") else {
        return;
    };
    let Some((cases, tsv)) = corpus(&python) else {
        return;
    };
    let limits = Limits::default();

    let out = oracle_output(&python, "values.py", &tsv).expect("python3 was found already");
    let mut canonical: BTreeMap<String, String> = BTreeMap::new();
    for line in out.lines() {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("values.py: {line:?} is not two fields"));
        canonical.insert(name.to_owned(), value.to_owned());
    }

    let mut compared = 0usize;
    for case in &cases {
        let Some(want) = canonical.get(&case.name) else {
            // CPython refused the bytes, so it has no answer about what was in
            // them. A verdict difference is the other test's business.
            continue;
        };
        let Ok(body) = body_of(case, limits) else {
            continue;
        };
        let Ok(ours) = scalars(&body, limits, LINE) else {
            continue;
        };
        let got = ours
            .iter()
            .map(|line| escape(line))
            .collect::<Vec<String>>()
            .join("\\n");
        assert_eq!(
            &got, want,
            "{}: the scalars CPython read and the scalars we read are not the same",
            case.name
        );
        compared += 1;
    }
    assert!(
        compared > 0,
        "no case was accepted by both, so nothing was compared"
    );
    println!("{compared} documents compared scalar by scalar against CPython");
}

/// The escaping `values.py` documents, applied to one canonical line.
///
/// Backslash doubled, anything below `0x20` as `\xNN` in lowercase hex, and the
/// escaped lines joined by the two characters `\` and `n`. Escaping a real newline
/// as `\x0a` and reserving `\n` for the separator is what keeps one string
/// containing a newline distinguishable from two scalars; the obvious escaping
/// does not.
///
/// `values.py` also escapes `U+D800..U+DFFF`, because CPython will hand back a
/// `str` holding a lone surrogate and that string cannot be encoded as UTF-8 at
/// all. There is no branch for it here and there cannot be: a Rust `String` cannot
/// hold one, which is exactly why this crate refuses those documents rather than
/// substituting or truncating.
fn escape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for ch in line.chars() {
        if ch == '\\' {
            out.push_str("\\\\");
        } else if (ch as u32) < 0x20 {
            out.push_str(&format!("\\x{:02x}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

#[test]
fn our_floats_are_the_bits_cpython_computes() {
    let Some(python) = tool("python3") else {
        return;
    };

    // Chosen literals, not generated ones. Each is a value that separates a
    // correctly rounded conversion from an approximate one, or a magnitude where
    // the answer is a refusal: `1.000000000000000005` and `1.0` print the same at
    // seventeen significant digits and differ in no bit, `2.2250738585072011e-308`
    // is the subnormal boundary that hung PHP, `1e23` is the classic case a
    // shortcut converter gets wrong in the last bit, and `4.9e-324` is the
    // smallest subnormal there is.
    const LITERALS: &[&str] = &[
        "0.2",
        "0.1",
        "1.5",
        "-0.25e1",
        "123.456e-789",
        "2.2250738585072011e-308",
        "2.2250738585072012e-308",
        "1.000000000000000005",
        "9007199254740993",
        "1e23",
        "4.9e-324",
        "0e1",
        "-0",
        "1e308",
        "1e-999",
        "1e309",
        "1e999",
        "-1e999",
    ];

    let mut input = String::new();
    for literal in LITERALS {
        input.push_str(literal);
        input.push('\n');
    }
    let Some(out) = oracle_output(&python, "floats.py", &input) else {
        return;
    };

    let mut bits: BTreeMap<&str, String> = BTreeMap::new();
    for line in out.lines() {
        if line.is_empty() {
            continue;
        }
        let (literal, hex) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("floats.py: {line:?} is not two fields"));
        let pinned = LITERALS
            .iter()
            .find(|l| **l == literal)
            .unwrap_or_else(|| panic!("floats.py answered about {literal}, which was not asked"));
        bits.insert(pinned, hex.to_owned());
    }
    assert_eq!(bits.len(), LITERALS.len(), "floats.py dropped a literal");

    // The infinity encodings, which are the only place we deliberately differ:
    // CPython's `float()` overflows to infinity and stores it, and
    // `Number::as_f64_finite` returns `None` instead. `1e999` is a *finite* number
    // the type cannot hold, so handing back infinity would be a repair, and this
    // tree does not repair. Underflow is the other way round on purpose: a number
    // too small to tell from zero is zero, and both agree about that.
    const INFINITY: &str = "7ff0000000000000";
    const NEGATIVE_INFINITY: &str = "fff0000000000000";

    let mut refused: Vec<&str> = Vec::new();
    for literal in LITERALS {
        let (value, used) = number::scan(literal.as_bytes(), 0, LINE, limits_number_bytes())
            .unwrap_or_else(|e| panic!("{literal} must be a JSON number: {e}"));
        assert_eq!(used, literal.len(), "{literal} was not read whole");
        let want = &bits[literal];
        match value.as_f64_finite() {
            Some(got) => assert_eq!(
                format!("{:016x}", got.to_bits()),
                *want,
                "{literal}: our bits and CPython's differ"
            ),
            None => {
                assert!(
                    want == INFINITY || want == NEGATIVE_INFINITY,
                    "{literal}: we refused it and CPython did not overflow, it got {want}"
                );
                refused.push(literal);
            }
        }
    }
    assert_eq!(
        refused,
        ["1e309", "1e999", "-1e999"],
        "the set of literals we refuse and CPython converts to infinity has changed"
    );
    println!(
        "{} literals compared bit for bit, {} deliberately refused where CPython \
         stores an infinity",
        LITERALS.len(),
        refused.len()
    );
}

fn limits_number_bytes() -> usize {
    Limits::default().max_number_bytes
}

/// The verdict the crate reaches for a case, by the path a stream takes.
fn verdict(case: &Case, limits: Limits) -> JsonResult<()> {
    match body_of(case, limits) {
        Err(e) => Err(e),
        Ok(body) => validate(&body, limits, LINE),
    }
}

/// The bytes the grammar question is asked about, having let the framer answer the
/// encoding and the line splitting first.
///
/// A UTF-8 byte-order mark at offset 0 is the framer's job and the reader
/// deliberately does not skip one, so the two BOM cases have to arrive here
/// already stripped. When a raw LF split the case, the case is asked as one line:
/// that a record cannot survive being cut in two is asserted in tests/corpus.rs,
/// and the question here is the grammar's.
fn body_of(case: &Case, limits: Limits) -> Result<Vec<u8>, JsonError> {
    let (mut lines, report) = frame(&case.bytes, limits)?;
    Ok(match lines.len() {
        0 => {
            let from = if report.leading_bom { BOM_UTF8 } else { 0 };
            case.bytes[from..].to_vec()
        }
        1 => lines.pop().expect("one line"),
        _ => case.bytes.clone(),
    })
}

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

/// Our verdict per case, the `accept`/`reject_*` column only.
fn expectations() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in include_str!("oracle/EXPECTATIONS.tsv").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let name = fields.next().expect("a name").to_owned();
        let verdict = fields
            .next()
            .unwrap_or_else(|| panic!("{name}: no verdict field"))
            .to_owned();
        out.insert(name, verdict);
    }
    out
}

/// Every case the two oracles answer differently, as `(cpython, node)` accepted.
fn disagreements() -> BTreeMap<String, (bool, bool)> {
    let mut out = BTreeMap::new();
    for line in include_str!("oracle/DISAGREEMENTS.tsv").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let name = fields.next().expect("a name").to_owned();
        let cpython = fields
            .next()
            .unwrap_or_else(|| panic!("{name}: no cpython field"));
        let node = fields
            .next()
            .unwrap_or_else(|| panic!("{name}: no node field"));
        assert_ne!(
            cpython, node,
            "{name} is in DISAGREEMENTS.tsv and the two columns agree"
        );
        out.insert(name, (cpython == "accept", node == "accept"));
    }
    assert!(!out.is_empty(), "DISAGREEMENTS.tsv holds no rows");
    out
}

/// The corpus and the TSV it came from, since the classifiers want the same bytes
/// on their standard input.
///
/// Each integration test file is its own binary, so this loader is repeated in
/// each of them rather than shared through a module.
fn corpus(python: &str) -> Option<(Vec<Case>, String)> {
    let tsv = oracle_output(python, "cases.py", "")?;
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
        let rfc = fields
            .next()
            .and_then(|v| v.chars().next())
            .unwrap_or_else(|| panic!("{name}: no verdict field"));
        cases.push(Case {
            name: name.to_owned(),
            bytes: from_hex(name, hex),
            rfc,
        });
    }
    assert!(!cases.is_empty(), "cases.py produced no cases");
    Some((cases, tsv))
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

/// The name of a tool if it is on this machine, or `None` having said so.
///
/// A skipped check that says it was skipped is honest; one that quietly passes is
/// what this project is against.
fn tool(name: &'static str) -> Option<String> {
    match Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Some(name.to_owned()),
        _ => {
            println!("skipped: {name} is not on this machine, so nothing was compared against it");
            None
        }
    }
}

fn script(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("oracle")
        .join(file)
}

/// Run one oracle script and hand back its standard output.
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
            println!("skipped: {tool} would not run {file} ({e})");
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
