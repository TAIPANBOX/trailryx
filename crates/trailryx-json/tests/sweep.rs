//! A hundred thousand inputs nobody wrote by hand.
//!
//! # This is not fuzzing, and the difference is worth stating
//!
//! `cargo-fuzz` and AFL++ are better than this at the thing this does. They follow
//! coverage, so they find the branch nobody thought of; they minimise a crashing
//! input down to the bytes that matter; they run for hours and keep a corpus
//! between runs. This walks a hundred thousand points chosen by a seed, with no
//! feedback of any kind, and it will never find a defect that needs a lucky
//! sequence of bytes to reach.
//!
//! It is what is here because `cargo-fuzz` is a third-party dependency and the
//! zero-dependency rule for this crate is absolute: the whole argument for a reader
//! that guards an audit store is that somebody can read it end to end, and that
//! argument does not survive a build-dependency tree. The generator is
//! `trailryx_sim::rng::SimRng`, which is already in the tree and is the thing the
//! rest of the project reproduces runs with, so a failure here is reproducible from
//! the seed and the iteration number printed with it.
//!
//! What it does catch is the class this crate is most exposed to: a slice index
//! computed from attacker-controlled bytes. Every offset in the reader comes from
//! the input, and an arithmetic mistake in one of them is a panic on a network path.
//!
//! # What every input is asserted to do
//!
//! Return `Ok` or `Err`. Never panic, and never disagree with itself: `validate`
//! walks with `skip_rest` while `scalars` drives the containers by hand, so a
//! document one accepts and the other refuses would mean a corpus case could pass
//! in one and fail in the other, which is the thing `validate.rs` exists to make
//! impossible.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use trailryx_json::frame::{Framer, Line};
use trailryx_json::validate::{depth_of, scalars};
use trailryx_json::{JsonResult, Kind, Limits, validate};
use trailryx_sim::rng::{RngExt, SimRng};

const LINE: u64 = 1;

/// The seed. Fixed, so a failure is reproducible and so the run is the same on
/// every machine: a sweep that picked a new seed each time would fail on somebody
/// else's laptop with an input this one never saw.
const SEED: u64 = 0x7261_696C_7279_78FF;

/// How many inputs in total.
const INPUTS: usize = 100_000;

/// How many single-byte mutations of each corpus case.
///
/// A single byte because that is the mutation that stays near a valid document:
/// the corpus cases are the interesting shapes, and one byte away from one of them
/// is where an off-by-one in an offset lives. Bigger mutations land back in the
/// random half of the sweep.
const MUTATIONS_PER_CASE: usize = 180;

/// What the sweep saw, so it can be asserted that it reached the code rather than
/// bouncing off the first byte a hundred thousand times.
#[derive(Debug, Default)]
struct Seen {
    accepted: u64,
    syntax: u64,
    limit: u64,
    encoding: u64,
}

impl Seen {
    fn count(&mut self, result: &JsonResult<()>) {
        match result {
            Ok(()) => self.accepted = self.accepted.saturating_add(1),
            Err(e) => match e.kind {
                Kind::Syntax(_) => self.syntax = self.syntax.saturating_add(1),
                Kind::Limit(_) => self.limit = self.limit.saturating_add(1),
                Kind::Encoding(_) => self.encoding = self.encoding.saturating_add(1),
            },
        }
    }

    fn total(&self) -> u64 {
        self.accepted
            .saturating_add(self.syntax)
            .saturating_add(self.limit)
            .saturating_add(self.encoding)
    }
}

#[test]
fn a_hundred_thousand_random_lines_never_panic() {
    let limits = Limits::default();
    let mut rng = SimRng::new(SEED);
    let mut seen = Seen::default();

    let cases = corpus().unwrap_or_default();
    let mutations = cases.len().saturating_mul(MUTATIONS_PER_CASE);
    assert!(
        mutations < INPUTS,
        "{mutations} mutations leaves no room for a random input in {INPUTS}"
    );
    if cases.is_empty() {
        println!(
            "skipped: the mutation half of the sweep needs python3 for the corpus, so \
             all {INPUTS} inputs are random bytes"
        );
    }

    for (name, bytes) in &cases {
        for i in 0..MUTATIONS_PER_CASE {
            let input = mutate(&mut rng, bytes);
            seen.count(&exercise(&input, limits, &format!("{name} mutation {i}")));
        }
    }

    for i in 0..INPUTS - mutations {
        let input = random_line(&mut rng);
        seen.count(&exercise(&input, limits, &format!("random {i}")));
    }

    assert_eq!(seen.total(), INPUTS as u64, "every input was answered");
    // A sweep that never accepts anything, or never reaches a bound, is testing the
    // first byte of `value` and nothing else. These four counts are the evidence
    // that it got past it, and they are fixed by the seed.
    assert!(seen.accepted > 0, "no input was accepted: {seen:?}");
    assert!(seen.syntax > 0, "no input was a syntax refusal: {seen:?}");
    assert!(seen.encoding > 0, "no input was refused as bytes: {seen:?}");
    // A bound needs twenty-six nested containers, a thousand-digit number or two
    // hundred and fifty-seven members, and a random line of under a hundred bytes
    // reaches none of them however long the sweep runs. The corpus cases sit on
    // every bound by construction, so this count is evidence only when the
    // mutation half ran, and claiming it otherwise would be claiming coverage the
    // sweep does not have.
    if !cases.is_empty() {
        assert!(seen.limit > 0, "no input reached a bound: {seen:?}");
    }
    println!(
        "{INPUTS} inputs at seed {SEED:#x} ({mutations} mutations of {} corpus cases, \
         {} random): {} accepted, {} syntax, {} limit, {} encoding",
        cases.len(),
        INPUTS - mutations,
        seen.accepted,
        seen.syntax,
        seen.limit,
        seen.encoding
    );
}

/// Put one input through every entry point.
///
/// `what` names the input well enough to get back to it, and [`preview`] prints the
/// bytes as hex, which is the form the corpus itself uses: a failing input can be
/// pasted into `cases.py` as a case without being re-encoded.
fn exercise(bytes: &[u8], limits: Limits, what: &str) -> JsonResult<()> {
    let validated = validate(bytes, limits, LINE);
    let walked = scalars(bytes, limits, LINE);
    assert_eq!(
        validated.is_ok(),
        walked.is_ok(),
        "{what}: validate said {:?} and scalars said {:?} about {}",
        validated.map(|()| "ok").map_err(|e| e.kind),
        walked.map(|_| "ok").map_err(|e| e.kind),
        preview(bytes)
    );
    let measured = depth_of(bytes, limits, LINE);
    assert_eq!(
        validated.is_ok(),
        measured.is_ok(),
        "{what}: validate and depth_of disagree about {}",
        preview(bytes)
    );

    // And by the path a stream takes, because that is where a caller meets these
    // bytes: the framer cuts them into lines and each line is read on its own.
    let mut framer = Framer::new(limits);
    {
        let mut sink = |l: Line<'_>| -> JsonResult<()> {
            let _ = validate(l.bytes, limits, l.number);
            let _ = scalars(l.bytes, limits, l.number);
            Ok(())
        };
        // An encoding refusal from the framer is a byte-order mark, which is an
        // answer and not a failure.
        let _ = framer.push(bytes, &mut sink);
        let _ = framer.finish(&mut sink);
    }

    validated
}

/// One corpus case with a single byte replaced.
fn mutate(rng: &mut SimRng, case: &[u8]) -> Vec<u8> {
    let mut out = case.to_vec();
    let byte = u8::try_from(rng.below(256)).expect("under 256");
    if out.is_empty() {
        out.push(byte);
        return out;
    }
    let at = usize::try_from(rng.below(out.len() as u64)).expect("an index into out");
    out[at] = byte;
    out
}

/// One random line: three parts JSON alphabet to one part any byte at all.
///
/// A uniformly random string is refused on its first byte and never reaches the
/// grammar, so a sweep made only of those would exercise one `match` arm a hundred
/// thousand times. The alphabet is what gets the generator into the container
/// drivers, the escape handling and the number scanner; the tenth that is any byte
/// at all is what reaches the UTF-8 check and the control-character check. A tenth
/// rather than a quarter because at these lengths a quarter puts a byte outside
/// ASCII in nearly every line, and the whole-line UTF-8 check then answers before
/// the grammar sees any of it.
fn random_line(rng: &mut SimRng) -> Vec<u8> {
    const ALPHABET: &[u8] =
        b"{}[]\",:0123456789.-+eE truefalsnul\\/uUxX\t\r\n\x00\x0b\x0c\x7f\x80\xc0\xc2\xed\xef\xff";
    // Half the lines are short, because a short line is the only one with a real
    // chance of being a whole valid document, and a sweep that never produces one
    // is not exercising the accepting path at all.
    let span = if rng.chance_ppm(500_000) { 8 } else { 96 };
    let len = usize::try_from(rng.below(span)).expect("under 96");
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let byte = if rng.chance_ppm(900_000) {
            let at = usize::try_from(rng.below(ALPHABET.len() as u64)).expect("an index");
            ALPHABET[at]
        } else {
            u8::try_from(rng.below(256)).expect("under 256")
        };
        out.push(byte);
    }
    out
}

/// The bytes as hex, truncated, so a failure can be reproduced without guessing.
fn preview(bytes: &[u8]) -> String {
    const SHOWN: usize = 96;
    let mut out = String::with_capacity(SHOWN * 2 + 32);
    for &b in bytes.iter().take(SHOWN) {
        out.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > SHOWN {
        out.push_str(&format!("... ({} bytes in all)", bytes.len()));
    }
    out
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
