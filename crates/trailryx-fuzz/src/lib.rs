//! Every hand-written parser, fed bytes it did not expect.
//!
//! # Why this exists rather than a fuzzing framework
//!
//! Stage 13 asks for the parsers to be fuzzed. The usual answer is `cargo-fuzz`,
//! which needs a nightly compiler and produces a corpus nobody can replay from a
//! commit message. This project already has the better half of that machinery: a
//! seeded deterministic generator whose whole purpose is that **a failure is a
//! number somebody else can rerun**. So the fuzzer is that generator pointed at the
//! parsers, and a failing case arrives as a seed and an index rather than as a file
//! in a directory on one machine.
//!
//! It also runs in the gate, which a nightly-only tool cannot.
//!
//! # What is being checked, and what is not
//!
//! Every target is a function from bytes to a result. The property is the same for
//! all of them and is deliberately weak, because a weak property that holds for
//! every input is worth more here than a strong one that holds for the inputs
//! somebody thought of:
//!
//! - **it must not panic**, on any bytes at all;
//! - **it must not hang**, which shows up as the run not finishing;
//! - **it must not allocate on a promise**, which the parsers enforce themselves by
//!   bounding every declared length against what is actually there. This one cannot
//!   be asserted from outside, so it is a rule the targets are written to and this
//!   suite catches only its symptom, a process that stops responding.
//!
//! What it does **not** check is that a parser accepts what it should. That is what
//! the oracle tests are for, where a real implementation sits on the other side.
//!
//! # How the inputs are made
//!
//! Random bytes find shallow bugs and almost nothing else, because a parser rejects
//! them at the first field. Most of the value is in **mutating something valid**:
//! flip a bit, truncate, splice two seeds together, repeat a chunk. That produces
//! input which is valid right up until it is not, which is where length fields,
//! offsets and nesting depths live.

use std::panic::{AssertUnwindSafe, catch_unwind};

use trailryx_sim::{Rng, RngExt, SimRng};

/// One parser, and something valid for it to be a mutation of.
///
/// `Debug` prints the corpus by size rather than by content: a corpus is bytes, and
/// a failing assertion that dumps three kilobytes of them helps nobody.
pub struct Target {
    pub name: &'static str,
    /// Bytes this parser accepts, used as the seed for mutation. An empty corpus is
    /// allowed and means only random input, which finds much less.
    pub corpus: Vec<Vec<u8>>,
    /// The parser. It answers whether the input was accepted, and that answer is
    /// not the property under test: it is how the suite measures whether it is
    /// reaching past the first rejection. A fuzzer whose inputs are all refused at
    /// byte one runs quickly and proves nothing.
    pub run: fn(&[u8]) -> bool,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("name", &self.name)
            .field(
                "corpus",
                &self.corpus.iter().map(Vec::len).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// What one run of the suite did, so the gate can print something a reader can act
/// on rather than the word "ok".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub targets: usize,
    pub cases: u64,
    /// How many inputs each target accepted. Reported rather than asserted here,
    /// because what counts as "deep enough" differs per parser, but a zero is
    /// always a suite that is testing nothing but the first check.
    pub accepted: Vec<(&'static str, u64)>,
    /// Every panic, with the seed and case index that produced it. A failing suite
    /// that does not say how to reproduce the failure is a suite nobody fixes.
    pub failures: Vec<Failure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub target: &'static str,
    pub seed: u64,
    pub case: u64,
    /// The input, so a reader can paste it into a test rather than re-deriving it.
    pub input: Vec<u8>,
}

impl Failure {
    /// A line somebody can act on without reading this crate.
    pub fn reproduce(&self) -> String {
        format!(
            "{} panicked on seed {} case {} with {} bytes: {}",
            self.target,
            self.seed,
            self.case,
            self.input.len(),
            self.input
                .iter()
                .take(64)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }
}

/// Run every target for `cases` inputs each, from one seed.
pub fn run(targets: &[Target], seed: u64, cases: u64) -> Report {
    let mut failures = Vec::new();
    let mut accepted = Vec::new();
    let mut total = 0;
    for target in targets {
        let mut rng = SimRng::new(seed ^ hash_name(target.name));
        let mut taken = 0;
        for case in 0..cases {
            let input = generate(&mut rng, &target.corpus);
            total += 1;
            // A parser reading somebody else's bytes must never take the process
            // down with it, which is the whole property being checked.
            match catch_unwind(AssertUnwindSafe(|| (target.run)(&input))) {
                Ok(true) => taken += 1,
                Ok(false) => {}
                Err(_) => failures.push(Failure {
                    target: target.name,
                    seed,
                    case,
                    input,
                }),
            }
        }
        accepted.push((target.name, taken));
    }
    Report {
        targets: targets.len(),
        cases: total,
        accepted,
        failures,
    }
}

/// A per-target offset, so two targets do not see the same stream of inputs.
fn hash_name(name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.as_bytes() {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// Random bytes, or a mutation of something valid. The second finds far more.
fn generate(rng: &mut SimRng, corpus: &[Vec<u8>]) -> Vec<u8> {
    if corpus.is_empty() || rng.chance_ppm(200_000) {
        let len = rng.below(512) as usize;
        return (0..len).map(|_| (rng.next_u64() & 0xff) as u8).collect();
    }
    let mut bytes = corpus[rng.below(corpus.len() as u64) as usize].clone();
    match rng.below(5) {
        // A flipped bit: the case that found the journal-deleting header bug.
        0 => {
            if !bytes.is_empty() {
                let at = rng.below(bytes.len() as u64) as usize;
                bytes[at] ^= 1 << (rng.below(8) as u8);
            }
        }
        // Truncation: every parser here has to survive its input ending anywhere.
        1 => {
            let keep = rng.below(bytes.len() as u64 + 1) as usize;
            bytes.truncate(keep);
        }
        // A byte replaced outright, which reaches length and tag fields harder than
        // a bit flip does.
        2 => {
            if !bytes.is_empty() {
                let at = rng.below(bytes.len() as u64) as usize;
                bytes[at] = (rng.next_u64() & 0xff) as u8;
            }
        }
        // Extra bytes on the end, which is how a parser that trusts its own length
        // field rather than the buffer gets caught.
        3 => {
            let extra = rng.below(32) as usize;
            for _ in 0..extra {
                bytes.push((rng.next_u64() & 0xff) as u8);
            }
        }
        // A chunk repeated, which produces plausible-looking nesting and the sort of
        // depth a recursive reader has to refuse rather than follow.
        _ => {
            if bytes.len() > 4 {
                let at = rng.below(bytes.len() as u64) as usize;
                let len = rng.below((bytes.len() - at) as u64) as usize;
                let chunk: Vec<u8> = bytes[at..at + len].to_vec();
                for _ in 0..rng.below(4) {
                    bytes.extend_from_slice(&chunk);
                }
            }
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_that_panics_is_reported_with_a_way_to_reproduce_it() {
        fn always_panics(bytes: &[u8]) -> bool {
            if bytes.len() > 1 {
                panic!("deliberate");
            }
            false
        }
        let targets = vec![Target {
            name: "deliberate",
            corpus: vec![vec![1, 2, 3, 4]],
            run: always_panics,
        }];
        let report = run(&targets, 1, 20);
        assert!(
            !report.failures.is_empty(),
            "a panicking target must be caught rather than taking the run down"
        );
        let line = report.failures[0].reproduce();
        assert!(line.contains("seed 1"), "{line}");
        assert!(line.contains("deliberate"), "{line}");
    }

    #[test]
    fn the_same_seed_produces_the_same_inputs() {
        fn nothing(_: &[u8]) -> bool {
            true
        }
        let targets = || {
            vec![Target {
                name: "nothing",
                corpus: vec![b"a valid enough thing".to_vec()],
                run: nothing,
            }]
        };
        let a = run(&targets(), 42, 50);
        let b = run(&targets(), 42, 50);
        assert_eq!(a, b, "a seed is the whole state");
    }

    /// Mutation has to actually mutate. A generator that returned its corpus
    /// unchanged would pass every suite and prove nothing, which is the failure mode
    /// worth guarding against here.
    #[test]
    fn mutation_produces_something_other_than_the_corpus() {
        let seed = b"the original bytes".to_vec();
        let mut rng = SimRng::new(9);
        let mut different = 0;
        for _ in 0..200 {
            if generate(&mut rng, std::slice::from_ref(&seed)) != seed {
                different += 1;
            }
        }
        assert!(
            different > 150,
            "only {different} of 200 inputs differed from the corpus"
        );
    }
}
