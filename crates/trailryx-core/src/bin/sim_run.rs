//! One command to reproduce any run.
//!
//!     trailryx-sim-run --seed 42 --steps 5000 --hostile --crash-ppm 3000
//!
//! Print the trace of a failing seed with `--trace`, and the same seed will
//! print the same bytes on any machine.

use trailryx_core::sim::{SimConfig, run};
use trailryx_sim::{BusFaults, IoFaults};

fn main() {
    let mut cfg = SimConfig::default();
    let mut show_trace = false;
    let mut sweep = 0u64;
    let mut corpus: Option<String> = None;
    let mut print_row = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_default()
        };
        match a {
            "--seed" => cfg.seed = next(&mut i).parse().unwrap_or(1),
            "--steps" => cfg.steps = next(&mut i).parse().unwrap_or(1_000),
            "--shards" => cfg.shards = next(&mut i).parse().unwrap_or(2),
            "--sync-every" => cfg.sync_every = next(&mut i).parse().unwrap_or(8),
            "--crash-ppm" => cfg.crash_ppm = next(&mut i).parse().unwrap_or(0),
            "--crash-at" => cfg.crash_at = next(&mut i).parse().ok(),
            "--sweep" => sweep = next(&mut i).parse().unwrap_or(0),
            "--corpus" => corpus = Some(next(&mut i)),
            "--corpus-row" => print_row = true,
            "--hostile" => {
                cfg.io_faults = IoFaults::HOSTILE;
                cfg.bus_faults = BusFaults::HOSTILE;
            }
            "--honest-disk" => cfg.io_faults.lying_fsync_ppm = 0,
            "--trace" => show_trace = true,
            "--help" | "-h" => {
                println!(
                    "trailryx-sim-run [--seed N] [--steps N] [--shards N] [--sync-every N]\n\
                     \x20                [--crash-ppm N] [--crash-at N] [--hostile] [--honest-disk]\n\
                     \x20                [--sweep N] [--trace]\n\
                     trailryx-sim-run --corpus sim/corpus.tsv\n\
                     trailryx-sim-run --seed N ... --corpus-row\n\
                     \n\
                     --corpus runs every row of a published seed corpus and refuses if any\n\
                     digest differs from the one recorded. That is a determinism check and\n\
                     NOT a correctness one: a wrong implementation reproduces perfectly.\n\
                     \n\
                     --corpus-row prints the row for the current parameters, so regenerating\n\
                     the corpus is a reviewable diff rather than a tool rewriting its own\n\
                     oracle."
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if let Some(path) = corpus {
        std::process::exit(run_corpus(&path));
    }

    if print_row {
        let r = run(cfg);
        println!(
            "{}",
            corpus_row(&cfg, &r.digest_hex(), r.durability_violations)
        );
        return;
    }

    if sweep > 0 {
        let base = cfg.seed;
        let mut failures = 0u64;
        for k in 0..sweep {
            let mut c = cfg;
            c.seed = base.wrapping_add(k);
            let r = run(c);
            if r.durability_violations > 0 {
                failures += 1;
                println!("FAIL {}", r.summary());
            }
        }
        println!("sweep of {sweep} seeds from {base}: {} failing", failures);
        if failures > 0 {
            std::process::exit(1);
        }
        return;
    }

    let r = run(cfg);
    println!("{}", r.summary());
    if show_trace {
        println!("--- trace ---");
        print!("{}", String::from_utf8_lossy(&r.trace_bytes));
    }
    if r.durability_violations > 0 {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// The published seed corpus
// ---------------------------------------------------------------------------
//
// `docs/planning/trailryx-architecture.md` §1a.2 point 4: the simulator is part of
// the product, and the seed of every failure is saved and reproduced with one
// command. A corpus makes the other half of that true as well: the seeds that
// **passed** are published too, with their digests, so anybody can run them and
// find out whether they get the same store.
//
// What it proves and does not prove, said here because it is the easiest thing to
// overstate: it proves this build reproduces those runs byte for byte, on this
// machine or another. It proves nothing about whether the runs are correct. A
// wrong implementation is perfectly reproducible.

/// One tab-separated row: the parameters, the digest they produce, and how many
/// acked records the run lost.
///
/// The violation count is recorded rather than required to be zero, because
/// `docs/durability.md` §7 says out loud that nothing in software defends against
/// a disk that lies about a flush, and that what the simulator guarantees is that
/// we **notice**. Under `--hostile` without `--honest-disk` the simulator lies, so
/// losses are expected there. What was missing until this file existed was the
/// number: "expected" with no count attached is a claim nobody can check, and a
/// change in it would have gone unnoticed.
fn corpus_row(cfg: &SimConfig, digest: &str, violations: u64) -> String {
    let faults = match (
        cfg.io_faults.short_write_ppm > 0 || cfg.bus_faults.drop_ppm > 0,
        cfg.io_faults.lying_fsync_ppm == 0,
    ) {
        (true, true) => "hostile+honest-disk",
        (true, false) => "hostile",
        (false, _) => "plain",
    };
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        cfg.seed, cfg.steps, cfg.shards, cfg.sync_every, cfg.crash_ppm, faults, digest, violations
    )
}

/// Whether this fault set includes a disk that lies about flushing.
///
/// The one condition under which a lost acked record is documented rather than a
/// defect. Named, so the guard below reads as the rule it is.
fn disk_may_lie(faults: &str) -> bool {
    faults == "hostile"
}

/// Parse one row into a configuration, its digest, and its violation count.
fn parse_row(line: &str) -> Result<(SimConfig, String, u64), String> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != 8 {
        return Err(format!("{} fields, expected 8", fields.len()));
    }
    let number = |i: usize, what: &str| -> Result<u64, String> {
        fields[i]
            .parse()
            .map_err(|_| format!("{what} is not a number: {:?}", fields[i]))
    };
    let mut cfg = SimConfig {
        seed: number(0, "the seed")?,
        steps: number(1, "the step count")?,
        shards: u16::try_from(number(2, "the shard count")?)
            .map_err(|_| "the shard count does not fit a u16".to_owned())?,
        sync_every: number(3, "sync-every")?,
        crash_ppm: u32::try_from(number(4, "crash-ppm")?)
            .map_err(|_| "crash-ppm does not fit a u32".to_owned())?,
        ..SimConfig::default()
    };
    match fields[5] {
        "plain" => {}
        "hostile" => {
            cfg.io_faults = IoFaults::HOSTILE;
            cfg.bus_faults = BusFaults::HOSTILE;
        }
        "hostile+honest-disk" => {
            cfg.io_faults = IoFaults::HOSTILE;
            cfg.bus_faults = BusFaults::HOSTILE;
            cfg.io_faults.lying_fsync_ppm = 0;
        }
        other => return Err(format!("unknown fault set {other:?}")),
    }
    let violations = number(7, "the violation count")?;
    // The guard that makes the tempting wrong action impossible. A run with an
    // honest disk that loses an acked record is a defect in the store, and the
    // easiest way to make that failure go away is to paste the new number into
    // this file. So a nonzero count is only accepted on a row where the simulator
    // is lying about fsync, and anywhere else the corpus itself is refused.
    if violations > 0 && !disk_may_lie(fields[5]) {
        return Err(format!(
            "records {violations} durability violations under {:?}, where the disk does not lie. \
             That is a defect in the store and not a number to record",
            fields[5]
        ));
    }
    Ok((cfg, fields[6].to_owned(), violations))
}

/// The one-command reproduction for a row, which is what a mismatch has to print.
fn reproduce_command(cfg: &SimConfig, faults: &str) -> String {
    let flags = match faults {
        "hostile" => " --hostile",
        "hostile+honest-disk" => " --hostile --honest-disk",
        _ => "",
    };
    format!(
        "cargo run --release --bin trailryx-sim-run -- --seed {} --steps {} --shards {} \
         --sync-every {} --crash-ppm {}{flags}",
        cfg.seed, cfg.steps, cfg.shards, cfg.sync_every, cfg.crash_ppm
    )
}

fn run_corpus(path: &str) -> i32 {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("cannot read the corpus {path}: {e}");
            return 2;
        }
    };

    let mut checked = 0usize;
    let mut mismatched = 0usize;
    let mut violations = 0usize;
    for (number, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (cfg, expected, expected_violations) = match parse_row(line) {
            Ok(parsed) => parsed,
            Err(why) => {
                eprintln!("{path}:{}: {why}", number + 1);
                return 2;
            }
        };
        let faults = line.split('\t').nth(5).unwrap_or("plain");
        let result = run(cfg);
        let actual = result.digest_hex();
        checked += 1;

        if actual != expected {
            mismatched += 1;
            println!(
                "MISMATCH {path}:{} expected {expected} got {actual}",
                number + 1
            );
            println!("  reproduce: {}", reproduce_command(&cfg, faults));
            // The row as it would now be, so regenerating the corpus is a diff a
            // person reads rather than a file a tool rewrote.
            println!(
                "  row now:   {}",
                corpus_row(&cfg, &actual, result.durability_violations)
            );
        }
        // A durability violation is a different and worse thing than a changed
        // digest: the store lost an acked record. Compared against the recorded
        // count rather than against zero, because under a lying fsync a loss is
        // documented behaviour and the number is the thing worth watching.
        if result.durability_violations != expected_violations {
            violations += 1;
            println!(
                "VIOLATIONS {path}:{} recorded {expected_violations}, saw {}",
                number + 1,
                result.durability_violations
            );
            println!("  {}", result.summary());
            println!("  reproduce: {}", reproduce_command(&cfg, faults));
        }
    }

    if checked == 0 {
        eprintln!("{path} has no rows, so this check proved nothing");
        return 2;
    }
    println!(
        "corpus of {checked} rows: {mismatched} digest mismatches, {violations} rows whose \
         durability violation count changed"
    );
    if mismatched > 0 || violations > 0 {
        // Said out loud because the tempting response to a mismatch is to paste
        // the new digest in and move on.
        println!(
            "a changed digest is either a defect or a deliberate change to the store's behaviour; \
             regenerating the corpus without knowing which is how a regression gets blessed"
        );
        return 1;
    }
    0
}
