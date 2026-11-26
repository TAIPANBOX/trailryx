//! One command to reproduce any run.
//!
//!     trailryx-sim-run --seed 42 --steps 5000 --hostile --crash-ppm 3000
//!
//! Print the trace of a failing seed with `--trace`, and the same seed will
//! print the same bytes on any machine.

use trailryx_core::sim::{SimConfig, run};
use trailryx_sim::{BusFaults, IoFaults};

/// What the command line asked for, before anything runs.
struct Options {
    cfg: SimConfig,
    show_trace: bool,
    sweep: u64,
    corpus: Option<String>,
    print_row: bool,
    help: bool,
}

/// The arguments, read in order. `--help` answers as soon as it is reached; an
/// argument nobody defined is refused rather than ignored.
fn options(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        cfg: SimConfig::default(),
        show_trace: false,
        sweep: 0,
        corpus: None,
        print_row: false,
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_default()
        };
        match a {
            "--seed" => o.cfg.seed = next(&mut i).parse().unwrap_or(1),
            "--steps" => o.cfg.steps = next(&mut i).parse().unwrap_or(1_000),
            "--shards" => o.cfg.shards = next(&mut i).parse().unwrap_or(2),
            "--sync-every" => o.cfg.sync_every = next(&mut i).parse().unwrap_or(8),
            "--crash-ppm" => o.cfg.crash_ppm = next(&mut i).parse().unwrap_or(0),
            "--crash-at" => o.cfg.crash_at = next(&mut i).parse().ok(),
            "--sweep" => o.sweep = next(&mut i).parse().unwrap_or(0),
            "--corpus" => o.corpus = Some(next(&mut i)),
            "--corpus-row" => o.print_row = true,
            "--hostile" => {
                o.cfg.io_faults = IoFaults::HOSTILE;
                o.cfg.bus_faults = BusFaults::HOSTILE;
            }
            "--honest-disk" => o.cfg.io_faults.lying_fsync_ppm = 0,
            "--trace" => o.show_trace = true,
            "--help" | "-h" => {
                o.help = true;
                return Ok(o);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(o)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Options {
        cfg,
        show_trace,
        sweep,
        corpus,
        print_row,
        help,
    } = match options(&args) {
        Ok(options) => options,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    if help {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A scratch directory for one test, unique to this process and to the test.
    fn scratch(what: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trailryx-sim-run-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    /// The rows of the published corpus short enough to run under a debug build.
    fn short_published_rows() -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../sim/corpus.tsv");
        let text = std::fs::read_to_string(path).expect("the published corpus is in the tree");
        let rows: Vec<String> = text
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| l.split('\t').nth(1).and_then(|s| s.parse::<u64>().ok()) <= Some(800))
            .map(str::to_owned)
            .collect();
        assert!(
            rows.iter().any(|r| r.contains("\thostile\t")),
            "the short rows include one where the disk lies, so a recorded loss is exercised"
        );
        rows
    }

    #[test]
    fn no_arguments_are_the_defaults() {
        let o = options(&[]).expect("no arguments are accepted");
        let d = SimConfig::default();
        assert_eq!(
            (o.cfg.seed, o.cfg.steps, o.cfg.shards, o.cfg.sync_every),
            (d.seed, d.steps, d.shards, d.sync_every)
        );
        assert!(!o.help && !o.show_trace && !o.print_row);
        assert_eq!((o.sweep, o.corpus), (0, None));
    }

    #[test]
    fn every_flag_lands_on_the_field_it_names() {
        let o = options(&args(&[
            "--seed", "7", "--steps", "200", "--shards", "3", "--sync-every", "4",
            "--crash-ppm", "12000", "--crash-at", "50", "--sweep", "5", "--trace",
            "--corpus-row", "--corpus", "x.tsv",
        ]))
        .expect("every flag is known");
        assert_eq!(o.cfg.seed, 7);
        assert_eq!(o.cfg.steps, 200);
        assert_eq!(o.cfg.shards, 3);
        assert_eq!(o.cfg.sync_every, 4);
        assert_eq!(o.cfg.crash_ppm, 12_000);
        assert_eq!(o.cfg.crash_at, Some(50));
        assert_eq!(o.sweep, 5);
        assert!(o.show_trace && o.print_row);
        assert_eq!(o.corpus.as_deref(), Some("x.tsv"));
    }

    #[test]
    fn hostile_turns_both_fault_sets_on_and_honest_disk_turns_only_the_lie_off() {
        let hostile = options(&args(&["--hostile"])).expect("known");
        assert_eq!(hostile.cfg.io_faults, IoFaults::HOSTILE);
        assert_eq!(hostile.cfg.bus_faults, BusFaults::HOSTILE);
        assert!(hostile.cfg.io_faults.lying_fsync_ppm > 0);

        let honest = options(&args(&["--hostile", "--honest-disk"])).expect("known");
        assert_eq!(honest.cfg.io_faults.lying_fsync_ppm, 0);
        assert_eq!(
            honest.cfg.io_faults.short_write_ppm,
            IoFaults::HOSTILE.short_write_ppm,
            "an honest disk is still an unreliable one"
        );
    }

    #[test]
    fn help_answers_where_it_is_reached_and_an_unknown_argument_is_refused() {
        assert!(options(&args(&["--help", "--bogus"])).expect("help").help);
        assert!(options(&args(&["-h"])).expect("help").help);
        assert_eq!(
            options(&args(&["--bogus", "--help"])).err(),
            Some("unknown argument: --bogus".to_owned())
        );
    }

    #[test]
    fn a_row_and_its_parse_are_inverses_for_every_fault_set() {
        let mut cfg = SimConfig {
            seed: 99,
            steps: 1_500,
            shards: 2,
            sync_every: 2,
            crash_ppm: 20_000,
            ..SimConfig::default()
        };
        assert!(corpus_row(&cfg, "abc", 0).contains("\tplain\t"));
        cfg.io_faults = IoFaults::HOSTILE;
        cfg.bus_faults = BusFaults::HOSTILE;
        let row = corpus_row(&cfg, "fd3383475e495889", 3);
        assert_eq!(row, "99\t1500\t2\t2\t20000\thostile\tfd3383475e495889\t3");
        let (back, digest, violations) = parse_row(&row).expect("its own row parses");
        assert_eq!(
            (back.seed, back.steps, back.shards, back.sync_every, back.crash_ppm),
            (99, 1_500, 2, 2, 20_000)
        );
        assert_eq!(back.io_faults, IoFaults::HOSTILE);
        assert_eq!((digest.as_str(), violations), ("fd3383475e495889", 3));

        cfg.io_faults.lying_fsync_ppm = 0;
        let honest = corpus_row(&cfg, "d", 0);
        assert!(honest.contains("\thostile+honest-disk\t"));
        let (back, _, _) = parse_row(&honest).expect("its own row parses");
        assert_eq!(back.io_faults.lying_fsync_ppm, 0);
        assert_eq!(back.bus_faults, BusFaults::HOSTILE);
    }

    #[test]
    fn a_malformed_row_is_refused_and_says_which_field() {
        let cases = [
            ("1\t400\t2\t8\t0\tplain\tabc", "7 fields, expected 8"),
            ("x\t400\t2\t8\t0\tplain\tabc\t0", "the seed is not a number"),
            ("1\t400\t70000\t8\t0\tplain\tabc\t0", "the shard count does not fit a u16"),
            ("1\t400\t2\t8\t5000000000\tplain\tabc\t0", "crash-ppm does not fit a u32"),
            ("1\t400\t2\t8\t0\tgentle\tabc\t0", "unknown fault set \"gentle\""),
            ("1\t400\t2\t8\t0\tplain\tabc\tmany", "the violation count is not a number"),
        ];
        for (row, why) in cases {
            let refused = parse_row(row).err().unwrap_or_default();
            assert!(refused.contains(why), "{row:?} gave {refused:?}, not {why:?}");
        }
    }

    #[test]
    fn a_loss_is_recorded_only_where_the_disk_lies() {
        assert!(parse_row("2\t800\t3\t4\t12000\thostile\tabc\t2").is_ok());
        for faults in ["plain", "hostile+honest-disk"] {
            let refused = parse_row(&format!("2\t800\t3\t4\t12000\t{faults}\tabc\t2"))
                .err()
                .unwrap_or_default();
            assert!(
                refused.contains("That is a defect in the store"),
                "a loss under {faults} was accepted as a number to record: {refused:?}"
            );
        }
    }

    #[test]
    fn the_reproduction_command_carries_the_flags_of_its_fault_set() {
        let cfg = SimConfig {
            seed: 3,
            steps: 800,
            shards: 3,
            sync_every: 4,
            crash_ppm: 12_000,
            ..SimConfig::default()
        };
        let base = "cargo run --release --bin trailryx-sim-run -- --seed 3 --steps 800 \
                    --shards 3 --sync-every 4 --crash-ppm 12000";
        assert_eq!(reproduce_command(&cfg, "plain"), base);
        assert_eq!(
            reproduce_command(&cfg, "hostile"),
            format!("{base} --hostile")
        );
        assert_eq!(
            reproduce_command(&cfg, "hostile+honest-disk"),
            format!("{base} --hostile --honest-disk")
        );
    }

    #[test]
    fn the_published_rows_reproduce_and_a_changed_digest_or_loss_count_is_refused() {
        let dir = scratch("corpus");
        let rows = short_published_rows();
        let path = dir.join("corpus.tsv");
        let path_text = path.to_string_lossy().into_owned();

        std::fs::write(&path, format!("# a comment\n\n{}\n", rows.join("\n")))
            .expect("the corpus is written");
        let reproduced = run_corpus(&path_text);

        let mut digest = rows.clone();
        let mut changed: Vec<String> = digest[0].split('\t').map(str::to_owned).collect();
        changed[6] = "0000000000000000".to_owned();
        digest[0] = changed.join("\t");
        std::fs::write(&path, digest.join("\n")).expect("the corpus is written");
        let mismatched = run_corpus(&path_text);

        let lying = rows
            .iter()
            .find(|r| r.contains("\thostile\t"))
            .expect("a row where the disk lies")
            .clone();
        let mut loss: Vec<String> = lying.split('\t').map(str::to_owned).collect();
        let recorded: u64 = loss[7].parse().expect("a recorded count");
        loss[7] = (recorded + 1).to_string();
        std::fs::write(&path, loss.join("\t")).expect("the corpus is written");
        let recounted = run_corpus(&path_text);

        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reproduced, 0, "a published row no longer reproduces");
        assert_eq!(mismatched, 1, "a changed digest was not reported");
        assert_eq!(recounted, 1, "a changed loss count was not reported");
    }

    #[test]
    fn a_corpus_that_cannot_be_read_or_holds_nothing_proves_nothing() {
        let dir = scratch("empty");
        let empty = dir.join("empty.tsv");
        std::fs::write(&empty, "# only a comment\n\n").expect("the corpus is written");
        let nothing = run_corpus(&empty.to_string_lossy());
        let bad = dir.join("bad.tsv");
        std::fs::write(&bad, "not\ta\trow\n").expect("the corpus is written");
        let malformed = run_corpus(&bad.to_string_lossy());
        let missing = run_corpus(&dir.join("absent.tsv").to_string_lossy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(nothing, 2, "an empty corpus passed");
        assert_eq!(malformed, 2, "a malformed corpus passed");
        assert_eq!(missing, 2, "a missing corpus passed");
    }
}
