//! `trailryx-verify <pack>`
//!
//! Reads an evidence pack, prints what it found, and exits non-zero if the pack
//! does not verify. No network, no configuration, no state.

use std::process::ExitCode;

/// What this program is, in the words somebody typing `--help` is asking for.
///
/// This binary is the one thing here meant to be run by a person who does not
/// trust us, so it is also the one thing that cannot answer `--help` with an
/// error. It did until 2026-08-04: the flag fell through to the path argument
/// and came back as `cannot read --help: No such file or directory`, which
/// reads as a broken program rather than an unsupported flag.
const USAGE: &str = "\
trailryx-verify <pack>

Verifies an evidence pack offline: no network, no configuration, no state.
Prints what it found and exits 0 only if the pack verifies.

  <pack>            path to the evidence pack to check
  -h, --help        print this and exit
  -V, --version     print the version and exit

Exit codes:
  0   verified
  1   read, and did not verify
  2   could not be read at all, or the arguments were wrong

The version matters when reporting a result: this binary is built
reproducibly, so a digest is only meaningful next to the version that
produced it. See docs/reproducing.md.";

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: trailryx-verify <pack>");
        return ExitCode::from(2);
    };

    // Before the path is treated as a path. A file genuinely called `--help` is
    // reachable as `./--help`, which is the same escape every other tool has.
    match path.as_str() {
        "-h" | "--help" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "-V" | "--version" => {
            println!("trailryx-verify {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let report = match trailryx_verify::verify(&bytes) {
        Ok(r) => r,
        Err(e) => {
            println!("BROKEN: {e}");
            return ExitCode::FAILURE;
        }
    };

    for finding in &report.findings {
        println!("{finding}");
    }
    println!(
        "{} records in {} segments",
        report.records_checked, report.segments_checked
    );

    if report.verified() {
        println!("VERIFIED");
        ExitCode::SUCCESS
    } else {
        println!("NOT VERIFIED");
        ExitCode::FAILURE
    }
}
