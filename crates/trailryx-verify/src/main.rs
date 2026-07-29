//! `trailryx-verify <pack>`
//!
//! Reads an evidence pack, prints what it found, and exits non-zero if the pack
//! does not verify. No network, no configuration, no state.

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: trailryx-verify <pack>");
        return ExitCode::from(2);
    };

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
