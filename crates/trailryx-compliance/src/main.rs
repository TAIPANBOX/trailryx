//! `trailryx-coverage PACK` prints what a pack proves next to what each
//! obligation asks for.
//!
//! A separate binary from `trailryx-verify` on purpose. The verifier's output is
//! about arithmetic and it must stay that way: a reader who wants to know whether
//! a pack is internally consistent should not have to read past a table about
//! regulation to find out. And the mapping is an interpretation that will change,
//! while the verifier's answer will not.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!(
            "trailryx-coverage PACK\n\
             \n\
             Prints what the pack demonstrates against the EU AI Act, prEN ISO/IEC 24970,\n\
             SR 11-7 and the SOC 2 criteria, and what it does not.\n\
             \n\
             This is not a compliance determination and not legal advice."
        );
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("trailryx-coverage: one pack at a time");
        return ExitCode::from(2);
    }

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("trailryx-coverage: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let report = match trailryx_verify::verify(&bytes) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("trailryx-coverage: {path} is not a readable pack: {e:?}");
            return ExitCode::from(2);
        }
    };

    let assessment = trailryx_compliance::assess(&report);
    print!("{}", trailryx_compliance::render(&assessment));

    // The pack's own verdict decides the exit code, not the coverage table. A
    // table of obligations means nothing about a pack that does not verify, and an
    // exit code that said otherwise would be the most quotable lie here.
    if report.verified() {
        ExitCode::SUCCESS
    } else {
        println!("the pack itself does not verify, so nothing above is evidence of anything");
        ExitCode::from(1)
    }
}
