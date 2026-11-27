//! The kill runs, run as `scripts/kill-linux.sh` runs them, at a few rounds each.
//!
//! These are the binary's own durability checks: a writer killed by the operating
//! system mid-stream, then the journal (or the key custodian) reopened and asked
//! whether anything it acknowledged is missing. Here they run short, so that the
//! harness itself, its counting and its verdict, is held by the suite rather than
//! only by a script somebody runs on a Linux box.
//!
//! The wait is bounded (invariant 18): a run that does not finish is killed and
//! reported rather than hanging the suite.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn kill_run(args: &[&str]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_trailryx-kill"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the kill binary starts");
    let mut stdout = child.stdout.take().expect("its stdout is piped");
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child can be asked") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    let _ = stdout.read_to_string(&mut out);
    let status = status.unwrap_or_else(|| panic!("{args:?} was still running after 120s: {out}"));
    (status.code(), out)
}

fn rounds(out: &str) -> Vec<&str> {
    out.lines()
        .filter(|l| l.trim_start().starts_with("round "))
        .collect()
}

#[test]
fn a_writer_killed_three_times_loses_no_acked_record() {
    let (code, out) = kill_run(&["run", "3"]);
    assert_eq!(code, Some(0), "the kill run reported a loss:\n{out}");
    let rounds = rounds(&out);
    assert_eq!(rounds.len(), 3, "three rounds were asked for:\n{out}");
    assert!(
        rounds.iter().all(|r| r.ends_with("ok")),
        "a round was not clean:\n{out}"
    );
    assert!(
        out.contains("3 kills, highest ack ") && out.contains("no acked record lost on "),
        "the verdict line is missing:\n{out}"
    );
}

#[test]
fn a_custodian_killed_twice_undoes_no_destruction_and_loses_no_wrap() {
    let (code, out) = kill_run(&["custody", "2"]);
    assert_eq!(
        code,
        Some(0),
        "the custody run reported a violation:\n{out}"
    );
    let rounds = rounds(&out);
    assert_eq!(rounds.len(), 2, "two rounds were asked for:\n{out}");
    assert!(
        rounds
            .iter()
            .all(|r| r.contains("resurrected   0, lost   0") && r.ends_with("ok")),
        "a round was not clean:\n{out}"
    );
    assert!(
        out.contains("2 kills, ") && out.contains("none undone"),
        "the verdict line is missing:\n{out}"
    );
}
