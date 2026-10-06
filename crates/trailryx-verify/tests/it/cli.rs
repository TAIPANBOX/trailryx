//! The binary's own surface, exercised as a person would reach it.
//!
//! Every other test in this workspace calls the library. That left the one
//! thing an outsider actually runs untested, and it showed: `--help` fell
//! through to the path argument and answered `cannot read --help: No such file
//! or directory`, which reads as a broken program rather than an unsupported
//! flag. Found by following this repository's own install instructions from a
//! published release on 2026-08-04, which is the first time anybody had.
//!
//! `CARGO_BIN_EXE_*` is set by cargo for integration tests of a crate with a
//! binary, so this runs the real binary from the real build with no dependency
//! and no path guessing.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_trailryx-verify"))
        .args(args)
        .output()
        .expect("the verifier binary runs");
    (
        out.status
            .code()
            .expect("it exited rather than being signalled"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn help_is_answered_rather_than_read_as_a_filename() {
    for flag in ["--help", "-h"] {
        let (code, stdout, stderr) = run(&[flag]);
        assert_eq!(code, 0, "{flag} must succeed, got {code} with {stderr:?}");
        assert!(
            stdout.contains("trailryx-verify <pack>"),
            "{flag} must print the usage, got {stdout:?}"
        );
        assert!(
            !stdout.contains("cannot read") && !stderr.contains("cannot read"),
            "{flag} must not be treated as a path, got {stdout:?} {stderr:?}"
        );
    }
}

#[test]
fn the_version_is_answered_because_a_digest_needs_one_beside_it() {
    for flag in ["--version", "-V"] {
        let (code, stdout, stderr) = run(&[flag]);
        assert_eq!(code, 0, "{flag} must succeed, got {code} with {stderr:?}");
        assert!(
            stdout.starts_with("trailryx-verify ") && stdout.trim().split(' ').count() == 2,
            "{flag} must print the name and one version, got {stdout:?}"
        );
        assert!(
            stdout.contains(env!("CARGO_PKG_VERSION")),
            "{flag} must print THIS build's version, got {stdout:?}"
        );
    }
}

/// The escape every other tool has, kept because the flag check now runs before
/// the path is opened: a file genuinely called `--help` is still reachable.
#[test]
fn a_path_that_looks_like_a_flag_is_still_reachable_as_a_path() {
    let (code, _stdout, stderr) = run(&["./--help"]);
    assert_eq!(code, 2, "a missing file is exit 2");
    assert!(
        stderr.contains("cannot read ./--help"),
        "it must have been treated as a path, got {stderr:?}"
    );
}

/// Unchanged behaviour, pinned so the flag handling above cannot quietly take
/// the no-argument case with it.
#[test]
fn no_arguments_still_says_how_to_call_it_and_exits_two() {
    let (code, _stdout, stderr) = run(&[]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("usage: trailryx-verify <pack>"),
        "got {stderr:?}"
    );
}
