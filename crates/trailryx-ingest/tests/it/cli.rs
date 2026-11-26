//! The `trailryx-ingest` binary's own command line, run as an operator runs it.
//!
//! Everything the binary refuses, it refuses before it serves, so each case here
//! exits on its own. The wait is bounded anyway (invariant 18): a case that
//! started serving by mistake is killed and reported rather than hanging the run.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Run the binary, and give back its exit code and everything it printed.
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_trailryx-ingest"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child can be asked") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    let status = status.unwrap_or_else(|| panic!("{args:?} was still running after 30s"));
    (status.code(), stdout, stderr)
}

/// A scratch directory for one case, unique to this process and to the case.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("trailryx-ingest-cli-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }

    fn file(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("a scratch file");
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn refused(args: &[&str], says: &str) {
    let (code, _stdout, stderr) = run(args);
    assert_eq!(code, Some(2), "{args:?} was not refused: {stderr}");
    assert!(
        stderr.starts_with("trailryx-ingest: ") && stderr.contains(says),
        "{args:?} was refused without saying {says:?}: {stderr}"
    );
}

#[test]
fn help_names_both_doors_and_exits_zero() {
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.starts_with("trailryx-ingest [--bind ADDR:PORT]"));
    assert!(
        stdout.contains("--token-file names a file holding one shared secret"),
        "the shared-secret door is not described: {stdout}"
    );
    assert!(
        stdout.contains("--agent-token-issuer URL"),
        "the agent-token door is not described: {stdout}"
    );
}

#[test]
fn an_argument_this_binary_does_not_take_is_refused_by_name() {
    refused(&["--frobnicate", "1"], "unknown argument --frobnicate");
    refused(&["--bind"], "unknown argument --bind");
}

#[test]
fn a_bind_tenant_or_trust_domain_it_cannot_use_is_refused_before_anything_listens() {
    refused(
        &["--bind", "somewhere"],
        "--bind somewhere is not an address:port",
    );
    refused(
        &["--tenant", "Not A Tenant"],
        "--tenant Not A Tenant is not a valid identifier",
    );
}

#[test]
fn the_shared_secret_and_the_agent_token_door_are_one_or_the_other() {
    let dir = Scratch::new("both");
    let secret = dir.file("secret", "a-fleet-secret\n");
    refused(
        &[
            "--token-file",
            &secret,
            "--agent-token-issuer",
            "https://issuer.example",
        ],
        "pass --token-file or the --agent-token-* flags, not both",
    );
}

#[test]
fn an_agent_token_door_missing_a_flag_does_not_start() {
    let (code, _stdout, stderr) = run(&["--agent-token-issuer", "https://issuer.example"]);
    assert_eq!(code, Some(2), "a door with one of four flags started: {stderr}");
}

#[test]
fn a_secret_that_cannot_be_read_or_is_empty_is_refused() {
    let dir = Scratch::new("secret");
    let absent = dir.0.join("absent").to_string_lossy().into_owned();
    refused(&["--token-file", &absent], "cannot read --token-file");
    let empty = dir.file("empty", "\n");
    refused(&["--token-file", &empty], &format!("--token-file {empty}"));
}

#[test]
fn a_routable_bind_with_no_credential_is_refused_and_told_what_would_do() {
    refused(
        &["--bind", "0.0.0.0:0"],
        "pass --token-file PATH, where PATH holds one shared secret",
    );
}

#[test]
fn a_port_somebody_else_holds_is_refused_with_a_credential_too() {
    let dir = Scratch::new("busy");
    let secret = dir.file("secret", "a-fleet-secret\n");
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let port = taken.local_addr().expect("its address").to_string();
    refused(
        &["--bind", &port, "--token-file", &secret],
        "cannot bind: ",
    );
    drop(taken);
}
