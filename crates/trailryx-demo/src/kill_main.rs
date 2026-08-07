//! The kill run: a real process, a real disk, and a real `SIGKILL`.
//!
//! # Why this exists when there is already a simulator
//!
//! The simulator crashes the store at every point in a write and checks that the
//! acked prefix survives. It is the reason to believe the design. What it cannot do
//! is be wrong about the disk: it is a model of one, written by the same people who
//! wrote the code it is testing, and a model shares its author's assumptions.
//!
//! A real filesystem lies in its own ways. Directory entries and file contents reach
//! the platter in an order nobody promised, `fsync` on a file says nothing about the
//! directory that names it, and a laptop's disk cache answers before anything is
//! durable. So this run does the only thing a model cannot: it lets the operating
//! system kill the process, without warning, on the actual filesystem underneath.
//!
//! The roadmap asks for ext4 and xfs. **This machine has neither**, so the number
//! this prints is for APFS and says so. That is worth more than nothing and less
//! than what stage 13 asks for, and the honest way to hold both of those at once is
//! to print which filesystem it ran on.
//!
//! # What is being checked
//!
//! The sentence the whole project is built on:
//!
//! > Every sequence number reported as acked survives any crash.
//!
//! So the writer prints each acked sequence number as it happens and the reader,
//! after the kill, recovers the journal and compares. Recovering **more** than was
//! acked is fine and expected: a write can land without its acknowledgement being
//! seen. Recovering **less** is the product being false about the one thing it
//! sells, and it fails the run.
//!
//! # The second subject: the key custodian
//!
//! `custody` runs the same shape against `trailryx_crypto_aws::PersistedKeyProvider`,
//! and the sentence it checks is the one crypto-erasure rests on:
//!
//! > Every key reported destroyed stays destroyed, and every key reported wrapped is
//! > still there.
//!
//! Both halves, because the ordering has two sides and only one of them is the
//! frightening one. A destruction that a crash rolls back is a controller who has
//! already told a regulator the data is gone; a wrapped key whose file never landed
//! is a payload nobody can open again. The child prints each answer as it gets it,
//! the parent kills it without warning, reopens the directory and asks.
//!
//! It is here rather than in a test because a test cannot be killed. `#[test]`
//! processes unwind, run destructors and flush, and every one of those is a thing a
//! `SIGKILL` does not do.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use trailryx_contracts::contracts::{KeyId, KeyProvider};
use trailryx_crypto_aws::{CustodyKey, PersistedKeyProvider};
use trailryx_journal::journal::{Appended, ChainStart, Journal};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_sim::{StdIo, SystemClock};

const JOURNAL: &str = "journal";

/// The root key the custody run uses.
///
/// A constant, and it is one of the few places in this repository where that is the
/// right answer: the directory it protects is created and destroyed by this binary
/// and holds nothing. A deployment's key comes from an operator, which is the whole
/// argument in `trailryx_crypto_aws::persisted`.
const CUSTODY_ROOT: [u8; 32] = [0x5a; 32];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("run");
    match mode {
        // The child: append until somebody kills it, printing each ack.
        "write" => write(PathBuf::from(&args[2])),
        // The custody child: wrap and destroy until somebody kills it.
        "custody-keys" => custody_keys(
            Path::new(&args[2]),
            args.get(3).and_then(|v| v.parse().ok()).unwrap_or(0),
        ),
        "custody" => {
            let rounds: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(10);
            custody(rounds);
        }
        // The parent: spawn, kill, verify, repeat.
        _ => {
            let rounds: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(10);
            run(rounds);
        }
    }
}

/// A key id from a counter. The custodian only needs them to be distinct.
fn kek(n: u64) -> KeyId {
    let mut bytes = [0u8; 48];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    KeyId(Hash(bytes))
}

/// The child: wrap keys, destroy two out of every three, and print each answer.
///
/// `base` keeps each round on key ids of its own. Without it every round re-treads
/// the ids the last one left behind, and the run measures reopening a directory
/// rather than committing to it: the first version did exactly that and produced one
/// destruction across twenty kills, which is invariant 19's failure wearing a
/// harness's clothes.
///
/// Two in three are destroyed rather than one in three, because the destruction is
/// the ordering under test and the survivors are the control.
///
/// Flushed per line, for the same reason the journal writer flushes: an answer still
/// in this process's buffer when it dies was never reported, and counting it would
/// make the test easier than the promise.
fn custody_keys(dir: &Path, base: u64) {
    let mut provider = match PersistedKeyProvider::open(dir, CustodyKey::from_bytes(CUSTODY_ROOT)) {
        Ok(provider) => provider,
        Err(e) => {
            eprintln!("the custodian would not open: {e}");
            return;
        }
    };
    let stdout = std::io::stdout();
    for n in base + 1.. {
        if provider.wrap(kek(n), &[7u8; 32]).is_err() {
            return;
        }
        {
            let mut out = stdout.lock();
            let _ = writeln!(out, "wrapped {n}");
            let _ = out.flush();
        }
        if n % 3 != 0 {
            if provider.destroy(kek(n)).is_err() {
                return;
            }
            let mut out = stdout.lock();
            let _ = writeln!(out, "destroyed {n}");
            let _ = out.flush();
        }
    }
}

/// The parent: spawn, kill, reopen the directory, and ask it what it kept.
fn custody(rounds: usize) {
    let dir = std::env::temp_dir().join(format!("trailryx-kill-custody-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    println!("custody kill run: {rounds} rounds in {}", dir.display());
    println!("filesystem: {}", filesystem(&dir));

    let exe = std::env::current_exe().expect("this binary");
    let mut resurrected = 0;
    let mut lost = 0;
    let mut destroyed_total = 0u64;
    let mut wrapped_total = 0u64;

    for round in 1..=rounds {
        let base = (round as u64) * 10_000;
        let mut child = Command::new(&exe)
            .arg("custody-keys")
            .arg(&dir)
            .arg(base.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the writer starts");

        // A different length each round, so the kill lands in a different place:
        // mid-generation, mid-commit, between the rename and the report. Longer than
        // the journal run's window because a commit here is two `fsync`s and a
        // `F_FULLFSYNC` on APFS is tens of milliseconds, so a short round measures
        // process start-up instead of the protocol.
        let micros = 400_000 + (round as u64 * 79_193) % 600_000;
        std::thread::sleep(std::time::Duration::from_micros(micros));
        let _ = child.kill();
        let output = child.wait_with_output().expect("the writer stops");

        let text = String::from_utf8_lossy(&output.stdout);
        let reported = |prefix: &str| -> Vec<u64> {
            text.lines()
                .filter_map(|l| l.strip_prefix(prefix).and_then(|n| n.parse::<u64>().ok()))
                .collect()
        };
        let destroyed = reported("destroyed ");
        let wrapped = reported("wrapped ");
        destroyed_total += destroyed.len() as u64;
        wrapped_total += wrapped.len() as u64;

        // A new process over the same directory, which is what a restart is.
        let mut provider = PersistedKeyProvider::open(&dir, CustodyKey::from_bytes(CUSTODY_ROOT))
            .expect("the custodian reopens");

        let mut back = 0;
        for n in &destroyed {
            // Three questions and not one: `exists` could be wrong on its own, and a
            // key that refuses `exists` while still unwrapping is the failure that
            // matters.
            if provider.exists(kek(*n))
                || provider.wrap(kek(*n), &[7u8; 32]).is_ok()
                || provider.unwrap(kek(*n), &[0u8; 1133]).is_ok()
            {
                back += 1;
            }
        }
        let mut gone = 0;
        for n in &wrapped {
            if n % 3 == 0 && !provider.exists(kek(*n)) {
                gone += 1;
            }
        }
        resurrected += back;
        lost += gone;

        println!(
            "  round {round:>3}: wrapped {:>5}, destroyed {:>5}, resurrected {back:>3}, lost {gone:>3}  {}",
            wrapped.len(),
            destroyed.len(),
            if back == 0 && gone == 0 {
                "ok"
            } else {
                "VIOLATION"
            }
        );
    }

    println!();
    if resurrected == 0 && lost == 0 {
        println!(
            "{rounds} kills, {destroyed_total} destructions reported and none undone, \
             {wrapped_total} wraps reported and none lost, on {}",
            filesystem(&dir)
        );
    } else {
        println!(
            "{resurrected} destroyed key(s) came back and {lost} wrapped key(s) vanished \
             across {rounds} kills"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    if resurrected > 0 || lost > 0 {
        std::process::exit(1);
    }
}

fn record(seq: u64, prev: Hash) -> Record {
    Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").expect("a tenant"),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/support").expect("an agent"),
        run_id: RunId::parse("kill-run").expect("a run"),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_000 + seq)),
        decided_at: None,
        recorded_at: Timestamp(1_000 + seq),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome::default(),
        payload: None,
        seq,
        prev_hash: prev,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

/// Append for ever, printing every acked sequence number as it is acked.
///
/// Flushed on every line on purpose: an ack that is still in this process's buffer
/// when it dies was never reported, and counting it would make the test easier than
/// the promise.
fn write(dir: PathBuf) {
    std::fs::create_dir_all(&dir).expect("a directory");
    let mut io = StdIo::new(dir).expect("the filesystem");
    let clock = SystemClock::new();
    let (mut journal, recovered) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        JOURNAL,
        // Every fourth record, so the run crosses both sides of a sync boundary
        // rather than only the easy one.
        4,
        ChainStart::First,
        &mut io,
        &clock,
    )
    .expect("the journal opens");

    let mut seq = recovered.max_seq;
    let mut head = recovered.head;
    let stdout = std::io::stdout();
    loop {
        seq += 1;
        match journal.append(&record(seq, head), &mut io) {
            Ok(Appended::Written { link, .. }) => head = link,
            // A record still going to disk, or one the device would not take
            // whole. Neither is an ack, so neither is printed, and the next call
            // continues it.
            Ok(_) => {
                seq -= 1;
                continue;
            }
            Err(_) => return,
        }
        // The caller decides when to sync, which is what makes the durability
        // contract explicit rather than inherited from a library's defaults. The
        // first version of this harness never called it, so `acked` stayed at zero,
        // every round compared zero against zero, and the run passed while proving
        // nothing. That is the failure mode this whole file exists to catch in the
        // store, met in the test for it.
        if journal.sync_due() {
            let acked = journal.sync(&mut io).expect("the sync succeeds");
            let mut out = stdout.lock();
            let _ = writeln!(out, "acked {acked}");
            let _ = out.flush();
        }
    }
}

/// Spawn the writer, kill it after a while, and check what survived.
fn run(rounds: usize) {
    let dir = std::env::temp_dir().join(format!("trailryx-kill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    println!("kill run: {rounds} rounds in {}", dir.display());
    println!("filesystem: {}", filesystem(&dir));

    let exe = std::env::current_exe().expect("this binary");
    let mut highest_acked = 0u64;
    let mut violations = 0;

    for round in 1..=rounds {
        let mut child = Command::new(&exe)
            .arg("write")
            .arg(&dir)
            .stdout(Stdio::piped())
            .spawn()
            .expect("the writer starts");

        // Let it get going, for a length that differs per round so the kill lands
        // in a different place each time: mid-record, mid-sync, between the two.
        let micros = 20_000 + (round as u64 * 7_919) % 60_000;
        std::thread::sleep(std::time::Duration::from_micros(micros));

        // SIGKILL: no unwinding, no destructors, no flush. The only thing that
        // survives is what the operating system already took.
        let _ = child.kill();
        let output = child.wait_with_output().expect("the writer stops");

        let acked = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix("acked ").and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(0);
        highest_acked = highest_acked.max(acked);

        let mut io = StdIo::new(dir.clone()).expect("the filesystem");
        let clock = SystemClock::new();
        let (_, recovered) = Journal::open(
            ShardIx(0),
            SegmentId(1),
            JOURNAL,
            4,
            ChainStart::First,
            &mut io,
            &clock,
        )
        .expect("the journal reopens");

        let survived = recovered.max_seq >= acked;
        if !survived {
            violations += 1;
        }
        println!(
            "  round {round:>3}: acked {acked:>5}, recovered {:>5}, discarded {:>5} bytes  {}",
            recovered.max_seq,
            recovered.discarded_bytes,
            if survived { "ok" } else { "VIOLATION" }
        );
        if let Some(violation) = recovered.durability_violation {
            println!("    the journal reported it itself: {violation:?}");
            violations += 1;
        }
    }

    println!();
    if violations == 0 {
        println!(
            "{rounds} kills, highest ack {highest_acked}, no acked record lost on {}",
            filesystem(&dir)
        );
    } else {
        println!("{violations} durability violations across {rounds} kills");
    }
    let _ = std::fs::remove_dir_all(&dir);
    if violations > 0 {
        std::process::exit(1);
    }
}

/// Which filesystem this actually ran on, because the answer is only meaningful
/// with it. A number from a run on APFS is not a number from a run on ext4, and
/// printing one while the roadmap asks for the other is the kind of quiet
/// substitution this project spends its time refusing.
fn filesystem(path: &std::path::Path) -> String {
    let _ = std::fs::create_dir_all(path);
    let device = Command::new("df")
        .arg(path)
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .nth(1)
                .and_then(|l| l.split_whitespace().next().map(str::to_owned))
        })
        .unwrap_or_default();
    let kind = proc_mounts(&device)
        .or_else(|| mount_command(&device))
        .unwrap_or_else(|| "unknown filesystem".to_owned());
    format!("{kind} on {device}")
}

/// Linux: the kernel's own table, in fixed columns, in a fixed order.
///
/// Worth preferring over parsing `mount`, and not for tidiness. The two platforms
/// print different things and the difference is silent: macOS puts the type first
/// inside the brackets, `apfs on /dev/disk3s5 (apfs, local, ...)`, while Linux puts
/// mount options there and the type after the word `type`. The macOS parser applied
/// to Linux does not fail, it returns `rw`, and this whole function exists because a
/// wrong filesystem name next to a durability claim is worth less than none.
fn proc_mounts(device: &str) -> Option<String> {
    let table = std::fs::read_to_string("/proc/mounts").ok()?;
    table
        .lines()
        .find(|l| l.split_whitespace().next() == Some(device))
        .and_then(|l| l.split_whitespace().nth(2))
        .map(str::to_owned)
}

/// macOS, and anything else with a BSD-shaped `mount`.
fn mount_command(device: &str) -> Option<String> {
    let out = Command::new("mount").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| !device.is_empty() && l.starts_with(device))
        .and_then(|l| {
            l.split_once('(')
                .and_then(|(_, rest)| rest.split(&[',', ')'][..]).next())
                .map(str::to_owned)
        })
}
