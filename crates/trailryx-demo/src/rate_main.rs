//! Append rate on one shard, against a real filesystem, at several sync policies.
//!
//! # Why this exists
//!
//! The README and three sections of `VALIDATION.md` said the same thing about this
//! plane: nothing here has been measured for throughput. That was honest and it was
//! also the one absence somebody deciding whether to put this in front of a live
//! event stream cannot work around, because the shape of the write path invites a
//! wrong guess in both directions. `sync_every` is a single field, the only number
//! between "every record is durable before the next one is written" and "a batch is
//! durable and the ones after it are not yet", and the distance between those two
//! ends is two thousand times, not two.
//!
//! # Why a binary rather than a test
//!
//! A test asserts and this measures. Written as a `#[test]` it would be a test that
//! cannot fail, which is noise in a suite where every other one refuses something,
//! and `scripts/readme-numbers.sh` would then carry its count as a claim about
//! coverage that it is not. The number it prints is a property of the machine under
//! it, so it cannot be a gate either: it belongs in *measured on demand*, with its
//! command and its date beside it, which is what `VALIDATION.md` reserves that
//! section for.
//!
//! # What this does NOT measure, which is most of what a deployment would pay
//!
//! One shard in one process, which is the plane's whole design (single-writer by
//! construction), so this is the ceiling for one and says nothing about many.
//! `payload: None`, so no encryption, no key wrap and no custodian: the custodian's
//! own cost is measured separately and is about 10 ms per key. No sealing, no Merkle
//! tree, no signing, no anchor, no network and no receiver in front. A journal that
//! starts empty and never rolls to a second segment.
//!
//! So the figure is the metadata write path alone, at its best, and every stage
//! added downstream can only take from it. It is a ceiling to design against, not a
//! throughput a deployment should expect.
//!
//! # What it does measure honestly
//!
//! A real `fsync` on a real filesystem, which on APFS is `F_FULLFSYNC` and is the
//! expensive and honest one. Each `sync` is two of them, the journal and then the
//! watermark, and the watermark is what makes the acked figure survive the process,
//! so a run that skipped it would be measuring a promise nobody could keep.
//!
//! Run it:
//!
//! ```text
//! cargo run --release --bin trailryx-rate
//! cargo run --release --bin trailryx-rate -- --seconds 10 --sync-every 1,64,4096
//! ```

use std::path::PathBuf;
use std::time::Instant;

use trailryx_journal::journal::{Appended, ChainStart, Journal};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_sim::{StdIo, SystemClock};

/// The default ladder. One at each end and three between, because the interesting
/// part is not either end but where the curve crosses the rate a caller needs.
const LADDER: &[u64] = &[1, 16, 128, 1024, 8192];

/// Long enough that a scheduling hiccup does not own the result, short enough that
/// the whole ladder is under a minute.
const DEFAULT_SECONDS: f64 = 5.0;

/// The record every run appends.
///
/// Deliberately the smallest one the type permits: no payload reference, no causal
/// edges, no delegation chain. A bigger record would measure the encoder as much as
/// the disk, and the encoder is not the question here. The bytes-per-record column
/// says what this one costs on the file, so a caller carrying more can scale it.
fn rec(n: u128) -> Record {
    Record {
        id: RecordId(n),
        tenant: TenantId::parse("acme").expect("a literal tenant"),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/support").expect("a literal agent"),
        run_id: RunId::parse(format!("run-{n}")).expect("a literal run"),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_000 + n as u64)),
        decided_at: None,
        recorded_at: Timestamp(1_000 + n as u64),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome::default(),
        payload: None,
        seq: 0,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(0),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

struct Run {
    records: u64,
    seconds: f64,
    bytes: u64,
}

fn one(sync_every: u64, seconds: f64, dir: &std::path::Path) -> Result<Run, String> {
    let _ = std::fs::remove_dir_all(dir);
    let mut io = StdIo::new(dir).map_err(|e| format!("{dir:?}: {e}"))?;
    let clock = SystemClock::new();
    let (mut journal, _) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "s0.journal",
        sync_every,
        ChainStart::First,
        &mut io,
        &clock,
    )
    .map_err(|e| format!("open: {e:?}"))?;

    let start = Instant::now();
    let mut n: u128 = 0;
    loop {
        n += 1;
        match journal.append(&rec(n), &mut io) {
            Ok(Appended::Written { .. }) => {}
            Ok(other) => return Err(format!("append refused at {n}: {other:?}")),
            Err(e) => return Err(format!("append failed at {n}: {e:?}")),
        }
        if journal.sync_due() {
            journal.sync(&mut io).map_err(|e| format!("sync: {e:?}"))?;
        }
        // The clock is read every 64 records rather than every one. At the fast end
        // the read itself would otherwise be a measurable share of the loop, which
        // would make the number smaller in exactly the case it is being trusted in.
        if n % 64 == 0 && start.elapsed().as_secs_f64() >= seconds {
            break;
        }
    }
    // Every run ends with the same promise made, so the columns are comparable: a
    // run that stopped mid-batch would have written more than it acked.
    journal
        .sync(&mut io)
        .map_err(|e| format!("final sync: {e:?}"))?;
    let elapsed = start.elapsed().as_secs_f64();

    let bytes = std::fs::metadata(dir.join("s0.journal"))
        .map(|m| m.len())
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(dir);

    Ok(Run {
        records: n as u64,
        seconds: elapsed,
        bytes,
    })
}

fn main() {
    let mut seconds = DEFAULT_SECONDS;
    let mut ladder: Vec<u64> = LADDER.to_vec();
    // Named after this process, because `$TMPDIR` is shared by every process one
    // user runs and two of these racing would take each other's journal.
    let mut dir = std::env::temp_dir().join(format!("trailryx-rate-{}", std::process::id()));

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| -> String {
            args.get(i + 1)
                .cloned()
                .unwrap_or_else(|| fail(&format!("{} needs a value", args[i])))
        };
        match args[i].as_str() {
            "--seconds" => {
                seconds = next(i)
                    .parse()
                    .unwrap_or_else(|_| fail("--seconds wants a number"));
                i += 2;
            }
            "--sync-every" => {
                ladder = next(i)
                    .split(',')
                    .map(|s| {
                        s.trim()
                            .parse()
                            .unwrap_or_else(|_| fail("--sync-every wants numbers, comma separated"))
                    })
                    .collect();
                i += 2;
            }
            "--dir" => {
                dir = PathBuf::from(next(i));
                i += 2;
            }
            "--help" | "-h" => {
                println!(
                    "trailryx-rate [--seconds N] [--sync-every A,B,C] [--dir PATH]\n\
                     \n\
                     Appends to one shard for N seconds at each sync policy and prints the rate.\n\
                     Every path it writes is removed afterwards."
                );
                return;
            }
            other => fail(&format!("unknown argument {other}")),
        }
    }

    if ladder.is_empty() {
        fail("--sync-every left nothing to run");
    }

    println!(
        "one shard, one process, {seconds:.0}s per policy, under {}",
        dir.display()
    );
    println!();
    println!("sync_every    records    seconds     records/s   bytes/record");
    println!("-------------------------------------------------------------");
    for sync_every in ladder {
        match one(sync_every, seconds, &dir.join(format!("s{sync_every}"))) {
            Ok(r) => println!(
                "{:>10}   {:>8}   {:>7.3}   {:>11.0}   {:>12.1}",
                sync_every,
                r.records,
                r.seconds,
                r.records as f64 / r.seconds,
                r.bytes as f64 / r.records as f64
            ),
            Err(e) => fail(&e),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!();
    println!(
        "The ceiling for metadata alone: no payload, no seal, no signature, no network.\n\
         Every stage downstream takes from it. See VALIDATION.md."
    );
}

fn fail(message: &str) -> ! {
    eprintln!("trailryx-rate: {message}");
    std::process::exit(2);
}
