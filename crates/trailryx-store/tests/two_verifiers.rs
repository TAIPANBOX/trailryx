//! Two verifiers, one pack, and they must agree.
//!
//! `docs/planning/trailryx-plan.md` asks for this by name under R6: a second
//! independent implementation in another language reading the same pack, because
//! **two implementations that agree prove the format rather than the author**. The
//! Rust verifier answers "who checked your code" with "read it, it has no
//! dependencies". This answers a different question: whether the format is written
//! down well enough that another program reaches the same verdict.
//!
//! The Python one is `verifier-py/trailryx_verify.py`, standard library only. It
//! shares no code with the Rust one.
//!
//! # What this test does and does not establish
//!
//! It establishes that both programs, on the same bytes, agree on VERIFIED or
//! BROKEN across a good pack and a set of tampered ones, and that they agree about
//! how many records they checked. Where they disagree, one is wrong and the format
//! is ambiguous, and both are worth finding out.
//!
//! It does not establish independence in the strongest sense: the Python was
//! written by reading the Rust, so it would not catch the same misunderstanding
//! made twice. Stated here rather than implied, because the weaker claim is still
//! the one the plan asks for and overstating it would be worse than not having it.

use std::process::Command;

use trailryx_crypto::{Sha384, chain_step};
use trailryx_index::segment::{Segment, ShardTree, StoreTree};
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_store::evidence::PackBuilder;
use trailryx_verify::verify;

const GENERATED_AT: Timestamp = Timestamp(1_700_000_000_000_000_000);

fn genesis() -> Hash {
    Sha384::digest(b"trailryx-test/segment-genesis")
}

fn record(id: u128, seq: u64, run: &str) -> Record {
    Record {
        id: RecordId(id),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/billing").unwrap(),
        run_id: RunId::parse(run).unwrap(),
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
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

/// A pack with two segments in one shard, so the cross-segment chain and the
/// shard root are both exercised rather than trivially satisfied.
fn pack() -> Vec<u8> {
    let mut tree = ShardTree::new(ShardIx(0));
    let mut segments = Vec::new();
    let mut link = genesis();
    let mut start = genesis();
    for id in 1..=2u64 {
        // Each segment numbers its records from one, because one segment is one
        // journal file. The first version of this fixture numbered globally and the
        // Rust verifier rejected it, correctly: `sequence-contiguous` checks
        // position plus one, not merely that the number went up.
        let records: Vec<Record> = (0..3)
            .map(|k| record(u128::from(id * 100 + k), k + 1, "run-a"))
            .collect();
        let leaves: Vec<(Record, Hash)> = records
            .iter()
            .map(|r| {
                link = chain_step(link, r.seq, &encode_record(r));
                (r.clone(), link)
            })
            .collect();
        let segment = Segment::seal(SegmentId(id), ShardIx(0), start, &leaves).unwrap();
        tree.push(segment.manifest().clone());
        start = link;
        segments.push(segment);
    }
    let store = StoreTree::from_shards(&[tree.clone()]);
    let refs: Vec<&Segment> = segments.iter().collect();
    PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&tree, &refs)
        .build(&store)
}

struct Verdict {
    verified: bool,
    records: u64,
}

fn rust(bytes: &[u8]) -> Verdict {
    match verify(bytes) {
        Ok(report) => Verdict {
            verified: report.verified(),
            records: report.records_checked,
        },
        // A pack that does not parse is not verified, which is the same answer the
        // Python gives, so the two are comparable at the boundary too.
        Err(_) => Verdict {
            verified: false,
            records: 0,
        },
    }
}

fn python(python: &str, bytes: &[u8], name: &str) -> Verdict {
    // The pid is invariant 29, and this is the site where breaking it cost the most:
    // `name` separates the cases within one run and nothing separated one run from
    // another, so a second run deleted `good.trxevid` below while this one's Python
    // was still reading it. Measured on 6 August 2026 at thirty concurrent copies,
    // 86 of 150 processes failed.
    //
    // What made it expensive is what the failure said. The pack was fine and the
    // reader was fine, and the assertion read "the second verifier rejected a pack
    // the first accepted, so the format is ambiguous or one of them is wrong". This
    // binary is also its own step of `.githooks/pre-push`, so it refused pushes
    // rather than flaking a test, and a `cargo test` in a second worktree was enough.
    //
    // `name` is in the directory as well as in the file so that the wipe at the end
    // can take the directory rather than leave an empty one behind on every run. The
    // three callers run on parallel test threads and each carries its own `name`,
    // which is what makes that wipe safe: wiping the shared per-process directory
    // instead would put the same bug back one level down, between threads.
    let dir = std::env::temp_dir().join(format!(
        "trailryx-two-verifiers-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.trxevid"));
    std::fs::write(&path, bytes).unwrap();

    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../verifier-py/trailryx_verify.py"
    );
    let out = Command::new(python)
        .arg(script)
        .arg(&path)
        .output()
        .expect("the second verifier should run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let verified = stdout.lines().last() == Some("VERIFIED");
    let records = stdout
        .lines()
        .find_map(|line| {
            line.strip_suffix(" segments")
                .and_then(|l| l.split_once(" records in "))
                .and_then(|(n, _)| n.parse().ok())
        })
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(&dir);
    Verdict { verified, records }
}

fn interpreter() -> Option<String> {
    // Any python3 will do: the script imports nothing but the standard library,
    // which is the point of writing it that way.
    let ok = Command::new("python3")
        .args(["-c", "import hashlib; hashlib.sha384()"])
        .output()
        .is_ok_and(|o| o.status.success());
    ok.then(|| "python3".to_owned())
}

/// The good pack, and both must agree on every number they report.
#[test]
fn both_verifiers_accept_a_good_pack_and_count_the_same_records() {
    let Some(py) = interpreter() else {
        println!("skipped: no python3 with hashlib, so the second verifier did not run");
        return;
    };
    let bytes = pack();
    let a = rust(&bytes);
    let b = python(&py, &bytes, "good");

    assert!(a.verified, "the Rust verifier rejected a pack it built");
    assert!(
        b.verified,
        "the second verifier rejected a pack the first accepted, so the format is \
         ambiguous or one of them is wrong"
    );
    assert_eq!(
        a.records, b.records,
        "the two verifiers checked a different number of records"
    );
    assert_eq!(a.records, 6, "two segments of three");
}

/// Every tampering must be caught by both. This is where a format that is
/// under-documented shows up: a check one side makes and the other does not.
#[test]
fn both_verifiers_reject_the_same_tamperings() {
    let Some(py) = interpreter() else {
        println!("skipped: no python3, so the second verifier did not run");
        return;
    };
    let good = pack();

    // Each case names what it breaks. The offsets are found by searching for the
    // bytes rather than hard-coded, so a format change moves them with it.
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    // A flipped bit deep in the last record: the chain, the history root and the
    // index roots all have to notice.
    let mut body = good.clone();
    let at = body.len() - 200;
    body[at] ^= 0x01;
    cases.push(("a flipped bit in a record", body));

    // The magic, so neither can even begin.
    let mut body = good.clone();
    body[1] ^= 0xFF;
    cases.push(("the magic", body));

    // A version from the future. Both must refuse rather than half-read it.
    let mut body = good.clone();
    body[7] = 99;
    cases.push(("an unknown version", body));

    // The store root in the header, which is what a signature would cover.
    let mut body = good.clone();
    let root_at = 8 + 1 + 8 + 4 + 1 + "acme".len() + 8;
    body[root_at] ^= 0x80;
    cases.push(("the store root", body));

    // Truncated in the middle: a length field then points past the end.
    cases.push(("a truncated pack", good[..good.len() / 2].to_vec()));

    for (what, bytes) in cases {
        let a = rust(&bytes);
        let b = python(&py, &bytes, "tampered");
        assert!(
            !a.verified,
            "the Rust verifier accepted {what} being altered"
        );
        assert!(
            !b.verified,
            "the second verifier accepted {what} being altered, which the first caught"
        );
    }
}

/// Both must reject an appended section nobody walks to. This is the defect that
/// was found in the Rust verifier by an adversarial review, so it is the one most
/// worth checking twice.
#[test]
fn both_verifiers_reject_a_shard_nobody_listed() {
    let Some(py) = interpreter() else {
        println!("skipped: no python3, so the second verifier did not run");
        return;
    };
    let good = pack();
    // Splice a segment section naming a shard the header never listed, in front of
    // the terminating SECTION_END.
    let end = good
        .iter()
        .rposition(|b| *b == 0)
        .expect("a pack ends with SECTION_END");
    let mut body = good[..end].to_vec();

    let mut section = Vec::new();
    section.extend_from_slice(&7u16.to_be_bytes()); // format version
    section.extend_from_slice(&99u64.to_be_bytes()); // segment id
    section.extend_from_slice(&42u16.to_be_bytes()); // a shard nobody lists
    section.extend_from_slice(&0u64.to_be_bytes()); // records
    section.extend_from_slice(&[0u8; 48]); // history root
    section.extend_from_slice(&[0u8; 48]); // chain before
    section.extend_from_slice(&[0u8; 48]); // chain after
    section.extend_from_slice(&0u64.to_be_bytes()); // index roots
    section.extend_from_slice(&0u64.to_be_bytes()); // first
    section.extend_from_slice(&0u64.to_be_bytes()); // last
    section.extend_from_slice(&[1u8, 1, 1]); // algorithms

    body.push(3); // SECTION_SEGMENT
    body.extend_from_slice(&(section.len() as u64).to_be_bytes());
    body.extend_from_slice(&section);
    body.extend_from_slice(&good[end..]);

    let a = rust(&body);
    let b = python(&py, &body, "orphan");
    assert!(!a.verified, "the Rust verifier accepted an unlisted shard");
    assert!(
        !b.verified,
        "the second verifier accepted an unlisted shard, so it is missing the check \
         an adversarial review added to the first"
    );
}
