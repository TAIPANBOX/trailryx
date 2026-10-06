//! The journal and the index, joined.
//!
//! Up to now the index was tested against records a test invented and links a
//! test made up. These tests take the real write path, seal what it produced,
//! and check that the proofs are about the records actually on disk.

use trailryx_crypto::Sha384;
use trailryx_index::completeness::Dimension;
use trailryx_journal::journal::ChainStart;
use trailryx_journal::journal::{Appended, Journal, JournalError};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted, Verdict,
};
use trailryx_sim::{Io, IoFaults, SimClock, SimIo};
use trailryx_store::{SealOutcome, StoreError, seal_segment};

fn rec(n: u128, at: u64) -> Record {
    Record {
        id: RecordId(n),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/support").unwrap(),
        run_id: RunId::parse(format!("run-{n}")).unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(at)),
        decided_at: None,
        recorded_at: Timestamp(at),
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

fn journal_with(io: &mut SimIo, n: u128, sync: bool) -> Journal {
    let clock = SimClock::new(1_800_000_000_000_000_000);
    let (mut j, _) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "s0.journal",
        1_000,
        ChainStart::First,
        io,
        &clock,
    )
    .unwrap();
    for i in 1..=n {
        assert!(matches!(
            j.append(&rec(i, 1_000 + i as u64 * 10), io).unwrap(),
            Appended::Written { .. }
        ));
    }
    if sync {
        j.sync(io).unwrap();
    }
    j
}

#[test]
fn a_sealed_segment_proves_things_about_the_records_on_disk() {
    let mut io = SimIo::new(1, IoFaults::NONE);
    let j = journal_with(&mut io, 10, true);

    let SealOutcome::Sealed(sealed) = seal_segment(&j, SegmentId(1), ShardIx(0), &mut io).unwrap()
    else {
        panic!("ten acked records should seal");
    };
    assert_eq!(sealed.records, 10);

    let idx = sealed
        .segment
        .index(Dimension::RecordedAt)
        .expect("dimension exists");
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_070);
    let proof = idx.range(&lo, &hi);
    assert_eq!(proof.matched(), 5);
    assert_eq!(
        proof.verify(Dimension::RecordedAt, &lo, &hi, idx.root(), idx.len()),
        Ok(())
    );
}

#[test]
fn the_segment_commits_to_the_journals_own_chain_links() {
    // The seam's whole job. If the segment's history were built from anything
    // the caller invented, a proof would be about that invention rather than
    // about the file.
    let mut io = SimIo::new(2, IoFaults::NONE);
    let j = journal_with(&mut io, 6, true);
    let walked = j.read_all(&mut io).unwrap();

    let SealOutcome::Sealed(sealed) = seal_segment(&j, SegmentId(1), ShardIx(0), &mut io).unwrap()
    else {
        panic!("should seal");
    };

    let last_link = walked.records.last().map(|(_, l)| *l).unwrap();
    assert_eq!(sealed.manifest().chain_after, last_link);
    assert_eq!(sealed.chain_after, j.head());
}

#[test]
fn only_the_durable_prefix_is_sealed() {
    // A published root describing records that a crash could take away is a
    // root that lies. Everything written but not yet synced stays out.
    let mut io = SimIo::new(3, IoFaults::NONE);
    let mut j = journal_with(&mut io, 4, true);
    for i in 5..=8u128 {
        j.append(&rec(i, 1_000 + i as u64 * 10), &mut io).unwrap();
    }
    assert_eq!(j.written(), 8);
    assert_eq!(j.acked(), 4);

    let SealOutcome::Sealed(sealed) = seal_segment(&j, SegmentId(1), ShardIx(0), &mut io).unwrap()
    else {
        panic!("should seal");
    };
    assert_eq!(sealed.records, 4, "only what survives a crash");
    assert_eq!(sealed.manifest().records, 4);
}

#[test]
fn an_idle_journal_seals_nothing_and_that_is_not_an_error() {
    let mut io = SimIo::new(4, IoFaults::NONE);
    let j = journal_with(&mut io, 0, false);
    assert!(matches!(
        seal_segment(&j, SegmentId(1), ShardIx(0), &mut io).unwrap(),
        SealOutcome::NothingDurable
    ));
}

#[test]
fn a_tampered_record_changes_what_the_segment_commits_to() {
    let mut io = SimIo::new(6, IoFaults::NONE);
    let j = journal_with(&mut io, 5, true);
    let SealOutcome::Sealed(honest) = seal_segment(&j, SegmentId(1), ShardIx(0), &mut io).unwrap()
    else {
        panic!("should seal");
    };

    // Rewrite one record's verdict in a parallel universe and seal that.
    let mut walked = j.read_all(&mut io).unwrap().records;
    walked[2].0.outcome.verdict = Some(Verdict::Allowed);
    walked[2].1 = Sha384::digest(b"a link for the rewritten record");
    let tampered =
        trailryx_index::segment::Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &walked)
            .unwrap();

    assert_ne!(
        honest.manifest().history_root,
        tampered.manifest().history_root
    );
    assert_ne!(honest.manifest().root(), tampered.manifest().root());
}

#[test]
fn a_suspect_journal_is_not_sealed() {
    // A torn tail is ordinary and the acked prefix is untouched by it, so that
    // seals. A chain that does not follow is not something to seal a prefix of.
    let mut io = SimIo::new(7, IoFaults::NONE);
    let j = journal_with(&mut io, 5, true);

    // Ordinary crash debris after the acked prefix.
    let f = io.create("s0.journal").unwrap();
    io.append(f, b"\xa7\x01\x05partial").unwrap();
    assert!(matches!(
        seal_segment(&j, SegmentId(1), ShardIx(0), &mut io).unwrap(),
        SealOutcome::Sealed(_)
    ));

    // Now make the file's own chain disagree with itself.
    let mut bytes = io.read_all(f).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    io.truncate(f, 0).unwrap();
    io.append(f, &bytes).unwrap();

    match seal_segment(&j, SegmentId(1), ShardIx(0), &mut io) {
        Err(StoreError::JournalSuspect(_)) | Err(StoreError::DurabilityViolation { .. }) => {}
        other => panic!("a damaged journal must not seal quietly: {other:?}"),
    }
}

/// Replaces two tests that no longer describe the code, and it is worth saying
/// which so nobody reintroduces them.
///
/// One was called `segments_chain_to_one_another` and sealed a single file twice
/// under two different chain starts, asserting the roots differed. It proved
/// something real, that the incoming head is committed to the root, while
/// claiming a property the implementation did not have.
///
/// The other asserted that a wrong chain start handed to `seal_segment` is
/// refused. There is no longer a way to hand it one: the journal knows where its
/// own chain began, so the parameter is gone and the mistake is unspellable.
#[test]
fn a_shards_segments_chain_across_files() {
    // What the previous version of this test said was impossible. A journal's
    // chain now continues from the head the segment before it ended on, so a
    // shard is one chain across as many files as it takes.
    //
    // Why it matters: without it, deleting a whole segment file left every
    // remaining file internally valid and the shard's history quietly shorter.
    let mut io = SimIo::new(7, IoFaults::NONE);
    let clock = SimClock::new(1_800_000_000_000_000_000);

    let (mut one, _) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "s0-1.journal",
        1_000,
        ChainStart::First,
        &mut io,
        &clock,
    )
    .unwrap();
    one.append(&rec(1, 1_010), &mut io).unwrap();
    one.sync(&mut io).unwrap();
    let SealOutcome::Sealed(first) = seal_segment(&one, SegmentId(1), ShardIx(0), &mut io).unwrap()
    else {
        panic!("should seal");
    };

    let (mut two, _) = Journal::open(
        ShardIx(0),
        SegmentId(2),
        "s0-2.journal",
        1_000,
        ChainStart::After(first.chain_after),
        &mut io,
        &clock,
    )
    .unwrap();
    two.append(&rec(2, 1_020), &mut io).unwrap();
    two.sync(&mut io).unwrap();
    let SealOutcome::Sealed(second) =
        seal_segment(&two, SegmentId(2), ShardIx(0), &mut io).unwrap()
    else {
        panic!("should seal");
    };

    assert_eq!(
        second.manifest().chain_before,
        first.chain_after,
        "the second segment must begin where the first ended"
    );
    assert_eq!(two.genesis_head(), first.chain_after);
}

#[test]
fn a_file_cannot_be_re_pointed_at_a_different_predecessor() {
    // The other half. Once a file's records are chained from one head, reopening
    // it under another makes its very first record fail to verify, so a segment
    // cannot be quietly moved to a different place in the shard's history.
    let mut io = SimIo::new(11, IoFaults::NONE);
    let clock = SimClock::new(1_800_000_000_000_000_000);
    let real = Sha384::digest(b"the head it really followed");

    let (mut j, _) = Journal::open(
        ShardIx(0),
        SegmentId(2),
        "s0-2.journal",
        1_000,
        ChainStart::After(real),
        &mut io,
        &clock,
    )
    .unwrap();
    j.append(&rec(1, 1_010), &mut io).unwrap();
    j.sync(&mut io).unwrap();
    drop(j);

    // The file used to be truncated here: the record failed the chain check
    // against the preferred head, and recovery discarded it and carried on. That
    // meant re-pointing a file both failed *and* emptied it, so the attempt
    // destroyed the evidence of itself. A well-formed frame whose chain does not
    // follow is not something a crash produces, so recovery now refuses and
    // leaves every byte in place.
    let file = io.create("s0-2.journal").unwrap();
    let before = io.read_all(file).unwrap().len();
    let err = Journal::open(
        ShardIx(0),
        SegmentId(2),
        "s0-2.journal",
        1_000,
        ChainStart::After(Sha384::digest(b"a head somebody would prefer")),
        &mut io,
        &clock,
    )
    .map(|_| ())
    .expect_err("a record chained from another head must not be adopted");
    assert!(
        matches!(err, JournalError::CorruptMidFile { .. }),
        "expected a refusal naming the corruption, got {err:?}"
    );
    assert_eq!(
        io.read_all(file).unwrap().len(),
        before,
        "the record was deleted by the attempt to re-point the file"
    );
}
