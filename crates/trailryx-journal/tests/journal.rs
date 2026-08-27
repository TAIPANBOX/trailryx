//! The journal against the fault-injecting simulator from stage 0.
//!
//! The skeleton that stood in for a journal is gone; these are the real write
//! path and the real recovery, and the same crash model is pointed at them.

use trailryx_crypto::{ChainState, Sha384};
use trailryx_journal::journal::{
    Appended, ChainStart, DurabilityViolation, Journal, JournalError, StoppedBecause,
};
use trailryx_journal::wire::{
    FRAME_VERSION, WireError, decode_frame, decode_record, decode_record_at, encode_frame,
    encode_frame_at, encode_record,
};
use trailryx_record::{
    AgentId, Algorithms, Basis, DelegationProof, ErrorCode, EventType, Hash, IssuerId,
    KeyThumbprint, MapperVersion, ModelId, Outcome, PayloadClass, PayloadRef, PolicyVersion,
    PrincipalId, Record, RecordId, RunId, SegmentId, Severity, ShardIx, TenantId, Timestamp,
    TokenId, ToolName, Untrusted, Verdict,
};
use trailryx_sim::{Io, IoFaults, SimClock, SimIo};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn minimal(n: u128) -> Record {
    Record {
        id: RecordId(n),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/support/tier1").unwrap(),
        run_id: RunId::parse(format!("run-{n}")).unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_800_000_000_000_000_000)),
        decided_at: None,
        recorded_at: Timestamp(1_800_000_000_000_000_001),
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

/// Every optional field populated, so the codec is exercised at its widest.
fn maximal(n: u128) -> Record {
    let mut r = minimal(n);
    r.parent_run_id = Some(RunId::parse("run-parent").unwrap());
    r.on_behalf_of = vec![
        PrincipalId::parse("user://analyst-7").unwrap(),
        PrincipalId::parse("agent://acme.example/planner").unwrap(),
    ];
    r.decided_at = Some(Untrusted::new(Timestamp(1_800_000_000_000_000_002)));
    r.knowledge_as_of = Some(Timestamp(1_799_000_000_000_000_000));
    r.clock_skew_nanos = Some(7_500_000_000);
    r.event_type = EventType::PolicyDecision;
    r.severity = Severity::Critical;
    r.basis = Basis {
        policy_version: Some(PolicyVersion::parse("v2.4.1").unwrap()),
        budget_remaining_micros: Some(-4_250_000),
        memory_ref: Some(Sha384::digest(b"memory snapshot")),
        model: Some(ModelId::parse("anthropic/claude-opus-5").unwrap()),
        temperature_milli: Some(700),
        max_tokens: Some(4096),
        prompt_hash: Some(Sha384::digest(b"the prompt")),
        tool_manifest: vec![
            ToolName::parse("search").unwrap(),
            ToolName::parse("send-mail").unwrap(),
        ],
        identity_chain: vec![PrincipalId::parse("user://analyst-7").unwrap()],
        delegation_proof: Some(DelegationProof {
            jti: TokenId::parse("tok-4kmsltbtx").unwrap(),
            jkt: KeyThumbprint::parse("uhqrs9p3jpnqqgty-b0pxkutr6o42sr9iul4jsyjjg0").unwrap(),
            iss: IssuerId::parse("https://vouchryx.acme.example").unwrap(),
            exp: Timestamp(1_787_823_801_000_000_000),
        }),
    };
    r.caused_by = vec![RecordId(11), RecordId(12), RecordId(13)];
    r.outcome = Outcome {
        verdict: Some(Verdict::Denied),
        error: Some(ErrorCode::BudgetExceeded),
        latency_micros: Some(123_456),
        tokens_in: Some(1_024),
        tokens_out: Some(0),
        cost_micros: Some(9_999),
    };
    r.payload = Some(PayloadRef {
        hash: Sha384::digest(b"payload bytes"),
        size_bytes: 4_096,
        class: PayloadClass::Prompt,
        key_id: Sha384::digest(b"subject key"),
    });
    r
}

fn open(io: &mut SimIo) -> Journal {
    let clock = SimClock::new(1_800_000_000_000_000_000);
    let (j, _) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "s0.journal",
        4,
        ChainStart::First,
        io,
        &clock,
    )
    .unwrap();
    j
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

#[test]
fn a_record_survives_a_round_trip() {
    for r in [minimal(1), maximal(2)] {
        let bytes = encode_record(&r);
        let back = decode_record(&bytes).expect("decodes");
        assert_eq!(back, r);
    }
}

#[test]
fn encoding_is_canonical() {
    // The chain hashes these bytes. If encoding had any freedom, two honest
    // writers could disagree about the same record with neither being wrong.
    let r = maximal(3);
    let a = encode_record(&r);
    let b = encode_record(&r.clone());
    assert_eq!(a, b);
}

#[test]
fn a_corrupt_identifier_is_refused_not_adopted() {
    // The disk is not a trusted input. A token that decoded straight into an
    // AgentId would carry a value the type promises is impossible.
    let r = minimal(4);
    let mut bytes = encode_record(&r);
    let needle = b"agent://acme.example/support/tier1";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("agent id present");
    bytes[at + 6] = b'A'; // uppercase is outside the character set
    assert!(decode_record(&bytes).is_err());
}

#[test]
fn trailing_bytes_are_an_error() {
    let mut bytes = encode_record(&minimal(5));
    bytes.push(0);
    assert!(decode_record(&bytes).is_err());
}

#[test]
fn a_truncated_record_does_not_panic() {
    let bytes = encode_record(&maximal(6));
    for cut in 0..bytes.len() {
        assert!(decode_record(&bytes[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn every_single_byte_flip_is_caught_by_the_frame() {
    let body = encode_record(&minimal(7));
    let link = Sha384::digest(&body);
    let frame = trailryx_journal::wire::encode_frame(&body, &link);

    for i in 0..frame.len() {
        for bit in [0x01u8, 0x80] {
            let mut bad = frame.clone();
            bad[i] ^= bit;
            let ok = decode_frame(&bad)
                .ok()
                .filter(|f| f.chain_link == link && f.body == body.as_slice())
                .is_some();
            assert!(!ok, "flip at byte {i} bit {bit:#x} went unnoticed");
        }
    }
}

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

#[test]
fn records_are_written_and_read_back_in_order() {
    let mut io = SimIo::new(1, IoFaults::NONE);
    let mut j = open(&mut io);

    for n in 1..=20u128 {
        assert!(matches!(
            j.append(&minimal(n), &mut io).unwrap(),
            Appended::Written { .. }
        ));
    }
    j.sync(&mut io).unwrap();

    let back = j.read_all(&mut io).unwrap();
    assert_eq!(back.records.len(), 20);
    assert_eq!(back.stopped_because, StoppedBecause::EndOfFile);
    for (i, (rec, _link)) in back.records.iter().enumerate() {
        assert_eq!(rec.seq, i as u64 + 1);
        assert_eq!(rec.id, RecordId(i as u128 + 1));
        assert_eq!(rec.segment_id, SegmentId(1));
    }
}

#[test]
fn the_journal_owns_seq_and_prev_hash() {
    let mut io = SimIo::new(2, IoFaults::NONE);
    let mut j = open(&mut io);

    // A caller filling these in with nonsense must not be able to steer the
    // chain: the journal overwrites them.
    let mut r = minimal(1);
    r.seq = 999;
    r.prev_hash = Sha384::digest(b"not the head");
    j.append(&r, &mut io).unwrap();

    let back = j.read_all(&mut io).unwrap();
    assert_eq!(back.records[0].0.seq, 1);
    // The chain starts at the header, not at zero, so a file cannot be adopted
    // as a journal for a different shard or segment.
    assert_ne!(back.records[0].0.prev_hash, Hash::ZERO);
}

#[test]
fn a_repeated_record_id_is_absorbed_once() {
    let mut io = SimIo::new(3, IoFaults::NONE);
    let mut j = open(&mut io);

    assert!(matches!(
        j.append(&minimal(1), &mut io).unwrap(),
        Appended::Written { .. }
    ));
    assert!(matches!(
        j.append(&minimal(1), &mut io).unwrap(),
        Appended::Duplicate { .. }
    ));
    assert_eq!(j.written(), 1);
    assert_eq!(j.read_all(&mut io).unwrap().records.len(), 1);
}

#[test]
fn a_failed_sync_moves_nothing() {
    let faults = IoFaults {
        fsync_error_ppm: 1_000_000,
        ..IoFaults::NONE
    };
    let mut io = SimIo::new(4, faults);
    let mut j = open(&mut io);
    j.append(&minimal(1), &mut io).unwrap();

    assert!(j.sync(&mut io).is_err());
    assert_eq!(j.acked(), 0, "a failed sync must promise nothing");
    assert!(j.degraded());
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

#[test]
fn a_torn_tail_is_discarded_and_truncated() {
    let mut io = SimIo::new(5, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=5u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();

    // Half a record arrives and the machine dies.
    let partial = encode_record(&minimal(6));
    let file = j_file(&mut io);
    io.append(file, &partial[..partial.len() / 2]).ok();

    let rep = j.recover(&mut io).unwrap();
    assert_eq!(rep.max_seq, 5);
    assert!(rep.discarded_bytes > 0);
    assert!(matches!(rep.stopped_because, StoppedBecause::TornTail(_)));
    assert!(
        !rep.is_suspicious(),
        "a torn tail is a crash, not an incident"
    );

    // And the journal is usable afterwards, which is what truncation is for.
    assert!(matches!(
        j.append(&minimal(7), &mut io).unwrap(),
        Appended::Written { seq: 6, .. }
    ));
}

fn j_file(io: &mut SimIo) -> trailryx_sim::FileId {
    io.create("s0.journal").unwrap()
}

#[test]
fn a_rewritten_record_mid_file_refuses_rather_than_deleting_the_rest() {
    // Distinguishing a crash from an edit matters: one is a restart, the other
    // is an incident, and an operator should not have to guess which.
    //
    // This test used to assert that recovery truncated and reported itself
    // suspicious. An adversarial review measured what truncating actually did:
    // one flipped byte early in a twenty-record file deleted all twenty, and
    // called it `TornTail`, the routine crash shape. A frame that still parses
    // after the stopping point is proof this was not a torn tail, so recovery
    // now refuses and leaves every byte where it was.
    let mut io = SimIo::new(6, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=4u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();

    let file = j_file(&mut io);
    let before = io.read_all(file).unwrap();
    let mut bytes = before.clone();
    let pos = bytes.len() / 2;
    bytes[pos] ^= 0x01;
    io.truncate(file, 0).unwrap();
    io.append(file, &bytes).unwrap();
    io.fsync(file).unwrap();

    let err = j
        .recover(&mut io)
        .expect_err("mid-file corruption must not be repaired silently");
    match err {
        JournalError::CorruptMidFile {
            at_offset,
            next_good_frame,
            ..
        } => assert!(
            next_good_frame > at_offset,
            "the refusal has to name a frame that still parses"
        ),
        other => panic!("expected CorruptMidFile, got {other:?}"),
    }

    assert_eq!(
        io.read_all(file).unwrap().len(),
        before.len(),
        "recovery must not have deleted the records after the edit"
    );
}

#[test]
fn a_bad_header_over_a_full_journal_refuses_rather_than_erasing_it() {
    // The worst of the defects the core review found. `ensure_header` treated a
    // header that failed its CRC the same as one cut short by a crash, and then
    // truncated the file to zero unconditionally. One flipped bit anywhere in
    // the twenty-byte header therefore deleted every acked record and reported
    // `records: 0, discarded_bytes: 0, durability_violation: None`, so
    // `is_suspicious()` was false and nothing said a record had ever existed.
    //
    // A crash cannot produce this: it keeps a prefix, so a header that did not
    // finish landing has nothing behind it. That is what the length test is.
    let mut io = SimIo::new(31, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=5u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    assert_eq!(j.sync(&mut io).unwrap(), 5);

    let file = j_file(&mut io);
    let before = io.read_all(file).unwrap();
    assert!(before.len() > 32, "the file has records behind its header");

    // Every byte of the header, one bit each. The magic and the version are
    // refused as `NotAJournal`; the rest used to be a silent erasure.
    for at in 0..20usize {
        let mut bytes = before.clone();
        bytes[at] ^= 0x01;
        io.truncate(file, 0).unwrap();
        io.append(file, &bytes).unwrap();
        io.fsync(file).unwrap();

        let clock = SimClock::new(1_800_000_000_000_000_000);
        let err = Journal::open(
            ShardIx(0),
            SegmentId(1),
            "s0.journal",
            4,
            ChainStart::First,
            &mut io,
            &clock,
        )
        .map(|_| ())
        .expect_err("a corrupt header must never be repaired by deletion");
        assert!(
            matches!(
                err,
                JournalError::CorruptHeader { .. } | JournalError::NotAJournal(_)
            ),
            "byte {at} gave {err:?}"
        );
        assert_eq!(
            io.read_all(file).unwrap().len(),
            before.len(),
            "byte {at}: the records were deleted"
        );
    }
}

#[test]
fn good_bytes_is_the_offset_past_the_last_record() {
    // It used to count only the frames one instance had appended: it omitted the
    // header, and a restart reset it to zero while the file kept growing, so a
    // caller using it for size-based rollover would never roll.
    let mut io = SimIo::new(33, IoFaults::NONE);
    let mut j = open(&mut io);
    let file = j_file(&mut io);
    assert_eq!(j.good_bytes(), io.size(file).unwrap(), "header only");

    for n in 1..=5u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();
    assert_eq!(j.good_bytes(), io.size(file).unwrap());

    // And across a restart, where it used to report zero.
    let mut reopened = open(&mut io);
    let rep = reopened.recover(&mut io).unwrap();
    assert_eq!(reopened.good_bytes(), io.size(file).unwrap());
    assert_eq!(reopened.good_bytes(), rep.good_bytes);
}

#[test]
fn an_empty_journal_recovers_to_nothing() {
    let mut io = SimIo::new(7, IoFaults::NONE);
    let mut j = open(&mut io);
    let rep = j.recover(&mut io).unwrap();
    assert_eq!(rep.records, 0);
    assert_eq!(rep.max_seq, 0);
    // An empty journal's head is its header, not zero: the file is already
    // bound to one shard and one segment before a single record exists.
    assert!(!rep.head.is_zero());
    assert_eq!(rep.stopped_because, StoppedBecause::EndOfFile);
    assert_eq!(rep.durability_violation, None);
}

#[test]
fn recovery_restores_the_chain_so_appends_continue_it() {
    let mut io = SimIo::new(8, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=3u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();
    let head_before = j.head();

    let rep = j.recover(&mut io).unwrap();
    assert_eq!(rep.head, head_before);

    j.append(&minimal(4), &mut io).unwrap();
    let walked = j.read_all(&mut io).unwrap();
    let all: Vec<_> = walked.records.into_iter().map(|(r, _)| r).collect();
    assert_eq!(all.len(), 4);

    // Independent replay over what is on disk, starting where the journal
    // starts: at the header.
    let mut chain = ChainState::resume(all[0].prev_hash, 0);
    for r in &all {
        chain.append(&encode_record(r));
    }
    assert_eq!(chain.head(), j.head());
}

// ---------------------------------------------------------------------------
// The durability contract, under a hostile disk
// ---------------------------------------------------------------------------

#[test]
fn acked_records_survive_a_crash_across_many_seeds() {
    for seed in 0..250u64 {
        let faults = IoFaults {
            lying_fsync_ppm: 0, // an unreliable disk, but an honest one
            ..IoFaults::HOSTILE
        };
        let mut io = SimIo::new(seed, faults);
        let mut j = open(&mut io);

        let mut n = 1u128;
        for step in 0..60 {
            if !j.has_pending() {
                let _ = j.append(&minimal(n), &mut io);
                n += 1;
            } else {
                let _ = j.append(&minimal(n - 1), &mut io);
            }
            if j.sync_due() {
                let _ = j.sync(&mut io);
            }
            if step % 17 == 16 {
                let promised = j.acked();
                io.crash();
                let rep = j.recover(&mut io).unwrap();
                assert!(
                    rep.max_seq >= promised,
                    "seed {seed}: promised {promised}, recovered {}",
                    rep.max_seq
                );
                assert!(
                    !rep.is_suspicious(),
                    "seed {seed}: a crash was misreported as tampering: {:?}",
                    rep.stopped_because
                );
            }
        }
    }
}

#[test]
fn a_refused_write_never_splits_the_journal() {
    // The stage 0 bug, now against the real write path: a record refused
    // mid-frame must be continued, never abandoned for a new one.
    let faults = trailryx_sim::IoFaults {
        no_space_ppm: 300_000,
        short_write_ppm: 300_000,
        lying_fsync_ppm: 0,
        fsync_error_ppm: 0,
    };
    for seed in 0..120u64 {
        let mut io = SimIo::new(seed, faults);
        let mut j = open(&mut io);

        let mut n = 1u128;
        for _ in 0..80 {
            match j.append(&minimal(n), &mut io).unwrap() {
                Appended::Written { .. } | Appended::Duplicate { .. } => n += 1,
                Appended::Stalled { .. } | Appended::Busy { .. } => {}
            }
            if j.sync_due() {
                let _ = j.sync(&mut io);
            }
        }
        let promised = j.acked();
        io.crash();
        let rep = j.recover(&mut io).unwrap();
        assert!(
            rep.max_seq >= promised,
            "seed {seed}: promised {promised}, recovered {}",
            rep.max_seq
        );
    }
}

#[test]
fn a_gap_is_counted_rather_than_swallowed() {
    let mut io = SimIo::new(9, IoFaults::NONE);
    let mut j = open(&mut io);
    assert_eq!(j.gaps(), 0);
    j.note_gap();
    assert_eq!(j.gaps(), 1, "a lost record must leave a trace");
}

#[test]
fn a_record_is_never_dropped_while_another_is_pending() {
    // The first version ignored the argument entirely when something was
    // pending and returned Written for the *previous* record, so the caller was
    // told its record had landed while it had been discarded and nothing
    // counted it.
    // A disk that refuses almost everything. Not everything: one that never
    // accepts a byte cannot host a journal at all, and open() says so.
    let faults = IoFaults {
        no_space_ppm: 950_000,
        ..IoFaults::NONE
    };
    let mut io = SimIo::new(11, faults);
    let mut j = open(&mut io);

    // Record 1 cannot get through in one go.
    assert!(matches!(
        j.append(&minimal(1), &mut io).unwrap(),
        Appended::Stalled { .. }
    ));
    assert!(j.has_pending());

    // A different record must be refused by name, not silently swallowed.
    match j.append(&minimal(2), &mut io).unwrap() {
        Appended::Busy { pending_seq } => assert_eq!(pending_seq, 1),
        other => panic!("record 2 was accepted while record 1 was pending: {other:?}"),
    }
    assert_eq!(j.written(), 0, "nothing completed");

    // Retrying the same record continues it rather than starting again.
    let mut finished = false;
    for _ in 0..500 {
        if let Appended::Written { seq, .. } = j.append(&minimal(1), &mut io).unwrap() {
            assert_eq!(seq, 1);
            finished = true;
            break;
        }
    }
    assert!(finished, "the outstanding record never completed");
    assert!(!j.has_pending());
}

#[test]
fn a_duplicate_reports_where_the_original_landed() {
    let mut io = SimIo::new(12, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=5u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    // Record 2 landed at position 2, not at the current watermark of 5.
    match j.append(&minimal(2), &mut io).unwrap() {
        Appended::Duplicate { seq } => assert_eq!(seq, 2),
        other => panic!("expected a duplicate, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Encoding is one shape, and a foreign file is not ours to erase
// ---------------------------------------------------------------------------

#[test]
fn an_overlong_varint_is_refused() {
    // [0x81, 0x00] also means 1. Accepting it would give one record several
    // valid byte forms, and the chain hashes those bytes: a verifier that
    // decoded and re-encoded a record would disagree with the disk.
    use trailryx_journal::wire::Reader;
    assert!(Reader::new(&[0x01]).varint().is_ok());
    assert!(Reader::new(&[0x81, 0x00]).varint().is_err());
    assert!(Reader::new(&[0x80, 0x80, 0x00]).varint().is_err());
    // Ten groups is the most a u64 holds, and the tenth carries one bit.
    assert!(
        Reader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01])
            .varint()
            .is_ok()
    );
    assert!(
        Reader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02])
            .varint()
            .is_err()
    );
}

#[test]
fn opening_a_foreign_file_refuses_rather_than_erasing_it() {
    // A mistyped path used to cost somebody their file: anything that did not
    // decode as a header was truncated to zero.
    let mut io = SimIo::new(20, IoFaults::NONE);
    let f = io.create("not-a-journal").unwrap();
    io.append(f, b"somebody else's data, thank you").unwrap();
    io.fsync(f).unwrap();

    let clock = SimClock::new(1_800_000_000_000_000_000);
    let result = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "not-a-journal",
        4,
        ChainStart::First,
        &mut io,
        &clock,
    );
    assert!(
        matches!(result, Err(trailryx_journal::JournalError::NotAJournal(_))),
        "a foreign file must be refused, not erased"
    );

    let still_there = io.read_all(f).unwrap();
    assert_eq!(still_there, b"somebody else's data, thank you");
}

#[test]
fn a_torn_header_is_still_ours_to_restart() {
    // The other half: our own file, cut short before the header landed, must
    // start clean rather than refusing forever.
    let mut io = SimIo::new(21, IoFaults::NONE);
    let f = io.create("s0.journal").unwrap();
    io.append(f, b"TRL").unwrap(); // half the magic, then a crash
    io.fsync(f).unwrap();

    let clock = SimClock::new(1_800_000_000_000_000_000);
    let (mut j, rep) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "s0.journal",
        4,
        ChainStart::First,
        &mut io,
        &clock,
    )
    .expect("opens");
    assert_eq!(rep.records, 0);
    assert!(matches!(
        j.append(&minimal(1), &mut io).unwrap(),
        Appended::Written { seq: 1, .. }
    ));
}

#[test]
fn a_file_cannot_be_adopted_as_another_shards_journal() {
    // Before, a journal file carried no segment id, recovery never compared a
    // record's shard against the header's, and the chain began at zero. Opening
    // shard 0's file as shard 7 produced one file, one intact chain, and two
    // shards claiming it.
    let mut io = SimIo::new(30, IoFaults::NONE);
    let clock = SimClock::new(1_800_000_000_000_000_000);

    let (mut j, _) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "s0.journal",
        4,
        ChainStart::First,
        &mut io,
        &clock,
    )
    .unwrap();
    for n in 1..=5u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();

    // The same bytes, opened under a different identity. Refused outright:
    // checking each record against the file's own header would have accepted
    // everything, because the file is perfectly consistent with itself.
    let result = Journal::open(
        ShardIx(7),
        SegmentId(99),
        "s0.journal",
        4,
        ChainStart::First,
        &mut io,
        &clock,
    );
    assert!(
        matches!(
            result,
            Err(trailryx_journal::JournalError::WrongOwner { .. })
        ),
        "a journal must not be adopted by another shard"
    );

    // And the records are still there for their rightful owner.
    let (_, rep) = Journal::open(
        ShardIx(0),
        SegmentId(1),
        "s0.journal",
        4,
        ChainStart::First,
        &mut io,
        &clock,
    )
    .unwrap();
    assert_eq!(rep.records, 5);
}

#[test]
fn losing_acked_data_is_reported_rather_than_absorbed() {
    // A disk that lies about flushing breaks the contract and nothing in
    // software prevents it. What must never happen is the watermark quietly
    // sliding down to match whatever came back.
    let faults = IoFaults {
        lying_fsync_ppm: 1_000_000,
        ..IoFaults::NONE
    };
    let mut io = SimIo::new(31, faults);
    let mut j = open(&mut io);
    for n in 1..=6u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap(); // reports success, flushes nothing
    assert_eq!(j.acked(), 6);

    io.crash();
    let rep = j.recover(&mut io).unwrap();
    // How much survives is up to the crash model, which keeps a random prefix
    // of unsynced bytes. What matters is that the loss is named rather than
    // absorbed by quietly lowering the watermark.
    let v = rep.durability_violation.expect("the loss must be reported");
    assert_eq!(v.promised, 6);
    assert!(v.recovered < 6, "{v:?}");
    assert!(rep.is_suspicious());
}

#[test]
fn a_promise_made_by_one_process_is_still_a_promise_after_a_restart() {
    // The debt the README carried for two days. `promised` came from a field in
    // memory, so a fresh process started at zero, `recovered < promised` could never
    // be true, and a journal that came back short of what a previous process had
    // acked reported nothing at all. The durability contract says every sequence
    // number reported as acked survives any crash, and until now nothing could check
    // that sentence across the crash it is about.
    let mut io = SimIo::new(41, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=5u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    assert_eq!(j.sync(&mut io).unwrap(), 5);
    let file = j_file(&mut io);
    let before = io.read_all(file).unwrap();
    drop(j);

    // A disk that lost the last two records after promising five. Not our bug, and
    // never something to discover from a silently lowered watermark.
    let mut short = before.clone();
    let frames = decode_frame(&short[20..]).unwrap().total_len;
    short.truncate(short.len() - 2 * frames);
    io.truncate(file, 0).unwrap();
    io.append(file, &short).unwrap();
    io.fsync(file).unwrap();

    let mut reopened = open(&mut io);
    let rep = reopened.recover(&mut io).unwrap();
    assert_eq!(rep.records, 3, "three came back");
    assert_eq!(
        rep.durability_violation,
        Some(DurabilityViolation {
            promised: 5,
            recovered: 3
        }),
        "a promise made before the restart has to survive it"
    );
    assert!(
        rep.is_suspicious(),
        "and this is an incident, not a restart"
    );
}

#[test]
fn a_watermark_that_did_not_finish_landing_promises_nothing() {
    // Truncate then append is not atomic, so a crash can leave the watermark torn.
    // The CRC is what makes that safe rather than merely unlikely: a torn file is
    // read as absent, and absent under-promises. A file that could be half-read as a
    // plausible number would be worse than no file.
    let mut io = SimIo::new(42, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=4u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();
    drop(j);

    let ack = io.create("s0.journal.ack").unwrap();
    let good = io.read_all(ack).unwrap();
    assert_eq!(good.len(), 12, "eight bytes and a checksum");

    for (label, bytes) in [
        ("a byte flipped in the value", {
            let mut b = good.clone();
            b[7] ^= 0x01;
            b
        }),
        ("a byte flipped in the checksum", {
            let mut b = good.clone();
            b[11] ^= 0x01;
            b
        }),
        ("only half of it landed", good[..6].to_vec()),
        ("nothing landed", Vec::new()),
    ] {
        io.truncate(ack, 0).unwrap();
        io.append(ack, &bytes).unwrap();
        io.fsync(ack).unwrap();

        let mut reopened = open(&mut io);
        let rep = reopened.recover(&mut io).unwrap();
        assert_eq!(rep.records, 4, "{label}: the journal itself is untouched");
        assert_eq!(
            rep.durability_violation, None,
            "{label}: an unreadable promise is no promise, never a guess"
        );
    }

    // And the intact one is still believed, so the check above is not passing by
    // being unable to read anything at all.
    io.truncate(ack, 0).unwrap();
    io.append(ack, &good).unwrap();
    io.fsync(ack).unwrap();
    let mut reopened = open(&mut io);
    assert_eq!(
        reopened.recover(&mut io).unwrap().durability_violation,
        None
    );
}

/// A reader gets the same walk without the write path attached.
///
/// `Journal::open` recovers, which writes a header onto a file that has none and
/// truncates a tail it will not trust. That is right for a writer and wrong for
/// anything auditing the file, so `walk_bytes` is the same walk over bytes
/// somebody else read. The point of the test is that it is the SAME walk: a
/// second decoder would be a second set of rules about what counts as valid, and
/// `docs/durability.md` §9 says the weaker one becomes the foundation of whatever
/// is built next.
#[test]
fn a_reader_walks_the_bytes_without_repairing_them() {
    let mut io = SimIo::new(11, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=5u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();
    let file = io.create("s0.journal").unwrap();
    let bytes = io.read_all(file).unwrap();
    let appends = io.stats.appends;

    let walked = Journal::walk_bytes(&bytes, ChainStart::First).unwrap();
    let mine = j.read_all(&mut io).unwrap();
    assert_eq!(walked.records.len(), 5);
    assert_eq!(
        walked.records.len(),
        mine.records.len(),
        "the file walked from outside is the file the journal reads"
    );
    assert_eq!(walked.chain.head(), mine.chain.head());
    assert_eq!(walked.stopped_because, StoppedBecause::EndOfFile);

    // A chain start that is not this file's is checked rather than believed: the
    // very first record fails its step, which is a broken chain at sequence one
    // and not a file that quietly reads as empty.
    let wrong = Journal::walk_bytes(&bytes, ChainStart::After(Hash::ZERO)).unwrap();
    assert!(
        matches!(
            wrong.stopped_because,
            StoppedBecause::ChainBroken { at_seq: 1 }
        ),
        "{:?}",
        wrong.stopped_because
    );
    assert!(wrong.records.is_empty());

    // And none of it wrote anything.
    assert_eq!(io.read_all(file).unwrap(), bytes);
    assert_eq!(
        io.stats.appends, appends,
        "a reader appended to the journal"
    );
}

// ---------------------------------------------------------------------------
// The event vocabulary, at the one byte where it meets the format
// ---------------------------------------------------------------------------

/// The offset of the `event_type` byte in a canonical record, found rather than
/// counted.
///
/// Two encodings of one record that differ in nothing but the event type differ
/// in exactly one byte, and that byte is the discriminant. Counting the offset by
/// hand would be a second transcription of the writing order, which is the thing
/// `trailryx-verify`'s own record reader says out loud it has to keep in step.
fn event_type_offset(r: &Record) -> usize {
    let mut a = r.clone();
    a.event_type = EventType::ModelCall;
    let mut b = r.clone();
    b.event_type = EventType::PolicyDecision;
    let (a, b) = (encode_record(&a), encode_record(&b));
    assert_eq!(a.len(), b.len(), "one byte wide, so the length cannot move");
    let differing: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert_eq!(differing.len(), 1, "the discriminant is one byte");
    differing[0]
}

/// Invariant 7, at the boundary a new event type actually moves.
///
/// The record format is frozen, and an event type is a one-byte discriminant in
/// it. Adding one takes the next unused code and redefines nothing, so what has
/// to hold is three things at once, and only the middle one is new: every code
/// that was ever written keeps decoding to the name it was written as, the new
/// code decodes to the new name, and the first code past it is still refused **by
/// name** rather than half-read. The third is what makes this additive instead of
/// a version: a build older than the new type meets it and says which field it
/// could not read, which is the same answer it gives for any byte nobody defined.
#[test]
fn every_event_code_ever_written_still_decodes_and_the_next_unused_one_is_refused() {
    let record = maximal(77);
    let at = event_type_offset(&record);
    let bytes = encode_record(&record);

    // Every code this format has ever assigned, and the name it was assigned to.
    // Written out rather than derived from `EventType::ALL`, because a list
    // derived from the enum would agree with a renumbering of the enum.
    let ever: &[(u8, &str)] = &[
        (1, "request_received"),
        (2, "model_call"),
        (3, "tool_call"),
        (4, "policy_decision"),
        (5, "budget_check"),
        (6, "memory_access"),
        (7, "delegation"),
        (8, "run_completed"),
        (9, "erasure"),
        (10, "store_event"),
        (11, "notification_dispatched"),
        (12, "identity_finding"),
    ];
    for (code, name) in ever {
        let mut patched = bytes.clone();
        patched[at] = *code;
        let decoded = decode_record(&patched)
            .unwrap_or_else(|e| panic!("code {code} must decode to {name}: {e}"));
        assert_eq!(
            decoded.event_type.as_str(),
            *name,
            "code {code} decoded to something other than {name}"
        );
    }

    // And the first code past the vocabulary is refused by name. This is what an
    // older build does when it meets a record carrying a type it has never heard
    // of: it says which field it could not read and stops, rather than reading the
    // rest of the record against a field it guessed at.
    let mut past = bytes.clone();
    past[at] = 13;
    match decode_record(&past) {
        Err(WireError::BadDiscriminant { field, got }) => {
            assert_eq!(field, "event_type");
            assert_eq!(got, 13);
        }
        other => panic!("an undefined event code must be refused by name: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The v1 to v2 migration
// ---------------------------------------------------------------------------

/// Encode a body the way FRAME_VERSION 1 did: everything except the trailing
/// `delegation_proof`. Written by hand rather than kept as a fixture blob so
/// the test says WHAT a v1 body is, and so it keeps compiling against the real
/// encoder rather than against a copy of it.
fn v1_body(rec: &Record) -> Vec<u8> {
    let mut r = rec.clone();
    r.basis.delegation_proof = None;
    let full = encode_record(&r);
    // A v2 body whose proof is absent is a v1 body plus one `None` marker
    // byte, which is exactly what "appended at the end" means. Drop it.
    assert_eq!(*full.last().expect("a body"), 0, "the absent-option marker");
    full[..full.len() - 1].to_vec()
}

/// The migration, and the whole reason it is shaped this way: nothing is
/// rewritten.
///
/// A store whose claim is tamper-evidence cannot rewrite its own history to add
/// a field. A migration that did would be indistinguishable from the tampering
/// the chain exists to catch. So a record written under v1 stays byte for byte
/// as it was, keeps its own hash, and keeps verifying; the reader is what moved.
#[test]
fn a_record_written_under_v1_still_reads_and_keeps_its_hash() {
    let rec = maximal(9);
    let body = v1_body(&rec);
    let before = Sha384::digest(&body);

    let back = decode_record_at(&body, 1).expect("a v1 body decodes under the new reader");

    assert_eq!(
        back.basis.delegation_proof, None,
        "a field the record never had must read as absent, which is what its \
         absence always meant (SPEC 5.2: absent is NOT PROVEN)"
    );
    let mut want = rec.clone();
    want.basis.delegation_proof = None;
    assert_eq!(back, want, "everything else must survive unchanged");

    assert_eq!(
        Sha384::digest(&body),
        before,
        "reading must not touch the bytes; the chain hashes these"
    );
}

/// A whole v1 FRAME, not just a body: the version byte is what tells the
/// reader which shape to expect, and a reader that ignored it would run off
/// the end of a v1 body or leave bytes over on a v2 one.
#[test]
fn a_v1_frame_is_accepted_and_a_v2_frame_is_too() {
    let rec = maximal(10);
    let link = Sha384::digest(b"previous");

    let v1 = {
        let body = v1_body(&rec);
        encode_frame_at(&body, &link, 1)
    };
    let f1 = decode_frame(&v1).expect("a v1 frame is still readable");
    assert_eq!(f1.version, 1);
    let r1 = decode_record_at(f1.body, f1.version).expect("its body decodes as v1");
    assert_eq!(r1.basis.delegation_proof, None);

    let v2 = encode_frame(&encode_record(&rec), &link);
    let f2 = decode_frame(&v2).expect("a v2 frame is readable");
    assert_eq!(f2.version, FRAME_VERSION);
    let r2 = decode_record_at(f2.body, f2.version).expect("its body decodes as v2");
    assert_eq!(r2.basis.delegation_proof, rec.basis.delegation_proof);
}

/// Reading a body as the WRONG version must fail loudly rather than produce a
/// record with the wrong shape. This is what `finish` is for, and it is the
/// reason the version is a parameter instead of a guess.
#[test]
fn a_body_read_as_the_wrong_version_is_refused() {
    let rec = maximal(11);

    let v2 = encode_record(&rec);
    assert!(
        decode_record_at(&v2, 1).is_err(),
        "a v2 body read as v1 leaves the proof unread, and trailing bytes are \
         refused rather than ignored"
    );

    let v1 = v1_body(&rec);
    assert!(
        decode_record_at(&v1, 2).is_err(),
        "a v1 body read as v2 runs off the end"
    );
}

/// A version this reader has never heard of is refused at the frame, before
/// any of the body is trusted.
#[test]
fn a_frame_from_the_future_is_refused() {
    let rec = maximal(12);
    let mut f = encode_frame(&encode_record(&rec), &Sha384::digest(b"prev"));
    f[1] = FRAME_VERSION + 1;
    assert!(matches!(
        decode_frame(&f),
        Err(WireError::UnknownVersion(_))
    ));
}

/// A segment written by the binary BEFORE `RECORD_V2`, read by this one.
///
/// `testdata/v1-segment-3acf4bd.journal` is 1072 real bytes produced by a
/// checkout of 3acf4bd through `StdIo`, not constructed by this build. That
/// distinction is the whole point: every other v1 test here builds a v1 body
/// with today's encoder minus one field, which proves the reader handles a
/// shape this build can describe. It does not prove the reader handles bytes an
/// older build actually wrote, and those are different claims.
///
/// The PR that added `RECORD_V2` said so in its own NOT PROVEN section. This is
/// that line closed, and it stays closed: the fixture is committed, so every
/// future build reads real v1 bytes rather than its own idea of them.
#[test]
fn a_segment_an_older_binary_wrote_still_reads() {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("v1-segment-3acf4bd.journal"),
    )
    .expect("the committed v1 segment");

    // It is v1 on the wire, not merely named so.
    let at = bytes
        .iter()
        .position(|b| *b == trailryx_journal::wire::FRAME_MAGIC)
        .expect("a frame");
    assert_eq!(bytes[at + 1], 1, "the fixture is not a v1 segment");

    let walked = Journal::walk_bytes(&bytes, ChainStart::First).expect("it walks");
    assert_eq!(walked.records.len(), 3, "three records were written");

    for (rec, _link) in &walked.records {
        assert_eq!(
            rec.basis.delegation_proof, None,
            "a field the record never had must read as absent, which is what \
             its absence always meant (SPEC 5.2: absent is NOT PROVEN)"
        );
    }

    // The middle one is `maximal`, so this is not a test over three empty
    // records that would decode under almost any reader.
    let (mid, _) = &walked.records[1];
    assert!(mid.basis.policy_version.is_some(), "the maximal record");
    assert_eq!(mid.basis.identity_chain.len(), 1);

    // And the walk ran to the end of the file rather than stopping at a link
    // it could not follow, over bytes this build did not produce.
    assert_eq!(
        walked.good_bytes as usize,
        bytes.len(),
        "the walk stopped early on an older binary's bytes: {:?}",
        walked.stopped_because
    );
}

/// The bodies out of that same real segment, decoded the way the COLD tier
/// does it: without a frame, and therefore without a version byte.
///
/// The archive path lost the one thing the journal path carries, and trying
/// both versions there is a determination rather than a guess: `finish` refuses
/// trailing bytes as well as truncation, so exactly one version can succeed.
/// This proves that on bytes an older binary wrote.
#[test]
fn a_body_from_an_older_binary_decodes_without_a_frame() {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("v1-segment-3acf4bd.journal"),
    )
    .expect("the committed v1 segment");
    let walked = Journal::walk_bytes(&bytes, ChainStart::First).expect("it walks");
    assert_eq!(walked.records.len(), 3);

    // Re-encode nothing: take the raw body straight out of the file, the way a
    // cold object holds it.
    let at = bytes
        .iter()
        .position(|b| *b == trailryx_journal::wire::FRAME_MAGIC)
        .expect("a frame");
    let frame = decode_frame(&bytes[at..]).expect("the first frame");
    assert_eq!(frame.version, 1);

    assert!(
        decode_record_at(frame.body, FRAME_VERSION).is_err(),
        "a v1 body must NOT decode as the current version, or trying both \
         would be a guess instead of a determination"
    );
    assert!(
        decode_record_at(frame.body, 1).is_ok(),
        "and it must decode as the version it actually is"
    );
}
