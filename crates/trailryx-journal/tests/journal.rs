//! The journal against the fault-injecting simulator from stage 0.
//!
//! The skeleton that stood in for a journal is gone; these are the real write
//! path and the real recovery, and the same crash model is pointed at them.

use trailryx_crypto::{ChainState, Sha384};
use trailryx_journal::journal::{Appended, ChainStart, Journal, StoppedBecause};
use trailryx_journal::wire::{decode_frame, decode_record, encode_record};
use trailryx_record::{
    AgentId, Algorithms, Basis, ErrorCode, EventType, Hash, MapperVersion, ModelId, Outcome,
    PayloadClass, PayloadRef, PolicyVersion, PrincipalId, Record, RecordId, RunId, SegmentId,
    Severity, ShardIx, TenantId, Timestamp, ToolName, Untrusted, Verdict,
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
fn a_rewritten_record_is_reported_as_suspicious() {
    // Distinguishing a crash from an edit matters: one is a restart, the other
    // is an incident, and an operator should not have to guess which.
    let mut io = SimIo::new(6, IoFaults::NONE);
    let mut j = open(&mut io);
    for n in 1..=4u128 {
        j.append(&minimal(n), &mut io).unwrap();
    }
    j.sync(&mut io).unwrap();

    let file = j_file(&mut io);
    let mut bytes = io.read_all(file).unwrap();
    // Flip a byte inside the third record's body and repair its CRC, so the
    // frame reads cleanly and only the chain notices.
    let pos = bytes.len() / 2;
    bytes[pos] ^= 0x01;
    io.truncate(file, 0).unwrap();
    io.append(file, &bytes).unwrap();
    io.fsync(file).unwrap();

    let rep = j.recover(&mut io).unwrap();
    assert!(rep.max_seq < 4);
    assert!(rep.discarded_bytes > 0);
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
