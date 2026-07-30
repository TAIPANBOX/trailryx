//! The pack the store writes, checked by the verifier that shares no code with it.
//!
//! This is the only place the two meet, and they meet through bytes. Every
//! tamper below is a thing somebody would do to a pack between the store and
//! the auditor, and the assertion is always that the verifier notices and names
//! what it noticed.

use trailryx_crypto::{Sha384, chain_step};

/// A plausible place for a shard's first chain to begin.
///
/// Not `Hash::ZERO`: a journal derives its first segment's start from the file's
/// own header, so zero is a value no journal produces and the verifier now says
/// so. These fixtures build segments by hand and have to look like something a
/// journal made.
fn genesis() -> Hash {
    Sha384::digest(b"trailryx-test/segment-genesis")
}
use trailryx_index::segment::{Segment, SegmentManifest, ShardTree, StoreTree};
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, SigAlg, TenantId, Timestamp, Untrusted,
};
use trailryx_sign::RootSignature;
use trailryx_store::evidence::PackBuilder;
use trailryx_verify::{Level, verify};

fn record(id: u128, shard: u16, seq: u64, agent: &str, run: &str, at: u64) -> Record {
    Record {
        id: RecordId(id),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(shard),
        agent_id: AgentId::parse(agent).unwrap(),
        run_id: RunId::parse(run).unwrap(),
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
        seq,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

/// Seal one segment, chaining from `before`, and give back the segment.
fn seal(segment: u64, shard: u16, before: Hash, records: &[Record]) -> Segment {
    let mut link = before;
    let leaves: Vec<(Record, Hash)> = records
        .iter()
        .map(|r| {
            link = chain_step(link, r.seq, &encode_record(r));
            (r.clone(), link)
        })
        .collect();
    Segment::seal(SegmentId(segment), ShardIx(shard), before, &leaves).unwrap()
}

struct Store {
    shard0: Vec<Segment>,
    shard1: Vec<Segment>,
}

/// Two shards, one of them with two segments, so the cross-segment chain and
/// the shard tree both have something to be wrong about.
fn store() -> Store {
    let a = seal(
        1,
        0,
        genesis(),
        &[
            record(1, 0, 1, "agent://acme.example/billing", "run-a", 1_000),
            record(2, 0, 2, "agent://acme.example/billing", "run-a", 1_010),
            record(3, 0, 3, "agent://acme.example/support", "run-b", 1_020),
        ],
    );
    // Segment two numbers its records from one, because one segment is one
    // journal file and a journal numbers each file from one. This fixture used
    // to say 4 and 5, continuing shard 0's count across the file boundary, and
    // no writer in the tree produces that. The offline verifier now checks the
    // sequence for contiguity rather than merely for increase, and a fixture
    // that cannot occur is a fixture that tests nothing.
    let b = seal(
        2,
        0,
        a.manifest().chain_after,
        &[
            record(4, 0, 1, "agent://acme.example/support", "run-b", 1_030),
            record(5, 0, 2, "agent://acme.example/billing", "run-c", 1_040),
        ],
    );
    let c = seal(
        1,
        1,
        genesis(),
        &[
            record(6, 1, 1, "agent://acme.example/triage", "run-d", 1_005),
            record(7, 1, 2, "agent://acme.example/triage", "run-d", 1_015),
        ],
    );
    Store {
        shard0: vec![a, b],
        shard1: vec![c],
    }
}

fn pack_of(s: &Store) -> Vec<u8> {
    let mut t0 = ShardTree::new(ShardIx(0));
    for segment in &s.shard0 {
        t0.push(segment.manifest().clone());
    }
    let mut t1 = ShardTree::new(ShardIx(1));
    for segment in &s.shard1 {
        t1.push(segment.manifest().clone());
    }
    let store_tree = StoreTree::from_shards(&[t0.clone(), t1.clone()]);

    PackBuilder::new(TenantId::parse("acme").unwrap(), Timestamp(1_700_000_000))
        .shard(&t0, &s.shard0.iter().collect::<Vec<_>>())
        .shard(&t1, &s.shard1.iter().collect::<Vec<_>>())
        .build(&store_tree)
}

fn broken(bytes: &[u8]) -> Vec<String> {
    let report = verify(bytes).expect("the pack should still parse");
    report
        .findings
        .iter()
        .filter(|f| f.level == Level::Broken)
        .map(|f| f.check.to_owned())
        .collect()
}

/// Replace the first occurrence of `needle`. Panics if it is not there, so a
/// tamper test cannot silently become a test of an untouched pack.
fn tamper(bytes: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len());
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("nothing to tamper with");
    bytes[at..at + needle.len()].copy_from_slice(replacement);
}

#[test]
fn a_pack_from_a_real_store_verifies() {
    let s = store();
    let report = verify(&pack_of(&s)).unwrap();
    assert!(report.verified(), "{:?}", report.findings);
    assert_eq!(report.records_checked, 7);
    assert_eq!(report.segments_checked, 3);
}

#[test]
fn an_unsigned_pack_says_so_rather_than_reporting_a_clean_bill() {
    // A pack with no signature proves it is self-consistent. It does not prove
    // who published it, and the difference is the whole reason an auditor asks.
    let report = verify(&pack_of(&store())).unwrap();
    assert!(report.verified());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "root-signature" && f.level == Level::Weak),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_pack_with_an_algorithm_this_build_cannot_check_says_so() {
    // A pack sealed under something newer must never come back "broken". The
    // verifier says it could not look, which is a different sentence and the
    // only honest one.
    let s = store();
    let mut t0 = ShardTree::new(ShardIx(0));
    for segment in &s.shard0 {
        t0.push(segment.manifest().clone());
    }
    let tree = StoreTree::from_shards(&[t0.clone()]);
    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), Timestamp(1))
        .signed_with(RootSignature {
            algorithm: SigAlg::MlDsa65,
            public_key: vec![1u8; 64],
            signature: vec![7u8; 3309],
        })
        .shard(&t0, &s.shard0.iter().collect::<Vec<_>>())
        .build(&tree);

    let report = verify(&bytes).unwrap();
    assert!(report.verified(), "{:?}", report.findings);
    let finding = report
        .findings
        .iter()
        .find(|f| f.check == "root-signature")
        .unwrap();
    assert_eq!(finding.level, Level::Weak);
    assert!(finding.detail.contains("cannot check"), "{finding}");
}

#[test]
fn a_changed_record_moves_every_root_above_it() {
    // The property that makes the pack worth sending. One byte of one record,
    // and the chain, the history tree and two indexes all disagree.
    let mut bytes = pack_of(&store());
    tamper(
        &mut bytes,
        b"agent://acme.example/support",
        b"agent://acme.example/nowhere",
    );

    let checks = broken(&bytes);
    assert!(
        checks.contains(&"chain-within-segment".to_owned()),
        "{checks:?}"
    );
    assert!(checks.contains(&"history-root".to_owned()), "{checks:?}");
    assert!(checks.contains(&"index-root".to_owned()), "{checks:?}");
}

#[test]
fn a_record_removed_from_a_segment_is_caught() {
    let s = store();
    let full = pack_of(&s);

    let short = Store {
        shard0: vec![
            seal(
                1,
                0,
                genesis(),
                &[
                    record(1, 0, 1, "agent://acme.example/billing", "run-a", 1_000),
                    record(3, 0, 3, "agent://acme.example/support", "run-b", 1_020),
                ],
            ),
            s.shard0[1].clone(),
        ],
        shard1: s.shard1.clone(),
    };
    let bytes = pack_of(&short);
    assert_ne!(bytes, full);

    // The short segment is internally consistent: it was resealed. What it
    // cannot fake is the chain into the segment that follows it.
    let checks = broken(&bytes);
    assert!(
        checks.contains(&"chain-across-segments".to_owned()),
        "a dropped record left the following segment reachable: {checks:?}"
    );
}

#[test]
fn a_whole_segment_removed_is_caught() {
    // Each remaining segment is internally valid. The shard root and the
    // declared segment count are what notice.
    let s = store();
    let mut t0 = ShardTree::new(ShardIx(0));
    for segment in &s.shard0 {
        t0.push(segment.manifest().clone());
    }
    let mut t1 = ShardTree::new(ShardIx(1));
    for segment in &s.shard1 {
        t1.push(segment.manifest().clone());
    }
    let tree = StoreTree::from_shards(&[t0.clone(), t1.clone()]);

    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), Timestamp(1))
        .shard(&t0, &[&s.shard0[0]]) // the second segment simply not handed over
        .shard(&t1, &s.shard1.iter().collect::<Vec<_>>())
        .build(&tree);

    let checks = broken(&bytes);
    assert!(checks.contains(&"shard-root".to_owned()), "{checks:?}");
}

#[test]
fn a_declared_index_root_that_does_not_follow_from_the_records_is_caught() {
    // The check that discharges what the store assumed about itself. Inside the
    // store an index is sorted because the code that built it sorted it. Here
    // the order is rebuilt from the record bytes, by other code, and the root
    // has to come out the same.
    let s = store();
    let mut bytes = pack_of(&s);
    let real = s.shard0[0]
        .manifest()
        .index_roots
        .iter()
        .find(|(d, _)| d.as_str() == "run_id")
        .map(|(_, r)| *r)
        .unwrap();
    tamper(
        &mut bytes,
        real.as_bytes(),
        Sha384::digest(b"a convenient root").as_bytes(),
    );

    let checks = broken(&bytes);
    assert!(checks.contains(&"index-root".to_owned()), "{checks:?}");
}

#[test]
fn a_declared_time_span_that_excludes_a_record_is_caught() {
    // A segment whose declared span misses a query is a segment the store may
    // skip when answering it, and the sealer writes the span.
    let s = store();
    let mut bytes = pack_of(&s);
    let real = s.shard0[0].manifest().last_recorded_at.as_nanos();
    tamper(&mut bytes, &real.to_be_bytes(), &(real - 15).to_be_bytes());

    let checks = broken(&bytes);
    assert!(checks.contains(&"time-span".to_owned()), "{checks:?}");
}

#[test]
fn a_convenient_store_root_is_caught() {
    let mut bytes = pack_of(&store());
    let real = verify(&bytes).unwrap();
    assert!(real.verified());
    // The header's root is the first hash after the tenant and timestamp.
    let at = bytes.windows(4).position(|w| w == b"acme").unwrap() + 4 + 8;
    bytes[at..at + 48].copy_from_slice(Sha384::digest(b"whatever we like").as_bytes());

    let checks = broken(&bytes);
    assert!(checks.contains(&"store-root".to_owned()), "{checks:?}");
}

#[test]
fn records_nothing_accounts_for_are_caught() {
    // A pack may be a subset of a store. It may not carry records no segment
    // describes, because nothing would then check them and a reader would
    // reasonably assume something had.
    let mut bytes = pack_of(&store());
    assert_eq!(bytes.pop(), Some(0), "the pack ends with the end marker");

    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // shard 0
    body.extend_from_slice(&99u64.to_be_bytes()); // a segment nothing describes
    body.extend_from_slice(&1u64.to_be_bytes()); // one record
    body.extend_from_slice(&4u32.to_be_bytes());
    body.extend_from_slice(b"junk");

    bytes.push(4); // a records section
    bytes.extend_from_slice(&(body.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&body);
    bytes.push(0);

    let checks = broken(&bytes);
    assert_eq!(checks, vec!["orphan-records".to_owned()], "{checks:?}");
}

#[test]
fn a_pack_that_is_not_one_is_refused_rather_than_half_read() {
    assert!(verify(b"").is_err());
    assert!(verify(b"not a pack at all").is_err());
    let bytes = pack_of(&store());
    for n in [1usize, 8, 40, 200] {
        assert!(verify(&bytes[..n.min(bytes.len())]).is_err(), "{n}");
    }
}

#[test]
fn the_verifier_and_the_store_agree_on_sha384() {
    // Two implementations, one answer. If they ever diverge, every root in
    // every pack diverges with them, so this is checked directly rather than
    // inferred from a pack that happened to verify.
    for input in [b"".to_vec(), b"abc".to_vec(), vec![0xa5u8; 1000]] {
        assert_eq!(
            Sha384::digest(&input).as_bytes(),
            &trailryx_verify::sha384::Sha384::digest(&input)
        );
    }
}

#[test]
#[ignore = "writes a pack for the binary to read; run explicitly"]
fn write_a_pack_for_the_binary() {
    let path = std::env::var("PACK_OUT").unwrap();
    std::fs::write(path, pack_of(&store())).unwrap();
}

#[test]
fn a_segment_missing_from_an_end_is_caught_by_its_number() {
    // The pairwise chain check sees a hole in the middle of a shard and cannot
    // see one at either end: drop the oldest or the newest segment and every
    // remaining pair still lines up. The numbering is what notices.
    let s = store();
    let mut t0 = ShardTree::new(ShardIx(0));
    for segment in &s.shard0 {
        t0.push(segment.manifest().clone());
    }
    let tree = StoreTree::from_shards(&[t0.clone()]);

    // Only the second segment, so the shard now begins at number two.
    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), Timestamp(1))
        .shard(&t0, &[&s.shard0[1]])
        .build(&tree);

    let checks = broken(&bytes);
    assert!(
        checks.contains(&"segment-numbering".to_owned()),
        "{checks:?}"
    );
}

#[test]
fn what_the_pack_cannot_prove_about_its_own_beginning_is_said_out_loud() {
    // A shard's first segment starts at a head derived from its journal file's
    // header, and the header is not in the pack. So that one value is asserted
    // rather than proved, and a verifier that stayed quiet about it would be
    // overstating what it checked.
    let report = verify(&pack_of(&store())).unwrap();
    let finding = report
        .findings
        .iter()
        .find(|f| f.check == "first-segment-start")
        .expect("the verifier should say so");
    assert_eq!(finding.level, Level::Note);
    assert!(finding.detail.contains("does not prove"), "{finding}");
}

/// A segment section and a records section for a shard the pack does not list.
///
/// Written by hand, in the pack's own wire format, because that is exactly what
/// an intermediary who cannot forge the store root would do.
fn append_segment_for(bytes: &mut Vec<u8>, shard: u16, segment: u64, records: &[&[u8]]) {
    assert_eq!(bytes.pop(), Some(0), "the pack ends with the end marker");

    let mut manifest = Vec::new();
    manifest.extend_from_slice(&1u16.to_be_bytes()); // format version
    manifest.extend_from_slice(&segment.to_be_bytes());
    manifest.extend_from_slice(&shard.to_be_bytes());
    manifest.extend_from_slice(&(records.len() as u64).to_be_bytes());
    manifest.extend_from_slice(Sha384::digest(b"a history root").as_bytes());
    manifest.extend_from_slice(&[0u8; 48]); // chain_before
    manifest.extend_from_slice(Sha384::digest(b"a chain after").as_bytes());
    manifest.extend_from_slice(&0u64.to_be_bytes()); // no index roots
    manifest.extend_from_slice(&0u64.to_be_bytes()); // first_recorded_at
    manifest.extend_from_slice(&0u64.to_be_bytes()); // last_recorded_at
    manifest.extend_from_slice(&[1u8, 1, 1]); // the header's own algorithms
    bytes.push(3);
    bytes.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&manifest);

    let mut set = Vec::new();
    set.extend_from_slice(&shard.to_be_bytes());
    set.extend_from_slice(&segment.to_be_bytes());
    set.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        set.extend_from_slice(&(record.len() as u32).to_be_bytes());
        set.extend_from_slice(record);
    }
    bytes.push(4);
    bytes.extend_from_slice(&(set.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&set);

    bytes.push(0);
}

#[test]
fn a_segment_for_a_shard_the_pack_does_not_list_is_caught() {
    // The worst of the verifier defects the core review found. Verification was a
    // strictly top-down walk from `pack.shards`, and nothing asserted that every
    // section parsed had been reached. A segment naming shard 7, where the header
    // lists no shard 7, was therefore checked by nothing: not `record-decodes`,
    // not `chain-within-segment`, not `history-root`, not even the explicit
    // "begins at a zero chain head, which no journal produces" check.
    //
    // The records hanging off it rode inside the pack unparsed, and because the
    // signature covers the store root and the store root is derived from
    // `pack.shards` alone, a signed pack stayed signed. An intermediary who
    // cannot forge a root could still add whole shards of exculpatory or
    // incriminating records to one.
    let mut bytes = pack_of(&store());
    assert!(verify(&bytes).unwrap().verified());

    append_segment_for(
        &mut bytes,
        7,
        1,
        &[b"total garbage", b"not a record at all"],
    );

    let checks = broken(&bytes);
    assert!(
        checks.contains(&"orphan-segment".to_owned()),
        "a fabricated shard rode along unchecked: {checks:?}"
    );
}

#[test]
fn a_second_record_set_for_a_real_segment_is_refused_at_the_parser() {
    // `records_for` returns the first match, so a second set for a segment the
    // pack already describes was never decoded, chained, indexed or counted,
    // while `orphan-records` passed because a segment does describe it. The pack
    // format has no two spellings of anything, and now says so.
    let mut bytes = pack_of(&store());
    assert_eq!(bytes.pop(), Some(0));

    let mut set = Vec::new();
    set.extend_from_slice(&0u16.to_be_bytes()); // shard 0
    set.extend_from_slice(&1u64.to_be_bytes()); // segment 1, which exists
    set.extend_from_slice(&1u64.to_be_bytes());
    set.extend_from_slice(&31u32.to_be_bytes());
    set.extend_from_slice(b"a second set for a real segment");
    bytes.push(4);
    bytes.extend_from_slice(&(set.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&set);
    bytes.push(0);

    let err = verify(&bytes).expect_err("a duplicate section must not parse");
    assert!(
        format!("{err}").contains("two record sets"),
        "unexpected error: {err}"
    );
}

/// One shard's index, root, and the manifests and record bytes under it.
type ShardParts = (u16, Hash, Vec<(SegmentManifest, Vec<Vec<u8>>)>);

/// Write a pack from manifests and record bytes directly.
///
/// `PackBuilder` takes sealed `Segment`s, and a sealed segment computes its own
/// manifest, so it cannot express a manifest that disagrees with its records.
/// The party that seals is the party being audited, so that is exactly what the
/// verifier has to be tested against.
fn hand_built_pack(shards: &[ShardParts], store_root: Hash) -> Vec<u8> {
    fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    fn section(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
        out.push(kind);
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
        out.extend_from_slice(body);
    }
    /// The three bytes the manifest root commits to. Derived rather than typed
    /// out: a literal here silently stops matching the moment an algorithm
    /// default changes, and the symptom is a `shard-root` finding in a test that
    /// is about something else entirely.
    fn codes(a: Algorithms) -> [u8; 3] {
        use trailryx_record::{HashAlg, KemAlg};
        [
            match a.hash {
                HashAlg::Sha384 => 1,
            },
            match a.signature {
                SigAlg::Es256 => 1,
                SigAlg::MlDsa65 => 2,
                SigAlg::SlhDsa => 3,
                SigAlg::Es384 => 4,
            },
            match a.kem {
                KemAlg::X25519MlKem768 => 1,
            },
        ]
    }

    let mut out = trailryx_store::evidence::MAGIC.to_vec();
    out.push(2);

    let mut header = Vec::new();
    put_bytes(&mut header, b"acme");
    header.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    header.extend_from_slice(store_root.as_bytes());
    header.extend_from_slice(&(shards.len() as u32).to_be_bytes());
    let algorithms = shards
        .first()
        .and_then(|(_, _, segments)| segments.first())
        .map(|(m, _)| codes(m.algorithms))
        .unwrap_or([1, 1, 1]);
    header.extend_from_slice(&algorithms);
    section(&mut out, 1, &header);

    for (shard, root, segments) in shards {
        let mut body = Vec::new();
        body.extend_from_slice(&shard.to_be_bytes());
        body.extend_from_slice(&(segments.len() as u32).to_be_bytes());
        body.extend_from_slice(root.as_bytes());
        section(&mut out, 2, &body);
    }

    for (_, _, segments) in shards {
        for (m, records) in segments {
            let mut body = Vec::new();
            body.extend_from_slice(&m.format_version.to_be_bytes());
            body.extend_from_slice(&m.segment.0.to_be_bytes());
            body.extend_from_slice(&m.shard.0.to_be_bytes());
            body.extend_from_slice(&m.records.to_be_bytes());
            body.extend_from_slice(m.history_root.as_bytes());
            body.extend_from_slice(m.chain_before.as_bytes());
            body.extend_from_slice(m.chain_after.as_bytes());
            body.extend_from_slice(&(m.index_roots.len() as u64).to_be_bytes());
            for (dimension, root) in &m.index_roots {
                put_bytes(&mut body, dimension.as_str().as_bytes());
                body.extend_from_slice(root.as_bytes());
            }
            body.extend_from_slice(&m.first_recorded_at.as_nanos().to_be_bytes());
            body.extend_from_slice(&m.last_recorded_at.as_nanos().to_be_bytes());
            body.extend_from_slice(&codes(m.algorithms));
            section(&mut out, 3, &body);

            let mut set = Vec::new();
            set.extend_from_slice(&m.shard.0.to_be_bytes());
            set.extend_from_slice(&m.segment.0.to_be_bytes());
            set.extend_from_slice(&(records.len() as u64).to_be_bytes());
            for record in records {
                put_bytes(&mut set, record);
            }
            section(&mut out, 4, &set);
        }
    }

    out.push(0);
    out
}

#[test]
fn a_segment_hollowed_out_to_zero_records_cannot_splice_the_chain() {
    // Every segment slot used to be a free splice point. `chain-within-segment`
    // was guarded by `!parsed.is_empty()`, so a segment claiming zero records was
    // never made to satisfy `chain_after == chain_before`; every other check on
    // an empty segment is trivially satisfiable by the sealer, because
    // history_root and all five index roots collapse to the empty root.
    //
    // So: replace segment 1 of shard 0 with an empty manifest that keeps its
    // original `chain_after`, and recompute the shard and store roots over it, as
    // the operator who holds the signing key can. Three records vanish from the
    // middle of a shard, and `chain-across-segments` sees the same head on both
    // sides and is satisfied.
    let honest = store();
    let empty = Segment::seal(SegmentId(1), ShardIx(0), genesis(), &[]).unwrap();

    let mut hollow = empty.manifest().clone();
    hollow.chain_after = honest.shard0[0].manifest().chain_after;

    let mut t0 = ShardTree::new(ShardIx(0));
    t0.push(hollow.clone());
    t0.push(honest.shard0[1].manifest().clone());
    let mut t1 = ShardTree::new(ShardIx(1));
    t1.push(honest.shard1[0].manifest().clone());
    let tree = StoreTree::from_shards(&[t0.clone(), t1.clone()]);

    let encoded = |segment: &Segment| -> Vec<Vec<u8>> {
        segment.records().iter().map(encode_record).collect()
    };
    let bytes = hand_built_pack(
        &[
            (
                0,
                t0.root(),
                vec![
                    (hollow, Vec::new()),
                    (
                        honest.shard0[1].manifest().clone(),
                        encoded(&honest.shard0[1]),
                    ),
                ],
            ),
            (
                1,
                t1.root(),
                vec![(
                    honest.shard1[0].manifest().clone(),
                    encoded(&honest.shard1[0]),
                )],
            ),
        ],
        tree.root(),
    );

    let checks = broken(&bytes);
    assert!(
        checks.contains(&"chain-within-segment".to_owned()),
        "three records were excised and the verifier reported a clean bill: {checks:?}"
    );
    // And nothing else: the roots all recompute, which is what made this work.
    assert_eq!(checks.len(), 1, "{checks:?}");
}

#[test]
fn a_gap_in_the_sequence_is_caught() {
    // Deleting one record from a segment and re-sealing everything above it left
    // no finding at all: the sequence was checked for increase, so 1, 3 read as
    // fine. One segment is one journal file and a journal numbers each file from
    // one, so the whole sequence is known and every number in it has to be there.
    let honest = seal(
        1,
        0,
        genesis(),
        &[
            record(1, 0, 1, "agent://acme.example/billing", "run-a", 1_000),
            record(2, 0, 2, "agent://acme.example/billing", "run-a", 1_010),
            record(3, 0, 3, "agent://acme.example/support", "run-b", 1_020),
        ],
    );
    let doctored = seal(
        1,
        0,
        genesis(),
        &[
            record(1, 0, 1, "agent://acme.example/billing", "run-a", 1_000),
            record(3, 0, 3, "agent://acme.example/support", "run-b", 1_020),
        ],
    );

    let pack = |segment: &Segment| {
        let mut t = ShardTree::new(ShardIx(0));
        t.push(segment.manifest().clone());
        let tree = StoreTree::from_shards(&[t.clone()]);
        PackBuilder::new(TenantId::parse("acme").unwrap(), Timestamp(1_700_000_000))
            .shard(&t, &[segment])
            .build(&tree)
    };

    assert!(verify(&pack(&honest)).unwrap().verified());
    let checks = broken(&pack(&doctored));
    assert!(
        checks.contains(&"sequence-contiguous".to_owned()),
        "the seq-2 record was deleted and nothing said so: {checks:?}"
    );
}
