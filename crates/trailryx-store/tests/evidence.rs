//! The pack the store writes, checked by the verifier that shares no code with it.
//!
//! This is the only place the two meet, and they meet through bytes. Every
//! tamper below is a thing somebody would do to a pack between the store and
//! the auditor, and the assertion is always that the verifier notices and names
//! what it noticed.

use trailryx_crypto::{Sha384, chain_step};
use trailryx_index::segment::{Segment, ShardTree, StoreTree};
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
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
        Hash::ZERO,
        &[
            record(1, 0, 1, "agent://acme.example/billing", "run-a", 1_000),
            record(2, 0, 2, "agent://acme.example/billing", "run-a", 1_010),
            record(3, 0, 3, "agent://acme.example/support", "run-b", 1_020),
        ],
    );
    let b = seal(
        2,
        0,
        a.manifest().chain_after,
        &[
            record(4, 0, 4, "agent://acme.example/support", "run-b", 1_030),
            record(5, 0, 5, "agent://acme.example/billing", "run-c", 1_040),
        ],
    );
    let c = seal(
        1,
        1,
        Hash::ZERO,
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
fn a_signed_pack_reports_the_signature_it_did_not_check() {
    // Claiming to have checked a signature this version cannot check would be
    // worse than saying nothing.
    let s = store();
    let mut t0 = ShardTree::new(ShardIx(0));
    for segment in &s.shard0 {
        t0.push(segment.manifest().clone());
    }
    let tree = StoreTree::from_shards(&[t0.clone()]);
    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), Timestamp(1))
        .signed_with(vec![7u8; 64])
        .shard(&t0, &s.shard0.iter().collect::<Vec<_>>())
        .build(&tree);

    let report = verify(&bytes).unwrap();
    assert!(report.verified(), "{:?}", report.findings);
    let finding = report
        .findings
        .iter()
        .find(|f| f.check == "root-signature")
        .unwrap();
    assert!(finding.detail.contains("not checked"), "{finding}");
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
                Hash::ZERO,
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
