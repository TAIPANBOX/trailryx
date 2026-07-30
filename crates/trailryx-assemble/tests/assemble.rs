//! The seam, from both sides.
//!
//! What matters here is not that the fields copy across. It is that the three
//! things this crate decides are decided the way the rest of the store needs, and
//! that the things it must not decide are visibly left alone.

use trailryx_assemble::{Assembler, DEFAULT_CORRELATION_WINDOW};
use trailryx_contracts::fakes::{MemoryKeyProvider, MemoryObjectStore};
use trailryx_contracts::ingest::{Correlation, Cursor, Ingest, MetaDraft, PayloadPart, SourceKey};
use trailryx_erasure::subject::SubjectHandle;
use trailryx_erasure::vault::Vault;
use trailryx_erasure::{PredictableKeys, Sha384Ctr};
use trailryx_record::{
    AgentId, Basis, EventType, Hash, MapperVersion, PayloadClass, RunId, SegmentId, Severity,
    ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_sim::rng::SimRng;

type Vaults = Vault<MemoryObjectStore, MemoryKeyProvider, Sha384Ctr, PredictableKeys>;

const NOW: Timestamp = Timestamp(1_700_000_000_000_000_000);

fn assembler() -> Assembler<SimRng> {
    Assembler::new(ShardIx(3), SimRng::new(42))
}

fn vault() -> Vaults {
    Vault::unvalidated(
        TenantId::parse("acme").unwrap(),
        "acme.example",
        MemoryObjectStore::default(),
        MemoryKeyProvider::default(),
        Sha384Ctr,
        PredictableKeys::new(),
    )
}

fn draft(claimed: u64) -> MetaDraft {
    MetaDraft {
        mapper: MapperVersion(7),
        tenant: TenantId::parse("acme").unwrap(),
        agent_id: AgentId::parse("agent://acme.example/billing").unwrap(),
        run_id: RunId::parse("run-a").unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(claimed)),
        decided_at: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        verdict: None,
        error: None,
        latency_micros: None,
        tokens_in: None,
        tokens_out: None,
        cost_micros: None,
    }
}

fn ingest(id: u8, parent: Option<u8>, payload: Vec<PayloadPart>) -> Ingest {
    Ingest {
        meta: draft(NOW.as_nanos()),
        payload,
        correlation: Some(Correlation {
            id: SourceKey::new(&[id; 8]).unwrap(),
            parent: parent.map(|p| SourceKey::new(&[p; 8]).unwrap()),
        }),
        cursor: Cursor(u64::from(id)),
    }
}

// ---------------------------------------------------------------------------
// What it decides
// ---------------------------------------------------------------------------

#[test]
fn the_shard_comes_from_the_assembler_and_not_from_the_draft() {
    // A source cannot choose which shard it lands in: that decides which key
    // hierarchy and which chain the record belongs to.
    let mut a = assembler();
    let record = a
        .record(draft(NOW.as_nanos()), NOW, Vec::new(), Vec::new())
        .record;
    assert_eq!(record.shard, ShardIx(3));
}

#[test]
fn the_source_never_chooses_an_identity() {
    // The journal deduplicates on the record id, so a source that could name one
    // could overwrite a record by claiming its identity.
    let mut a = assembler();
    let first = a.adopt(ingest(1, None, Vec::new()), NOW).record;
    let second = a.adopt(ingest(1, None, Vec::new()), NOW).record;
    assert_ne!(
        first.id, second.id,
        "two events with the same source name are still two records"
    );
}

#[test]
fn a_parent_the_source_named_becomes_an_edge_over_our_own_ids() {
    let mut a = assembler();
    let parent = a.adopt(ingest(1, None, Vec::new()), NOW).record;
    let child = a.adopt(ingest(2, Some(1), Vec::new()), NOW).record;
    assert_eq!(child.caused_by, vec![parent.id]);
}

#[test]
fn a_parent_nobody_remembers_yields_no_edge_rather_than_a_wrong_one() {
    // Guessing here would put a false edge in a causal graph, which is worse than
    // an absent one: an absent edge costs a reconstruction its completeness, and
    // the reconstruction says so.
    let mut a = assembler();
    let orphan = a.adopt(ingest(2, Some(9), Vec::new()), NOW).record;
    assert!(orphan.caused_by.is_empty());
}

#[test]
fn a_parent_that_fell_out_of_the_window_yields_no_edge() {
    // The bound is the point. A receiver runs for months.
    let mut a = Assembler::with_window(ShardIx(0), SimRng::new(1), 2);
    let _first = a.adopt(ingest(1, None, Vec::new()), NOW);
    a.adopt(ingest(2, None, Vec::new()), NOW);
    a.adopt(ingest(3, None, Vec::new()), NOW);

    let late_child = a.adopt(ingest(4, Some(1), Vec::new()), NOW).record;
    assert!(late_child.caused_by.is_empty(), "the parent was evicted");
    assert_eq!(a.correlation().len(), 2);

    let recent_child = a.adopt(ingest(5, Some(4), Vec::new()), NOW).record;
    assert_eq!(
        recent_child.caused_by.len(),
        1,
        "a recent parent still resolves"
    );
}

#[test]
fn the_source_name_never_reaches_the_record() {
    // It is matched for equality inside a batch and then dropped. A span id that
    // happened to contain somebody's name would be a leak if it were stored.
    let mut a = assembler();
    let record = a.adopt(ingest(0x7f, None, Vec::new()), NOW).record;
    let rendered = format!("{record:?}");
    assert!(!rendered.contains("SourceKey"), "{rendered}");
    assert!(!rendered.contains("correlation"), "{rendered}");
}

#[test]
fn the_recorded_time_is_ours_and_the_claimed_one_stays_untrusted() {
    let mut a = assembler();
    let claimed = NOW.as_nanos() - 3_600_000_000_000;
    let record = a.record(draft(claimed), NOW, Vec::new(), Vec::new()).record;

    assert_eq!(record.recorded_at, NOW);
    assert_eq!(record.occurred_at.as_untrusted().as_nanos(), claimed);
    assert_eq!(
        record.clock_skew_nanos,
        Some(3_600_000_000_000),
        "the disagreement is recorded, not resolved"
    );
}

// ---------------------------------------------------------------------------
// What it refuses to decide
// ---------------------------------------------------------------------------

#[test]
fn the_fields_the_journal_stamps_are_left_obviously_empty() {
    // A plausible sequence number here would be a lie that survives into a
    // record, so they are left at values nobody could mistake for real.
    let mut a = assembler();
    let record = a
        .record(draft(NOW.as_nanos()), NOW, Vec::new(), Vec::new())
        .record;
    assert_eq!(record.seq, 0);
    assert_eq!(record.prev_hash, Hash::ZERO);
    assert_eq!(record.segment_id, SegmentId(0));
}

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

#[test]
fn a_payload_is_sealed_against_the_record_that_carries_it() {
    // The ordering that used to be the caller's problem: mint the id, then seal
    // against it. Getting it the other way round produced a reference bound to a
    // record that did not exist.
    let mut a = assembler();
    let mut v = vault();
    let subject = SubjectHandle::parse("subject-1").unwrap();

    let assembled = a.record(
        draft(NOW.as_nanos()),
        NOW,
        Vec::new(),
        vec![PayloadPart::new(
            PayloadClass::Prompt,
            b"a question".to_vec(),
        )],
    );
    assert!(assembled.has_payload());
    let id = assembled.record.id;
    let record = assembled.seal(&mut v, Some(&subject)).unwrap();

    let reference = record.payload.expect("a reference");
    assert_eq!(record.id, id);
    assert_eq!(v.open(record.id, &reference).unwrap().len(), 1);
}

#[test]
fn a_record_with_nothing_to_seal_needs_no_vault_round_trip() {
    let mut a = assembler();
    let mut v = vault();
    let assembled = a.record(draft(NOW.as_nanos()), NOW, Vec::new(), Vec::new());
    assert!(!assembled.has_payload());
    assert!(assembled.seal(&mut v, None).unwrap().payload.is_none());
}

#[test]
fn an_unattributed_payload_can_be_reached_later() {
    // The normal case: an agent rarely knows whose data is in a prompt when it
    // sends one. Sealed under a key belonging to nobody, and attribution catches
    // up without anything being re-encrypted.
    let mut a = assembler();
    let mut v = vault();
    let subject = SubjectHandle::parse("subject-1").unwrap();

    let record = a
        .adopt(
            ingest(
                1,
                None,
                vec![PayloadPart::new(
                    PayloadClass::Prompt,
                    b"whose is this".to_vec(),
                )],
            ),
            NOW,
        )
        .seal(&mut v, None)
        .unwrap();
    let reference = record.payload.clone().expect("a reference");

    assert!(v.attribute(&reference, &subject));
    let forgotten = v.forget(&subject, NOW).unwrap();
    assert_eq!(forgotten.keys_destroyed, 1);
    assert!(matches!(
        v.open(record.id, &reference),
        Err(trailryx_erasure::VaultError::Erased)
    ));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn the_same_seed_and_the_same_input_assemble_the_same_records() {
    // The whole store is built so a seed reproduces a run. An assembler that
    // reached for entropy would break that for everything downstream of it.
    let build = || -> Vec<u128> {
        let mut a = Assembler::new(ShardIx(0), SimRng::new(11));
        (0..4)
            .map(|i| {
                a.adopt(ingest(i, i.checked_sub(1), Vec::new()), NOW)
                    .record
                    .id
                    .0
            })
            .collect()
    };
    assert_eq!(build(), build());
}

#[test]
fn the_default_window_is_large_enough_to_be_uninteresting() {
    // A parent arrives before its child within milliseconds, so the default is
    // generous by orders of magnitude and nobody should have to think about it.
    let a: Assembler<SimRng> = Assembler::new(ShardIx(0), SimRng::new(1));
    assert_eq!(a.correlation().capacity(), DEFAULT_CORRELATION_WINDOW);
    assert!(
        a.correlation().capacity() >= 65_536,
        "a window this small would make edges depend on timing"
    );
    assert!(a.correlation().is_empty());
}

#[test]
fn a_batch_ordered_children_first_still_gets_its_edges() {
    // The premise the window was justified with was backwards for the only source
    // in the tree. "A parent arrives before its child by construction in a trace"
    // is false for OpenTelemetry: a span is exported when it *ends*, and a child
    // ends inside its parent, so a batch is ordered children first. `adopt`
    // resolved the parent before remembering the current event, so a parent that
    // arrived after its child could never be found, whatever the window size, and
    // the causal graph was empty for every OTLP-sourced trace.
    let mut a = assembler();
    let assembled = a.adopt_batch(
        vec![
            ingest(2, Some(1), Vec::new()), // the child, exported first
            ingest(1, None, Vec::new()),    // its parent
        ],
        NOW,
    );

    let child = &assembled[0].record;
    let parent = &assembled[1].record;
    assert_eq!(
        child.caused_by,
        vec![parent.id],
        "a child exported before its parent got no edge"
    );
    assert!(parent.caused_by.is_empty());
    assert_eq!(a.unresolved_parents(), 0);

    // The ids still increase in the order the batch arrived, so the child's id is
    // lower than its parent's. That is a property of when things were recorded and
    // not of what caused what, and the edge is what carries causation.
    assert!(child.id.0 < parent.id.0);
}

#[test]
fn an_unresolvable_parent_is_counted_rather_than_dropped_in_silence() {
    // The edge vanished with no counter, no marker and no event, so a reconstruction
    // over the records could not tell "this event named a parent we lost" from
    // "this event had no parent", and reported itself complete either way.
    let mut a = Assembler::with_window(ShardIx(3), SimRng::new(5), 2);
    a.adopt(ingest(1, None, Vec::new()), NOW);
    a.adopt(ingest(8, None, Vec::new()), NOW);
    a.adopt(ingest(9, None, Vec::new()), NOW); // evicts name 1
    assert_eq!(a.unresolved_parents(), 0);

    let orphan = a.adopt(ingest(2, Some(1), Vec::new()), NOW).record;
    assert!(orphan.caused_by.is_empty());
    assert_eq!(a.unresolved_parents(), 1, "the lost edge was not counted");

    // A parent nobody ever named counts too.
    a.adopt(ingest(3, Some(77), Vec::new()), NOW);
    assert_eq!(a.unresolved_parents(), 2);
}

#[test]
fn a_span_naming_itself_as_its_own_parent_gets_no_edge() {
    // Resolving after remembering makes this reachable, so it has to be refused
    // here: an edge from a record to itself is a cycle of length one, and a false
    // edge is worse than an absent one.
    let mut a = assembler();
    let assembled = a.adopt_batch(vec![ingest(1, Some(1), Vec::new())], NOW);
    assert!(assembled[0].record.caused_by.is_empty());
    assert_eq!(a.unresolved_parents(), 1);
}
