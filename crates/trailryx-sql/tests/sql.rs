//! Real SQL, through DataFusion, over sealed segments.
//!
//! The point is not that a query returns rows. It is that the predicate reached the
//! **authenticated index**, and that the answer says so. `docs/planning/trailryx-architecture.md`
//! §3.2 puts it in one sentence: SQL does not become a hole in the proof model,
//! because it either proves or says honestly that it did not.
//!
//! So every test here asserts on the provability alongside the rows, and two of them
//! assert that a query which cannot be proved is reported as partial rather than
//! quietly answered.

use std::sync::Arc;

use datafusion::prelude::SessionContext;

use trailryx_crypto::{Sha384, chain_step};
use trailryx_index::segment::Segment;
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_sql::table::{Provability, RecordTable};

fn genesis() -> Hash {
    Sha384::digest(b"trailryx-test/segment-genesis")
}

fn record(seq: u64, run: &str, event: EventType, agent: &str) -> Record {
    Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse(agent).unwrap(),
        run_id: RunId::parse(run).unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_000 + seq)),
        decided_at: None,
        recorded_at: Timestamp(1_000_000 + seq),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: event,
        severity: if seq % 2 == 0 {
            Severity::Error
        } else {
            Severity::Info
        },
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

/// Six records: three runs, two event types, two agents, so every dimension has
/// something to select on and something to leave behind.
fn segment() -> Segment {
    let records = [
        record(
            1,
            "run-a",
            EventType::ModelCall,
            "agent://acme.example/billing",
        ),
        record(
            2,
            "run-a",
            EventType::ToolCall,
            "agent://acme.example/billing",
        ),
        record(
            3,
            "run-b",
            EventType::ModelCall,
            "agent://acme.example/billing",
        ),
        record(
            4,
            "run-b",
            EventType::ModelCall,
            "agent://acme.example/support",
        ),
        record(
            5,
            "run-c",
            EventType::ToolCall,
            "agent://acme.example/support",
        ),
        record(
            6,
            "run-c",
            EventType::ModelCall,
            "agent://acme.example/support",
        ),
    ];
    let mut link = genesis();
    let leaves: Vec<(Record, Hash)> = records
        .iter()
        .map(|r| {
            link = chain_step(link, r.seq, &encode_record(r));
            (r.clone(), link)
        })
        .collect();
    Segment::seal(SegmentId(1), ShardIx(0), genesis(), &leaves).unwrap()
}

async fn ask(sql: &str) -> (usize, Provability) {
    let table = Arc::new(RecordTable::new(vec![segment()]));
    let ctx = SessionContext::new();
    ctx.register_table("records", Arc::clone(&table) as Arc<_>)
        .expect("the table registers");
    let rows = ctx
        .sql(sql)
        .await
        .expect("the query plans")
        .collect()
        .await
        .expect("the query runs")
        .iter()
        .map(|b| b.num_rows())
        .sum();
    let proof = table.last_proof().expect("a scan happened");
    (rows, proof)
}

#[tokio::test]
async fn a_predicate_on_a_provable_dimension_is_answered_with_a_full_proof() {
    let (rows, proof) = ask("SELECT * FROM records WHERE run_id = 'run-b'").await;
    assert_eq!(rows, 2, "run-b has two records");
    assert_eq!(
        proof,
        Provability::Full,
        "a predicate on a provable dimension must carry its proof"
    );
}

#[tokio::test]
async fn every_provable_dimension_can_carry_a_proof() {
    // Each of the five, by the projection's own column name and the projection's own
    // rendering of the value. A dimension that quietly stopped being provable would
    // show up here rather than in a demo.
    let cases = [
        ("run_id = 'run-a'", 2),
        ("agent_id = 'agent://acme.example/support'", 3),
        ("event_type = 'tool_call'", 2),
        ("recorded_at_nanos = 1000003", 1),
        ("record_id = '00000000000000000000000000000004'", 1),
    ];
    for (predicate, expected) in cases {
        let (rows, proof) = ask(&format!("SELECT * FROM records WHERE {predicate}")).await;
        assert_eq!(rows, expected, "{predicate}");
        assert_eq!(proof, Provability::Full, "{predicate} should be provable");
    }
}

#[tokio::test]
async fn a_range_on_the_time_dimension_is_provable() {
    let (rows, proof) =
        ask("SELECT * FROM records WHERE recorded_at_nanos BETWEEN 1000002 AND 1000004").await;
    assert_eq!(rows, 3);
    assert_eq!(proof, Provability::Full);
}

/// The rule §3.2 exists for. A predicate off the provable dimensions is applied,
/// the rows are right, and the answer says it cannot prove it was complete.
#[tokio::test]
async fn a_predicate_off_the_provable_dimensions_answers_correctly_and_says_partial() {
    let (rows, proof) = ask("SELECT * FROM records WHERE severity = 'error'").await;
    assert_eq!(rows, 3, "three records have severity error");
    match proof {
        Provability::Partial(reasons) => {
            assert!(
                !reasons.is_empty(),
                "a partial proof must say what was not proved"
            );
        }
        Provability::Full => panic!("severity is not a provable dimension"),
    }
}

/// Two predicates on two provable dimensions: the index sorts by one at a time, so
/// the second costs the proof and is named. The rows are still correct, because
/// DataFusion applies what we could not.
#[tokio::test]
async fn a_second_provable_predicate_is_named_rather_than_silently_dropped() {
    let (rows, proof) =
        ask("SELECT * FROM records WHERE run_id = 'run-b' AND event_type = 'model_call'").await;
    assert_eq!(rows, 2, "both of run-b's records are model calls");
    let Provability::Partial(reasons) = proof else {
        panic!("two provable dimensions cannot both be the sorted one");
    };
    assert!(
        reasons.iter().any(|r| r.contains("one at a time")),
        "{reasons:?}"
    );
}

/// Something the facade cannot model at all. The answer is still correct, because
/// DataFusion evaluates it above us, and the proof says we could not see it.
#[tokio::test]
async fn an_expression_the_facade_cannot_read_is_still_answered_and_still_disclosed() {
    let (rows, proof) = ask("SELECT * FROM records WHERE lower(agent_id) LIKE '%support%'").await;
    assert_eq!(rows, 3);
    assert!(matches!(proof, Provability::Partial(_)));
}

/// A full scan is a complete answer to "everything", so it keeps its proof. Refusing
/// to prove a scan would make the most common query the least trustworthy.
#[tokio::test]
async fn a_query_with_no_predicate_scans_and_keeps_its_proof() {
    let (rows, proof) = ask("SELECT * FROM records").await;
    assert_eq!(rows, 6);
    assert_eq!(proof, Provability::Full);
}

/// The columns are the projection's, including the four real lists. A facade that
/// dropped or renamed one would be a table whose columns mean something else than
/// the exported file's.
#[tokio::test]
async fn the_table_has_the_projections_own_columns_including_the_lists() {
    let table = Arc::new(RecordTable::new(vec![segment()]));
    let ctx = SessionContext::new();
    ctx.register_table("records", Arc::clone(&table) as Arc<_>)
        .unwrap();

    let batches = ctx
        .sql("SELECT record_id, run_id, tool_manifest, caused_by FROM records LIMIT 1")
        .await
        .unwrap()
        .collect()
        .await
        .unwrap();
    let schema = batches[0].schema();
    assert_eq!(schema.fields().len(), 4);
    for name in ["tool_manifest", "caused_by"] {
        let field = schema.field_with_name(name).expect(name);
        assert!(
            matches!(
                field.data_type(),
                datafusion::arrow::datatypes::DataType::List(_)
            ),
            "{name} should be a list, not {:?}",
            field.data_type()
        );
    }
}

/// Writing is not on offer. `INSERT` through SQL is forbidden by the plan, and
/// records arrive through a `Source` and nowhere else.
///
/// The property asserted is that **no write completes**, not that the planner
/// refuses. An earlier version of this test checked only that planning failed, and it
/// failed itself: DataFusion happily plans the statement and the refusal comes at
/// execution, from the trait's own default `insert_into`. Planning is not the boundary
/// and asserting on it was asserting the wrong thing.
#[tokio::test]
async fn sql_cannot_write() {
    let table = Arc::new(RecordTable::new(vec![segment()]));
    let ctx = SessionContext::new();
    ctx.register_table("records", Arc::clone(&table) as Arc<_>)
        .unwrap();

    let before = ask("SELECT * FROM records").await.0;

    for statement in [
        "INSERT INTO records (run_id) VALUES ('smuggled')",
        "INSERT INTO records SELECT * FROM records",
        "DELETE FROM records",
        "UPDATE records SET run_id = 'rewritten'",
    ] {
        let outcome = match ctx.sql(statement).await {
            Err(_) => Err(()),
            // It planned. That is not permission: run it and require the failure.
            Ok(frame) => frame.collect().await.map(|_| ()).map_err(|_| ()),
        };
        assert!(
            outcome.is_err(),
            "{statement} completed, so SQL can write and the store has a second way in"
        );
    }

    assert_eq!(
        ask("SELECT * FROM records").await.0,
        before,
        "the row count moved, so something got through"
    );
}
