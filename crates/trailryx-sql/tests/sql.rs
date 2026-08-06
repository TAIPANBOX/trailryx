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

// ---------------------------------------------------------------------------
// The gate, through the only entry point there is
// ---------------------------------------------------------------------------

use trailryx_sql::{QueryError, Session};

/// The whole reason `gate` exists, end to end. A bare `SessionContext` reads the file;
/// a `Session` refuses before the engine is asked.
#[tokio::test]
async fn a_session_cannot_be_talked_into_reading_a_local_file() {
    // Per process. The path was a constant and this test wipes it on the way out, so
    // one run deleted the `secret.csv` another run was in the middle of asking the
    // session to refuse. Measured 6 August 2026 at six concurrent runs: 3 of 30
    // processes failed. The refusal being tested is real either way; what the
    // collision broke was the setup that makes the refusal mean anything.
    let dir = std::env::temp_dir().join(format!("trailryx-sql-gate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("secret.csv");
    std::fs::write(&secret, "a,b\n1,hunter2\n").unwrap();

    let session = Session::new(vec![segment()]);
    let attempt = session
        .query(&format!(
            "CREATE EXTERNAL TABLE leak (a INT, b VARCHAR) STORED AS CSV LOCATION '{}'",
            secret.display()
        ))
        .await;

    let Err(QueryError::Refused(refusal)) = attempt else {
        panic!("a session read, or tried to read, a path a client named: {attempt:?}");
    };
    assert!(
        refusal.to_string().contains("arbitrary local file read"),
        "{refusal}"
    );

    // And the table was never created, so a follow-up cannot find it either.
    assert!(session.query("SELECT * FROM leak").await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same protection against the shape that hides a second statement behind a
/// harmless first one.
#[tokio::test]
async fn a_second_statement_cannot_ride_in_behind_a_select() {
    let session = Session::new(vec![segment()]);
    let attempt = session
        .query("SELECT 1; CREATE EXTERNAL TABLE leak (a INT) STORED AS CSV LOCATION '/etc/passwd'")
        .await;
    assert!(
        matches!(attempt, Err(QueryError::Refused(_))),
        "{attempt:?}"
    );
}

/// A session still answers the queries it is for, and still reports provability
/// through the same entry point.
#[tokio::test]
async fn a_session_answers_a_query_and_reports_its_proof() {
    let session = Session::new(vec![segment()]);
    let rows: usize = session
        .query("SELECT * FROM records WHERE run_id = 'run-b'")
        .await
        .expect("a select is served")
        .iter()
        .map(|b| b.num_rows())
        .sum();
    assert_eq!(rows, 2);
    assert_eq!(session.last_proof(), Some(Provability::Full));

    let rows: usize = session
        .query("SELECT * FROM records WHERE severity = 'error'")
        .await
        .expect("a select is served")
        .iter()
        .map(|b| b.num_rows())
        .sum();
    assert_eq!(rows, 3);
    assert!(matches!(
        session.last_proof(),
        Some(Provability::Partial(_))
    ));
}

/// Writing through a session is refused by the gate rather than by the engine, so the
/// refusal names the statement instead of being a planning failure.
#[tokio::test]
async fn writing_through_a_session_is_refused_by_name() {
    let session = Session::new(vec![segment()]);
    for (sql, expected) in [
        (
            "INSERT INTO records VALUES (1)",
            "records arrive through a Source",
        ),
        ("DELETE FROM records", "append-only"),
        ("UPDATE records SET run_id = 'x'", "append-only"),
        ("DROP TABLE records", "nothing served here"),
    ] {
        let Err(QueryError::Refused(refusal)) = session.query(sql).await else {
            panic!("{sql} was not refused by the gate");
        };
        assert!(refusal.to_string().contains(expected), "{sql}: {refusal}");
    }
}

// ---------------------------------------------------------------------------
// The dialect extensions
// ---------------------------------------------------------------------------
//
// Table functions rather than the architecture's illustrative `AS OF TIMESTAMP` and
// trailing `WITH PROOF`, neither of which the engine's parser accepts. That was
// checked, not assumed, and `dialect`'s own docs carry the reasoning: getting the
// syntax exactly would need a second parser over the same string, which is the defect
// class `gate` exists to remove.

async fn rows_of(session: &Session, sql: &str) -> usize {
    session
        .query(sql)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .iter()
        .map(|b| b.num_rows())
        .sum()
}

/// Transaction time: what the store had recorded by an instant.
#[tokio::test]
async fn records_as_of_answers_the_store_as_it_was() {
    let session = Session::new(vec![segment()]);
    // Every record in the fixture is recorded at 1000000 + seq, so an instant in the
    // middle must cut the answer in half rather than returning everything.
    let all = rows_of(&session, "SELECT * FROM records_as_of('9999999999')").await;
    assert_eq!(all, 6, "an instant after everything sees everything");

    let half = rows_of(&session, "SELECT * FROM records_as_of('1000003')").await;
    assert_eq!(half, 3, "an instant in the middle sees the first three");

    let none = rows_of(&session, "SELECT * FROM records_as_of('1')").await;
    assert_eq!(none, 0, "an instant before everything sees nothing");
}

/// The spelled-out form and the numeric one must mean the same moment.
#[tokio::test]
async fn an_instant_may_be_spelled_two_ways_and_means_one_thing() {
    let session = Session::new(vec![segment()]);
    let numeric = rows_of(&session, "SELECT * FROM records_as_of('9999999999')").await;
    let spelled = rows_of(
        &session,
        "SELECT * FROM records_as_of('2026-03-01T00:00:00Z')",
    )
    .await;
    assert_eq!(numeric, spelled);
}

/// An instant nobody can place is refused rather than guessed at.
#[tokio::test]
async fn an_ambiguous_instant_is_refused() {
    let session = Session::new(vec![segment()]);
    for bad in ["2026-03-01", "yesterday", "2026-03-01T00:00:00+02:00"] {
        assert!(
            session
                .query(&format!("SELECT * FROM records_as_of('{bad}')"))
                .await
                .is_err(),
            "{bad} should not have parsed as an instant"
        );
    }
}

/// The proof, readable from SQL.
#[tokio::test]
async fn trailryx_proof_reports_the_last_answers_provability() {
    let session = Session::new(vec![segment()]);

    // Before anything has been answered, the answer is "none" and not "full". A
    // session that has proved nothing must not report the strongest value.
    let batches = session
        .query("SELECT proof FROM trailryx_proof()")
        .await
        .expect("the function is registered");
    let first = format!("{:?}", batches[0].column(0));
    assert!(first.contains("none"), "{first}");

    session
        .query("SELECT * FROM records WHERE run_id = 'run-b'")
        .await
        .unwrap();
    let batches = session
        .query("SELECT proof, unproved FROM trailryx_proof()")
        .await
        .unwrap();
    assert!(format!("{:?}", batches[0].column(0)).contains("full"));

    session
        .query("SELECT * FROM records WHERE severity = 'error'")
        .await
        .unwrap();
    let batches = session
        .query("SELECT proof, unproved, reason FROM trailryx_proof()")
        .await
        .unwrap();
    let rendered = format!("{:?}", batches[0]);
    assert!(rendered.contains("partial"), "{rendered}");
}

/// The causal closure of a run, with the reconstruction's own verdict carried over
/// rather than re-derived.
#[tokio::test]
async fn causal_closure_returns_a_runs_closure() {
    let session = Session::new(vec![segment()]);
    let rows = rows_of(&session, "SELECT * FROM causal_closure('run-a')").await;
    assert_eq!(rows, 2, "run-a has two records and no delegation");

    // A run nobody wrote is an empty closure, not an error: "there is nothing" is a
    // real answer and a different one from "the query was wrong".
    let none = rows_of(&session, "SELECT * FROM causal_closure('run-zzz')").await;
    assert_eq!(none, 0);
}

/// An argument that is not a run identifier is refused by name.
#[tokio::test]
async fn causal_closure_refuses_something_that_is_not_a_run() {
    let session = Session::new(vec![segment()]);
    let error = session
        .query("SELECT * FROM causal_closure('not a run id at all!!')")
        .await
        .expect_err("must be refused");
    assert!(error.to_string().contains("run identifier"), "{error}");
}

/// The extensions go through the same gate as everything else, so a table function
/// cannot be a way round it.
#[tokio::test]
async fn the_extensions_are_still_behind_the_statement_gate() {
    let session = Session::new(vec![segment()]);
    assert!(
        session
            .query("CREATE TABLE x AS SELECT * FROM causal_closure('run-a')")
            .await
            .is_err(),
        "a table function must not carry a create past the gate"
    );
}

// ---------------------------------------------------------------------------
// journal(): the raw truth, shaped like pg_walinspect
// ---------------------------------------------------------------------------
//
// Every assertion here is one of the four decisions PostgreSQL made for
// `pg_walinspect`, which solves the same problem: expose the log through SQL without
// letting the query engine near the write path. Copied rather than re-derived, and
// each test names which decision it is.

/// Decision one: a table function taking a range, so there is no "give me everything".
#[tokio::test]
async fn journal_is_a_range_function_and_not_a_table() {
    let session = Session::with_raw_access(vec![segment()], true);
    assert!(
        session.query("SELECT * FROM journal").await.is_err(),
        "a log must not be askable in one piece"
    );
    assert!(
        session.query("SELECT * FROM journal(1)").await.is_err(),
        "one bound is not a range"
    );
    assert_eq!(rows_of(&session, "SELECT * FROM journal(1, 6)").await, 6);
    assert_eq!(rows_of(&session, "SELECT * FROM journal(2, 4)").await, 3);
}

/// Decision two: an error when the start is not available, never a silent empty
/// answer. The two mean very different things to somebody doing forensics.
#[tokio::test]
async fn a_start_that_is_not_sealed_is_an_error_and_says_what_is_available() {
    let session = Session::with_raw_access(vec![segment()], true);

    let error = session
        .query("SELECT * FROM journal(99, 200)")
        .await
        .expect_err("a start past the sealed records must be refused");
    assert!(
        error.to_string().contains("past the last sealed"),
        "{error}"
    );
    // And it says why, so nobody reads it as the record being hidden.
    assert!(error.to_string().contains("write path"), "{error}");

    // The fixture starts at 1, so there is no earlier case to test here; the
    // backwards range is the other refusal that must not be a silent empty answer.
    let error = session
        .query("SELECT * FROM journal(5, 2)")
        .await
        .expect_err("a backwards range must be refused");
    assert!(error.to_string().contains("backwards"), "{error}");
}

/// Decision three: permissive about the upper bound. Postgres accepts an end past the
/// current LSN and returns what exists, because erroring would make "everything from
/// here" a moving target.
#[tokio::test]
async fn an_upper_bound_past_the_end_returns_what_exists() {
    let session = Session::with_raw_access(vec![segment()], true);
    assert_eq!(
        rows_of(&session, "SELECT * FROM journal(1, 999999)").await,
        6,
        "an open-ended range returns everything sealed, not an error"
    );
}

/// Decision four: a different privilege from ordinary SQL. A session without the grant
/// does not have the function, rather than being refused when it reaches for it.
#[tokio::test]
async fn a_session_without_the_raw_grant_does_not_have_the_function_at_all() {
    let ordinary = Session::new(vec![segment()]);
    let error = ordinary
        .query("SELECT * FROM journal(1, 6)")
        .await
        .expect_err("journal must not be in an ordinary session's catalog");
    // Not "permission denied" but "no such function": the catalog a session sees is
    // what it may use, which is how pg_walinspect behaves when the grant is absent.
    assert!(
        error.to_string().to_lowercase().contains("journal"),
        "{error}"
    );

    // And the ordinary surface still works, so the grant is the only difference.
    assert_eq!(rows_of(&ordinary, "SELECT * FROM records").await, 6);
}

/// The raw path carries no proof, and it says so rather than reporting the strongest
/// value for a scan that deliberately went round the thing that proves.
#[tokio::test]
async fn journal_reports_no_proof_because_it_went_past_the_projections() {
    let session = Session::with_raw_access(vec![segment()], true);
    session.query("SELECT * FROM journal(1, 6)").await.unwrap();
    let Some(Provability::Partial(reasons)) = session.last_proof() else {
        panic!("a raw read must never report a full proof");
    };
    assert!(
        reasons.iter().any(|r| r.contains("past the projections")),
        "{reasons:?}"
    );
}

/// And it is still behind the statement gate, so the raw function is not a way round
/// anything else.
#[tokio::test]
async fn the_raw_function_is_still_behind_the_gate() {
    let session = Session::with_raw_access(vec![segment()], true);
    assert!(
        session
            .query("CREATE TABLE x AS SELECT * FROM journal(1, 6)")
            .await
            .is_err()
    );
}
