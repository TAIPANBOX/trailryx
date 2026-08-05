//! A real Postgres client, over a real socket.
//!
//! The plan's exit criterion for stage 10 is "Grafana connects as it would to
//! Postgres". Grafana is not installable in a test, so the stand-in is
//! `tokio-postgres`, the same driver Rust clients use and the same protocol Grafana
//! speaks. If this connects, authenticates, queries and is refused where it should
//! be, a Postgres client works.
//!
//! Every test binds port zero and reads the address back, so nothing here needs 5432
//! to be free and two tests can run at once.

use std::sync::Arc;
use std::time::Duration;

use tokio_postgres::error::SqlState;
use trailryx_contracts::contracts::{
    Action, AdapterError, AdapterResult, AuthProvider, Decision, Principal,
};
use trailryx_crypto::{Sha384, chain_step};
use trailryx_index::segment::Segment;
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, PrincipalId, Record,
    RecordId, RunId, SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_sql::Session;
use trailryx_sql::server::{Config, ReadGate, StartError, check, serve_on};

const SECRET: &str = "read-only-please";

fn record(seq: u64, run: &str) -> Record {
    Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/billing").unwrap(),
        run_id: RunId::parse(run).unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_000 + seq)),
        decided_at: None,
        recorded_at: Timestamp(1_000_000 + seq),
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

fn segment() -> Segment {
    let records = [record(1, "run-a"), record(2, "run-a"), record(3, "run-b")];
    let mut link = Sha384::digest(b"trailryx-test/segment-genesis");
    let start = link;
    let leaves: Vec<(Record, Hash)> = records
        .iter()
        .map(|r| {
            link = chain_step(link, r.seq, &encode_record(r));
            (r.clone(), link)
        })
        .collect();
    Segment::seal(SegmentId(1), ShardIx(0), start, &leaves).unwrap()
}

struct OneReader;

impl AuthProvider for OneReader {
    fn authenticate(&mut self, credential: &[u8]) -> AdapterResult<Principal> {
        if credential == SECRET.as_bytes() {
            Ok(Principal {
                id: PrincipalId::parse("user://acme.example/auditor").unwrap(),
                via: "password",
            })
        } else {
            Err(AdapterError::Rejected("wrong password"))
        }
    }

    fn authorize(&mut self, _p: &Principal, action: Action, _scope: &str) -> Decision {
        if action == Action::Query {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

/// Start a server on a throwaway port and return its address.
///
/// The configuration is passed rather than defaulted because `max_connections` is a
/// bound this crate has to keep, and a test that could not set it could not watch it
/// hold. The bind in it is ignored: the listener is already open.
async fn start(config: Config, gate: Option<Arc<ReadGate>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("port zero binds");
    let address = listener.local_addr().expect("an address").to_string();
    let session = Arc::new(Session::new(vec![segment()]));
    tokio::spawn(async move {
        let _ = serve_on(listener, config, session, gate).await;
    });
    address
}

fn conninfo(address: &str, password: &str) -> String {
    let (host, port) = address.rsplit_once(':').expect("host:port");
    format!("host={host} port={port} user=auditor password={password} dbname=trailryx")
}

/// The driver's own error type, not a string.
///
/// It used to be flattened to `to_string()`, which is enough to see that a connection
/// failed and not enough to see what it was told: a refusal carries a SQLSTATE, and a
/// SQLSTATE is the part a client's retry logic reads.
async fn connect(
    address: &str,
    password: &str,
) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
    let (client, connection) =
        tokio_postgres::connect(&conninfo(address, password), tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

/// The exit criterion: a Postgres client connects, authenticates and gets rows.
#[tokio::test]
async fn a_postgres_client_connects_authenticates_and_queries() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(Config::default(), Some(gate)).await;

    let client = connect(&address, SECRET)
        .await
        .expect("the right password should connect");
    let rows = client
        .simple_query("SELECT run_id FROM records WHERE run_id = 'run-a'")
        .await
        .expect("a select is served");

    // `simple_query` returns row messages plus a command-complete; count the rows.
    let count = rows
        .iter()
        .filter(|m| matches!(m, tokio_postgres::SimpleQueryMessage::Row(_)))
        .count();
    assert_eq!(count, 2, "run-a has two records");
}

/// The wrong password does not get in, and the right one still does afterwards, so a
/// refusal does not wedge the server.
#[tokio::test]
async fn a_wrong_password_is_refused_and_the_server_keeps_serving() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(Config::default(), Some(Arc::clone(&gate))).await;

    let refused = connect(&address, "guess").await;
    assert!(refused.is_err(), "a wrong password must not connect");
    assert_eq!(gate.refusals().rejected, 1);

    assert!(
        connect(&address, SECRET).await.is_ok(),
        "a refusal must not take the server down"
    );
}

/// The gate is on the wire, not only in the library. This is the statement that reads
/// a local file, sent by a real client over a real socket.
#[tokio::test]
async fn the_statement_gate_refuses_over_the_wire() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(Config::default(), Some(gate)).await;
    let client = connect(&address, SECRET).await.expect("connects");

    let attempt = client
        .simple_query("CREATE EXTERNAL TABLE leak (a INT) STORED AS CSV LOCATION '/etc/passwd'")
        .await;
    assert!(
        attempt.is_err(),
        "a client read, or was allowed to try reading, a path it named"
    );

    // And writes, over the same connection, so a refusal does not depend on being the
    // first thing a client says.
    for sql in [
        "INSERT INTO records VALUES (1)",
        "DELETE FROM records",
        "DROP TABLE records",
    ] {
        assert!(
            client.simple_query(sql).await.is_err(),
            "{sql} was not refused over the wire"
        );
    }

    // The connection still works for what it is for.
    assert!(client.simple_query("SELECT 1").await.is_ok());
}

/// An extended-protocol client prepares a statement and executes it later. The gate
/// has to be on that path too, or a client could prepare what it may not run.
#[tokio::test]
async fn the_gate_is_on_the_prepared_statement_path_as_well() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(Config::default(), Some(gate)).await;
    let client = connect(&address, SECRET).await.expect("connects");

    let prepared = client.prepare("DROP TABLE records").await;
    assert!(
        prepared.is_err(),
        "a client prepared a statement it must not be able to run"
    );

    // A query it may run still prepares and executes, so the gate is not simply
    // breaking the extended protocol.
    let good = client
        .prepare("SELECT run_id FROM records WHERE run_id = $1")
        .await
        .expect("a select prepares");
    let rows = client
        .query(&good, &[&"run-b"])
        .await
        .expect("and executes");
    assert_eq!(rows.len(), 1);
}

/// What `trailryx_proof()` says on one connection.
async fn proof_on(client: &tokio_postgres::Client) -> String {
    let messages = client
        .simple_query("SELECT proof FROM trailryx_proof()")
        .await
        .expect("the proof function is served");
    messages
        .iter()
        .find_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_owned),
            _ => None,
        })
        .expect("one row with one column")
}

/// Two connections open at once, and each is told about its own answer.
///
/// `trailryx_proof()` reports the last answer **on this session**, and a Postgres
/// session is a connection. While the proof slot was shared by the whole process, it
/// was not: one reader ran a query the index could not prove, another ran one it
/// could, and whichever asked second was handed the other's verdict. An unproved
/// answer reported as proved is the one lie this crate is arranged against, and it
/// arrived through the function whose entire purpose is to prevent it.
///
/// The two connections are open together and the statements are ordered on purpose.
/// A test that raced them would fail sometimes, and a proof that is right most of the
/// time is not a proof.
#[tokio::test]
async fn two_connections_each_read_their_own_proof_and_never_the_others() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(Config::default(), Some(gate)).await;

    let a = connect(&address, SECRET).await.expect("A connects");
    let b = connect(&address, SECRET).await.expect("B connects");

    // A asks something the index cannot prove: `severity` is not one of the five
    // provable dimensions, so it is applied as a filter and the answer is partial.
    a.simple_query("SELECT run_id FROM records WHERE severity = 'info'")
        .await
        .expect("A's select is served");
    // B asks something it can: `run_id` is the sorted dimension of an authenticated
    // index range, so B's answer carries a completeness proof.
    b.simple_query("SELECT run_id FROM records WHERE run_id = 'run-a'")
        .await
        .expect("B's select is served");

    assert_eq!(
        proof_on(&a).await,
        "partial",
        "A ran a query the index could not prove and was told B's verdict"
    );
    assert_eq!(
        proof_on(&b).await,
        "full",
        "B ran a provable query and must be told about that one"
    );

    // The other way round, because a shared value is right in one direction by
    // accident whenever the two clients happen to agree.
    b.simple_query("SELECT run_id FROM records WHERE severity = 'info'")
        .await
        .expect("B's second select is served");
    a.simple_query("SELECT run_id FROM records WHERE run_id = 'run-a'")
        .await
        .expect("A's second select is served");

    assert_eq!(
        proof_on(&b).await,
        "partial",
        "B ran a query the index could not prove and was told A's verdict"
    );
    assert_eq!(
        proof_on(&a).await,
        "full",
        "A ran a provable query and must be told about that one"
    );
}

/// A connection that has asked nothing has proved nothing, whatever anybody else has
/// been asking on the same server.
///
/// The stronger half of the test above: the shared slot did not only mix two
/// verdicts, it also gave a brand new connection a verdict about a query it had
/// never run. "None" is the only true answer to "how provable was your last answer"
/// when there has not been one.
#[tokio::test]
async fn a_fresh_connection_has_proved_nothing_however_busy_the_server_is() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(Config::default(), Some(gate)).await;

    let busy = connect(&address, SECRET).await.expect("the first connects");
    busy.simple_query("SELECT run_id FROM records WHERE run_id = 'run-a'")
        .await
        .expect("a select is served");

    let fresh = connect(&address, SECRET)
        .await
        .expect("the second connects");
    assert_eq!(
        proof_on(&fresh).await,
        "none",
        "a connection that has answered nothing was handed somebody else's proof"
    );
}

/// The connection cap is a bound the server keeps, not a sentence in a struct.
///
/// It was documented as a bound on live connections and read by nothing: a deployer
/// who lowered it got a server that behaved exactly as before, and a field like that
/// is worse than no field, because it reads as a mitigation somebody has applied.
///
/// The refusal is an answer rather than a vanishing, which is the choice the ingest
/// side made for the same reason. 53300 is `too_many_connections`, and a client that
/// is told it can back off; a client whose socket simply closes cannot tell this
/// apart from a crash, a firewall or a wrong password.
#[tokio::test]
async fn a_connection_past_the_cap_is_refused_and_the_server_keeps_serving() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(
        Config {
            max_connections: 1,
            ..Config::default()
        },
        Some(gate),
    )
    .await;

    let held = connect(&address, SECRET)
        .await
        .expect("the first connection is under the cap");
    assert!(held.simple_query("SELECT 1").await.is_ok());

    let refused = connect(&address, SECRET)
        .await
        .expect_err("a second connection is over the cap");
    assert_eq!(
        refused.code(),
        Some(&SqlState::TOO_MANY_CONNECTIONS),
        "refused, but not in a way a client can act on: {refused}"
    );
    assert!(
        refused
            .as_db_error()
            .is_some_and(|e| e.message().contains("connection limit")),
        "and the half a person reads must say what happened: {refused}"
    );

    // The point of a cap: the connections under it keep working while the one over it
    // is turned away.
    assert!(
        held.simple_query("SELECT run_id FROM records")
            .await
            .is_ok(),
        "the refusal took the server with it"
    );
}

/// A connection that ends gives its slot back.
///
/// The failure this guards is the one that only shows up later: a count that leaks on
/// some exit path reaches the cap once and then refuses everything for ever, and the
/// server looks healthy the whole time.
#[tokio::test]
async fn a_connection_that_ends_gives_its_slot_back() {
    let gate = Arc::new(ReadGate::new(Box::new(OneReader), "acme"));
    let address = start(
        Config {
            max_connections: 1,
            ..Config::default()
        },
        Some(gate),
    )
    .await;

    let held = connect(&address, SECRET).await.expect("the first connects");
    assert!(held.simple_query("SELECT 1").await.is_ok());
    drop(held);

    // The slot comes back when the server's side of that connection ends, which is
    // not the instant the client drops it. Polled with a bound rather than slept on
    // for a guessed interval: a test that waits without one reports nothing at all.
    let mut back = None;
    for _ in 0..100 {
        match connect(&address, SECRET).await {
            Ok(client) => {
                back = Some(client);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let next = back.expect("the slot never came back, so the cap is reached once and for ever");
    assert!(next.simple_query("SELECT 1").await.is_ok());
}

/// A routable bind with no provider must not open a port, and the message must say
/// what this port serves so an operator understands why.
#[test]
fn a_routable_bind_without_a_provider_will_not_start() {
    let config = Config {
        bind: "192.0.2.1:5432".parse().unwrap(),
        ..Config::default()
    };
    let error = check(&config, None).expect_err("must refuse");
    assert!(matches!(error, StartError::RoutableWithoutAuth(_)));
    assert!(error.to_string().contains("audit trail"), "{error}");
}

/// Loopback with no provider is tolerated, because the port is the boundary there,
/// and it still only permits querying.
#[tokio::test]
async fn a_loopback_bind_with_no_provider_serves_reads_and_nothing_else() {
    let address = start(Config::default(), None).await;
    let client = connect(&address, "anything")
        .await
        .expect("loopback connects");
    assert!(client.simple_query("SELECT 1").await.is_ok());
    assert!(client.simple_query("DROP TABLE records").await.is_err());
}
