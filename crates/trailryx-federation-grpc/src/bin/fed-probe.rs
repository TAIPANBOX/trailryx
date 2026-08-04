//! One federation peer, or one query across several, from a command line.
//!
//! The integration suite proves the rule over loopback. This binary is the same
//! code with the two halves on different machines, which is the only way to find
//! out what a real network does to it: latency that is not zero, an MTU, a
//! middlebox, and a partition where both sides are alive and each believes the
//! other is gone.
//!
//! Deliberately small and deliberately not a service. It reads key material from
//! files, does one thing, and prints a result a script can assert on.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use trailryx_federation::Registry;
use trailryx_federation_grpc::{
    ClientIdentity, GrpcPeer, ServedProof, ServerIdentity, fan_out, serve,
};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};

fn usage() -> ! {
    eprintln!(
        "usage:
  fed-probe serve --name <peer> --bind <addr:port> --cert <pem> --key <pem> \\
                  --client-ca <pem> --records <n> [--partial]

  fed-probe query --peer <name>=<host:port> [--peer ...] --registry <name,name> \\
                  --cert <pem> --key <pem> --server-ca <pem> [--timeout-secs <n>]

`query` exits 0 when the composed answer is FULL, 1 when it is not, and prints
one line per peer plus a summary. Anything else is a usage or setup error."
    );
    std::process::exit(2)
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn arg_all(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        }
    }
    out
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(2)
    })
}

/// A record that is real enough to travel: every identifier goes through the
/// same constructors the far side will re-run on arrival.
fn record(seq: u64) -> Record {
    Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").expect("a tenant"),
        shard: ShardIx(0),
        agent_id: AgentId::parse_strict("agent://acme.example/support").expect("an agent"),
        run_id: RunId::parse("run-1").expect("a run"),
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => serve_cmd(&args),
        Some("query") => query_cmd(&args),
        _ => usage(),
    }
}

fn serve_cmd(args: &[String]) -> ! {
    let name = arg(args, "--name").unwrap_or_else(|| usage());
    let bind: SocketAddr = arg(args, "--bind")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap_or_else(|e| {
            eprintln!("--bind is not an address: {e}");
            std::process::exit(2)
        });
    let n: u64 = arg(args, "--records")
        .unwrap_or_else(|| "3".to_owned())
        .parse()
        .unwrap_or(3);
    let proof = if args.iter().any(|a| a == "--partial") {
        ServedProof::Partial(vec![
            trailryx_federation_grpc::Incompleteness::SegmentUnavailable,
        ])
    } else {
        ServedProof::Full
    };

    let identity = ServerIdentity {
        cert_pem: read(&arg(args, "--cert").unwrap_or_else(|| usage())),
        key_pem: read(&arg(args, "--key").unwrap_or_else(|| usage())),
        client_ca_pem: read(&arg(args, "--client-ca").unwrap_or_else(|| usage())),
    };

    let running = serve(bind, (0..n).map(record).collect(), proof, identity).unwrap_or_else(|e| {
        eprintln!("cannot serve: {e}");
        std::process::exit(2)
    });
    println!("serving {name} on {} with {n} records", running.addr());

    // The server owns its runtime and stops when dropped, so the process has to
    // stay alive on purpose rather than by accident.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn query_cmd(args: &[String]) -> ! {
    let identity = ClientIdentity {
        cert_pem: read(&arg(args, "--cert").unwrap_or_else(|| usage())),
        key_pem: read(&arg(args, "--key").unwrap_or_else(|| usage())),
        server_ca_pem: read(&arg(args, "--server-ca").unwrap_or_else(|| usage())),
    };
    let timeout = Duration::from_secs(
        arg(args, "--timeout-secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(10),
    );
    let registry_names: Vec<String> = arg(args, "--registry")
        .unwrap_or_else(|| usage())
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    let mut peers = Vec::new();
    for spec in arg_all(args, "--peer") {
        let Some((name, addr)) = spec.split_once('=') else {
            usage()
        };
        let addr: SocketAddr = addr.parse().unwrap_or_else(|e| {
            eprintln!("--peer {spec}: not an address: {e}");
            std::process::exit(2)
        });
        let started = Instant::now();
        match GrpcPeer::connect(name, addr, identity.clone(), timeout) {
            Ok(p) => {
                println!(
                    "peer {name} at {addr}: handshake ok in {} ms",
                    started.elapsed().as_millis()
                );
                peers.push(p);
            }
            // Not fatal, and that is the point: a peer that cannot be reached is
            // silent, and silence is what the rule is supposed to notice.
            Err(e) => println!("peer {name} at {addr}: UNREACHABLE ({e})"),
        }
    }

    // Attested on purpose: the question under test is what happens when a member
    // of a signed set does not answer, which an unattested registry would mask
    // by refusing a full proof for its own separate reason.
    let registry = Registry::attested(1, registry_names, true);
    let started = Instant::now();
    let (federated, failures) = fan_out(&registry, &mut peers, "recorded_at >= 0");
    let elapsed = started.elapsed();

    for (name, err) in &failures {
        println!("peer {name}: FAILED ({err})");
    }
    println!("records: {}", federated.records.len());
    println!("silent: {:?}", federated.silent);
    println!("unexpected: {:?}", federated.unexpected);
    println!("fan-out took {} ms", elapsed.as_millis());
    println!("proof: {:?}", federated.proof);

    if federated.proof.is_full() {
        println!("VERDICT: complete");
        std::process::exit(0)
    }
    println!("VERDICT: not complete");
    std::process::exit(1)
}
