//! `trailryx-ingest --bind 127.0.0.1:4318`
//!
//! A runnable receiver, and the smallest honest example of what an embedding
//! store has to do around it. The server itself only ever calls `accept`, so
//! this binary does the other half: it drains the source on a timer and turns
//! whatever was lost into a record. A store that skips that accumulates records
//! nobody collects and holes nobody wrote down.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use trailryx_contracts::contracts::Source;
use trailryx_ingest::config::Config;
use trailryx_ingest::handler::Ingest;
use trailryx_ingest::server::{Server, stderr_log};
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::{TenantId, Timestamp};

fn main() -> std::process::ExitCode {
    let mut config = Config::default();
    let mut tenant = "acme".to_owned();
    let mut trust_domain = "acme.example".to_owned();

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next();
        match (flag.as_str(), value) {
            ("--bind", Some(v)) => match v.parse() {
                Ok(addr) => config.bind = addr,
                Err(_) => return fail(&format!("--bind {v} is not an address:port")),
            },
            ("--tenant", Some(v)) => tenant = v,
            ("--trust-domain", Some(v)) => trust_domain = v,
            ("--help", _) => {
                println!(
                    "trailryx-ingest [--bind ADDR:PORT] [--tenant NAME] [--trust-domain DOMAIN]\n\
                     \n\
                     Accepts OTLP/HTTP traces. No TLS and no authentication: anything that\n\
                     can reach the port can write records. Put a proxy in front of a\n\
                     routable bind."
                );
                return std::process::ExitCode::SUCCESS;
            }
            (other, _) => return fail(&format!("unknown argument {other}")),
        }
    }

    let Ok(tenant_id) = TenantId::parse(tenant.clone()) else {
        return fail(&format!("--tenant {tenant} is not a valid identifier"));
    };
    let Ok(mapper) = MapperConfig::new(tenant_id, &trust_domain) else {
        return fail(&format!("--trust-domain {trust_domain} is not usable"));
    };

    // The store's clock, injected. The server never reaches for one.
    let clock = Box::new(|| {
        Timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        )
    });
    let ingest = Arc::new(Ingest::new(OtlpSource::new(mapper), config, clock));
    let server = match Server::bind(Arc::clone(&ingest)) {
        Ok(server) => Arc::new(server),
        Err(e) => return fail(&format!("cannot bind: {e}")),
    };
    println!("listening on {}", server.address());
    if server.address().ip().is_loopback() {
        println!("loopback only. there is no TLS and no authentication here.");
    } else {
        println!(
            "WARNING: {} is reachable from the network, and this server has no TLS and no \
             authentication. Anything that reaches it can write records.",
            server.address()
        );
    }

    // The embedding store's half: drain, and write down what was lost.
    let draining = Arc::clone(&ingest);
    std::thread::Builder::new()
        .name("trailryx-drain".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let stamp = Timestamp(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0),
                );
                let drained = draining.with_source(|source| {
                    let batch = source.poll(4096).unwrap_or_default();
                    // A real store would seal these into a segment here. This
                    // one counts them, so the demo shows arrival without
                    // pretending to be a store.
                    let anomaly = source.anomaly_event(stamp);
                    (batch.len(), anomaly.is_some())
                });
                if let Some((n, anomaly)) = drained
                    && (n > 0 || anomaly)
                {
                    println!(
                        "drained {n} records{}",
                        if anomaly {
                            ", and wrote down a loss"
                        } else {
                            ""
                        }
                    );
                }
            }
        })
        .ok();

    server.serve(stderr_log());
    std::process::ExitCode::SUCCESS
}

fn fail(why: &str) -> std::process::ExitCode {
    eprintln!("trailryx-ingest: {why}");
    std::process::ExitCode::from(2)
}
