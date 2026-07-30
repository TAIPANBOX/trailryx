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
use trailryx_ingest::auth::Gate;
use trailryx_ingest::bearer::SharedSecret;
use trailryx_ingest::config::Config;
use trailryx_ingest::handler::Ingest;
use trailryx_ingest::server::{Server, stderr_log};
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::{TenantId, Timestamp};

fn main() -> std::process::ExitCode {
    let mut config = Config::default();
    let mut tenant = "acme".to_owned();
    let mut trust_domain = "acme.example".to_owned();
    let mut token_file: Option<String> = None;

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
            ("--token-file", Some(v)) => token_file = Some(v),
            ("--help", _) => {
                println!(
                    "trailryx-ingest [--bind ADDR:PORT] [--tenant NAME] [--trust-domain DOMAIN]\n\
                     \x20               [--token-file PATH]\n\
                     \n\
                     Accepts OTLP/HTTP traces.\n\
                     \n\
                     --token-file names a file holding one shared secret. Exporters then\n\
                     present it as `Authorization: Bearer <secret>` and anything else is\n\
                     refused before a body is read. Without it the port is open to whatever\n\
                     can reach it, which is why a routable --bind requires it and refuses\n\
                     to start without one.\n\
                     \n\
                     There is no TLS here either way. A routable bind belongs behind a\n\
                     terminating proxy: on a plaintext hop the secret is readable on the\n\
                     wire by anything between the exporter and this port."
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
    let mut ingest = Ingest::new(OtlpSource::new(mapper), config, clock);
    if let Some(path) = &token_file {
        // Read here and not stored: the file's bytes live in this scope, and
        // what the gate keeps is a digest of them.
        let secret = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => return fail(&format!("cannot read --token-file {path}: {e}")),
        };
        let provider = match SharedSecret::new(&secret, tenant.clone()) {
            Ok(provider) => provider,
            Err(e) => return fail(&format!("--token-file {path}: {e}")),
        };
        ingest = ingest.with_auth(Gate::new(Box::new(provider), tenant.clone()));
    }
    let ingest = Arc::new(ingest);
    let server = match Server::bind(Arc::clone(&ingest)) {
        Ok(server) => Arc::new(server),
        Err(e) => return fail(&format!("cannot bind: {e}")),
    };
    println!("listening on {}", server.address());
    // Said in full, because these are the two questions an operator has about
    // this port and the answers are independent of each other.
    match (server.address().ip().is_loopback(), token_file.is_some()) {
        (true, false) => {
            println!("loopback only, and no authentication: whatever runs on this host can write.");
        }
        (true, true) => println!("loopback only, and a shared secret is required. No TLS."),
        (false, true) => println!(
            "WARNING: {} is reachable from the network. A shared secret is required, but there \
             is no TLS here, so the secret is readable on the wire. Terminate TLS in front of it.",
            server.address()
        ),
        // Unreachable: `Server::bind` refuses this combination and the error
        // above has already returned. Printed rather than omitted so that if the
        // refusal is ever weakened, the port still says what it is.
        (false, false) => println!(
            "WARNING: {} is reachable from the network with no authentication and no TLS.",
            server.address()
        ),
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
