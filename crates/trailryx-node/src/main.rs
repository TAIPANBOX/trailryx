//! `trailryx-node run --data DIR` and `trailryx-node read --data DIR`.
//!
//! The record plane as one process. `run` accepts OTLP over HTTP, writes every
//! record to the journal, and seals a segment on a schedule; `read` opens the
//! directory that leaves behind, rebuilds every sealed segment from the journal's
//! own bytes and answers a query with whatever proof it carries.
//!
//! What this process does not do is printed by `run` at startup rather than left
//! in a document: no payload plane, no object store, no SQL port, no TLS. Each of
//! those is a real gap and each is a smaller lie than a store that implied it had
//! them. See the crate documentation for why the payload plane is absent rather
//! than stubbed.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use trailryx_contracts::contracts::Source;
use trailryx_index::completeness::Dimension;
use trailryx_ingest::auth::Gate;
use trailryx_ingest::bearer::SharedSecret;
use trailryx_ingest::config::Config;
use trailryx_ingest::handler::Ingest;
use trailryx_ingest::server::{Server, stderr_log};
use trailryx_node::plane::{Plane, SealPolicy, seed_from_process};
use trailryx_node::{Resume, Ship, reader, ship};
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::{ShardIx, TenantId, Timestamp};
use trailryx_store::query::{Query, query_segment};

const USAGE: &str = "\
trailryx-node run  [--data DIR] [--bind ADDR:PORT] [--token-file PATH]
                   [--tenant NAME] [--trust-domain DOMAIN] [--shard N]
                   [--seal-records N] [--seal-seconds S] [--sync-every N]
                   [--drain-ms MS]
trailryx-node read [--data DIR] [--shard N] [--agent ID | --run ID | --all]
                   [--pack FILE]
trailryx-node events --file PATH [--data DIR] [--tenant NAME]
                   [--trust-domain DOMAIN] [--shard N] [--seal-records N]

run   accepts OTLP/HTTP traces, writes every record to the journal, syncs on a
      policy and seals a segment on a schedule. Records land under --data.

read  rebuilds every sealed segment from the journal's own bytes, refuses any
      that does not rebuild the manifest published for it, and answers a query
      with its completeness proof. --pack writes an evidence pack the offline
      verifier reads.

events reads a file of the estate's shared agent-event NDJSON envelope
      (taipanbox.dev/agent-event v0.1 or v0.2), maps every line it can into a
      record, seals what it wrote, and says by name what it could not map.
      It is safe to put on a timer: it remembers where it stopped in each file,
      beside the data, and takes only what has arrived since. A file that was
      truncated or replaced under the same name is read from the beginning and
      the run says which of those happened.
      It seals every --seal-records records and writes its position down after
      each seal, so a run that is killed costs a re-import of the records it
      had written and not sealed, and of nothing before them. A smaller number
      is a smaller window and one more fsync per segment.

This process keeps the metadata plane only. It has no key custodian, so payload
parts a source hands over are declined and counted, and the count is written
down as a record. It does not publish to object storage and it serves no SQL
port. There is no TLS on the ingest port: put a terminating proxy in front.";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run") => run(args.collect()),
        Some("read") => read(args.collect()),
        Some("events") => events(args.collect()),
        Some("--help") | Some("-h") | None => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => fail(&format!("unknown command {other}; try --help")),
    }
}

fn fail(why: &str) -> ExitCode {
    eprintln!("trailryx-node: {why}");
    ExitCode::from(2)
}

/// Flags, as `--name value` pairs, with everything else refused.
///
/// A flag whose value is missing is an error rather than a default: a node that
/// silently bound somewhere other than where it was told is the failure mode this
/// whole binary exists to avoid.
fn flags(args: Vec<String>) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        if flag == "--all" || flag == "--help" {
            out.push((flag, String::new()));
            continue;
        }
        let Some(value) = it.next() else {
            return Err(format!("{flag} needs a value"));
        };
        if !flag.starts_with("--") {
            return Err(format!("unexpected argument {flag}"));
        }
        out.push((flag, value));
    }
    Ok(out)
}

fn value<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .find(|(flag, _)| flag == name)
        .map(|(_, v)| v.as_str())
}

fn number(flags: &[(String, String)], name: &str, fallback: u64) -> Result<u64, String> {
    match value(flags, name) {
        Some(raw) => raw
            .parse()
            .map_err(|_| format!("{name} {raw} is not a number")),
        None => Ok(fallback),
    }
}

fn data_dir(flags: &[(String, String)]) -> PathBuf {
    PathBuf::from(value(flags, "--data").unwrap_or("trailryx-data"))
}

fn shard_of(flags: &[(String, String)]) -> Result<ShardIx, String> {
    let n = number(flags, "--shard", 0)?;
    u16::try_from(n)
        .map(ShardIx)
        .map_err(|_| format!("--shard {n} is past the number of shards a store can have"))
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

fn run(args: Vec<String>) -> ExitCode {
    let flags = match flags(args) {
        Ok(flags) => flags,
        Err(why) => return fail(&why),
    };
    if value(&flags, "--help").is_some() {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let dir = data_dir(&flags);
    let shard = match shard_of(&flags) {
        Ok(shard) => shard,
        Err(why) => return fail(&why),
    };
    let tenant_name = value(&flags, "--tenant").unwrap_or("acme").to_owned();
    let trust_domain = value(&flags, "--trust-domain")
        .unwrap_or("acme.example")
        .to_owned();
    let Ok(tenant) = TenantId::parse(tenant_name.clone()) else {
        return fail(&format!("--tenant {tenant_name} is not a valid identifier"));
    };

    let policy = SealPolicy {
        seal_after_records: match number(&flags, "--seal-records", 4_096) {
            Ok(n) => n.max(1),
            Err(why) => return fail(&why),
        },
        seal_after_nanos: match number(&flags, "--seal-seconds", 60) {
            Ok(s) => s.saturating_mul(1_000_000_000).max(1),
            Err(why) => return fail(&why),
        },
        sync_every: match number(&flags, "--sync-every", 64) {
            Ok(n) => n.max(1),
            Err(why) => return fail(&why),
        },
    };
    let drain = Duration::from_millis(match number(&flags, "--drain-ms", 250) {
        Ok(ms) => ms.max(1),
        Err(why) => return fail(&why),
    });

    let mut config = Config::default();
    if let Some(bind) = value(&flags, "--bind") {
        match bind.parse() {
            Ok(addr) => config.bind = addr,
            Err(_) => return fail(&format!("--bind {bind} is not an address:port")),
        }
    }

    let Ok(mapper) = MapperConfig::new(tenant.clone(), &trust_domain) else {
        return fail(&format!("--trust-domain {trust_domain} is not usable"));
    };

    // The plane first, so a directory that will not open is reported before a
    // port is offered to anybody. A receiver that accepts records it has nowhere
    // to put is the shape this binary exists to replace.
    let (mut plane, opened) = match Plane::open(
        &dir,
        shard,
        tenant.clone(),
        &trust_domain,
        policy,
        seed_from_process(),
    ) {
        Ok(pair) => pair,
        Err(why) => return fail(&format!("{}: {why}", dir.display())),
    };
    println!(
        "data {}, shard {shard}, writing into {}",
        dir.display(),
        opened.segment
    );
    println!(
        "{} sealed segment(s) already here; recovery took back {} record(s), stopped at {:?}",
        opened.sealed_segments, opened.recovered.records, opened.recovered.stopped_because
    );
    if opened.recovered.is_suspicious() {
        println!(
            "WARNING: recovery is suspicious: {:?}",
            opened.recovered.durability_violation
        );
    }

    // The store's clock, injected. The server never reaches for one.
    let clock = Box::new(|| {
        Timestamp(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        )
    });
    let mut ingest = Ingest::new(OtlpSource::new(mapper), config, clock);
    if let Some(path) = value(&flags, "--token-file") {
        let secret = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => return fail(&format!("cannot read --token-file {path}: {e}")),
        };
        let provider = match SharedSecret::new(&secret, tenant_name.clone()) {
            Ok(provider) => provider,
            Err(e) => return fail(&format!("--token-file {path}: {e}")),
        };
        ingest = ingest.with_auth(Gate::new(Box::new(provider), tenant_name.clone()));
    }
    let ingest = Arc::new(ingest);
    let server = match Server::bind(Arc::clone(&ingest)) {
        Ok(server) => Arc::new(server),
        Err(e) if value(&flags, "--token-file").is_none() => {
            return fail(&format!(
                "cannot bind: {e}\n\
                 trailryx-node: from this binary, that means: pass --token-file PATH, where \
                 PATH holds one shared secret, or keep the port private with \
                 --bind 127.0.0.1:4318"
            ));
        }
        Err(e) => return fail(&format!("cannot bind: {e}")),
    };
    println!("listening on {}", server.address());
    println!(
        "sealing at {} records or {} seconds, syncing every {} records",
        policy.seal_after_records,
        policy.seal_after_nanos / 1_000_000_000,
        policy.sync_every
    );
    println!(
        "metadata plane only: payload parts are declined and counted. No object store, \
         no SQL port, no TLS."
    );

    let serving = Arc::clone(&server);
    let thread = std::thread::Builder::new()
        .name("trailryx-serve".to_owned())
        .spawn(move || serving.serve(stderr_log()));
    if thread.is_err() {
        return fail("could not start the server thread");
    }

    // The drain loop is the store's half, and it owns the plane: one writer per
    // shard, with no lock, because two writers would be two minters of one
    // sequence.
    loop {
        std::thread::sleep(drain);
        let now = plane.now();
        let batch = match ingest.with_source(|source| source.poll(4_096)) {
            Some(Ok(batch)) => batch,
            Some(Err(e)) => {
                eprintln!("trailryx-node: the source refused a poll: {e}");
                Vec::new()
            }
            None => {
                eprintln!("trailryx-node: the ingest lock is poisoned; stopping");
                let _ = plane.sync();
                return ExitCode::FAILURE;
            }
        };
        let anomaly = ingest
            .with_source(|source| source.anomaly_event(now))
            .flatten();
        let mut units = batch;
        units.extend(anomaly);

        if !units.is_empty() {
            let count = units.len();
            match plane.accept(units, now) {
                Ok(accepted) => {
                    println!(
                        "took {count} unit(s): {} record(s) written, {} duplicate(s), \
                         {} payload part(s) declined",
                        accepted.written, accepted.duplicates, accepted.declined_payload_parts
                    );
                }
                Err(why) => {
                    eprintln!("trailryx-node: the journal refused a record: {why}");
                    let _ = plane.sync();
                    return ExitCode::FAILURE;
                }
            }
        }

        match plane.tick(now) {
            Ok(Some(sealed)) => println!(
                "sealed {} with {} record(s); manifest {}",
                sealed.segment,
                sealed.records,
                sealed.manifest_path.display()
            ),
            Ok(None) => {}
            Err(why) => {
                eprintln!("trailryx-node: sealing failed: {why}");
                return ExitCode::FAILURE;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

fn events(args: Vec<String>) -> ExitCode {
    let flags = match flags(args) {
        Ok(flags) => flags,
        Err(why) => return fail(&why),
    };
    if value(&flags, "--help").is_some() {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some(file) = value(&flags, "--file") else {
        return fail("events needs --file PATH");
    };
    let dir = data_dir(&flags);
    let shard = match shard_of(&flags) {
        Ok(shard) => shard,
        Err(why) => return fail(&why),
    };
    let tenant_name = value(&flags, "--tenant").unwrap_or("acme").to_owned();
    let trust_domain = value(&flags, "--trust-domain")
        .unwrap_or("acme.example")
        .to_owned();
    let Ok(tenant) = TenantId::parse(tenant_name.clone()) else {
        return fail(&format!("--tenant {tenant_name} is not a valid identifier"));
    };
    let policy = SealPolicy {
        seal_after_records: match number(&flags, "--seal-records", 4_096) {
            Ok(n) => n.max(1),
            Err(why) => return fail(&why),
        },
        seal_after_nanos: u64::MAX,
        sync_every: 64,
    };

    let shipped = match ship(&Ship {
        dir: &dir,
        shard,
        tenant,
        trust_domain: &trust_domain,
        policy,
        seed: seed_from_process(),
        file: std::path::Path::new(file),
    }) {
        Ok(shipped) => shipped,
        Err(why) => return fail(&format!("{file}: {why}")),
    };

    // Why this run read what it read, before what it read. A run that started at
    // byte zero because a file was rotated and a run that started there because
    // it had never seen the file are the same output otherwise, and an operator
    // watching a schedule needs to tell them apart.
    if let Resume::Whole(why) = &shipped.resume {
        println!("{file}: {why}");
    }

    if shipped.nothing_new() {
        // The whole point of the command being safe to run again: a reader has to
        // be able to tell "nothing new" from "nothing happened", so this says
        // where it is standing rather than printing a row of zeroes.
        println!(
            "{file}: nothing new. The cursor is at byte {} of {} ({} line(s), {} record(s) so far)",
            shipped.cursor.bytes,
            shipped.cursor.bytes + shipped.held_back,
            shipped.cursor.lines,
            shipped.cursor.records
        );
    } else {
        println!(
            "{file}: bytes {}..{}, {} mapped, {} record(s) written, {} payload part(s) declined",
            shipped.from,
            shipped.to,
            shipped.ingested.report.mapped,
            shipped.ingested.accepted.written,
            shipped.ingested.accepted.declined_payload_parts
        );
    }
    if shipped.held_back > 0 {
        println!(
            "  {} byte(s) of a line with no terminator were left for the next run: a \
             producer that flushes on a timer has not finished writing it",
            shipped.held_back
        );
    }

    // Every reason, by name, including the zeroes: a report that prints only what
    // went wrong cannot be compared with the last one.
    let r = shipped.ingested.report;
    println!(
        "  refused: not_an_envelope {} unknown_schema {} no_agent {} foreign_trust_domain {} \
         unknown_type {} no_run_id {} bad_time {}",
        r.not_an_envelope,
        r.unknown_schema,
        r.no_agent,
        r.foreign_trust_domain,
        r.unknown_type,
        r.no_run_id,
        r.bad_time
    );
    // One line per sealed segment, which is one line per commit point. The
    // position moved after each of them, so this is also the list of places a
    // crash could have left the next run resuming from.
    for sealed in &shipped.sealed {
        println!(
            "sealed {} with {} record(s); manifest {}",
            sealed.segment,
            sealed.records,
            sealed.manifest_path.display()
        );
    }
    if shipped.sealed.is_empty() && !shipped.nothing_new() {
        println!("nothing durable to seal");
    }
    if shipped.cursor_written {
        println!(
            "cursor: byte {}, {} line(s), {} record(s), committed {} time(s), in {}",
            shipped.cursor.bytes,
            shipped.cursor.lines,
            shipped.cursor.records,
            shipped.cursor_commits,
            shipped.cursor_path.display()
        );
    }
    if r.lost() > 0 {
        // Not a failure of this command: the file was read, and what it could not
        // become is counted. The exit code stays zero so a pipeline does not
        // learn to ignore it.
        println!(
            "{} line(s) produced no record. `trailryx-agentevent` documents which types \
             this reading maps and why the rest are refused.",
            r.lost()
        );
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// read
// ---------------------------------------------------------------------------

fn read(args: Vec<String>) -> ExitCode {
    let flags = match flags(args) {
        Ok(flags) => flags,
        Err(why) => return fail(&why),
    };
    if value(&flags, "--help").is_some() {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let dir = data_dir(&flags);
    let shard = match shard_of(&flags) {
        Ok(shard) => shard,
        Err(why) => return fail(&why),
    };

    let held = match reader::read_sealed(&dir, shard) {
        Ok(held) => held,
        Err(why) => return fail(&format!("{}: {why}", dir.display())),
    };
    println!(
        "{} sealed segment(s), {} record(s), in {}",
        held.segments.len(),
        held.records(),
        dir.display()
    );
    for segment in &held.segments {
        let manifest = segment.manifest();
        println!(
            "  {} {} record(s), history root {}, {} .. {}",
            manifest.segment,
            manifest.records,
            &manifest.history_root.to_hex()[..16],
            manifest.first_recorded_at.as_nanos(),
            manifest.last_recorded_at.as_nanos()
        );
    }

    let query = if let Some(agent) = value(&flags, "--agent") {
        Some(Query::point(Dimension::AgentId, agent.as_bytes().to_vec()))
    } else if let Some(run) = value(&flags, "--run") {
        Some(Query::point(Dimension::RunId, run.as_bytes().to_vec()))
    } else if value(&flags, "--all").is_some() {
        Some(Query::range(
            Dimension::RecordedAt,
            Vec::new(),
            vec![0xff; 8],
        ))
    } else {
        None
    };

    if let Some(query) = query {
        let mut rows = 0usize;
        for segment in &held.segments {
            let answer = query_segment(segment, &query);
            for record in &answer.records {
                println!(
                    "  {} seq {} {} {} {}",
                    record.id,
                    record.seq,
                    record.event_type.as_str(),
                    record.agent_id,
                    record.run_id
                );
            }
            rows += answer.records.len();
            println!(
                "  {} answered {} row(s), proof {:?}",
                segment.manifest().segment,
                answer.records.len(),
                answer.proof
            );
        }
        println!("{rows} row(s)");
    }

    if let Some(path) = value(&flags, "--pack") {
        let tenant = match held.segments.first() {
            Some(segment) => segment.records().first().map(|r| r.tenant.clone()),
            None => None,
        };
        let Some(tenant) = tenant else {
            return fail("there is nothing sealed here to pack");
        };
        let at = Timestamp(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        );
        let bytes = reader::pack(&held, &tenant, at);
        if let Err(e) = std::fs::write(path, &bytes) {
            return fail(&format!("cannot write {path}: {e}"));
        }
        println!("{} bytes written to {path}", bytes.len());
        println!("check it with somebody else's code: trailryx-verify {path}");
    }

    ExitCode::SUCCESS
}
