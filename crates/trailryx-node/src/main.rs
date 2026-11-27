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

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use trailryx_contracts::contracts::Source;
use trailryx_index::completeness::Dimension;
use trailryx_ingest::agent_door::{AgentTokenFlags, FLAGS_HELP, gate_from_flags};
use trailryx_ingest::auth::Gate;
use trailryx_ingest::bearer::SharedSecret;
use trailryx_ingest::config::Config;
use trailryx_ingest::handler::Ingest;
use trailryx_ingest::server::{Server, stderr_log};
use trailryx_node::keyryx::{KeyryxSigner, parse_pin};
use trailryx_node::plane::{Plane, SealPolicy, seed_from_process};
use trailryx_node::signing::{self, Outcome};
use trailryx_node::{Resume, Ship, reader, ship};
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::{ShardIx, TenantId, Timestamp};
use trailryx_store::query::{Query, query_segment};

const USAGE: &str = "\
trailryx-node run  [--data DIR] [--bind ADDR:PORT] [--token-file PATH]
                   [--agent-token-issuer URL --agent-token-audience AUD
                    --agent-token-jwks PATH --agent-token-origin URL]
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

Signing is optional. With TRAILRYX_SIGNER=keyryx, TRAILRYX_KEYRYX_URL (an http origin),
TRAILRYX_KEYRYX_KID (the kid Keyryx publishes for its key, which the node pins to) and
TRAILRYX_KEYRYX_CREDENTIAL_FILE (the consumer credential), each sealed root is signed by
Keyryx, and a signature is kept only if it verifies under that key. A root that cannot be
signed is queued beside the data and signed when Keyryx answers, and the records are sealed
either way. read --pack attaches the signature for the root it packs, and any witness
attestation filed under TRAILRYX_WITNESS_ATTESTATIONS.

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
            println!("{USAGE}\n\nThe agent-token door, for run:\n\n{FLAGS_HELP}");
            ExitCode::SUCCESS
        }
        Some(other) => fail(&format!("unknown command {other}; try --help")),
    }
}

/// Whole seconds for the agent-token door's clock, read here: the ingest
/// library never reads a clock of its own.
fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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
        if flag == "--help" {
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

fn now_timestamp() -> Timestamp {
    Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    )
}

/// How long a queued root waits before the next attempt after one that failed. An attempt
/// costs at most the connect and I/O timeouts, once, and never once per record.
const SIGN_RETRY: Duration = Duration::from_secs(30);

/// The signer the seal uses, from the environment. Unset means no signer, and the seal
/// stays as it was. `keyryx` takes the Keyryx at TRAILRYX_KEYRYX_URL and presents the
/// consumer credential in the file TRAILRYX_KEYRYX_CREDENTIAL_FILE, and signs only under the
/// key whose thumbprint is TRAILRYX_KEYRYX_KID. Anything else, or a setting missing, is
/// refused at start rather than sealing unsigned.
fn keyryx_signer() -> Result<Option<KeyryxSigner>, String> {
    let kind = match std::env::var("TRAILRYX_SIGNER") {
        Ok(kind) => kind,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(e) => return Err(format!("TRAILRYX_SIGNER: {e}")),
    };
    if kind != "keyryx" {
        return Err(format!(
            "TRAILRYX_SIGNER={kind} is not a signer this build has; the one it has is keyryx"
        ));
    }
    let origin = std::env::var("TRAILRYX_KEYRYX_URL").map_err(|_| {
        "TRAILRYX_SIGNER=keyryx needs TRAILRYX_KEYRYX_URL, such as http://keyryx:4340".to_owned()
    })?;
    let pin_text = std::env::var("TRAILRYX_KEYRYX_KID").map_err(|_| {
        "TRAILRYX_SIGNER=keyryx needs TRAILRYX_KEYRYX_KID, the kid Keyryx publishes for the key this node signs under"
            .to_owned()
    })?;
    let pin = parse_pin(&pin_text).map_err(|why| format!("TRAILRYX_KEYRYX_KID: {why}"))?;
    let credential_path = std::env::var("TRAILRYX_KEYRYX_CREDENTIAL_FILE").map_err(|_| {
        "TRAILRYX_SIGNER=keyryx needs TRAILRYX_KEYRYX_CREDENTIAL_FILE, the file holding the consumer credential"
            .to_owned()
    })?;
    let credential = std::fs::read_to_string(&credential_path)
        .map_err(|e| format!("cannot read {credential_path}: {e}"))?;
    let bearer = credential.trim();
    if bearer.is_empty() {
        return Err(format!("{credential_path} holds no credential"));
    }
    KeyryxSigner::new(&origin, bearer, &pin)
        .map(Some)
        .map_err(|e| format!("TRAILRYX_KEYRYX_URL {origin}: {e}"))
}

/// Queue what the seal left and sign it, saying what happened. Returns when the next
/// attempt is due.
fn sign_and_report(
    dir: &Path,
    shard: ShardIx,
    tenant: &TenantId,
    signer: &mut KeyryxSigner,
    now: Timestamp,
) -> Instant {
    match signing::sign_sealed(dir, shard, tenant, signer, now) {
        Ok(Outcome::Clear) => {}
        Ok(Outcome::Signed(count)) => println!("keyryx signed {count} root(s)"),
        Ok(Outcome::Queued { waiting, why }) => eprintln!(
            "trailryx-node: keyryx did not sign; {waiting} root(s) are queued and the \
             records stay sealed: {why}"
        ),
        Err(why) => eprintln!("trailryx-node: the signing queue could not be written: {why}"),
    }
    Instant::now() + SIGN_RETRY
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
        println!("{USAGE}\n\nThe agent-token door, for run:\n\n{FLAGS_HELP}");
        return ExitCode::SUCCESS;
    }

    let dir = data_dir(&flags);
    let shard = match shard_of(&flags) {
        Ok(shard) => shard,
        Err(why) => return fail(&why),
    };
    let agent_flags = AgentTokenFlags {
        issuer: value(&flags, "--agent-token-issuer"),
        audience: value(&flags, "--agent-token-audience"),
        jwks: value(&flags, "--agent-token-jwks"),
        origin: value(&flags, "--agent-token-origin"),
    };
    // One door, one way in, and said before anything is opened: a door that
    // also took the fleet secret would let any holder of it write as any agent.
    if agent_flags.any() && value(&flags, "--token-file").is_some() {
        return fail("pass --token-file or the --agent-token-* flags, not both");
    }
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
    let mut signer = match keyryx_signer() {
        Ok(signer) => signer,
        Err(why) => return fail(&why),
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
    let agent_tokens = agent_flags.any();
    match gate_from_flags(
        agent_flags,
        &tenant_name,
        &trust_domain,
        Box::new(unix_seconds),
    ) {
        Ok(Some(gate)) => ingest = ingest.with_auth(gate),
        Ok(None) => {}
        Err(why) => return fail(&why),
    }
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
        Err(e) if value(&flags, "--token-file").is_none() && !agent_tokens => {
            return fail(&format!(
                "cannot bind: {e}\n\
                 trailryx-node: from this binary, that means: pass --token-file PATH, where \
                 PATH holds one shared secret, or the four --agent-token-* flags, or keep the \
                 port private with --bind 127.0.0.1:4318"
            ));
        }
        Err(e) => return fail(&format!("cannot bind: {e}")),
    };
    println!("listening on {}", server.address());
    if agent_tokens {
        println!(
            "each agent writes with its own token and proof; a span naming another agent is \
             refused, and the refusal is written down as a record"
        );
    }
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
    if signer.is_some() {
        println!("roots are signed by keyryx, and queued while it cannot sign");
    }

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
    let mut sign_again = Instant::now();
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

        let mut sealed_now = false;
        match plane.tick(now) {
            Ok(Some(sealed)) => {
                println!(
                    "sealed {} with {} record(s); manifest {}",
                    sealed.segment,
                    sealed.records,
                    sealed.manifest_path.display()
                );
                sealed_now = true;
            }
            Ok(None) => {}
            Err(why) => {
                eprintln!("trailryx-node: sealing failed: {why}");
                return ExitCode::FAILURE;
            }
        }
        // A seal is signed as soon as it is made. Until Keyryx answers, a queued root is
        // retried on the retry interval, so an outage costs one attempt per interval.
        if let Some(signer) = signer.as_mut()
            && (sealed_now || Instant::now() >= sign_again)
        {
            sign_again = sign_and_report(plane.dir(), plane.shard(), plane.tenant(), signer, now);
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

    let mut signer = match keyryx_signer() {
        Ok(signer) => signer,
        Err(why) => return fail(&why),
    };
    let signing_tenant = tenant.clone();
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
    // What this run sealed is signed before the run reports, so a timer that runs this
    // command leaves nothing it sealed waiting for the next run.
    if let Some(signer) = signer.as_mut() {
        sign_and_report(&dir, shard, &signing_tenant, signer, now_timestamp());
    }

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
         claimed_subject {} unknown_type {} no_run_id {} bad_time {}",
        r.not_an_envelope,
        r.unknown_schema,
        r.no_agent,
        r.foreign_trust_domain,
        r.claimed_subject,
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
    if shipped.held_for_trust_domain {
        // Loud, and it names the argument rather than the counter, because the
        // counter is already printed above and told nobody anything: this run
        // read the file, stored none of it, and the reason is a value the
        // caller passed. The position is deliberately where it was, so the
        // same bytes are still here once that value is right.
        // "nothing was stored" is about THIS region, and on a run that resumed
        // after a crash it would be printed directly under a `sealed ...` line
        // holding the previous run's recovered records, contradicting it. The
        // ordering is right (a seal that failed never reaches the commit) and
        // only the wording would lie, so the wording changes.
        let stored = if shipped.sealed.is_empty() {
            "nothing was stored"
        } else {
            "nothing NEW was stored, and the segment sealed above holds records \
             recovered from an earlier run"
        };
        println!(
            "cursor: NOT moved. Every line this run read names an agent outside the \
             trust domain it was given, and {stored}, so the position stays at byte \
             {} rather than marking those lines read. Give --trust-domain the domain \
             this bus actually mints under and run it again.",
            shipped.cursor.bytes
        );
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
        // The pack carries what Keyryx made of this root, if it made anything of it: the
        // signature over exactly this root, and the witnesses filed for it. A root still
        // in the queue is packed unsigned, and the verifier says so.
        let root = reader::trees(&held).1.root();
        let signed = match signing::signed_root(&dir, root) {
            Ok(signed) => signed,
            Err(why) => return fail(&format!("{}: {why}", dir.display())),
        };
        let witnesses = match std::env::var_os("TRAILRYX_WITNESS_ATTESTATIONS") {
            Some(folder) => match signing::witnesses_for(Path::new(&folder), &tenant, root) {
                Ok(witnesses) => witnesses,
                Err(why) => return fail(&format!("{}: {why}", folder.to_string_lossy())),
            },
            None => Vec::new(),
        };
        if signed.is_none() {
            println!("this root has no keyryx signature yet, so the pack is unsigned");
        }
        let bytes = reader::pack_attested(&held, &tenant, signed, witnesses, now_timestamp());
        if let Err(e) = std::fs::write(path, &bytes) {
            return fail(&format!("cannot write {path}: {e}"));
        }
        println!("{} bytes written to {path}", bytes.len());
        println!("check it with somebody else's code: trailryx-verify {path}");
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENTS: &str = concat!(
        r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","source":"tokenfuse","type":"budget_exhausted","severity":"critical","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","on_behalf_of":["user://acme.example/j.doe"],"data":{"budget_usd":2.0,"spent_usd":2.0}}"#,
        "\n",
        r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:45.000Z","source":"wardryx","type":"policy_deny","severity":"high","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","data":{"policy":"prod-deploy"}}"#,
        "\n",
    );

    /// An exit code, in the only form std lets two of them be compared.
    fn code(exit: ExitCode) -> String {
        format!("{exit:?}")
    }

    fn ok() -> String {
        code(ExitCode::SUCCESS)
    }

    fn refused() -> String {
        code(ExitCode::from(2))
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A scratch directory for one test, unique to this process and to the test.
    fn scratch(what: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trailryx-node-main-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    fn text(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn events_then_read_seals_once_and_packs_what_the_verifier_accepts() {
        let dir = scratch("round-trip");
        let file = dir.join("events.ndjson");
        std::fs::write(&file, EVENTS).expect("the events are written");
        let data = dir.join("store");
        let pack = dir.join("pack.trxevid");
        let import = args(&[
            "--file",
            &text(&file),
            "--data",
            &text(&data),
            "--tenant",
            "acme",
            "--trust-domain",
            "acme.example",
        ]);

        let first = code(events(import.clone()));
        let after_first = reader::read_sealed(&data, ShardIx(0))
            .ok()
            .map(|held| held.records());
        let second = code(events(import));
        let after_second = reader::read_sealed(&data, ShardIx(0))
            .ok()
            .map(|held| held.records());
        let queries = [
            code(read(args(&["--data", &text(&data), "--all"]))),
            code(read(args(&[
                "--data",
                &text(&data),
                "--agent",
                "agent://acme.example/support/tier1-bot",
            ]))),
            code(read(args(&["--data", &text(&data), "--run", "run-8842"]))),
        ];
        let packed = code(read(args(&[
            "--data",
            &text(&data),
            "--all",
            "--pack",
            &text(&pack),
        ])));
        let bytes = std::fs::read(&pack);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(first, ok(), "the import failed");
        let sealed = after_first.expect("the directory reads back after the import");
        assert!(sealed >= 2, "two lines sealed {sealed} records");
        assert_eq!(second, ok(), "a second import of the same file failed");
        assert_eq!(
            after_second,
            Some(sealed),
            "a second import of an unchanged file stored its records again"
        );
        assert_eq!(queries, [ok(), ok(), ok()]);
        assert_eq!(packed, ok(), "the pack was not written");
        let report =
            trailryx_verify::verify(&bytes.expect("the pack is on disk")).expect("the pack parses");
        assert!(report.verified(), "the pack read writes does not verify");
        assert_eq!(
            usize::try_from(report.records_checked).ok(),
            Some(sealed),
            "the pack holds every sealed record and nothing else"
        );
    }

    #[test]
    fn a_directory_with_nothing_sealed_has_nothing_to_pack() {
        let dir = scratch("empty");
        let pack = dir.join("pack.trxevid");
        let answer = code(read(args(&[
            "--data",
            &text(&dir.join("store")),
            "--pack",
            &text(&pack),
        ])));
        let written = pack.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(answer, refused());
        assert!(!written, "a pack of nothing was written");
    }

    #[test]
    fn a_flag_without_its_value_or_an_argument_that_is_not_a_flag_is_refused() {
        assert_eq!(
            flags(args(&["--data"])),
            Err("--data needs a value".to_owned())
        );
        assert_eq!(
            flags(args(&["data", "dir"])),
            Err("unexpected argument data".to_owned())
        );
        assert_eq!(
            flags(args(&["--all", "--shard", "3", "--help"])),
            Ok(vec![
                ("--all".to_owned(), String::new()),
                ("--shard".to_owned(), "3".to_owned()),
                ("--help".to_owned(), String::new()),
            ]),
            "--all and --help take no value and the rest take one each"
        );
    }

    #[test]
    fn numbers_and_shards_are_read_strictly_and_fall_back_only_when_absent() {
        let given = flags(args(&["--shard", "7", "--seal-records", "x"])).expect("flags");
        assert_eq!(number(&given, "--drain-ms", 250), Ok(250));
        assert_eq!(number(&given, "--shard", 0), Ok(7));
        assert_eq!(
            number(&given, "--seal-records", 4_096),
            Err("--seal-records x is not a number".to_owned())
        );
        assert_eq!(shard_of(&given), Ok(ShardIx(7)));
        let past = flags(args(&["--shard", "65536"])).expect("flags");
        assert_eq!(
            shard_of(&past),
            Err("--shard 65536 is past the number of shards a store can have".to_owned())
        );
        let last = flags(args(&["--shard", "65535"])).expect("flags");
        assert_eq!(shard_of(&last), Ok(ShardIx(65_535)));
        assert_eq!(data_dir(&[]), PathBuf::from("trailryx-data"));
    }

    #[test]
    fn each_command_answers_help_and_refuses_what_it_cannot_start_with() {
        let dir = scratch("refusals");
        let data = text(&dir.join("store"));
        let missing = text(&dir.join("absent.ndjson"));
        let answers = [
            code(events(args(&["--help"]))),
            code(read(args(&["--help"]))),
            code(run(args(&["--help"]))),
        ];
        let refusals = [
            code(events(args(&["--data", &data]))),
            code(events(args(&["--file", &missing, "--data", &data]))),
            code(events(args(&["--file", &missing, "--shard", "70000"]))),
            code(events(args(&[
                "--file",
                &missing,
                "--tenant",
                "Not A Tenant",
            ]))),
            code(events(args(&[
                "--file",
                &missing,
                "--seal-records",
                "many",
            ]))),
            code(events(args(&["--file"]))),
            code(read(args(&["--shard", "x"]))),
            code(read(args(&["stray"]))),
            code(run(args(&["--shard", "70000"]))),
            code(run(args(&["--tenant", "Not A Tenant"]))),
            code(run(args(&["--seal-records", "x"]))),
            code(run(args(&["--seal-seconds", "x"]))),
            code(run(args(&["--sync-every", "x"]))),
            code(run(args(&["--drain-ms", "x"]))),
            code(run(args(&["--bind", "not-an-address"]))),
            code(run(args(&[
                "--token-file",
                &missing,
                "--agent-token-issuer",
                "https://issuer.example",
            ]))),
        ];
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(answers, [ok(), ok(), ok()]);
        for (n, answer) in refusals.iter().enumerate() {
            assert_eq!(answer, &refused(), "case {n} was not refused");
        }
    }

    #[test]
    fn run_opens_the_plane_and_refuses_a_port_it_may_not_or_cannot_take() {
        let dir = scratch("bind");
        let data = text(&dir.join("store"));
        let secret = dir.join("secret");
        std::fs::write(&secret, "a-fleet-secret\n").expect("the secret is written");
        let empty = dir.join("empty-secret");
        std::fs::write(&empty, "\n").expect("the empty secret is written");
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = taken.local_addr().expect("its address").to_string();

        // Routable with no credential: the server refuses to bind at all.
        let open_to_all = code(run(args(&["--data", &data, "--bind", "0.0.0.0:0"])));
        let opened = dir.join("store").exists();
        // A credential that cannot be read, or holds nothing, is refused before any port.
        let unreadable = code(run(args(&[
            "--data",
            &data,
            "--token-file",
            &text(&dir.join("absent")),
        ])));
        let blank = code(run(args(&["--data", &data, "--token-file", &text(&empty)])));
        // A port somebody else holds, with and without a credential.
        let busy = code(run(args(&["--data", &data, "--bind", &port])));
        let busy_with_secret = code(run(args(&[
            "--data",
            &data,
            "--bind",
            &port,
            "--token-file",
            &text(&secret),
        ])));
        drop(taken);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            opened,
            "the plane was not opened before the port was offered"
        );
        assert_eq!(open_to_all, refused());
        assert_eq!(unreadable, refused());
        assert_eq!(blank, refused());
        assert_eq!(busy, refused());
        assert_eq!(busy_with_secret, refused());
    }
}
