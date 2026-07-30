//! `trailryx-jsonl FILE`, or `trailryx-jsonl -` to read a pipe.
//!
//! The smallest honest thing that can be done with [`JsonlSource`]: read a file
//! of OTLP/JSON lines in fixed-size pieces, drain what they produced into
//! records, and print what was lost. A real store would seal the records into a
//! segment here; this one counts them, so the program shows arrival without
//! pretending to be a store.
//!
//! A path is read as an archive and a pipe as a live file, which is the whole of
//! the difference between the two constructors: replaying last week's export
//! through a reader that assesses clock skew marks every record skewed and then
//! writes that down as an incident, which would be true of the reader and false
//! of the fleet.
//!
//! `fixtures/incident.jsonl` is hand-written from the documented Collector shape
//! and was not captured from a live pipeline. It carries one deliberate loss, a
//! span naming an operation this mapper version does not know, because a demo in
//! which nothing is ever lost never shows the half of the design that matters.

use std::io::Read;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use trailryx_assemble::Assembler;
use trailryx_contracts::contracts::Source;
use trailryx_otlp::MapperConfig;
use trailryx_otlp::jsonl::JsonlSource;
use trailryx_record::{PayloadClass, ShardIx, TenantId, Timestamp};
use trailryx_sim::rng::SimRng;

/// One read at a time, and the queue drained after each. `accept_chunk` refuses
/// to read while the queue is full, so the peak the reader holds is one buffer
/// plus one line plus whatever has not been drained.
const BUFFER: usize = 64 * 1024;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("trailryx-jsonl FILE|-   (OTLP/JSON lines in, records out)");
        return ExitCode::from(2);
    };
    let Ok(tenant) = TenantId::parse("acme") else {
        return fail("acme is not a valid tenant");
    };
    let Ok(cfg) = MapperConfig::new(tenant, "acme.example") else {
        return fail("acme.example is not a usable trust domain");
    };

    let live = path == "-";
    let mut input: Box<dyn Read> = if live {
        Box::new(std::io::stdin())
    } else {
        match std::fs::File::open(&path) {
            Ok(file) => Box::new(file),
            Err(e) => return fail(&format!("cannot read {path}: {e}")),
        }
    };
    // A pipe is being written now, so both clocks mean now. A file is an archive.
    let mut src = if live {
        JsonlSource::tail(cfg)
    } else {
        JsonlSource::replay(cfg)
    };

    let mut assembler = Assembler::new(ShardIx(0), SimRng::new(1));
    let mut buffer = vec![0u8; BUFFER];
    let mut records = 0usize;
    let mut edges = 0usize;
    loop {
        // The clock is read here and passed in. The source never reaches for one:
        // a reader that stamped its own time would be one process away from a
        // source that stamps its own time.
        match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                src.accept_chunk(&buffer[..n], now());
                let (r, e) = drain(&mut src, &mut assembler);
                records += r;
                edges += e;
            }
            Err(e) => return fail(&format!("cannot read {path}: {e}")),
        }
    }
    src.finish(now());
    let (r, e) = drain(&mut src, &mut assembler);
    records += r;
    edges += e;

    // The path is printed to a terminal and never reaches a record: a file name
    // is operator infrastructure and frequently somebody's home directory.
    println!(
        "{path}: {} mode, {records} records, {edges} causal edges",
        src.mode()
    );
    for counter in src.counters().list().iter().filter(|c| c.value > 0) {
        println!("  {:<26} {}", counter.name, counter.value);
    }
    match src.anomaly_event(now()) {
        Some(event) => {
            // Mapper 0 is `UNMAPPED` and cursor 0 is nowhere: a record the store
            // wrote about itself was produced by no mapper, and an anomaly is not
            // a position in the file that a resume could start from.
            println!(
                "anomaly record: {:?}/{:?}, mapper {}, cursor {}",
                event.meta.event_type, event.meta.severity, event.meta.mapper.0, event.cursor.0
            );
            for part in event
                .payload
                .iter()
                .filter(|p| p.class == PayloadClass::Diagnostic)
            {
                for l in String::from_utf8_lossy(&part.bytes)
                    .lines()
                    .filter(|l| !l.ends_with("\t0"))
                {
                    println!("  {l}");
                }
            }
        }
        None => println!("no anomaly: nothing was lost"),
    }
    ExitCode::SUCCESS
}

/// Poll, assemble, acknowledge. Returns the records and the edges they resolved.
///
/// Acknowledged after assembling and not before: an acknowledgement is a promise
/// that the records are ours now, and a source that was told so before they were
/// would be entitled to forget them.
fn drain(src: &mut JsonlSource, assembler: &mut Assembler<SimRng>) -> (usize, usize) {
    let batch = src.poll(4096).unwrap_or_default();
    let Some(highest) = batch.iter().map(|i| i.cursor).max() else {
        return (0, 0);
    };
    // The whole batch at once, because a batch arrives children first: a span is
    // exported when it ends, and a child ends inside its parent.
    let assembled = assembler.adopt_batch(batch, now());
    let edges = assembled
        .iter()
        .filter(|a| !a.record.caused_by.is_empty())
        .count();
    let _ = src.ack(highest);
    (assembled.len(), edges)
}

fn now() -> Timestamp {
    Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    )
}

fn fail(why: &str) -> ExitCode {
    eprintln!("trailryx-jsonl: {why}");
    ExitCode::from(2)
}
