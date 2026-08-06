//! A file of the estate's agent events, read into the plane.
//!
//! The other products in this estate already emit NDJSON in the shared
//! `taipanbox.dev/agent-event` envelope. `trailryx-agentevent` maps one line into
//! one ingest unit; this is what makes that mapper reachable, because a mapper
//! nothing calls is exactly the shape the audit of 5 August 2026 found everywhere
//! else in this repository.
//!
//! Framing is `trailryx_json::Framer`, the same framer the OTLP/JSON file source
//! uses, and it is a dependency rather than a second loop for the reason that
//! crate gives: a partial last line is not corruption, an oversize line is a
//! bound rather than a syntax error, and a byte-order mark makes the whole stream
//! unreadable at any read size. Every one of those was a defect once.

use std::path::Path;

use trailryx_agentevent::{EnvelopeConfig, Rejection, Report, map_line};
use trailryx_contracts::ingest::{Cursor, Ingest};
use trailryx_json::{Framer, Limits};
use trailryx_record::Timestamp;

use crate::plane::{Accepted, Plane, PlaneError};

/// How many units are handed to the plane at once.
///
/// A batch rather than a line, because the assembler resolves causal edges within
/// one batch and a batch of one can never find a parent.
const BATCH: usize = 1_024;

/// What a file cost, in records and in lines that produced none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ingested {
    pub accepted: Accepted,
    pub report: Report,
}

/// Read a file of agent events into the plane.
///
/// Fail-open per line and never silent, which is the rule every source in this
/// tree follows: a line that cannot become a record is counted by its reason and
/// the rest of the file still lands. What the caller does with the counts is its
/// own business, and the binary writes them out.
pub fn ingest_file(
    plane: &mut Plane,
    cfg: &EnvelopeConfig,
    path: &Path,
    now: Timestamp,
) -> Result<Ingested, PlaneError> {
    let bytes =
        std::fs::read(path).map_err(|e| PlaneError::Io(format!("{}: {e}", path.display())))?;
    ingest_bytes(plane, cfg, &bytes, now)
}

/// The same, over bytes a caller already holds.
pub fn ingest_bytes(
    plane: &mut Plane,
    cfg: &EnvelopeConfig,
    bytes: &[u8],
    now: Timestamp,
) -> Result<Ingested, PlaneError> {
    let mut out = Ingested::default();
    let mut framer = Framer::new(Limits::default());
    let mut batch: Vec<Ingest> = Vec::new();
    let mut cursor = 0u64;

    let mut take = |line: trailryx_json::Line<'_>| -> trailryx_json::JsonResult<()> {
        cursor += 1;
        match map_line(cfg, line.bytes, Cursor(cursor)) {
            Ok(unit) => {
                out.report.mapped = out.report.mapped.saturating_add(1);
                batch.push(unit);
            }
            Err(rejection) => out.report.note(rejection),
        }
        Ok(())
    };

    // A stream this framer refuses is refused whole rather than half read: a
    // UTF-16 mark means nothing in the file is what it says it is.
    if framer.push(bytes, &mut take).is_err() || framer.finish(&mut take).is_err() {
        return Err(PlaneError::Refused(
            "this file is not UTF-8 JSON Lines, so none of it was read".to_owned(),
        ));
    }

    for chunk in batch.chunks(BATCH) {
        let accepted = plane.accept(chunk.to_vec(), now)?;
        out.accepted.written += accepted.written;
        out.accepted.duplicates += accepted.duplicates;
        out.accepted.declined_payload_parts += accepted.declined_payload_parts;
    }
    Ok(out)
}

/// Whether a rejection means a producer has to change something.
///
/// Split out because the two kinds want different answers from an operator: a
/// line this reading of the registry does not map is a decision written down in
/// `trailryx-agentevent`, while a line with no run identifier is a producer that
/// can add one.
pub fn is_producer_fixable(rejection: Rejection) -> bool {
    matches!(
        rejection,
        Rejection::NoRunId | Rejection::NoAgent | Rejection::ForeignTrustDomain
    )
}
