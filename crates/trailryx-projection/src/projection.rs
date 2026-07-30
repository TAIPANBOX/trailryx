//! Turning sealed segments into a columnar table.
//!
//! # A projection is never evidence
//!
//! This is the rule the whole crate is arranged around, and it is the opposite
//! of what a data lake usually assumes. A Parquet file here is **derived**: it
//! can be deleted and rebuilt from the journal, byte for byte, and it carries
//! no proof of anything. An answer computed from it is an answer without a
//! completeness proof, and every surface that reads one has to say so.
//!
//! The temptation is obvious. The projection is fast, it is what a SQL engine
//! wants, and its rows look exactly like the records they came from. Treating
//! it as evidence would be one line of convenience and would quietly retire the
//! only thing this store sells. So [`Projection::provable`] exists as a method
//! that always returns false rather than as a paragraph nobody reads.
//!
//! Each row carries its `chain_link`, which is what keeps the projection useful
//! without making it authoritative: a row can be traced back to the journal and
//! to an inclusion proof, and the proof comes from the segment, never from here.
//!
//! # No payload, ever
//!
//! A projection lands in object storage, gets copied into a lake, gets
//! replicated, gets backed up. It is precisely the surface crypto-erasure
//! cannot reach. So it holds no payload bytes and no free text at all: typed
//! fields, validated tokens, enum names and hashes. `payload_hash` and
//! `payload_key_id` are here so a row can be connected to its payload; the
//! payload itself stays behind its key, where erasure can still find it.

use crate::parquet::{Column, Values, WriteError, write};
use trailryx_index::segment::Segment;
use trailryx_record::{Hash, Record};

/// Bumped when a column is added, removed or given a different meaning.
///
/// Not a format freeze: a projection is rebuildable, so changing it costs a
/// rebuild rather than a migration. That is exactly the difference between
/// derived data and the journal.
pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    bytes: Vec<u8>,
    rows: usize,
    columns: usize,
}

impl Projection {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Always false.
    ///
    /// A method rather than a comment, so an implementation that overrides it
    /// is visibly doing something wrong, and so a caller that wants to believe
    /// otherwise has to write the words down.
    pub fn provable(&self) -> bool {
        false
    }

    pub fn why_not_provable(&self) -> &'static str {
        "a projection is derived from the journal and carries no proof; ask the segment"
    }
}

/// Build a projection over the segments, in the order given.
///
/// A pure function of its input. No clock, no randomness, no map iteration
/// reaching the output: the same segments always produce the same bytes, which
/// is what makes "delete it and rebuild it" a safe thing to say.
pub fn project(segments: &[&Segment]) -> Result<Projection, WriteError> {
    let columns = project_columns(segments);
    let bytes = write(&columns)?;
    Ok(Projection {
        rows: columns.first().map(|c| c.values.count()).unwrap_or(0),
        columns: columns.len(),
        bytes,
    })
}

/// The columns a projection would hold, without encoding them.
///
/// Public so a test can compare our own idea of every cell against what an
/// outside reader finds in the file.
pub fn project_columns(segments: &[&Segment]) -> Vec<Column> {
    let mut rows: Vec<(Record, Hash)> = Vec::new();
    for segment in segments {
        let links = segment.links();
        for (record, link) in segment.records().iter().zip(links) {
            rows.push((record.clone(), link));
        }
    }
    build_columns(&rows)
}

/// The column list, and the only place it is written down.
///
/// Every entry is a typed field, a validated token, an enum name or a hash.
/// There is no column that could hold a sentence, which is checked by a test
/// rather than left to whoever adds the next one.
/// The columns for a set of records and their chain links.
///
/// Public because the SQL facade projects the records an index returned rather than
/// a whole segment, and the column list has to have exactly one home: a second copy
/// of it in the facade would drift, and a drifted projection is a table whose columns
/// mean something different from the file's.
pub fn columns_from_records(rows: &[(Record, Hash)]) -> Vec<Column> {
    build_columns(rows)
}

fn build_columns(rows: &[(Record, Hash)]) -> Vec<Column> {
    let text = |f: &dyn Fn(&Record) -> String| -> Values {
        Values::String(rows.iter().map(|(r, _)| Some(f(r))).collect())
    };
    let maybe_text = |f: &dyn Fn(&Record) -> Option<String>| -> Values {
        Values::String(rows.iter().map(|(r, _)| f(r)).collect())
    };
    let int = |f: &dyn Fn(&Record) -> i64| -> Values {
        Values::Int64(rows.iter().map(|(r, _)| Some(f(r))).collect())
    };
    let maybe_int = |f: &dyn Fn(&Record) -> Option<i64>| -> Values {
        Values::Int64(rows.iter().map(|(r, _)| f(r)).collect())
    };
    // A real Parquet list, not a comma-joined string. The record field is a `Vec`
    // that is always present and whose elements are validated tokens, so the
    // column is a required LIST of required elements and an empty vec is an empty
    // list rather than a null.
    let list = |f: &dyn Fn(&Record) -> Vec<String>| -> Values {
        Values::StringList(rows.iter().map(|(r, _)| f(r)).collect())
    };

    vec![
        // Identity and placement.
        Column::required("record_id", text(&|r| format!("{:032x}", r.id.0))),
        Column::required("tenant", text(&|r| r.tenant.as_str().to_owned())),
        Column::required(
            "shard",
            Values::Int32(
                rows.iter()
                    .map(|(r, _)| Some(i32::from(r.shard.0)))
                    .collect(),
            ),
        ),
        Column::required("segment_id", int(&|r| r.segment_id.0 as i64)),
        Column::required("seq", int(&|r| r.seq as i64)),
        // The tie back to the journal. Everything else in this file is a
        // convenience; this is what makes a row checkable.
        Column::required(
            "chain_link",
            Values::String(rows.iter().map(|(_, l)| Some(l.to_hex())).collect()),
        ),
        Column::required("prev_hash", text(&|r| r.prev_hash.to_hex())),
        // Who.
        Column::required("agent_id", text(&|r| r.agent_id.as_str().to_owned())),
        Column::required("run_id", text(&|r| r.run_id.as_str().to_owned())),
        Column::optional(
            "parent_run_id",
            maybe_text(&|r| r.parent_run_id.as_ref().map(|v| v.as_str().to_owned())),
        ),
        Column::required(
            "on_behalf_of",
            list(&|r| {
                r.on_behalf_of
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect()
            }),
        ),
        // When. Nanoseconds throughout: a lossless export cannot round a
        // timestamp on the way out, and no Parquet converted type carries
        // nanosecond precision, so the unit is in the column name instead.
        Column::required(
            "occurred_at_nanos",
            int(&|r| r.occurred_at.as_untrusted().as_nanos() as i64),
        ),
        Column::optional(
            "decided_at_nanos",
            maybe_int(&|r| {
                r.decided_at
                    .as_ref()
                    .map(|t| t.as_untrusted().as_nanos() as i64)
            }),
        ),
        Column::required(
            "recorded_at_nanos",
            int(&|r| r.recorded_at.as_nanos() as i64),
        ),
        Column::optional(
            "knowledge_as_of_nanos",
            maybe_int(&|r| r.knowledge_as_of.map(|t| t.as_nanos() as i64)),
        ),
        Column::optional(
            "clock_skew_nanos",
            maybe_int(&|r| r.clock_skew_nanos.map(|v| v as i64)),
        ),
        // What.
        Column::required("event_type", text(&|r| r.event_type.as_str().to_owned())),
        Column::required("severity", text(&|r| r.severity.as_str().to_owned())),
        Column::required(
            "caused_by",
            list(&|r| {
                r.caused_by
                    .iter()
                    .map(|c| format!("{:032x}", c.0))
                    .collect()
            }),
        ),
        // On what grounds.
        Column::optional(
            "policy_version",
            maybe_text(&|r| {
                r.basis
                    .policy_version
                    .as_ref()
                    .map(|v| v.as_str().to_owned())
            }),
        ),
        Column::optional(
            "budget_remaining_micros",
            maybe_int(&|r| r.basis.budget_remaining_micros),
        ),
        Column::optional(
            "memory_ref",
            maybe_text(&|r| r.basis.memory_ref.map(|h| h.to_hex())),
        ),
        Column::optional(
            "model",
            maybe_text(&|r| r.basis.model.as_ref().map(|v| v.as_str().to_owned())),
        ),
        Column::optional(
            "temperature_milli",
            maybe_int(&|r| r.basis.temperature_milli.map(i64::from)),
        ),
        Column::optional(
            "max_tokens",
            maybe_int(&|r| r.basis.max_tokens.map(i64::from)),
        ),
        Column::optional(
            "prompt_hash",
            maybe_text(&|r| r.basis.prompt_hash.map(|h| h.to_hex())),
        ),
        Column::required(
            "tool_manifest",
            list(&|r| {
                r.basis
                    .tool_manifest
                    .iter()
                    .map(|t| t.as_str().to_owned())
                    .collect()
            }),
        ),
        Column::required(
            "identity_chain",
            list(&|r| {
                r.basis
                    .identity_chain
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect()
            }),
        ),
        // How it ended.
        Column::optional(
            "verdict",
            maybe_text(&|r| r.outcome.verdict.map(|v| v.as_str().to_owned())),
        ),
        Column::optional(
            "error",
            maybe_text(&|r| r.outcome.error.map(|v| v.as_str().to_owned())),
        ),
        Column::optional(
            "latency_micros",
            maybe_int(&|r| r.outcome.latency_micros.map(|v| v as i64)),
        ),
        Column::optional(
            "tokens_in",
            maybe_int(&|r| r.outcome.tokens_in.map(i64::from)),
        ),
        Column::optional(
            "tokens_out",
            maybe_int(&|r| r.outcome.tokens_out.map(i64::from)),
        ),
        Column::optional("cost_micros", maybe_int(&|r| r.outcome.cost_micros)),
        // The payload, by reference only.
        Column::optional(
            "payload_hash",
            maybe_text(&|r| r.payload.as_ref().map(|p| p.hash.to_hex())),
        ),
        Column::optional(
            "payload_size_bytes",
            maybe_int(&|r| r.payload.as_ref().map(|p| p.size_bytes as i64)),
        ),
        Column::optional(
            "payload_class",
            maybe_text(&|r| r.payload.as_ref().map(|p| p.class.as_str().to_owned())),
        ),
        Column::optional(
            "payload_key_id",
            maybe_text(&|r| r.payload.as_ref().map(|p| p.key_id.to_hex())),
        ),
        // Which primitives produced it, so a migration can enumerate what needs
        // re-signing without opening the journal.
        Column::required("hash_alg", text(&|r| r.algorithms.hash.as_str().to_owned())),
        Column::required(
            "sig_alg",
            text(&|r| r.algorithms.signature.as_str().to_owned()),
        ),
        Column::required("kem_alg", text(&|r| r.algorithms.kem.as_str().to_owned())),
        Column::required("mapper_version", int(&|r| i64::from(r.mapper.0))),
    ]
}
