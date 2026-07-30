//! The dialect extensions, as table functions.
//!
//! # A deviation from the architecture's syntax, and why
//!
//! `docs/planning/trailryx-architecture.md` §3.3 illustrates three extensions:
//!
//! ```sql
//! SELECT * FROM records AS OF TIMESTAMP '2026-03-01T00:00:00Z' WHERE agent_id = '...';
//! SELECT * FROM records WHERE run_id = '4471' WITH PROOF;
//! SELECT * FROM causal_closure('4471');
//! ```
//!
//! The third parses with the engine's own parser. **The first two do not**, and that
//! was checked rather than assumed: `AS OF TIMESTAMP` and a trailing `WITH PROOF` are
//! both rejected by `DFParser`. `sqlparser` has a `FOR SYSTEM_TIME AS OF` form, and
//! DataFusion's dialect does not enable it.
//!
//! So getting that syntax exactly would need one of two things, and both are refused:
//!
//! - **Forking or wrapping the parser.** Then two parsers read one string and can
//!   disagree about where a clause ends, which is the defect class
//!   [`crate::gate`] exists to remove. Adding it back in the next module would be
//!   incoherent.
//! - **Preprocessing the text** to strip the clause before handing the rest over.
//!   Worse: a string literal containing `WITH PROOF` gets mangled, and the gate then
//!   inspects a statement that is not the one that runs.
//!
//! So all three are table functions, which the engine's parser accepts as written and
//! which need no second reader:
//!
//! ```sql
//! SELECT * FROM records_as_of('2026-03-01T00:00:00Z') WHERE agent_id = '...';
//! SELECT * FROM causal_closure('4471');
//! SELECT * FROM trailryx_proof();
//! ```
//!
//! The capability is the same and the spelling is not. That is a decision worth
//! writing down rather than a syntax quietly not implemented, and if the syntax
//! matters more than the parser count later, the way to get it is to teach
//! `sqlparser` upstream rather than to read the string twice here.

use std::sync::Arc;

use datafusion::arrow::array::{ArrayRef, StringArray, UInt64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::{TableFunctionImpl, TableProvider};
use datafusion::common::{DataFusionError, Result as DfResult, ScalarValue};
use datafusion::datasource::MemTable;
use datafusion::logical_expr::Expr;

use trailryx_index::segment::Segment;
use trailryx_record::{RunId, Timestamp};
use trailryx_store::causal::{Bounds, reconstruct};

use crate::table::{ProofSlot, Provability, RecordTable};

/// The one string argument a table function was given.
fn one_string(args: &[Expr], what: &str) -> DfResult<String> {
    match args {
        [Expr::Literal(ScalarValue::Utf8(Some(value)), _)]
        | [Expr::Literal(ScalarValue::LargeUtf8(Some(value)), _)] => Ok(value.clone()),
        // Named rather than "invalid argument": somebody who passed a column instead
        // of a literal should learn that is the problem.
        _ => Err(DataFusionError::Plan(format!(
            "{what} takes exactly one string literal"
        ))),
    }
}

/// `records_as_of('<nanoseconds or RFC 3339 instant>')`
///
/// Transaction time, and the distinction is not pedantry: this answers "what had the
/// store recorded by then", not "what was true then". Valid-time travel would need a
/// layer of facts that supersede one another, and this store holds events. Offering
/// one and meaning the other is the kind of thing an auditor finds out at the worst
/// moment, so the name and this comment both say which it is.
#[derive(Debug)]
pub struct RecordsAsOf {
    segments: Arc<Vec<Segment>>,
    /// The session's proof slot, so an answer from this function is reachable through
    /// the same accessor as an answer from `records`.
    slot: ProofSlot,
}

impl RecordsAsOf {
    pub fn new(segments: Arc<Vec<Segment>>, slot: ProofSlot) -> Self {
        Self { segments, slot }
    }
}

impl TableFunctionImpl for RecordsAsOf {
    fn call(&self, args: &[Expr]) -> DfResult<Arc<dyn TableProvider>> {
        let text = one_string(args, "records_as_of")?;
        let nanos = parse_instant(&text)?;
        Ok(Arc::new(
            RecordTable::new((*self.segments).clone())
                .sharing(Arc::clone(&self.slot))
                .as_of(Timestamp(nanos)),
        ))
    }
}

/// Nanoseconds since the epoch, either as a number or as a plain UTC instant.
///
/// Deliberately narrow. A timezone-bearing format would need a timezone database and
/// a decision about what a local time means to a store whose whole point is that its
/// timestamps are unambiguous, so the two forms accepted are the two that cannot be
/// misread.
fn parse_instant(text: &str) -> DfResult<u64> {
    if let Ok(nanos) = text.parse::<u64>() {
        return Ok(nanos);
    }
    // `YYYY-MM-DDTHH:MM:SSZ`, UTC, seconds resolution. Same rules as the timestamp
    // reader in `trailryx-verify`, and refused rather than guessed at otherwise.
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z';
    if !shaped {
        return Err(DataFusionError::Plan(format!(
            "{text:?} is neither nanoseconds since the epoch nor a UTC instant like \
             2026-03-01T00:00:00Z"
        )));
    }
    let n = |from: usize, to: usize| -> DfResult<i64> {
        text[from..to]
            .parse::<i64>()
            .map_err(|_| DataFusionError::Plan(format!("{text:?} is not a UTC instant")))
    };
    let (year, month, day) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    let (hour, minute, second) = (n(11, 13)?, n(14, 16)?, n(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(DataFusionError::Plan(format!("{text:?} is not a date")));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(DataFusionError::Plan(format!("{text:?} is not a time")));
    }
    // Hinnant's days_from_civil, the same arithmetic the verifier uses, so two parts
    // of this repository cannot disagree about what an instant is.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds)
        .map(|s| s * 1_000_000_000)
        .map_err(|_| DataFusionError::Plan(format!("{text:?} is before 1970")))
}

/// `causal_closure('<run id>')`
///
/// Every record reachable from a run by delegation and causation, with the traversal
/// bounded. The bound is not a performance guard: an unbounded traversal over a store
/// somebody else writes to is a query anybody can turn into an outage.
#[derive(Debug)]
pub struct CausalClosure {
    segments: Arc<Vec<Segment>>,
    /// The session's proof slot, so an answer from this function is reachable through
    /// the same accessor as an answer from `records`.
    slot: ProofSlot,
}

impl CausalClosure {
    pub fn new(segments: Arc<Vec<Segment>>, slot: ProofSlot) -> Self {
        Self { segments, slot }
    }
}

impl TableFunctionImpl for CausalClosure {
    fn call(&self, args: &[Expr]) -> DfResult<Arc<dyn TableProvider>> {
        let text = one_string(args, "causal_closure")?;
        let run = RunId::parse(text.clone())
            .map_err(|_| DataFusionError::Plan(format!("{text:?} is not a run identifier")))?;
        let refs: Vec<&Segment> = self.segments.iter().collect();
        let closure = reconstruct(&refs, &run, Bounds::default());

        // The reconstruction already decided which records are in the closure and how
        // provable that is, so this hands the answer over rather than re-deriving it.
        // A second traversal here could disagree with the first, and the first is the
        // one the store's own tests are about.
        Ok(Arc::new(RecordTable::from_records(
            closure.records,
            match closure.proof.is_full() {
                true => Provability::Full,
                false => Provability::Partial(vec![format!(
                    "causal_closure({text}): {:?}, stopped {:?}",
                    closure.proof, closure.stopped
                )]),
            },
            Arc::clone(&self.slot),
        )))
    }
}

/// `trailryx_proof()`
///
/// One row: how provable the **last** answer on this session was, and why not, if it
/// was not.
///
/// A stopgap for `WITH PROOF`, and it says so rather than being presented as the
/// design. What it inherits from the suffix syntax it replaces is the honest part: the
/// value is derived from which predicates were pushed into the index, never asserted.
/// What it does not inherit is atomicity, and that is the cost: a second query on the
/// same session between the two statements overwrites it. So it is truthful and it is
/// racy, which is a worse property than `WITH PROOF` would have had and a better one
/// than a second parser.
#[derive(Debug)]
pub struct ProofOfLastAnswer {
    table: Arc<RecordTable>,
}

impl ProofOfLastAnswer {
    pub fn new(table: Arc<RecordTable>) -> Self {
        Self { table }
    }
}

impl TableFunctionImpl for ProofOfLastAnswer {
    fn call(&self, _args: &[Expr]) -> DfResult<Arc<dyn TableProvider>> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("proof", DataType::Utf8, false),
            Field::new("unproved", DataType::UInt64, false),
            Field::new("reason", DataType::Utf8, true),
        ]));

        let (status, unproved, reason) = match self.table.last_proof() {
            Some(Provability::Full) => ("full".to_owned(), 0u64, None),
            Some(Provability::Partial(reasons)) => (
                "partial".to_owned(),
                reasons.len() as u64,
                Some(reasons.join("; ")),
            ),
            // Not "full". A session that has answered nothing has proved nothing, and
            // reporting the strongest value for the absence of an answer is the exact
            // shape of lie the rest of this crate is arranged against.
            None => (
                "none".to_owned(),
                0,
                Some("no query has been answered on this session yet".to_owned()),
            ),
        };

        let columns: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from(vec![status])),
            Arc::new(UInt64Array::from(vec![unproved])),
            Arc::new(StringArray::from(vec![reason])),
        ];
        let batch = RecordBatch::try_new(Arc::clone(&schema), columns)
            .map_err(|e| DataFusionError::ArrowError(Box::new(e), None))?;
        Ok(Arc::new(MemTable::try_new(schema, vec![vec![batch]])?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instant_is_accepted_in_the_two_forms_that_cannot_be_misread() {
        assert_eq!(parse_instant("0").unwrap(), 0);
        assert_eq!(
            parse_instant("1700000000000000000").unwrap(),
            1_700_000_000_000_000_000
        );
        assert_eq!(
            parse_instant("1970-01-01T00:00:00Z").unwrap(),
            0,
            "the epoch, spelled out"
        );
        assert_eq!(
            parse_instant("2026-03-01T00:00:00Z").unwrap(),
            1_772_323_200_000_000_000
        );
    }

    /// A local time with no zone is a time nobody can place. Refused rather than
    /// assumed to be UTC, for the same reason the timestamp reader in the verifier
    /// refuses it: a store whose value is unambiguous timestamps must not guess.
    #[test]
    fn anything_ambiguous_is_refused_rather_than_guessed() {
        for text in [
            "2026-03-01",
            "2026-03-01T00:00:00",
            "2026-03-01T00:00:00+02:00",
            "2026-13-01T00:00:00Z",
            "2026-03-32T00:00:00Z",
            "2026-03-01T25:00:00Z",
            "yesterday",
            "",
            "-1",
        ] {
            assert!(
                parse_instant(text).is_err(),
                "{text:?} should not have parsed"
            );
        }
    }

    /// The two accepted forms must agree with each other, or the same moment would
    /// mean two things depending on how it was written.
    #[test]
    fn the_two_forms_agree_about_the_same_moment() {
        let spelled = parse_instant("2026-03-01T00:00:00Z").unwrap();
        assert_eq!(parse_instant(&spelled.to_string()).unwrap(), spelled);
    }

    #[test]
    fn a_table_function_wants_one_string_literal_and_says_so() {
        let error = one_string(&[], "records_as_of").unwrap_err().to_string();
        assert!(error.contains("exactly one string literal"), "{error}");
        let error = one_string(
            &[Expr::Literal(ScalarValue::Int64(Some(1)), None)],
            "causal_closure",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("exactly one string literal"), "{error}");
    }
}

/// `journal(<from seq>, <to seq>)`
///
/// The records as the journal holds them, in journal order, past the projections and
/// past the proofs. `docs/planning/trailryx-architecture.md` §3.3 calls it "the raw
/// truth", and §3.2a says the facade never touches the live journal. Both are true at
/// once, and the shape that makes them true is not one this repository invented.
///
/// # It is modelled on `pg_walinspect`, which solves the same problem
///
/// PostgreSQL faced exactly this: expose the write-ahead log through SQL without
/// letting the query executor near the write path. `pg_walinspect` shipped in
/// PostgreSQL 15 and every one of its four decisions applies here, so all four are
/// copied rather than re-derived:
///
/// - **A table function taking a range, not a table.** `pg_get_wal_records_info(start,
///   end)`. There is no `SELECT * FROM wal`, because a log is unbounded and a client
///   that could ask for all of it could ask the server to read all of it.
/// - **An error when the start is not available.** Postgres refuses an LSN that has
///   not been flushed or has been recycled. Here the equivalent is a sequence number
///   in no **sealed** segment: a record in the live journal is not refused because it
///   is secret, it is refused because reading it would put this runtime on the write
///   path, which is what §3.2a forbids and what would cost the shard its determinism.
/// - **Permissive about the upper bound.** Postgres accepts an `end_lsn` past the
///   current one and returns what exists. Erroring instead would make the ordinary
///   "everything from here" query a moving target.
/// - **A different privilege from ordinary SQL.** Restricted by default to superusers
///   and `pg_read_server_files`. Here that is [`Action::ReadMetadata`] rather than
///   [`Action::Query`], asked for separately, and a session that was not granted it
///   does not get this function registered at all. The catalog a session sees is what
///   it may use.
///
/// [`Action::ReadMetadata`]: trailryx_contracts::contracts::Action::ReadMetadata
/// [`Action::Query`]: trailryx_contracts::contracts::Action::Query
#[derive(Debug)]
pub struct Journal {
    segments: Arc<Vec<Segment>>,
    /// The session's proof slot, so an answer from this function is reachable through
    /// the same accessor as an answer from `records`.
    slot: ProofSlot,
}

impl Journal {
    pub fn new(segments: Arc<Vec<Segment>>, slot: ProofSlot) -> Self {
        Self { segments, slot }
    }
}

impl TableFunctionImpl for Journal {
    fn call(&self, args: &[Expr]) -> DfResult<Arc<dyn TableProvider>> {
        let (from, to) = two_numbers(args)?;
        if from > to {
            return Err(DataFusionError::Plan(format!(
                "journal({from}, {to}): the range runs backwards"
            )));
        }

        // Sealed segments only, and in journal order, which is `(segment, seq)`
        // because one segment is one journal file numbering from one.
        let mut rows: Vec<(trailryx_record::Record, trailryx_record::Hash)> = Vec::new();
        let mut available_from: Option<u64> = None;
        let mut available_to: Option<u64> = None;
        let mut ordered: Vec<&Segment> = self.segments.iter().collect();
        ordered.sort_by_key(|s| s.manifest().segment.0);
        for segment in ordered {
            for (record, link) in segment.records().iter().zip(segment.links()) {
                available_from =
                    Some(available_from.map_or(record.seq, |v: u64| v.min(record.seq)));
                available_to = Some(available_to.map_or(record.seq, |v: u64| v.max(record.seq)));
                if record.seq >= from && record.seq <= to {
                    rows.push((record.clone(), link));
                }
            }
        }

        // The start has to exist, exactly as Postgres refuses an LSN it cannot reach.
        // A silent empty answer would be indistinguishable from "that range is empty",
        // and the two mean very different things to somebody doing forensics.
        let (Some(low), Some(high)) = (available_from, available_to) else {
            return Err(DataFusionError::Plan(
                "journal: no sealed segment is available to read".to_owned(),
            ));
        };
        if from < low {
            return Err(DataFusionError::Plan(format!(
                "journal({from}, {to}): sequence {from} is not in any sealed segment; the \
                 earliest available is {low}"
            )));
        }
        if from > high {
            return Err(DataFusionError::Plan(format!(
                "journal({from}, {to}): sequence {from} is past the last sealed record, \
                 which is {high}. A record that is not sealed yet is not refused for being \
                 secret: reading it would put this runtime on the write path"
            )));
        }
        // The upper bound stays permissive, as Postgres is: whatever exists.

        Ok(Arc::new(RecordTable::from_records_with_links(
            rows,
            // No proof, and it says so rather than reporting `Full` for a scan that
            // deliberately went around the thing that proves.
            Provability::Partial(vec![
                "journal() reads past the projections, so no completeness proof applies to \
                 this answer"
                    .to_owned(),
            ]),
            Arc::clone(&self.slot),
        )))
    }
}

/// The two integer arguments a range function was given.
fn two_numbers(args: &[Expr]) -> DfResult<(u64, u64)> {
    let number = |e: &Expr| -> Option<u64> {
        match e {
            Expr::Literal(ScalarValue::Int64(Some(v)), _) => u64::try_from(*v).ok(),
            Expr::Literal(ScalarValue::UInt64(Some(v)), _) => Some(*v),
            Expr::Literal(ScalarValue::Int32(Some(v)), _) => u64::try_from(*v).ok(),
            _ => None,
        }
    };
    match args {
        [a, b] => match (number(a), number(b)) {
            (Some(from), Some(to)) => Ok((from, to)),
            _ => Err(DataFusionError::Plan(
                "journal takes two non-negative sequence numbers".to_owned(),
            )),
        },
        _ => Err(DataFusionError::Plan(
            "journal takes exactly two arguments: journal(from_seq, to_seq)".to_owned(),
        )),
    }
}
