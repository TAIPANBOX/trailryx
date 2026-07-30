//! The `TableProvider`: DataFusion asks, the authenticated index answers.
//!
//! This is the engine-facing half. It translates DataFusion's `Expr` into the
//! shapes [`crate::pushdown`] understands, runs the resulting query against sealed
//! segments, and turns the records into Arrow batches. Every decision about
//! provability is made in `pushdown`, which knows nothing about DataFusion, so this
//! file is translation and nothing else.
//!
//! # What it reads, and what it must never read
//!
//! Sealed segments only. `docs/planning/trailryx-architecture.md` §3.2a: the facade
//! reads **projections and snapshots, never the live journal**. A sealed segment is
//! immutable and its roots are already committed, so a query over one cannot race a
//! writer and cannot see a record that is not yet in a chain. Reaching into the
//! journal would put a tokio thread on the write path and cost the core the
//! determinism the whole correctness method rests on.
//!
//! # What `supports_filters_pushdown` promises
//!
//! Three answers, and getting them wrong is a correctness bug rather than a
//! performance one:
//!
//! - **`Exact`** for the predicate that became the sorted dimension. We guarantee we
//!   omit only rows that fail it, so DataFusion does not re-check. Claiming this for
//!   a predicate we only approximate would silently drop rows.
//! - **`Inexact`** for a predicate we apply as a filter. We do apply it, and
//!   DataFusion re-checks anyway, which is free correctness insurance.
//! - **`Inexact`** for everything else too, and **never `Unsupported`**. That is not
//!   laziness, it is the difference between an honest proof and a false one:
//!   DataFusion does not pass an `Unsupported` filter to `scan` at all, so a facade
//!   that returned it would never learn the predicate existed and would report a
//!   **full** proof for a query it had not fully seen. Measured, not reasoned:
//!   `severity = 'error'` came back marked fully provable until this was changed.
//!   `Inexact` costs a redundant re-check above us and buys the ability to tell the
//!   truth.
//!
//! # Where the proof goes
//!
//! SQL has nowhere to put it until `WITH PROOF` exists, so every scan records its
//! provability in [`RecordTable::last_proof`]. That is a stopgap and it says so: a
//! caller reading it is reading the last query's answer, not this query's, and a
//! concurrent second query overwrites it. What it is not is a lie: the value is
//! derived from which predicates were pushed, never asserted.

use std::fmt;
use std::sync::{Arc, Mutex};

use datafusion::arrow::array::{ArrayRef, Int32Array, Int64Array, ListBuilder, StringBuilder};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{DataFusionError, Result as DfResult, ScalarValue};
use datafusion::datasource::MemTable;
use datafusion::logical_expr::{Expr, Operator, TableProviderFilterPushDown, TableType};
use datafusion::physical_plan::ExecutionPlan;

use trailryx_index::completeness::Dimension;
use trailryx_index::segment::Segment;
use trailryx_projection::parquet::{Column, Values};
use trailryx_projection::project_columns;
use trailryx_store::query::query_segment;

use crate::pushdown::{Placement, Plan, Predicate, dimension_of, plan};

/// How provable the last answer was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provability {
    /// Every predicate fell on the sorted dimension of an authenticated index.
    Full,
    /// At least one did not. Each is named, because a partial proof whose gaps are
    /// unnamed is indistinguishable from a full one to anybody reading a row count.
    Partial(Vec<String>),
}

impl fmt::Display for Provability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("full"),
            Self::Partial(reasons) => {
                write!(f, "partial: {}", reasons.join("; "))
            }
        }
    }
}

/// Sealed segments, exposed as a table.
#[derive(Debug)]
pub struct RecordTable {
    segments: Vec<Segment>,
    schema: SchemaRef,
    /// The dimension to scan when no predicate can be the sorted one.
    fallback: Dimension,
    /// Transaction-time bound, if this table is a point in the store's past.
    as_of: Option<trailryx_record::Timestamp>,
    /// Rows somebody else selected, for a table function that has already done the
    /// selecting. `None` means the index answers.
    fixed: Option<Vec<(trailryx_record::Record, trailryx_record::Hash)>>,
    last_proof: Mutex<Option<Provability>>,
}

impl RecordTable {
    pub fn new(segments: Vec<Segment>) -> Self {
        Self {
            segments,
            schema: projection_schema(),
            fallback: Dimension::RecordedAt,
            as_of: None,
            fixed: None,
            last_proof: Mutex::new(None),
        }
    }

    /// The store as it was known at an instant.
    ///
    /// Transaction time: records the store had recorded by then. Not valid time,
    /// which would need facts that supersede one another, and this store holds
    /// events. The two answer different questions and only one is on offer.
    pub fn as_of(mut self, at: trailryx_record::Timestamp) -> Self {
        self.as_of = Some(at);
        self
    }

    /// A table over records somebody else already selected, with the provability they
    /// already established.
    ///
    /// For `causal_closure`, where the traversal has decided both. Re-deriving either
    /// here could disagree with the reconstruction, and the reconstruction is the one
    /// the store's own tests are about.
    pub fn from_records(records: Vec<trailryx_record::Record>, proof: Provability) -> Self {
        let rows: Vec<(trailryx_record::Record, trailryx_record::Hash)> = records
            .into_iter()
            // The chain link is not carried by a reconstruction, and inventing one
            // would put a value in `chain_link` that nothing chains to. `prev_hash` is
            // the record's own field and is at least true about the record.
            .map(|r| {
                let link = r.prev_hash;
                (r, link)
            })
            .collect();
        Self {
            segments: Vec::new(),
            schema: projection_schema(),
            fallback: Dimension::RecordedAt,
            as_of: None,
            fixed: Some(rows),
            last_proof: Mutex::new(Some(proof)),
        }
    }

    /// The sealed segments this table answers from.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// How provable the last scan was, if there has been one.
    ///
    /// A stopgap until the dialect carries `WITH PROOF`, and the doc comment on this
    /// module says so rather than leaving somebody to find out by reading a stale
    /// value.
    pub fn last_proof(&self) -> Option<Provability> {
        self.last_proof.lock().ok().and_then(|g| g.clone())
    }

    /// The plan for a set of filters, without running it. For a caller that wants
    /// to know what a query would cost before paying for it, and for tests.
    pub fn explain(&self, filters: &[Expr]) -> Plan {
        plan(&translate(filters), self.fallback)
    }
}

/// The element field of every list column, in one place.
///
/// Arrow compares a batch's type against the schema's field by field, **including
/// the list element's name and nullability**, so a builder's default `item` against a
/// schema's `element` is a type mismatch and every query fails. Derived here once so
/// the schema and the builder cannot disagree: the first version declared it twice
/// and nine tests failed with one message.
///
/// Non-nullable because a repeated record field holds validated tokens and a `Vec`
/// cannot contain a null. The Parquet writer says the same thing about the same
/// columns, and the pyarrow oracle insists on it.
fn list_element_field() -> Arc<Field> {
    Arc::new(Field::new("element", DataType::Utf8, false))
}

/// The Arrow schema of a projection, derived from the projection itself.
///
/// Built from an empty projection rather than written out again: the column list
/// lives in `trailryx-projection` and a second copy here would drift. The types map
/// one to one, and the list columns become `List<Utf8>` with non-nullable elements,
/// which is what the Parquet writer emits and what pyarrow reads back.
fn projection_schema() -> SchemaRef {
    let columns = project_columns(&[]);
    let fields: Vec<Field> = columns
        .iter()
        .map(|c| match &c.values {
            Values::Int32(_) => Field::new(&c.name, DataType::Int32, c.optional),
            Values::Int64(_) => Field::new(&c.name, DataType::Int64, c.optional),
            Values::String(_) => Field::new(&c.name, DataType::Utf8, c.optional),
            Values::StringList(_) => {
                Field::new(&c.name, DataType::List(list_element_field()), false)
            }
        })
        .collect();
    Arc::new(Schema::new(fields))
}

/// One Arrow array per column.
fn to_array(column: &Column) -> ArrayRef {
    match &column.values {
        Values::Int32(v) => Arc::new(Int32Array::from(v.clone())) as ArrayRef,
        Values::Int64(v) => Arc::new(Int64Array::from(v.clone())) as ArrayRef,
        Values::String(v) => {
            let mut b = StringBuilder::new();
            for cell in v {
                match cell {
                    Some(text) => b.append_value(text),
                    None => b.append_null(),
                }
            }
            Arc::new(b.finish()) as ArrayRef
        }
        Values::StringList(v) => {
            let mut b = ListBuilder::new(StringBuilder::new()).with_field(list_element_field());
            for list in v {
                for element in list {
                    b.values().append_value(element);
                }
                // Always append, so an empty list is an empty list and not a null.
                // The same distinction the Parquet writer had to get right, and the
                // same failure if it is wrong: every later row shifts by one.
                b.append(true);
            }
            Arc::new(b.finish()) as ArrayRef
        }
    }
}

/// A literal, rendered the way the projection renders that column.
fn literal_text(value: &ScalarValue) -> Option<String> {
    match value {
        ScalarValue::Utf8(Some(s)) | ScalarValue::LargeUtf8(Some(s)) => Some(s.clone()),
        _ => None,
    }
}

fn literal_i64(value: &ScalarValue) -> Option<i64> {
    match value {
        ScalarValue::Int64(Some(v)) => Some(*v),
        ScalarValue::Int32(Some(v)) => Some(i64::from(*v)),
        ScalarValue::UInt64(Some(v)) => i64::try_from(*v).ok(),
        _ => None,
    }
}

/// The index key a literal names on a dimension, or `None` if it names nothing.
///
/// Every byte comes from `Dimension::key_from_text` or `key_from_i64`, which live in
/// `trailryx-index` beside the derivation used when the record was written. This
/// function does no encoding of its own on purpose: a key computed here that
/// differed by one byte would make a range miss records the index holds while the
/// completeness proof said the answer was whole.
fn key_of(dimension: Dimension, value: &ScalarValue) -> Option<Vec<u8>> {
    if let Some(text) = literal_text(value) {
        return dimension.key_from_text(&text);
    }
    literal_i64(value).and_then(|v| dimension.key_from_i64(v))
}

/// Turn DataFusion's filters into predicates this facade can reason about.
///
/// One entry out per filter in, in order, so `supports_filters_pushdown` and `scan`
/// agree about which filter is which. A shape that is not recognised becomes
/// `Opaque` carrying its own text, so the answer can name it.
fn translate(filters: &[Expr]) -> Vec<Predicate> {
    filters.iter().map(translate_one).collect()
}

fn translate_one(filter: &Expr) -> Predicate {
    let opaque = || Predicate::Opaque(filter.to_string());

    match filter {
        Expr::BinaryExpr(binary) => {
            let (column, value, op) = match (binary.left.as_ref(), binary.right.as_ref()) {
                (Expr::Column(c), Expr::Literal(v, _)) => (c, v, binary.op),
                // `4471 = run_id` means the same thing with the operator mirrored.
                // Handled because a planner may hand it over either way round and a
                // facade that only read one shape would quietly stop proving.
                (Expr::Literal(v, _), Expr::Column(c)) => (c, v, mirror(binary.op)),
                _ => return opaque(),
            };
            let Some(dimension) = dimension_of(&column.name) else {
                return opaque();
            };
            let Some(key) = key_of(dimension, value) else {
                return opaque();
            };
            match op {
                Operator::Eq => Predicate::Equals {
                    column: column.name.clone(),
                    key,
                },
                // A one-sided bound is a range with the other end open. The open end
                // is the widest key the dimension can hold, which for a byte-ordered
                // index is a run of 0xFF longer than any real key.
                Operator::GtEq => Predicate::Between {
                    column: column.name.clone(),
                    lo: key,
                    hi: vec![0xFF; 64],
                },
                Operator::LtEq => Predicate::Between {
                    column: column.name.clone(),
                    lo: Vec::new(),
                    hi: key,
                },
                // Strict inequalities are deliberately not narrowed. The index's
                // ranges are inclusive, and turning `>` into `>=` on the successor
                // key needs key arithmetic per dimension. Treating it as opaque is
                // correct and slower; treating it as inclusive would return a row
                // the query excluded.
                _ => opaque(),
            }
        }
        Expr::Between(between) if !between.negated => {
            let (Expr::Column(column), Expr::Literal(low, _), Expr::Literal(high, _)) = (
                between.expr.as_ref(),
                between.low.as_ref(),
                between.high.as_ref(),
            ) else {
                return opaque();
            };
            let Some(dimension) = dimension_of(&column.name) else {
                return opaque();
            };
            match (key_of(dimension, low), key_of(dimension, high)) {
                (Some(lo), Some(hi)) => Predicate::Between {
                    column: column.name.clone(),
                    lo,
                    hi,
                },
                _ => opaque(),
            }
        }
        _ => opaque(),
    }
}

fn mirror(op: Operator) -> Operator {
    match op {
        Operator::Lt => Operator::Gt,
        Operator::LtEq => Operator::GtEq,
        Operator::Gt => Operator::Lt,
        Operator::GtEq => Operator::LtEq,
        other => other,
    }
}

#[async_trait::async_trait]
impl TableProvider for RecordTable {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        // Read only, and not as a default: `INSERT` through SQL is forbidden by
        // `docs/planning/trailryx-plan.md`. Records arrive through a `Source` and
        // nowhere else, so there is nothing here that could perform a write.
        TableType::View
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DfResult<Vec<TableProviderFilterPushDown>> {
        let owned: Vec<Expr> = filters.iter().map(|f| (*f).clone()).collect();
        let planned = plan(&translate(&owned), self.fallback);
        Ok(planned
            .placements
            .iter()
            .map(|placement| match placement {
                // Exact only for the sorted dimension, where the index guarantees it
                // omits nothing that passes. Claiming Exact for an approximation is
                // how rows go missing without anybody noticing.
                Placement::Indexed => TableProviderFilterPushDown::Exact,
                // Inexact for both of the others, and `Unsupported` for nothing.
                //
                // `Unsupported` means DataFusion evaluates the predicate above us and
                // does not hand it to `scan`. A facade whose job includes reporting
                // provability cannot afford not to be told: it would see no predicate,
                // find nothing unproved, and report a FULL proof for a query it had
                // only seen part of. That is the exact shape of lie this whole design
                // exists to prevent, and it was live until a test asked what
                // `severity = 'error'` reported.
                //
                // The cost of `Inexact` is that DataFusion re-checks a predicate we
                // may have already applied. That is a redundant comparison. The
                // alternative was a false proof.
                Placement::Filtered | Placement::Engine => TableProviderFilterPushDown::Inexact,
            })
            .collect())
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        // Rows already chosen by a table function: nothing to plan, and the proof
        // came with them.
        if let Some(rows) = &self.fixed {
            let batch = self.batch(rows)?;
            let table = MemTable::try_new(Arc::clone(&self.schema), vec![vec![batch]])?;
            return table.scan(state, projection, &[], limit).await;
        }

        let mut planned = plan(&translate(filters), self.fallback);
        if let Some(at) = self.as_of {
            // Folded into the query rather than filtered afterwards, so the index
            // answers the bounded question and the proof is about that question.
            planned.query = planned.query.as_of(at);
        }

        // The query goes to the authenticated index, segment by segment. Nothing
        // here scans a record the index did not return, which is what makes the
        // pushdown real rather than decorative.
        let mut rows: Vec<(trailryx_record::Record, trailryx_record::Hash)> = Vec::new();
        let mut proof_downgraded = Vec::new();
        for segment in &self.segments {
            let answer = query_segment(segment, &planned.query);
            if !answer.proof.is_full() {
                proof_downgraded.push(format!(
                    "segment {}: {:?}",
                    segment.manifest().segment.0,
                    answer.proof
                ));
            }
            // The chain link comes from the segment, which is the only place that
            // has it: an answer carries records and not links. Matched on `seq`,
            // which is unique within a segment because the journal numbers each file
            // from one. Deriving a link any other way would put a value in the
            // `chain_link` column that nothing chains to, and that column is what
            // makes a row checkable at all.
            let wanted: std::collections::BTreeSet<u64> =
                answer.records.iter().map(|r| r.seq).collect();
            for (record, link) in segment.records().iter().zip(segment.links()) {
                if wanted.contains(&record.seq) {
                    rows.push((record.clone(), link));
                }
            }
        }

        // The proof is derived: full only when every predicate was indexed AND every
        // segment's own proof came back whole. Two independent ways to lose it and
        // both are reported, because a partial answer that says which half failed is
        // actionable and one that does not is just a smaller number.
        let mut reasons = planned.unproved.clone();
        reasons.extend(proof_downgraded);
        let provability = if reasons.is_empty() {
            Provability::Full
        } else {
            Provability::Partial(reasons)
        };
        if let Ok(mut slot) = self.last_proof.lock() {
            *slot = Some(provability);
        }

        let batch = self.batch(&rows)?;
        let table = MemTable::try_new(Arc::clone(&self.schema), vec![vec![batch]])?;
        table.scan(state, projection, &[], limit).await
    }
}

impl RecordTable {
    /// The records the index returned, as one Arrow batch.
    fn batch(
        &self,
        rows: &[(trailryx_record::Record, trailryx_record::Hash)],
    ) -> DfResult<RecordBatch> {
        // The projection is built by `trailryx-projection` rather than assembled
        // here, so the column list and the rendering have exactly one home.
        let columns = trailryx_projection::columns_from_records(rows);
        let arrays: Vec<ArrayRef> = columns.iter().map(to_array).collect();
        RecordBatch::try_new(Arc::clone(&self.schema), arrays)
            .map_err(|e| DataFusionError::ArrowError(Box::new(e), None))
    }
}
