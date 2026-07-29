//! The read surface.
//!
//! One rule governs everything here:
//!
//! > **Every answer says how much of itself is proved.**
//!
//! Not a flag the caller may request, and not something only the evidence path
//! bothers with. An answer that quietly mixes proved rows with filtered ones is
//! worse than an unproved answer, because it looks like the first kind. So
//! [`ProofStatus`] rides on every [`Answer`], and each thing that downgrades it
//! names itself.
//!
//! # What downgrades a proof
//!
//! - a predicate on a field that is not a sorted dimension;
//! - `as_of` combined with a dimension other than time, because one index is
//!   sorted by one thing and a second predicate on a different field cannot be
//!   covered by it;
//! - records still in the journal, unsealed: they are real and returned, but no
//!   segment commits to them yet.
//!
//! Each of those is a legitimate query. None of them is a proof, and the
//! difference is the product.

use trailryx_index::completeness::{CompletenessProof, Dimension};
use trailryx_index::segment::Segment;
use trailryx_record::{ErrorCode, Record, Severity, TenantId, Timestamp, Verdict};

/// A predicate that no index is sorted by.
///
/// Perfectly useful, never provable. Applying one is a deliberate act with a
/// visible cost, which is why they are enumerated rather than free-form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    Tenant(TenantId),
    Severity(Severity),
    MinSeverity(Severity),
    Verdict(Verdict),
    Error(ErrorCode),
    HasPayload(bool),
}

impl Filter {
    fn matches(&self, r: &Record) -> bool {
        match self {
            Self::Tenant(t) => &r.tenant == t,
            Self::Severity(s) => r.severity == *s,
            Self::MinSeverity(s) => severity_rank(r.severity) >= severity_rank(*s),
            Self::Verdict(v) => r.outcome.verdict == Some(*v),
            Self::Error(e) => r.outcome.error == Some(*e),
            Self::HasPayload(want) => r.payload.is_some() == *want,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Tenant(_) => "tenant",
            Self::Severity(_) | Self::MinSeverity(_) => "severity",
            Self::Verdict(_) => "outcome.verdict",
            Self::Error(_) => "outcome.error",
            Self::HasPayload(_) => "payload",
        }
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Debug => 0,
        Severity::Info => 1,
        Severity::Notice => 2,
        Severity::Warning => 3,
        Severity::Error => 4,
        Severity::Critical => 5,
    }
}

/// What to ask for.
#[derive(Debug, Clone)]
pub struct Query {
    pub dimension: Dimension,
    pub lo: Vec<u8>,
    pub hi: Vec<u8>,
    /// Predicates outside the sorted dimension. Each one costs the proof.
    pub filters: Vec<Filter>,
    /// The store as it was known at this instant.
    ///
    /// This is **transaction time**: records the store had recorded by then.
    /// It is not valid-time travel, which would need a layer of facts that
    /// supersede one another, and this store holds events. Saying which of the
    /// two is on offer matters, because the two answer different questions and
    /// only one of them is implemented.
    pub as_of: Option<Timestamp>,
}

impl Query {
    pub fn range(dimension: Dimension, lo: Vec<u8>, hi: Vec<u8>) -> Self {
        Self {
            dimension,
            lo,
            hi,
            filters: Vec::new(),
            as_of: None,
        }
    }

    pub fn point(dimension: Dimension, key: Vec<u8>) -> Self {
        Self::range(dimension, key.clone(), key)
    }

    pub fn time_between(from: Timestamp, to: Timestamp) -> Self {
        Self::range(
            Dimension::RecordedAt,
            Dimension::time_key(from.as_nanos()),
            Dimension::time_key(to.as_nanos()),
        )
    }

    pub fn with(mut self, f: Filter) -> Self {
        self.filters.push(f);
        self
    }

    pub fn as_of(mut self, at: Timestamp) -> Self {
        self.as_of = Some(at);
        self
    }

    /// The effective upper bound, once `as_of` has been folded in where it can
    /// be.
    fn effective_hi(&self) -> Vec<u8> {
        match (self.as_of, self.dimension) {
            // On the time dimension, `as_of` is simply a tighter bound, and the
            // proof survives.
            (Some(at), Dimension::RecordedAt) => {
                let bound = Dimension::time_key(at.as_nanos());
                if bound < self.hi {
                    bound
                } else {
                    self.hi.clone()
                }
            }
            _ => self.hi.clone(),
        }
    }
}

/// How much of an answer is proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofStatus {
    /// Every returned record is covered by a completeness proof, and nothing
    /// matching was left out.
    Full,
    /// Some of the answer is proved and some is not. The reasons are listed so
    /// a reader knows precisely what they are being told.
    Partial { unproved: Vec<&'static str> },
    /// Nothing was proved.
    None { why: &'static str },
}

impl ProofStatus {
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }

    fn downgrade(&mut self, reason: &'static str) {
        match self {
            Self::Full => {
                *self = Self::Partial {
                    unproved: vec![reason],
                }
            }
            Self::Partial { unproved } => {
                if !unproved.contains(&reason) {
                    unproved.push(reason);
                }
            }
            Self::None { .. } => {}
        }
    }
}

/// Records, and the truth about how well they are backed.
#[derive(Debug, Clone)]
pub struct Answer {
    pub records: Vec<Record>,
    pub proof: ProofStatus,
    /// One completeness proof per segment consulted, in order.
    pub segment_proofs: Vec<CompletenessProof>,
    /// How many records the sorted index matched before filters were applied.
    /// The gap between this and `records.len()` is exactly what the filters
    /// removed, and it is visible on purpose.
    pub matched_before_filters: usize,
}

impl Answer {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Run a query over one sealed segment.
///
/// The proof covers the sorted dimension. Filters are applied afterwards, in
/// the open, and each one downgrades the status by name.
pub fn query_segment(segment: &Segment, q: &Query) -> Answer {
    let hi = q.effective_hi();
    let mut status = ProofStatus::Full;

    if q.as_of.is_some() && q.dimension != Dimension::RecordedAt {
        // One index is sorted by one thing. A second predicate on a different
        // field cannot be covered by it, and pretending otherwise would be the
        // exact dishonesty this type exists to prevent.
        status.downgrade("as_of");
    }

    let Some(idx) = segment.index(q.dimension) else {
        return Answer {
            records: Vec::new(),
            proof: ProofStatus::None {
                why: "the segment has no index for this dimension",
            },
            segment_proofs: Vec::new(),
            matched_before_filters: 0,
        };
    };

    let proof = idx.range(&q.lo, &hi);
    let matched = proof.matched();

    // The index proves which entries match; the records themselves come from
    // the segment's own copy, keyed by the position the proof commits to.
    let mut records: Vec<Record> = proof
        .entries
        .iter()
        .filter_map(|e| segment.record_by_link(e.record_link).cloned())
        .collect();

    if let Some(at) = q.as_of
        && q.dimension != Dimension::RecordedAt
    {
        records.retain(|r| r.recorded_at <= at);
    }

    for f in &q.filters {
        records.retain(|r| f.matches(r));
        // Applied, therefore counted, even when it removed nothing this time.
        // The proof covers the range, not the filtered result, and whether a
        // particular run happened to drop rows is not what makes the difference.
        status.downgrade(f.name());
    }

    Answer {
        records,
        proof: status,
        segment_proofs: vec![proof],
        matched_before_filters: matched,
    }
}
