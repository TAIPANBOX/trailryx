//! Reconstructing what led to a decision.
//!
//! # The shape of the problem
//!
//! A record names several parents, not one: a decision follows from a request
//! **and** a policy verdict **and** a memory state **and** a budget. Following
//! those is a graph traversal, and a traversal is exactly the kind of operation
//! that quietly stops being provable, because each hop is a fresh question and
//! nothing obliges the answerer to ask it honestly.
//!
//! # How it stays provable
//!
//! Every hop is a query on a **sorted dimension**, so each one carries its own
//! completeness proof:
//!
//! - a run is fetched by `run_id`;
//! - a parent record is fetched by `id`, which is why the record id became the
//!   fifth provable dimension.
//!
//! And every hop's *reason for existing* is an edge inside a record that was
//! already proved. So the closure is not a walk somebody took and asked us to
//! believe; it is a sequence of proved answers, each justified by committed
//! data in the previous one.
//!
//! If any hop comes back short of a full proof, the whole reconstruction says
//! so. A closure that is ninety percent proved is not a proved closure, and
//! reporting it as one would be the failure this project exists to avoid.
//!
//! # Bounds, and why they are visible
//!
//! Depth and size are bounded. A malformed graph, or a hostile one, must not
//! turn a query into an unbounded walk. When a bound stops the traversal the
//! result says which one and how much was left, because a truncated closure
//! reported as complete is the same lie in a different coat.

use crate::query::{Answer, ProofStatus, Query, query_segment};
use std::collections::{BTreeSet, VecDeque};
use trailryx_index::completeness::{CompletenessProof, Dimension};
use trailryx_index::segment::Segment;
use trailryx_record::{Record, RecordId, RunId};

/// How far a reconstruction may go before it stops and says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub max_hops: usize,
    pub max_records: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_hops: 64,
            max_records: 10_000,
        }
    }
}

/// Why a traversal stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// Nothing left to follow.
    Exhausted,
    HopLimit,
    RecordLimit,
}

/// One step of the traversal, and why it was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hop {
    /// The run asked about.
    Root { run: RunId },
    /// A run reached through `parent_run_id` on an already-proved record.
    ParentRun { run: RunId, from: RecordId },
    /// A record reached through a `caused_by` edge on an already-proved record.
    Cause { record: RecordId, from: RecordId },
}

#[derive(Debug, Clone)]
pub struct Reconstruction {
    pub records: Vec<Record>,
    pub proof: ProofStatus,
    /// Each hop, in the order taken, with the record that justified it.
    pub hops: Vec<Hop>,
    pub segment_proofs: Vec<CompletenessProof>,
    pub stopped: Stopped,
}

impl Reconstruction {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether every hop came back fully proved **and** the traversal finished.
    ///
    /// Both halves matter: a closure cut short by a bound is not complete even
    /// if every hop it did take was perfect.
    pub fn is_complete(&self) -> bool {
        self.proof.is_full() && self.stopped == Stopped::Exhausted
    }
}

enum Step {
    Run(RunId),
    Record(RecordId),
}

/// Reconstruct everything that led to a run, across the segments given.
///
/// The segments are the caller's business: one shard's, or every shard's. The
/// traversal does not care, which is the point, because causality crosses
/// shards by nature: a delegation chain connects different agents, and agents
/// are what the store is sharded by.
pub fn reconstruct(segments: &[&Segment], run: &RunId, bounds: Bounds) -> Reconstruction {
    let mut records: Vec<Record> = Vec::new();
    let mut seen_records: BTreeSet<RecordId> = BTreeSet::new();
    let mut seen_runs: BTreeSet<String> = BTreeSet::new();
    let mut hops: Vec<Hop> = Vec::new();
    let mut proofs: Vec<CompletenessProof> = Vec::new();
    let mut status = ProofStatus::Full;

    let mut queue: VecDeque<(Step, Option<RecordId>)> = VecDeque::new();
    queue.push_back((Step::Run(run.clone()), None));
    seen_runs.insert(run.as_str().to_owned());
    hops.push(Hop::Root { run: run.clone() });

    let mut taken = 0usize;
    let mut stopped = Stopped::Exhausted;

    while let Some((step, from)) = queue.pop_front() {
        if taken >= bounds.max_hops {
            stopped = Stopped::HopLimit;
            break;
        }
        taken += 1;

        let query = match &step {
            Step::Run(r) => Query::point(Dimension::RunId, r.as_str().as_bytes().to_vec()),
            Step::Record(id) => Query::point(Dimension::RecordId, Dimension::id_key(*id)),
        };

        // Every segment is asked, and each answers with its own proof. A
        // segment that holds nothing matching still answers, because "I have
        // none of these" is a claim that has to be backed like any other.
        let mut found: Vec<Record> = Vec::new();
        for seg in segments {
            let a: Answer = query_segment(seg, &query);
            merge_status(&mut status, &a.proof);
            proofs.extend(a.segment_proofs);
            found.extend(a.records);
        }

        if let (Step::Record(id), Some(_)) = (&step, from)
            && !found.iter().any(|r| r.id == *id)
        {
            // An edge pointing at a record no segment holds. Not a crash and
            // not silence: the closure is short and must say so.
            status.downgrade_public("a caused_by edge points outside these segments");
        }

        for r in found {
            if !seen_records.insert(r.id) {
                continue;
            }
            if records.len() >= bounds.max_records {
                stopped = Stopped::RecordLimit;
                break;
            }

            // Edges are read from a record that has just been proved, so the
            // reason for the next hop is committed data rather than a claim.
            if let Some(parent) = &r.parent_run_id
                && seen_runs.insert(parent.as_str().to_owned())
            {
                hops.push(Hop::ParentRun {
                    run: parent.clone(),
                    from: r.id,
                });
                queue.push_back((Step::Run(parent.clone()), Some(r.id)));
            }
            for cause in &r.caused_by {
                if seen_records.contains(cause) {
                    continue;
                }
                hops.push(Hop::Cause {
                    record: *cause,
                    from: r.id,
                });
                queue.push_back((Step::Record(*cause), Some(r.id)));
            }

            records.push(r);
        }

        if stopped == Stopped::RecordLimit {
            break;
        }
    }

    // A stable order, so two honest reconstructions of the same closure are
    // the same answer rather than merely equivalent ones.
    records.sort_by_key(|r| (r.recorded_at, r.id));

    Reconstruction {
        records,
        proof: status,
        hops,
        segment_proofs: proofs,
        stopped,
    }
}

fn merge_status(into: &mut ProofStatus, other: &ProofStatus) {
    match other {
        ProofStatus::Full => {}
        ProofStatus::Partial { unproved } => {
            for u in unproved {
                into.downgrade_public(u);
            }
        }
        ProofStatus::None { why } => into.downgrade_public(why),
    }
}
