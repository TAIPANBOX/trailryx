//! Completeness, attacked.
//!
//! The honest cases are the easy half. The half that matters is every way an
//! answer could be shrunk, padded or reshuffled while still looking plausible:
//! hiding a record, inventing one, dropping a boundary, supplying a boundary
//! that does not bound, or reusing a proof for a different range.

use trailryx_crypto::Sha384;
use trailryx_index::completeness::{Dimension, Entry, ProofFailure, SortedIndex};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};

fn record(seq: u64, agent: &str, at: u64, kind: EventType) -> (Record, Hash) {
    let r = Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse(agent).unwrap(),
        run_id: RunId::parse(format!("run-{seq}")).unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(at)),
        decided_at: None,
        recorded_at: Timestamp(at),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: kind,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome::default(),
        payload: None,
        seq,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    };
    let leaf = Sha384::digest(format!("record-leaf-{seq}").as_bytes());
    (r, leaf)
}

/// Twelve records across three agents and a spread of times.
fn corpus() -> Vec<(Record, Hash)> {
    let agents = [
        "agent://acme.example/support",
        "agent://acme.example/billing",
        "agent://acme.example/triage",
    ];
    (1..=12u64)
        .map(|i| {
            record(
                i,
                agents[(i as usize - 1) % 3],
                1_000 + i * 10,
                if i % 2 == 0 {
                    EventType::ModelCall
                } else {
                    EventType::ToolCall
                },
            )
        })
        .collect()
}

#[test]
fn an_honest_range_verifies() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    let proof = idx.range(&lo, &hi);
    assert_eq!(proof.matched(), 6, "times 1030..=1080 inclusive");
    assert_eq!(
        proof.verify(Dimension::RecordedAt, &lo, &hi, root, idx.len()),
        Ok(())
    );
}

#[test]
fn a_range_at_each_edge_verifies() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();

    // Everything: no boundaries exist to supply.
    let all = idx.range(&Dimension::time_key(0), &Dimension::time_key(u64::MAX));
    assert_eq!(all.matched(), 12);
    assert!(all.left_boundary.is_none() && all.right_boundary.is_none());
    assert_eq!(
        all.verify(
            Dimension::RecordedAt,
            &Dimension::time_key(0),
            &Dimension::time_key(u64::MAX),
            root,
            idx.len()
        ),
        Ok(())
    );

    // Nothing: an empty answer still has to prove it is empty.
    let none = idx.range(&Dimension::time_key(5_000), &Dimension::time_key(6_000));
    assert_eq!(none.matched(), 0);
    assert_eq!(
        none.verify(
            Dimension::RecordedAt,
            &Dimension::time_key(5_000),
            &Dimension::time_key(6_000),
            root,
            idx.len()
        ),
        Ok(())
    );
}

#[test]
fn every_dimension_answers_and_proves() {
    let c = corpus();
    for d in Dimension::ALL {
        let idx = SortedIndex::build(*d, &c);
        let root = idx.root();
        let proof = idx.range(&[], &[0xff; 32]);
        assert_eq!(
            proof.verify(*d, &[], &[0xff; 32], root, idx.len()),
            Ok(()),
            "{d:?}"
        );
    }
}

#[test]
fn one_agents_records_are_provably_all_of_them() {
    let idx = SortedIndex::build(Dimension::AgentId, &corpus());
    let root = idx.root();
    let key = b"agent://acme.example/billing".to_vec();

    let proof = idx.range(&key, &key);
    assert_eq!(proof.matched(), 4);
    assert_eq!(
        proof.verify(Dimension::AgentId, &key, &key, root, idx.len()),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Attacks
// ---------------------------------------------------------------------------

#[test]
fn hiding_a_record_breaks_the_proof() {
    // The whole point. An answer with a record quietly removed must not verify.
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    let mut proof = idx.range(&lo, &hi);
    proof.entries.remove(2);
    proof.entry_proofs.remove(2);

    let err = proof
        .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
        .unwrap_err();
    assert!(
        matches!(err, ProofFailure::NotContiguous { .. }),
        "expected a contiguity failure, got {err:?}"
    );
}

#[test]
fn hiding_the_last_record_of_a_range_breaks_the_proof() {
    // Trimming the tail is the subtler attack: contiguity still holds, so the
    // right boundary is what has to catch it. Both a lazy attacker and a
    // careful one are tried, because only the careful one tests the property.
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    // Lazy: drop the entry, leave the old boundary in place.
    let mut lazy = idx.range(&lo, &hi);
    lazy.entries.pop();
    lazy.entry_proofs.pop();
    let err = lazy
        .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            ProofFailure::BoundaryAtWrongPosition { side: "right", .. }
        ),
        "got {err:?}"
    );

    // Careful: also move the boundary to the position that now looks right,
    // which is the hidden record itself. It is a genuine entry with a genuine
    // inclusion proof, so only the range check can refuse it.
    let mut careful = idx.range(&lo, &hi);
    let hidden = careful.entries.pop().expect("range is not empty");
    let hidden_proof = careful.entry_proofs.pop().expect("proof exists");
    careful.right_boundary = Some((hidden, hidden_proof));
    let err = careful
        .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
        .unwrap_err();
    assert_eq!(
        err,
        ProofFailure::BoundaryDoesNotBound { side: "right" },
        "a boundary inside the range would leave the record hidden"
    );
}

#[test]
fn hiding_the_first_record_of_a_range_breaks_the_proof() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    // Lazy: drop the head and shift the start, leaving the stale boundary.
    let mut lazy = idx.range(&lo, &hi);
    lazy.entries.remove(0);
    lazy.entry_proofs.remove(0);
    lazy.first_index += 1;
    let err = lazy
        .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            ProofFailure::BoundaryAtWrongPosition { side: "left", .. }
        ),
        "got {err:?}"
    );

    // Careful: move the left boundary onto the hidden record.
    let mut careful = idx.range(&lo, &hi);
    let hidden = careful.entries.remove(0);
    let hidden_proof = careful.entry_proofs.remove(0);
    careful.first_index += 1;
    careful.left_boundary = Some((hidden, hidden_proof));
    let err = careful
        .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
        .unwrap_err();
    assert_eq!(
        err,
        ProofFailure::BoundaryDoesNotBound { side: "left" },
        "a boundary inside the range would leave the record hidden"
    );
}

#[test]
fn inventing_a_record_breaks_the_proof() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    let mut proof = idx.range(&lo, &hi);
    proof.entries[1].record_link = Sha384::digest(b"a record that never existed");

    let err = proof
        .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
        .unwrap_err();
    assert!(
        matches!(err, ProofFailure::EntryNotInTree { at: 1 }),
        "got {err:?}"
    );
}

#[test]
fn dropping_a_boundary_breaks_the_proof() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    let mut proof = idx.range(&lo, &hi);
    proof.right_boundary = None;
    assert_eq!(
        proof.verify(Dimension::RecordedAt, &lo, &hi, root, idx.len()),
        Err(ProofFailure::MissingRightBoundary)
    );

    let mut proof = idx.range(&lo, &hi);
    proof.left_boundary = None;
    assert_eq!(
        proof.verify(Dimension::RecordedAt, &lo, &hi, root, idx.len()),
        Err(ProofFailure::MissingLeftBoundary)
    );
}

#[test]
fn a_boundary_that_does_not_bound_is_rejected() {
    // Supplying a real, provable entry that happens to sit inside the range
    // would let a record beyond it stay hidden.
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    let inner = idx.range(&Dimension::time_key(1_050), &Dimension::time_key(1_050));
    let mut proof = idx.range(&lo, &hi);
    proof.right_boundary = Some((inner.entries[0].clone(), inner.entry_proofs[0].clone()));

    let err = proof
        .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
        .unwrap_err();
    assert!(
        matches!(
            err,
            ProofFailure::BoundaryAtWrongPosition { side: "right", .. }
        ),
        "a boundary from the middle of the range sits at the wrong index: {err:?}"
    );
}

#[test]
fn a_proof_for_one_range_does_not_answer_another() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let proof = idx.range(&Dimension::time_key(1_030), &Dimension::time_key(1_080));

    // Same proof, wider question. It must not pass, or an answer could be
    // reused to under-report a larger range.
    assert!(
        proof
            .verify(
                Dimension::RecordedAt,
                &Dimension::time_key(1_000),
                &Dimension::time_key(1_120),
                root,
                idx.len()
            )
            .is_err()
    );
}

#[test]
fn a_proof_from_one_dimension_does_not_answer_another() {
    let c = corpus();
    let by_time = SortedIndex::build(Dimension::RecordedAt, &c);
    let proof = by_time.range(&Dimension::time_key(0), &Dimension::time_key(u64::MAX));
    assert_eq!(
        proof.verify(
            Dimension::AgentId,
            &[],
            &[0xff],
            by_time.root(),
            by_time.len()
        ),
        Err(ProofFailure::WrongDimension)
    );
}

#[test]
fn a_proof_does_not_verify_against_another_segments_root() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let mut other_records = corpus();
    other_records.push(record(
        13,
        "agent://acme.example/support",
        1_130,
        EventType::ToolCall,
    ));
    let other = SortedIndex::build(Dimension::RecordedAt, &other_records);

    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);
    let proof = idx.range(&lo, &hi);

    assert!(
        proof
            .verify(Dimension::RecordedAt, &lo, &hi, other.root(), idx.len())
            .is_err()
    );
}

#[test]
fn reordering_the_answer_is_rejected() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();
    let lo = Dimension::time_key(1_030);
    let hi = Dimension::time_key(1_080);

    let mut proof = idx.range(&lo, &hi);
    proof.entries.swap(0, 1);

    assert!(
        proof
            .verify(Dimension::RecordedAt, &lo, &hi, root, idx.len())
            .is_err()
    );
}

#[test]
fn every_sub_range_of_the_corpus_verifies() {
    // Exhaustive rather than sampled: every window over the twelve records,
    // including the empty ones at both ends.
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let root = idx.root();

    for lo_t in (990..=1_140).step_by(5) {
        for hi_t in (lo_t..=1_140).step_by(5) {
            let lo = Dimension::time_key(lo_t);
            let hi = Dimension::time_key(hi_t);
            let proof = idx.range(&lo, &hi);
            assert_eq!(
                proof.verify(Dimension::RecordedAt, &lo, &hi, root, idx.len()),
                Ok(()),
                "range {lo_t}..={hi_t}"
            );
            let expected = (1..=12u64)
                .filter(|i| {
                    let t = 1_000 + i * 10;
                    t >= lo_t && t <= hi_t
                })
                .count();
            assert_eq!(proof.matched(), expected, "range {lo_t}..={hi_t}");
        }
    }
}

// ---------------------------------------------------------------------------
// The shape of the answer must not come from the answer
// ---------------------------------------------------------------------------

#[test]
fn an_empty_proof_does_not_verify_against_a_non_empty_index() {
    // The attack that defeated the first version: declare size 0 and there are
    // no entries to check, no boundaries to demand, and the root is never read.
    // It verified against every root, including one belonging to a segment full
    // of matching records.
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let forged = trailryx_index::completeness::CompletenessProof {
        dimension: Dimension::RecordedAt,
        size: 0,
        first_index: 0,
        entries: Vec::new(),
        entry_proofs: Vec::new(),
        left_boundary: None,
        right_boundary: None,
    };

    let lo = Dimension::time_key(0);
    let hi = Dimension::time_key(u64::MAX);
    assert_eq!(
        forged.verify(Dimension::RecordedAt, &lo, &hi, idx.root(), idx.len()),
        Err(ProofFailure::WrongSize {
            expected: 12,
            got: 0
        })
    );
    // Even told the size it claims, it cannot borrow another index's root.
    assert_eq!(
        forged.verify(Dimension::RecordedAt, &lo, &hi, idx.root(), 0),
        Err(ProofFailure::EmptyAnswerAgainstNonEmptyIndex)
    );
}

#[test]
fn an_honestly_empty_index_still_answers() {
    let idx = SortedIndex::build(Dimension::RecordedAt, &[]);
    let lo = Dimension::time_key(0);
    let hi = Dimension::time_key(u64::MAX);
    let proof = idx.range(&lo, &hi);
    assert_eq!(proof.matched(), 0);
    assert_eq!(
        proof.verify(Dimension::RecordedAt, &lo, &hi, idx.root(), 0),
        Ok(())
    );
}

#[test]
fn an_empty_index_cannot_answer_with_entries() {
    // The seventh hole, found by the core review. Pinning the root closed the
    // first half of the `size: 0` attack and left the second half open: every
    // check below the branch is skipped, so an answer could declare itself empty
    // and still carry entries, and `matched()` counted them.
    //
    // What that buys an operator: seal one empty segment per shard before the
    // store root is signed and witnessed (an idle shard is normal, the sealer
    // calls it `NothingDurable`), and afterwards attach any number of fabricated
    // records to that slot in any query. The offline verifier sees nothing
    // either, because a zero-record segment passes record-count, history-root
    // and chain-across-segments cleanly.
    let empty = SortedIndex::build(Dimension::RecordedAt, &[]);
    let full = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let lo = Dimension::time_key(0);
    let hi = Dimension::time_key(u64::MAX);
    let borrowed = full.range(&lo, &hi);
    assert!(borrowed.matched() > 0, "there is something to borrow");

    let forged = trailryx_index::completeness::CompletenessProof {
        dimension: Dimension::RecordedAt,
        size: 0,
        first_index: 0,
        entries: borrowed.entries.clone(),
        entry_proofs: borrowed.entry_proofs.clone(),
        left_boundary: None,
        right_boundary: None,
    };
    assert_eq!(
        forged.verify(Dimension::RecordedAt, &lo, &hi, empty.root(), 0),
        Err(ProofFailure::EntriesAgainstEmptyIndex),
        "an empty index answered with twelve entries"
    );

    // Entries that are not even real, which is the cheaper version of the same
    // attack: no inclusion proof has to hold for a branch that checks none.
    let invented = trailryx_index::completeness::CompletenessProof {
        dimension: Dimension::RecordedAt,
        size: 0,
        first_index: 7,
        entries: vec![Entry {
            key: Dimension::time_key(1_234),
            seq: 99,
            record_link: Sha384::digest(b"a record that never existed"),
        }],
        entry_proofs: borrowed.entry_proofs[..1].to_vec(),
        left_boundary: None,
        right_boundary: None,
    };
    assert_eq!(
        invented.verify(Dimension::RecordedAt, &lo, &hi, empty.root(), 0),
        Err(ProofFailure::EntriesAgainstEmptyIndex)
    );

    // And the honest empty answer still verifies, which is the whole reason the
    // branch exists.
    let honest = empty.range(&lo, &hi);
    assert_eq!(
        honest.verify(Dimension::RecordedAt, &lo, &hi, empty.root(), 0),
        Ok(())
    );
}

#[test]
fn a_reversed_range_is_empty_rather_than_a_panic() {
    // A query surface forwards whatever a caller typed; a slice index is not
    // where that should be discovered.
    let idx = SortedIndex::build(Dimension::RecordedAt, &corpus());
    let proof = idx.range(&Dimension::time_key(1_090), &Dimension::time_key(1_010));
    assert_eq!(proof.matched(), 0);
}
