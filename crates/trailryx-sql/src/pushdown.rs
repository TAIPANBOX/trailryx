//! Which predicates reach the authenticated index, and which cost the proof.
//!
//! This module is the whole of `docs/planning/trailryx-architecture.md` §3.2 and it
//! deliberately **knows nothing about DataFusion**. It takes a description of a
//! predicate, decides where it can be evaluated, and says what that does to the
//! answer's provability. The engine-facing code translates DataFisuion's `Expr`
//! into these shapes and back.
//!
//! Keeping the boundary here is not tidiness. The classification is the part that
//! decides whether an answer is provable, so it has to be testable without an
//! async runtime, without a session context and without a query planner, and it has
//! to survive DataFusion changing its expression type.
//!
//! # The three places a predicate can be evaluated
//!
//! | Where | What it costs | Example |
//! |---|---|---|
//! | The **sorted dimension** of the authenticated index | nothing: the answer carries a completeness proof | `run_id = '4471'`, `recorded_at BETWEEN ...` |
//! | Our own **filter** pass over the records the index returned | the proof, because the index cannot prove a set it did not order | `severity = 'error'` |
//! | **DataFusion**, above us | the proof, and we do not even see what was dropped | `lower(agent_id) LIKE '%billing%'` |
//!
//! A query is fully provable only when every predicate landed in the first row.
//! One in either of the others and the answer says `partial` and names what did not
//! fall, which is what §3.2 requires in those words: "SQL не стає діркою в моделі
//! доказів: він або доводить, або чесно каже, що ні."
//!
//! # Why only one dimension can be the sorted one
//!
//! The index sorts each segment by one dimension at a time and proves completeness
//! against that order. Two range predicates on two dimensions cannot both be the
//! sorted one, so one of them becomes a filter and the answer is partial. Choosing
//! which is a cost decision and it is made explicitly in [`plan`] rather than by
//! whichever predicate happened to be first.

use trailryx_index::completeness::Dimension;
use trailryx_store::query::{Filter, Query};

/// A predicate, in the only shapes this facade can act on.
///
/// Not a general expression tree. A shape that is not here is a shape DataFusion
/// evaluates above us, and that is a decision rather than a gap: an expression
/// language we half-understood would be a place for a predicate to be quietly
/// dropped while the answer still claimed to be complete.
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    /// `column = value`, with the value already rendered as the index key would
    /// see it.
    Equals { column: String, key: Vec<u8> },
    /// `column BETWEEN lo AND hi`, inclusive both ends, as the index's ranges are.
    Between {
        column: String,
        lo: Vec<u8>,
        hi: Vec<u8>,
    },
    /// A predicate on a typed field the index does not order by.
    Field(Filter),
    /// Something this facade does not model.
    ///
    /// Carried rather than discarded so the answer can name it. A predicate the
    /// store cannot see is exactly the thing a partial proof exists to disclose.
    Opaque(String),
}

impl Predicate {
    /// The dimension this predicate could be proved on, if any.
    pub fn dimension(&self) -> Option<Dimension> {
        let column = match self {
            Self::Equals { column, .. } | Self::Between { column, .. } => column.as_str(),
            _ => return None,
        };
        dimension_of(column)
    }
}

/// The five provable dimensions, by the column name the projection uses.
///
/// The names are the projection's, not SQL's, because the projection is what a
/// reader sees. `recorded_at_nanos` rather than `recorded_at`: the column carries
/// its unit in its name because no Parquet converted type holds nanoseconds, and a
/// facade that silently accepted the shorter name would be accepting a column that
/// does not exist.
pub fn dimension_of(column: &str) -> Option<Dimension> {
    Some(match column {
        "record_id" => Dimension::RecordId,
        "recorded_at_nanos" => Dimension::RecordedAt,
        "agent_id" => Dimension::AgentId,
        "run_id" => Dimension::RunId,
        "event_type" => Dimension::EventType,
        _ => return None,
    })
}

/// What became of one predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Pushed into the authenticated index as the sorted dimension. Provable.
    Indexed,
    /// Applied by us over what the index returned. Costs the proof.
    Filtered,
    /// Left to the engine above us. Costs the proof, and we cannot say what it did.
    Engine,
}

/// A plan: what to ask the index, what it costs, and why.
#[derive(Debug, Clone)]
pub struct Plan {
    pub query: Query,
    /// One entry per predicate, in the order they arrived, so a caller can map an
    /// answer back to the query that produced it.
    pub placements: Vec<Placement>,
    /// Every predicate that was not proved, named. Empty means the answer is fully
    /// provable.
    pub unproved: Vec<String>,
}

impl Plan {
    pub fn is_fully_provable(&self) -> bool {
        self.unproved.is_empty()
    }
}

/// Choose the sorted dimension, and decide where everything else lands.
///
/// `fallback` is the dimension to scan when no predicate can be the sorted one: a
/// full scan of a dimension is still a proof that the scan was complete, which is
/// worth more than refusing to answer.
///
/// The choice among several candidates is **the most selective shape first**: an
/// equality before a range, and among equalities the first one given. Deliberate
/// and stated: taking whichever arrived first would make the provability of an
/// answer depend on the order somebody typed a `WHERE` clause.
pub fn plan(predicates: &[Predicate], fallback: Dimension) -> Plan {
    let chosen = predicates
        .iter()
        .position(|p| matches!(p, Predicate::Equals { .. }) && p.dimension().is_some())
        .or_else(|| {
            predicates
                .iter()
                .position(|p| matches!(p, Predicate::Between { .. }) && p.dimension().is_some())
        });

    let mut query = match chosen.map(|i| &predicates[i]) {
        Some(Predicate::Equals { column, key }) => Query::point(
            dimension_of(column).expect("chosen only when the dimension resolves"),
            key.clone(),
        ),
        Some(Predicate::Between { column, lo, hi }) => Query::range(
            dimension_of(column).expect("chosen only when the dimension resolves"),
            lo.clone(),
            hi.clone(),
        ),
        // No usable predicate: scan the whole fallback dimension. The proof still
        // says the scan was complete, which is the honest strongest answer.
        _ => Query::range(fallback, Vec::new(), vec![0xFF; 64]),
    };

    let mut placements = Vec::with_capacity(predicates.len());
    let mut unproved = Vec::new();

    for (i, predicate) in predicates.iter().enumerate() {
        if Some(i) == chosen {
            placements.push(Placement::Indexed);
            continue;
        }
        match predicate {
            Predicate::Field(filter) => {
                query = query.with(filter.clone());
                placements.push(Placement::Filtered);
                unproved.push(format!("{filter:?}"));
            }
            // A second predicate on a provable dimension is still not provable:
            // the index sorts by one dimension at a time. Named so nobody reads a
            // partial answer and assumes the store simply did not look.
            Predicate::Equals { column, .. } | Predicate::Between { column, .. } => {
                placements.push(Placement::Engine);
                unproved.push(format!(
                    "{column}: a second predicate on a provable dimension, and the index sorts \
                     by one at a time"
                ));
            }
            Predicate::Opaque(text) => {
                placements.push(Placement::Engine);
                unproved.push(text.clone());
            }
        }
    }

    Plan {
        query,
        placements,
        unproved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_record::Severity;

    fn eq(column: &str, key: &[u8]) -> Predicate {
        Predicate::Equals {
            column: column.to_owned(),
            key: key.to_vec(),
        }
    }

    #[test]
    fn a_single_equality_on_a_provable_dimension_is_fully_provable() {
        let p = plan(&[eq("run_id", b"4471")], Dimension::RecordedAt);
        assert_eq!(p.placements, vec![Placement::Indexed]);
        assert!(p.is_fully_provable());
        assert_eq!(p.query.dimension, Dimension::RunId);
        assert_eq!(p.query.lo, b"4471".to_vec());
        assert_eq!(p.query.hi, b"4471".to_vec());
    }

    #[test]
    fn a_range_on_a_provable_dimension_is_fully_provable() {
        let p = plan(
            &[Predicate::Between {
                column: "recorded_at_nanos".to_owned(),
                lo: vec![0; 8],
                hi: vec![0xFF; 8],
            }],
            Dimension::RecordId,
        );
        assert!(p.is_fully_provable());
        assert_eq!(p.query.dimension, Dimension::RecordedAt);
    }

    /// The rule §3.2 states in those words: one predicate off the provable
    /// dimensions and the answer says so rather than looking complete.
    #[test]
    fn a_field_predicate_costs_the_proof_and_is_named() {
        let p = plan(
            &[
                eq("run_id", b"4471"),
                Predicate::Field(Filter::Severity(Severity::Error)),
            ],
            Dimension::RecordedAt,
        );
        assert_eq!(p.placements, vec![Placement::Indexed, Placement::Filtered]);
        assert!(!p.is_fully_provable());
        assert_eq!(p.unproved.len(), 1);
        assert!(p.unproved[0].contains("Severity"), "{:?}", p.unproved);
        // And it is still applied, so the answer is correct even though it is not
        // provable. A partial proof is not an excuse to return the wrong rows.
        assert_eq!(p.query.filters.len(), 1);
    }

    /// Two ranges on two dimensions cannot both be the sorted one. The second is
    /// named rather than silently dropped or silently applied.
    #[test]
    fn a_second_provable_predicate_is_still_not_provable_and_says_why() {
        let p = plan(
            &[eq("run_id", b"4471"), eq("agent_id", b"agent://x/y")],
            Dimension::RecordedAt,
        );
        assert_eq!(p.placements, vec![Placement::Indexed, Placement::Engine]);
        assert!(!p.is_fully_provable());
        assert!(p.unproved[0].contains("one at a time"), "{:?}", p.unproved);
    }

    /// Provability must not depend on the order somebody typed a WHERE clause, so
    /// an equality is chosen over a range wherever both are available.
    #[test]
    fn an_equality_is_chosen_over_a_range_whichever_order_they_arrive_in() {
        let range = Predicate::Between {
            column: "recorded_at_nanos".to_owned(),
            lo: vec![0; 8],
            hi: vec![0xFF; 8],
        };
        let equality = eq("run_id", b"4471");
        for order in [
            vec![range.clone(), equality.clone()],
            vec![equality.clone(), range.clone()],
        ] {
            let p = plan(&order, Dimension::RecordId);
            assert_eq!(
                p.query.dimension,
                Dimension::RunId,
                "the equality should be the sorted dimension in either order"
            );
        }
    }

    #[test]
    fn something_the_facade_cannot_model_is_carried_rather_than_discarded() {
        let p = plan(
            &[Predicate::Opaque(
                "lower(agent_id) LIKE '%billing%'".to_owned(),
            )],
            Dimension::RecordedAt,
        );
        assert_eq!(p.placements, vec![Placement::Engine]);
        assert_eq!(p.unproved, vec!["lower(agent_id) LIKE '%billing%'"]);
        // The scan still happens, over the fallback dimension, and it is still a
        // complete scan of that dimension. Refusing to answer would be worse.
        assert_eq!(p.query.dimension, Dimension::RecordedAt);
    }

    #[test]
    fn no_predicate_at_all_scans_the_fallback_dimension_and_proves_the_scan() {
        let p = plan(&[], Dimension::RecordedAt);
        assert!(
            p.is_fully_provable(),
            "a complete scan is a complete answer"
        );
        assert_eq!(p.query.dimension, Dimension::RecordedAt);
        assert!(p.query.filters.is_empty());
    }

    /// The column names are the projection's. A facade that accepted a name the
    /// projection does not use would be accepting a column that does not exist.
    #[test]
    fn only_the_projections_own_column_names_resolve_to_dimensions() {
        for name in [
            "record_id",
            "recorded_at_nanos",
            "agent_id",
            "run_id",
            "event_type",
        ] {
            assert!(dimension_of(name).is_some(), "{name} should resolve");
        }
        for name in ["recorded_at", "id", "tenant", "severity", "seq", ""] {
            assert!(
                dimension_of(name).is_none(),
                "{name} is not a provable dimension"
            );
        }
    }
}
