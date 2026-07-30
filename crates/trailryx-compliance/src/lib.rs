//! A versioned map from what this store proves to what a framework asks for.
//!
//! # This does not tell anybody they are compliant
//!
//! The word does not appear in any output of this crate, and that is a design
//! rule rather than a style preference. Compliance is a judgement about an
//! organisation made by an auditor or a regulator, and a database asserting it
//! would be the single most dishonest thing in this repository. What a database
//! can do is say precisely what it proved, next to the text of the obligation
//! that proof bears on, and be equally precise about the obligations it does not
//! touch.
//!
//! So every obligation here resolves to one of four answers, and two of them are
//! "no":
//!
//! - [`Coverage::Demonstrated`]: the evidence this obligation would need is
//!   present in this pack and verified.
//! - [`Coverage::NotInThisPack`]: this store can produce that evidence and this
//!   particular pack does not carry it. A gap in the pack, not in the product.
//! - [`Coverage::NotAddressed`]: nothing this store does bears on the obligation.
//!   Listed anyway, because an obligation absent from a mapping reads as covered.
//! - [`Coverage::Operator`]: it depends on how the store is run, and the store
//!   cannot know. Retention periods are the clearest example: nothing in a pack
//!   can show that logs were kept for six months.
//!
//! # Why the answer is derived and never declared
//!
//! Every answer comes from the offline verifier's own findings about a specific
//! pack. Nothing here reads a claim the pack makes about itself, and nothing here
//! is written into a pack: a pack that carried its own compliance assertion would
//! be the store describing its own evidence, which is the failure mode the
//! verifier exists to catch.
//!
//! # Why it is versioned
//!
//! [`MAPPING_VERSION`]. Law changes, guidance is reissued, and a reading of a
//! clause can turn out to be wrong. A statement made under version 1 has to stay
//! distinguishable from one made under version 2, or a correction silently
//! rewrites what was claimed last year. The same argument as the record format's
//! version, applied to an interpretation instead of to bytes.
//!
//! # Sources, and their limits
//!
//! The clause text quoted in [`OBLIGATIONS`] was read from a primary or
//! near-primary source on **30 July 2026**, and each entry says which. That date
//! is part of the mapping: it is what a reader needs in order to know whether to
//! re-read the source themselves. The estate has already shipped one factual
//! claim about a competitor that was wrong, so nothing here is quoted from memory.
//!
//! **This is not legal advice, and the summaries are not the law.** Where a
//! summary and the official text differ, the official text is right and this
//! mapping has a defect worth reporting.
//!
//! # Why nothing here says "conforms to the standard"
//!
//! As of June 2026 **no JTC 21 document is cited in the Official Journal**, so no
//! harmonised standard confers a presumption of conformity on anybody, for any
//! product. Harmonised standards for high-risk systems are expected in H2 2026 or
//! H1 2027, and EN 18286 on quality management systems is the furthest along.
//!
//! The profile document for what this store does is **prEN ISO/IEC 24970, "AI
//! system logging"**: logging of events during an AI system's operation, for
//! traceability and post-market surveillance. It is a draft. Its clauses are
//! deliberately **not quoted below**, because quoting clause numbers from a moving
//! draft would be manufacturing a precision that does not exist yet.
//!
//! So the phrasing rule, taken from
//! `docs/planning/trailryx-architecture.md` §14.3 and enforced by a test rather
//! than by care: **do not write "conforms to the standard" while no standard is
//! cited.** What can be said is that the store covers the Article 12 requirements
//! and is ready to be mapped onto prEN ISO/IEC 24970 when that document settles.
//!
//! The Article 12 obligations were due on 2 August 2026 and the **Digital Omnibus
//! on AI moved them to 2 December 2027** for stand-alone Annex III systems, and to
//! 2 August 2028 for AI inside Annex I products. The technical standard telling
//! anybody how to satisfy them still does not exist. That gap is the reason this
//! crate is worth writing, and it is also the reason it must not overstate itself.
//!
//! The move is why [`MAPPING_VERSION`] is 2 rather than 1. Version 1 carried the
//! pre-omnibus dates, read from a consolidated text that did not yet include the
//! amendment, and a statement made under version 1 has to stay distinguishable
//! from one made now. A mapping that silently corrected itself would rewrite what
//! it told somebody last quarter.

#![forbid(unsafe_code)]

use trailryx_verify::{Level, Report};

/// The version of this interpretation.
///
/// Bumped when an obligation is added, removed, or read differently. Not bumped
/// for wording.
pub const MAPPING_VERSION: u16 = 2;

/// When the quoted clause text was last read from its source.
pub const SOURCES_READ_ON: &str = "2026-07-30";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    /// Regulation (EU) 2024/1689, the Artificial Intelligence Act.
    EuAiAct,
    /// SR 11-7, the Federal Reserve and OCC supervisory guidance on model risk
    /// management.
    Sr117,
    /// The AICPA Trust Services Criteria, as used in a SOC 2 examination.
    Soc2,
    /// prEN ISO/IEC 24970, "AI system logging". A **draft**, and the profile
    /// document for what this store does.
    PrEn24970,
}

impl Framework {
    pub fn name(self) -> &'static str {
        match self {
            Self::EuAiAct => "EU AI Act",
            Self::Sr117 => "SR 11-7",
            Self::Soc2 => "SOC 2",
            Self::PrEn24970 => "prEN ISO/IEC 24970 (draft)",
        }
    }

    /// Where the text was read from, and what kind of source that is.
    pub fn source(self) -> &'static str {
        match self {
            // The consolidated text on EUR-Lex is the official one; the article
            // pages used here reproduce it and were cross-read against each
            // other. A reader checking this should use EUR-Lex.
            Self::EuAiAct => {
                "Regulation (EU) 2024/1689, articles read 2026-07-30; official text on EUR-Lex"
            }
            // SR 11-7 is a short public letter. It is summarised here at the
            // level of its own three sections, not quoted clause by clause,
            // because it has no clause numbering to quote.
            Self::Sr117 => {
                "SR 11-7 (2011-04-04), Federal Reserve and OCC; summarised at section level"
            }
            // The criteria numbering is the AICPA's and the authoritative wording
            // is theirs. CC7.2's wording below was read from a secondary source,
            // and that is said rather than glossed over.
            Self::Soc2 => {
                "AICPA Trust Services Criteria; CC7.2 wording read from a secondary source 2026-07-30"
            }
            // Named at the level of its subject matter and no further. Quoting
            // clause numbers from a draft that is still moving would manufacture a
            // precision that does not exist.
            Self::PrEn24970 => {
                "prEN ISO/IEC 24970, a DRAFT and not cited in the Official Journal; \
                 no clause is quoted here for that reason"
            }
        }
    }
}

/// What a pack has to carry before an obligation can be called demonstrated.
///
/// Each variant is answered from the verifier's own findings, by name. The check
/// names are the verifier's and they are quoted in [`Requirement::from_report`]
/// so that a renamed check breaks a test rather than silently making every
/// obligation look uncovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The pack verified: every root recomputed, every chain linked.
    Verifies,
    /// Records are actually in it. A pack of manifests with no records proves the
    /// arithmetic and shows no events.
    Records,
    /// A signature over the store root that this verifier could check.
    SignedRoot,
    /// Somebody who is not the publisher placed the root in time: a witness
    /// attestation or an RFC 3161 anchor.
    TimeAttested,
    /// The chain runs unbroken across segment boundaries, which is what makes
    /// "nothing was removed from the middle" a checkable statement.
    ChainAcrossSegments,
    /// The index is strictly sorted, which is what completeness proofs stand on.
    SortedIndex,
}

impl Requirement {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Verifies => "the pack verifies",
            Self::Records => "the pack carries records",
            Self::SignedRoot => "the root is signed and the signature checks out",
            Self::TimeAttested => "a witness or a timestamp authority places the root in time",
            Self::ChainAcrossSegments => "the chain is unbroken across segments",
            Self::SortedIndex => "the index is strictly sorted",
        }
    }

    /// Answer this requirement from a verifier report.
    ///
    /// Public because a caller who is short of evidence wants to know which piece,
    /// and because an obligation reports only the **first** requirement it failed:
    /// asking directly is how you find out whether a later one is also missing.
    ///
    /// A finding at [`Level::Broken`] never satisfies anything, and neither does
    /// a missing one. A `Weak` finding is a stated limitation, so it satisfies
    /// nothing either: that is the whole point of the level.
    pub fn satisfied_by(self, report: &Report) -> bool {
        let noted = |check: &str| {
            report
                .findings
                .iter()
                .any(|f| f.check == check && f.level == Level::Note)
        };
        let unbroken = |check: &str| {
            report
                .findings
                .iter()
                .all(|f| f.check != check || f.level != Level::Broken)
        };
        match self {
            Self::Verifies => report.verified(),
            Self::Records => report.records_checked > 0 && unbroken("record-decodes"),
            Self::SignedRoot => noted("root-signature"),
            // Either kind of independent attestation. The verifier emits the
            // `witnesses` finding when it has neither, which is checked here as
            // well so the two cannot drift apart.
            Self::TimeAttested => {
                (noted("witness") || noted("anchor"))
                    && !report.findings.iter().any(|f| f.check == "witnesses")
            }
            Self::ChainAcrossSegments => {
                report.verified() && unbroken("chain-across-segments") && unbroken("orphan-segment")
            }
            Self::SortedIndex => report.verified() && unbroken("index-strictly-sorted"),
        }
    }
}

/// How this store bears on one obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bearing {
    /// Evidence in a pack can demonstrate it, given these requirements.
    Evidenced {
        needs: &'static [Requirement],
        how: &'static str,
    },
    /// Nothing this store does bears on it.
    Silent(&'static str),
    /// It depends on how the store is operated.
    Operator(&'static str),
}

/// One obligation, and what this store has to say about it.
#[derive(Debug, Clone, Copy)]
pub struct Obligation {
    pub framework: Framework,
    /// How the source refers to it, so a reader can look it up.
    pub reference: &'static str,
    /// What it asks for. A quotation where the source has quotable text, and a
    /// summary marked as one where it does not.
    pub requires: &'static str,
    pub bearing: Bearing,
}

/// What this store says about each obligation, at [`MAPPING_VERSION`].
///
/// Deliberately includes the obligations this store does nothing for. A mapping
/// that lists only what it covers is a mapping that reads as complete, and
/// somebody will quote it that way.
pub const OBLIGATIONS: &[Obligation] = &[
    // -- EU AI Act ---------------------------------------------------------
    Obligation {
        framework: Framework::EuAiAct,
        reference: "Article 12(1)",
        requires: "\"High-risk AI systems shall technically allow for the automatic recording of \
                   events (logs) over the lifetime of the system.\"",
        bearing: Bearing::Evidenced {
            needs: &[Requirement::Verifies, Requirement::Records],
            how: "a pack that verifies and carries records is automatic recording that can be \
                  shown to a third party rather than described to one",
        },
    },
    Obligation {
        framework: Framework::EuAiAct,
        reference: "Article 12(2)",
        requires: "Summary, not a quotation: logging must enable recording of events relevant \
                   to identifying risk situations or substantial modification, to post-market \
                   monitoring, and to monitoring operation under Article 26(5).",
        bearing: Bearing::Evidenced {
            needs: &[Requirement::Records, Requirement::ChainAcrossSegments],
            how: "the record schema types verdict, severity and error code, and an unbroken \
                  chain across segments is what makes \"this is every relevant event, not a \
                  selection\" a checkable claim rather than an assurance",
        },
    },
    Obligation {
        framework: Framework::EuAiAct,
        reference: "Article 12(3)",
        requires: "Summary, not a quotation: for biometric identification systems in Annex III \
                   point 1(a), logging must record each use period with start and end times, the \
                   reference database checked, the input data that led to a match, and the \
                   identification of the persons verifying results under Article 14(5).",
        bearing: Bearing::Silent(
            "this store records what agents did and holds no reference database, no biometric \
             input and no verifier identity. A deployment of an Annex III point 1(a) system \
             needs those recorded somewhere, and it is not here",
        ),
    },
    Obligation {
        framework: Framework::EuAiAct,
        reference: "Article 19(1)",
        requires: "\"the logs shall be kept for a period appropriate to the intended purpose of \
                   the high-risk AI system, of at least six months\"",
        bearing: Bearing::Operator(
            "nothing in a pack can show how long anything was kept. What this store adds is \
             narrower and worth having: a retained log whose completeness is provable, so \
             retention becomes a question about storage rather than about trust",
        ),
    },
    Obligation {
        framework: Framework::EuAiAct,
        reference: "Article 19(2)",
        requires: "Summary, not a quotation: providers that are financial institutions shall \
                   maintain the logs as part of the documentation kept under the relevant \
                   financial services law.",
        bearing: Bearing::Operator(
            "which documentation regime applies, and whether a pack belongs inside it, is the \
             institution's determination",
        ),
    },
    Obligation {
        framework: Framework::EuAiAct,
        reference: "Article 26(6)",
        requires: "\"Deployers of high-risk AI systems shall keep the logs automatically \
                   generated by that high-risk AI system ... of at least six months\"",
        bearing: Bearing::Operator(
            "the same retention question as Article 19(1), on the deployer rather than the \
             provider",
        ),
    },
    Obligation {
        framework: Framework::EuAiAct,
        reference: "Article 113",
        requires: "Dates, from Article 113 as amended by the Digital Omnibus on AI, adopted by \
                   Parliament on 16 June 2026 and by Council on 29 June 2026: the high-risk \
                   obligations for stand-alone Annex III systems apply from 2 December 2027, and \
                   for AI embedded in Annex I products from 2 August 2028. The Article 50 \
                   transparency duties stay on 2 August 2026, with a grace period to 2 December \
                   2026 for marking content from systems already on the market. Chapters I and \
                   II have applied since 2 February 2025, and the general-purpose model chapter \
                   since 2 August 2025.",
        bearing: Bearing::Silent(
            "a date, not an obligation. It is in the mapping because the record-keeping duties \
             above are worth nothing without knowing when they bite, and because a mapping that \
             omitted it would invite somebody to assume they had longer or less time than they \
             do. Version 1 of this mapping said 2 August 2026, which was the law when it was \
             written and was moved by an amendment weeks later: the clearest possible argument \
             for versioning an interpretation rather than restating it",
        ),
    },
    // -- prEN ISO/IEC 24970 ------------------------------------------------
    //
    // Named by subject, not by clause. It is a draft; clause numbers taken from a
    // moving document and printed next to a verdict would be the most quotable
    // wrong thing in this crate.
    Obligation {
        framework: Framework::PrEn24970,
        reference: "Subject: logging of events during AI system operation",
        requires: "Summary, not a quotation: the draft specifies logging of events during an AI                    system's operation, for traceability and post-market surveillance. It is the                    profile document for what this store does and is not yet citable.",
        bearing: Bearing::Evidenced {
            needs: &[Requirement::Records, Requirement::Verifies],
            how: "the store covers the Article 12 requirements today and is ready to be mapped                   onto this document when it settles. That is the whole claim: no conformity is                   asserted, because no standard is cited",
        },
    },
    Obligation {
        framework: Framework::PrEn24970,
        reference: "Status: not cited in the Official Journal",
        requires: "As of June 2026 no JTC 21 document is cited in the Official Journal, so no                    harmonised standard confers a presumption of conformity on anybody.                    Harmonised standards for high-risk systems are expected in H2 2026 or H1 2027.",
        bearing: Bearing::Silent(
            "a fact about the standards landscape rather than an obligation. It is in the mapping              because it is the single most likely thing for somebody to get wrong in the other              direction: a presumption of conformity is not available to be claimed, by this              store or by any other product",
        ),
    },
    Obligation {
        framework: Framework::PrEn24970,
        reference: "Clause-level mapping",
        requires: "Summary, not a quotation: a clause-by-clause mapping is what an assessor would                    eventually work from.",
        bearing: Bearing::Operator(
            "deliberately absent. The clauses of a draft change, and a mapping published against              them would be wrong quietly rather than loudly. This layer is versioned so that the              mapping can be added when the document is cited, without rewriting what was claimed              before it was",
        ),
    },
    // -- SR 11-7 -----------------------------------------------------------
    Obligation {
        framework: Framework::Sr117,
        reference: "Documentation (section on governance, policies and controls)",
        requires: "Summary, not a quotation: model documentation should be detailed enough that \
                   somebody unfamiliar with a model can understand how it operates, its \
                   limitations and its key assumptions, and can reproduce its results.",
        bearing: Bearing::Evidenced {
            needs: &[Requirement::Records, Requirement::Verifies],
            how: "a record names the model, the policy version in force and the verdict, and a \
                  pack lets a reviewer who was not there reconstruct what happened without \
                  asking the operator to vouch for the extract",
        },
    },
    Obligation {
        framework: Framework::Sr117,
        reference: "Model inventory (section on governance, policies and controls)",
        requires: "Summary, not a quotation: banks should maintain a comprehensive inventory of \
                   models in use, under development or recently retired.",
        bearing: Bearing::Silent(
            "an inventory is a register of models, kept deliberately. This store records calls \
             to models and is not that register; deriving one from observed traffic would \
             produce a list of what was used, which is a different document and a misleading \
             substitute",
        ),
    },
    Obligation {
        framework: Framework::Sr117,
        reference: "Ongoing monitoring (section on model validation)",
        requires: "Summary, not a quotation: ongoing monitoring confirms that a model is \
                   appropriately implemented and continues to perform as intended, including \
                   process verification and benchmarking.",
        bearing: Bearing::Evidenced {
            needs: &[Requirement::Records, Requirement::SortedIndex],
            how: "outcomes over time are what monitoring reads, and a sorted index is what \
                  makes a query over a period answerable with a proof that nothing matching was \
                  left out",
        },
    },
    Obligation {
        framework: Framework::Sr117,
        reference: "Conceptual soundness (section on model validation)",
        requires: "Summary, not a quotation: validation should evaluate the quality of a model's \
                   design and construction, including its theory and logic.",
        bearing: Bearing::Silent(
            "whether a model is well designed is a judgement about the model. Nothing in a \
             record of its calls answers it",
        ),
    },
    Obligation {
        framework: Framework::Sr117,
        reference: "Change control (section on model development, implementation and use)",
        requires: "Summary, not a quotation: changes to models and to their implementation \
                   should be documented and controlled.",
        bearing: Bearing::Evidenced {
            needs: &[Requirement::Records, Requirement::ChainAcrossSegments],
            how: "a record carries the policy version and the mapper version in force at the \
                  time, so a change shows up as a change in the trail rather than as a memory \
                  of one",
        },
    },
    // -- SOC 2 -------------------------------------------------------------
    Obligation {
        framework: Framework::Soc2,
        reference: "CC7.2",
        requires: "\"The entity monitors system components and the operation of those components \
                   for anomalies that are indicative of malicious acts, natural disasters, and \
                   errors affecting the entity's ability to meet its objectives; anomalies are \
                   analyzed to determine whether they represent security events.\"",
        bearing: Bearing::Evidenced {
            needs: &[Requirement::Records, Requirement::Verifies],
            how: "loss is itself recorded rather than merely counted, so a gap in monitoring \
                  appears in the trail instead of appearing as nothing",
        },
    },
    Obligation {
        framework: Framework::Soc2,
        reference: "Integrity of the audit trail itself",
        requires: "Summary, not a quotation: an examiner asks whether the evidence they are \
                   shown could have been altered, and by whom.",
        bearing: Bearing::Evidenced {
            needs: &[
                Requirement::Verifies,
                Requirement::SignedRoot,
                Requirement::TimeAttested,
            ],
            how: "a signed root says whose history it is and an independent attestation says the \
                  root existed by a time the publisher did not choose. Without the second, a \
                  history can be rebuilt today, signed today and dated last year",
        },
    },
    Obligation {
        framework: Framework::Soc2,
        reference: "Logical access (CC6 family)",
        requires: "Summary, not a quotation: access to systems and data is restricted to \
                   authorised users.",
        bearing: Bearing::Operator(
            "the ingest surface authenticates and authorises writes, and the payload plane is \
             behind a separate authorisation. Whether the deployment's access model is sound is \
             not something a pack can show",
        ),
    },
];

/// The answer for one obligation, about one pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// The needed evidence is present and verified.
    Demonstrated,
    /// This store can produce that evidence and this pack does not carry it.
    /// Carries the first requirement that was not met.
    NotInThisPack(Requirement),
    /// Nothing this store does bears on it.
    NotAddressed,
    /// It depends on how the store is operated.
    Operator,
}

impl Coverage {
    /// A word for a report line. None of them is "compliant".
    pub fn label(self) -> &'static str {
        match self {
            Self::Demonstrated => "shown",
            Self::NotInThisPack(_) => "not in this pack",
            Self::NotAddressed => "not addressed",
            Self::Operator => "operator",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Line {
    pub obligation: Obligation,
    pub coverage: Coverage,
}

#[derive(Debug, Clone)]
pub struct Assessment {
    pub mapping_version: u16,
    pub lines: Vec<Line>,
}

impl Assessment {
    pub fn shown(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| l.coverage == Coverage::Demonstrated)
            .count()
    }

    pub fn missing(&self) -> impl Iterator<Item = &Line> {
        self.lines
            .iter()
            .filter(|l| matches!(l.coverage, Coverage::NotInThisPack(_)))
    }

    pub fn for_framework(&self, framework: Framework) -> impl Iterator<Item = &Line> {
        self.lines
            .iter()
            .filter(move |l| l.obligation.framework == framework)
    }
}

/// Work out what this pack demonstrates, obligation by obligation.
pub fn assess(report: &Report) -> Assessment {
    let lines = OBLIGATIONS
        .iter()
        .map(|obligation| {
            let coverage = match obligation.bearing {
                Bearing::Silent(_) => Coverage::NotAddressed,
                Bearing::Operator(_) => Coverage::Operator,
                Bearing::Evidenced { needs, .. } => needs
                    .iter()
                    .find(|r| !r.satisfied_by(report))
                    .map_or(Coverage::Demonstrated, |r| Coverage::NotInThisPack(*r)),
            };
            Line {
                obligation: *obligation,
                coverage,
            }
        })
        .collect();
    Assessment {
        mapping_version: MAPPING_VERSION,
        lines,
    }
}

/// Render an assessment as text.
///
/// The header states the mapping version, the date the sources were read and the
/// disclaimer, on every single report. A reader who sees only the table has to be
/// told what the table is not.
pub fn render(assessment: &Assessment) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "coverage against three frameworks, mapping version {}\n\
         clause text read {}\n\
         \n\
         This states what the pack proves next to what each obligation asks for. It is not a\n\
         compliance determination and it is not legal advice: only an auditor or a regulator\n\
         makes that judgement, and the official text of each source governs over the summaries\n\
         here.\n\n",
        assessment.mapping_version, SOURCES_READ_ON
    ));

    for framework in [
        Framework::EuAiAct,
        Framework::PrEn24970,
        Framework::Sr117,
        Framework::Soc2,
    ] {
        out.push_str(&format!(
            "{}\n  source: {}\n",
            framework.name(),
            framework.source()
        ));
        for line in assessment.for_framework(framework) {
            out.push_str(&format!(
                "  [{}] {}\n",
                line.coverage.label(),
                line.obligation.reference
            ));
            match (line.coverage, line.obligation.bearing) {
                (Coverage::Demonstrated, Bearing::Evidenced { how, .. }) => {
                    out.push_str(&format!("      {how}\n"));
                }
                (Coverage::NotInThisPack(missing), _) => {
                    out.push_str(&format!(
                        "      this pack does not show that {}\n",
                        missing.describe()
                    ));
                }
                (Coverage::NotAddressed, Bearing::Silent(why)) => {
                    out.push_str(&format!("      {why}\n"));
                }
                (Coverage::Operator, Bearing::Operator(why)) => {
                    out.push_str(&format!("      {why}\n"));
                }
                _ => {}
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_verify::{Finding, Report};

    fn report(findings: Vec<(Level, &'static str)>, records: u64) -> Report {
        Report {
            findings: findings
                .into_iter()
                .map(|(level, check)| Finding {
                    level,
                    check,
                    detail: String::new(),
                })
                .collect(),
            records_checked: records,
            segments_checked: 1,
        }
    }

    /// The rule this crate is built around. If it ever fails, the crate is
    /// claiming something no database is entitled to claim.
    #[test]
    fn nothing_this_crate_emits_says_compliant() {
        let assessment = assess(&report(vec![], 0));
        let text = render(&assessment).to_lowercase();
        for forbidden in [
            "compliant",
            "compliance with",
            "certifies",
            "guarantees compliance",
        ] {
            assert!(
                !text.contains(forbidden),
                "the rendered report contains {forbidden:?}"
            );
        }
        for coverage in [
            Coverage::Demonstrated,
            Coverage::NotInThisPack(Requirement::Verifies),
            Coverage::NotAddressed,
            Coverage::Operator,
        ] {
            assert!(!coverage.label().contains("compl"));
        }
        // And the disclaimer is on every report, not only a good one.
        assert!(text.contains("not legal advice"));
        assert!(text.contains("not a\ncompliance determination"));
    }

    /// The phrasing rule from `docs/planning/trailryx-architecture.md` §14.3, which
    /// says not to write "conforms to the standard" while no standard is cited.
    /// A rule enforced by care is a rule until somebody is in a hurry.
    #[test]
    fn nothing_this_crate_emits_claims_conformity_to_a_standard() {
        let perfect = report(
            vec![
                (Level::Note, "root-signature"),
                (Level::Note, "witness"),
                (Level::Note, "anchor"),
            ],
            1000,
        );
        let text = render(&assess(&perfect)).to_lowercase();
        for forbidden in [
            "conforms to",
            "conformant",
            "conformity is achieved",
            "meets the standard",
            "certified",
        ] {
            assert!(
                !text.contains(forbidden),
                "the rendered report contains {forbidden:?}, which claims conformity"
            );
        }

        // "presumption of conformity" is a phrase this crate has to be able to use,
        // because saying it is unavailable is the honest thing to say. An earlier
        // version of this test banned the substring and caught its own denial, so
        // the check is now about the sense rather than the letter: wherever the
        // phrase appears, a negation appears with it.
        for sentence in text.split('.') {
            if sentence.contains("presumption of conformity") {
                assert!(
                    sentence.contains("not ") || sentence.contains("no "),
                    "a presumption of conformity is mentioned without being denied: {sentence:?}"
                );
            }
        }

        // And it must say the thing that makes the whole section honest.
        assert!(text.contains("not cited in the official journal"));
        assert!(text.contains("draft"));
    }

    /// An obligation nothing bears on must still appear. A mapping that lists
    /// only its wins reads as complete, and somebody will quote it that way.
    #[test]
    fn obligations_this_store_does_nothing_for_are_listed_and_labelled() {
        let assessment = assess(&report(vec![], 0));
        let not_addressed: Vec<_> = assessment
            .lines
            .iter()
            .filter(|l| l.coverage == Coverage::NotAddressed)
            .map(|l| l.obligation.reference)
            .collect();
        assert!(
            not_addressed.contains(&"Article 12(3)"),
            "the biometric logging duty must be listed as not addressed: {not_addressed:?}"
        );
        assert!(
            not_addressed
                .contains(&"Model inventory (section on governance, policies and controls)"),
            "{not_addressed:?}"
        );
        assert!(not_addressed.len() >= 4, "{not_addressed:?}");

        let text = render(&assessment);
        assert!(text.contains("Article 12(3)"));
        assert!(text.contains("no biometric"));
    }

    /// A retention duty can never be demonstrated by a pack, whatever is in it.
    /// This is the case where an over-eager mapping would be most tempting and
    /// most wrong.
    #[test]
    fn a_retention_duty_is_never_demonstrated_however_good_the_pack_is() {
        let perfect = report(
            vec![
                (Level::Note, "root-signature"),
                (Level::Note, "witness"),
                (Level::Note, "anchor"),
            ],
            1000,
        );
        let assessment = assess(&perfect);
        for reference in ["Article 19(1)", "Article 19(2)", "Article 26(6)"] {
            let line = assessment
                .lines
                .iter()
                .find(|l| l.obligation.reference == reference)
                .expect("the obligation is in the mapping");
            assert_eq!(
                line.coverage,
                Coverage::Operator,
                "{reference} must stay an operator question"
            );
        }
    }

    #[test]
    fn an_empty_pack_demonstrates_nothing_that_needs_records() {
        let assessment = assess(&report(vec![], 0));
        assert_eq!(assessment.shown(), 0, "an empty pack shows nothing");
        let missing: Vec<_> = assessment.missing().map(|l| l.coverage).collect();
        assert!(
            missing
                .iter()
                .all(|c| matches!(c, Coverage::NotInThisPack(_))),
            "{missing:?}"
        );
        assert!(!missing.is_empty());
    }

    #[test]
    fn a_verified_pack_with_records_demonstrates_the_recording_duties() {
        let assessment = assess(&report(vec![], 3));
        let article_12_1 = assessment
            .lines
            .iter()
            .find(|l| l.obligation.reference == "Article 12(1)")
            .expect("in the mapping");
        assert_eq!(article_12_1.coverage, Coverage::Demonstrated);
    }

    /// A `Broken` finding must never satisfy a requirement, and neither must a
    /// `Weak` one: a stated limitation is a limitation.
    #[test]
    fn neither_a_broken_nor_a_weak_finding_satisfies_a_requirement() {
        for level in [Level::Broken, Level::Weak] {
            let r = report(vec![(level, "root-signature"), (level, "witness")], 3);
            assert!(
                !Requirement::SignedRoot.satisfied_by(&r),
                "{level:?} root-signature must not count as signed"
            );
            assert!(
                !Requirement::TimeAttested.satisfied_by(&r),
                "{level:?} witness must not count as attested"
            );
        }
        let good = report(
            vec![(Level::Note, "root-signature"), (Level::Note, "witness")],
            3,
        );
        assert!(Requirement::SignedRoot.satisfied_by(&good));
        assert!(Requirement::TimeAttested.satisfied_by(&good));
    }

    /// A pack that is broken must demonstrate nothing at all, regardless of what
    /// notes it also carries.
    #[test]
    fn a_broken_pack_demonstrates_nothing() {
        let broken = report(
            vec![
                (Level::Broken, "history-root"),
                (Level::Note, "root-signature"),
                (Level::Note, "anchor"),
            ],
            1000,
        );
        assert!(!broken.verified());
        assert_eq!(assess(&broken).shown(), 0);
    }

    /// The anchor and the witness are alternatives, not two names for one thing.
    /// Either satisfies the attestation requirement, and the verifier's own
    /// "nothing places this in time" finding vetoes both.
    #[test]
    fn either_a_witness_or_an_anchor_attests_and_the_verifiers_veto_beats_both() {
        for check in ["witness", "anchor"] {
            let r = report(vec![(Level::Note, check)], 3);
            assert!(
                Requirement::TimeAttested.satisfied_by(&r),
                "a noted {check} should attest"
            );
        }
        // The verifier emits `witnesses` when nothing independent attests. If it
        // is present, this crate must not disagree with it.
        let contradictory = report(vec![(Level::Note, "anchor"), (Level::Weak, "witnesses")], 3);
        assert!(
            !Requirement::TimeAttested.satisfied_by(&contradictory),
            "this crate must not overrule the verifier's own finding"
        );
    }

    /// Every requirement names a check the verifier actually emits. A renamed
    /// check would otherwise make obligations quietly uncoverable for ever.
    #[test]
    fn every_check_name_this_crate_relies_on_is_one_the_verifier_emits() {
        // The list is here rather than derived, so a rename breaks this test and
        // somebody has to look at both sides.
        let relied_on = [
            "record-decodes",
            "root-signature",
            "witness",
            "anchor",
            "witnesses",
            "chain-across-segments",
            "orphan-segment",
            "index-strictly-sorted",
        ];
        let source = include_str!("../../trailryx-verify/src/verify.rs");
        for check in relied_on {
            assert!(
                source.contains(&format!("\"{check}\"")),
                "this crate keys on the check {check:?} and the verifier no longer emits it"
            );
        }
    }

    /// Every entry must be well formed: a reference, requirement text, and a
    /// reason wherever the answer is no.
    #[test]
    fn every_obligation_names_its_source_and_explains_a_no() {
        for obligation in OBLIGATIONS {
            assert!(!obligation.reference.is_empty());
            assert!(
                obligation.requires.len() > 40,
                "{}: the requirement text is too short to be useful",
                obligation.reference
            );
            match obligation.bearing {
                Bearing::Silent(why) | Bearing::Operator(why) => assert!(
                    why.len() > 40,
                    "{}: a no needs a reason",
                    obligation.reference
                ),
                Bearing::Evidenced { needs, how } => {
                    assert!(
                        !needs.is_empty(),
                        "{}: nothing to check",
                        obligation.reference
                    );
                    assert!(how.len() > 40, "{}: how is too short", obligation.reference);
                }
            }
        }
        // Every framework is represented, or a reader of one section would think
        // it had been considered when it had not.
        for framework in [
            Framework::EuAiAct,
            Framework::PrEn24970,
            Framework::Sr117,
            Framework::Soc2,
        ] {
            assert!(
                OBLIGATIONS.iter().any(|o| o.framework == framework),
                "{} has no obligations in the mapping",
                framework.name()
            );
        }
    }

    /// A summary must be marked as one. A paraphrase presented as clause text is
    /// how a mapping starts being quoted as law.
    /// A paraphrase must be marked as one. A summary presented as clause text is
    /// how a mapping starts being quoted as law, and the first version of this
    /// test let a whole framework off on the grounds of which framework it was,
    /// which is not a reason.
    #[test]
    fn every_entry_either_quotes_its_source_or_says_it_is_a_summary() {
        for obligation in OBLIGATIONS {
            let quoted = obligation.requires.starts_with('"');
            let marked = obligation.requires.contains("Summary, not a quotation");
            // Two entries are statements of fact about dates and standing rather
            // than obligations, and are neither quotations nor summaries of one.
            let factual = obligation.reference.starts_with("Article 113")
                || obligation.reference.starts_with("Status:");
            assert!(
                quoted || marked || factual,
                "{}: neither quoted, nor marked as a summary, nor a statement of fact",
                obligation.reference
            );
            assert!(
                !(quoted && marked),
                "{}: claims to be both a quotation and a summary",
                obligation.reference
            );
        }
        // The AI Act's text is public, so where it is used it is quoted rather
        // than paraphrased.
        let quoted = OBLIGATIONS
            .iter()
            .filter(|o| o.framework == Framework::EuAiAct && o.requires.starts_with('"'))
            .count();
        assert!(
            quoted >= 3,
            "only {quoted} AI Act entries quote their source"
        );
        // And the draft standard's clauses are quoted nowhere, on purpose.
        assert!(
            OBLIGATIONS
                .iter()
                .filter(|o| o.framework == Framework::PrEn24970)
                .all(|o| !o.requires.starts_with('"')),
            "a clause of a moving draft must not be quoted as though it were settled"
        );
    }
}
