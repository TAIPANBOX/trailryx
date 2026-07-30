# What this store proves, next to what a framework asks for

This document and `crates/trailryx-compliance` are one thing in two forms. Neither
of them tells anybody they are compliant, and that is a design rule rather than a
disclaimer: compliance is a judgement about an organisation, made by an auditor or
a regulator. A database asserting it would be the most dishonest sentence in this
repository.

What a database can do is say precisely what it proved, put that next to the
obligation the proof bears on, and be equally precise about the obligations it does
not touch.

## The one fact that governs how any of this may be phrased

As of June 2026, **no JTC 21 document is cited in the Official Journal.** No
harmonised standard confers a presumption of conformity on anybody, for any
product. Harmonised standards for high-risk systems are expected in H2 2026 or H1
2027, and EN 18286 on quality management systems is expected to be cited first.

The profile document for what this store does is **prEN ISO/IEC 24970, "AI system
logging"**: logging of events during an AI system's operation, for traceability and
post-market surveillance. It is a draft.

So: **the obligations of Article 12 now bite on 2 December 2027, moved there from
2 August 2026 by the Digital Omnibus on AI, and the technical standard telling anybody
how to satisfy them still does not exist.** That gap is
why this layer is worth building. It is also exactly why it must not overstate
itself, and the rule is one line:

> Do not write "conforms to the standard" while no standard is cited.

What can be said is that the store covers the Article 12 requirements today and is
ready to be mapped onto prEN ISO/IEC 24970 when that document settles. The rule is
enforced by a test in `crates/trailryx-compliance/src/lib.rs`, not by care, because
a rule enforced by care is a rule until somebody is in a hurry.

## Four answers, and two of them are no

Every obligation in the mapping resolves to one of four:

| Answer | What it means |
|---|---|
| **shown** | the evidence this obligation needs is in this pack and verified |
| **not in this pack** | the store can produce that evidence and this pack does not carry it. A gap in the pack, not in the product |
| **not addressed** | nothing this store does bears on it. Listed anyway, because an obligation absent from a mapping reads as covered |
| **operator** | it depends on how the store is run, and the store cannot know |

Retention is the clearest **operator** case and the most tempting one to fudge.
Article 19(1) and Article 26(6) both require logs to be kept for at least six
months. Nothing in a pack can show how long anything was kept. What the store adds
is narrower and worth having on its own: a retained log whose completeness is
provable, so retention becomes a question about storage rather than about trust.

## Why every answer is derived and never declared

The mapping is a static table. What a *particular* pack demonstrates comes from
the offline verifier's own findings about that pack, by check name. Nothing reads a
claim the pack makes about itself.

And nothing is written **into** a pack. A pack carrying its own compliance
assertion would be the store describing its own evidence, which is the failure mode
the verifier exists to catch. The coverage report is produced beside a pack, from a
verifier run, by whoever is asking.

```bash
trailryx-coverage incident-4471.trxevid
```

The exit code follows the **pack's** verdict, not the coverage table. A table of
obligations means nothing about a pack that does not verify, and an exit code that
said otherwise would be the most quotable lie here.

## Why it is versioned

`MAPPING_VERSION`. Law changes, guidance is reissued, and a reading of a clause can
turn out to be wrong. A statement made under version 1 has to stay distinguishable
from one made under version 2, or a correction silently rewrites what was claimed
last year. The same argument as the record format's version, applied to an
interpretation instead of to bytes.

There is deliberately **no clause-level mapping onto prEN ISO/IEC 24970 yet**.
Clause numbers taken from a moving draft and printed next to a verdict would be
manufacturing a precision that does not exist. The layer is versioned so that
mapping can be added when the document is cited, without rewriting what was
claimed before it was.

## Sources, and their limits

Every quotation was read from a primary or near-primary source on **30 July 2026**,
and each entry in the table says which. That date is part of the mapping: it is
what a reader needs in order to decide whether to re-read the source themselves.
This estate has already shipped one factual claim about a competitor that was
wrong, so nothing here is quoted from memory.

| Framework | Source, and what kind |
|---|---|
| EU AI Act | Regulation (EU) 2024/1689. Official text on EUR-Lex; the article text was read and cross-checked 2026-07-30 |
| prEN ISO/IEC 24970 | A **draft**, not cited in the Official Journal. Named by subject only; no clause is quoted |
| SR 11-7 | Federal Reserve and OCC supervisory guidance, 4 April 2011. Summarised at the level of its own sections, because it has no clause numbering to quote |
| SOC 2 | AICPA Trust Services Criteria. CC7.2's wording was read from a secondary source, and that is said rather than glossed over |

**This is not legal advice, and the summaries are not the law.** Where a summary
and the official text differ, the official text is right and this mapping has a
defect worth reporting.

## What is honestly not covered

Worth reading before anything else, because a mapping that lists only its wins
reads as complete:

- **Article 12(3)**, biometric identification logging. This store records what
  agents did. It holds no reference database, no biometric input and no verifier
  identity. A deployment of an Annex III point 1(a) system needs those recorded
  somewhere, and it is not here.
- **SR 11-7 model inventory.** An inventory is a register of models, kept
  deliberately. This store records calls to models. Deriving a register from
  observed traffic would produce a list of what was used, which is a different
  document and a misleading substitute for the one that is asked for.
- **SR 11-7 conceptual soundness.** Whether a model is well designed is a
  judgement about the model. Nothing in a record of its calls answers it.
- **Clause-level conformity with anything.** See above: no standard is cited.
