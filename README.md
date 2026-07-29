<div align="center">

# Trailryx

**The tamper-evident record database for AI agents.**

![Stage](https://img.shields.io/badge/stage-6%20of%2013-blue.svg)
![Core](https://img.shields.io/badge/core-frozen-success.svg)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)
![Tests](https://img.shields.io/badge/tests-244-success.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)
![Unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)

</div>

Trailryx stores what AI agents did, and can **prove** it: show the full chain
behind a decision, confirm no record was altered, prove that what you are
looking at is **all** of it, and still erase one person on request.

Two sentences carry the whole design.

> Every sequence number reported as acked survives any crash.

> A verifier must never learn the shape of an answer from the answer.

---

## The question nobody else answers

Agent telemetry usually lands in a span store. That works until an auditor asks
something an auditor asks.

| Question | Span store | Trailryx |
|---|---|---|
| Was this record altered? | no answer | hash chain, Merkle segments |
| Is this **all** the matching records? | no answer | **proof of completeness** |
| What did the system *know* when it decided? | not captured | `basis`: policy version, budget state, memory reference, tool manifest |
| What led to this decision? | one parent | causal DAG, provable hop by hop |
| What did we know in March, before we knew better? | no answer | `as_of` on the time dimension |
| Delete this person, keep the audit valid | mutually exclusive | crypto-erasure; the erasure is itself a record |

Obligations under EU AI Act Article 12 apply from 2 August 2026. The harmonised
standards that would say *how* are not cited in the Official Journal yet.

## What exists

Stages 0 to 6. The core is **frozen**: the journal format, the index structures
and the proof shapes do not change without a version and a migration.

| Crate | What it is | Tests |
|---|---|---|
| `trailryx-sim` | injectable clock, rng, io and bus; a crash model and fault injection | 18 |
| `trailryx-record` | the canonical record, its schema, and the plane boundary | 26 |
| `trailryx-crypto` | SHA-384 and the hash chain | 14 |
| `trailryx-contracts` | eight adapter traits and a conformance suite | 19 |
| `trailryx-journal` | wire format, append-only write path, recovery | 24 |
| `trailryx-index` | Merkle history tree, completeness proofs, segment composition | 53 |
| `trailryx-store` | sealing, the read surface, causal reconstruction | 27 |
| `trailryx-otlp` | protobuf reader, OTLP decode, the GenAI semconv mapper | 46 |

**Zero dependencies.** `unsafe` forbidden at the workspace level.

## Try it

```bash
cargo test                                    # 244 tests
cargo run --bin trailryx-sim-run -- --help
```

One seed reproduces a run exactly, on any machine:

```bash
cargo run --release --bin trailryx-sim-run -- \
  --seed 777 --steps 20000 --shards 4 --crash-ppm 5000 --hostile --honest-disk
```

```
seed=777 steps=20000 digest=42c29db84fa0d604 lines=37394 crashes=95 violations=0
```

## What a proof actually does

A range answer carries the matching entries with an inclusion proof each,
evidence that their positions are **contiguous** from a stated start, and the
entries immediately before and after the range, whose keys must fall outside it.
In a sorted list that leaves nowhere for an omitted record to hide: every index
between the two boundaries is accounted for.

The tests are written from the attacker's side. Each of these is refused:

- hiding a record in the middle of a range, or at either end;
- hiding one and moving the boundary onto it, which is the version that actually
  tests the property, because the boundary is then a genuine entry with a
  genuine inclusion proof;
- inventing an entry, reordering the answer, reusing a proof for a wider range
  or a different dimension or another segment's root;
- forgetting a segment, forgetting **every** segment of a shard, or forgetting a
  shard;
- skipping a segment that does overlap, or skipping one on a dimension whose
  extent nothing commits to;
- declaring `size: 0` so there is nothing to check.

Completeness is provable only for predicates on a sorted dimension. There are
five. Everything else is answered honestly as a filter **without** a proof, and
every answer carries a status saying which it is. An answer that quietly mixes
proved rows with filtered ones is worse than an openly unproved one, because it
looks like the first kind.

## Writing to it without changing your agent

An agent instrumented with a stock OpenTelemetry SDK writes here as it stands.
`trailryx-otlp` decodes OTLP trace batches and maps the GenAI semantic
conventions onto records: `chat` becomes a model call, `execute_tool` a tool
call, `invoke_agent` a request or a delegation depending on whether somebody
else started it. Protobuf is decoded by hand, like everything else here, with a
depth limit, because a few hundred bytes of nested length prefixes will
otherwise overflow the stack and a stack overflow in Rust aborts the process.

The mapper's rule: **an attribute goes into a typed metadata field only if it
parses into one, and everything else goes to the payload plane.** Unrecognised
OpenTelemetry attributes routinely contain prompts, so a mapper that does not
recognise something must never decide it is safe. The consequence is tested as
an invariant: every attribute lands in exactly one plane, never both, never
neither. Nothing is repaired on the way: a model name that does not fit its
field leaves the field empty rather than being lowercased into a different
model.

And the honest half. A span records that a call happened. It does not record
the grounds on which it was allowed to happen: there is no OTLP attribute for a
policy version, a budget state or a memory reference, so those stay empty. That
gap is the difference between telemetry and evidence, and it is why the store
has an envelope of its own.

What the receiver refuses, each with a test written from the sender's side: a
span choosing its own tenant, an agent name forging a trust domain, a value
smuggling a separator into the payload, a message nested past the limit, an
operation name this version does not know (refused rather than mapped to
something adjacent, because a wrong event type is worse than a missing record).
Everything dropped is counted, and the counts become a record: a gap nobody
wrote down is worse than a gap, because the trail looks complete.

## What a review found

An adversarial architecture review, run after stage 3, found the proof system
accepting answers it should have refused. Six critical, each reproduced with a
runnable test before being fixed:

- a proof declaring `size: 0` verified against **any** root, so a store-wide
  answer of zero records verified for any query;
- a shard could contribute an empty segment list, because the loop simply never
  ran;
- the history leaf hashed the sequence number, so two segments differing in
  verdict, cost, tenant and payload reference produced **identical roots**;
- a segment could be skipped on time bounds the sealer wrote itself, and the
  sealer is the party being audited;
- inclusion and consistency proofs took their own sizes, so a signed head for a
  five-leaf log could be paired with a proof claiming sizes 8 and 16;
- the journal ignored its argument when a record was already going to disk and
  returned "written" for the previous one.

They shared one root cause, which is now the rule at the top of this file. Four
of the six were counts a proof was allowed to state about itself; the fifth
version of that mistake is the one I got right, which is why the other four went
unnoticed.

The review also confirmed the parts that were least certain: SHA-384 matches
FIPS 180-4, the Merkle algorithms match RFC 6962 rather than merely matching
each other, and the plane boundary holds end to end.

## Design

| Decision | Choice |
|---|---|
| Language | Rust: the deterministic-simulation ecosystem exists here, and an off-the-shelf query engine can be embedded |
| Correctness | DST first, before the first line of the journal; injectable interfaces cannot be retrofitted |
| Concurrency | shared-nothing thread-per-core; each shard single-threaded and deterministic, no locks in the core |
| Truth | the journal; columnar projections are derived and rebuildable |
| Proofs | Merkle history tree (RFC 6962) plus a sorted Merkle index per segment per dimension |
| Composition | one recursion for record → segment → shard → store → federation |
| Crypto | hybrid X25519 + ML-KEM-768 key wrapping from day one, because crypto-erasure lasts only as long as its KEM |
| Licence | Apache-2.0 |

Full documents in [`docs/planning/`](docs/planning/), written in Ukrainian. The
durability contract is [`docs/durability.md`](docs/durability.md); what erasure
cannot reach is [`docs/identifiers.md`](docs/identifiers.md).

## What is ours and what is borrowed

Ours: journal, authenticated index, proofs, sharding, bitemporal resolution,
causality traversal, crypto-erasure mechanics, the simulator, the offline
verifier.

Borrowed on purpose, from stage 7 onwards: cryptographic primitives (a
FIPS-validated module beats anything hand-rolled, and that validation is part of
what is being sold), the SQL engine, and the interchange formats.

Turn off SQL, Parquet and the external KMS, and the database still writes,
proves and erases. That is the test of whose engine it is.

## Working on it

```bash
git config core.hooksPath .githooks   # once
```

No CI while the repository is private, because Actions minutes are metered
there and a local gate does the same work for nothing. `.githooks/pre-push` runs
formatting, clippy with warnings as errors, the tests, a standalone build of the
substrate crate, a zero-dependency check, an `unsafe` check, the determinism
criterion and a 200-seed durability sweep. When the repository goes public,
Actions become free and that script becomes the workflow unchanged.

## Next

Stage 7 onward: crypto-erasure against a real KMS, the evidence pack and its
offline verifier, Parquet projections, the SQL facade, object storage,
federation.

Stage 6 is done for OTLP traces and their mapping. Two pieces of it are not:
the HTTP and gRPC transport, so the receiver takes bytes rather than listening
on a socket, and the NDJSON source that gives the demo live data.

Two known costs, both deferred deliberately. A range answer currently carries an
inclusion proof per entry, so a full range is O(n²) hashing; the fix is a
multiproof over the contiguous range, and it waits for a benchmark to measure it
against. And index sortedness is assumed rather than proved; the offline
verifier discharges it once per segment, and segments are immutable, so one
audit lasts forever.

## Licence

Apache-2.0.
