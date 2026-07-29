<div align="center">

# Trailryx

**The tamper-evident record database for AI agents.**

![Stage](https://img.shields.io/badge/stage-0%20of%2013-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)
![Unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)

</div>

Trailryx stores what AI agents did, and can **prove** it: show the full chain
behind a decision, confirm no record was altered, prove that what you are looking
at is **all** of it, and still erase one person on request.

> Every sequence number reported as acked survives any crash.

That sentence is the durability contract. A deterministic simulator exists to
break it, and it is wired in before the first line of the journal.

---

## Why this is not another observability store

Agent telemetry usually lands in a span store. That works until someone asks a
question an auditor asks:

| Question | Span store | Trailryx |
|---|---|---|
| Was this record altered? | no answer | hash chain, Merkle segments |
| Is this **all** the matching records? | no answer | proof of completeness |
| What did the system *know* when it decided? | not captured | `basis`: policy version, budget state, memory reference, tool manifest |
| What did we believe in March, before we knew better? | no answer | bitemporal, `AS OF` |
| Delete this person, keep the audit valid | mutually exclusive | crypto-erasure, the erasure is itself a record |

Obligations under EU AI Act Article 12 apply from 2 August 2026. The harmonised
standards that would say *how* are not cited in the Official Journal yet.

## Status: stage 0 of 13

What exists is the **determinism and sharding substrate**. Not a database yet:
the seam without which a provable one cannot be built.

| Component | What it does |
|---|---|
| `Clock` | monotonic and wall time kept separate; wall can jump, as an NTP correction does |
| `Rng` | splitmix64; a seed fully determines a run |
| `Io` | append-only storage with a **crash model**: durable vs dirty, and a random prefix of dirty survives a power cut |
| `Bus` | shard-to-shard messaging with deterministic delivery order |
| `Trace` | deterministic event log; byte equality of two runs **is** the determinism test |
| `invariant!` | invariants that stay on in release builds |

The simulator injects: power cuts, short writes, **lying `fsync`**, sync errors,
out of space, message loss, duplication and delay, clock jumps.

**Zero dependencies.** `unsafe` forbidden at the workspace level.

## Try it

```bash
cargo test                                    # 33 tests
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

Hunt for a contract violation across thousands of seeds:

```bash
cargo run --release --bin trailryx-sim-run -- \
  --sweep 5000 --steps 500 --shards 4 --crash-ppm 20000 --hostile --honest-disk
```

```
sweep of 5000 seeds from 100000: 0 failing
```

## What the simulator found on day one

The first hostile run reported `promised=13 recovered=3`.

A refused write **in the middle of a record** left orphaned bytes in the stream,
and the next tick started a **new** record right after them. Recovery stops at
the first thing that does not verify, so everything written afterwards became
unreachable while the acked watermark kept climbing. Thirteen promised, three
real.

Two fixes, both ordinary journal engineering:

1. an unfinished record is **continued on the next tick**, never abandoned for a
   new one;
2. a torn tail is **truncated during recovery**, otherwise every later recovery
   would stop at the same offset and the store would quietly freeze while
   pretending to accept writes.

Both are covered by regression tests. This is the entire argument for putting
deterministic simulation first: a class of bug that surfaces in production after
years surfaced here in minutes.

A note on the fault model: `IoFaults::HOSTILE` includes a lying `fsync`, and the
durability tests deliberately switch it off. Nothing can defend against a disk
that reports a flush it did not perform, but the harness must **notice**, so a
separate test fails if the crash model ever goes blind to it.

## Design

| Decision | Choice |
|---|---|
| Language | Rust: the DST ecosystem exists here, and an off-the-shelf query engine can be embedded |
| Concurrency | shared-nothing thread-per-core; each shard single-threaded and deterministic, no locks in the core |
| Truth | the journal; columnar projections are derived and rebuildable |
| Proofs | Merkle history tree (RFC 6962 model) plus a sorted Merkle index per segment |
| Crypto | hybrid X25519 + ML-KEM-768 key wrapping from day one, because crypto-erasure only lasts as long as its KEM |
| SQL | DataFusion above the engine, never under it; predicates push into the authenticated index so a query can return a proof |
| Licence | Apache-2.0 |

Full documents in [`docs/planning/`](docs/planning/): the plan (what and why),
the architecture (how), and the roadmap (order of work). They are working
documents, written in Ukrainian.

## What is ours and what is borrowed

Ours: journal, authenticated index, proofs, sharding, bitemporal resolution,
causality traversal, crypto-erasure mechanics, the simulator, the offline
verifier.

Borrowed on purpose: cryptographic primitives (a FIPS-validated module beats
anything hand-rolled, and that validation is part of what is being sold),
the SQL engine, and the interchange formats.

Turn off SQL, Parquet and the external KMS, and the database still writes,
proves and erases. That is the test of whose engine it is.

## Roadmap

Stage 0 done. Next: the canonical record model, the L1 contracts, the conformance
suite, and the plane boundary rule (typed fields only in metadata, any free text
lives solely in the encrypted payload plane).

Milestones: **A "Proof"** (single node, evidence pack, offline verifier),
**B "Compatibility"** (OTLP, Parquet, SQL with `WITH PROOF`), **C "Scale"**
(object storage, federation, multi-cloud).

## Licence

Apache-2.0.
