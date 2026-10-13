# Trailryx

> An immutable, provable, bitemporal record of AI agent behavior.
> Own core, clean start, zero dependency on the rest of the stack.
>
> Status: plan. Date: 2026-07-29. Replaces `chronyx-plan.md`.

---

## 0. Name and terminology

**Trailryx** = `audit trail` + the family suffix `-ryx` (Wardryx, Verdryx, Mockryx, Genaryx).

The root was chosen deliberately: **audit trail is the term the buyer speaks in** (risk, compliance,
the regulator), not `trace`, which an engineer uses when talking about performance.

> **Trail** = the recorded chain of an agent's decisions: what it did, on what basis,
> what the system knew at that moment, and how it ended.

The difference from a trace is fundamental, not cosmetic. An OpenTelemetry span is a performance measurement:
how long it took and who called whom. Our trail is **a record of what was done, with its basis**,
and it has a structure a span does not have: several parents, four time axes, a decision-basis block
and an integrity proof.

We **accept** OTel spans **on input** and turn them into records. We do not convert back without loss
and do not claim to.

Name status as of 2026-07-29: `.com`, `.io`, `.dev`, `.app`, `.ai`, `.org`, `.net` are free,
as are the GitHub organization, PyPI, npm and crates.io. No company or product with this name was found.

---

## 1. What it is, in one sentence

> Trailryx is a database that stores what AI agents did and can **prove** it:
> show the full chain of a decision, confirm that a record has not been changed, prove
> that the records shown are **all** the records, and at the same time erase a specific person on request.

Four words define it: **provable**, **complete**, **bitemporal**, **erasable**.

## 2. Whom it serves

| Role | The question it answers |
|---|---|
| Compliance / risk | "Show the regulator what the agent did in March, and prove that this is everything" |
| Security | "Why did the agent make this call and who authorised it" |
| Engineer | "What exactly broke in run 4471" |
| DPO / lawyer | "Delete this person in a way that leaves the audit valid" |

## 3. What it is not

- Not a performance tracing backend (Jaeger, Tempo, VictoriaTraces).
- Not a replacement for Prometheus: numeric metrics are exported **there**.
- Not a dashboard, not an eval platform, not a policy engine.
- Not a vector DB: vectors appear after the pilot and as a **projection**, not as the essence.
- Not a blockchain: no consensus, no nodes, no token.

## 4. Zero coupling

Trailryx is useful **on its own**, without any other service. This is what separates a product
from a feature, and it is an architectural decision, not a declarative one:

- **the primary input is OTLP** (any agent with OTel instrumentation);
- native formats (NDJSON, JSON envelopes) are **adapters on input**, on a par with third-party ones;
- nothing from the stack is a dependency: not in the build, not in the runtime, not in configuration;
- integrations are one-way: Trailryx pushes data out, it does not go and fetch it.

---

## 5. Record model

### 5.1. The unit

```
record {
  # identity
  id                 # ULID, monotonic within a segment
  agent_id, run_id, parent_run_id, on_behalf_of[]

  # four times, not one
  occurred_at        # when the event happened in the world (from the emitter, NOT trusted)
  decided_at         # when the decision was made
  recorded_at        # when we recorded it (our clock, trusted)
  knowledge_as_of    # as of which knowledge the decision was made

  # basis: "what the system knew"
  basis {
    policy_version   # which policy was in force
    budget_state     # what the remaining balance was
    memory_ref       # what the agent remembered (a reference, not a copy)
    model, params    # what it was invoked with
    prompt_hash      # hash of the prompt, not the prompt
    tool_manifest    # which tools were available
    identity_chain   # delegation, root-first
  }

  # causality: a DAG, not a tree
  caused_by[]        # several parents: request + policy + memory + budget

  # outcome
  outcome { verdict, error, latency_ms, tokens_in, tokens_out, cost }

  # the payload does NOT live here
  payload_ref { hash, size, class, key_id }

  # integrity and algorithm agility
  seq, prev_hash, segment_id
  hash_alg, sig_alg, kem_alg
}
```

**There is no `ext` in the metadata.** Everything that came from the mapper and did not fit the typed
fields of the canon goes into the **encrypted payload plane**, not here. The reason is in §5.2 (d).

### 5.2. Four decisions everything rests on

**(a) Hot metadata separate from cold payload.** Prompts and responses are kilobytes
and megabytes. The record holds only `payload_ref`. The content lives in a content-addressed store,
encrypted. This immediately gives: a small index, deduplication of identical system prompts
and the possibility of erasure (§7).

**(b) Causality is a DAG.** For an agent, a decision has several parents at the same time: the user's
request, the policy verdict, the memory state, the remaining budget. `parent_span_id` does not
express this. Edges are explicit.

**(c) Bitemporality is not an option.** Two axes, always: when it was true and when we
found out. The interval is closed, a row is never overwritten, any `as_of`
hits exactly one row.

**(d) The plane boundary is a schema invariant, not an agreement.** The most important of the four,
and it is a legal one.

> **The metadata plane contains only typed fields**: identifiers, enums, hashes,
> numbers, timestamps. **Any free text lives exclusively in the encrypted
> payload plane**, under the subject's key.

Why this is critical. OTel GenAI attributes can carry **full prompts, addresses, names**:
the semconv explicitly provides for capturing content. If a mapper puts unrecognised attributes
into the metadata "verbatim", then `forget` erases the payload, **while PII stays in the metadata**,
and the promise of the right to be forgotten becomes false. The same applies to text fields
inside `basis`: the policy version, the prompt hash and the memory reference are allowed there,
but not the prompt itself and not the memory itself.

Consequences, mandatory at stage 1:

- a conformance test **"no free-text field in the metadata plane"** that fails
  the build;
- a DPIA-style pass over **every canon field**: what data it is, whether it can be
  personal, which plane it lives in;
- a mapper that does not know where to put an attribute puts it **into the encrypted plane**,
  never into the metadata.

---

## 6. Architecture: what is ours, what is borrowed

The split runs along one line: **ours is what gives guarantees; borrowed is what gives speed**.

| Layer | Decision |
|---|---|
| 1. Journal (the truth) | **ours** |
| 2. Authenticated index | **ours, and this is the main thing** |
| 3. Causality traversal, bitemporal resolution | **ours** |
| 4. Erasure mechanics | **ours** |
| 5. Columnar projection | Parquet |
| 6. Ad-hoc SQL execution | DataFusion / Arrow |
| 7. Codecs, ANN index | ready-made libraries |

### 6.1. The journal is the truth, columns are a projection

```
             OTLP  |  NDJSON  |  other adapters
                        v
                +---------------+
                |    mappers    |  -> canonical record
                +-------+-------+
                        v
        JOURNAL: append-only, write-oriented,
        every record is verified IN ISOLATION
                        v
        segment close: Merkle + manifest + signature
                        v
        +---------------+----------------+
        v                                v
  AUTHENTICATED INDEX              PROJECTIONS (derived)
  (inclusion proof and              Parquet | text | vectors
   COMPLETENESS proof)              can be thrown away and rebuilt
```

This is fundamental for provability: if the index and the truth are one file, any compaction
or format migration becomes an event that has to be proven to the regulator. With the separation, a merge is
simply a cache rebuild, while the truth lies untouched.

### 6.2. Completeness proof: what the custom index is written for

No existing database answers this question:

> "Here are the rows, and here is the proof that these are **all** the rows matching the predicate
> in this interval, and that none of them has been changed."

The regulator is interested not in what you showed, but in **what you did not show**. Technically this requires
a structure that can do both an inclusion proof and a **proof of absence** (that between two adjacent
keys there is nothing): a sorted Merkle index per segment, whose roots are signed.

Bolting this onto Parquet from above is impossible. Either it is in the index from day one, or
it never will be. This is precisely what justifies a custom engine, not speed. Speed
never justifies it.

### 6.3. Open export as an obligation

A custom format is a debt of trust: the auditor will have to believe our reader. It is closed
by one mandatory decision: **a guaranteed lossless export to Parquet + JSON**, itself
verifiable. Our own engine gives proofs and speed, and the open export removes
the question "what if your reader is lying".

This is not a concession, it is a selling point.

---

## 7. Cryptography, erasure, the post-quantum era

### 7.1. Provability

- **A chain on records**: `prev_hash`, one stream = one chain, continues after a restart.
- **Merkle per segment**: verifying one record costs log(n).
- **A signature per segment**, not per record (see 7.4).
- **Epoch anchoring** outward: after the pilot, but the manifest format is prepared immediately.

The wording stays honest: **tamper-evident, not tamper-proof**.

### 7.2. Erasure versus immutability

GDPR requires deletion, the AI Act requires an immutable log. Crypto-erasure resolves this:

1. The payload is encrypted with a key issued **per data subject**.
2. Deletion = destroying the key + an `erasure` record in the same chain.
3. The chain remains verifiable, the content disappears forever, **the fact of erasure itself becomes proof**.

**The problem this wording hides: at the time of writing, the subject is usually unknown.**
An OTLP span arrives without an identified person, and the fact that somebody's data was in the prompt
is established later, sometimes months later, sometimes only at the request of the person themselves.

Hence a two-level scheme, not a "key per subject" directly:

| Level | What it is | When it is created |
|---|---|---|
| **DEK** | a random key **per payload** | at write time, always |
| **KEK** | the key under which the DEK is wrapped | the subject's, if the subject is known; otherwise the **tenant's** |

**Later attribution** (it was found out that the payload concerns a specific person) is a
**re-wrap**: the DEK is re-wrapped under the subject's KEK, the old wrapped key is destroyed.
Both actions, the attribution and the destruction of the wrapped key, **are events in the chain**, not a quiet
operation on the key store.

The consequence for `forget`: it destroys the subject's KEK, and with it all the DEKs ever wrapped
under it become unrecoverable. Payloads that remained under the tenant
KEK are erased by a separate operation, by list, and that list is also a record.

### 7.3. The post-quantum era is a question of correctness, not of compliance

The external frame: CNSA 2.0 (new systems 2027, legacy 2030, fully 2035),
NCSC (2028 / 2031 / 2035), NIST IR 8547 (deprecation of RSA-2048 and P-256 from 2030, disallowed from 2035),
the EU roadmap (critical infrastructure end of 2030, the rest end of 2035).

But the reason is not the standards:

**Crypto-erasure lives exactly as long as the KEM lives.** If the subject's key is wrapped with
RSA or ECDH, and the ciphertext has already been collected, then destroying the key **erases nothing**: it
will be unwrapped in 2032. "Harvest now, decrypt later" hits not the transport, but our
central promise.

Therefore: **hybrid ML-KEM (X25519 + ML-KEM-768) from day one**. Re-wrapping a stolen
ciphertext after the fact is impossible in principle.

**A proof outlives the cryptography it was signed with.** A record's life is years: six
months minimum under the AI Act, but liability for harm caused by a model is 5-10 years.

| Threat | Remedy |
|---|---|
| Backdated forgery (a CRQC creates "old" records) | external time anchoring + **a built-in re-signing cycle** |
| Harvest now, decrypt later | hybrid ML-KEM |

Re-signing is not a configuration option. A product that cannot re-anchor its own
archive becomes a pile of unprovable files in 2030.

### 7.4. Three signature levels (size dictates the architecture)

ML-DSA-65 is ~3.3 KB versus 64 bytes for ES256. Signing every record post-quantum
is infeasible. Therefore:

| Level | Mechanism | Why | State as of 2026-07-29 |
|---|---|---|---|
| Record | hash chain on **SHA-384** | zero signatures, zero overhead | done |
| Segment | Merkle + **ML-DSA-65** (hybrid with ES256) | one signature per millions of records | aws-lc-rs, behind an unstable flag |
| Epoch | external anchor + **SLH-DSA** | security rests **on hashes alone**, the most conservative for 10+ years | **moved beyond v1** |

**Why SLH-DSA is not in v1.** There is no audited Rust library that covers all three
algorithms today: `aws-lc-rs` has no SLH-DSA at all, and the pure
RustCrypto `slh-dsa` has not been audited. Putting the **longest-lived** tier of
provability on an unaudited implementation means promising a reliability that does not exist.
The manifest format is prepared for it from the start and is switched on when a validated
implementation appears. Details and the library table: §14.2 of the architecture.

SHA-384, not SHA-256, is deliberate: CNSA 2.0 requires 384+, and **the product must pass
its own scanner** (`qryx scan --policy cnsa` with no violations).

### 7.5. Algorithm agility is a schema field

Every record and manifest carries: what it is signed with, with which key, which hash function, which KEM.
Without this, the 2030 migration is technically impossible: there would be no way to enumerate what to re-sign.

**Re-signing is recorded as an event, never as a silent overwrite.** A silent
re-signing of an audit journal cannot be told apart from forgery.

**The verifier never removes support for an old algorithm**, it only marks it weak.
Dropping ES256 would destroy the provability of everything signed with it.

---

## 8. The query surface

| Path | Pilot |
|---|---|
| Structural + time filter (with completeness proof) | yes |
| Run reconstruction with causality | yes |
| Evidence pack | yes |
| Ad-hoc SQL over the exported projection | yes |
| Full-text over the payload | no (conflicts with encryption, §11.7) |
| Vector similarity | no, after the pilot |

**The consumer of this data is an agent, not only a person.** So the surface is designed
for it from the start: MCP-native, economical with tokens (summaries and references, not a 200 KB dump),
every answer cited and verifiable, built for thousands of small queries instead of
one large report. No observability system is built this way, because they were written
for a person with a dashboard.

---

## 9. The demo, which is also the acceptance criterion

1. An agent exceeds its budget and makes a dangerous call, and it is blocked.
2. `trailryx run 4471` unfolds the chain: request → policy verdict (with version)
   → budget state → what the agent remembered → call → block.
3. `trailryx query --agent X --march` returns rows **plus a completeness proof**.
4. `trailryx evidence --incident 4471 > pack.json` assembles the evidence pack.
5. The pack is moved **to a machine without Trailryx**: `trailryx-verify pack.json` says OK.
6. `trailryx forget --subject "Ivan Petrenko"` erases the subject.
7. `trailryx-verify pack.json` **says OK again**, but the payloads are empty and the chain
   contains an erasure record.
8. `qryx scan --policy cnsa` on its own store: no violations.

Nobody else on the market will show steps 3 and 7.

**Acceptance criterion:** all eight pass on a clean machine, from scratch, **twice in a row**.

---

## 10. How this is validated

An engine dies not in the main scenario but in the tail. So validation is a separate phase,
not "we ran the tests":

| Suite | What it does |
|---|---|
| **Crash injection** | `kill -9` at every phase of the write, torn records, a lying fsync, a full disk. After each: the journal opens, the chain is intact, the last incomplete record is explicitly discarded |
| **Adversarial forgery tests** | flip a bit, remove a record, reorder records, substitute a segment, replay an old segment. **Every case must be detected**, zero silent passes |
| **Completeness proof under attack** | hide a record from the answer → the completeness proof **must** break |
| **Property-based tests on bitemporality** | for any `as_of` exactly one active row per (s, p); the supersession chain restores continuity |
| **Erasure under attack** | after `forget`, try to recover the payload by every path: from projections, from caches, from export, from backup |
| **Clock** | jumps backwards, NTP corrections, issuer and receiver divergence above the threshold |
| **Second run** | everything above is repeated on an already populated store, not only on an empty one |

Mockryx can generate adversarial scenarios for the first two suites (as an external tool,
not as a dependency).

---

## 10a. Phase 0 decisions (made 2026-07-29)

Five blocking questions are closed. Each can be revisited, but then deliberately
and with an understanding of the consequences listed below.

### R1. Core language: Rust

> Revised 2026-07-29 after research. The first edition named Go; it
> relied on the assumption that an embedded SQL engine is not needed, and did not take into account
> the DST requirements. Both assumptions turned out to be wrong.

**Why.** Two **independent** lines of argument give one answer.

*Line 1, correctness.* @decided 2026-07-29: the main product priority is that it does not crash, does not lose data and has few
bugs; it is achieved by the DST methodology (§1a of the architecture), not by the language. But DST
imposes a requirement: all nondeterminism sits behind injected interfaces, and the core is
deterministic **per shard** (thread-per-core, §1b of the architecture), with no shared memory
and no locks. The Go runtime **deliberately randomizes** goroutine scheduling,
and a deterministic program cannot run on more than one OS thread: Polar Signals
compiled to WASM and forked the runtime for this, Resonate wrote its own
cooperative scheduler. In Rust this is a ready-made ecosystem (MadSim in RisingWave,
turmoil, mad-turmoil).

*Line 2, query engine.* The closest precedent, the InfluxDB rewrite from Go to Rust
(2020-2024), was done precisely to **embed a ready-made query engine**,
and not because of GC or speed.

**Consequences.**
- ML-KEM from **aws-lc-rs** (FIPS 140-3 validation), ML-DSA from the same crate behind an unstable flag,
  SLH-DSA outside v1 (§14.2 of the architecture).
- The estate has two ecosystems (6 Go repositories + TokenFuse and Trailryx in Rust);
  contributor onboarding is slower. A deliberate cost.
- **Zig** was considered and rejected: the best for DST, but with no DataFusion and no
  validated PQC we would have to write our own crypto and our own SQL.

### R2. Hybrid ML-KEM from day one: yes

**Design.** Every payload is encrypted with **AES-256-GCM** under its own random DEK;
the DEK is wrapped under a KEK via **HPKE with hybrid X25519 + ML-KEM-768** (the KDF takes both
secrets: strength is preserved if at least one holds). The KEK is per subject if
the subject is known, otherwise per tenant, with a later re-wrap (§7.2). `forget` destroys
the subject KEK.

**Consequences.** The key hierarchy is designed in phase 1. `kem_alg` and `key_id` are in the schema
from day one. KEK management (where it lives, how it is rotated) becomes a separate subsection:
without it erasure does not work.

### R3. OTel GenAI semconv: our own canon, semconv as an adapter

We map only the stable part (`gen_ai.operation.name`, model, tokens, tool
calls, latency). Everything else we store **verbatim and without interpretation,
but in the encrypted payload plane**, never in metadata (§5.2 g): unrecognized
OTel attributes regularly contain prompts and PII, and in metadata they would survive `forget`.

**Consequences.** When semconv changes, the **mapper version** changes, not the format
of the store. Every record keeps the version of the mapper that created it. A corpus
of conformance tests on real OTLP streams is needed, and among them a test that the metadata plane
contains no free-text field.

### R4. Authenticated index: two structures

| What we prove | Structure |
|---|---|
| the journal was only appended to, never rewritten | **Merkle history tree**, consistency proofs, the CT model (RFC 6962) |
| these are **all** the records matching a predicate in a range | **sorted Merkle index per segment**, inclusion and non-inclusion proofs via neighboring leaves |

Sparse Merkle Tree is rejected: it was built for mutable state, and our segments
are immutable.

**A limitation we state explicitly.** A completeness proof is possible only for predicates over an
**indexed sort key**. An arbitrary `WHERE` cannot be proven without
a commitment to the whole scan. So we fix a small set of **proof dimensions**:
time range, `agent_id`, `run_id`, event type. The rest is a filter **without proof**,
and the API marks this with an explicit flag in the response.

**Consequences.** The set of proof dimensions is fixed in phase 1: it determines the sorting
of segments, and changing it later means rebuilding all indexes.

### R6. Trust in us as a producer of proofs

The question the first serious auditor will ask: **"who has reviewed your code?"**
For an ordinary database this is secondary, for a proof-grade one it is the main objection, and solo authorship
makes it sharper. The answer is built in steps, in order of increasing cost:

1. **Minimizing the TCB.** The offline verifier is a separate crate with minimal dependencies,
   written so that a person can read it in an hour. Everything not needed for verification
   stays outside it.
2. **Reproducible builds and published DST seeds.** Anyone can reproduce our run
   and our binary byte for byte.
3. **A second independent implementation of the verifier** in another language (for example Go or Python),
   reading the same pack. Two implementations that agree prove the format, not the author.
4. **An external audit of the crypto-usage layer** before the first compliance contract.
   This is a cost, so it is a separate decision and not now, but it is in the plan.

Items 1-2 go into v0.1, item 3 into v0.2, item 4 is subject to a separate decision.

### R5. License: Apache-2.0

@decided 2026-07-29: nothing is paid, and the money comes from consulting. This is consistent with that decision and with the rest of the estate.

AGPL is rejected deliberately: it protects against a cloud vendor who would host the product
and take the revenue, but here there is no hosting revenue by definition. Meanwhile AGPL
noticeably complicates adoption inside a bank's perimeter. For a product that
sells trust, the simplest license is an advantage. Apache-2.0 also gives an explicit
patent grant, which the legal department of a large client looks at.

---

## 11. Questions to close

The **[B]** questions are closed in §10a. Below remain the **[P]** (decided in the pilot)
and **[D]** (can be postponed); the blocking ones are kept for the decision history.

| # | Question | Recommendation |
|---|---|---|
| 1 | **[B]** Core language | Go: one static binary, mature Parquet and Arrow, fast onboarding. Counterargument: TokenFuse is in Rust, so the estate will have two ecosystems |
| 2 | **[B]** Hybrid ML-KEM from the start? | **Yes.** Without it crypto-erasure stops erasing as soon as a CRQC appears, and a stolen ciphertext cannot be re-wrapped |
| 3 | **[B]** Binding to OTel GenAI semconv | Not as the canon: as of 17.07.2026 no `gen_ai.*` is Stable, on 12 June they were moved to a separate repository. Our own canon, semconv supported on input and output |
| 4 | **[B]** Structure of the authenticated index | A sorted Merkle per segment with inclusion **and absence** proofs. Alternatives (sparse Merkle tree, verifiable B-tree) to be compared on a prototype before phase 3 |
| 5 | **[B]** License | Apache-2.0, nothing paid, money from consulting and implementation |
| 6 | **[P]** Journal format | Record-oriented, self-describing, with length and CRC per record. Format version in every segment from day one |
| 7 | **[P]** Payload indexing versus encryption | No full-text in the pilot. Later: an index built before encryption and erased together with the key, or a blind index. The two leak in different ways, choose deliberately |
| 8 | **[P]** Granularity of erasure keys | **Closed (§7.2):** a DEK per payload, KEK per subject or tenant, later attribution via re-wrap, both actions as chain events |
| 9 | **[P]** Trust in the clock | `recorded_at` is ours and trusted, `occurred_at` comes from the issuer and is marked untrusted. A divergence above the threshold is an event, not a silent correction |
| 10 | **[P]** Behavior under pressure | Fail-open with respect to issuer traffic, but **the loss of a record itself becomes a record** (a gap counter). Silent loss is the worst thing for an audit |
| 11 | **[P]** Idempotency | Deduplication key `(source, agent_id, run_id, seq)` |
| 12 | **[P]** Retention and tiers | At least six months under the AI Act. Hot tier is local disk, cold tier is object storage. **Downsampling is forbidden by definition**: an audit is not thinned out |
| 13 | **[P]** Re-signing policy | On a schedule (annual cycle) and on an event (algorithm deprecation). Each as a record |
| 14 | **[D]** Multitenancy | One tenant in the pilot. Later a tenant prefix in segments, not a shared table |
| 15 | **[D]** Source of the external anchor | RFC 3161 TSA with PQC, a transparency log, or a signed CI artifact. The manifest is prepared for all three |
| 16 | **[D]** Domain and GitHub | Check availability, the trademark in classes 9 and 42. **Registration only after separate consent** (a cost) |

---

## 12. Phases

**The single source of work order is [`trailryx-roadmap.md`](trailryx-roadmap.md).**
There is deliberately no phase table here: three documents with three different numberings
diverge on the first edit. The roadmap holds stages 0-13, grouped into three
milestones (A "Proof", B "Compatibility", C "Scale"), with a "done when" criterion
for each stage.

The ordering rule that applies in all documents: **guarantees first, then speed**.
The first implementation of the journal and index is deliberately naive and slow, but with the full set of
properties. Optimization comes after there is something to measure regressions against.

---

## 13. What costs money

- Development and all tests locally: **0**.
- Pilot run on a box: Hetzner CPX class, roughly **EUR 10-30/month**, torn down afterwards.
- Object storage for the cold tier: **a metered service**, not enabled in the pilot,
  we write to local disk.
- Domain and trademark: a cost, only after separate consent.
- **External audit of the crypto-usage layer** (R6, item 4): a deferred cost, relevant
  before the first compliance contract, not earlier. Price levels to be clarified closer to the date.
- No paid API in the hot path: signatures are local, no LLM is needed at all.

---

## Sources

- OTel GenAI semconv, state as of July 2026: [overview](https://john-hodge.com/blog/opentelemetry-genai-semantic-conventions/)
- EU AI Act art. 12: [Help Net Security](https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/)
- PQC deadlines: NIST IR 8547, CNSA 2.0, NCSC, the EU roadmap (June 2025)
- ClickHouse + Langfuse: [announcement](https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability)
- VictoriaMetrics as a model of operational simplicity: [site](https://victoriametrics.com), [GitHub](https://github.com/VictoriaMetrics)
