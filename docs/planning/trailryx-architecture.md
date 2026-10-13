# Trailryx: architecture

> Complements [`trailryx-plan.md`](trailryx-plan.md). The plan answers "what and why",
> this document answers "how, so that it lives in any environment".
>
> Date: 2026-07-29.

---

## 0. The principle without which "multi-functionality" kills a project

Breadth of functionality kills systems not by the volume of code but because every new capability
undermines the guarantees. Hence the single rule on which the whole document rests:

> **A small immutable core + a wide periphery behind stable contracts.
> An adapter never has the right to weaken a guarantee of the core.**

The core provides four things and nothing more: immutability, completeness proof, bitemporality,
erasure. Everything else (clouds, protocols, databases, SIEM, metrics) is **adapters**, which
plug in, are replaced and are written by the community without touching the core.

A practical safeguard: **every adapter passes a conformance suite** that proves
it does not lie about time, does not silently drop fields and does not bypass the index. An adapter
that fails does not enter the build.

---

## 1. Layers

```
L3  QUERY INTERFACES
    SQL (Postgres wire) | REST | MCP | CLI | gRPC | /metrics
─────────────────────────────────────────────────────────────
L2  ADAPTERS (many, replaceable)
    Sources | Sinks | ObjectStore | KeyProvider | Anchor | Foreign tables
─────────────────────────────────────────────────────────────
L1  CONTRACTS (traits, stable, versioned)
─────────────────────────────────────────────────────────────
L0  CORE (small, no plugins)
    journal · authenticated index · crypto · erasure · bitemporality
```

The L1 contracts, which are fixed in phase 1 and are not broken afterwards:

| Contract | What it does | Example implementations |
|---|---|---|
| `Source` | brings events in from outside | OTLP, Kafka, CloudTrail, S3-drop |
| `Sink` | sends data out | OTLP, remote_write, Splunk, Parquet |
| `ObjectStore` | cold storage | S3, GCS, Azure Blob, MinIO, FS |
| `KeyProvider` | keys and their destruction | file, AWS KMS, GCP KMS, Vault, HSM |
| `Anchor` | external anchoring of roots | RFC 3161 TSA, transparency log, CI artifact |
| `TableProvider` | foreign data as a table in SQL | Postgres, ClickHouse, BigQuery, Iceberg |
| `AuthProvider` | who is asking and what they are allowed to do | OIDC, SPIFFE, cloud IAM, mTLS |
| `Peer` | another Trailryx node | federation between clouds |

---

## 1a. Correctness methodology: DST-first

**This is the most important section of the document.** The language, the engine and the formats are secondary to it.

A product whose entire value lies in "the record is provably intact" has no right to silent loss
or corruption of data. Ordinary unit and integration tests do not catch this:
rare failures (a crash in the middle of a write, a lying fsync, a clock jump, partial
delivery) show up in production years later.

### 1a.1. What it is

**Deterministic Simulation Testing**: all nondeterminism (time, randomness,
disk I/O, network) is moved behind injected interfaces, the core runs
as a **single-threaded deterministic state machine**, and the simulator drives it with a controlled
seed, inserting faults at arbitrary points.

What this gives: **years of operation in minutes**, exact replay of any failure
by seed, and detection of a class of bugs that otherwise wait for production.

Evidence base: the approach was pioneered by FoundationDB (~2010); TigerBeetle keeps
a DST cluster on 1000 cores that runs **two millennia of simulated time per day**;
RisingWave (on MadSim), WarpStream and Resonate went down the same path; Antithesis
sells this as a service.

### 1a.2. Why this is architecture, not testing

**DST cannot be added later.** It places requirements on the design of the core from day one:

1. **No direct access to the clock, randomness, disk or network in the core.**
   Only through the traits `Clock`, `Rng`, `Io`, `Net`. In production these are real implementations,
   in simulation they are controlled ones.
2. **The core is deterministic per shard** (thread-per-core model, §1b): each shard
   is single-threaded and deterministic, exchange between shards by explicit messages
   is simulated the same way as the network. There is no shared memory or locks in the core,
   because they are exactly what kills determinism.
3. **Assert density as in TigerBeetle**: invariants are checked everywhere,
   and those critical for integrity stay enabled **in release too**. Better to crash
   loudly than to write a falsehood quietly.
4. **The simulator is part of the product**, not a test folder. The seed of each failure
   is stored and replayed with one command.

### 1a.3. What we simulate

| Failure class | Specifics |
|---|---|
| Crash | `kill -9` at every point of the write, including the middle of a segment write |
| Disk | partial writes, lying `fsync`, full disk, corrupted sector, slow disk |
| Clock | jump backwards, NTP correction, divergence between emitter and receiver |
| Network | loss, duplication, reordering, partition between federation peers |
| Object store | conditional write error, duplicate publication, unavailability |
| Hostility | segment substitution, record removal, replay of an old segment |

### 1b. Concurrency model: shared-nothing thread-per-core

Three options were considered. The third was chosen.

| | single-threaded core | multi-threaded with shared memory | **thread-per-core** |
|---|---|---|---|
| Core utilization | one | all | **all** |
| Lock contention | none | grows with the number of cores | **none** |
| Cache-line ping-pong | none | present | **none** |
| Determinism for DST | present | **disappears** | **present, per shard** |

**Why not single-threaded, despite the TigerBeetle example.** They have two reasons, and the main one
is negative: their workload is **inherently concurrent** (hot accounts, a transfer
between two accounts serializes the system, sharding a financial ledger is notoriously hard).
**Our workload is the opposite**: an append-only stream, naturally partitioned by
`tenant` and `agent_id`, with no transactions across records and no global invariants.
The reason that forces them onto one thread is absent for us.

**Why not shared memory with locks.** That is exactly where determinism dies, and with it DST,
which is the top quality priority. Plus lock contention and cache-line ping-pong
on multi-core machines eat the gain.

**The chosen model** (Seastar / ScyllaDB): N single-threaded deterministic shards,
one per core, each owning **its own journal, its own index, its own
segments**; exchange by explicit messages through lock-free queues, with no shared
memory. Scaling is linear across cores.

**Consequences that must be built in from the start:**

1. **The number of shards is fixed at store creation, generously, and forever.**
   Not "as many as there are cores", but deliberately more: virtual shards whose ownership migrates
   between cores. Migrating ownership is allowed, **re-splitting never**.
   The reason is not performance: **shard identity enters the proof paths**,
   and redistribution after the fact breaks proofs that have already been issued. If a different number is ever
   needed, it is a **new store epoch with explicit lineage**, not a rebuild of the old one.
   Key: hash of `(tenant, agent_id)`, with more shards than cores, otherwise one "hot"
   agent saturates one core while the rest sit idle.
2. **One proof recursion for all levels.**
   `record → segment → shard → store → federation`, and at every level the same
   mechanism: the root of a level is a Merkle tree over the roots of the level below. In particular
   **the epoch root = a Merkle tree over the roots of all shards**. Consequence: one external anchor
   is needed for the whole store, not one per shard, and federation (§7)
   gets the composition of proofs for free, because it is the same code.
3. **Causality crosses shards, and this is designed at stages 4-5, not at 12.**
   We shard by `(tenant, agent_id)`, but the delegation chain (`on_behalf_of`,
   `parent_run_id`) connects **different agents**, that is, different shards. So
   `causal_closure()` is a cross-shard traversal with composition of proofs, not a local
   operation. Discovering this at the federation stage would mean rewriting the index.
4. **We write our own reactor, a thin one.** Ready-made runtimes do not fit: monoio lags
   behind on io_uring features and is sluggishly maintained, glommio has its own reactor that we will not
   be able to make deterministic. We need an `Io` trait with real and simulated
   implementations, so the reactor has to be ours.
5. **Two I/O backends, both first-class.**
   `io_uring` is **an optimization where permitted**, not a requirement:
   the default seccomp profiles of container runtimes restrict it, managed
   Kubernetes platforms and hardened kernels do too (after a series of CVEs large operators
   disabled it in production) - that is, exactly where our buyer sits.
   So **the epoll backend is a full production path**, not a crutch for development
   on macOS. Both live behind the same `Io` trait and the same DST seam,
   both pass the same set of durability tests.
6. **`fsync` goes around the ring**, as in PostgreSQL (§1a.4).

### 1a.4. The durability contract is designed explicitly

Research shows that this is easy to get silently wrong:

- `O_DIRECT_NO_FSYNC` gives a real **write hole**: the WAL reports that the data is flushed,
  but it is not flushed;
- `fsync` in io_uring is **blocking**, runs on spare workers, and cannot
  be issued from rings in IOPoll mode; **PostgreSQL deliberately calls `fsync` directly**,
  so as not to spawn io workers on the critical path.

Consequence: our durability contract (what exactly is flushed, when and how; what we promise
after `ack` returns) is **described in the document and verified by the simulator**,
rather than relying on the default behavior of a library.

---

## 2. Revision R1: the core in **Rust**, not Go

Decision R1 in the plan was justified by the assumption that an embedded SQL engine is not needed.
That assumption has been dropped, and it was the main argument. Recalculation:

The decision rests on two **independent** lines of argument. When two different criteria
give the same answer, the choice is robust.

**Line 1: DST (§1a), that is, the top quality priority.**

The Go runtime **deliberately randomizes** goroutine scheduling, and a deterministic program
cannot run on more than one OS thread. Those who did DST in Go
paid dearly: Polar Signals (FrostDB) compiled the application to **WASM and forked
the Go runtime**; Resonate wrote its own cooperative scheduler in a single goroutine.
`synctest` from Go 1.24 gives only "bubbles" with a synthetic clock, without disk
and network faults. `gosim` exists, but it is a young third-party project.

In Rust this is a working ecosystem: **MadSim** (RisingWave runs on it), **turmoil**,
**mad-turmoil** from S2.dev with libc interception of time and entropy. Not free either
(a seam at the libc level is needed, because transitive crates pull in time and randomness around the
runtime), but it is an existing tool, not our own fork of the compiler.

**Line 2: an embedded query engine.**

The most relevant precedent is the **rewrite of InfluxDB from Go to Rust** (2020-2024).
The reason named by the authors is **not GC and not speed**: the goal was to embed a **ready-made
query engine**, and Rust offers better compatibility with C than Go. This is literally our case.

| Criterion | Go | Rust |
|---|---|---|
| **DST** | the runtime randomizes scheduling; a runtime fork or WASM is needed | **MadSim / turmoil / mad-turmoil**, in production at RisingWave |
| Embedded SQL engine | no mature one (Arc from 10.2025 is too new); what remains is cgo+DuckDB, which breaks the static binary | **DataFusion 54**, the fastest single-node engine over Parquet |
| Postgres wire | write from scratch | **pgwire** + `datafusion-postgres`, a path verified by GreptimeDB |
| Pushing predicates down into our own index | do it yourself | **`TableProvider::supports_filters_pushdown`**, the standard extension point |
| FIPS-validated crypto | Go Cryptographic Module | **aws-lc-rs** over AWS-LC, **the first module with ML-KEM in FIPS 140-3 validation** |
| Memory safety on untrusted input | GC, but no guarantees on parsers | compiler guarantees |
| Affinity with the estate | 6 Go repositories | TokenFuse is already Rust |

**The cost, stated honestly.** InfluxDB spent 4.5 years on the rewrite (admittedly, it was
a rewrite of a live product with a business, not greenfield); a typical field report
on a Go→Rust migration is a dip in development speed for a quarter. The estate
gains a second ecosystem, and onboarding contributors is slower.

**Considered and rejected: Zig.** TigerBeetle is built on it, the most correct system
in the industry, and for DST it is the best choice in principle. But it has neither DataFusion
nor validated post-quantum crypto: two of our key requirements would have to be written
from scratch. The risk of our own crypto and our own SQL outweighs the gain.

---

## 2a. Revision R7: we take dependencies when they are better than our own

**@decided 2026-07-30 (standing):** the project adopts the best available implementation of a component
and writes its own only where building it ourselves is the whole point of the product. Dependencies
no longer need individual sign-off: this policy is recorded here.

The claim "zero third-party dependencies in the workspace" died in two steps, and both were
right. First the SQL facade took DataFusion and pgwire, because compatibility with the
Postgres protocol matters more than the size of the tree. Then it turned out that the `Aead` seam has no
validated implementation, so **crypto-erasure, which is what this store is bought for, does not run
in a deployment**, and no amount of our own code will fix that,
because what is being sold is the validation itself.

**What stays ours and why:** the record format, proofs, journal, index, erasure mechanics,
offline verifier. Writing our own here is the product.

**What we take from others:** a validated cipher, post-quantum key exchange, TLS, the SQL engine.
Nobody buys a proof store because its author implemented AES.

**The boundary the policy does not move, and it is what carries the argument:** the core and `trailryx-verify`
stay free of third-party dependencies. The auditor reads the verifier, and every crate in it
is one more crate that they are asked to take on trust instead of reading. So a dependency always
lives in an L2 adapter, and the gates check two things: the list of crates that are allowed
to have dependencies, and that the core builds and passes its tests without any adapter.

**First consequence:** `aws-lc-rs` as the crypto provider. One dependency closes three
open questions: validated AES-GCM for the `Aead` seam, validated ML-KEM for
hybrid key exchange (the format carries an identifier for it from day one), and
TLS, because `rustls` uses the same backend.

---

## 3. SQL as a first-class interface

### 3.1. Why Postgres wire specifically

The same lesson that VictoriaMetrics taught: **what wins is not speed but compatibility**.
By speaking the Postgres protocol, the product works on release day with Grafana, Metabase,
Superset, DBeaver, psql, pandas, every ORM and every driver in every language.
Zero integration work on our side.

### 3.2. How SQL does not break provability

This is the main constructive problem, and it is solved, not ignored.

Our data is exposed to DataFusion through **our own `TableProvider`**, which implements
`supports_filters_pushdown`. Predicates on the provable dimensions (time, `agent_id`, `run_id`,
event type) **are pushed down into the authenticated index** rather than executed by a scan
on top. Then:

- if all the predicates of the query land on provable dimensions, the answer carries a **completeness proof**;
- if even one does not, the answer is marked `proof: partial` with a list of what
  is proven and what is not.

So SQL does not become a gap in the proof model: it either proves, or honestly says that it does not.

### 3.2a. Two runtimes, physically separated

The core lives in its own thread-per-core reactor (§1b). DataFusion and pgwire pull in
**tokio**, with its own thread pool and its own scheduling. Mixing them in one
task address space would mean losing the determinism of the core, that is, DST.

The separation is strict:

- the facade (tokio) runs **on dedicated threads**, not on the shard cores;
- the facade reads **only projections and snapshots** and never reaches into the live journal;
- communication with the core goes **only through channels**, by requests and responses;
- the **build test without DataFusion** is part of CI: if the core does not build and does not
  pass its tests without the facade, the facade has crept into the foundation.

### 3.3. Dialect extensions

On top of standard Postgres-compatible SQL:

```sql
-- bitemporality
SELECT * FROM records AS OF TIMESTAMP '2026-03-01T00:00:00Z' WHERE agent_id = '...';

-- proof together with the answer
SELECT * FROM records WHERE run_id = '4471' WITH PROOF;

-- reconstruction of the causal closure
SELECT * FROM causal_closure('4471');

-- raw truth, bypassing projections
SELECT * FROM journal WHERE seq BETWEEN 1000 AND 2000;
```

### 3.4. Foreign databases as tables

`TableProvider` works in both directions: we attach external sources as tables
and join them with our records without copying them into our storage.

Target set: **Postgres, ClickHouse, BigQuery, Snowflake, Parquet on object
storage, Iceberg, Delta Lake**. This covers interoperability with different databases and connectors
without separate ETL machinery.

---

## 4. Input: Sources

| Category | Implementations |
|---|---|
| Telemetry standard | **OTLP gRPC + HTTP**, OTel Collector (as an exporter on our side) |
| Collection agents | Fluent Bit, Vector, Logstash |
| Queues and buses | Kafka, Redpanda, NATS, AWS Kinesis, GCP Pub/Sub, Azure Event Hubs |
| Cloud audit | **AWS CloudTrail**, **GCP Cloud Audit Logs**, **Azure Activity Log**, Kubernetes audit |
| Object storage | S3 / GCS / Azure Blob (picking up files that have arrived) |
| Direct | REST webhook, NDJSON files, gRPC, syslog |
| SDK | Rust, Go, Python, TypeScript, Java |

**Trust rule for each source.** A Source declares whether its
time and identity can be trusted. Records from an untrusted source keep `occurred_at`
with the `untrusted` mark, while `recorded_at` is always ours. A divergence above the threshold
becomes a separate event, not a silent correction.

---

## 5. Output: Sinks and export

| Destination | Implementations |
|---|---|
| Metrics | **Prometheus `/metrics`**, `remote_write` to VictoriaMetrics / Mimir / Thanos |
| Telemetry | OTLP export (traces and logs back into a foreign stack) |
| Analytics | Parquet to object storage, **Iceberg** and **Delta Lake** tables |
| SIEM | Splunk HEC, Elastic, Microsoft Sentinel, Google SecOps |
| Proofs | evidence pack (JSON + signatures), offline verifier |
| Notifications | webhook, PagerDuty, Slack, e-mail (through a foreign channel, not our own) |

@decided 2026-07-29: foreign telemetry is handed over to the operator's own stack, and this section implements that directly:
we **do not try to be a monitoring system**; we hand metrics over to the place
where the operator is already looking.

---

## 6. Storage and multi-cloud

### 6.1. Tiers

```
hot:  local NVMe, journal + fresh segments + index
warm: local disk, segments within the window of active queries
cold: object storage, segments + manifests + projections
```

### 6.2. Atomic segment publication without an external coordinator

Lesson from VictoriaMetrics: **no etcd, no Consul, no separate locking service**.
Publication atomicity is achieved by the storage's own conditional write:

- S3: `If-None-Match` (conditional write);
- GCS: `ifGenerationMatch`;
- Azure Blob: ETag preconditions;
- local filesystem: `rename` within a single volume.

A segment is considered published if and only if its manifest has appeared
atomically. Double publication is impossible, no coordinator is needed.

### 6.3. WORM as an additional line of defense

Where a regulator wants it, immutability is enabled at the storage level:
**S3 Object Lock**, retention policy in GCS, immutable blobs in Azure. This is not a replacement
for our proofs but a second, independent line of defense: even an administrator with rights
will not be able to overwrite a segment.

---

## 7. Federation: working across clouds

The scenario to cover: agents run in AWS, GCP and on-prem, while people ask a single
question: "show everything this agent did in March, everywhere".

### 7.1. Model

Each environment has its **own Trailryx node**, which owns its data.
A query fans out to the peers, and each one answers with its own slice.

### 7.2. Proofs compose

This is the key and non-obvious point:

- each peer returns its slice **together with its own completeness proof**;
- a federated answer is complete if and only if **the list of peers itself
  is attested** (a signed peer registry with a version);
- otherwise the answer is marked `proof: partial (peer set unattested)`.

Without this, federation silently destroys provability: it is enough to "forget" one node.

**This is the same code as between shards.** The recursion from §1b (record → segment → shard →
store → federation) means that the composition of shard proofs and the composition of peer
proofs are one construction at two levels. It is implemented once at Stage 4,
and federation at Stage 12 only adds the transport and the peer registry.

### 7.3. Computation goes to the data

Filtering and aggregation run **on the peer's side**, and the result travels back.
The reason is not only performance: **cross-cloud egress is real money**,
and an architecture that pulls raw data across a cloud boundary makes the bill unpredictable.

### 7.4. Three modes

| Mode | What it does |
|---|---|
| Federated read | fan-out query, merging of results and proofs |
| Verified replication | asynchronous replication; the receiver **verifies the chain** before accepting |
| Evidence aggregation | a single evidence pack assembled from several environments |

---

## 8. Identity and access

- **OIDC** for people, **SPIFFE/SVID** for machines (maps onto `agent://` with Agent Passport),
  **cloud IAM** natively: IRSA in EKS, Workload Identity in GKE, Managed Identity in Azure,
  **mTLS** for peer-to-peer.
- RBAC by tenant, agent and data class; access to payloads is separate from access to metadata.
- **Reading proofs is itself recorded.** Who looked at the audit and when is also a record.
  An audit that does not audit its own readers is incomplete.

---

## 9. Deployment forms

| Form | For whom |
|---|---|
| A single static binary | locally, on-prem, demo |
| Docker | standard |
| Kubernetes: Helm + operator | production, multi-cloud |
| Embedded library | tests, edge, embedded scenarios |
| Sidecar | when the agent cannot speak OTLP |

---

## 10. Keys and KMS

`KeyProvider` abstracts everything that erasure depends on:

local file (dev) · **AWS KMS** · **GCP KMS** · **Azure Key Vault** ·
**HashiCorp Vault** · **PKCS#11 / HSM**

Crypto-erasure with an external KMS means destroying the key material **there**,
with the result written to our journal. That is, the proof of erasure does not depend on
whether we trust our own code.

---

## 11. What it costs

Honestly: the scope grows roughly twofold compared with a narrow pilot. The discipline that
keeps it from sprawling:

1. **L1 contracts are fixed in phase 1**, before any adapter. We do not break them later.
2. **One reference implementation per category in v1**: one cloud (AWS),
   one bus (Kafka), one SIEM (Splunk), one KMS (AWS KMS), one foreign
   TableProvider (Postgres). The rest come later, and they no longer require core changes.
3. **A conformance suite for adapters** is written together with the contracts, not after.
4. The L0 core is **frozen** after Stage 5 of the roadmap. Changes require a separate decision.

---

## 12. Order of work

**The single source of order is [`trailryx-roadmap.md`](trailryx-roadmap.md)**: stages 0-13,
grouped into three milestones. There is deliberately no phase table here, so that the three documents do not diverge
into three different numberings.

Two ordering rules that follow directly from the architecture:

- **Stage 0 is not reordered.** The DST scaffold and the shard boundaries are put in place before the first
  line of the journal: injected interfaces and the sharding model cannot be bolted
  onto a finished core.
- **The L0 core is frozen** after Stage 5 of the roadmap (our read surface).
  Changes to it after that require a separate decision and a migration.

---

## 13. What remains to be decided

| # | Question | Leaning |
|---|---|---|
| A1 | Projection format: Parquet directly or Iceberg right away? | Parquet in v1, Iceberg through an adapter: a table abstraction is needed only when there is more data than one node holds |
| A2 | Federation transport: gRPC or HTTP/2 + protobuf? | gRPC, because result streaming and mutual mTLS are needed |
| A3 | Should a record be exposed back through OTLP without loss? | No, and say so plainly: our record is richer than a span, so the reverse mapping is lossy |
| A4 | Multi-tenancy: separate journals or one journal with a prefix? | A separate journal per tenant: a completeness proof over a shared journal leaks across tenants |
| A5 | Should writes through SQL (`INSERT`) be allowed? | No. Writes only through `Source`, otherwise the journal stops being the single source of truth |

---

## 14. State of the outside world as of 2026-07-29

Recorded as of the date the decisions were made. Re-read before each phase.

### 14.1. DataFusion: healthy, and gives more than expected

**54.0.0 of 12 June 2026** (53.0.0 in April). Pace: ~740 commits and 139 contributors
per release, so the project is alive, not mothballed.

Two new features directly useful to us:

- **content-defined chunking in the Parquet writer**: page boundaries are aligned to the data,
  not to a fixed number of rows. This improves deduplication and **incremental
  storage**, which directly makes our cold tier in object storage cheaper.
- **`cosine_distance` and `inner_product` as scalar functions**: vector similarity
  is available directly in SQL. When we get to the vector path (after the pilot), a separate
  engine may not be needed at all.

Plus memory-limited joins with spill to disk: large queries do not kill the node.

### 14.2. Post-quantum crypto in Rust: not as even as it seemed

This is a finding that **changes §7.4 of the plan**.

| Algorithm | aws-lc-rs (FIPS-validated AWS-LC) | RustCrypto (pure Rust) |
|---|---|---|
| ML-KEM (FIPS 203) | **available, in FIPS 140-3 validation** | available (`ml-kem`) |
| ML-DSA (FIPS 204) | available, but **behind an unstable flag**, the PQ part awaiting FIPS review | available (`ml-dsa`) |
| SLH-DSA (FIPS 205) | **not available** | available (`slh-dsa`), unaudited |

**An audited Rust library that covers all three does not exist today.**

Consequences for the design:

1. A `CryptoProvider` trait is introduced, and **each algorithm is isolated separately**.
   This is not abstraction for abstraction's sake: the providers here objectively differ in maturity
   and will change at different times.
2. **We take ML-KEM from aws-lc-rs** (the only path with FIPS 140-3 validation, and that
   is what sells to a compliance buyer).
3. **We take ML-DSA from aws-lc-rs behind the unstable flag**, with a fallback to RustCrypto,
   and record in the documentation that this branch has not yet passed review.
4. **SLH-DSA for epoch anchoring is moved beyond v1.** The reason is not laziness:
   putting the most durable line of provability on an unaudited library means
   promising a reliability that does not exist. The manifest format is prepared for it right away,
   and it is enabled when a validated implementation appears.

### 14.3. EU AI Act: the obligations exist, the standard does not, and this is our market

State as of June 2026: **no JTC 21 document has yet been cited in the Official Journal**,
that is, **none gives a presumption of conformity**. Harmonised standards for
high-risk systems are expected in H2 2026 / H1 2027. The furthest advanced is
**EN 18286** (quality management systems), and it will be cited first.

Our profile document is **prEN ISO/IEC 24970, "AI system logging"**: specifications
for logging events during the operation of an AI system for traceability and post-market monitoring.

What follows from this:

- the Art. 12 obligations were due to enter into force on 2 August 2026, and the Digital Omnibus on AI
  moved them to **2 December 2027** for standalone systems under Annex III (and to 2 August
  2028 for AI inside products under Annex I). There is still no technical standard that says "do it
  this way", so the window has not gone away but has shifted together with the date;
- we make the mapping to prEN ISO/IEC 24970 **a separate versioned layer**, not baked
  into the core: the document will still change;
- in materials we **do not write "complies with the standard"** until the standard is cited.
  Wording: "covers the requirements of Art. 12 and is ready for mapping to prEN ISO/IEC 24970".

### 14.4. MCP: the specification changed yesterday

**Version 2026-07-28**, released on 28 July 2026, the biggest changes since authorization appeared:

- the core becomes **stateless request/response** instead of bidirectional stateful;
- routing by the `Mcp-Method` header, so the server lives behind an ordinary
  round-robin balancer;
- **`tools/list` is cached** by the client for `ttlMs`;
- Tasks moved into the extension `io.modelcontextprotocol/tasks` with `tasks/get` polling;
- **Roots, Sampling and Logging are deprecated** (they will keep working for at least a year);
- Dynamic Client Registration is deprecated in favour of CIMD;
- the deprecated HTTP+SSE transport is being phased out over the course of a year.

Consequences: we build our MCP surface **directly for 2026-07-28**, stateless. This is even
convenient for us: our calls are read-only and idempotent, and a cached `tools/list` and horizontal
scaling behind a balancer fit naturally. We design in no stateful sessions
at all.
