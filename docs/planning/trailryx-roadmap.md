# Trailryx: order of work

> What we build in which order, and why in exactly this order.
> Companion documents: [`trailryx-plan.md`](trailryx-plan.md) (what and why),
> [`trailryx-architecture.md`](trailryx-architecture.md) (how).
>
> Date: 2026-07-29. Language: Rust.

---

## State as of 2026-07-29

Stages **0-5 done**, stages 6-9 partly done, **demo criterion met**,
the core **frozen**. 450 tests, 29,598 lines, sixteen crates, zero
dependencies.

| Stage | State | What appeared |
|---|---|---|
| 0. DST and shard skeleton | done | traits, simulator, crash model, replay by seed |
| 1. Canon and contracts | done | record, schema, plane boundary, eight contracts, conformance |
| 2. Journal | done | codec, framing, write path, recovery, durability contract |
| 3. Index | done | RFC 6962, completeness proof, segment → shard → store composition |
| 4-5. Read surface | done | queries with pushdown, `as_of`, reconstruction, provability flag |
| 6. Ingestion | partial | protobuf reader, OTLP parsing, mapper, **OTLP/HTTP transport**, **OTLP/JSON file reader**; gRPC and authentication remain |
| 7. Crypto and erasure | partial | envelopes, key hierarchy, erasure without deletion; primitives are behind a seam |
| 8. Proofs outward | partial | evidence pack, offline verifier, P-384 signature and witnesses; TSA and mapping remain |
| 9. Projections | partial | own Thrift + Parquet, checked with pyarrow; lists and storage tiers remain |

Between stages 3 and 4 an **adversarial architecture review** took place, which found six
critical gaps in the proof system. All are closed, each with a regression test
from the attacker's side. The common root is stated as a rule:
**the verifier must never learn the shape of the answer from the answer itself.**

### What exactly was done in stage 6 (2026-07-29)

Done: own protobuf reader with a nesting limit, parsing of
`ExportTraceServiceRequest`, the OTel GenAI semconv mapper, a `Source` adapter with
loss counters. A foreign agent with stock instrumentation writes to us without
any change in it.

The mapper rule: **an attribute lands in a typed metadata field only if it
parses into it, the rest goes to the payload plane.** The consequence is stated as an
invariant and checked by a test: every attribute lands in exactly one plane.
Nothing is "fixed up": a model name that does not fit into `ModelId` leaves the field
empty rather than being lowercased.

What OTLP cannot provide and what therefore stays empty: `policy_version`,
`budget_remaining_micros`, `memory_ref`, `identity_chain`, `parent_run_id`.
That is not a mapper defect, it is the difference between telemetry and proof.

**Not done at that point**: the HTTP/gRPC transport and the NDJSON source. The first was
closed the same day (`trailryx-ingest`), the second on 2026-07-30 (`trailryx-json` plus
`otlpjson` and `jsonl`). What remains is gRPC and authentication.

Two real bugs were found by the tests themselves while being written: the clippy hint
`then_some` evaluates the value before checking the condition, so the guard against negative
duration did not guard (panic on overflow); and an `error.type` of the form
`RateLimitError` did not match, because matching went by underscores, not by letters.

### Stage 7: the mechanics exist, the primitives do not (2026-07-29)

Done: the payload envelope format bound to the record, the key hierarchy, the
"subject → keys" registry, erasure, the erasure manifest, the erasure record.
The main property is checked by a test, not declared: seal, prove,
erase, prove again - the same root, the same proof.

**A mistake was found in the plan itself.** The plan said: while the subject is unknown,
wrap the DEK under the tenant key, and after attribution re-wrap it under the subject key
and **destroy the old wrapped key**. That does not work. The old wrapped key sits in
replicated, backed-up, often WORM storage, and "destroy the old wrapped key"
means deleting an object, which is exactly what crypto-erasure exists to
avoid. If it stays, the tenant key still opens it.

So attribution here re-wraps nothing: an unattributed payload gets its
**own key that belongs to nobody**, and attribution only adds that key to the
subject's set. The price is more keys. The gain is erasure that survives a
restored backup. An `ObjectStore` without a delete method turned out not to be a gap
in the contract but exactly the right shape.

One more decision of the same kind: the erasure manifest does not list the ids of destroyed keys.
Otherwise anyone with access to the metadata would intersect the manifest with the records and
learn exactly which records belonged to the person who asked to be forgotten. Each manifest
entry is a hash of a pair (subject key, destroyed key): it is checked by whoever
has the pseudonym, and tells everyone else nothing.

**Not done**: a validated cipher behind the seam (a stub stands in, which answers
`is_validated()` with `false`, and the constructor refuses it), a key provider
on a real KMS. The hostile tests pass through all the paths that already exist;
caches, projections, exports and backups add their own attempt as they arrive.

### Stage 8: debt closed (2026-07-29)

`trailryx-verify` is a separate crate **with no dependencies at all**, including the rest of
Trailryx, ~1500 lines with tests, with its own SHA-384. A shared hash would mean
that a bug in it gives a false root and a verifier that cheerfully agrees.

The pack carries the record bytes as the journal wrote them, and the segment manifests.
Nothing more: no chain links, no index keys, no extracted fields. What the
pack **claims**, the pack can lie about; so everything else is **derived**.
The verifier recomputes the chain from the bytes of each record, the history tree from those
links, each index with its own sort, the roots of manifests, shards and the store.

**This closes one of the two recorded debts.** Inside the store the index is
sorted because the code that built it sorted it. Now other code, which
shares nothing with it, sorts the same records and must arrive at the same
root. A completeness proof over an unsorted index means nothing, and until now
nobody from outside had checked this.

There are two things the verifier refuses to do. It **never** drops support for an
algorithm, it only marks it weak: on the day SHA-384 is withdrawn from use, every
pack issued before that must still verify, because a proof with an expiry date is
not a proof. And it **never** writes "all good" on an unsigned pack: a pack
proves its own internal consistency, and whether this is the genuine history is established by
the signature and the external anchor.

Checked end to end: the binary read a 2790-byte file and said
VERIFIED; after changing **one letter** in one agent_id eight checks
failed and it said NOT VERIFIED with exit code 1.

**Not done**: a signature over the store root (so every pack is currently
"unsigned"), RFC 3161 TSA, mapping to Art. 12 of the AI Act / SR 11-7 / SOC 2,
reproducible builds.

### Stage 9: Parquet by hand, verified by others (2026-07-29)

Writing an exchange format by hand is a bad deal if the result is merely
"similar to Parquet". So correctness is not proved here but delegated: a test
writes a file, and **pyarrow** reads back every cell. Result:
`pyarrow read 3 rows, 42 columns, 126 cells, all matching`.

The limits are deliberate: PLAIN, no compression, one row group, data page v1. The rest
of the format is compression and speed, and stage 9 is not about that.

**Two rules define what a projection is.**

First: **it is never a proof.** The Parquet file here is derived: delete it, and it
will be rebuilt from the journal byte for byte. `Projection::provable()` returns `false`
by method, not by a paragraph, because the temptation is real: a projection is fast, SQL wants it, and its
rows look exactly like records. Each row carries `chain_link`, and that is what
makes it useful without making it authoritative: a row is traceable back to the
journal, and the proof is given by the segment.

Second: **it contains neither a payload nor free text.** A projection lands in
object storage, is copied into the lake, replicated, backed up: exactly the
surface that destroying a key does not reach. So every column is a typed field,
a validated token, an enum name or a hash, and a test walks every cell to
make sure that no value can be a sentence.

Times are in nanoseconds, columns are named `_nanos`: no converted type in Parquet
carries nanosecond precision, and an export that rounds time on the way out is not the
"lossless" export that the roadmap asked for.

**Not done**: repeated columns (lists are joined with a comma, which is safe because no
identifier character set contains a comma), storage tiers
hot/warm/cold.

### Adversarial review of the transport (2026-07-30)

The review that twice fell over on a 529 took place: **six lenses, 96 agents, 11
million tokens**, every finding handed to three skeptics with orders to
refute it. 12 survived, and they reduce to **eight distinct defects**. My
own single-pair-of-eyes review found four things back then, and none of them was one of these.

**The worst: the body budget counted the compressed length.** A gzip request reserved what it
declared, then inflated to 16 MiB and held that while waiting for the lock. 256
connections of 15 KiB could hold 4 GiB against a 64-megabyte limit that had counted
4 MB. Now a compressed request is counted at the worst case it can
inflate to, and the default of the limit says it directly: divide it by `max_body` and you get
the number of simultaneous gzip requests.

**Second: the ratio limit could never fire.** It opened after
32 KiB of **consumed input**, while a 16-megabyte bomb is 16 KiB of input. Measured: 16
MiB of zeros compress to 16,328 bytes and returned `Ok` at a ratio of 1027.
The absolute output limit still held, so nothing was unbounded, but a check
whose only purpose is to make the attacker's costs proportional was decoration with
a comment saying otherwise, and that is worse than no check. Now the gate opens
on the **produced output**, and a test checks this with the settings the server
actually ships, not with ones picked so that it passes.

The other six: spans that the decoder dropped on its own limits were reported to the client
as complete success, because `submit` read two counters while there are three; an idle
keep-alive connection received an unsolicited 408 for a request that had not started, and the
client's real request was then eaten by the drain (408 is not retryable, and the default
read_timeout is 5 seconds, which is also the default batch delay in the OTel exporter, so
this was the most ordinary case of all); the full-queue check happened in a different
lock acquisition than the insertion; an under-subscribed Huffman code was accepted, so a stream
that every zlib decoder rejects produced a body that we handed to the store; the gzip trailer
was read from the last 8 bytes regardless of what came before them, so a legal
multi-member stream was rejected as corruption, and bytes hidden before the
trailer were ignored; and fixed Huffman tables were built for every block,
so 16 MiB of empty blocks burned 21 seconds under silent limits.

All eight are fixed, each with a regression test. The fix for the under-subscribed
code at first broke the **whole** corpus: the fixed distance code from the
specification itself is defined over 30 symbols with five-bit codes, that is, under-subscribed
by arithmetic and legal by definition. That is how the code learned to tell it apart from an
under-subscribed code read off the wire.

### Two debts closed without opening the schema (2026-07-30)

I had described both myself as "running into the frozen record schema". That was my
**reading, not a fact**, and checking overturned the belief: neither of them needed the schema.

**The durability mark.** `acked` lived only in memory, so a new process started from
zero, `recovered < promised` could never become true, and a journal that came back three
records shorter than what the previous process had acknowledged reported nothing. Now it is
twelve bytes in a file next to the journal. The segment header cannot hold them, because
it is hashed into genesis and written once, so a separate file, and the **record format did not
change by a single byte**.

The order here is the whole point: first fsync the journal, then the mark. A crash between them leaves
the mark **behind** the journal, so it promises less than there is, and that is safe. The reverse
order would promise records that the journal does not have, and that is exactly the lie the whole
file exists against. A torn mark promises nothing rather than a plausible number: the CRC
is responsible for that, and a test checks four ways of corrupting it.

**The lost causal edge.** `reconstruct` could only lower the proof for an edge that is
**present** and does not resolve; an edge that was never created yielded no
hop at all, so the closure stayed `Full` and reported itself complete, which is indistinguishable from
a run that really had no parent.

A counter could not change this, because there is no counter in the store. **A record exists.** The assembler
writes a `StoreEvent` with the **own** `run_id` of the run that lost the edge, and since
`run_id` is one of the five proof dimensions, the very same query that reconstruction already
makes finds it: no new field, no new index, no format version. So
the downgrade is now backed by a chained and fixed record, not by a number in memory,
and that is strictly better than the field I was going to add.

`EventType::StoreEvent` is documented as "gap, re-sign, recovery", and the downgrade is
recognised by `Verdict::Failed` and **not** by the kind of loss: reconstruction does not need to know
whether an edge, a span or a batch vanished, only that something vanished. A general anomaly record lives in
its own synthetic `run_id`, so it does not collide.

The map of runs that lost an edge is bounded by the same window as correlation, for the same
reason: the receiver runs for months. But the **grand total is not bounded**, because dropping a
counter is not the same as dropping a fact.

### Stages 11 and 12 closed, 13 started (2026-07-31)

**Stage 11 closed.** Atomic publication works in three clouds: S3, GCS (the same
adapter, four other names) and Azure (a separate Shared Key signature). Plus a cold tier and
tiering with a policy and reading through it, where a segment read from cold is
**re-sealed** and its manifest is checked against the published one.

**Stage 12 closed in the part that is the rule**, which is the criterion: a federation answer is complete
if and only if the set of peers is attested, every peer answered, and every
answer was itself complete. A forgotten peer breaks the proof. The transport (gRPC with mTLS per
decision A2) remains.

**Stage 13 started:** fuzzing of all parsers in the gates, a real kill run
(40 kills, apfs, zero lost acknowledged records) and `VALIDATION.md`, where every
number has a command and a date, and a separate section names what is **not yet measured**:
ext4/xfs, two I/O backends, a live bucket, years of simulated time, an external
audit of the crypto.

### Segment publication: a success that nobody learned about (2026-07-30)

This is the third item of the stage 11 criterion: "a simulator with conditional-write errors does not
create divergence". Now it is a test, not an intention.

**The protocol is two writes.** The segment body under a key that contains its own digest,
then the manifest by conditional write. The manifest is the commit point: a segment is published if
and only if the manifest exists. A body without a manifest is invisible, and a lifecycle
rule cleans it up; a manifest without a body would be a commitment to bytes that nobody can read. The order
is not a matter of taste. Thanos writes `meta.json` last, Iceberg swaps the pointer to the metadata, Delta
writes a single entry in the log: all three converged on this, because it is what an object store
can promise at all.

**The failure that shapes the code is the lost acknowledgement.** The write reached the store,
the response did not reach the client. The client retries, and the conditional write refuses it against
an object that was written not by someone else but by itself. A publisher that reads this as "I was
beaten to it" will report a conflict with itself, and if it also publishes under a different name,
it will cut one segment into two.

**The idempotency token is the manifest itself.** Kafka has a producer id, Stripe an idempotency
key, Delta transaction identifiers. Here the manifest is a deterministic function of what is
sealed, so on a refusal we **read the stored manifest and compare the bytes**: the same
bytes mean the segment is published (by us or by a peer that sealed the same
records), different bytes mean two parties sealed DIFFERENT records under one segment
number. The second is reported loudly and is never "resolved" silently.

**A consequence that broke my test and is worth recording:** with a lost acknowledgement a segment
can be published in such a way that NO publisher hears `Committed`. Both correctly
get "already published", the manifest is in place. My test demanded that somebody report
`Committed`, and failed on seed 17. The test was wrong, and about exactly the behaviour for
which the protocol exists.

**The fault model** in the same form as `IoFaults` and `BusFaults`: `unavailable_ppm`,
`lost_ack_ppm`, `read_error_ppm`, everything through a seeded RNG, so a failure is a seed that can be
rerun. 200 seeds per property: a single publisher converges; two that
agree both succeed; of two that disagree, exactly one publishes.

**Mutations against my own code, useful again.** Four: do not compare the read manifest,
do not write the body, remove the digest from the body key, retry `Unsupported`. Three caught,
**the fourth not**: no test covered `Unsupported`, meaning a store without conditional write
would burn the whole attempt budget before saying the one useful thing. A test added with
a call count: exactly one, not one per attempt.

### S3: the dangerous store is the one that says "yes" (2026-07-30)

A segment is published atomically by a conditional write, and this is exactly what removes the coordinator: no
etcd, no Consul, no lock service. In S3 this is `If-None-Match: *`.

**Three facts from the AWS documentation, each as a separate test:** `412` is a lost race, not a
failure (two nodes seal the same segment, and the one that lost reads someone else's
bytes); `409 Conflict` happens when a deletion slips in between the check and the write, and AWS
says PutObject can simply be retried; and in a versioned bucket a conditional write
**succeeds if the current version is a delete marker**, meaning an administrator who deleted
the segment opens its name again. The last one is the reason why a published object is
read **by version**, not by key.

**The worst failure is quieter than all three.** Not every S3-compatible store implements a conditional
write, and one that ignores the header answers `200` and **overwrites**. The response
has no field that would distinguish this from an honest first write. Two nodes would
have published different bytes under one name, and any proof on that segment would
depend on which copy you read.

**Precedent:** `object_store` in Rust has `S3ConditionalPut` as a **declared property of the
backend**, not an assumption, precisely because backends differ. I copy this through `Conditional`
and add a step that a configuration setting cannot provide: `verify_conditional_writes`
**measures** the endpoint by writing the same key twice and requiring the second write to be
refused. A health check that changes nothing cannot detect this class of store, so
this one deliberately writes one small object.

**The HTTP client is moved into a separate crate `trailryx-http`**, because the TSP client could only do
POST, one path and 200. Now it really is ONE per workspace, and the strictness of TSP stayed
in the anchor. The client **decodes chunked**, and this is not politeness: S3 answers
`ListObjectsV2` precisely as chunked without `Content-Length`, so a client that cannot do chunked
cannot list a bucket at all.

**Mutation check of my own tests.** All 28 tests passed on the first run, and this is
exactly the case where one must check whether they bite. Eight mutations against
my own code: do not send the condition, lowercase hex in UriEncode, do not sort the query, stop
listing after the first page, report a lost race as a write, drop the prefix
`AWS4`, break the `&amp;` decoding, forget CRLF in chunked. Seven were caught. **The eighth, the removed
query sorting, was not caught**, because my test fed the pairs already in the right order,
so it was a comment, not a test. Rewritten to an input that matches neither the
response nor the pre-encoding order (the key `{` is encoded to `%7B`, and `%` sorts
below all unreserved characters), and now it catches both mutations: both the missing sorting and
sorting BEFORE encoding.

**Not yet done:** TLS (the same seam as in ingestion and pgwire: the terminator is provided by the
deployment), multipart for large segments, hot/cold tiering, GCS and Azure.

### SigV4 by hand, verified against the AWS CLI (2026-07-30)

@decided 2026-07-30: one HTTP client plus SigV4 for the cloud calls, not three cloud SDKs. The reasoning holds:
**the S3 API is HTTP plus a signature**, and the HTTP client was already in the workspace (written for RFC 3161),
and both hash functions too. `aws-sdk-s3` would pull in a runtime, an HTTP stack, a TLS stack and a few
hundred crates to say the same thing. `trailryx-s3` has **zero third-party dependencies**, like
everything outside the SQL facade.

**But this is justified only if the signature is right.** A signature verified against itself is
a signature that in production gets `SignatureDoesNotMatch` with no hint of which stage
diverged. So verification is delegated to the **AWS CLI**: the tests run it, extract the canonical request,
string-to-sign and signature from the debug log, and require a **byte-for-byte match** on
the same inputs. Plus, a separate test covers the example documented by AWS itself
(`AKIDEXAMPLE`, IAM ListUsers, signature `5d672d79...`).

**Three rules that bite, each with its own test:**

- **`UriEncode` is not the platform's.** AWS itself says so in the documentation. Hex in upper
  case, a space is `%20` and never `+`, a slash is encoded in a query value and stays in the
  path.
- **The query string is sorted AFTER encoding**, not before. `a+` is encoded to `a%2B`, and `%`
  sorts before `b`: sorting first gives a different order.
- **The signing key starts with `"AWS4" + secret`**, not with the secret.

**HMAC-SHA256** is written with RFC 4231 vectors, including case 6, where the key is longer than the
block and must be **hashed, not truncated**, because truncation silently makes different keys equal.

**Two mistakes of mine in the tests, both worth recording.** The first: the test for RFC case 7 checked the
**length** of the digest instead of the value, so it would have passed for any implementation;
rewritten to the real vector. The second: the test "the secret is not printed" looked for the substring `tok` and
found it inside the **field name** `session_token`, so it failed while the code was right.

And one in the oracle: the log parser cut a block at the next line starting with `20`, and the
second line of the string-to-sign is exactly the timestamp. The block was cut off after the first line, and the
oracle reported a divergence that did not exist. **A broken oracle is worse than none**, so this is
in a comment too.

**Not yet done:** the S3 operations themselves on top of the signature (PUT with `If-None-Match`, GET by
versionId, LIST) and TLS. TLS here is the same seam as in ingestion and pgwire: it is provided by the deployment,
not by us, and the terminator sits in front of the routed bind.

### WORM protects the version, not the key (2026-07-30)

Stage 11 started from the same principle: look at how it actually works in those where
it works. The strongest claim in §6.3 reads: "even an administrator with
privileges cannot overwrite a segment". I checked it against the S3 Object Lock documentation, and
it is true **in one mode of two and only if the reader asks for the version**.

The documentation says it directly: retention and legal hold "**don't prevent new versions of the
object from being created**, or delete markers to be added on top of the object".

That is:

- **Object Lock protects the version, not the key.** An actor with credentials can always put
  a new version on top, and any reader who asks for the key gets its bytes.
- **A plain `DELETE` returns `200 OK`**, puts a delete marker, and the object disappears from
  ordinary reads while the locked version lies beneath it, intact and unreachable for
  someone who does not know that it must be requested.
- **The two modes are not interchangeable.** In **governance**, a user with
  `s3:BypassGovernanceRetention` deletes the object, and the AWS console sends this header **by
  default**. Only **compliance** refuses everyone, including root, and there too:
  "the only way to delete before the retention period ends is to delete the account".

This is not nitpicking the documentation. It is the difference between Object Lock protecting something or
no one: the actor it exists against is exactly the one who has credentials.

**What changed in the contract.** `put_if_absent` returns **how the store named the object**, and
`get_version` reads exactly that, whatever is written on top. A store without versioning
returns `None` and **refuses** reads by version, so the deployment learns that it does not have this
guarantee instead of assuming it. "We enabled Object Lock" is a sentence that
ends up in a compliance document.

**The attack is run, not described.** `VersioningObjectStore` models the documented
behavior of S3, and the tests show: the conditional write refuses the second publisher, while an
administrator still puts a new version, an ordinary read returns the forgery, and the
published version is read by token. Plus eight forgeries and a delete marker on top do not
reach it.

The conformance suite now requires: a store that issued a version token must be **able to
honor it**. Issuing a token and being unable to read by it is worse than not issuing one at all.

**Not yet done in stage 11:** the S3/GCS/Azure adapters themselves (these are SDKs, meaning more dependencies,
and that is a separate decision), and the tiered hot and cold migration.

### `journal()`: looked at how Postgres solved it, and did the same (2026-07-30)

The question was real: §3.3 wants the raw truth bypassing projections, §3.2a says the facade never touches the live journal.
@decided 2026-07-30: look at how this works in systems where it already works, and only successful
examples are of interest.

**PostgreSQL ran into exactly this and shipped `pg_walinspect` in version 15**: expose the WAL
through SQL without letting the query executor onto the write path. Its four decisions
transfer here completely, so all four are copied, not derived anew:

| `pg_walinspect` | here | why |
|---|---|---|
| table function with a range | `journal(from_seq, to_seq)` | there is no `SELECT * FROM wal`, because a client that can ask for the whole log can ask the server to read all of it |
| error when the start is unavailable | error when the sequence is in no **sealed** segment | a silent empty response is indistinguishable from "this range is empty", and for forensics these are different things |
| lenient about the upper bound | the same | otherwise "everything from here on" becomes a moving target |
| **a different privilege** than ordinary SQL | `Action::ReadMetadata`, not `Action::Query` | reading around the proofs is a **stronger** permission than a query, despite how the names read |

**The fourth one I would have done wrong.** A session without a grant does not get the function
**registered at all**, meaning it does not have it, rather than getting a refusal when it reaches for it.
The catalog a session sees is what it may use.

Plus: `Action::ReadMetadata` and `Action::Query` now have doc comments that say that the
former is stronger than the latter. Without this the next reader of the vocabulary would decide the opposite.

And the `journal()` response **carries no proof and says so**, rather than reporting the strongest value
for a scan that deliberately bypassed what proves.

**One real gap was found by a test:** the proof of a table function's response went nowhere,
because `last_proof()` read only the main table. Now there is **one slot per session**, into
which any table that answered writes: the question of "how provable was the last
response" must not depend on which table answered.

**Stage 10 closed completely.**

### Dialect extensions, and a deliberate deviation from the syntax (2026-07-30)

§3.3 shows three extensions. **The third is parsed by the engine's parser, the first two are not**, and this is
verified, not assumed: `DFParser` rejects `AS OF TIMESTAMP` and the trailing `WITH PROOF`.
`sqlparser` has the form `FOR SYSTEM_TIME AS OF`, and the DataFusion dialect does not
enable it.

The illustrated syntax could be obtained exactly in two ways, and I rejected both
of them:

- **Fork or wrap the parser.** Then two parsers read one string and may
  diverge on where a clause ends, and this is exactly the class of defect that the `gate` was built to
  eliminate. Bringing it back in through one module would be inconsistent.
- **Preprocess the text.** Worse: a string literal containing `WITH PROOF` would be distorted,
  and the gate would examine a statement that is not what will be executed.

So all three are table functions that the engine's parser accepts as is:
`records_as_of('...')`, `causal_closure('4471')`, `trailryx_proof()`. **The capability is the
same, the spelling is different**, and this decision is worth recording, rather than a syntax that was quietly
not done. If the spelling ever outweighs the number of parsers, the path to it goes
through `sqlparser` upstream, not through a second reading of the string here.

**Two things where I did not let a weaker answer through:**

`records_as_of` is **transaction time**, meaning what the store **had managed to write** by that
moment, not what was true then. Valid-time travel would need a layer of
facts that supersede one another, and this store holds events. The name and the comment say
which of the two is on the table, because learning about the difference from an auditor is the worst moment.

`trailryx_proof()` before the first response says **"none", not "full"**. A session that has proven nothing
has no right to report the strongest value in place of an absent response.

An instant is accepted in two forms that cannot be read two ways: nanoseconds since the
epoch, or `YYYY-MM-DDTHH:MM:SSZ`. Local time without a zone is **refused** rather than
assumed to be UTC, for the same reason as in the verifier's label reader.

`causal_closure` returns the verdict of the reconstruction itself and does not derive it anew: a second
traversal could diverge from the first, and the first is the one the store's tests are about.

**Stage 10 closed**, except `journal` as a table of raw truth, which per §3.3 reads around the
projections, meaning per §3.2a the facade cannot go there at all.

### pgwire: a client connects, and two defaults had to be refused (2026-07-30)

The exit criterion of stage 10 reads: "Grafana connects the way it does to Postgres". Grafana
cannot be put into a test, so the substitute is `tokio-postgres`, the same driver and the same
protocol. It connects, authenticates, reads, and gets a refusal **on both
protocols**, simple and prepared statements.

**`datafusion_postgres::serve` is not used**, and both reasons are measured against the
library, not assumed:

1. **It authenticates nothing.** `HandlerFactory::new` installs
   `SimpleStartupHandler`, whose own comment says "does no authentication", and
   `AuthManager::new` creates the superuser `postgres` with an **empty password**,
   `can_login: true` and `Permission::All`. Whoever reached the port is in as
   a superuser.
2. **It passes arbitrary SQL**, meaning reading an arbitrary file.

This is not a reproach to the library: a universal adapter that made these decisions for you
would be worse. These are decisions that a store that serves an audit trail makes itself.

**So the startup handler is ours**, and it asks the deployment's `AuthProvider`, naming
**`Action::Query`** directly: the contract separates `ReadMetadata`, `ReadPayload` and `Query`, because
these are different permissions, and **permission to write records is not permission to read them** (there is a separate test on a
provider that allows only `Ingest`). Loopback by default, a routed
bind without a provider **does not start before the socket is opened**, and a poisoned mutex refuses
forever rather than failing open.

**The credential model is ours, and it is stronger than pgwire's.** pgwire's `AuthSource` asks the
server which password is **expected**, so the server must hold it. Our
`AuthProvider::authenticate` takes a credential and returns a principal, so the server does not
hold the secret and does not decide who this is. So `StartupHandler` is implemented directly, not through
their `AuthSource`. The user name the client sends is recorded and **trusted by
no one**: the principal comes from the provider, otherwise the client would choose who it is.

**Two things about writing this handler are worth passing on**, because the symptom of skipping
either is the same and says nothing: **every client sees "connection closed"**.
`protocol_negotiation` is needed, and
`set_state(PgWireConnectionState::AuthenticationInProgress)` is needed, without which pgwire does not
route password messages to the handler at all. I found out by skipping both.

**I did not write the Arrow-to-pg-rows conversion.** `DfSessionService` does it via `arrow-pg`,
and 42 columns with four lists is a lot of encoding to get subtly
wrong, and their version has been run by more clients than ours would be. Ours
here is **what is allowed to run**, and that is where we need to be right.

**The gate is installed as a hook on all three phases**, including parse: otherwise a client would prepare a
statement now and execute it later, bypassing a gate that looked only at execution. And
`Session` itself builds the pg service with the gate inside, and never hands out the context, so
forgetting the gate is impossible.

Dependencies are now **297** transitive (were 243). 895 tests.

**Left in stage 10:** `AS OF TIMESTAMP`, `WITH PROOF` and `causal_closure()` in the dialect itself.
The semantics of all three already exist in the core (`Query::as_of`, `ProofStatus`,
`causal.rs`), so this is dialect parsing work, not new guarantees.

### A Postgres port with arbitrary SQL is reading an arbitrary file (2026-07-30)

Before wiring up the network, I checked one thing, and it turned out to be the most important of
all the wiring. A plain DataFusion `SessionContext` accepts this, plans it, executes it and
returns the file:

```sql
CREATE EXTERNAL TABLE leak (a INT, b VARCHAR) STORED AS CSV LOCATION '/etc/passwd';
SELECT * FROM leak;
```

So a facade that passes arbitrary SQL into the session is a **read of an arbitrary local
file on the store's host**. And whoever wired it up following the architecture, without thinking
about statement kinds, would have shipped exactly this. For a store whose whole value is
that it is believed by someone who does not trust the operator, this is worse than anything on the write side:
ingestion can only add a record, while this carries everything else off the machine.

**Measured by execution, not by reasoning.** The test for this comes first in `gate.rs`.

**The gate decides on the parsed statement**, by the engine's own parser. Comparing
string prefixes is broken by a comment, whitespace, case and a semicolon. And two
parsers that diverge on where a statement ends are the same class of
defect as request smuggling, and using the engine's parser removes it. Two
statements in one request are **refused, not split**: a gate that checks the
first and executes the rest is the form of every SQL injection ever written.

This is an **allowlist**: queries, `EXPLAIN`, and the session chatter that every client
sends on connecting (`SET client_encoding`, `SHOW`, `BEGIN`). A denylist would be
a list that someone must keep complete while `sqlparser` grows, and the update would be
someone's memory.

**And the gate cannot be forgotten.** `Session` owns the context, **does not hand it out** and gates
before the engine is asked. A server author who reached for `SessionContext::sql`
would recreate the gap without any warning, so this door simply does not exist.

**Not done yet:** the pgwire server itself. `datafusion-postgres 0.18` has `QueryHook` and
`serve_with_hooks`, so the gate plugs in there, but a question remains that I will not
settle in a hurry: **read authentication**. The contract has `Action::Query`,
`ReadMetadata` and `ReadPayload`, and a port that serves the audit trail must
ask for them. The doctrine is the same as on ingestion: loopback by default, and a routed
bind without a provider does not start.

### `TableProvider`: SQL that either proves or says it cannot (2026-07-30)

§3.2 is implemented: a predicate on one of the five provable dimensions becomes a sorted
range dimension of the authenticated index, and the answer carries a completeness proof. The rest
is applied (that is, the rows are correct), but the answer is marked `partial`, **and
every predicate that was not pushed down is named**.

Nine tests through real DataFusion, and two of them found what would have been a silent
lie.

**First, and it is serious: the facade has no right to answer `Unsupported`.** DataFusion
does not pass an unsupported filter to `scan` at all, so the facade **does not learn that the
predicate existed**, finds nothing unproven and reports **a full proof for a
query it saw only in part**. `severity = 'error'` was returned marked as
fully provable until a test asked. Now everything we cannot prove exactly is
`Inexact`: the engine re-checks, which costs one extra comparison and buys
the ability to tell the truth.

**Second: two bounds on the same column are one range, not two competitors.**
DataFusion rewrites `BETWEEN` into `>= AND <=`, and reading the second bound as a competing
dimension made the most ordinary time query `partial`. And a `partial` that fires on
ordinary queries teaches the reader that partial does not mean anything specific, and that is worse
than having no proof.

**Third, smaller: the `INSERT` test checked the wrong property.** It required the
planner to refuse, but DataFusion plans happily and fails at **execution**, from the
trait's own default `insert_into`. Planning is not the boundary. The test now requires that
**no write completes**, and checks this on four statements plus the row count
afterwards.

**The key derivation stayed in one place.** The facade has to build an index key from an
SQL literal, and `event_code` was private in `trailryx-index`. Duplicating it would have been
a mistake of the class "a derivation written twice will diverge": a key that differs by a byte
gives a range that misses records the index holds, while the completeness proof will say that
the answer is whole. So `Dimension::key_from_text` and `key_from_i64` appeared in the index, and the
facade **encodes nothing itself**. The test next to the derivation requires that the key from a literal
equal the key from a record byte for byte.

**We take the chain link from the segment, we do not invent it.** `Answer` carries records and carries no links, and the
`chain_link` column is what makes a row verifiable. Record-link pairs are taken from
the segment itself and selected by `seq`, which is unique within a segment.

**One Arrow mistake worth recording:** `ListBuilder` by default makes the `item` field
nullable, while the schema declared `element` non-nullable, and Arrow compares types including
the element's name and nullability. Nine tests failed with one message. The field is now
derived from a single function, so the schema and the builder cannot diverge.

**What is not yet in stage 10:** pgwire (that is, connecting Grafana), `AS OF TIMESTAMP`,
`WITH PROOF` in the dialect itself, `causal_closure()`. The proof is for now read through
`RecordTable::last_proof()`, and this is a stub that says so about itself: a concurrent
second query will overwrite it.

### Dependencies taken, the boundary enforced by a check (2026-07-30)

@decided 2026-07-30: take the dependencies that are needed; the main thing is that the database works, has no bugs and does not
crash, while the absence of dependencies is a third or fourth concern.

**Measured cost, not estimated:**

| | before | after |
|---|---|---|
| third-party crates in the facade tree (2026-07-30) | 0 | **243** |
| clean facade build | - | **2:19** |
| gate on a warm cache | ~40 s | **1:28** |
| third-party crates in the verifier | 0 | **0** |

**What was done before writing the engine.** The old check "zero third-party deps
workspace-wide" stopped being true, and was replaced by **two**, each of which is worth
more than the single old one:

1. `zero deps outside the facade`: every crate except `trailryx-sql` has zero.
2. `core builds without the facade`: `cargo test --workspace --exclude trailryx-sql`.
   §3.2a asks for this test by name: if the core does not build and pass its tests without
   the facade, the facade has crept into the foundation.

The second check is not hygiene but a **correctness guard**. The core is a deterministic
automaton per shard, and this is exactly what DST lives on (§1a, named the most important section of the
architecture). DataFusion pulls in tokio with its own pool and its own scheduling; mixing them in a
single task space means losing determinism, and with it the way to find rare bugs.
@decided 2026-07-30: the boundary protects exactly what was named the main priority (a database that works, has no bugs and does not crash).

The comment in the hook ("from stage 10 it stops being trivial, because DataFusion and pgwire
arrive as a facade") anticipated this day and is now rewritten in the past tense.

**The claims were reworded, not left in place.** The `deps-0` badge became
`deps-0 in the core`; the comparison table against the leaders now says "zero third-party
dependencies **in the verifier**", because that is what remained true and what carried the
argument; in the README the number 243 stands openly next to "the verifier has zero", and in
SECURITY.md an item appeared saying that a vulnerability in a facade crate is a real report, but a
report **about the facade**, while a report that a facade dependency reaches the core is more serious.

**`pushdown.rs`: §3.2, and it knows nothing about DataFusion.** Classifying predicates is the
part that decides the provability of the answer, so it is tested without an async runtime, without a
session and without a planner, and will survive a change in the engine's API. Three places where a predicate can
run: a sorted dimension of the authenticated index (completeness proof), our own
filter (costs the proof), the engine above us (costs the proof, and we cannot even see what it
dropped). Every predicate not pushed down is **named** in the answer.

One decision worth its own mention: among several candidates **equality is chosen before a
range**, not the first one supplied. Otherwise the provability of the answer would depend on the
order in which someone typed the `WHERE`.

**Not done yet:** the `TableProvider` itself over DataFusion, pgwire, `AS OF TIMESTAMP`,
`WITH PROOF`, `causal_closure()`. That is, the boundary and the provable part are done, not the engine.

### Second verifier, and README drift against the architecture (2026-07-30)

@decided 2026-07-30: keep checking against the Fable architecture continuously and work within the system
design. The first thing this produced: **I found a drift, and it is mine**.

README said "the provable query language that **replaces** the SQL facade". In
the architecture and the plan there is **not a single instance** of such a phrase, and the opposite is said: §3.1,
SQL over the Postgres wire **is** the first-class interface, because it wins on compatibility, not
speed; §3.2, provability is given not by another language but by `supports_filters_pushdown`, which
pushes predicates on the provable dimensions **into the authenticated index**, and the answer either
carries a completeness proof or is marked `proof: partial` with a list of what did not fit.
I introduced this wording back in commit `fb9c448` and repeated it in this session's CONTRIBUTING.
Fixed to say what the architecture says, plus a line: the architecture takes priority over
any retelling, and a sentence that contradicts it is a defect in the sentence.

**Second: stage 10, per the architecture, cannot be done without third-party dependencies**, and I am not
making this decision myself. Details separately below.

**What was done from stage 10 with no dependency at all:** the item the plan asks for directly, R6.

`verifier-py/trailryx_verify.py`, standard library only, no code shared
with Rust. It recomputes on its own everything the format consists of: SHA-384, RFC 6962
roots with the correct split point, the chain step with a domain prefix, the segment
manifest root, the shard leaf, the index keys over the five provable dimensions.
`two_verifiers.rs` runs both on the same packs, good and forged, and requires
the same verdict and the same number of records checked.

**And it immediately paid for itself.** My Python sequence check compared each record
with the previous one, which is weaker than Rust in the direction that matters: a segment that lost its
**first** record, or whose numbers were all shifted by the same amount, would have passed.
The Rust verifier had already been hardened after the adversarial review, with the reasoning next to the
code ("contiguous from one, not merely increasing"), and the Python one had not. What found this was
the cross-check of the two, so the mechanism works as designed.

My second mistake from the same test: the fixture numbered records globally, while one segment
is one journal file and numbers from one. Rust refused correctly.

**What the second verifier does NOT prove**, and this is stated first in its README, not
last: it was written by reading the Rust, so the same oversight made twice it will not
catch; it does not verify signatures, because ECDSA over P-384 in pure Python is several hundred
lines of modular arithmetic with silent bugs, and the subject here is the format, not the curve. It is a
second opinion, not a replacement.

The gate has eleven checks.

### Open decision: DataFusion and pgwire

The rest of stage 10 (our `TableProvider`, physical isolation of the runtimes, pgwire, dialect
extensions) **requires third-party dependencies**, and the architecture plans this deliberately: §3.2a
says the facade lives on tokio in dedicated threads, reads only projections and snapshots,
talks to the core over channels, and that **the build test without DataFusion goes into CI**. The
pre-push hook already knows this, it says "from stage 10 it stops being trivial".

But this ends the property "zero third-party dependencies **workspace-wide**", which
stands on the badge, in the README, in SECURITY.md and in the argument "the auditor will read the
verifier". Per the architecture it is correctly reworded as "zero in the core, and the
optional SQL facade takes DataFusion and pgwire", and the gate check changes from
"zero in the workspace" to "zero in the core, and the core builds and passes tests without the
facade".

This does not cost money, but it is the project's largest architectural promise and its public
delivery surface. So I am not switching it myself.

### Key destruction is asynchronous, and "erased" silently meant "hidden" (2026-07-30)

Seam applied: §7.2 of the plan, the semantics of `forget`, "destroys the subject KEK, and with
it all DEKs become unrecoverable". I checked the blocker against my own note, and it turned
out not to be where I thought: a KMS provider **does not need a cipher**. It needs something else.

**The `KeyProvider` contract could not be fulfilled by any real KMS.** `Destroyed` had two
variants, `Now` and `Already`, and both meant "the key is gone". And the guarantee said: "after
`destroy`, `unwrap` for that key fails **forever**, and a key id is never reissued".

Checked against the providers' primary documentation on 30.07.2026:

- **AWS KMS** `ScheduleKeyDeletion`: a mandatory waiting period of **7-30 days**, 30 by default,
  and the actual date can be a day later still. During the window the key is in the state
  `Pending deletion` and performs no cryptographic operations. `CancelKeyDeletion` **brings it back**.
- **GCP Cloud KMS** `CryptoKeyVersions.destroy`: **30 days** by default, state
  `scheduled for destruction`, unusable, and `CryptoKeyVersions.restore` brings it back.

So in the window the payload is **unreadable and not erased**, and the difference is not academic: an operator
cancels it with one API call for up to a month. A store that reported this as
erasure would be telling the subject that their data is gone while it is one call away from
coming back. This is exactly "erased" silently meaning "hidden", which this whole project is against.

**What was done.** A third variant `Destroyed::Scheduled { effective_at, reversible }`,
and the guarantee rewritten to what holds universally: "fails **from that moment
on**". A weaker claim, but a true one, and the difference is not swept under the rug: a provider that only
schedules must say so, and from there it is **the caller's duty** not to report a completed
erasure. The vault does not do that:

- `Forgotten::is_complete()` returns false, and the question is asked in one place so that no
  call site answers it by looking at `keys_destroyed`;
- the record's verdict is **`Held`**, not `Allowed`. This word in the record's vocabulary already meant
  exactly that, so **nothing in the frozen format changed**. `Allowed` would have made an
  unfinished erasure indistinguishable from a finished one in the trail itself, that is, the trail
  would have lied about the one operation it exists to prove;
- `tokens_out` carries the count of only the promised ones, so the reader reaches the same conclusion without
  trusting the verdict;
- **the subject row is not dropped** while anything is merely scheduled. The same
  reasoning that was already extended once: the row is the only thing that will make the next attempt
  look again. A store that dropped it would have no way to find out whether the
  erasure it reported ever happened;
- the controller learns the **date** (the latest, because erasure completes with the last
  key, not the first) and **whether it can be cancelled**.

**The reference `SchedulingKeyProvider`**, because a seam without an implementation is a seam nobody has
run: it schedules, the key is unusable at once, the material remains, `elapse` closes the
window, `cancel` brings it back. The conformance suite now passes on it too, and it gained a
check that was not there: **a repeated `destroy` must not move the date**. The erasure job
is retried, and a custodian that restarted the clock on every retry would
be scheduling an erasure that never arrives.

**The test shows rather than argues:** it cancels the schedule and the payload **comes back**. That is
exactly the fact the controller would hide by reporting the window as erasure. Five of the nine
new tests fail if the store is made to treat a promise as fulfilment, and I
checked this rather than assumed it.

Two of my wrong expectations in the tests: I thought the subject KEK is destroyed, but what is
destroyed are the **per-record keys** registered to the subject at seal; the subject KEK
is only the basis for the tag.

### Real lists in Parquet (2026-07-30)

Obligation applied: §6.3 of the plan, "a proprietary format is a trust debt: the auditor
would have to trust our reader", which is closed by "a guaranteed lossless
export to Parquet + JSON, itself verifiable". And in the same place: "This is not a concession, it is a
selling point".

The four repeated fields (`tool_manifest`, `on_behalf_of`, `caused_by`,
`identity_chain`) were glued together with commas. That was **lossless**, because no identifier
grammar admits commas, and this was written down, not hidden. What it was not
was honest columnar output: pyarrow returned a string where the record has a list, so
anyone querying the export had to know to split. A column that cannot be
read without local knowledge carries exactly the trust debt the export was meant to close.

Now the canonical three-level form:
`required group NAME (LIST) { repeated group list { required element } }`. Both
outer levels are chosen by the shape of the record, not for convenience: the repeated field is a `Vec`
that is always present, and the elements are validated tokens that are never null. So
the maximum definition level is 1 and the maximum repetition level is 1, one
bit each, and the existing RLE encoder covers both.

**The danger the lists exist for** is the empty list: it writes a pair of levels and
**no value**. If this is done wrong, every following row shifts
by one, and the file reads cleanly but says something else. The test places empty lists at the
start, in the middle and at the end, two list columns in a row and a scalar next to them.

**I checked that the test really catches.** Two of the likeliest mistakes were introduced on purpose:
`num_values` equal to the row count instead of the level count, and an empty list with
the level at the maximum. pyarrow failed on both.

The oracle now requires not only a text match but the **type**: a column the writer calls a
list must arrive as a list, the elements must be non-nullable, and the list itself is
never null. Comparing a single rendering would have passed the same whether the reader returned a list or a
string, that is, would not have seen the very change.

As a side effect the semantics were fixed: previously an empty list had to be written as null, because
an empty string and a list of one empty string are the same text. A list
column does not need to make that choice, so a record with no tools now reads as a
record with no tools, not as a record that did not say.

What remains at stage 9 is the tiered storage migration, and it is really about object storage,
that is, stage 11.

### Reproducibility: a published seed corpus and a byte-for-byte build (2026-07-30)

The exit criterion of stage 8 said: "anyone reproduces our run and our binary
byte for byte". Seam applied: §1a.2 item 4 of the architecture, "the simulator is part of the
product, not a test folder, and the seed of every failure is replayed by one command".

**`sim/corpus.tsv`**, sixteen rows: the full parameter set, the trace digest and
how many acknowledged records the run lost. `--corpus` runs all of them and fails
if even one digest or counter diverged, printing one command to
replay that row. In the gate on every push.

The file header states **what this proves and what it does not**: it proves that this build
reproduces those runs byte for byte on someone else's machine; it does **not** prove correctness, because a
wrong implementation reproduces perfectly. Confusing the two is the easiest way to
read more out of the file than it says.

**The corpus caught what was documented and never measured.** Two rows
reported durability violations, both from `--hostile` without `--honest-disk`, that is, with a
lying fsync. `docs/durability.md` §7 names this outright: "Nothing against a disk
that lies... What the simulator guarantees is that we **notice**". What was missing was a
**number**: "expected" without a counter is a claim nobody can check, and a
change in it would have gone unnoticed. Now it is the eighth column, and a change in it fails
the gate.

And a separate guard against the most tempting reaction: **a corpus that records a loss on a
row where the disk does NOT lie refuses by itself**, with the words "That is a defect in the
store and not a number to record". Because the usual reaction to a new failure is to insert a
new number and move on.

**`scripts/reproduce.sh`**: `git archive` twice, into two directories with names of **deliberately
different length**, `--release --locked` in each, a comparison of digests, plus a separate
check that the build directory does not appear inside the binary. The length matters: what usually
breaks this is a path embedded in panic messages and debug info, and two paths of the
same length would hide a length-dependent difference. The first version of this
check used `rb1` and `rb2` and proved less than it looked.

It turned out that `--remap-path-prefix` is not needed today: the verifier has no
dependencies and no absolute path gets into it. The check is there for the day one
does, and then it will fail on the push, not at the audit.

**What is honestly NOT pinned:** `rust-toolchain.toml` says `channel = "stable"`, and stable
moves. This is a decision, not an oversight: pinning an exact version would remove the signal "a new
compiler breaks the build", and that is worth more than a constant digest. Hence the rule:
**a build digest only means something published together with the toolchain version and the
target triple**, and the script prints all three every time.

**One tool error, again not Rust.** The corpus generator was first a shell
loop with `set -- $spec`, and **zsh does not do word splitting on an unquoted
expansion**, so empty values went into the binary and the result was sixteen identical
rows of defaults. The binary was right, the loop was wrong, and the output looked like output.
Rewritten in Python, and the generator now itself checks that the runner returned the parameters
it was given.

The gate has ten checks instead of eight, about forty seconds. **Stage 8 closed
completely.**

### The compliance layer, and the reading of the plan that should have been done earlier (2026-07-30)

@decided 2026-07-30: code is written using the architectural
research already done with Fable. The question of why it was not used is exact, and the cost is named concretely.

I read `trailryx-roadmap.md` and the existing code. I did **not** read `trailryx-architecture.md`
and `trailryx-plan.md`, that is, exactly the two documents, 1120 lines together. Three
things followed from them, two of which I had already done wrong:

**Item 15 of the plan:** "Source of the external anchor: RFC 3161 TSA with PQC,
transparency log, or a signed CI artifact. **The manifest is prepared for all three**."
And I had just fixed the pack section with the fields `authority`, `root`, `nonce: u64`,
`token`, that is, for one of the three. `nonce` means nothing for a transparency log,
and there is no room for an inclusion proof. Reworked: `kind` as a discriminator, `algorithm`
for evidence that does not describe itself, `challenge` instead of `nonce`, `evidence` instead of
`token`. Found by reading the plan, not by a test, and **before** a format version was
spent on this mistake.

**§14.2.4 of the architecture:** "SLH-DSA for epoch anchoring is moved beyond v1...
**The manifest format is prepared for it right away**." That is why `algorithm` is a field, not
an assumption: a CI artifact signature is bare bytes, and nobody else is left to name the scheme.

**§14.3 of the architecture**, and this is directly about what I was writing at that moment: the profile
document is **prEN ISO/IEC 24970 "AI system logging"**, no JTC 21 document
is cited in the Official Journal, harmonised ones are expected H2 2026 / H1 2027, and EN 18286 will be the first
to be cited. And a direct rule: **do not write "conforms to the standard" until the
standard is cited**; the wording is "covers the requirements of Art. 12 and is ready for mapping
to prEN ISO/IEC 24970". I was aiming at AI Act + SR 11-7 + SOC 2 and did not mention 24970
at all.

**What was done.** `trailryx-compliance`: a versioned table of obligations, and four
answers for each, two of which are "no": `shown`, `not in this pack`,
`not addressed`, `operator`. The word "compliant" appears nowhere in the output, and a
test checks this. The wording rule from §14.3 is a test too, because a rule that rests
on carefulness holds until the first rush.

The key point: **the answer is derived from the verifier's findings about a specific pack,
never asserted**. And nothing is written into the pack: a pack that carries its own
compliance claim is a store describing its own evidence, which is exactly the
failure mode the verifier exists for. The `trailryx-coverage` exit code follows the
verdict of the **pack**, not the table.

Retention is the cleanest `operator` case and the most tempting one to fudge: Art.
19(1) and 26(6) want at least six months, and there is nothing in the pack that shows
how long anything was kept. What the store adds is narrower and worth stating separately: a kept
log whose completeness is provable, so retention becomes a question about the medium, not about trust.

A clause-by-clause mapping to prEN ISO/IEC 24970 is **deliberately absent**. Clause numbers
from a moving draft, printed next to a verdict, are invented precision. The layer is
versioned precisely so that the mapping can be added when the document is cited, without
rewriting what was claimed before.

**Three test wordings turned out to be wrong, and all three were mine.** The most interesting is the second:
I banned the substring "presumption of conformity is", and it caught my own
**negating** text "a presumption of conformity is not available to be
claimed". The check was about the letter, not the meaning; now it requires the negation
in the same sentence. The third: I checked that the anchor increases the number of shown
obligations, and it did not change, because the only obligation that needs
attestation first needs a signature, and the fixture is unsigned. The test was wrong about the
fixture, not about the design.

**What I changed in the way of working:** before each stage I read `architecture.md` and
`plan.md`, and say aloud which seam or pattern I am applying. This roadmap entry exists
because two corrections to the format could have been avoided.

### RFC 3161: an anchor placed by someone other than the operator (2026-07-30)

A root signature says **who** published the history. It cannot say **when**, because the
signer chooses the time they sign: a history can be rebuilt today,
signed today and dated last year, and the signature will check out perfectly. That is exactly
the forgery an audit trail exists to stop. The tree already had one answer,
witness attestation, but it requires someone to hold a witness. Now there is the one
an auditor asks for by name: a token from a public TSA, which can be obtained today and
verified with any OpenSSL.

**Three new pieces of hand-written parsing**, because the workspace takes no dependencies:
`trailryx-asn1` (a bounded DER reader), `trailryx-anchor` (TimeStampReq/Resp,
TSTInfo, a CMS subset, RSA PKCS#1 v1.5 via Montgomery) and `Sha256` in
`trailryx-crypto`, because **the digest for its own signature is chosen by the TSA**, and it is mostly
SHA-256, not our SHA-384.

**Decisions that carry weight here:**

- **The PKCS#1 block is built and compared, never parsed.** A verifier that
  parses it is a Bleichenbacher 2006 signature forgery; whole
  TLS stacks fell to it. One legal encoding per signed digest, and no
  tolerance within which a second one can be built.
- **Trust is a pinned key.** No chain building, no revocation, no EKU, no
  validity windows. Pinning decides which key to believe, **once and outside the
  path**, where a human can look at it. The cost is named, not hidden: this code
  cannot be pointed at an arbitrary TSA and told to work it out itself.
- **Without a pinned key `verify` returns `Unsupported`, not `Ok(true)`.** A token
  that is bound to the right root but whose signature nobody checked proves
  nothing, and the one thing not allowed here is letting it read as
  attestation. The structural type is called `Claim`, the cryptographic one `Attested`.
- **The nonce is always sent and always checked.** It is the only thing that tells "the
  TSA answered my request" from a replay of an old response for the same root, and the root
  does not change between retries.
- **This lives OUTSIDE the offline verifier.** That the crate can be read in an hour is the
  answer to the question "who reviewed your code"; ASN.1 plus CMS plus RSA
  would double its size.

**What did appear inside the verifier: ninety lines.** They read the token's
own imprint and check that it commits to **this** root. That is the part
an auditor cannot do without the pack. The verifier does **not** check the TSA signature
and says so aloud as a separate finding, together with the command that does check it. Because the
store has no right to declare by itself that its third-party evidence is valid. But what
it definitely has no right to do is **describe its own evidence**: a token whose
imprint is a different root is `BROKEN`, not a note.

The second DER reader in the repository is named as a second reader, not quietly added: two
readers of the same bytes are two chances to disagree, so a real token from a real
TSA goes through both, and `trailryx-store/tests/it/anchored.rs` compares what each
of them read from it.

**The pack format became version 3** (`SECTION_ANCHOR`), and version 2 is read as
before: a pack written by an older commit must still verify. The bump is needed
for the other direction: an **old** verifier meeting a new pack will say "unknown
version", not "unknown section". Both will refuse, but only one says why.
The **record format did not change**.

**Four defects found by measurement, three of them my own:**

1. My SHA-256 **dropped buffered bytes** when `update` did not complete a block.
   All published one-shot vectors passed; "abc" one byte at a time gave
   the digest of "c". The existing SHA-384 protects the same assignment and was never wrong.
2. CMS puts **`rsaEncryption`** in `signatureAlgorithm`, not
   `sha256WithRSAEncryption`. Because of that the code rejected every real token as an
   unsupported algorithm, until a token from `openssl ts -reply` went through it.
3. The bit-flip sweep **claimed every byte of the token was load-bearing**, and
   found 73 positions where that is not so. All of them in `digestAlgorithms` and
   `certificates`, which CMS does not sign. The claim was wrong, not the code, and the fix
   was `tsp::covered`, which puts the trust boundary into code as byte ranges.
4. In the verifier's minimal reader I three times used "the value fills the container"
   where the field is followed by its neighbours. That rejected every real token as
   not DER.

And one tool error worth recording: a `python` replacement inserted the anchor-record block
**twice**, because the pattern occurred in the file twice. It was not a review that found it, but a test that
saw two identical findings where there should have been one.

**The oracle is the point.** OpenSSL stands up a real TSA, issues a real certificate
and signs a real response, and our hand-written arithmetic verifies it. Then the same
token is handed to OpenSSL itself to verify, so agreement runs in both directions. No test
is skipped.

What remains at stage 8: the mapping to Art. 12 AI Act / SR 11-7 / SOC 2 and reproducible
builds with published seeds.

### Ingestion authentication: the check before the body (2026-07-30)

`AuthProvider` and `Action::Ingest` have existed since stage 1, conformance on them was green,
and the server called neither. This is not a "future feature": a server that listens on a
port and writes to the audit store for anyone who reaches it is a ceiling for
any real deployment, and an honour system written down in the docs does not raise it.

**What matters here is not the rejection code but its moment.** The body is capped at 16 MiB, and the sum of bodies
in flight at 256 MiB. A check after reading the body would give an unauthenticated call
the ability to occupy a quarter of a gigabyte of memory at the price of one header line. So the gate
lives in the pre-body phase, on the head itself.

And this is not "put earlier just in case", it is **measured**. The check sits **before**
the `Content-Length` parsing, because the first branch of that parsing itself returns `ReadBody` for a
declared zero length. I moved the gate three lines lower, to where it
looks just as correct, and ran the suite: an unauthenticated empty export
got **200**. One test exists for exactly this order, and it is the only one of twelve
that failed from the move.

A second such trap: `100 Continue` is written inside the `ReadBody` branch, so a gate
after the verdict would invite a body it was about to reject. A separate test that
the invitation does not arrive.

**401 and 403 are both non-retryable, and that is a decision, not a consequence.** An exporter with a
wrong token must stop, not hammer; a fleet that retries a wrong
token is a fleet attacking its own auth. The only retryable variant, 503, is when the
**provider** is down, because then the batch must be kept. "Wrong token" and "a scheme we
do not understand" answer identically: a difference would let one enumerate what the deployment accepts.

**A poisoned mutex refuses.** A provider that panicked poisons the lock, and from then on the
gate answers 503 to every request. Failing through would be the only mode that
turns a failure in authentication into an open door, so this branch is written out by hand,
not reached through `unwrap`. The test poisons the lock on purpose and measures the three
following requests.

**A routed bind without a gate now does not start.** Before, it only wrote a
warning to the log, that is, the operator who most needed to see it read it
least: the line arrives **after** the port is already open. Now it is a refusal, and
a refusal **before** `TcpListener::bind`, so that the port does not exist even for a moment. The test measures
exactly this difference: the same address with a gate fails on the socket, not on policy.

**A reference provider exists, because a seam without an implementation is a seam nobody has run.**
`bearer::SharedSecret` is one secret, presented as `Bearer`. It authenticates the **fleet,
not the agent**, and says so; the record's identity still comes from
resource attributes via the mapper, and no second, unattested source of truth
has appeared next to it. The secret is stored as a **digest**: comparison goes through the existing
`digests_equal` on two fixed lengths, so neither prefix nor length leaks, and a
core dump of this process yields the digest, not the working token. It is read from a file, because
`argv` is visible in `ps`, and the environment is inherited by every child process.

Two more small things that would have been gaps: two `Authorization` fields is a refusal, not a choice
of one of them (otherwise a proxy that adds its own quietly takes the access over), and
an empty field value does not reach the provider at all.

Exactly one thing remains at stage 6: gRPC.

### NDJSON: reading the file the collector already writes (2026-07-30)

The question was not "how to implement" but "what is a line". Research and three
independent designs with a judging panel gave the answer: **one line is one
OTLP/JSON envelope**, byte for byte what the collector's file exporter writes with
`format: json` and `compression: none`, and what its own `otlp_json_file` receiver
reads back. No conversion step: the operator points at a file that already exists.

The alternative was a human-readable event format of our own, which reads better by
hand, but loses on one deciding point: it needs a **second mapper**. Every
decision about the plane, the content table, the derivations and the handling of remainders would exist
in two places, and the schema test in `trailryx-record` sees only one of them. Plus a
line could assert a verdict that the mapper refuses with an explicitly stated reason:
an auditor reading `allowed` would reasonably assume the policy engine said so.
So the JSON decoder yields **the same in-memory structures** as the protobuf decoder,
and then calls the same `map_span`. Two decoders, one value.

This is also what makes the main test possible: one fixture, described once, encoded
twice by two **independently written** encoders, read by both readers, and
the results compared as whole structures. Had the plane boundary been defined twice,
this test would be what noticed it.

**The JSON is ours too, and that is the part that bites.** A hand-written parser at a trust boundary
is a liability until it is checked against parsers with no common
ancestry, so `trailryx-json` is checked against three: V8 in node, CPython and
Ruby. **222 conformance cases**, the generator committed, every oracle
classifies them, and divergences are pinned: the set of cases where we disagree with
CPython is exactly 26, with node exactly 23, and a twenty-seventh breaks the build.

CPython and node disagree **with each other** on 5 of 222, and these five are worth naming,
because they are the whole map of where the JSON world has still not made up its mind: four are the
non-standard literals `NaN`, `Infinity` and `-Infinity` in CPython, which V8 rejects and
we reject, and one is CPython's limit of 4300 digits. On all five we are on the side of the RFC.

Three divergences are ours deliberately, each because a liberal answer would change bytes that
this store hashes: **a duplicated member name is fatal** (the RFC blesses both
answers in two different sections, so each parser picks a winner, and
CVE-2017-12635 is exactly the detail that decided who is an administrator); **a lone
surrogate is fatal** (Rust does not hold it in a `String`, so any liberal
path loses data: U+FFFD changes the hash, and truncation is a published privilege
escalation primitive, because `"superadmin\ud888"` must not become `superadmin`); and **a limit
is never reported as a syntax error** (RFC 8259 §9 in a single paragraph
asks to accept every conforming text and permits setting limits, so the tension
lives in the error type).

Depth is the place where the adversarial review earned its cost, and it is worth saying
plainly. The first version limited the JSON reader to 25 containers and claimed that this number was
**derived** from the protobuf reader's limit of 16, so no transport is more liberal than the
other. That derivation cannot be made correct, and the lens found it failing
**in both directions at once**: a resource attribute with two levels of array and three levels of
map the wire rejected and JSON accepted; a span attribute with four levels of array and one level of
map the wire accepted and JSON rejected. Two transports that disagree on which
rows become records are two stores.

The arithmetic says why. The wire counts nested **messages** and takes 2 per level of
`arrayValue` and 3 per level of `kvlistValue`; JSON counts **containers** and takes 3 and 4.
Two different ratios, so no single container limit coincides with the message limit
for all mixes.

So parity moved to where it can be exact: the JSON decoder counts OTLP message levels
the same way the wire reader does, against the same constant, and the container limit
went back to what it should always have been: a safeguard against hostile
nesting, not a parity device. The deepest container nesting that a wire-legal
OTLP value can reach is **27**, measured, so the safeguard
is set at 32. And the test that missed this is now a grid: the three positions where
`AnyValue` can sit, across all mixes of the two forms, **144 cases**, and both decoders must
agree on every one.

Numbers do not pass through a float on input. An OTLP timestamp is routinely larger than
2^53, and `"9223372036854775808".parse::<u64>()` succeeds and `as i64` then gives
`i64::MIN`, `1e19 as i64` gives `i64::MAX`, and wrapping accumulation of
`18446744073709551616` gives 0. Each of these is a failure dressed as a plausible
value, so there is no float-to-integer conversion on the value path at all, and a test
checks this by grep.

**An archive and a live file are different sources.** `replay` does not assess clock skew and
counts that it did not; `tail` assesses it. Reading last week's export without
this separation marks every record as excessively skewed and produces an anomaly record,
true about the reader and false about the fleet. The demo binary shows this: the same bytes,
`skew_not_assessed 4` one way and `excessive_clock_skew 3` the other.

The source also fixes **three defects that its protobuf sibling still carries**,
each marked in the code with what it fixes: the sum of anomalies is computed over a list
built by exhaustively destructuring all report structs, so a counter added
later is a compile error until someone classifies it as a loss
or a diagnostic (the handwritten sum next to it skips one and therefore never reports a
batch whose only fault was invalid UTF-8); both identifiers are built
**before** the reported mark advances, so a construction failure cannot discard a report
already marked delivered; and the anomaly record is stamped `UNMAPPED`, because no
mapper touched a record that the store wrote about itself.

**What we do not do, and it is on the "not done" list**: HTTP does not serve JSON
(`application/json` is still a 415, but the reason changed and the comment in
`trailryx-ingest` acknowledges this); no gRPC, metrics or logs; no decompression and
reframing (gzip, zstd and length-prefixed are refused, naming the collector setting
that produced them); no multi-line JSON; no snake_case keys and
base64 identifiers, so the output of `otel-cli server json` is refused rather than
read halfway; no following of rotation; and no persisted resume mark,
so the source claims at-least-once.

**The adversarial review of the new surface went only partially, and that is recorded as it is.**
Six lenses, of which four ran; **all 50 skeptic agents failed on 529
Overloaded**, so the script's summary "14 refuted" is a logic artifact, not a
verdict. I verified three findings by measurement myself and fixed them:

1. **Critical.** A refusal on the encoding marker swallowed the rest of the buffer. The framer
   refused inside the stream-opening path, before the chunk was framed
   or accounted for, so `push` dropped it whole, and the call read on from the next one.
   Measured: the same 40-kilobyte file behind a UTF-16 marker yielded **0 records
   when read in 64 KiB pieces, 118 at 16 KiB, 179 at 4 KiB and 199 at two bytes**, and
   every run reported one or two lost lines. How much of a file reaches
   the store cannot be a function of the read size. Now the refusal is latched in both
   layers, the stream yields nothing at any size, and it is counted exactly once.
2. **High, in two directions at once.** The derivation of the depth limit (see above).
3. **Medium.** A producer flush inside a multi-byte character was counted as a
   damaged line. `Utf8Error::error_len()` already distinguishes "the bytes ended
   inside a valid sequence" from "the sequence is broken", so this cost
   nothing: the new `Encoding::IncompleteUtf8` is forgiven **only on the last
   line**, because a cut-off character before the terminator is real damage. Measured
   before the fix: 19 of the 299 cut points of one Ukrainian-language line produced a
   `Verdict::Failed` record about a loss that did not happen.

**The skeptics ran on the second attempt**, and three more findings survived them. All three
are fixed here:

- **`unterminated_final_line` was counted twice.** The latch was a flag that
  was reset every time the carry buffer emptied, and the framer also empties it when
  it drops an oversized line. So one line without a terminator was counted twice:
  once while it was partial under the limit, and again on `finish`. This number
  goes into the hashed, signed anomaly record, so the operator was told about two
  truncated lines in a file that had one. Now the latch is keyed on the line number.
- **A repeated attribute key lost every value after the first.** The filter
  dropped the **key**, not the occurrence, so `Span::attr` read the first value in
  metadata while the payload skipped all of them. Measured on a span with two
  `gen_ai.request.model`: the second model name appeared nowhere. Now a repeat
  of a metadata key goes to the remainder, and a repeat of a content key gets its own
  part of the same class, because the remainder is a `Diagnostic` and content must not
  be reclassified along the way.
- **My own `prompt_hash` fix was half a fix.** I closed the top level, and the skeptic
  measured that the collision is alive one level deeper, in the same shape the conventions
  actually use: `gen_ai.input.messages` is an array of maps, and the limit drops
  the **part** itself. Now the check is recursive, and deliberately conservative: if
  any part came in empty, there is no hash at all.

**Open: zero.** All three closed the same day, each with a regression test, and below
stays a record of what they were and what exactly each meant. Three decisions are worth
naming, because two of them are decisions about **semantics**, not about code:

- **What `queue_full_stops` means.** It counts **transitions into the stop state**, not the calls
  rejected while it lasts, and it is classified as **a diagnostic, not a loss**. Both
  halves were wrong. A full queue is not a loss: the bytes were not read, so they are still
  with the caller, and the same chunk goes after the drain; an anomaly record that claims a loss
  that did not happen teaches the operator not to believe one that claims a real one. And "repeats"
  measure the caller's retry loop, not the store: one who retries every millisecond and one
  who retries every second would show different numbers under identical conditions, and this is the same class as
  a test that pinned the machine instead of what it tests. The stop stays visible where
  it belongs: in the reader's own report, which the binary prints, and in the anomaly breakdown
  when that is born from another cause. The HTTP surface draws the line in the same place:
  backpressure there is a 503 to the client, not a record in the store.
- **What to count `unknown_fields` on.** On the **element**, on both sides. The wire sees
  one tag per element of a repeated field, and that is a better measure of "how much we did not understand"
  than one per object member. So the JSON side changed, not the wire, which has had this semantics
  in service for a long time. An empty unknown array costs **zero**: proto3 JSON omits
  an empty repeated field, so `[]` and absence are one message. The first attempt
  put a floor of one there, and the differential test caught it within a minute.
- **What to do with an id of the wrong length.** **Drop the span, on both transports.**
  The wire changed, because dropping is the safe side, not just the JSON side: keeping such
  a span means deriving the run identifier from four bytes of something, and an unreadable
  `parent_span_id`, read as absent, turns a delegation into the arrival of a request,
  and that is exactly the defect for which `MAPPER_VERSION` 2 was cut. Absent and zero
  are each treated as absent, so an emitter that follows the specification loses
  nothing.

**What was open before this:** The number used to say 6, and it was stale in the very paragraph
where I wrote about the staleness of status: I counted the candidates **before** three fixes of the same
day, and one more item ("one about the framer itself") I simply invented, because no candidate
corresponded to it. Each of the three below is **measured against the current code of 2026-07-30**, not
counted:

1. **`queue_full_stops` counts call repeats, not the stop** (`jsonl.rs:475`, medium).
   Measured: filling the queue and submitting the same chunk five times, as the
   documented recovery prescribes, gives `queue_full_stops = 5` with one real
   stop. That is, the loss counter grows because the caller does everything right.
2. **`unknown_fields` counts differently on the two transports** (`otlpjson.rs:281`,
   medium). Measured on a span with two elements of an unknown repeated field
   (`links`): the wire says 2, JSON says 1, because one counts per element and the other per member
   of the object. This is a gap in the same claim, "two decoders, one value", which
   stands in the README: a differential test on such a legal message will fail.
3. **The wire accepts an id of any length, while JSON drops the span** (`otlp.rs:411`, low).
   Measured on a trace_id of four bytes: the wire yields 1 span, JSON yields 0. That is,
   the two transports disagree on which spans become records, and this is the same class
   as the already fixed depth limit.

**One candidate closed itself, and that is worth recording:** "a partial line that begins
in the same read where the previous one ended is not counted" no longer reproduces,
because the tail latch fix is keyed on the line number, so a new partial line has
a new number and is counted. Measured: 1, not 0.

A review that did not happen is not a review that found nothing; a review that
happened partially is closed to the end; and the number of open items is also
a statement about status, and it goes stale in the same way.

**One staleness of status was found and fixed along the way.** The README said "Stage 6
has no HTTP or gRPC transport" right up until someone compared it with the crate table
two sections above, where `trailryx-ingest` stands with 84 tests. A sentence
about status outlives the work it described unless it is swept out separately.

### Adversarial review of the core (2026-07-30)

The transport went through that review because it was the newest and most exposed code. The core
had never been through it: **nine lenses, 140 agents, 16 million tokens**, one
lens for each claim the store makes out loud, each finding
handed to three skeptics with orders to refute it. 47 candidates, 25
refuted, **16 survived**: five critical, three high, seven medium, one
low. Each of the five critical ones had a comment next to it that promised the opposite.

**A single flipped bit in the 20-byte header deleted the journal entirely.**
Recovery treated a header that failed its CRC the same way as one truncated
by a crash, and then truncated the file to zero. Measured: five confirmed records,
one bit in the last byte of the CRC, the file went from 1095 bytes to 20, and the report said
`records: 0, discarded_bytes: 0, durability_violation: None`, and `is_suspicious()`
was `false`. Nothing said a record had ever existed. 15 of the 20 header bytes
did this. The distinction the code lacked: a crash preserves a **prefix**, so behind
a header that never arrived there can be nothing, and a file longer than the header cannot
have become so from a crash. Now it refuses, and the bytes are left to the operator. The same
logic closed a second defect: a bad checksum in an early frame swallowed
every valid record after it, and reported a routine `TornTail`. A frame that
still parses after the stopping point proves this was not the tail.

**A completeness proof that claimed zero records could carry as many of them as anyone liked.**
Binding the empty root closed half of this attack a stage earlier and left
the other: at `size == 0` every check below is skipped, so records copied
from another segment were compared with nothing, and `matched()` counted them. The path to
exploiting it is ordinary operation, not a compromise: close one empty
segment per shard **before** the root is signed and witnessed (an idle shard is
normal, the closer calls this `NothingDurable`), and then hang invented records on
that slot in any query. The offline verifier saw nothing either: a segment of
zero records passes record-count, history-root and chain-across-segments cleanly. This is
the **seventh** gap in the same function, and the file's own rule names it: the verifier
must not learn the shape of the answer from the answer.

**The erasure record published the subject key, and that linked the forgotten person to their
records from the metadata plane alone.** A manifest row is a hash of the subject key
and of the destroyed key; the destroyed key is `payload.key_id`, open on every record.
The subject key in `basis.memory_ref`, also open, made both inputs public,
so a `for` loop over the store could read off exactly which records belonged to that person. The comment above
the row function said that this is exactly what it rules out. Worse: a payload sealed
when the subject was already known went under the **subject key**, so `payload.key_id` was
the same on all of their records, and the store grouped by subject without a manifest
at all. Now every payload is under its own record's key, and the record carries a one-way
tag over the subject key instead of the key: the descriptor's owner can still verify their own
erasure, and nobody else can count a single row. The demo checks this on a real
store.

**`forget` dropped the subject's registry row before destroying the keys.** The registry's own
doc comment forbids this order in so many words. A single `Unavailable` from KMS
in the middle of the loop was enough: the row was already gone, so the retry that every
erasure job makes found nothing and wrote `NotApplicable` ("we hold nothing about this
person"), while three of the four payloads stayed readable, and nowhere was left
a single key id that was supposed to die. Now destruction comes first, and the row is dropped only when
all the destructions have gone through; `destroy` is already idempotent, and that is what makes the retry
correct, and not merely possible.

**A segment that named a shard absent from the pack's list was checked by nothing.**
The verifier walks top-down from `pack.shards`, and nothing required that every
parsed section be reached, so appending two sections to a **signed** pack
put a whole invented shard into it, and the report came out byte for byte the same, together with the
signature: the signature covers the store root, and the root is derived only from the list
of shards. An intermediary who cannot forge the root could still add shards
of favourable records. The traversal is now complete in both directions, and duplicate sections
are rejected by the parser, because `records_for` returned the first match and the second set
of records for the real segment was never decoded at all.

Further, in the same pack: a segment of zero records did not have to claim
`chain_after == chain_before`, so every segment slot was a free splice point,
and three records were cut out of the middle of a shard with all roots recomputed;
the sequence was checked for increase, not for continuity, so deleting
the record with seq 2 out of three produced no finding; witness names are arbitrary UTF-8
from the party being audited, and were printed as is, one line per finding, so
a name with line breaks appended findings to the auditor's report, including a
`root-signature` note naming a key, on a pack with **no signature** (now the signer
refuses everything except a restricted token, and the verifier escapes what it prints); and
the issuer could be its own witness, because independence was compared between witnesses and
never against the signing key.

Outside the store: the stated precondition of the correlation window was inverted for the only
source that exists. "A parent arrives before its child by construction" is false for
OpenTelemetry, where a span is exported when it **ends**, and a child ends
inside its parent, so a batch arrives children first and resolution in arrival
order found nothing. Measured over a real wire: one parent, one
child, one batch, and both records came out with no edge. **The causal graph was
empty for every trace from OTLP.** `adopt_batch` mints all ids and remembers all
names before resolving even one. A zero span id, which OTLP defines as
invalid but emitters write anyway, was accepted as a real name, so unrelated
roots got a parent that was never named and were reclassified as delegations;
now it is absent in the same way a zero trace id already was, and the version
of the mapper went to 2 to say so. An unresolved parent is now counted instead of
vanishing into silence.

All 16 are fixed, each with a regression test. Two fixes made the store
**stricter with itself** and broke fixtures that had encoded the old behaviour: a segment
assembled by hand that numbered records 4 and 5 (no journal does that), and a test
that asserted a redirected journal file is emptied rather than refused.

**What the review did not close, and why.** Two debts run into the frozen
record schema. A record cannot say "this event named a parent we did not resolve",
so a reconstruction without that edge cannot lower its own proof; the assembler
counts a loss instead. And the journal's confirmed-durability mark lives
only in memory, so after a restart nothing reports a violation against what
the previous process promised; the destructive paths through which this mattered are closed, but the
mark itself wants persistence. One deliberate availability trade-off: a journal with a
damaged middle now refuses to open instead of healing itself by truncation,
so the store does not start until an operator has looked. For an evidence store this
is the right side: the previous behaviour started cleanly and had already deleted the evidence.

### Assembly moved out of the demo (2026-07-29)

Both ends of the seam were built and tested before the middle: the source
emits `Ingest`, the journal takes `Record`, and nothing connected them. One commit
of wiring lived in the demo binary, which is the wrong place for the missing half
of a product. Now it is `trailryx-assemble`, and moving it out closed **three real defects**
that the demo tolerated and the store must not.

**Identities were a counter.** The counter restarts from one along with
the process, so the first record after a restart claims an identity that is already
taken, the journal reports a duplicate, and the record is dropped. A silent loss, from
the one field that must not collide. Now it is a ULID, whose high bits are the record's own
`recorded_at`, which also makes the index on id usable for range queries by
time, not only for point lookups. A clock that went backwards does not drag the id
along with it.

**Every source name it had ever seen was remembered.** The demo lives for a second,
the receiver for months. The window is now bounded, and a parent that has fallen out of it gives an **absent**
edge, not a guessed one: a wrong edge in the causality graph is worse than an absent one, because
an absent one costs the reconstruction its completeness, and the reconstruction says so.

**The order of sealing was the caller's problem.** One had to ask which id
would be next, seal the payload against it, and hand the reference back. Two
steps that had to agree, in two places. Now the id is minted first, and
sealing lives behind a single call.

The crate decides three things and refuses to decide the rest. `seq`, `prev_hash` and
`segment_id` stay as values that nobody will mistake for real ones, because they are
stamped by the journal at append, and a plausible number there would be a lie that would survive
in the record.

One of the tests I wrote was wrong, not the code: a `u64` of nanoseconds gives at most
18.4e12 milliseconds, and a 48-bit field holds 281e12, so it cannot be overflowed from
a `Timestamp`. The assertion was corrected to what is true, and it
stayed as a test, because a defensive clamp looks significant and is not.

### Chaining of segments (2026-07-29)

The biggest debt the demo found is closed. **Shard segments are now one
chain, across as many files as you like.**

What it was: every journal started its chain from a genesis derived from its own header,
so deleting a whole segment file left every other file internally valid and the
shard's history silently shorter. The manifest has carried `chain_before`/`chain_after` for exactly
this since stage 3, and nobody implemented them. Worse than the bug was that a test
named `segments_chain_to_one_another` **asserted the opposite** and passed.

What it is now: a continuation segment starts **literally** from the head on which the
previous one ended. The first segment of a shard still starts from the genesis of its own
header, so the file cannot be accepted as someone else's; and a continuation file cannot be
redirected: reopening it under a different predecessor fails the very first record,
and the bytes are discarded.

I chose this form over the alternative "put the previous head into the header and derive the
genesis from it". That variant kept the file's cryptographic binding to its own identity
for all segments, but it dragged in a header format change, `created_at`
in the manifest, a manifest version and a pack format version. The chosen variant **does not change the
on-disk format at all**, and identity is held by the header check on open
(`WrongOwner`), which already existed.

`seal_segment` no longer takes the start of the chain as a parameter. A parameter that
can have only one correct value is a parameter that can be wrong.

The verifier got its second half. Deleting a segment from the middle of a shard breaks
the pair; deleting the oldest or the newest does not, so numbering is checked too.
And it now says outright what it **cannot** check: the first segment
of a shard starts from a head derived from the journal header, which is not in the pack,
so that one value is claimed, not proven. Truncating the newest segment
is caught by the signed root and the witness, not by numbering, and that is already built.

One bug turned up during the fix: `read_all` recomputed the genesis from the header
instead of using the one the journal actually started from. That was correct while every file
started from itself, and became wrong the moment a segment could continue
the previous one.

**Not done**: assembling records from the source (`Assembler`) still lives in the demo.

### The demo, which is also the acceptance criterion (2026-07-29)

```
cargo run --release --bin trailryx-demo -- --runs 2
→ ALL EIGHT STEPS PASSED, TWICE
```

Eight steps, twice in a row, from an empty directory. Nothing is faked: each step
does the real work and fails the run if it did not.

Two of the eight steps are **not** what the plan asked for, and the demo says so itself.
Step 1 asks to block the agent: blocking is the job of a policy engine, and this is
a record store, so the demo **records** the incident rather than forbidding it. Step 8
asks for a scan by a third-party tool, which this project does not have; instead
the demo reads back the primitives that every record declares and asks the verifier whether
any of them has been withdrawn from use.

**Writing the demo found four real defects**, and that is exactly what an end-to-end run
is for.

The worst one was silent. The journal chain starts **not from zero** but from a genesis
derived from the file header, while `seal_segment` took any `Hash` the
caller gave it. `Hash::ZERO` compiled, sealed, got assembled into a pack and failed
only in the offline verifier, four stages later. **All the existing sealing tests
passed the same wrong value and stayed green.** Now the chain start is an enum,
whose plain case is the correct one, the seam checks that the records agree with it, and the test
named "segments_chain_to_one_another" is replaced by one that says outright: **shard
segments are not yet chained between files**. The manifest has `chain_before`/`chain_after`
for exactly this purpose, but the journal does not yet carry the head across a file boundary.

The other three: subject erasure did not reach the OTLP payload (correct behaviour,
but the demo had to show the attribution that closes this, and now it does);
`Algorithms::default()` said `es256` when we sign P-384, so a record
wrongly declared its own algorithms, which makes the migration those fields exist for
impossible to plan; and `Segment::seal` had nowhere to check
continuity, because the canonical codec lives on the other side of the seam.

**Not done**: chaining segments between files; assembling records from the source
(`Assembler`) lives in the demo and should be a separate crate, and it says so there.

### Transport (2026-07-29)

An OTLP/HTTP server with no dependencies: the HTTP/1.1 parser, the gzip decoder and the encoder
of protobuf responses are all in the crate. The stock OTel SDK or OpenTelemetry Collector
write to us unchanged.

Before the first line of code I ran a fan-out of four research lenses (RFC
9110/9112, the OTLP/HTTP specification, resource exhaustion, the constraints of our
codebase) and a synthesis into a single 57-item checklist. **One finding changed the decision
about gzip**: stock SDKs mostly do not compress, but the Collector's `otlphttp` exporter
compresses by default, and agent → collector → store is a normal
production topology. Refusing gzip would mean a standard forwarder could not
reach us, and that refusal is a 415, i.e. not retryable, i.e. silent data loss
at the emitter.

**What is not there and will not be**, and this is written in the crate docs, not left to guesswork:
TLS, authentication, HTTP/2 and hence OTLP over gRPC, chunked bodies, JSON, metrics and
logs, pipelining. Whoever can reach the port writes records, so the default bind is
loopback, and a routed one announces itself at startup.

Hence the strictness of the parser: a proxy in front means two HTTP parsers in a row, and
any disagreement between them about where a message ends is smuggling. So the
parser refuses to have an opinion about anything ambiguous. CRLF only, never a
bare LF, even though the RFC permits recognising it. `Transfer-Encoding` in
any form is a 501, which removes a whole family instead of defending against it. A second
`Content-Length` is a refusal, not a choice between the two.

30 tests are written from the sender's side: a bare LF, a second request in the same
TCP write, a body trickling below the speed threshold, a kilobyte that decompresses into
four megabytes, more connections than the limit, a full queue, a truncated body that
must not become half a record.

**The adversarial multi-agent review did not happen**: all 18 attempts (6 lenses × 3
repeats) failed with 529 Overloaded. I did the review myself, with one pair of eyes instead of six,
and found four things, all fixed with regression tests:

1. `Content-Length: 0` and a missing header were merged into one value through
   `unwrap_or(0)`, so an SDK sending a legitimate empty export with a Content-Type
   got 411 "no length". It had stated a length. The length was zero.
2. The body speed threshold required 8 KiB to have arrived and truncated the time to whole
   seconds. Together that meant it could not fire for ~8 seconds, when the deadline was
   already doing all the work. A threshold that cannot fire is worse than none, because
   the comment above it says otherwise.
3. The failed-spawn path logged status 503, which it never sent to anyone.
4. `Instant + Duration` panics on overflow, and the durations come from
   configuration.

**Not done**: gRPC (that is HTTP/2, i.e. HPACK, frames and flow control),
NDJSON sources, authentication (the `AuthProvider` contract and `Action::Ingest` exist,
the server does not call them yet).

### Signature and anchor (2026-07-29)

Two different questions, and the signature answers only the first.

**The signature says whose root this is.** ECDSA P-384 over SHA-384: one hash for the whole
system instead of two, the strength levels match, the key stores of
all three clouds support the curve. `SigAlg::Es384` is added as a new discriminant, the change is additive.
Our code never touches the private key: `trailryx-sign` is a seam, and there is deliberately
**no** implementation of the trait in the repository - the tests drive OpenSSL.

**We write the verification ourselves, and it cannot be otherwise.** The verifier has its own P-384:
about 500 lines of modular arithmetic, reduction by binary division, because that is the
version a person checks by eye. Signing works with the private key and a
nonce and has to live behind a validated module; verification works only with public
values, so there is nothing for it to leak. Without this, the single binary an auditor
uses to check us without us would say "there is a signature, I did not look at it".

Checked against signatures with no common origin: OpenSSL signs with twelve
keys, we agree on all twelve acceptances and all thirty-six
rejections, and each of the 768 bits of a genuine signature is flipped in turn and
must be rejected.

**The witness says when.** The publisher chooses the time it signs, so a history can be
assembled today, signed today and dated last year, and the signature will
verify flawlessly. Only an independent party saying it saw the
root rules that out. An attestation is the same signature over a different statement, so the verifier
has nothing new to learn, and several independent witnesses are stronger than one authority.
RFC 3161 will come later as another kind of receipt: it needs ASN.1, CMS and
a certificate chain, and that does not belong in a crate whose value is that it
is read in one sitting.

A pack with a valid signature and no witness at all still gets a remark, and
that remark sounds like pedantry until somebody tries it.

Checked end to end: the binary read a signed pack and named the keys;
changing one letter left the signature valid (the publisher really did sign that
root) and failed everything under it; changing the root itself failed the signature.

**Not done**: RFC 3161 TSA, a mapping to Art. 12 AI Act / SR 11-7 / SOC 2,
reproducible builds.

### Core freeze (2026-07-29)

Frozen: the journal format and framing, the canonical codec, the shape of the chain,
the index structures, the proof shapes (inclusion, consistency, completeness, composition),
the set of proof dimensions, the segment manifest format.

Changing any of this is a **format change**: it needs a new version, a migration
and a separate decision. The reason is not bureaucratic: segments are immutable once sealed,
and roots are published and go to the auditor, so changing the shape of a proof means that proofs already
issued stop verifying.

**There are five proof dimensions**, and the fifth (`id`) was added deliberately in stage 5, because
`caused_by` names records by id, and a closure that cannot prove its own
edges is half a feature.

**Two deliberately deferred debts**, both recorded in the code:

1. A range response carries an inclusion proof for every record, so a full
   range is O(n²) hashing. The fix is a multiproof over a contiguous
   range, and it waits for a benchmark so there is something to measure that it helped.
2. The sortedness of the index is assumed, not proven. It is closed by the offline
   verifier in stage 8: it will rebuild the index from the segment's records and compare
   the roots. Segments are immutable, so one audit holds forever.

---

## Three milestones

The fourteen stages are not equal. They are grouped into three release points:

| Milestone | Stages | What is inside | Criterion |
|---|---|---|---|
| **A. "Proof"** (v0.1) | 0-5, 7, 8 + a minimal NDJSON Source | one node, local FS, no SQL and no clouds | all eight steps of the demo, twice in a row, from scratch |
| **B. "Compatibility"** (v0.2) | 6, 9, 10 | OTLP and semconv, Parquet projections, SQL with `WITH PROOF` | a foreign agent writes into it without changes; Grafana connects as to Postgres |
| **C. "Scale"** (v0.3) | 11, 12, 13 | object stores and WORM, federation, multi-cloud validation | a query across two clouds yields a correct joint proof |

**Publish the repository after milestone A.** It is self-sufficient, and steps 3 and 7 of the demo
(a query with a completeness proof; erasure of a person, after which the pack still verifies)
show what nobody else will show.

The first real costs appear in milestone C (boxes per run), each one requiring separate consent.

---

## Three ordering rules

1. **What cannot be bolted on later comes first.** The DST skeleton and the sharding model
   cannot be added to a finished core. So they come first, before the first line of the journal.
2. **Truth first, then convenience.** The journal, index and proofs are built before
   any adapters, SQL and clouds. An adapter for an immature core has to be written twice.
3. **Freeze after stage 5.** After that the journal and index format does not change without
   a separate decision and a migration.

**What is ours and what is foreign** (details in §"Boundary" below): all of the engine is ours (journal,
index, proofs, sharding, simulator, erasure). Three things are foreign: crypto primitives
(FIPS-validated), the SQL engine (DataFusion) and the exchange formats (Parquet, Arrow).
None of them is a foundation: switch them off and the database keeps working.

---

## Stage 0. Determinism and shard skeleton

**Ours: 100%.**

- Traits `Clock`, `Rng`, `Io`, `Net` and `Shard`. Real implementations and simulated ones.
- Our own thin reactor, **two equal backends**: `io_uring` (where permitted)
  and `epoll` (hardened kernels, managed Kubernetes platforms, seccomp profiles of
  container runtimes, development on macOS). Both behind the same `Io` trait,
  both pass the same durability tests.
- A **thread-per-core** skeleton: N single-threaded shards, exchanging lock-free messages.
  The number of shards is fixed generously when the store is created; migrating ownership between
  cores is allowed, **re-split never** (a shard's identity is part of the proof paths).
- Simulator: a controlled seed, injection of crashes and faults at an arbitrary point,
  recording and replaying a seed with one command.
- Assertion mechanics: invariants that stay enabled **in release**.

**Done when:** an empty core with two shards runs through the simulator;
one seed gives a **byte-identical** run twice; a crash at an arbitrary point
is replayed by a command.

**Why here:** injected interfaces and shard boundaries cannot be bolted on later.

---

## Stage 1. Record model and contracts

**Ours: 100%.**

- Canonical **decision record**: four times, `basis`, `caused_by[]`,
  `payload_ref`, `outcome`, algorithm-agility fields (`hash_alg`, `sig_alg`,
  `kem_alg`, `key_id`), `seq` / `prev_hash` / `segment_id`.
- JSON Schema + a corpus of conformance tests.
- **L1 contracts**: `Source`, `Sink`, `ObjectStore`, `KeyProvider`, `Anchor`,
  `TableProvider`, `AuthProvider`, `Peer`.
- A conformance suite **for adapters** (written together with the contracts, not after).
- Fixing the **proof dimensions**: time, `agent_id`, `run_id`, event type.
- **Plane boundary** (§5.2 g of the plan): metadata is typed fields only; any free
  text, including unrecognised OTel attributes, only in the encrypted payload plane.
- **A DPIA-style pass over every field of the canon**: what it is, whether it can be personal,
  which plane it lives in.

**Done when:** schema v1 is frozen; conformance is green, and it contains a test
**"no free-text field in the metadata plane"**, which fails the build;
the set of proof dimensions is recorded as a decision (it determines the sorting of segments,
and does not change afterwards); the per-field DPIA table is filled in.

**Why here:** everything that follows depends on the shape of the record; changing it after stage 3
means migrating all the data.

---

## Stage 2. Journal: write and recovery

**Ours: 100%. This is the engine, part one.**

- Record format: length, CRC, self-description, a format version in every segment.
- An append-only write path per shard, buffering, batching.
- **A written durability contract**: what exactly is flushed, when and how; what we
  promise after `ack`. `fsync` **bypassing io_uring**, as in PostgreSQL.
- Crash recovery: an incomplete tail is discarded **explicitly and loudly**.
- A hash chain on **SHA-384**, one chain per shard, continued after restart.
- Deduplication on `(source, agent_id, run_id, seq)`, a gap counter.

**Done when:** a simulator with crashes, partial writes, a lying `fsync`,
a full disk and a corrupted sector **finds no loss of acknowledged records**;
a gap in the chain always becomes a record, never silence.

**Why here:** the journal is the source of truth; everything else is derived.

---

## Stage 3. Segments, Merkle, signatures

**Ours: 100%, except signatures (aws-lc-rs).**

- Segment closing, Merkle tree, manifest.
- Segment signature: ES256 now, ML-DSA-65 as a hybrid (behind the aws-lc-rs unstable flag).
- Atomic local publication (`rename` within a volume).
- Compaction (merge) of segments **without changing the truth**: the journal stays untouched.

**Done when:** verifying a single record costs log(n); a change of any byte
in a segment is detected; compaction changes no proof.

---

## Stage 4. Authenticated index

**Ours: 100%. This is the engine, part two, and the main differentiator.**

- **Merkle history tree** (the CT model, RFC 6962): proof that the journal was only appended to.
- **Sorted Merkle index per segment** over the provable dimensions: proofs of
  **inclusion and non-inclusion** via neighbouring leaves.
- Composing these two into a **completeness proof** of the answer.
- **One composition recursion** for all levels: `record → segment → shard → store →
  federation`; a level's root is a Merkle tree over the roots of the level below. It is written here once;
  federation at stage 12 only adds the transport and the peer registry.
- **Epoch root = Merkle tree over the roots of all shards**, so one external anchor is needed
  per store, not one per shard.

**Done when:** hiding a single record **breaks the proof**; the simulator's hostile scenarios
(removal, substitution, reordering, replay of an old segment) do not pass
unnoticed; a query across two shards gives a correct joint proof.

**Why here:** this is the reason a custom engine is being written. It cannot be bolted on later.

---

## Stage 5. Our read surface (core freeze)

**Ours: 100%.**

- Point and range queries over the provable dimensions, with pushdown into the index.
- **Run reconstruction**: a walk of the causal DAG, causal closure.
  **The walk is cross-shard**: the delegation chain (`on_behalf_of`, `parent_run_id`)
  connects different agents, that is, different shards, so `causal_closure()` composes
  proofs from several shards. This is designed here, not discovered at stage 12.
- `as_of`: bitemporal resolution, exactly one active row per (s, p) at any moment.
- Provability flag in **every** answer: `proof: full | partial` with a list of
  what is proven and what is not.
- REST + CLI.

**Done when:** reconstruction of a run over a million records takes < 1 s; no answer
leaves without a provability flag.

**From here on, the journal and index format is frozen.**

---

## Stage 6. Ingestion

**Ours: the ingestion path. Others': the protocols.**

- Internal ingestion API → first `Source`: HTTP + NDJSON.
  **First live data for the demo**: TokenFuse NDJSON events through **the same generic adapter**,
  on a par with any foreign source. This creates no coupling (the adapter does not know
  whose stream it is), and the demo gets real data instead of synthetic data.
- Then **OTLP** (gRPC + HTTP) as the primary external input.
- OTel GenAI semconv mapper: the stable part maps into typed fields, the rest
  **verbatim, but into the encrypted payload plane** (§5.2 g of the plan). A mapper that does not know
  where to put an attribute puts it in the encrypted plane, never in the metadata.
- Trust level per source: `occurred_at` from the emitter is marked untrusted,
  `recorded_at` is always ours, a divergence beyond a threshold becomes an event.
- Fail-open with respect to the emitter's traffic, but **the loss of a record itself becomes a record**.
- **Authentication on the ingestion surface**: `AuthProvider` is called before the body
  is read, `Action::Ingest` is authorized against the tenant, deny by default. Done
  2026-07-30, details above.

**Done when:** a third-party agent with standard OTel instrumentation writes to us
**with no change in it**; conformance on a real OTLP stream is green.

---

## Stage 7. Crypto, keys, erasure

**Ours: the mechanics. Others': the primitives (aws-lc-rs, FIPS 140-3).**

- Key hierarchy: **a DEK per payload** (AES-256-GCM), the DEK wrapped under a KEK
  via **HPKE with hybrid X25519 + ML-KEM-768**.
- **The subject is usually unknown at write time**: the KEK is per subject if the subject is known,
  otherwise per tenant. Later attribution is a **re-wrap** of the DEK under the subject KEK and destruction of the
  old wrapped key, and **both actions are chain events**, not a silent operation on the KMS.
- `KeyProvider`: file (dev) and **AWS KMS** (reference implementation).
- `forget`: destruction of the subject KEK + an `erasure` record in the chain; payloads that remained
  under the tenant KEK are erased by a separate operation from a list, and the list is also a record.
- Hostile tests: after `forget`, an attempt to recover the payload by **every** path
  (projections, caches, export, backup, replication log).

**Done when:** what was erased cannot be recovered by any path; the chain after erasure
**remains verifiable**; the fact of erasure is itself a record.

**Why here and not earlier:** the schema fields (`kem_alg`, `key_id`) have been in place since stage 1,
but the mechanics rest on a stable journal and segments.

---

## Stage 8. Proofs outward

**Ours: 100%.**

- **Evidence pack**: self-contained, self-describing, with all proofs and signatures.
- **Offline verifier** as a separate binary, **with no dependency on Trailryx**.
  **TCB minimisation**: a separate crate with a minimum of dependencies, written so that
  a person can read it in an hour. This is a direct answer to the auditor's question
  "who verified your code" (R6 of the plan).
- **Reproducible builds and published DST seeds**: anyone can reproduce our run
  and our binary byte for byte. **Done 2026-07-30**: `sim/corpus.tsv`,
  `scripts/reproduce.sh`, `docs/reproducing.md`; details above.
- Mapping to Art. 12 of the AI Act / SR 11-7 / SOC 2 as a **separate versioned layer**.
  **Done 2026-07-30**, `trailryx-compliance`, plus prEN ISO/IEC 24970 as a
  profile document; details above.
- `Anchor`: RFC 3161 TSA (reference implementation). **Done 2026-07-30**, details
  above: trust via a pinned key, full verification outside the verifier, and in the
  verifier ninety lines for binding to the root.

**Done when:** a pack is verified on a machine where Trailryx was never installed;
the verifier never drops support for an old algorithm, it only marks it as weak.

---

## Stage 9. Projections and export

**Ours: generation and rebuild. Others': the format (Parquet).**

- Lossless export to **Parquet**, itself verifiable.
- Rebuilding a projection **from the journal from scratch**, deterministically.
- Storage tiers: hot (NVMe) → warm → cold.

**Done when:** a projection that is thrown away entirely is restored from the journal
**byte for byte identically**; the export is read by a third-party tool without our code.

**Why here:** SQL (stage 10) reads projections, so they must exist earlier.

---

## Stage 10. SQL facade

**Others': the engine (DataFusion). Ours: `TableProvider` and the extensions.**

- DataFusion + **our `TableProvider`** with `supports_filters_pushdown`:
  predicates over the provable dimensions go **into our index**, not into a scan.
- **Physical isolation of runtimes**: the tokio-based facade lives on dedicated threads,
  not on the shard cores, reads only projections and snapshots, and talks to the core over channels.
- **A second independent implementation of the verifier** in another language (Go or Python), reading
  the same pack: two implementations that agree prove the format, not the author (R6).
- **pgwire**: the Postgres protocol → Grafana, Metabase, Superset, DBeaver, psql,
  any driver on release day.
- Dialect extensions: `AS OF TIMESTAMP`, `WITH PROOF`, `causal_closure()`.
- Forbidden: `INSERT` through SQL. Writes only through `Source`.

**Done when:** Grafana connects as to Postgres; `WITH PROOF` returns a proof;
**turning SQL off entirely does not break the core** (verified by a build test without DataFusion).

---

## Stage 11. Object storage and multi-cloud

**Ours: the logic. Others': the cloud SDKs.**

- `ObjectStore`: local FS, **S3**, GCS, Azure Blob, MinIO.
- **Atomic publication without a coordinator**: S3 `If-None-Match`,
  GCS `ifGenerationMatch`, Azure ETag. No etcd, no Consul.
- WORM optional: S3 Object Lock, GCS retention policy, Azure immutable blobs.

**Done when:** a segment is published atomically in three clouds; double publication
is impossible; the simulator with conditional-write errors creates no divergence.

---

## Stage 12. Federation

**Ours: 100%.**

- `Peer`, fan-out query, **proof composition** (the same construction as between shards).
- **Signed peer registry**: without it the answer is `proof: partial (peer set unattested)`.
- Verified replication: the receiver **verifies the chain** before accepting.
- Computation travels to the data (cross-cloud egress is money).

**Done when:** a query across two environments gives a correct joint proof;
**a "forgotten" peer breaks the completeness proof** instead of passing silently.

---

## Stage 13. Validation and release

- Long DST run: the equivalent of years of operation with no invariant violated.
- **Real kill run on ext4 and xfs**: the simulator is a model, and a real disk
  lies in its own way. A supplement to DST, not a replacement.
- Run on **both I/O backends** (io_uring and epoll) with the same result.
- Multi-cloud demo run (the eight steps of §9 of the plan) **twice in a row from scratch**.
- `qryx scan --policy cnsa` on our own storage with no violations.
- Fuzzing of all parsers; `cargo audit` in CI.
- `VALIDATION.md` with real numbers. README in the estate style.

---

## Boundary: ours and others', in brief

| Layer | Who writes it | Why |
|---|---|---|
| Journal, segments, compaction | **us** | this is the engine itself |
| Authenticated index, proofs | **us** | nobody else has this |
| Sharding, reactor, DST simulator | **us** | all the guarantees depend on them |
| Bitemporality, causality, erasure | **us** | product semantics |
| Evidence pack, verifier | **us** | our responsibility to the auditor |
| Crypto primitives | aws-lc-rs | own crypto = catastrophe; the value lies precisely in **FIPS validation** |
| SQL engine | DataFusion | 740 commits and 139 contributors in 11 weeks; our edge is not here |
| Parquet, Arrow | Apache | these are **exchange** formats; our own reader would defeat the point |

None of the borrowed parts is a foundation. Turn off SQL, Parquet and the external KMS,
and the database still writes, proves and erases. That is the check that the engine is ours.
