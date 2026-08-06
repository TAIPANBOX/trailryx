# Validation

Nothing in this file is an estimate, and nothing in it is a promise about a machine
other than the one it ran on, which is described at the bottom.

Two kinds of number appear, and the difference matters more than any individual
figure:

- **Held by the gate.** Re-derived on every push, and the push is refused if the
  number moves. **This section carries no date, on purpose.** The only date anybody
  could honestly put on it is the day somebody last typed it out, which says nothing
  about when it was last true. A fixed date over numbers that are re-derived on every
  push reads as reassurance while providing none.
- **Measured on demand.** Run when somebody asks. These *can* rot, so each one
  carries its command and its date. Unless its own section says otherwise, the date
  is **31 July 2026**; the federation transport below is 4 August 2026.

This header used to open with "every number here was measured on 31 July 2026", over
both kinds at once. It was true on the day it was written and could not stay true in
either direction: the gate re-measured its half on every push afterwards, and the
figures transcribed from it moved while the date stood still.

---

## Held by the gate

`.githooks/pre-push` runs eighteen checks and `.github/workflows/ci.yml` runs the same
eighteen, so a green push is a green pull request. The old wording here, "the same
fifteen plus `cargo audit`", recorded a real difference: the advisories check was
CI's alone until 4 August 2026. It is in both now, and the sets are identical. The
seventeenth arrived on 5 August, for a configuration field that was declared, given a
reason, and read by nothing. The eighteenth arrived on 6 August, for a scratch
directory two runs of one test binary were sharing without either of them knowing.

What a row may state, and it is a narrow licence: **what the check is set to do, and
what it refuses to see.** A parameter (200 seeds, 300 cases, 13 targets, 16 corpus
rows) moves only when somebody edits the check, and a zero the check refuses to move
past is the check itself. An *output* moves on its own, so a test count and a digest
are named here rather than quoted, and live where something owns them. Two rows below
used to quote an output. The test count had drifted, by 33 tests and by the crate that
arrived with the federation transport. The determinism digest had not, and that is
worth being exact about: nothing was holding it either. That check compares two runs
of one seed against each other and never against this page, so the figure here was
only ever as fresh as the last person who typed it out, and it happened to be fresh.

The commands are now the scripts, wherever a script exists, for the reason invariant
17 gives: a command retyped into a table loses a flag. The determinism row printed
`--seed 1 --steps 300` while the check runs seed 20260729 for 800 steps, and the
durability row left out `--honest-disk`, without which almost every seed reports a
violation, the exact opposite of the 0 standing beside it.

| What | Number | Command |
|---|---|---|
| Tests | the whole workspace suite, green. The count and the per-crate table are in the README, checked against the suite rather than against a copy of themselves | `cargo test --workspace` |
| Third-party dependencies in the verifier | 0 | `cargo tree -p trailryx-verify` |
| Third-party dependencies in the core | 0 | `./scripts/declared-deps.sh` |
| `unsafe` | forbidden at the workspace level, and grepped for | `grep -rn unsafe crates` |
| Determinism: same seed, twice | two runs of one seed, identical byte for byte. The digest is printed by the check, not recorded here; the recorded ones are the corpus's | `./scripts/determinism.sh` |
| Published seed corpus | 16 rows, 0 digest mismatches | `./scripts/seed-corpus.sh` |
| Durability sweep | 200 seeds, 0 violations | `./scripts/durability-sweep.sh` |
| Two verifiers, one verdict | agree on every pack | `cargo test -p trailryx-store --test two_verifiers` |
| Verifier build reproducibility | same binary from two paths | `./scripts/reproduce.sh` |
| Parsers under hostile bytes | 13 targets, 300 cases each, 0 panics | `cargo test -p trailryx-fuzz` |
| The durability check can fail | a lying `fsync` is caught | `cargo test -p trailryx-core --test determinism` |
| README numbers | the badge, the quoted total, every crate row, the rows' sum, the dependency count for the host it runs on, the image tag it tells people to pull, the stage badge against the roadmap, and no other tracked file stating a dependency count of its own | `./scripts/readme-numbers.sh` |
| Configuration fields nothing reads | 0, across every `Config`, `Limits` and `Policy` struct in the workspace. How many fields that is moves on its own, so the check prints it rather than this page quoting it | `./scripts/config-fields.sh` |
| Temp paths two processes would share | 0. Every path built from `temp_dir()` carries `std::process::id()`, so two runs of one test binary cannot take each other's scratch directory. How many such paths exist moves on its own, so the check prints it | `./scripts/temp-paths.sh` |

The gate takes about two minutes, most of it the SQL facade's dependency tree.

---

## Measured on demand

### The kill run: a real process, a real disk, a real `SIGKILL`

The simulator crashes the store at every point in a write. It is the reason to
believe the design, and it cannot be right about the disk, because it is a model of
one written by the same people who wrote the code it tests.

```
./target/release/trailryx-kill run 40
```

| Filesystem | Rounds | Highest acked | Acked records lost |
|---|---|---|---|
| **apfs** on `/dev/disk3s5` | 40 | 648 | **0** |
| **ext4** on `/dev/loop0` | 40 | 2,788 | **0** |
| **xfs** on `/dev/loop0` | 40 | 4,388 | **0** |

Each run recovers exactly four records beyond the ack, which is the sync interval.
Recovering more than was acked is expected: a write can land without its
acknowledgement being seen, and under-promising is the safe direction. Recovering
less would be the product being false about the sentence it is built on.

ext4 and xfs are real filesystems on loopback devices inside a Linux container on the
same Mac, made with `mkfs.ext4` and `mkfs.xfs` and mounted by the kernel:

```
docker run --privileged -v "$PWD":/src rust:1-bookworm sh /scripts/kill-linux.sh
```

**What the container costs the claim, stated rather than left to be discovered.** It
would weaken a power-loss test badly, because the barrier below the filesystem is a
file on APFS and a virtual block device rather than a platter. It costs this test very
little, because **this test kills a process, not a machine**: the kernel survives, the
page cache survives, and what is under examination is our recovery from a write torn
in the middle, which is filesystem and page-cache behaviour and is real Linux code
here. Buying a cloud machine would not change that either, since it is also
virtualised storage.

**What is still missing is the machine dying**, on every filesystem including APFS.
That needs a real power cut or a block layer that can be told to forget, and it is in
*not yet measured* below rather than implied by the table above.

### The long simulation run, and the run that proves it can see

Stage 13 asks for a long deterministic run. The gate does 200 seeds on every push,
which catches a regression; this is the one that goes looking.

```
trailryx-sim-run --seed 1 --sweep 400000 --steps 2000 --shards 3 \
  --sync-every 4 --crash-ppm 15000 --hostile --honest-disk
```

| | |
|---|---|
| Seeds | 400,000 |
| Steps each | 2,000 |
| Shard ticks | **800 million** |
| Crashes injected | at 15,000 ppm, so roughly 12 million |
| Simulated time | 2 seconds per seed, **9 days 6 hours** summed |
| Real time | 10 minutes 40 seconds, so about 1,250x |
| Durability violations | **0** |

Stage 13 asks for *years* of simulated time and this is nine days, so the gap is
stated rather than rounded away. It is also worth saying why the phrase is weaker
than it sounds: the simulator advances its clock by a millisecond per step because
some constant had to be chosen, and a run can be made to cover centuries by changing
that number without testing anything more. **Ticks and crashes are the honest units
here**, and years would be the flattering one.

**And the number that makes that one mean something.** A sweep reporting zero
violations proves nothing unless the same sweep can report a violation when there is
one. The gate already holds that property on every push, in a test named
`the_harness_catches_a_lying_fsync`, whose comment says what it is for: *if this test
stops failing to find violations, the crash model has gone soft*. What follows is the
same property at the scale of the run above, with the disk allowed to lie about
`fsync`, which is the write hole every durability contract is written against:

```
trailryx-sim-run --seed 900001 --sweep 20000 --steps 2000 --shards 3 \
  --sync-every 4 --crash-ppm 15000 --hostile
```

**17,869 of 20,000 seeds fail**, each naming its own seed, its digest and how many
lying syncs it took. That is the correct answer: a disk that acknowledges a sync it
did not perform breaks the promise by definition, and a harness that reported
otherwise would be blind rather than reassuring.

The two together are the claim: with a disk that keeps its word, 800 million
operations lose nothing, and the check that says so is a check that fails when the
disk stops keeping it.

### The acceptance demo, including against real object stores

```
cargo run --release --bin trailryx-demo -- --runs 2
```

Eight steps, twice in a row, from an empty directory, in **10.5 seconds**. Nothing in
it is narrated: each step does the thing and fails the run if it did not.

Stage 13 asks for that run to be **multi-cloud**, and until now it was not: the demo
always published into memory, and this file's *not yet measured* section did not say
so, which made it read as done. `TRAILRYX_DEMO_STORE` now chooses, with everything
else coming from the environment so no credential reaches a command line, and the run
prints where it published so a pass cannot later be mistaken for a pass against
memory.

| Store | Result |
|---|---|
| memory | eight steps, twice |
| **MinIO** over a real socket | eight steps, **twice** |
| **Azurite**, Microsoft's own emulator | eight steps, **twice** |

The second run is the one that matters and it was checked rather than assumed: the
bucket holds ten objects after two runs, with the two runs' payload keys distinct, so
the second genuinely published rather than meeting the first run's objects and
passing on them.

**What this still is not.** Both are emulators on this machine. The adapters
themselves have been run against real AWS and real Google Cloud Storage, above, but
the eight steps have not.

### The S3 adapter against somebody else's server

The suite in `store.rs` runs the adapter over a real socket against a fake that
speaks S3. The fake cannot disagree with us: it was written from the same reading of
the same documentation as the client, so wherever that reading is wrong, both are
wrong together and the tests pass. So the adapter was pointed at **MinIO
RELEASE.2025-09-07**, an implementation nobody here wrote, running locally.

```
docker run -d --name trailryx-minio -p 9000:9000 \
  -e MINIO_ROOT_USER=... -e MINIO_ROOT_PASSWORD=... minio/minio server /data
TRAILRYX_S3_ENDPOINT=http://127.0.0.1:9000 TRAILRYX_S3_BUCKET=trailryx \
TRAILRYX_S3_KEY=... TRAILRYX_S3_SECRET=... \
  cargo test -p trailryx-s3 --test live -- --nocapture
```

**It failed on the first request, and the reason is the point of the exercise.** The
adapter was sending **two `Host` headers**. SigV4 has to sign the host, so the signer
put `host` in its header list; `trailryx-http` writes `Host` for every request because
it owns the connection. Each was right alone. RFC 9112 requires a server to refuse a
request carrying two, and Go's HTTP layer does it before any S3 code runs, so the
answer was a bare `400 Bad Request` with a plain-text body, no error code, nothing in
the server's log.

That means the adapter had **never worked against a real S3 endpoint**, and the whole
suite was green. The fakes parsed headers into a list and never minded the duplicate.
A regression test now asserts exactly one `Host` reaches the wire, and the HTTP client
refuses a request that brings its own rather than silently sending a second.

With that fixed, against MinIO:

| | |
|---|---|
| The four operations | put, get, get by version, list |
| A second conditional write | **refused by the server**, and the first bytes survived |
| Listing across pages | 12 objects in pages of 5: 3 requests, 2 continuation tokens |
| Versioning | not enabled on this bucket, so `get_version` is untested and says so |

The conditional write is the one that matters. Atomic publication with no coordinator
rests on the store refusing the second writer, and until this run that rested on a
fake we wrote agreeing with a client we wrote.

**What this still is not.** MinIO is not AWS. It does not reproduce real error codes
under contention, throttling, or a real TLS chain, and this bucket has no versioning.
A run against a live bucket is in *not yet measured*, and it needs a credential and
costs money.

### The Azure adapter against Microsoft's own emulator

Shared Key signing is a harder version of the same risk than SigV4: the string to
sign is a fixed run of lines whose emptiness rules are documented in prose. Ours was
already pinned to Microsoft's two published worked examples, which is a strong check
on the algorithm and no check at all on everything around it.

```
docker run -d -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
  azurite-blob --blobHost 0.0.0.0
TRAILRYX_AZURE_ENDPOINT=http://devstoreaccount1.blob.localhost:10000 \
TRAILRYX_AZURE_CONTAINER=trailryx TRAILRYX_AZURE_ACCOUNT=devstoreaccount1 \
TRAILRYX_AZURE_KEY=... cargo test -p trailryx-azure --test live -- --nocapture
```

Put, get and list pass, and so does the one that matters: **Azurite refuses the
second conditional write and keeps the first blob's bytes.** No `Host` bug here, the
Azure client never added one, and the signature was accepted first time.

Two things the run pinned down that no fake would have:

- **The endpoint must be production-shaped**, with the account in the host. Aimed at
  Azurite's path-shaped default the signature is *accepted* and the answer is `404
  ResourceNotFound`, which sends a reader to the signer for an afternoon.
- **Azurite's debug log prints the string to sign it expected**, the same way the AWS
  CLI's debug output settles a SigV4 argument. That is what caught a `Content-Type`
  header a helper library had added on its own.

### Both clouds, for real, over TLS

The emulator runs above are worth what they are worth. This is the same suite against
**AWS S3 in eu-central-1** and **Google Cloud Storage**, over `https`, with a
versioned bucket on each. It cost a few dozen requests and a few kilobytes, which is
fractions of a cent, and both buckets were deleted afterwards.

| | AWS S3 | Google Cloud Storage |
|---|---|---|
| Four operations | pass | pass |
| A second conditional write | **refused by AWS**, first bytes kept | **refused by Google**, first bytes kept |
| Read back by version | `wd1hFJIEIn8FRY72u.UObyOr1DR86_hz` | generation `1785506773704642` |
| Paged listing | 12 keys in pages of 5, real continuation tokens | same, marker-based |
| Addressing | virtual-hosted | path |

**Two more defects, both found in the first minutes, neither findable without a real
endpoint.**

*Google closes a TLS connection without `close_notify`.* rustls reports that as an
unexpected end of file rather than an end of file, because at the TLS layer a
finished stream and one an attacker cut short look identical. This client read to EOF
and only then parsed, so **every single request to GCS failed with a TLS error while
the complete response sat in the buffer**. HTTP can tell the difference, because a
response carries its own framing, so an unexpected end is now treated as an end and
the parser judges: a body shorter than its `Content-Length` is refused and an
unfinished chunked body fails to decode. Three tests hold both halves, including the
one that must keep failing.

*A request to Google may not carry `x-amz-` headers.* Google accepts an
`AWS4-HMAC-SHA256` signature, which is why reads worked, but it answers `400
ExcessHeaderValues` to a request mixing the two families, and its only
conditional-write header is `x-goog-if-generation-match`. So this adapter could read
a GCS bucket perfectly and **could never publish a segment to one**, which is the
operation the entire design rests on. The signer now speaks both dialects:
`GOOG4-HMAC-SHA256`, the `GOOG4` key prefix, the `goog4_request` terminator, the
`storage` service, and the `x-goog-` header family throughout.

### GCS: no free second implementation, which is why the above was needed

The GCS support is not a second adapter. Google Cloud Storage's XML API *is* the S3
API, so `Flavour::Gcs` changes four things and reuses the rest: the header that makes
a write conditional, the header naming the version, the parameter asking for one, and
the older marker-based pagination.

The obvious way to check it the way MinIO and Azurite checked the others is
`fake-gcs-server`, and it cannot do the job. It routes a `PUT` on the XML path into
its JSON upload handler and answers `400 invalid uploadType`, with or without
`x-goog-if-generation-match`, so it never reaches the behaviour under test. Google
publishes emulators for Pub/Sub, Firestore, Bigtable, Datastore and Spanner, and none
for Cloud Storage.

That left GCS checked against our own fake and against Google's documentation and
against nothing Google wrote, which was exactly the position the S3 adapter was in on
the morning of the day its `Host` bug was found.

**It did not stay there. That gap was closed the same day**, by the live run recorded
under *Both clouds, for real, over TLS* above: a real bucket, an interoperability HMAC
key, generation `1785506773704642` read back, and Google itself refusing the second
conditional write. It found two defects in the first minutes, and neither was findable
without a real endpoint, which is the argument for the run in one sentence.

This paragraph used to end by saying the gap needed credentials and money and was
listed in *not yet measured*. Both halves were wrong by the time anyone read them: the
run had happened, and that section names GCS among the clouds already exercised. The
paragraph was written before the run and never revisited, which is the ordinary way a
validation record starts lying: not by inventing a measurement, but by keeping the
sentence that described the world before one.

### Fuzzing depth

The number that keeps the fuzz suite honest is not how many cases ran, it is how many
inputs each parser **accepted**, because a suite whose inputs all die at byte one runs
quickly and proves nothing.

```
TRAILRYX_FUZZ_CASES=50000 cargo test -p trailryx-fuzz --release -- --nocapture
```

650,000 cases, 0 panics, and 11 of the 13 targets reach past the first check:

| Target | Accepted of 50,000 |
|---|---|
| `json::Framer` | 50,000 |
| `asn1::Der` | 24,158 |
| `otlp::decode_trace_request` | 21,657 |
| `http::parse_response` | 19,721 |
| `store::cold::decode_envelope` | 16,197 |
| `store::evidence::decode_manifest` | 16,070 |
| `journal::wire::decode_record` | 12,040 |
| `s3::xml` | 10,728 |
| `azure::base64_decode` | 9,728 |
| `json::validate` | 8,136 |
| `store::cold::decode_body` | 6,595 |
| `verify::tsp::read` | **0**, rejection path only |
| `verify::Pack` | **0**, rejection path only |

The two zeroes are stated rather than hidden: their valid inputs are a real timestamp
token and a real evidence pack, which need an authority and a sealing run
respectively. They are exercised for rejection, which is worth something and is not
the same thing.

### Dependencies

```
cargo tree -p trailryx-sql
```

297 distinct third-party crates behind the SQL facade on macOS, 294 on Linux, because
part of any dependency tree is platform-specific. 279 of them ship (`-e normal`); the
rest arrive to build and to test it.

Two of those three sit in the wrong section and are left here for one place to look:
`scripts/readme-numbers.sh` runs that command on every push and compares the README's
figure for the host it is running on, so 297 is held by the hook on a Mac and 294 by
CI on Linux. The 279 is the one nothing measures: it is the 31 July figure, and what
the gate holds about it is only that no file disagrees with the README about it.

Since 6 August 2026 that last part is the rule for all three. The README is the one
place any of them is stated as a measurement, and the gate refuses a push when any
other tracked file states a count of its own, this file included. Everything outside the facade, the cryptographic
provider and the demo has none, and the verifier has none by design: an auditor reads
it, and every crate pulled in is a crate they are asked to trust instead.

### The cryptographic inventory, and the scan that was passing for the wrong reason

Stage 13 asks for `qryx scan --policy cnsa` on this repository with no violations.

```
qryx scan --policy cnsa .
```

| | |
|---|---|
| Sources scanned | 211 |
| Findings | 58, in 10 unique assets |
| Policy `cnsa` | **PASS**, exit 0 |

**The first run of this passed, and the pass was worthless.** It reported 3 findings
in 2 assets, and both were in a Python script that generates test vectors. Not one
came from the 169 Rust files, including the one that implements ECDSA P-384 and
contains the string `ECDSA` three times. The reason: qryx's crypto detector carried
patterns for Python and JS/TS, Go had its own AST detector, and **there was nothing
for Rust at all**. A pass from not looking is worse than no scan, because somebody
files it as evidence.

That is fixed in qryx rather than worked around here: a Rust detector that strips
comments and string literals before matching, so a doc comment explaining that ECDSA
is quantum-vulnerable is not counted as using it. It also turned up a false positive
worth its own fix: a comment in `trailryx-store/Cargo.toml` ending "...pins the two
independent token readers together" was reported as a dependency on the **Together AI
SDK**, in a workspace whose store crate has no dependencies at all.

**What the honest inventory says.** Ten assets: SHA-384 (26 occurrences), SHA-256,
AES, HMAC, ML-DSA, ML-KEM, SLH-DSA, and three quantum-vulnerable ones, ECDSA, ECDH
and RSA. The last three are not a surprise and not a defect:

- **ECDSA P-384** is what a segment root is signed with, and there is no
  post-quantum signature in v1 by decision: the verifier has to stay short enough to
  read.
- **RSA** is in the anchor, which verifies an RFC 3161 timestamp authority's
  certificate, and the authority chooses that, not this project.
- **ECDH** is the X25519 half of `X25519MlKem768`, the hybrid key exchange. qryx has
  no way to say "hybrid", so it reports the classical half on its own, which is
  correct as an inventory line and misleading as a risk line.

`cnsa` passes because the builtin policy forbids MD5, SHA-1, DES, 3DES, RC4, RC2, DSA
and RSA under 3072 bits, none of which appear, and deliberately does not gate on
quantum-vulnerability, which has a 2030 deadline rather than an immediate one. Asked
the strict question instead, the answer is the one above:

```
qryx scan --policy pq-strict.json .     # forbidQuantumVulnerable: true
```

**FAIL, 3 violations**: ECDSA, ECDH, RSA. That is the true position of the signature
layer today, and it is the same thing the architecture already says in prose.

### What was changed so this class stops recurring

Three defects in one day, all the same shape: **a fake written from the same reading
of the same documentation as the client agrees with the client's mistakes**. Patching
three bugs would leave the fourth. So:

- **The fake refuses what a compliant server refuses**, before any storage logic:
  more than one `Host`, any header twice, and `x-amz-` headers sent to Google or
  `x-goog-` ones sent to AWS. Every test that touches the fake now carries those
  rules, not just a test written for them. Reintroducing the `Host` bug fails **11 of
  12** tests in the crate; signing Google the AWS way fails 3.
- **The HTTP client refuses a request that brings its own `Host`**, rather than
  writing a second one, so the class cannot come back through another caller.
- **The response read loop is a function over any reader**, so both endings can be
  tested: a complete response after an unclean close is accepted, a truncated one is
  still refused. The second test is what keeps the first safe.
- **No test waits without a bound.** Teaching the fake to refuse turned one failing
  test into a run that never ended: no failure, no name, no output. The fake's socket
  now has a timeout and every wait for a request is bounded, so the answer is always
  a test result. Finding that cost more than the bug it hid.
- **`tests/live.rs` in both adapter crates**, run against any endpoint given in the
  environment and printing `skipped` with a reason when there is none.

### Oracles

Nothing here grades its own homework where a second implementation exists:

| Ours | Checked against |
|---|---|
| SHA-384, ECDSA P-384, base64 | **OpenSSL** |
| RFC 3161 token reading | a token issued by **OpenSSL**'s timestamp authority |
| Parquet writing | **pyarrow**, at the type level |
| AWS SigV4 | the **AWS CLI**'s own debug output, byte for byte |
| Azure Shared Key | **Microsoft's published worked examples**, byte for byte |
| JSON | **node**, **CPython** and **Ruby** |
| Civil dates | **Python**'s `datetime` |

A test whose oracle is absent prints `skipped` and says so, because a check that
quietly passes when it did not run is the thing this project is against.

### Adversarial review

Two runs, each finding handed to three skeptics instructed to refute it.

| | Transport | Core |
|---|---|---|
| Lenses | 6 | 9 |
| Agents | 96 | 140 |
| Candidates | | 47 |
| Refuted | | 25 |
| Real | | **16** (5 critical, 3 high, 7 medium, 1 low) |

The worst: one flipped bit in a twenty-byte header destroyed an entire journal while
the report said `records: 0, is_suspicious() == false`. Fifteen of the twenty header
bytes did it. Next to each of the five critical findings sat a comment promising the
opposite.

---

### The federation transport, over real sockets and real mutual TLS

```
cargo test -p trailryx-federation-grpc
```

18 tests, 5 August 2026: six over the codec, nine that bind a loopback listener and
complete a real TLS 1.3 handshake against a certificate authority the test creates,
and three that carry a chain across that wire and re-verify it on the far side.
Nothing is mocked, because a mocked transport agrees with whatever the transport
does, including its mistakes, and two of its mistakes are the only interesting
results here.

This line said 15 until today, and it was right when it was written: the nine and
this paragraph arrived in the same commit on 4 August, and `replication_over_the_wire`
added three more to the same crate later the same day. Half a day of accuracy, from a
figure that carried its own date and its own command and still needed somebody to come
back and run it. The copy with an owner is the crate's row in the README, which the
gate checks against the suite, and it says 18 as well.

**What the run establishes.** Two environments answering completely compose to a
complete answer, and the roadmap's stage-12 criterion holds on a wire rather than in
memory. A registry naming three environments while two answer yields a partial proof
with the third named. A peer that is down is silent rather than empty. A peer's own
partial answer stays partial after crossing. A stream that ends before its trailer is
refused outright, and inside a fan-out that peer contributes nothing rather than a
plausible-looking two thirds.

The three added later hold the assumption verified replication rests on: the bytes a
chain covers cross protobuf unchanged, a chain still verifies after the round trip,
and a record altered after the wire is still refused. Without them a lossy codec would
report a broken chain rather than reporting itself.

**What it found.** Two things, both by a test failing first.

The transport was **weaker than the ingest door it sits beside**. It parsed an
arriving `agent_id` with the lax constructor `trailryx-journal` uses for records it
wrote itself, so a peer could have sent an identifier with no `agent://` scheme and
had it stored, while the same value arriving through `trailryx-otlp` would have been
refused. Now invariant 23, with the test that caught it.

**Mutual TLS refuses later than it looks.** The first version of the client-authority
test asserted that `connect` fails for a certificate signed by an authority we do not
trust. It does not. Under TLS 1.3 the server sends its own Finished before processing
the client certificate, so an unauthorised client connects successfully and is refused
on its first request instead. The property that actually holds, and the one now
asserted, is that such a client ends the exchange with no records. Measured against a
real handshake, not read from a specification.

The name-from-certificate check was then **shown to be load-bearing** rather than
decorative: with the expected name replaced by a constant, five of the nine tests
fail, including the impersonation one.

---

### The SQL facade, read on 5 August 2026: one real defect and one false claim

```
cargo test -p trailryx-sql --test wire
```

**The proof slot was process-wide while the function that reads it says "session".**
`serve_on` built one `Handlers`, over one `Session`, over one `SessionContext`, and
Arc-cloned it into every connection's task. Every table and table function registered
on that context shared one proof slot, so `trailryx_proof()` answered about the last
query **anybody** had run on that server. A reader who ran a query the index could not
prove and then asked for its proof was told `full` if a stranger's provable query had
landed in between: an unproved answer reported as proved, through the one function
whose purpose is to prevent exactly that. It went in either direction and it also gave
a brand new connection a verdict about a query it had never run.

Fixed by making a session per connection: `Session::for_connection` forks a fresh
`SessionContext`, table and slot over the same `Arc<Vec<Segment>>`, so the isolation
costs a pointer rather than a copy of the trail. A per-connection *service* was
considered and does not work, which is worth recording because it looks like it would:
`SessionContext` is `Clone` over an `Arc<RwLock<SessionState>>`, so every service built
from one session resolves the same registered tables and the same slot. A task-local
slot was considered and refused: it holds only while nothing between `context.sql` and
the table provider's scan crosses a task boundary, and the failure mode is a silent
fall back to a shared slot, which is this defect again with a mechanism that hides it.

Two tests, both run against the unfixed code first and both failing there.
`two_connections_each_read_their_own_proof_and_never_the_others` reported `full` where
`partial` was true, and `a_fresh_connection_has_proved_nothing_however_busy_the_server_is`
reported `full` where `none` was true. Now invariant 26.

**The read surface has no row filtering, and three documents implied it had.** Not a
code change: authorisation on the Postgres port is one `Action::Query` decision at
connect time against a scope fixed when the server was built, and past it every
authenticated client reads every record in every segment that server registered,
whatever the `tenant` field says. Nothing on the read path takes a principal or a
tenant. The unit tests showing two gates with different scopes refusing each other's
principals read as tenant isolation and are really two servers in one test. The
constraint is now stated in `SECURITY.md`, in the README's SQL section and on
`ReadGate` itself, in the form a deployer needs: **one server per scope**.

**`Action::ReadMetadata` is never requested from an `AuthProvider`.** The module doc
and the README both described raw journal access as that action "asked for
separately".

```
grep -rn --include='*.rs' '\.authorize(' crates/     # 11 call sites
```

Six are in `trailryx-contracts/src/conformance.rs`, which asks a provider for
`ReadMetadata`, `ReadPayload`, `Query` and `Erase` in turn precisely to check that it
tells them apart; that is a test of somebody's provider, not a request from this
store. Three are inside `trailryx-ingest/src/bearer.rs`'s `#[cfg(test)] mod tests`.
The two in a production path are `Action::Query` in `trailryx-sql/src/server.rs:178`
and `Action::Ingest` in `trailryx-ingest/src/auth.rs:180`. **No path asks for
`ReadMetadata`.**

What exists instead is `raw: bool` on `Session::with_raw_access`, decided once for the
whole server, and `grep -rn with_raw_access` finds two definitions and five callers,
all five of them tests in `crates/trailryx-sql/tests/sql.rs`. Both documents now
describe the flag that exists. Implementing the grant is a second `authorize` call
somewhere the principal is known, which is not where the flag is: the catalog is fixed
when the session is built and the principal arrives at connect time.

---

## Not yet measured

Stated so the absence is visible rather than inferred:

- **The federation transport across an actual network.** Everything above is
  loopback. A handshake to `127.0.0.1` is a real handshake and is not a real network:
  no latency worth the name, no packet loss, no MTU, no middlebox, no partition, and
  no clock disagreement between the two ends. Two environments in two clouds is the
  test this one stands in for, and it has not been run.
- **The first link of an unanchored run.** Verified replication is built
  (`trailryx-federation::replication`, 2026-08-04) and the chain is now recomputed
  before a peer's records are adopted: altered, removed, duplicated and reordered
  records are all refused, measured by eleven tests that each reach one refusal and
  by five deliberate breakages of the implementation. What it cannot do is check
  where a run STARTS when the receiver holds no prior head for that shard. A peer
  that invented a history from a fabricated head passes `accept_unanchored`, because
  a fabricated chain is internally consistent: that is what a chain is. This is a
  limit of the problem, not of the code, and it is why the weaker entry point has a
  name rather than a flag. `accept_from`, which every receiver that already knows the
  shard should use, has no such gap.

  Two things this rests on and does not itself prove: that both sides encode a record
  to the same bytes (invariant 7 freezes the format; `encoding_is_canonical` in
  `trailryx-journal` tests it), and that protobuf does not move a byte on the way
  (`replication_over_the_wire` tests exactly that, because a lossy codec would report
  a broken chain rather than reporting itself).
- **A machine dying rather than a process.** Every kill run above is a `SIGKILL`,
  so the kernel and its page cache survive it. Power loss, where the disk's own cache
  is allowed to forget what it acknowledged, is a different and harsher test. The
  simulator models it (that is what the lying-`fsync` sweep is), but nothing has run
  it against a real block layer, for instance under `dm-log-writes`.
- **Both I/O backends.** Not "not measured", which is what this line used to say and
  which was flattering: **neither exists**. There is one `Io` implementation, on the
  standard library's blocking file API, behind the same trait the simulator fills.
  `io_uring` and `epoll` are a decision the architecture records and nobody has
  implemented, so there is nothing to run side by side yet.
- **The eight-step demo against a real cloud.** It now runs twice against MinIO and
  twice against Azurite, above, which is two real servers and no real cloud. Pointing
  it at the AWS and GCS buckets that the adapter suite used would need them to exist
  again, and they were deleted.
- **Azure against real Blob Storage: decided against**, not pending. S3 and GCS have
  been run against their own clouds; Azure has met Azurite and will not be taken
  further. Recorded as a decision so nobody reads it later as unfinished work.
- **Contention, throttling and failure modes.** Every live run above was one client
  doing one thing at a time. Two publishers racing for the same key against a real
  endpoint, and what a throttled or half-failed request does to a publication, are
  not tested anywhere but the simulator.
- **Years of simulated time.** The long run above covers nine days, not years, and
  the arithmetic for closing that gap is in its own section.
- **Read authorisation past the connect-time door.** Not "not measured": **not
  built**. The SQL surface authorises once, per connection, against a scope fixed when
  the server was built, and does no per-principal or per-tenant row filtering
  afterwards. Neither does it ask for `Action::ReadMetadata`. Both are recorded above,
  in `SECURITY.md` and in the README, so the deployment model (one server per scope)
  is something a deployer reads rather than infers.
- **An external audit of the cryptographic layer.** Planned before the first
  compliance contract, and not started.

---

## The machine

Apple silicon, macOS, APFS, Rust 1.96.1, 31 July 2026. Every command under *measured
on demand* was run on it, and none of those numbers should be assumed to hold on
hardware that is not it. The gate's eighteen also run on CI's Linux runners, which is
the whole reason the dependency count is two figures rather than one.
