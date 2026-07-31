# Validation

Every number here was measured on **31 July 2026**, with the command printed next to
it, on the machine described at the bottom. Nothing in this file is an estimate, and
nothing in it is a promise about a machine other than the one it ran on.

Two kinds of number appear, and the difference matters more than any individual
figure:

- **Held by the gate.** Re-measured on every push, and the push is refused if the
  number moves. These cannot rot.
- **Measured on demand.** Run when somebody asks, dated here. These *can* rot, so
  each one carries its command and its date, and this file is the only place they are
  quoted.

---

## Held by the gate

`.githooks/pre-push` runs fifteen checks and `.github/workflows/ci.yml` runs the same
fifteen plus `cargo audit`, so a green push is a green pull request.

| What | Number | Command |
|---|---|---|
| Tests | 1,028 across 28 crates | `cargo test --workspace` |
| Third-party dependencies in the verifier | 0 | `cargo tree -p trailryx-verify` |
| Third-party dependencies in the core | 0 | `./scripts/declared-deps.sh` |
| `unsafe` | forbidden at the workspace level, and grepped for | `grep -rn unsafe crates` |
| Determinism: same seed, twice | identical digest `b9b9663ec65feb8a` | `trailryx-sim-run --seed 1 --steps 300` |
| Published seed corpus | 16 rows, 0 digest mismatches | `trailryx-sim-run --corpus sim/corpus.tsv` |
| Durability sweep | 200 seeds, 0 violations | `trailryx-sim-run --seed 1 --sweep 200 --hostile` |
| Two verifiers, one verdict | agree on every pack | `cargo test -p trailryx-store --test two_verifiers` |
| Verifier build reproducibility | same binary from two paths | `./scripts/reproduce.sh` |
| Parsers under hostile bytes | 13 targets, 300 cases each, 0 panics | `cargo test -p trailryx-fuzz` |
| The durability check can fail | a lying `fsync` is caught | `cargo test -p trailryx-core --test determinism` |
| README numbers | badge, totals and every crate row | `./scripts/readme-numbers.sh` |

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

### The acceptance demo

```
cargo run --release --bin trailryx-demo -- --runs 2
```

Eight steps, twice in a row, from an empty directory, in **10.5 seconds**. Nothing in
it is narrated: each step does the thing and fails the run if it did not.

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

### GCS: the one with no free second implementation

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

So **GCS is checked against our own fake and against Google's documentation, and
against nothing that Google wrote**, which is exactly the position the S3 adapter was
in the morning of the day its `Host` bug was found. Closing it needs a real bucket and
an interoperability HMAC key, which is credentials and money, and it is in *not yet
measured* with the others.

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
rest arrive to build and to test it. Everything outside the facade, the cryptographic
provider and the demo has none, and the verifier has none by design: an auditor reads
it, and every crate pulled in is a crate they are asked to trust instead.

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

## Not yet measured

Stated so the absence is visible rather than inferred:

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
- **A live cloud bucket.** S3 now runs against MinIO and Azure against Azurite, both
  above, and neither is the cloud it stands for: no real error codes under
  contention, no throttling, no real TLS chain, no versioned bucket. GCS has nothing
  at all, for want of an emulator that implements its XML API. The `Host` bug is the
  argument for spending the few cents this would cost: one request to a real server
  said what our whole suite could not.
- **Years of simulated time.** The long run above covers nine days, not years, and
  the arithmetic for closing that gap is in its own section.
- **An external audit of the cryptographic layer.** Planned before the first
  compliance contract, and not started.

---

## The machine

Apple silicon, macOS, APFS, Rust 1.96.1, 31 July 2026. Every command above was run on
it, and none of the numbers should be assumed to hold on hardware that is not it.
