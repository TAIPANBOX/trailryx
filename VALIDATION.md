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
| Tests | 1,022 across 28 crates | `cargo test --workspace` |
| Third-party dependencies in the verifier | 0 | `cargo tree -p trailryx-verify` |
| Third-party dependencies in the core | 0 | `./scripts/declared-deps.sh` |
| `unsafe` | forbidden at the workspace level, and grepped for | `grep -rn unsafe crates` |
| Determinism: same seed, twice | identical digest `b9b9663ec65feb8a` | `trailryx-sim-run --seed 1 --steps 300` |
| Published seed corpus | 16 rows, 0 digest mismatches | `trailryx-sim-run --corpus sim/corpus.tsv` |
| Durability sweep | 200 seeds, 0 violations | `trailryx-sim-run --seed 1 --sweep 200 --hostile` |
| Two verifiers, one verdict | agree on every pack | `cargo test -p trailryx-store --test two_verifiers` |
| Verifier build reproducibility | same binary from two paths | `./scripts/reproduce.sh` |
| Parsers under hostile bytes | 13 targets, 300 cases each, 0 panics | `cargo test -p trailryx-fuzz` |
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

| | |
|---|---|
| Rounds | 40 |
| Filesystem | **apfs** on `/dev/disk3s5` |
| Highest acked sequence | 648 |
| Acked records lost | **0** |
| Recovered beyond the ack | 4 records per round, which is the sync interval |

Recovering more than was acked is expected: a write can land without its
acknowledgement being seen, and under-promising is the safe direction. Recovering
less would be the product being false about the sentence it is built on.

**What this is not.** The roadmap asks for ext4 and xfs. This machine has neither, so
the run above is APFS and says so in its own output. It is worth more than nothing
and less than what stage 13 asks for, and both of those are true at once.

### The acceptance demo

```
cargo run --release --bin trailryx-demo -- --runs 2
```

Eight steps, twice in a row, from an empty directory, in **10.5 seconds**. Nothing in
it is narrated: each step does the thing and fails the run if it did not.

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

- **ext4 and xfs kill runs.** Only APFS so far, above.
- **Both I/O backends.** `io_uring` and `epoll` have not been run side by side.
- **A multi-cloud demo run.** The three adapters are tested against fakes over real
  sockets and against published worked examples; none has been run against a live
  bucket, which needs credentials and costs money.
- **A long DST run.** The sweep is 200 seeds per push, not the years of simulated time
  stage 13 asks for.
- **An external audit of the cryptographic layer.** Planned before the first
  compliance contract, and not started.

---

## The machine

Apple silicon, macOS, APFS, Rust 1.96.1, 31 July 2026. Every command above was run on
it, and none of the numbers should be assumed to hold on hardware that is not it.
