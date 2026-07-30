# Contributing

The bar here is unusual in one specific way, so it is worth stating before you spend
an afternoon: **a change arrives with the test that would have caught the thing it
fixes.** Not a test that exercises the new code, a test written from the attacker's
side that fails before the change and passes after it. Most of the tests in this
repository exist because something was measured to be wrong, and each one names what
it was.

## Getting set up

```bash
git clone https://github.com/TAIPANBOX/trailryx
cd trailryx
git config core.hooksPath .githooks   # once
cargo test
```

There is nothing to install beyond a Rust toolchain. Every crate except
`trailryx-sql` has **zero third-party dependencies** and the gate enforces it, so a
pull request that adds one outside the facade needs to argue for it in the description
rather than in `Cargo.toml`.

`trailryx-sql` is the SQL facade and it is the exception on purpose: DataFusion and
the Postgres wire protocol, 297 transitive crates, decided on 30 July 2026 with
`docs/planning/trailryx-architecture.md` §3.1 behind it. Two gate checks hold the
boundary: everything else has zero, and the core builds and tests with the facade
absent. **A change that makes the core depend on the facade will fail the second one**,
and that is the check to read the failure of rather than to work around.

Some tests reach for `python3`, `node` or `openssl` as third-party oracles, because a
hand-written SHA-384, ECDSA, Parquet writer or JSON parser checked only against
itself proves nothing. Those tests print `skipped` and say so when the tool is
absent; a check that quietly passes when it did not run is the thing this project is
against.

## Before you push

`.githooks/pre-push` runs twelve checks and refuses the push if any fails:
formatting, clippy with warnings as errors, the whole test suite, a standalone build
of the substrate crate, the zero-dependency count, an `unsafe` scan, the determinism
criterion (one seed reproduces a run byte for byte), the published seed corpus in
`sim/corpus.tsv`, the Python verifier in `verifier-py/` agreeing with the Rust one on
the same packs, a reproducible build of the offline verifier from two directories with
different names, and a two-hundred-seed durability sweep. About forty seconds.
It is the same set `.github/workflows/ci.yml` runs, so a green push is a green pull
request.

If a change moves a digest in `sim/corpus.tsv`, that is either a defect or a
deliberate change to the store's behaviour, and the pull request has to say which.
`docs/reproducing.md` covers how to regenerate it and why the diff has to be read
rather than committed.

## House style, and why each rule is there

- **A comment states the defect the code prevents**, with the measurement or the
  reason, and does not narrate what the next line does. Read
  `crates/trailryx-journal/src/wire.rs` or `crates/trailryx-otlp/src/otlp.rs` for
  the voice.
- **A test is named as a sentence stating the property**:
  `a_lone_surrogate_is_refused_rather_than_truncated`, not `test_surrogate`.
- **A bound has its number and its reason in the same place.** See
  `crates/trailryx-ingest/src/config.rs` and `crates/trailryx-json/src/lib.rs`.
- **No `unsafe`.** Forbidden at the workspace level.
- **No long em dashes** in code, comments, docs or commit messages. A comma, a colon,
  parentheses or a short hyphen. The local `grep` on some machines misses U+2014, so
  check with something that reads bytes.
- **Counters use `saturating_add`.** The test profile turns on overflow checks, so a
  plain `+` on a `u32` counter is a panic waiting for a large file.

## What a good pull request looks like

- One defect or one capability. The commit message says what was measured, what was
  wrong, and what the fix does, in that order.
- If it changes a stated guarantee, it changes the document that states it:
  `docs/durability.md`, `docs/identifiers.md`, or the README section that claims it.
- If it changes a number the README prints, it changes the number. Stale status
  sentences outlive the work they described, and this repository has already shipped
  two of them.
- If it touches the record format, it does not. The canonical record is frozen: every
  hash, chain and published root depends on those bytes. A format change needs a
  version and a migration, and that is a conversation before it is a diff.

## Where the open work is

`docs/planning/trailryx-roadmap.md` is the working record, in Ukrainian, and it is
where each stage says what it did **not** do, stage by stage. Every review finding
raised so far has been measured and either fixed or refuted, so the open work is now
the named gaps rather than a candidate list: gRPC, a validated cipher behind the AEAD
seam, the SQL facade, object storage, federation, and a second independent
implementation of the offline verifier in another language.

`docs/planning/trailryx-architecture.md` is the design and it wins over any summary,
including the ones in this file and in the README. A sentence here that contradicts it
is a defect in the sentence.
