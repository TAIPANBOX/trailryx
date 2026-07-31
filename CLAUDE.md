# Working on Trailryx

**Before writing a line of code, read [`docs/planning/trailryx-architecture.md`](docs/planning/trailryx-architecture.md) and [`docs/planning/trailryx-plan.md`](docs/planning/trailryx-plan.md) in full.** They are the approved decisions; this file is only their enforceable summary, and where the two disagree, those two win. [`docs/planning/trailryx-roadmap.md`](docs/planning/trailryx-roadmap.md) is the single source of what order things happen in.

Everything below is a rule, not a description. Each one says what holds it today:

- `(gate: <path>)` a check that refuses the push. Most live in `scripts/`; a few are still written inline in `.githooks/pre-push`, and that difference matters, see the debt list.
- `(test: <name>)` a test, and nothing else.
- `(not checked)` this line is the only thing holding it. Treat those as the fragile ones.

---

## Invariants

1. **Never write `unsafe`.** The workspace lint forbids it and the gate greps for it anyway. *(gate: .githooks/pre-push)*

2. **Never add a third-party dependency to the core or to `trailryx-verify`.** A dependency belongs in an L2 adapter, and that adapter's crate name must be added to the allow-list in the gate script before its dependency will build. The reason is not minimalism: an auditor reads the verifier, and every crate pulled into it is a crate they are asked to trust instead of read. Everything else (a validated cipher, a post-quantum KEM, TLS, a SQL engine) is taken from whoever does it better than we would, because nobody buys a proof store for its author's AES. *(gate: scripts/declared-deps.sh)*

3. **The core must build and pass its tests with every adapter absent.** If it cannot, an adapter has got into the foundation. *(gate: scripts/declared-deps.sh)*

4. **Never read a clock, a random number, a disk or a socket directly from the core.** Go through `Clock`, `Rng`, `Io`, `Net`, or deterministic simulation stops working and every guarantee built on it stops meaning anything. *(gate: .githooks/pre-push, determinism)*

5. **Never put free text in the metadata plane.** Typed fields only: identifiers, enums, hashes, numbers, timestamps. Any prose lives in the encrypted payload plane under the subject's key, or `forget` leaves personal data behind and the promise is false. *(test: no_prompt_text_reaches_the_metadata_plane)*

6. **A mapper that does not know where an attribute belongs puts it in the encrypted plane.** Never in metadata, never dropped. *(test: every_attribute_lands_in_exactly_one_plane)*

7. **Never redefine a field in place.** The record and journal formats are frozen: a change is a new version plus a migration, and old versions keep parsing. *(test: a_version_two_pack_still_parses)*

8. **Do not add a post-quantum signature in v1.** The KEM is hybrid X25519 + ML-KEM-768 from day one because crypto-erasure only lasts as long as the KEM; the segment signature stays ES384, and SLH-DSA waits for a validated implementation. *(test: defaults_are_the_post_quantum_ones)*

9. **Never remove an algorithm from the verifier.** Mark it weak. Dropping ES256 destroys the provability of everything signed with it. *(not checked)*

10. **Never compile a compliance framework's vocabulary into the format or the core.** The mapping is its own versioned crate, because the standards it maps to are still drafts. *(not checked)*

11. **Never claim compliance in anything this repository emits.** The wording is "covers the requirements of Article 12", not "compliant", until a standard is cited in the Official Journal. *(test: nothing_this_crate_emits_says_compliant)*

12. **Records arrive only through a `Source`.** SQL reads; it never writes, or the journal stops being the only truth. *(test: every_way_of_writing_is_refused)*

13. **An answer whose predicates do not all land on the provable dimensions must say so.** Mark it partial rather than let a reader take it as proved. *(test: a_predicate_off_the_provable_dimensions_answers_correctly_and_says_partial)*

14. **Every adapter passes the conformance suite before it enters a build.** *(test: reference_object_store_conforms, and its siblings in `crates/trailryx-contracts/tests/conformance_suite.rs`)*

15. **Never fix the shard count by counting cores, and never re-split it.** Shard identity is inside proof paths, so redistributing afterwards breaks proofs already issued; a different count is a new store epoch with explicit lineage. *(not checked)*

16. **If two places need the same value, export it from one and import it in both.** Two functions computing what is meant to be one number is how a publisher and a reader end up disagreeing about the same object. *(not checked)*

17. **If a check exists in two places, it is one file that both call.** *(not checked, and currently violated: see the debt list)*

18. **Never let a test wait without a bound.** A hanging test reports nothing at all: no failure, no name, no output, which is less than a wrong answer tells you. *(not checked)*

19. **Never report "nothing found" without a run where the same check does find something.** A check that cannot fail reports zero forever. *(test: the_harness_catches_a_lying_fsync)*

20. **A fake must refuse what a compliant server refuses.** A fake written from the same reading of the same documentation as the client agrees with the client's mistakes, so it has to be taught the rules the client is not allowed to break. *(test: the_request_carries_exactly_one_host_header)*

---

## What is a gate, and what is still only a sentence

**Decisions that became gates.** Zero dependencies outside the declared list, the core standing up without adapters, no `unsafe`, a seed reproducing a run byte for byte, the published seed corpus, two independent verifiers agreeing on one pack, a reproducible verifier binary, the TLS builds, every parser under hostile bytes, every number the README states, and a 200-seed durability sweep. Fifteen checks, run by `.githooks/pre-push` and again by CI.

**Decisions with no gate yet.** This list is debt, and it is here so it stays visible:

- Invariants 9, 10, 15, 16, 17 and 18 above are held by nothing but their own sentence.
- Three checks are written inline in both `.githooks/pre-push` and `.github/workflows/ci.yml` rather than in one file both call: `no unsafe`, `determinism`, and the durability sweep. The dependency check was in that same shape until its two copies disagreed and CI failed a push the hook had passed, which is why it now lives in `scripts/declared-deps.sh` and why invariant 17 exists. These three have not drifted yet.
- `qryx scan --policy cnsa` is run on demand, not on push.
- The federation transport (gRPC with mutual TLS, decision A2) is specified and unbuilt: the completeness rule exists, the wires do not.

Numbers, and what has and has not been measured, live in [`VALIDATION.md`](VALIDATION.md). Nothing in this file should restate a number.

---

## Standing rule

**An approved architectural decision is not finished until it is two things: a numbered invariant in this file, and a gate in `scripts/` if it can be checked structurally.** Until then it is a document, and documents do not stop code. When you make or implement a decision, the last step is to come back here and add the line, or to add the check and then the line.

The corollary is the reason this file exists at all: a decision recorded only in `docs/planning/` is read once, by whoever wrote it.
