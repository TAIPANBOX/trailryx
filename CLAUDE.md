# Working on Trailryx

**Before writing a line of code, read [`docs/planning/trailryx-architecture.md`](docs/planning/trailryx-architecture.md) and [`docs/planning/trailryx-plan.md`](docs/planning/trailryx-plan.md) in full.** They are the approved decisions; this file is only their enforceable summary, and where the two disagree, those two win. [`docs/planning/trailryx-roadmap.md`](docs/planning/trailryx-roadmap.md) is the single source of what order things happen in.

Everything below is a rule, not a description. Each one says what holds it today:

- `(gate: <path>)` a check that refuses the push, written once in `scripts/` and called by both `.githooks/pre-push` and CI.
- `(test: <name>)` a test, and nothing else.
- `(not checked)` this line is the only thing holding it. Treat those as the fragile ones.

---

## Invariants

1. **Never write `unsafe`.** The workspace lint forbids it and the gate greps for it anyway, because a lint can be relaxed in a manifest by somebody who meant well. *(gate: scripts/no-unsafe.sh)*

2. **Never add a third-party dependency to the core or to `trailryx-verify`.** A dependency belongs in an L2 adapter, and that adapter's crate name must be added to the allow-list in the gate script before its dependency will build. The reason is not minimalism: an auditor reads the verifier, and every crate pulled into it is a crate they are asked to trust instead of read. Everything else (a validated cipher, a post-quantum KEM, TLS, a SQL engine) is taken from whoever does it better than we would, because nobody buys a proof store for its author's AES. *(gate: scripts/declared-deps.sh)*

3. **The core must build and pass its tests with every adapter absent.** If it cannot, an adapter has got into the foundation. *(gate: scripts/declared-deps.sh)*

4. **Never read a clock, a random number, a disk or a socket directly from the core.** Go through `Clock`, `Rng`, `Io`, `Net`, or deterministic simulation stops working and every guarantee built on it stops meaning anything; breaking this does not announce itself, it shows up as two runs of one seed that no longer agree. *(gate: scripts/determinism.sh)*

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

16. **If two places need the same value, export it from one and import it in both.** Two functions computing what is meant to be one number is how a publisher and a reader end up disagreeing about the same object. The same holds for a number written in prose, and there it is worse, because nothing compiles it: the facade's dependency count sat in five places, the README's copy was corrected within hours of being wrong and a doc comment's copy was fifty crates out for six days, in the file whose subject it was. One value in prose now means one owner in prose. For that count the owner is the README, whose figure the gate measures against `cargo tree`, and no other tracked file may state a count of its own. A superseded figure may appear where a sentence is recording history, and it has to be declared with a reason that is re-derived on every run, exactly as invariant 24 requires of a silenced advisory: `history` means the paragraph carrying the number also says when, and a paragraph that stops saying when stops being exempt. *(gate: scripts/readme-numbers.sh, for the dependency count; the general rule about two functions computing one number is still not checked)*

17. **A check with any logic or parameters of its own goes in `scripts/`, and both the hook and CI call it.** Bare `cargo` invocations may stay written out in both; anything carrying a seed, a flag, a pattern or a list may not, because that is what drifts. *(not checked, and it is a rule because a drifted copy once made CI refuse a push the hook had passed)*

18. **Never let a test wait without a bound.** A hanging test reports nothing at all: no failure, no name, no output, which is less than a wrong answer tells you. *(not checked)*

19. **Never report "nothing found" without a run where the same check does find something.** A check that cannot fail reports zero forever. *(test: the_harness_catches_a_lying_fsync)*

20. **A fake must refuse what a compliant server refuses.** A fake written from the same reading of the same documentation as the client agrees with the client's mistakes, so it has to be taught the rules the client is not allowed to break. *(test: the_request_carries_exactly_one_host_header)*

21. **A peer's name comes from its certificate, never from anything it sent.** The completeness rule counts answers against a signed registry, and that count is worth nothing if a name can be claimed: one node holding one valid federation certificate could otherwise answer to every missing name in turn and stamp the result complete. The client names the peer it expects, TLS refuses a certificate that does not carry it, and no field in the response body takes part in the decision. *(test: a_peer_cannot_answer_under_a_name_its_certificate_does_not_carry)*

22. **A federated stream that ended without its trailer is not an answer.** The proof status rides last precisely so that its absence is a signal. Rows that arrived without a claim attached are refused rather than returned, because a truncated answer that reads as a small complete one is the exact failure the federation rule exists to prevent, one layer down. *(test: a_stream_that_ends_before_its_trailer_is_refused_rather_than_read_as_complete)*

23. **An identifier arriving from a peer is parsed at the strictness of the ingest door, not of the journal.** `trailryx-journal` reads ids back with the lax constructor because it wrote them; `trailryx-otlp` uses the strict one because those came from outside. A peer is outside wearing the journal's clothes, and the transport got this wrong the first time it was written. *(test: an_agent_id_that_is_not_a_uri_is_refused_the_way_the_ingest_door_refuses_it)*

24. **A silenced advisory carries a reason, and the reason is re-derived on every run.** `cargo audit` reads the lockfile, which is correct, and therefore flags crates cargo records but never compiles. Silencing one of those is sometimes right; silencing it with a sentence in a configuration file is not, because the sentence stops being true without saying so and the entry then protects nothing while still reading as a decision. Two reasons are allowed and both are facts rather than judgements: `never-built`, the crate is in no build graph because it sits behind an optional feature nothing enables, and `dev-only`, the crate is compiled for tests but reaches no normal dependency edge. The second is the weaker one and says so: it means the code is not in a shipped artifact, not that it never runs here. An id silenced with no recorded reason fails the gate outright. *(gate: scripts/audit.sh, verified by pointing each reason at a crate that breaks it and by adding an unexplained id, all three of which fail it)*

25. **A peer's chain is recomputed before its records are adopted, and a run that does not continue a head this receiver holds is refused.** Registry membership is authorisation, not evidence: it says a peer may speak, not that what it said links up. Replication is where the difference bites, because accepting records means adopting a history. The receiver hashes bytes IT produced by re-encoding what it decoded, never a link that travelled with the record, which is the same rule `store::tier` already follows when it warms a segment. Two entry points and not one with a flag: `accept_from` takes the head this receiver holds, and `accept_unanchored` is named so that choosing the weaker check is visible in the calling code, because a fabricated history is internally consistent and passes it. *(test: the eleven in `crates/trailryx-federation/tests/replication.rs`, each reaching one refusal, all verified by breaking the implementation five ways; plus `crates/trailryx-federation-grpc/tests/replication_over_the_wire.rs`, which holds the assumption the whole thing rests on: a record's canonical bytes survive protobuf unchanged, so a lossy codec would report a broken chain rather than itself)*

26. **A reader is never told about somebody else's answer.** `trailryx_proof()` says how provable the last answer on **this session** was, and over the Postgres facade a session is a connection: `serve_on` forks one per accepted socket, so the proof slot, the table and the `SessionContext` are that connection's own. Anything shared between connections must be immutable, which the sealed segments are. This was live: one slot served the whole process, so a client that ran a query the index could not prove and asked for its proof could be handed a stranger's `full`, and a connection that had asked nothing was told about a query it never ran. An unproved answer taken as proved is the failure the entire crate is arranged against, and it arrived through the function meant to prevent it. What remains, and is stated rather than fixed, is one session's own race: a second statement between a query and the proof that asks about it overwrites the slot. *(test: `two_connections_each_read_their_own_proof_and_never_the_others` and `a_fresh_connection_has_proved_nothing_however_busy_the_server_is` in `crates/trailryx-sql/tests/wire.rs`, both verified by failing against the shared slot; a gate would have to prove a negative about code not yet written, which is the same reason 21 to 23 are tests)*

27. **The SQL read surface admits or refuses a connection, and never filters a row.** One `Action::Query` decision at connect time, against a scope fixed when the server was built. Past it every authenticated client reads every record in every segment that server registered, whatever the `tenant` field says, and nothing on the read path takes a principal or a tenant. The deployment model is **one server per scope**; two tenants means two servers. This is a constraint and not a defect, and the rule is that it stays written where a deployer meets it: `SECURITY.md`, the README's SQL section and `ReadGate`'s own documentation. Adding row filtering later does not delete this line, it replaces it, because the line a deployment was built on must not quietly stop being true. *(not enforced, and the thing most likely to break it is not code: the unit tests showing two scopes refusing each other's principals read as tenant isolation, so anybody reading them without this line concludes the opposite)*

28. **A declared limit is read by the code it bounds, and what it does is held by a test. A limit that is neither is deleted, not documented.** `Config::max_connections` on the SQL surface was declared with its reason beside it, "a read surface with none is a read surface that can be exhausted", and nothing read it: `serve_on` spawned a task per accepted socket and counted none of them, so lowering the number changed nothing at all. An absent bound is a gap somebody can see. A declared bound with a paragraph of justification reads as a mitigation already applied, and it is the paragraph that gets believed, which is why this is worse than the field not existing. At the cap the connection is **answered rather than dropped**, the same choice `trailryx-ingest` makes at its own: a socket that closes without a word is what a client also sees on a crash, a firewall and a wrong password, so it carries no information, while `53300` is the one condition on this port worth retrying. *(gate: scripts/config-fields.sh, which finds a field nothing reads and, run against the commit before this one, names exactly that field; the gate cannot prove a field is obeyed, so the two tests in `crates/trailryx-sql/tests/wire.rs` hold that half, verified by breaking the implementation four ways: a guard that never returns a slot, `>=` for `>`, a close with no answer, and a message length that forgets to count itself)*

29. **A test's scratch directory carries the process id, always, and not only when a collision has been seen.** `$TMPDIR` belongs to the user, not to the run: a fixture named after itself is a fixture the next process names identically, and both the pre-clean and the `Drop` that tidy it up name it by path rather than by ownership. Whoever wipes first takes the other's files, and the report is a file that was written and then was not there, which points at everything except the run that removed it. Measured on 6 August 2026, eight copies of one test binary at once: the anchor's authority failed 11 of 30 processes before and 0 of 60 after, the ASN.1 oracle 12 of 40 before and 0 of 40 after. The rule is mechanical rather than judged, because the nine sites that had never been seen to fail were written by people who would each have judged their own fixture safe, and one of them was. *(gate: scripts/temp-paths.sh, verified by putting a constant path back and by adding a new fixture with one, wrapped across two lines so the statement rather than the line is what is read)*

---

## What is a gate, and what is still only a sentence

**Decisions that became gates.** Zero dependencies outside the declared list, the core standing up without adapters, no `unsafe`, a seed reproducing a run byte for byte, the published seed corpus, two independent verifiers agreeing on one pack, a reproducible verifier binary, the TLS builds, every parser under hostile bytes, every number the README states including the image tag it tells people to pull, the facade's dependency count wherever else in the tree it is written down, a 200-seed durability sweep, the advisories with the reasons the silenced ones are silenced, every field of every configuration struct against the code meant to read it, and every temp path a test builds. Eighteen checks, run by `.githooks/pre-push` and again by CI.

**Decisions with no gate yet.** This list is debt, and it is here so it stays visible:

- Invariants 9, 10, 15, 17, 18 and 27 above are held by nothing but their own sentence. Invariant 16 is half held: the facade's dependency count is gated in every tracked file, and the general rule about two computations of one value is not.
- Invariants 21, 22, 23 and 26 are held by tests rather than by a gate. A gate would have to prove a negative about code that has not been written yet ("no future call path reads a name out of the body"), and a grep that pretended to do so would be worse than the honest sentence.
- Invariant 28 is gated by half. `scripts/config-fields.sh` proves a configuration field is read; nothing structural proves it is obeyed, and a limit read into a variable and then ignored would pass it. The two tests named beside the invariant are what hold that half, and a third configuration struct arriving without them would be new debt rather than covered by the old.
- The fuzz step differs between the hook and CI on purpose, 300 cases against 3,000: the hook is fast and CI is thorough. Do not "fix" it into agreement.
- `qryx scan --policy cnsa` is run on demand, not on push.
- ~~The federation transport (gRPC with mutual TLS, decision A2) is specified and unbuilt.~~ Built 2026-08-04 in `trailryx-federation-grpc`, with invariants 21 to 23. ~~What remains unbuilt from stage 12 is verified replication.~~ Built 2026-08-04 in `trailryx-federation::replication`, invariant 25. **Stage 12 is closed.** What it does NOT do is anchor the first link of a run for a receiver holding no prior head for that shard, which is a limit of the problem rather than of the code and is stated in `VALIDATION.md` and in the module.

Numbers, and what has and has not been measured, live in [`VALIDATION.md`](VALIDATION.md). Nothing in this file should restate a number.

---

## Standing rule

**An approved architectural decision is not finished until it is two things: a numbered invariant in this file, and a gate in `scripts/` if it can be checked structurally.** Until then it is a document, and documents do not stop code. When you make or implement a decision, the last step is to come back here and add the line, or to add the check and then the line.

The corollary is the reason this file exists at all: a decision recorded only in `docs/planning/` is read once, by whoever wrote it.
