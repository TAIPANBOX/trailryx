# Security Policy

Trailryx exists to be believed by somebody who does not trust the operator running
it. A defect that lets a record be altered without the chain moving, an answer be
shortened without the proof noticing, or a person's data survive an erasure they
asked for, is not a bug in a database: it is the product being false about the one
thing it sells. Those are the reports we most want.

## Reporting a vulnerability

Please report privately, not in a public issue or pull request:

- Open a **GitHub private security advisory**:
  <https://github.com/TAIPANBOX/trailryx/security/advisories/new>

Include the affected commit, what the store claimed, and what you measured instead.
A failing test is the most useful form a report can take, and this repository has
about seven hundred of them to copy the shape from. We aim to acknowledge within a few
days and to fix anything that breaks a stated guarantee before disclosing it. There
is no bug-bounty programme; reporters are credited in the advisory unless they
prefer otherwise.

## What counts as a vulnerability here

The guarantees are stated out loud, so a report can name the one it breaks:

- **`docs/durability.md`**: every sequence number reported as acked survives any
  crash. A case where an acked record does not come back is a report.
- **Completeness**: a verifier must never learn the shape of an answer from the
  answer. A proof that verifies while a matching record was withheld is a report,
  and six such holes have been found and closed this way already.
- **The plane boundary**: content belongs in the encrypted payload and never in
  metadata. An input that lands prompt text, a name or any personal data in a
  typed metadata field is a report, and `crates/trailryx-record/src/schema.rs`
  is the table it would breach.
- **Erasure**: after a **completed** `forget`, no path recovers the payload. A path
  that does is a report, and the hostile suite in `crates/trailryx-erasure/tests/`
  is where a new one belongs.

  "Completed" is load-bearing and was added on 30 July 2026. Every real key
  custodian schedules destruction rather than performing it: AWS KMS waits 7 to 30
  days and GCP Cloud KMS 30 by default, and both let an operator cancel throughout.
  So `Forgotten::is_complete()` can be false, the erasure record says `Held` rather
  than `Allowed`, and during that window the payload is **unreadable and not
  erased**. A `forget` that reported a scheduled destruction as a finished one would
  be a report; so would a path that reads a payload whose key the custodian has
  already shredded.
- **The anchor**: a timestamp token in a pack must be about that pack's root. A
  token whose imprint is a different root and which the verifier does not report as
  BROKEN is a report, because the pack would then be describing its own evidence.
- **The offline verifier**: a pack it reports as VERIFIED must be internally
  consistent in every part it carries. A pack that passes while holding records
  nothing checked is a report.
- **The ingest gate**: an unauthenticated request that gets past
  `crates/trailryx-ingest/src/auth.rs`, or one that makes the server read a body
  before the gate has answered. The second is the subtler of the two and
  `crates/trailryx-ingest/tests/wire.rs` is where its cases live.
- **Denial of service on the ingest surface**: an input under a megabyte that costs
  disproportionate memory or time. The bounds are all in
  `crates/trailryx-ingest/src/config.rs` and `crates/trailryx-json/src/lib.rs`, each
  with the reason for its number next to it.

## What is deliberately weaker, and is not a finding

Stated here so nobody spends their time on it:

- **A cancelled destruction is not a defect in this store.** An operator with the
  custodian's credentials can undo a scheduled key deletion, and no software here
  can stop them. What the store must do is never claim the erasure finished while
  that is possible, and it does not. Making the window shorter, or irreversible, is
  a key-management policy decision and belongs in the custodian.
- **The AEAD and the key source shipped in-tree are stand-ins**, and say so:
  `Aead::is_validated()` returns false and `Vault::new` refuses them. A deployment
  is expected to supply a validated implementation behind that seam. Breaking
  `Sha384Ctr` is not a finding; a way to bypass the `is_validated` check is.
- **A published object read back by key rather than by version.** S3 Object Lock
  protects a version, so an actor with credentials can put a new version over the key
  and a reader that does not pin the version gets it. A path in this store that reads a
  published segment or manifest without its version token is a report.
- **An unauthenticated read of the trail over the Postgres port.** The facade's
  startup handler consults the deployment's `AuthProvider` for `Action::Query`, a
  routable bind with no provider refuses to start, and a poisoned provider denies for
  ever. A way past any of those is a report. Note that
  `datafusion_postgres::serve` does no authentication at all, which is why it is not
  used; a deployment that calls it directly has built its own hole.
- **A path that gets SQL past `trailryx_sql::gate`.** A statement kind the gate lets
  through that can name a filesystem path, or a way to reach `SessionContext::sql`
  without the gate, is arbitrary local file read on the store's host and is the most
  serious report this crate can receive. `crates/trailryx-sql/src/gate.rs` states what
  is allowed and why each one is.
- **The SQL facade has 297 transitive dependencies, and everything else has none.**
  `trailryx-sql` took DataFusion and the Postgres wire protocol on 30 July 2026. A
  vulnerability in one of those crates is a real report and `cargo audit` in CI is
  where it should surface, but it is a vulnerability in the facade and not in the
  store: the gate proves the core builds and passes its tests with the facade absent,
  and `trailryx-verify` still depends on nothing at all. A report that a facade
  dependency reaches the core is a report about the boundary, which is the more
  serious kind.
- **The HTTP listener has no TLS.** That is the honest configuration for a listener
  built with no dependencies, and it says so at startup. On a routable bind the
  credential is readable on the wire, so a routable bind belongs behind a terminating
  proxy.
- **The in-tree `AuthProvider` is one shared secret.** `bearer::SharedSecret`
  authenticates a fleet, not an agent, and says so. A deployment that needs per-agent
  authorisation supplies its own provider behind the same seam. A way past the gate is
  a report; the fact that one secret is one identity is not.
- **No gRPC.** OTLP over HTTP is the specification's default protocol. That is written
  in the README's own list of what is unfinished.
- **An RFC 3161 anchor is trusted by a pinned key, not by a certificate chain.** No
  path building, no revocation, no extended key usage, no validity windows. A way to
  make a token verify under a key that did not sign it is a report; the absence of
  chain validation is not.
- **The offline verifier reads a timestamp token and does not verify its signature.**
  It checks the token commits to the pack's root and says so. A token whose imprint is
  another root and which the verifier reports as anything but BROKEN is a report; the
  unchecked signature is stated in the verifier's own output.
- **Signing is done by an external signer.** This repository contains no signing
  code on purpose; the tests drive OpenSSL as a subprocess.

## Supported versions

Pre-1.0 and moving. Only `main` is supported. The record format is frozen and
versioned, so a pack written by an older commit still verifies.
