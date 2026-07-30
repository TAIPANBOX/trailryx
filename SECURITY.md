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
- **Erasure**: after `forget`, no path recovers the payload. A path that does is a
  report, and the hostile suite in `crates/trailryx-erasure/tests/` is where a new
  one belongs.
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

- **The AEAD and the key source shipped in-tree are stand-ins**, and say so:
  `Aead::is_validated()` returns false and `Vault::new` refuses them. A deployment
  is expected to supply a validated implementation behind that seam. Breaking
  `Sha384Ctr` is not a finding; a way to bypass the `is_validated` check is.
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
- **Signing is done by an external signer.** This repository contains no signing
  code on purpose; the tests drive OpenSSL as a subprocess.

## Supported versions

Pre-1.0 and moving. Only `main` is supported. The record format is frozen and
versioned, so a pack written by an older commit still verifies.
