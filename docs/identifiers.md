# Identifiers, and what erasure cannot reach

Trailryx erases content by destroying a key. That works for prompts, completions,
tool arguments and documents, which live encrypted in the payload plane.

It does not work for identifiers, and this document exists because the gap is
easy to miss and unpleasant to discover late.

---

## The gap

Nine fields hold values the **operator** supplies:

`tenant` · `agent_id` · `run_id` · `parent_run_id` · `on_behalf_of` ·
`basis.policy_version` · `basis.model` · `basis.tool_manifest` ·
`basis.identity_chain`

They live in the metadata plane in the clear, because queries and proofs need
them there: four of them are provable dimensions, and a proof about a value
nobody can read is not a proof.

Being in the clear has a consequence that no amount of key management changes.
An identifier ends up **committed inside a segment's index roots**, those roots
are committed into a shard root, and that into a store root, and those roots are
published, anchored and handed to auditors. Segments are immutable by design.
Destroying a key does not reach a Merkle root that went out last year.

So: **anything you put in an identifier is permanent.**

## What the type system does and does not stop

Identifiers are constrained tokens: bounded length, a fixed character set,
validated at the door and re-validated on the way back off disk. That stops a
sentence, a document and an email address.

It does not stop a name:

```text
agent://acme.example/ivan.petrenko.1979      passes every check
run://acme/case-2026-0417-petrenko           passes every check
user://ivan.petrenko                         passes every check
```

The schema is honest about this. Those nine fields are classified
`operator-pseudonymous` rather than `never`, the classification is in the
committed schema artifact where an auditor can see it, and a test pins the list
so a tenth field cannot join it quietly.

## What operators must do

**Identifiers must be pseudonymous.** They are stable references, not
descriptions.

| Instead of | Use |
|---|---|
| `user://ivan.petrenko` | `user://u-8f3a91` |
| `agent://acme.example/support/petrenko-case` | `agent://acme.example/support/tier1` |
| `run://acme/case-2026-0417-petrenko` | `run://acme/01JH8Z2K3M4N5P6Q` |

The mapping from a pseudonym to a person lives in your identity system, where
you can already delete it. That deletion is what makes the audit trail
unlinkable, and it is the only mechanism that works, because it is the only one
that operates on data Trailryx never sees.

## Why not simply hash them

Indexing a keyed hash of each identifier instead of the identifier itself was
considered and rejected for now.

It would make erasure reach identifiers, which is a real gain. It would also
break every **range** query on those dimensions, because a hash destroys order:
`agent_id BETWEEN 'agent://acme.example/support/' AND 'agent://acme.example/support/~'`
is a query auditors genuinely ask, and equality alone does not answer it.

The trade may be worth revisiting per deployment, and the schema's algorithm
agility leaves room for it: a future dimension could be `agent_id_hashed`
alongside the plaintext one, with the operator choosing which to index. Until
then the guarantee here is contractual, and pretending otherwise would be the
kind of quiet false promise this product exists to make impossible.

## For a data protection assessment

- Identifiers are pseudonymous references chosen by the controller.
- They are retained for the life of the record and are not erasable by the
  processor, because they are cryptographically committed in immutable
  integrity structures.
- Erasure of the natural person's data is achieved by destroying the payload
  key, which removes all content, and by removing the pseudonym mapping in the
  controller's own identity system.
- Every field's classification is machine-readable in
  `crates/trailryx-record/schema/record.v1.json` under `x-pii`.
