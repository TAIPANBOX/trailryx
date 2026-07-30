# A second verifier, in another language

```bash
python3 trailryx_verify.py ../incident-4471.trxevid
```

Standard library only. No pip install, no virtualenv, nothing to trust that is not
already on the machine.

## Why this exists

`docs/planning/trailryx-plan.md` asks for it by name, under R6. The Rust verifier
answers "who checked your code" with *read it, it has no dependencies and it fits in
an hour*. This answers a different question:

> **Two implementations that agree prove the format, not the author.**

Every root, chain link and index key in a pack is recomputed here from the bytes,
independently, by a program that shares no code with the Rust one.
`crates/trailryx-store/tests/two_verifiers.rs` runs both on the same packs, good and
tampered, and requires the same verdict and the same record count from each.

## What it does not prove

The honest limit is narrower than the headline, so it is stated first rather than
last:

- **It was written by reading the Rust.** A fully independent reimplementation would
  come from a specification and a different person. This one would not catch a defect
  that is the same misunderstanding made twice. What it does catch is a change to one
  side the other did not follow, and every place the format needed guessing, because
  those are the places it is under-documented.
- **It does not check signatures.** ECDSA over P-384 in pure Python is several hundred
  lines of modular arithmetic whose bugs are silent, and the subject here is the
  format rather than the curve. A signature is reported as present and unchecked, the
  same split the Rust verifier makes for a timestamp token and for the same reason.
- **It is a second opinion, not a replacement.** A pack is believed when both say so.

## It has already paid for itself

Writing it found a real divergence. The Python's sequence check compared each record
to the one before it, which is weaker than the Rust one in a way that matters: a
segment missing its **first** record, or one whose numbers all shifted by the same
amount, would have passed. The Rust verifier had already been strengthened past that
after an adversarial review, with the reasoning written next to the code, and the
Python had not. Running the two against each other is what surfaced it.

That is the mechanism working as intended, and it is the argument for keeping this
file rather than the argument for having written it.
