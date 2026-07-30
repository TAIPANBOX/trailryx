# The JSON oracles

Four scripts and two tables. The scripts generate a conformance corpus and ask
two parsers with no shared ancestry what they make of it. The tables are the
answers, checked in, so `tests/oracle.rs` can pin our behaviour against them
without needing python or node on the machine that runs `cargo test`.

Nothing here is part of the crate. The crate depends on nothing, and that
includes these files.

## The scripts

| file | tool | what it answers |
| --- | --- | --- |
| `cases.py` | python3 (std only) | the corpus itself: 222 hand-written cases as `name`, `hex`, `verdict` |
| `classify.py` | CPython `json` | accept or reject, per case |
| `classify.js` | node `JSON.parse` (V8) | accept or reject, per case |
| `values.py` | CPython `json` with the number hooks hijacked | the scalars in every case CPython accepts, canonically |
| `floats.py` | CPython `float` and `struct` | the exact binary64 bits for a float literal |

Verified on the machine these tables were produced on: python3 3.14.6, node
v22.23.1. ruby 4.0.6 and jq 1.7.1 are also present and are deliberately unused:
a third oracle is worth adding when there is a divergence class the first two
cannot see, and adding one now would mean three columns of the same answer.

CPython's `json` and V8's `JSON.parse` were chosen because they share no code and
no lineage. Two parsers derived from the same reference implementation agreeing
proves only that the reference is self-consistent.

```sh
python3 cases.py > /tmp/corpus.tsv
python3 classify.py < /tmp/corpus.tsv > /tmp/py.tsv
node    classify.js < /tmp/corpus.tsv > /tmp/node.tsv
python3 values.py   < /tmp/corpus.tsv > /tmp/values.tsv
printf '1e999\n2.2250738585072011e-308\n' | python3 floats.py
```

## The formats

**The corpus is hex-encoded.** `name<TAB>hex<TAB>verdict`, no header. Hex because
a corpus stored as text loses exactly the cases that matter: invalid UTF-8 cannot
round-trip through a text file at all, a NUL is dropped or truncated by half the
tools that would touch the file, and a byte-order mark is silently eaten by
editors.

**`verdict` is the RFC's answer, not ours.** `y` a conforming parser must accept,
`n` must reject, `i` the grammar is satisfied but the answer is
implementation-defined. What *we* are expected to do is in `EXPECTATIONS.tsv`, in
a separate file on purpose: the RFC verdict and our verdict are different claims,
and merging them would hide the four places we knowingly diverge.

**`values.py` escapes its field.** A canonical document contains newlines by
construction and a string value can contain a tab or a NUL of its own, so each
scalar line is escaped (backslash doubled, anything below `0x20` as `\xNN`,
`U+D800..U+DFFF` as `\uNNNN`) and the escaped lines are joined by the two
characters `\` and `n`. Escaping a real newline as `\x0a` and reserving `\n` for
the separator is what keeps one string containing a newline distinguishable from
two scalars; the obvious escaping does not. A Rust comparison has to apply the
same transformation to `validate::scalars` output before comparing.

The surrogate escape exists because CPython will hand back a `str` holding a lone
surrogate, and that string cannot be encoded as UTF-8 at all. Writing it raw
would put invalid UTF-8 in the output and break every reader of the file.

**Both tables allow `#` comment lines** at the top, carrying provenance. A reader
skips lines beginning with `#` and splits the rest on tabs.

## The tables

`DISAGREEMENTS.tsv` lists every case where CPython and node disagree with each
other: **5 of 222**, in two classes. CPython accepts the three non-standard
literals `NaN`, `Infinity` and `-Infinity`, and CPython refuses an integer
literal of more than 4300 digits where node converts it to `Infinity`.

`EXPECTATIONS.tsv` gives our verdict for all 222 cases: 75 `accept`, 118
`reject_syntax`, 20 `reject_encoding`, 9 `reject_limit`. One reason contains
`UNSURE` and is an open question for the implementation pass rather than a claim:
`i_number_exponent_expansion` is 21 bytes and grammar-conformant, so the four
bounds admit it, but the `max_number_bytes` doc in `lib.rs` says that exact
literal is refused outright.

Where we differ from both oracles at once, it is one of four declared positions:
duplicate member names are fatal, lone surrogates are fatal, bare `NaN` and
`Infinity` are fatal, and a UTF-8 BOM at offset 0 is skipped rather than refused.
The first three are in the crate doc. The fourth makes us *more* permissive than
both oracles, which both refuse a leading BOM, and it is the framer's job.

## What an oracle proves

That our answer for a given input differs from a mainstream parser's answer, or
does not. That is all, and it is worth being precise about the limits, because a
comparison suite is very good at producing the feeling of correctness.

- **It does not prove we are right.** Two parsers can agree and both be wrong,
  and 20 of the 67 parsers in the reference survey accept a raw newline inside a
  string. Where we disagree with both oracles we are deliberately stricter, and
  the argument for each divergence is in `lib.rs`, not in a table.
- **The `y`/`n`/`i` column is a human claim.** It was assigned by reading RFC
  8259, case by case. A mislabelled case makes the corpus quietly wrong in a way
  that no amount of running it will reveal, which is why every case is
  hand-written from a named divergence class and none is generated.
- **222 cases is not coverage.** The corpus can only find defects somebody
  thought of. It is the floor under the fuzzing and the property tests, not a
  substitute for them.
- **The oracles are versioned software.** Both tables are dated measurements
  against two specific builds, and a CPython or node upgrade can move a row. The
  Rust test asserting the disagreement set has not grown is the thing that
  notices.
- **node has no encoding refusal, and `classify.js` supplies one.** V8 never sees
  the raw bytes: `Buffer.toString("utf8")` substitutes `U+FFFD` rather than
  failing, so the script re-encodes and compares byte for byte first and reports
  a mismatch as a reject. Without that, node would accept most of the sixteen
  invalid-UTF-8 cases as documents full of replacement characters. The
  agreement on that class is therefore partly our construction and the comment
  in the script says so.
- **`values.py` compares scalars, not shape.** Two documents with the same
  scalars in the same order and different nesting produce the same canonical
  form. It catches a reordering and a rounding, which is what it was built for.
- **`floats.py` compares conversion, not grammar.** CPython's `strtod` is
  correctly rounded, so the bits are a strong oracle for what a literal means and
  say nothing at all about whether the literal is legal.
- **One bound is absent.** `max_line_bytes` is 16 MiB, and a case that reached it
  would make this corpus a 33 MB file of hex. It belongs to the framer rather
  than to the grammar and is measured in `tests/frame.rs` and `tests/hostile.rs`.
  The other three bounds (depth 25, number 1024 bytes, 256 members per object)
  are exercised here from both sides.
