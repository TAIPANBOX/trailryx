# Reproducing our runs and our binary

Stage 8's second exit criterion, from `docs/planning/trailryx-roadmap.md`: anybody
reproduces our run and our binary byte for byte. This is how, and it is also where
the limits of that claim are written down.

## The runs

`sim/corpus.tsv` is a published seed corpus. Each row is a full parameter set, the
digest of the trace it produces, and how many acked records the run lost.

```bash
cargo run --release --bin trailryx-sim-run -- --corpus sim/corpus.tsv
```

It refuses if any digest or any violation count differs from what is recorded, and
prints the one-command reproduction for the row that disagreed. The gate runs it on
every push.

**What this proves.** That this build reproduces those runs byte for byte, on your
machine as well as ours. Deterministic simulation is the method the whole
correctness argument rests on (`docs/planning/trailryx-architecture.md` §1a calls
it the most important section of that document, and a requirement on the design
rather than on the tests), and a corpus is what makes the claim checkable by
somebody who does not trust us.

**What it does not prove.** That the runs are correct. **A wrong implementation is
perfectly reproducible.** Correctness is what the 200-seed durability sweep and the
836 tests are for. Conflating the two is the easiest way to read more into this file
than it says, so its own header says it first.

### Why some rows record lost records, on purpose

Two rows record a nonzero violation count. Both are `hostile` without
`honest-disk`, which means the simulated disk **lies about flushing**.
`docs/durability.md` §7 has always said this out loud:

> **Nothing against a disk that lies.** A device that reports a successful flush it
> did not perform breaks the contract, and nothing in software can prevent it. What
> the simulator guarantees is that we notice.

What was missing until the corpus existed was the **number**. "Expected" with no
count attached is a claim nobody can check, and a change in it would have gone
unnoticed. Now a change in it fails the gate.

The corpus reader also refuses a corpus that records a loss on a row where the disk
does **not** lie, and says why:

```
records 3 durability violations under "hostile+honest-disk", where the disk does
not lie. That is a defect in the store and not a number to record
```

That guard exists because the tempting response to a new failure is to paste the
new number in and move on. Here that is not possible.

### Regenerating the corpus

```bash
cargo build --release --bin trailryx-sim-run
python3 sim/regenerate.py > sim/corpus.tsv
git diff sim/corpus.tsv
```

Then **read the diff**. A changed digest is either a defect or a deliberate change
to the store's behaviour, and no tool can tell you which. Committing a regenerated
corpus without deciding is how a regression gets blessed.

The generator is Python rather than shell for a reason worth passing on: zsh does
not word-split an unquoted parameter expansion, so the obvious `set -- $spec` loop
passed empty values to every flag and produced sixteen identical rows of defaults.
The binary was right and the loop was wrong, and the output looked like output.

## The binary

```bash
./scripts/reproduce.sh                    # the offline verifier
./scripts/reproduce.sh trailryx-sim-run   # or any other binary in the workspace
```

It exports the tree twice with `git archive`, into two directories with names of
**deliberately different lengths**, builds `--release --locked` in each, and
compares the digests. It also checks that neither build directory appears inside
the binary, so a match cannot be luck.

Different lengths matter: the thing that usually breaks this is a path embedded in
panic messages or debug info, and two paths of equal length would hide a
length-dependent difference. An earlier version of this check used `rb1` and `rb2`
and proved less than it looked like.

As of commit `a7df2ca`, on `rustc 1.96.1 (31fca3adb 2026-06-26)`, `aarch64-apple-darwin`:

```
trailryx-verify  d5e9e78ee756a317da9777ef3694a64d94796d8785d496b73dfda54faa51dbd2
```

No `--remap-path-prefix` is needed today, because the verifier has no dependencies
and nothing puts an absolute path into it. The check is here so that the day
something does, it fails on a push rather than in an audit.

### What a digest is worth without a version next to it

Nothing. Byte-identical output needs the **same rustc**, and
`rust-toolchain.toml` says `channel = "stable"`, which moves.

That is deliberate rather than an oversight. Pinning an exact version would stop
the gate telling us when a new compiler breaks the build, and that signal is worth
more than a digest that stays constant on its own. So the rule is:

> A build digest is only meaningful published together with a toolchain version and
> a target triple.

`scripts/reproduce.sh` prints all three every time it runs, which is why the block
above has them. If you get a different digest, check the version first: a
difference there explains it and is not a finding.

### What is not claimed

- **Nothing across platforms.** A macOS binary and a Linux binary differ by
  construction. The claim is per target triple, not across them.
- **Nothing about a release artifact.** There are no published binaries yet.
  Nothing outside GitHub is registered, so there is nothing to sign or to compare a
  download against. When there is, its digest and toolchain go here.
- **Nothing about the whole workspace.** The script builds one binary at a time. The
  gate checks the verifier, because that is the one an auditor runs.
