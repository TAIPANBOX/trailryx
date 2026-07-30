#!/usr/bin/env python3
"""Regenerate sim/corpus.tsv from actual runs.

Run it, then READ THE DIFF. A digest that changed is either a defect or a
deliberate change to the store's behaviour, and this script cannot tell you which.
Committing its output without deciding is how a regression gets blessed.

    cargo build --release --bin trailryx-sim-run
    python3 sim/regenerate.py > sim/corpus.tsv
    git diff sim/corpus.tsv

Written in Python rather than shell for one specific reason: zsh does not word-split
an unquoted parameter expansion, so the obvious `set -- $spec` loop silently passed
empty values to every flag and produced sixteen identical rows of defaults. The
binary was right and the loop was wrong.
"""

import subprocess
import sys

BINARY = "target/release/trailryx-sim-run"

HEADER = """\
# The published seed corpus.
#
# Every row is a full parameter set and the digest of the trace it produces. Run
# them all with:
#
#     cargo run --release --bin trailryx-sim-run -- --corpus sim/corpus.tsv
#
# WHAT THIS PROVES: that this build reproduces these runs byte for byte, on this
# machine or on somebody else's, today or in a year. That is the property the whole
# DST method stands on, and `docs/planning/trailryx-architecture.md` §1a.2 calls it
# a requirement on the design rather than on the tests.
#
# WHAT IT DOES NOT PROVE: that the runs are correct. A wrong implementation is
# perfectly reproducible. Correctness is what the 200-seed durability sweep and the
# rest of the suite are for; this file is about determinism only, and conflating the
# two is the easiest way to read more into it than it says.
#
# A CHANGED DIGEST is either a defect or a deliberate change to the store's
# behaviour. Regenerating this file without deciding which is how a regression gets
# blessed. Regenerate with `python3 sim/regenerate.py` and read the diff.
#
# Columns, tab separated:
#   seed  steps  shards  sync_every  crash_ppm  faults  digest
#
# faults is one of: plain, hostile, hostile+honest-disk\
"""

# Chosen to spread across the axes that change the store's behaviour rather than to
# look thorough: one shard and many, syncing every step and rarely, no faults and
# the hostile set, a crash rate of zero and of two percent. The last two seeds are
# the extremes of the u64 range, because a seed is fed to the generator and an
# implementation that treats the ends specially is one that has a special case
# nobody wrote down.
ROWS = [
    # seed, steps, shards, sync_every, crash_ppm, faults
    (1, 400, 2, 8, 0, "plain"),
    (2, 400, 2, 8, 0, "plain"),
    (3, 1000, 1, 1, 0, "plain"),
    (7, 200, 3, 4, 0, "plain"),
    (42, 5000, 4, 8, 0, "plain"),
    (1, 400, 2, 8, 3000, "hostile"),
    (2, 800, 3, 4, 12000, "hostile"),
    (3, 800, 3, 4, 12000, "hostile+honest-disk"),
    (17, 2000, 4, 16, 5000, "hostile"),
    (99, 1500, 2, 2, 20000, "hostile+honest-disk"),
    (20260729, 800, 3, 4, 12000, "hostile+honest-disk"),
    (20260730, 3000, 5, 8, 8000, "hostile"),
    (777, 20000, 4, 8, 5000, "hostile+honest-disk"),
    (1000003, 600, 6, 32, 1000, "hostile"),
    (4294967295, 500, 2, 8, 0, "plain"),
    (18446744073709551615, 500, 3, 4, 9000, "hostile"),
]

FLAGS = {
    "plain": [],
    "hostile": ["--hostile"],
    "hostile+honest-disk": ["--hostile", "--honest-disk"],
}


def main() -> int:
    print(HEADER)
    for seed, steps, shards, sync_every, crash_ppm, faults in ROWS:
        argv = [
            BINARY,
            "--seed", str(seed),
            "--steps", str(steps),
            "--shards", str(shards),
            "--sync-every", str(sync_every),
            "--crash-ppm", str(crash_ppm),
            *FLAGS[faults],
            "--corpus-row",
        ]
        try:
            out = subprocess.run(argv, capture_output=True, text=True, check=True)
        except FileNotFoundError:
            print(f"build it first: cargo build --release --bin trailryx-sim-run", file=sys.stderr)
            return 2
        except subprocess.CalledProcessError as e:
            print(f"seed {seed} failed: {e.stderr}", file=sys.stderr)
            return 1
        row = out.stdout.strip()
        # The runner reports the parameters it actually used, so a row that comes
        # back with different ones means an argument did not arrive. That is exactly
        # the failure the shell version of this script had, and it went unnoticed
        # because the output looked like output.
        fields = row.split("\t")
        if fields[:5] != [str(seed), str(steps), str(shards), str(sync_every), str(crash_ppm)]:
            print(
                f"the runner echoed {fields[:5]} for {[seed, steps, shards, sync_every, crash_ppm]}: "
                "an argument did not arrive",
                file=sys.stderr,
            )
            return 1
        print(row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
