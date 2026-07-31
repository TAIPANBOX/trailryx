#!/usr/bin/env bash
#
# A short hunt for a durability violation, on every push.
#
# Two hundred seeds is not the long run: that one is in `VALIDATION.md` with its own
# number and is not run here. This is enough to catch a write-path regression before
# it leaves the machine.
#
# `--honest-disk` on purpose. With a disk allowed to lie about `fsync` almost every
# seed fails, which is correct and is the point of the test that proves this check
# can see a violation at all (`the_harness_catches_a_lying_fsync`). A gate has to
# answer a different question: did anything change today.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

cargo run --quiet --release --bin trailryx-sim-run -- \
  --seed 1 --sweep 200 --steps 300 --shards 3 --sync-every 4 \
  --crash-ppm 15000 --hostile --honest-disk
