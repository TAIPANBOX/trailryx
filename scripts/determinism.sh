#!/usr/bin/env bash
#
# The same seed, twice, byte for byte.
#
# Stage 0's exit criterion, checked on every push rather than once at the time. If a
# seed stops reproducing a run, deterministic simulation stops being evidence and
# every guarantee built on top of it stops meaning anything: a failing seed is no
# longer something another person can rerun.
#
# It is also what catches invariant 4 being broken. A clock, a random number or a
# socket reached directly from the core does not announce itself; it shows up here,
# as two runs of one seed that no longer agree.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`.
# Prints the digest on success, because a check that only says "ok" is a check
# nobody can compare against anything.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

run_once() {
  cargo run --quiet --bin trailryx-sim-run -- \
    --seed 20260729 --steps 800 --shards 3 --sync-every 4 \
    --crash-ppm 12000 --hostile --honest-disk 2>/dev/null
}

a=$(run_once)
b=$(run_once)

if [ -z "$a" ] || [ "$a" != "$b" ]; then
  printf 'run 1: %s\nrun 2: %s\n' "$a" "$b"
  exit 1
fi
printf '%s\n' "$(printf '%s' "$a" | tr ' ' '\n' | grep '^digest=')"
exit 0
