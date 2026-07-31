#!/usr/bin/env bash
#
# Every recorded seed still produces the digest and the violation count written
# down for it in `sim/corpus.tsv`.
#
# This is a DETERMINISM check and not a correctness one, and the corpus file says so
# in its own header: a wrong implementation reproduces its own wrongness perfectly.
# Its value is that a change in behaviour cannot arrive quietly.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

cargo run --quiet --release --bin trailryx-sim-run -- --corpus sim/corpus.tsv
