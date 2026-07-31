#!/usr/bin/env bash
#
# Everything that compiles only when the `tls` feature is on.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`, for
# the reason recorded next to `declared-deps.sh`: the two used to hold their own
# copies of a check and drifted the first time one changed.
#
# Why it needs its own step at all: the feature is off by default, so that these
# crates keep their zero third-party dependencies, which is what the dependency check
# measures. A feature that is never compiled is a feature that quietly stops
# compiling, and this one is the only way any adapter reaches a real cloud endpoint,
# because every one of them is https.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

cargo test -p trailryx-http --features tls --quiet
cargo test -p trailryx-s3 -p trailryx-azure \
  --features trailryx-s3/tls,trailryx-azure/tls --quiet
