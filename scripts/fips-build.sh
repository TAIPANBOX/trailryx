#!/usr/bin/env bash
#
# The build that links AWS-LC's FIPS 140-3 module, compiled and run.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`, for
# the reason recorded next to `declared-deps.sh`: the two used to hold their own
# copies of a check and drifted the first time one changed.
#
# WHY IT NEEDS A STEP AT ALL, and it is `tls-builds.sh`'s argument with more at stake.
# `Vault::new` refuses any provider whose `Aead` and `KeySource` answer
# `is_validated() == false`, and both answer `cfg!(feature = "fips")`. So `fips` is not
# an optional extra: it is the ONLY configuration in which a deployment may use this
# store at all. Until 7 August 2026 no script, hook step or CI job compiled it, which
# means the one build a deployment runs had never been built here. A feature nobody
# builds is a feature that quietly stops compiling, and this one stops compiling in the
# place where nobody would find out until a deployment.
#
# WHAT IT COSTS. `aws-lc-rs/fips` swaps `aws-lc-sys` for `aws-lc-fips-sys`, which
# builds AWS-LC's FIPS module from source and needs CMake, Go and a C compiler. It is
# minutes on a cold cache and seconds on a warm one. That is why it runs the tests of
# one crate rather than the workspace: the crate is the only one the feature reaches.
#
# WHEN IT SKIPS, AND WHY THAT IS NOT A PASS. A laptop without CMake or Go cannot
# compile the module. The honest answer there is to say so, loudly, in the way
# `scripts/audit.sh` says it when `cargo audit` is absent, rather than to turn every
# push into a fifteen-minute build. What must never happen is that the same silence
# reaches CI, where the toolchain is present and a skip would be a check passing by not
# looking. So CI sets TRAILRYX_FIPS_REQUIRED=1 and this script REFUSES instead of
# skipping when a prerequisite is missing under it. Invariant 19 is the rule: a check
# that cannot fail reports zero for ever.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

required="${TRAILRYX_FIPS_REQUIRED:-0}"

missing=""
for tool in cmake go cc; do
  command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done

if [ -n "$missing" ]; then
  if [ "$required" = "1" ]; then
    printf 'the fips build was required and cannot run:%s missing.\n' "$missing"
    printf 'aws-lc-fips-sys builds AWS-LC from source and needs all three.\n'
    exit 1
  fi
  # Said out loud. A check that declines to run has to report that it declined, or it
  # is indistinguishable from one that passed.
  printf 'skipped: %s missing, so the FIPS module cannot be built on this machine.\n' \
    "${missing# }"
  printf 'CI builds it with TRAILRYX_FIPS_REQUIRED=1 and cannot skip.\n'
  exit 0
fi

# `--features fips` on the crate rather than on the workspace: it is the only crate the
# feature reaches, and asking the workspace for it would rebuild everything for
# nothing. Tests rather than a bare check, because compiling proves the code exists and
# running proves the validated module agrees with the one the rest of the gate used:
# `validation_is_claimed_only_by_the_build_that_has_it` asserts the opposite answer
# here from the one it asserts everywhere else, and the hybrid KEM runs against the
# certified implementation rather than against the ordinary one.
cargo test -p trailryx-crypto-aws --features fips --quiet || exit 1
printf 'fips build compiled and its tests ran\n'
