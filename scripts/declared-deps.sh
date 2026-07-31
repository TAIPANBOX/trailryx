#!/usr/bin/env bash
#
# Which crates may carry third-party dependencies, and the check that nothing else
# does.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`,
# because the two used to hold their own copies of this loop and they drifted the
# first time the list changed: the hook learned about the cryptographic provider and
# CI did not, so a push that passed locally failed in CI with a list of crates the
# hook had been told about. The header of the workflow file warns about exactly that
# drift, which is a good argument for not keeping two copies at all.
#
# The list IS the policy (architecture §2a): a crate not on it must have none, and
# adding one is a line somebody writes here rather than a dependency that appears in
# a manifest. What it must never contain is the core or `trailryx-verify`: an auditor
# reads the verifier, and every crate pulled into it is a crate they are asked to
# trust instead of read.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

ALLOWED="trailryx-sql trailryx-crypto-aws trailryx-demo"

case "${1:-check}" in
  # `list` prints the crates to exclude when asking whether the core stands alone.
  list)
    for crate in $ALLOWED; do printf -- '--exclude %s ' "$crate"; done
    exit 0
    ;;
esac

offenders=""
for dir in crates/*/; do
  crate=$(basename "$dir")
  case " $ALLOWED " in *" $crate "*) continue ;; esac
  n=$(cargo tree -p "$crate" --prefix none 2>/dev/null | grep -v '^trailryx' | grep -c . || true)
  if [ "$n" -ne 0 ]; then
    offenders="$offenders $crate($n)"
  fi
done

if [ -n "$offenders" ]; then
  printf 'third-party dependencies in crates that are not on the declared list:%s\n' "$offenders"
  exit 1
fi
printf 'declared: %s\n' "$ALLOWED"
