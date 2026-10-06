#!/usr/bin/env bash
#
# Invariant 45: a crate's integration tests link into one binary.
#
# Cargo makes every top-level `tests/*.rs` a test target of its own, and every target
# links the crate's whole dependency tree again, debug info and all. In a crate that
# carries DataFusion that is hundreds of megabytes per file, written again on every
# rebuild that touches anything underneath, so a crate with seven test files wrote
# seven copies of its world on one `cargo test`. The disk pays for that, not the
# clock, which is why nobody noticed: it shows up as an SSD's write budget spent in a
# week rather than as a slow run.
#
# So each crate has at most one integration-test target, `tests/it/main.rs`, with one
# `mod` per former file (or a single `tests/<name>.rs` while it has only one). What is
# counted is what cargo would build:
#
#   - every top-level `tests/*.rs`, each autodiscovered as a target;
#   - every `tests/<dir>/main.rs`, autodiscovered the same way (`tests/it` is one);
#   - every `[[test]]` table in the crate's manifest. One that only configures an
#     autodiscovered target is counted twice, which is the safe direction: it refuses
#     rather than passes, and the allow-list below is where a real reason goes.
#
# It reads the disk rather than `git ls-files`, because cargo builds what is on the
# disk, and an untracked test file is exactly what somebody adds before committing.
#
# WHAT IT DOES NOT CHECK, said here rather than discovered: `autotests = false` with
# targets declared some other way, a test target in a crate outside `crates/`, and
# whether a test that moved into `tests/it` still shares process-wide state safely with
# its new neighbours. That last one is the real cost of the merge and only a reading
# can judge it: separate binaries were separate processes, one binary is one process,
# so `set_var`, `set_current_dir`, a global subscriber and a scratch path keyed only on
# the process id all became shared on the day this landed. CLAUDE.md invariant 45 says
# what was audited.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

# Crates allowed more than one integration-test binary, one per line, as
#   crates/<name>  <why it needs a process of its own>
# Empty today. A line here is a decision, so it carries its reason, and a line whose
# crate no longer needs it fails the check: an exemption that outlives its reason
# protects nothing while still reading as a decision (invariant 24's rule, here).
allowed=""

problems=0
crates=0
with_tests=0

note() {
  printf '%s\n' "$1"
  problems=$((problems + 1))
}

reason_for() {
  printf '%s\n' "$allowed" | awk -v c="$1" '$1 == c { $1 = ""; sub(/^ +/, ""); print; exit }'
}

for manifest in crates/*/Cargo.toml; do
  [ -f "$manifest" ] || continue
  crate=${manifest%/Cargo.toml}
  crates=$((crates + 1))

  targets=()
  for f in "$crate"/tests/*.rs "$crate"/tests/*/main.rs; do
    [ -f "$f" ] && targets+=("${f#"$crate"/}")
  done
  declared=$(grep -cE '^\[\[test\]\]' "$manifest")
  count=$((${#targets[@]} + declared))
  [ "$count" -gt 0 ] && with_tests=$((with_tests + 1))

  extra=""
  [ "$declared" -gt 0 ] && extra=", $declared [[test]] table(s)"
  reason=$(reason_for "$crate")
  if [ "$count" -gt 1 ] && [ -z "$reason" ]; then
    note "$crate builds $count integration-test binaries (${targets[*]}$extra): move the files into tests/it/ as modules of one"
  elif [ "$count" -le 1 ] && [ -n "$reason" ]; then
    note "$crate is allowed more than one test binary ($reason) and builds $count, so the exemption is stale"
  fi
done

# An allow-list line naming a crate that is not there is stale the same way.
while read -r c _; do
  [ -n "$c" ] || continue
  [ -f "$c/Cargo.toml" ] || note "the allow-list names $c, which is not a crate"
done <<EOF
$allowed
EOF

# The subject first, before any verdict. A glob over a directory that is not there
# matches nothing, and a loop over nothing finds no crate with two binaries.
if [ "$crates" -eq 0 ]; then
  echo "FAIL: no crates/*/Cargo.toml found, so this measured nothing."
  echo "      If the crates moved, this check has to move with them."
  exit 1
fi

if [ "$problems" -gt 0 ]; then
  echo "each integration-test file is a binary that links the whole dependency tree again"
  exit 1
fi
printf '%d crates, %d with integration tests, one binary each\n' "$crates" "$with_tests"
exit 0
