#!/usr/bin/env bash
#
# Every number the README states about this repository, checked against the
# repository.
#
# This exists because of what an audit of the page on 30 July 2026 found: six crate
# test counts in the table had drifted as tests were added, the dependency count
# behind the SQL facade could not be reproduced by any reading of the tree, and a
# line describing the verifier's token reader was off by a factor of two. None of it
# was a lie when it was written. That is the point: a number in a README is a claim
# with no owner, and the only way one stays true is if something refuses the push
# when it stops being true.
#
# It checks four things, and each one is a claim a reader would take at face value:
#
#   1. the tests badge equals what `cargo test` actually runs;
#   2. every crate row's count equals that crate's own suite;
#   3. the rows sum to the total, so the table is checkable at a glance;
#   4. the stage badge is not behind the roadmap.
#
# It does not check prose. Prose needs a reader; numbers need a script.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
problems=0

note() {
  printf '%s\n' "$1"
  problems=$((problems + 1))
}

# Total, from the suite itself rather than from anything that quotes it.
total=$(cargo test --workspace --quiet 2>/dev/null |
  grep -E '^test result' | awk '{s += $4} END {print s + 0}')
if [ "$total" -eq 0 ]; then
  note "the suite reported no tests at all, which means this check measured nothing"
  exit 1
fi

badge=$(grep -o 'badge/tests-[0-9]*-' "$readme" | grep -o '[0-9]*')
[ "$badge" = "$total" ] ||
  note "the badge says $badge tests and the suite runs $total"

quoted=$(grep -o '# [0-9]* tests' "$readme" | grep -o '[0-9]*' | head -1)
[ "$quoted" = "$total" ] ||
  note "the Try it block says $quoted tests and the suite runs $total"

# Per crate. The table is the part that rots fastest, because adding a test to a
# crate is exactly when nobody is looking at the README.
sum=0
while IFS= read -r line; do
  crate=$(printf '%s' "$line" | sed -n 's/^| `\([a-z0-9-]*\)`.*/\1/p')
  stated=$(printf '%s' "$line" | awk -F'|' '{gsub(/ /, "", $(NF-1)); print $(NF-1)}')
  [ -n "$crate" ] || continue
  # A crate whose row says "-" has no suite of its own by design.
  [ "$stated" != "-" ] || continue
  actual=$(cargo test -p "$crate" --quiet 2>/dev/null |
    grep -E '^test result' | awk '{s += $4} END {print s + 0}')
  sum=$((sum + actual))
  [ "$stated" = "$actual" ] ||
    note "$crate: the table says $stated tests and the crate runs $actual"
done < <(grep '^| `trailryx-' "$readme")

[ "$sum" -eq "$total" ] ||
  note "the table's rows sum to $sum and the workspace runs $total"

# The stage badge, against the roadmap that owns the order of work.
stage=$(grep -o 'badge/stage-[0-9]*%20of%20[0-9]*' "$readme" | grep -o '[0-9]*' | head -1)
closed=$(grep -oE 'Етап [0-9]+ закритий' docs/planning/trailryx-roadmap.md |
  grep -oE '[0-9]+' | sort -n | tail -1)
if [ -n "$closed" ] && [ "$stage" -lt "$closed" ]; then
  note "the badge says stage $stage and the roadmap records stage $closed closed"
fi

if [ "$problems" -gt 0 ]; then
  printf 'the README states %d number(s) the repository does not support\n' "$problems"
  exit 1
fi
printf '%d tests across %d crate rows, badge and table agree\n' \
  "$total" "$(grep -c '^| `trailryx-' "$readme")"
