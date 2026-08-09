#!/usr/bin/env bash
#
# How many checks the gate runs, counted rather than remembered.
#
# Three claims, and the first is the one worth having:
#
#   1. `.githooks/pre-push` and `.github/workflows/ci.yml` run the same NUMBER of
#      checks. The header of both files promises a green push is a green pull
#      request, and until now nothing counted them. A check added to one and not the
#      other is a laptop that says yes and a runner that says no, which has happened
#      here before and cost an afternoon.
#   2. The README, which is where the checks are listed for a reader, states that
#      number correctly.
#   3. No other tracked file states a number of its own.
#
# The third exists because of what the first run of this script found:
# `CONTRIBUTING.md` had put the number at twelve since the day it was written, and by
# then the gate ran eighteen. It also listed them, and the list was missing six.
# Nobody had noticed, because a number in prose has no owner and a list in prose has
# less of one. That file now points at the README instead of keeping a copy.
#
# The sentence above is worded around this check on purpose. Written the way
# `CONTRIBUTING.md` had written it, quoting the claim rather than describing it, this
# file fails its own rule, and it did: the first push carrying it was refused at this
# line. It passed before the commit only because the scan reads tracked files, and an
# uncommitted script is not one, so the check's reach grew at exactly the moment it
# stopped being able to see itself missing. A gate that cannot be run against its own
# working copy is worth knowing about.
#
# This is invariant 16 again, on the number that had drifted the most times in one
# day: sixteen to seventeen to eighteen on 6 August 2026, each step meaning a hand
# edit in five documents, which is exactly the shape of a number that is about to be
# wrong somewhere.
#
# What it deliberately does NOT flag: a sentence recording what a count used to be.
# The README's own "fifteen green checks on a laptop and a red gate on the runner" is
# history, and history is why that check exists. The shapes below are the ones this
# repository writes when it is making a CLAIM about today.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
hook=".githooks/pre-push"
ci=".github/workflows/ci.yml"
problems=0

note() {
  printf '%s\n' "$1"
  problems=$((problems + 1))
}

# The hook's own checks. `step` and `say` are the two wrappers it runs them through;
# `say` exists for the ones that print what they measured.
hook_count=$(grep -cE '^(step|say) ' "$hook")

# CI runs exactly one check the hook cannot, and it is named here rather than
# left as slack in the comparison, because slack is how the two drift.
#
# `scripts/gates-have-teeth.sh` breaks each check on purpose and requires the
# failure. One of its cases rewrites `.githooks/pre-push`, to check that this
# script notices a hook with no countable checks left. Bash reads a script as it
# executes it, so running that from the hook makes the shell resume inside
# different bytes; measured 2026-08-09 as "unexpected EOF while looking for
# matching quote" at the last line, after every check had already passed.
#
# So the hook is allowed to be exactly one short, of exactly this check. Any
# other difference is still a laptop that says yes and a runner that says no.
ci_only=$(grep -cE '^\s+run: \./scripts/gates-have-teeth\.sh' "$ci")

# CI's checks, which are the steps whose first line of `run:` invokes cargo or a
# script. That is what separates them from the setup steps (checkout, toolchain,
# cache, protoc), and it has to look at the FIRST line: the advisories step installs
# cargo-audit before calling the same script the hook calls. An environment variable
# in front is still a check, which is how the fuzzer asks CI for ten times the volume.
ci_count=$(awk '
  /^      - name:/ { inrun = 0; next }
  /^        run:/ {
    rest = $0
    sub(/^        run: */, "", rest)
    if (rest != "" && rest != "|") { emit(rest); next }
    inrun = 1
    next
  }
  inrun && /^          [^ ]/ { line = $0; sub(/^ */, "", line); emit(line); inrun = 0 }
  function emit(line) {
    while (line ~ /^[A-Z_]+=[^ ]+ /) sub(/^[A-Z_]+=[^ ]+ /, "", line)
    if (line ~ /^(cargo |\.\/scripts\/)/) count++
  }
  END { print count + 0 }
' "$ci")

[ "$hook_count" -gt 0 ] ||
  note "counted no checks in $hook at all, which means this check measured nothing"

# The comparison subtracts the one CI-only check rather than inflating the hook,
# so the README stays true about what the hook actually runs.
[ "$hook_count" = "$((ci_count - ci_only))" ] ||
  note "$hook runs $hook_count checks and $ci runs $ci_count with $ci_only of them CI-only, so a green push is not a green pull request"

# The README's figure, written the way this repository writes numbers in prose.
words="zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty-one twenty-two twenty-three twenty-four twenty-five"
word_for() {
  local n=$1 i=0
  for w in $words; do
    [ "$i" = "$n" ] && { printf '%s' "$w"; return; }
    i=$((i + 1))
  done
  printf '%s' "$n"
}
number_for() {
  local want=$1 i=0
  for w in $words; do
    [ "$w" = "$want" ] && { printf '%s' "$i"; return; }
    i=$((i + 1))
  done
  printf '%s' "$want"
}

stated=$(grep -oE '`\.githooks/pre-push` runs [a-z-]+ checks' "$readme" | awk '{print $(NF-1)}')
if [ -z "$stated" ]; then
  note "$readme no longer says how many checks the gate runs, and it is the one file that should"
else
  [ "$(number_for "$stated")" = "$hook_count" ] ||
    note "$readme says the gate runs $stated checks and $hook runs $hook_count ($(word_for "$hook_count"))"
fi

# Every other file. The shapes are the claim-making ones, listed rather than guessed
# at, and a new phrasing would escape this: said out loud because a check that hides
# its own limit is worse than one that states it.
#
# A number, and only a number: an early version of this matched any word after "the
# same" and flagged "runs the same set", which is the phrasing this change introduced
# everywhere else. A check whose first act is to refuse the fix for the thing it
# checks is a check people learn to route around.
num=$(printf '%s' "$words" | tr ' ' '|')
num="($num|[0-9]+)"
shapes="runs $num checks|runs the same $num|the same $num checks|gate.s $num (also )?run|$num checks, run by"
while IFS= read -r f; do
  [ "$f" = "$readme" ] && continue
  [ -f "$f" ] || continue
  file "$f" | grep -q text || continue
  hits=$(grep -nEi "$shapes" "$f" || true)
  [ -n "$hits" ] || continue
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    note "$f:${hit%%:*} states how many checks the gate runs, and the README is the one place that may"
  done <<EOF
$hits
EOF
done < <(git ls-files)

if [ "$problems" -gt 0 ]; then
  printf 'the count belongs in one file, and the others say "the same checks"\n'
  exit 1
fi
printf '%d checks in the hook, %d in CI (%d CI-only), README says %s\n' "$hook_count" "$ci_count" "$ci_only" "$stated"
exit 0
