#!/usr/bin/env bash
#
# Invariant 32: a gate skips only on positive evidence that there is nothing to check.
#
# `.githooks/pre-push` exits without running anything when every ref in the push is a
# deletion. That shortcut is worth having, and it has one dangerous direction: skipping
# when something was in fact being pushed. The empty case is the one to watch, because
# an empty stdin is how the hook is run BY HAND, and a hand run has no backstop at all.
# A push that wrongly skips still meets CI, which is what a pull request is for; a
# developer typing `.githooks/pre-push` to check their work meets nothing.
#
# WHY THIS CHECKS THE DECISION AND NOT THE HOOK, in most of its cases. A check the gate
# runs cannot test the hook by running it: a case whose correct answer is "run
# everything" would run the gate, which would run this file, which would run the hook.
# Those are precisely the cases worth checking. So the decision lives in
# `scripts/deletion-only-push.sh` where it can be exercised on its own, and what
# remains about the hook is asked of its text and of one safe end-to-end run.
#
# The end-to-end run is the deletion case, which exits before any check starts. It is
# fenced twice anyway, because the run it is least safe to make is the one where the
# invariant is already broken: `TRAILRYX_DELETION_SKIP_INNER` makes a nested copy of
# this check a no-op, and the run is killed if it has not exited quickly. Neither fence
# is decoration; without them a regression here would launch the gate inside the gate.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

# The inner copy, if the hook below ever reaches its checks, does nothing and says so.
if [ -n "${TRAILRYX_DELETION_SKIP_INNER:-}" ]; then
  printf 'nested run, not recursing\n'
  exit 0
fi

decide=./scripts/deletion-only-push.sh
hook=.githooks/pre-push
problems=0
cases=0

Z=0000000000000000000000000000000000000000
H=1111111111111111111111111111111111111111

note() {
  printf '%s\n' "$1"
  problems=$((problems + 1))
}

# `want` is skip or run. The decision answers 0 for skip and 1 for run, and prints the
# ref count when it skips, which is checked too: a count the hook prints has to be the
# number of refs and not, say, the number of lines it happened to read.
expect() {
  local want=$1 label=$2 count=${3:-} input=$4
  cases=$((cases + 1))
  local out status
  out=$(printf '%s' "$input" | "$decide" 2>/dev/null)
  status=$?
  case $want in
    skip)
      [ "$status" = 0 ] || { note "$label: should have been a skip and was not"; return; }
      [ -z "$count" ] || [ "$out" = "$count" ] ||
        note "$label: skipped but counted $out refs where there are $count"
      ;;
    run)
      [ "$status" = 0 ] && note "$label: SKIPPED, and this push was carrying something"
      ;;
  esac
}

# Skips. Both need at least one ref and every ref a deletion.
expect skip "one deletion"    1 "(delete) $Z refs/heads/a $H
"
expect skip "three deletions" 3 "(delete) $Z refs/heads/a $H
(delete) $Z refs/heads/b $H
(delete) $Z refs/heads/c $H
"

# Runs. Each of these is a way of having something to check, or of not knowing.
expect run "an ordinary push"       "" "refs/heads/x $H refs/heads/x $Z
"
expect run "a deletion and an update" "" "(delete) $Z refs/heads/a $H
refs/heads/x $H refs/heads/x $Z
"
expect run "the update first"       "" "refs/heads/x $H refs/heads/x $Z
(delete) $Z refs/heads/a $H
"
# The one with no backstop. An empty stdin is a hand run, and it must never skip.
expect run "no refs at all"         "" ""
expect run "nothing but blank lines" "" "

"

# A stall must not skip either, and the stall that matters is A DELETION AND THEN A
# STALL. That is not the obvious case and the first version of this check got it wrong:
# it stalled with nothing read at all, which the ref count already refuses, so the
# clock is not load-bearing there and removing it went undetected. Here one deletion
# has been read and the pipe then goes quiet, so every counter says "skip" and only the
# clock says the refs are unknown. Verified by deleting the clock check and watching
# this fail.
#
# It costs a wall-clock wait, so it says what it is doing. Ten seconds against a gate
# that takes minutes is noise, and the alternative is a timeout parameter that exists
# only for the check and can drift from the one that ships.
printf 'the stall case waits for the read bound, about ten seconds\n'
cases=$((cases + 1))
fifo=$(mktemp -u "${TMPDIR:-/tmp}/trailryx-refs-$$-XXXX")
mkfifo "$fifo" || exit 1
( printf '(delete) %s refs/heads/a %s\n' "$Z" "$H"; sleep 13 ) > "$fifo" &
holder=$!
if "$decide" < "$fifo" >/dev/null 2>&1; then
  note "a deletion then a stalled stdin: SKIPPED, and more refs may have been coming"
fi
kill "$holder" 2>/dev/null
wait "$holder" 2>/dev/null
rm -f "$fifo"

# What is left is about the hook rather than the decision, and is asked of its text.
#
# The order matters and is the thing most likely to be tidied back: the precondition
# that this is the right hook has to answer BEFORE the skip, because the skip is
# decided by the file whose provenance is in question.
cases=$((cases + 1))
grep -q "$decide" "$hook" ||
  note "$hook does not call $decide, so the decision it is checked against is not the one it makes"

cases=$((cases + 1))
precondition=$(grep -n 'scripts/hooks-path.sh' "$hook" | head -1 | cut -d: -f1)
shortcut=$(grep -n 'scripts/deletion-only-push.sh' "$hook" | head -1 | cut -d: -f1)
if [ -z "$precondition" ] || [ -z "$shortcut" ]; then
  note "$hook no longer has both the hooks-path precondition and the deletion shortcut"
elif [ "$precondition" -ge "$shortcut" ]; then
  note "$hook decides to skip (line $shortcut) before checking it is the right hook (line $precondition)"
fi

# And one end-to-end run of the hook itself, on the case that exits before any check.
# Doubly fenced, as the header says.
cases=$((cases + 1))
out=$(mktemp "${TMPDIR:-/tmp}/trailryx-hook-$$-XXXX")
TRAILRYX_DELETION_SKIP_INNER=1 "$hook" origin url >"$out" 2>&1 <<EOF &
(delete) $Z refs/heads/a $H
EOF
pid=$!
alive=1
for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "$pid" 2>/dev/null || { alive=0; break; }
  sleep 0.3
done
if [ "$alive" = 1 ]; then
  kill -9 "$pid" 2>/dev/null
  note "$hook did not exit on a deletion-only push, so it started checking something"
elif ! grep -q 'every one a deletion, so no check ran' "$out"; then
  note "$hook exited on a deletion-only push without saying that it had skipped"
fi
rm -f "$out"

if [ "$problems" -gt 0 ]; then
  printf 'the rule is invariant 32: skip on positive evidence, and say so\n'
  exit 1
fi
printf '%d cases, the skip fires only on refs that are all deletions\n' "$cases"
exit 0
