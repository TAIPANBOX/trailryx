#!/usr/bin/env bash
#
# Does this push consist of nothing but ref deletions?
#
# Exit 0 and print the ref count when it does; exit 1 when it does not, and when the
# answer is not knowable. This is `.githooks/pre-push`'s own decision, moved out to
# where a check can reach it, and the reason it had to move is worth stating: a check
# that the hook runs cannot test the hook by running it, because a case whose correct
# answer is "run everything" would run the gate, which would run the check, which
# would run the hook. The cases that matter most are exactly those, so testing the
# decision in place was not available. Invariant 17 wanted this in `scripts/` anyway.
#
# Git feeds the hook one line per ref on stdin:
#
#     <local ref> <local sha> <remote ref> <remote sha>
#
# and a deletion is a line whose LOCAL sha is all zeroes. Every line is asked, not the
# first, so a push that deletes one branch and updates another answers "no".
#
# INVARIANT 32 LIVES HERE: the answer is yes only on positive evidence, at least one
# ref AND every ref a deletion. Absence of information is not absence of work. An
# empty stdin is the case that matters, because it is how the hook is run by hand and
# by anybody following CONTRIBUTING.md, and reading no refs as nothing to do would
# turn every hand run into a silent pass.
#
# Called by the hook, not by CI, and not counted as one of the gate's checks: it is
# the gate deciding whether to run rather than one of the things it runs.
# `scripts/deletion-skip-cases.sh` is the check that this file behaves.

set -uo pipefail

# A terminal is never read. `.githooks/pre-push` typed at a prompt would otherwise
# hang here with no output, which invariant 18 has something to say about, and it
# carries no refs in any case.
[ -t 0 ] && exit 1

refs=0
deletions=0
started=$SECONDS

# The read is bounded so an unclosed pipe cannot hang the hook. A stall is detected
# with the CLOCK and not with `read`'s exit status, and that is not fussiness: `read
# -t` returns above 128 on timeout in bash 4 and later, while the bash on this machine
# is 3.2.57, the one Apple ships, which returns 1 for a timeout and 1 for the end of
# input alike. Measured: on a pipe held open and silent, `read -r -t 3` returns status
# 1 after three seconds. The bound works; the way of telling why the read ended does
# not survive being asked.
while read -r -t 10 _local_ref local_sha _rest; do
  [ -n "${local_sha:-}" ] || continue
  refs=$((refs + 1))
  case $local_sha in
    *[!0]*) ;;
    *) deletions=$((deletions + 1)) ;;
  esac
done

# A stall means there may have been more refs coming, so the refs are unknown, so the
# answer is no. The dangerous mistake available here is to answer yes about a push
# that was carrying something.
if [ $((SECONDS - started)) -ge 10 ]; then
  printf 'stdin stalled, so the refs are unknown and every check will run\n' >&2
  exit 1
fi

[ "$refs" -gt 0 ] && [ "$refs" = "$deletions" ] || exit 1
printf '%d\n' "$refs"
exit 0
