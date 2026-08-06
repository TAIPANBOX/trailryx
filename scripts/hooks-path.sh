#!/usr/bin/env bash
#
# The hook that runs belongs to the worktree it is running for.
#
# `core.hooksPath` has two scopes and the narrower one is invisible. `.git/config`
# here says `.githooks`, which is RELATIVE and therefore resolves inside whichever
# worktree git is running in, and that is right: it is what `CONTRIBUTING.md` and the
# README tell people to set. But `extensions.worktreeConfig` is on, and a worktree can
# carry its own `config.worktree` that overrides it with an ABSOLUTE path into
# whichever checkout created it. Nothing about that is visible from the worktree:
# `git config --get core.hooksPath` answers with the override and does not mention
# that a different value was overridden.
#
# What that does is split the gate across two commits. The hook comes from whatever
# branch the OTHER checkout has out; the scripts it calls come from this one, because
# the hook's first act is `cd "$(git rev-parse --show-toplevel)"`. So the list of
# checks and the checks themselves can be from different days.
#
# Measured on 6 August 2026. A push from a worktree was refused because the main
# checkout was on `gate/one-check-count`, whose hook calls `scripts/gate-count.sh`,
# and the pushing branch predated that script. That direction is loud and costs ten
# minutes. **The other direction is silent and is the reason this file exists:** if
# the other checkout sits on an OLDER branch, the push runs FEWER checks than the
# commit requires and prints `all N checks passed`. That is the same shape as a test
# that skips and reports a pass, which is what invariant 19 is about.
#
# WHAT THIS CANNOT DO, said first because it matters more than what it can. This runs
# only when the hook that ran is one that calls it, so a hook older than this file
# cannot refuse on its behalf. It closes the case forward, not backward. The actual
# repair is one command in the affected worktree, and the message below prints it.
#
# NOT a `step` in the hook and not called by CI, on purpose and not by omission. CI
# has no hooks, so there is nothing there for this to ask about, and this is a
# precondition for the gate rather than one of its checks. `scripts/gate-count.sh`
# counts `step` and `say` lines, so leaving it out of both keeps the two counts equal,
# which is the honest arithmetic: the number of CHECKS did not change.

set -uo pipefail

root=$(git rev-parse --show-toplevel) || exit 1
mine=$root/.githooks

# Resolve to a physical path so that a symlinked worktree, or `/var` against
# `/private/var` on macOS, does not read as a mismatch when it is not one.
physical() {
  (cd "$1" 2>/dev/null && pwd -P) || printf '%s' "$1"
}

want=$(physical "$mine")

# With an argument, the question is about the file that IS executing, which is what
# actually matters and is stronger than asking the configuration what it intends.
# The hook passes its own `$0`. Without one, fall back to asking git where it would
# look, so the script is still useful run by hand.
if [ "$#" -gt 0 ] && [ -n "${1:-}" ]; then
  ran=$(physical "$(dirname "$1")")
  subject="the hook that is running"
else
  configured=$(git rev-parse --git-path hooks)
  case $configured in
    /*) ;;
    *) configured=$root/$configured ;;
  esac
  ran=$(physical "$configured")
  subject="the hook directory git would use"
fi

if [ "$ran" = "$want" ]; then
  printf '%s\n' "$want"
  exit 0
fi

printf '%s is not this worktree'"'"'s\n' "$subject"
printf '  running:   %s\n' "$ran"
printf '  this tree: %s\n' "$want"
printf '\n'
printf 'So the checks that ran are this commit'"'"'s and the list of them is not, and if the\n'
printf 'other checkout is on an older branch this push ran fewer checks than it should\n'
printf 'have and would have said so cheerfully. Repair it in THIS worktree with:\n'
printf '\n'
printf '  git config --worktree --unset core.hooksPath\n'
printf '\n'
printf 'which leaves the relative `.githooks` from `.git/config` in force, the value\n'
printf 'CONTRIBUTING.md tells you to set, and that one resolves per worktree.\n'
exit 1
