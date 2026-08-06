#!/usr/bin/env bash
#
# No test builds a path under the temp directory that another process would build too.
#
# `$TMPDIR` is shared by every process one user runs. A fixture that names its scratch
# directory after itself, and nothing else, is therefore naming a directory that a
# second run of the same binary will name identically: two git worktrees on one
# machine, a `.githooks/pre-push` run beside a developer's `cargo test`, two agent
# sessions. Whichever of them wipes first takes the other's files, and the failure
# surfaces a long way from its cause, as a file that was written and then was not
# there.
#
# This is not hypothetical and it is not one fixture. Measured on 6 August 2026, eight
# copies of one compiled test binary run at once, five rounds:
#
#   trailryx-anchor's authority       11 of 30 processes failed before, 0 of 60 after
#   trailryx-asn1's OpenSSL oracle    12 of 40 processes failed before, 0 of 40 after
#
# The first cost two refused pushes and an hour, because the panic named
# `query.tsq` in a directory that had ceased to exist and said nothing about who had
# removed it. Ten sites carried the shape, and when this was written nine of them had
# never been seen to fail, which is the property that makes this worth a gate rather
# than a fix.
#
# Six of those nine have since been seen to fail, each measured on its own at thirty
# copies rather than eight. The table is in VALIDATION.md. The two that matter to
# anybody reading this file:
#
#   trailryx-store's two_verifiers    86 of 150 before, 0 of 300 after. It is its own
#                                     step of the hook, so it refused pushes.
#   trailryx-store's anchored         0 of 150 by exit code, and 145 of 150 processes
#                                     ran no anchor test at all while printing
#                                     `13 passed`. A collision there is a silence.
#
# The rule is one thing and it is mechanical: a path derived from `temp_dir()` carries
# `std::process::id()`. Not every such path can collide, two processes writing
# identical bytes to one file usually get away with it, and a rule that asks a reader
# to judge which ones can is a rule nobody applies to their own new fixture at half
# past midnight.
#
# The projection oracle was the example of getting away with it, and it is half an
# example. That file holds two fixtures: the cells test writes identical bytes and
# removes nothing, and is 0 of 300; the lists test removes its directory at the end,
# and is 95 of 150. Run together at eight copies they fail 13 of 40. A zero over that
# whole binary is what `TRAILRYX_PARQUET_ORACLE` being unset produces, because both
# tests then return before they reach a path, which is invariant 19 and not evidence
# about directories.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

problems=0
paths=0

# Statements rather than lines, because a path is often built across a wrapped line
# and the process id may be on either of them. A statement ends at a semicolon, which
# is coarse and is enough here: the question asked of each one is only whether two
# particular calls appear in it.
while IFS= read -r hit; do
  case "$hit" in
    COUNT:*) paths=$((paths + ${hit#COUNT:})) ;;
    *)
      printf '%s: a temp path with no process id in it, so two runs of this binary share it\n' "$hit"
      problems=$((problems + 1))
      ;;
  esac
done < <(
  git ls-files '*.rs' | while IFS= read -r f; do
    awk -v F="$f" '
      { buf = buf $0 " "; if (start == 0) start = FNR }
      /;/ {
        if (buf ~ /temp_dir\(\)/) {
          count++
          if (buf !~ /process::id\(\)/) printf "%s:%d\n", F, start
        }
        buf = ""; start = 0
      }
      END { if (count) printf "COUNT:%d\n", count }
    ' "$f"
  done
)

if [ "$problems" -gt 0 ]; then
  printf 'the fix is the idiom the workspace already uses: '
  printf 'format!("name-{}", std::process::id())\n'
  printf '%d temp path(s) that a second process on this machine would collide with\n' "$problems"
  exit 1
fi

# The count is printed rather than a bare "ok", so a run can be compared against
# another run. A check that says only that it passed is a check that cannot be
# compared with anything, including its own last result.
printf '%d temp paths, every one of them carrying a process id\n' "$paths"
exit 0
