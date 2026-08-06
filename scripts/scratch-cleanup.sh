#!/usr/bin/env bash
#
# Every scratch path under the temp directory is removed by the file that made it.
#
# This is the debt invariant 29 took on. Putting `std::process::id()` into a fixture
# path was right and is what stops two runs sharing a directory, but it changes what
# "nothing ever deletes this" costs. A constant path that is never wiped is one stale
# directory, reused by every run forever, and nobody notices for a year. The same path
# with a process id in it is a NEW directory on every run, and the pile grows for as
# long as the machine lives.
#
# Measured on 6 August 2026, five runs of each affected suite, counting `$TMPDIR`
# afterwards:
#
#   trailryx-store's signed        55 directories, and 55 EC private keys inside them
#   trailryx-otlp's JSON oracle     5 directories holding 80 files
#   two_verifiers, inflate          5 directories each
#
# `signed` is the one that carries the argument. Its scratch holds the key its
# `Openssl::new` generates, so before this rule the working state of any machine that
# ran the suite was an unbounded pile of private keys in a world-readable temp
# directory. Nothing there is secret, they are throwaway test keys, and that is not
# the point: a fixture that leaves key material behind teaches the habit that leaving
# key material behind is normal.
#
# WHAT THIS CHECKS, precisely, because it is a count and not a proof. For each file,
# every `let` that builds a path from `temp_dir()` is counted by the name it binds,
# and so is every `remove_dir_all` that names that same binding, whether directly or
# through `self.` for the `Drop` spelling. A name bound more often than it is removed
# is reported. Counting rather than merely looking is what catches the projection
# oracle, which had two fixtures and one wipe: a check asking only "does this file
# remove anything" would have called that file clean, and it was the file that leaked.
#
# WHAT IT DOES NOT CATCH, and this is the honest half:
#
#   - A pre-clean is indistinguishable from a cleanup. `remove_dir_all` before
#     `create_dir_all` guards against a recycled process id and is not tidying up,
#     but it satisfies this count exactly as a real wipe does. `anchored.rs` has both
#     and would still pass if its `Drop` were deleted.
#   - A wipe placed below an early return is a wipe this cannot see past. `inflate`
#     needed its call moved ABOVE two returns, and this check would have been happy
#     either way.
#
# Both are cases where the removal exists and is in the wrong place. What the check
# holds is the case that actually happened five times in one day: the removal was not
# written at all. That is worth a gate; the rest is worth the sentence above.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

problems=0
paths=0

while IFS= read -r hit; do
  case "$hit" in
    COUNT:*) paths=$((paths + ${hit#COUNT:})) ;;
    *)
      printf '%s\n' "$hit"
      problems=$((problems + 1))
      ;;
  esac
done < <(
  git ls-files '*.rs' | while IFS= read -r f; do
    awk -v F="$f" '
      # Statements rather than lines, for the same reason temp-paths.sh reads them
      # that way: a path is routinely built across a wrapped line.
      {
        buf = buf $0 " "
        if (start == 0) start = FNR
        # The line the call is actually on, not where the statement began. A struct
        # definition carries no semicolon, so the buffer for the `let` after one can
        # open two dozen lines above the thing being reported.
        if ($0 ~ /temp_dir\(\)/) at = FNR
      }

      # Every removal in the file, by the name it removes. Read per line, because a
      # `Drop` body is nowhere near the `let` it undoes.
      {
        line = $0
        while (match(line, /remove_dir_all\([ ]*&?[ ]*(self\.)?[A-Za-z_][A-Za-z0-9_]*/)) {
          piece = substr(line, RSTART, RLENGTH)
          sub(/^remove_dir_all\([ ]*&?[ ]*/, "", piece)
          sub(/^self\./, "", piece)
          removes[piece]++
          line = substr(line, RSTART + RLENGTH)
        }
      }

      /;/ {
        if (buf ~ /temp_dir\(\)/) {
          count++
          # The name this statement binds. `let`, optionally `mut`, optionally typed.
          if (match(buf, /let[ ]+(mut[ ]+)?[A-Za-z_][A-Za-z0-9_]*/)) {
            name = substr(buf, RSTART, RLENGTH)
            sub(/^let[ ]+(mut[ ]+)?/, "", name)
            binds[name]++
            if (firstline[name] == 0) firstline[name] = at
          }
        }
        buf = ""; start = 0; at = 0
      }

      END {
        for (n in binds) {
          if (removes[n] < binds[n]) {
            printf "%s:%d: `%s` is built from temp_dir() %d time(s) and removed %d, so a run leaves its scratch behind\n",
              F, firstline[n], n, binds[n], removes[n]
          }
        }
        if (count) printf "COUNT:%d\n", count
      }
    ' "$f"
  done
)

if [ "$problems" -gt 0 ]; then
  printf 'the fix is a `remove_dir_all` on every exit that is not a failure worth reading,\n'
  printf 'or a `Drop` on the struct that owns the path\n'
  printf '%d scratch path(s) that no run ever removes\n' "$problems"
  exit 1
fi

# The count is printed rather than a bare "ok", for the reason temp-paths.sh gives:
# a check that says only that it passed cannot be compared with its own last result.
printf '%d scratch paths, every one of them removed by the file that made it\n' "$paths"
exit 0
