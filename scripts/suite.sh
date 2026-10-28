#!/usr/bin/env bash
#
# The workspace suite, run once, and what other checks may count from that run.
#
#   ./scripts/suite.sh              run `cargo test --workspace`
#   ./scripts/suite.sh counts FILE  read a recorded run and print its counts
#
# WHY THIS EXISTS. `scripts/readme-numbers.sh` compares every test count the README
# states against the suite. It used to get them by running the suite again: once for
# the workspace and then once per crate row, thirty-odd `cargo test -p` invocations,
# each resolving its own feature set and so each compiling parts of the tree the
# workspace run had already compiled. Measured on CI with a cold cache on 2026-10-28,
# in three runs: that one step took 12 to 15 minutes, about as long as the compile and
# run of the whole suite it was checking, and on a warm cache it was the single
# longest step. A count is a thing the first run already knows; asking the tree to
# produce it again bought nothing but time.
#
# THE RULE THAT MAKES THIS SAFE, and the reason it is one file. The count is only as
# good as the run it is read from, so the file that WRITES a record and the file that
# READS it are the same file, and the format is defined once. A record carries the
# commit it was made at, the exit status of the run, and cargo's own account of which
# test binary belongs to which crate; `counts` refuses a record that lacks any of the
# three, rather than reading a partial one. A partial count looks exactly like a
# measurement, which is the failure `readme-numbers.sh` already refuses for its own
# runs (6 August 2026: a badge said 1066 tests and the suite ran 51).
#
# WHAT IS RECORDED, and why this is not a second source of truth. Cargo is asked for
# its build messages as JSON alongside the test output. Each message names a test
# executable and the manifest it came from, and each "Running" line the test run
# prints names the executable it is about to run, so every `test result:` line is
# attributed to a crate by cargo's own naming rather than by a guess about directory
# layout or by the order tests happen to run in. Doc-tests are announced by crate.
# A result that cannot be attributed, a binary no message accounts for, and a record
# with no results at all are all errors. There is no fallback to a looser reading.
#
# NO RECORD, NO CHANGE. With TRAILRYX_SUITE_RECORD unset this runs exactly what the
# hook has always run, `cargo test --workspace --quiet`, and writes nothing. The
# record is written only where the caller asks for one, which today is CI: it is the
# one place where the suite and the README check run back to back in one job, on one
# checkout, with nothing in between that could change the tree. The hook still runs
# the suite again for the README check, which is slower and cannot be wrong in a way
# this file could be. Both sides run the same comparisons; only where the counts come
# from differs, and `scripts/gates-have-teeth.sh` holds the reading half.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

# --- counts ----------------------------------------------------------------------

counts() {
  local rec="$1"

  if [ ! -r "$rec" ]; then
    printf 'no suite record at %s, so nothing was counted\n' "$rec"
    return 1
  fi

  # The exit status of the run. Written last, so a run that was killed has none, and
  # a run that failed says so: a count from a failing run is not a count.
  local status
  status=$(sed -n 's/^suite-exit-status: //p' "$rec" | tail -1)
  if [ "$status" != 0 ]; then
    printf 'the suite record does not end in a clean run (exit status: %s), so nothing was counted\n' \
      "${status:-none recorded}"
    return 1
  fi

  # The commit it was made at. A record is evidence about one tree.
  local recorded here
  recorded=$(sed -n 's/^suite-head: //p' "$rec" | head -1)
  here=$(git rev-parse HEAD 2>/dev/null)
  if [ -z "$recorded" ] || [ "$recorded" != "$here" ]; then
    printf 'the suite record was made at commit %s and this checkout is %s, so nothing was counted\n' \
      "${recorded:-none recorded}" "${here:-unknown}"
    return 1
  fi

  # Two passes over one file. The first reads cargo's build messages: executable ->
  # the workspace crate whose manifest it was built from. Messages are replayed for
  # artifacts that were already fresh, so a fully cached build still produces them.
  # The second walks the test output, in the order it ran, and gives each result line
  # to whichever crate the last header named.
  local out
  out=$(awk '
    function base(p,   n, a) { n = split(p, a, "/"); return a[n] }

    NR == FNR {
      if ($0 ~ /^\{"reason":"compiler-artifact"/ && match($0, /"manifest_path":"[^"]*"/)) {
        mp = substr($0, RSTART + 17, RLENGTH - 18)
        if (match($0, /"executable":"[^"]*"/)) {
          ex = substr($0, RSTART + 14, RLENGTH - 15)
          n = split(mp, parts, "/")
          if (n >= 3 && parts[n] == "Cargo.toml" && parts[n - 2] == "crates") {
            owner[base(ex)] = parts[n - 1]
            member[parts[n - 1]] = 1
          }
        }
      }
      next
    }

    /^ *Running / {
      line = $0
      sub(/[ \t\r]+$/, "", line)
      cur = "?"
      if (match(line, /\([^()]*\)$/)) {
        exe = base(substr(line, RSTART + 1, RLENGTH - 2))
        if (exe in owner) cur = owner[exe]; else unknown[exe] = 1
      }
      if (cur != "?") seen[cur] = 1
      headers++
      next
    }

    /^ *Doc-tests / {
      cur = $2
      gsub(/_/, "-", cur)
      if (cur in member) seen[cur] = 1; else { unknown["Doc-tests " $2] = 1; cur = "?" }
      headers++
      next
    }

    /^test result: / {
      results++
      total += $4
      if (cur == "" || cur == "?") unattributed++; else count[cur] += $4
      cur = ""
      next
    }

    END {
      printf "headers %d\n", headers
      printf "results %d\n", results
      printf "total %d\n", total
      printf "unattributed %d\n", unattributed
      for (u in unknown) printf "unknown %s\n", u
      for (c in seen) printf "crate %s %d\n", c, count[c]
    }
  ' "$rec" "$rec")

  local results unattributed
  results=$(printf '%s\n' "$out" | awk '$1 == "results" {print $2}')
  unattributed=$(printf '%s\n' "$out" | awk '$1 == "unattributed" {print $2}')

  if [ "${results:-0}" -eq 0 ]; then
    printf 'the suite record holds no "test result" line at all (%s Running or Doc-tests header(s) seen), so nothing was counted\n' \
      "$(printf '%s\n' "$out" | awk '$1 == "headers" {print $2}')"
    return 1
  fi
  if [ "${unattributed:-0}" -ne 0 ]; then
    printf '%s test result line(s) in the suite record belong to no crate cargo named' "$unattributed"
    printf ' (binaries nothing accounts for: %s), so nothing was counted\n' \
      "$(printf '%s\n' "$out" | awk '$1 == "unknown" {sub(/^unknown /, ""); printf "%s; ", $0}')"
    return 1
  fi
  # Every run header is followed by exactly one result line, so a header with none is
  # a binary that ran and said nothing, or a record that was cut.
  local headers
  headers=$(printf '%s\n' "$out" | awk '$1 == "headers" {print $2}')
  if [ "${headers:-0}" -ne "$results" ]; then
    printf 'the suite record has %s run header(s) and %s result line(s), so nothing was counted\n' \
      "${headers:-0}" "$results"
    return 1
  fi

  printf '%s\n' "$out" | awk '$1 == "total" || $1 == "crate"' | sort
}

# --- run -------------------------------------------------------------------------

run() {
  local rec="${TRAILRYX_SUITE_RECORD:-}"

  if [ -z "$rec" ]; then
    exec cargo test --workspace --quiet
  fi

  mkdir -p "$(dirname "$rec")"
  printf 'suite-head: %s\n' "$(git rev-parse HEAD)" >"$rec"

  # Cargo's own progress lines are kept (the "Running" headers are what attribute the
  # results), libtest is asked for its terse form so the log stays readable, and the
  # build messages go to the record but not to the log. `tee` would hide cargo's exit
  # status, so it is read from PIPESTATUS before anything else runs.
  cargo test --workspace --message-format json-render-diagnostics -- --quiet 2>&1 |
    tee -a "$rec" |
    grep -v '^{"reason":'
  local status=${PIPESTATUS[0]}

  printf 'suite-exit-status: %s\n' "$status" >>"$rec"
  return "$status"
}

case "${1:-run}" in
  run) run ;;
  counts)
    if [ "$#" -ne 2 ]; then
      printf 'usage: %s counts FILE\n' "$0" >&2
      exit 2
    fi
    counts "$2"
    ;;
  *)
    printf 'usage: %s [run | counts FILE]\n' "$0" >&2
    exit 2
    ;;
esac
