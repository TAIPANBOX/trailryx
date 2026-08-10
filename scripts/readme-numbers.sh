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
# It checks six things, and each one is a claim a reader would take at face value:
#
#   1. the tests badge equals what `cargo test` actually runs;
#   2. every crate row's count equals that crate's own suite;
#   3. the rows sum to the total, so the table is checkable at a glance;
#   4. the stage badge is not behind the roadmap;
#   5. no other file in the tree states a dependency count of its own;
#   6. the verifier's size, which is what "an auditor can read all of it" rests on.
#
# The fifth arrived on 6 August 2026 and is the one that reaches outside this page.
# The doc comment on `trailryx-sql` had said "two hundred and forty-three" since the
# day the dependencies landed, while the README, corrected within hours of the same
# mistake by the commit that added this script, said 294 and 297. One of the two had
# a gate. That is the whole difference, and it is invariant 16 exactly: if two places
# need one value, it is exported from one of them, and here the README is the one.
#
# It does not check prose. Prose needs a reader; numbers need a script.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
problems=0
unmeasured=0

note() {
  printf '%s\n' "$1"
  problems=$((problems + 1))
}

# Total, from the suite itself rather than from anything that quotes it.
#
# The exit status is read, and this is not defensive programming for its own sake: a
# run that is blocked on another process's build lock, or that dies partway, prints
# the results it did reach and nothing about the ones it did not. On 6 August 2026
# that produced "the badge says 1066 tests and the suite runs 51" and refused a push
# over a drift that did not exist, because the only guard here was against a total of
# exactly zero. A partial count is worse than no count: it looks like a measurement.
suite=$(cargo test --workspace --quiet 2>/dev/null)
suite_status=$?
total=$(printf '%s\n' "$suite" | grep -E '^test result' | awk '{s += $4} END {print s + 0}')
if [ "$suite_status" -ne 0 ] || [ "$total" -eq 0 ]; then
  note "the suite did not finish (cargo exited $suite_status, $total tests seen), so nothing here was compared against it"
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
  # Same reason as the total above: a crate whose run never completed has not been
  # measured, and saying so is the only honest answer. Reporting its row as drifted
  # would send somebody to edit a number that was right.
  crate_out=$(cargo test -p "$crate" --quiet 2>/dev/null)
  crate_status=$?
  actual=$(printf '%s\n' "$crate_out" |
    grep -E '^test result' | awk '{s += $4} END {print s + 0}')
  if [ "$crate_status" -ne 0 ]; then
    note "$crate: its suite did not finish (cargo exited $crate_status), so its row was not checked"
    unmeasured=1
    continue
  fi
  sum=$((sum + actual))
  [ "$stated" = "$actual" ] ||
    note "$crate: the table says $stated tests and the crate runs $actual"
done < <(grep '^| `trailryx-' "$readme")

# Only meaningful when every row was actually measured: a crate whose run never
# finished contributes nothing to the sum, and a sum short by that crate would read
# as a drifted table rather than as a run that did not happen.
if [ "$unmeasured" -eq 0 ]; then
  [ "$sum" -eq "$total" ] ||
    note "the table's rows sum to $sum and the workspace runs $total"
fi

# The dependency figure behind the SQL facade. It is the number the whole
# zero-dependency argument is spent against, and it is the one that moved twice in a
# day: once because a dependency tree is bigger than it looks, and once because an
# audit measured it with a narrower edge filter than the line meant. The command in
# the README is the command run here, which is the only way a reader can check it.
if deps=$(cargo tree --offline -p trailryx-sql --prefix none 2>/dev/null |
  awk '{print $1}' | grep -v '^trailryx' | grep -v '^$' | sort -u | wc -l | tr -d ' ') &&
  [ -n "$deps" ] && [ "$deps" -gt 0 ]; then
  # Host-specific on purpose. Part of any dependency tree is platform-specific, so
  # the same command counts 294 on Linux and 297 on macOS, and the first version of
  # this check compared a Linux tree against a number measured on a Mac. Resolving
  # for all targets would be portable and needs to download crates the build never
  # uses, which is worse in a gate.
  case "$(uname -s)" in
    Darwin) stated=$(grep -o 'and \*\*[0-9]*\*\* on macOS' "$readme" | grep -o '[0-9]*') ;;
    *) stated=$(grep -o '\*\*[0-9]* third-party crates\*\*' "$readme" | grep -o '[0-9]*') ;;
  esac
  [ "$stated" = "$deps" ] ||
    note "the README says $stated crates behind the facade on $(uname -s) and \`cargo tree\` counts $deps"
else
  # Said out loud rather than passed silently: a check that cannot run is not a
  # check that passed.
  printf 'skipped the dependency count: cargo tree could not resolve offline\n'
fi

# The same figure, everywhere else in the tree it is written down.
#
# The check above gives the README an owner. This one gives every copy of it one,
# because the copies are where it actually rotted: `SECURITY.md`, `CONTRIBUTING.md`,
# `VALIDATION.md` and a CI comment all state it, and a doc comment stated it wrongly
# for six days while every gate stayed green.
#
# It runs on text this repository tracks, not only on markdown, because the fourth
# copy was in `.github/workflows/ci.yml`. The allowed figures come from the README
# and nowhere else, so a change to the tree moves one number, in one file, and every
# other copy is refused until it follows.
#
# Two things it does deliberately narrowly, both learned by running it.
#
# It looks only where a phrase NAMES this count: "third-party crates", "third-party
# dependencies", "transitive crates", "transitive dependencies". Wider wording was
# tried first, "dependency count" and "dependency tree" among it, and it swept up the
# durability sweep's seeds and the fuzzer's cases per target out of paragraphs that
# mention dependencies only in passing. A check that cries wolf has its trigger
# widened by the next person it wakes, which is how a gate becomes a `|| true`.
#
# Numbers are whole tokens, and a comma inside one joins rather than splits. An
# identifier with digits in it (`SHA256SUMS` in the Dockerfile is the one that made
# this necessary) is a word, and a figure written with a thousands separator is one
# number rather than two, the second of which is three digits long and looks briefly
# like a count of crates.
readme_mac=$(grep -o 'and \*\*[0-9]*\*\* on macOS' "$readme" | grep -o '[0-9]*')
readme_lin=$(grep -o '\*\*[0-9]* third-party crates\*\*' "$readme" | grep -o '[0-9]*')
readme_ships=$(grep -oE '[0-9]+ of the [0-9]+ are what actually ships' "$readme" |
  grep -oE '^[0-9]+')

if [ -z "$readme_mac" ] || [ -z "$readme_lin" ] || [ -z "$readme_ships" ]; then
  # The allowed set is read out of the README, so an unreadable README would make
  # every copy look wrong. Refuse rather than report a hundred false failures.
  note "could not read the dependency figures out of $readme, so the copies were not checked"
else
  # A figure that is NOT the current count, and may appear anyway. Each entry is a
  # file, a number and a reason, and the reason is re-derived below rather than
  # believed: `history` requires the paragraph carrying the number to carry a year
  # as well, so a sentence that stops saying when it was true stops being exempt.
  # This is invariant 24's rule, applied to a second kind of silence. An entry whose
  # reason is not re-derivable fails the gate, and so does a number with no entry.
  exceptions="crates/trailryx-sql/src/lib.rs 243 history"

  while IFS= read -r f; do
    [ "$f" = "$readme" ] && continue
    [ -f "$f" ] || continue
    file "$f" | grep -q text || continue

    # Paragraphs, except that a table row is its own paragraph: a row about the
    # dependency count sits in the same block as rows about seeds and cases, and
    # those numbers have nothing to do with this one.
    found=$(awk '{ if (/^\|/) print "\n" $0 "\n"; else print }' "$f" |
      awk -v RS='' -v allow="$readme_mac $readme_lin $readme_ships" '
        tolower($0) ~ /third-party crates|third-party dependenc|transitive crates|transitive dependenc/ {
          para = $0
          year = (para ~ /(19|20)[0-9][0-9]/) ? "dated" : "undated"
          body = para
          gsub(/,/, "", body)
          n = split(body, tok, /[^0-9A-Za-z]+/)
          for (i = 1; i <= n; i++) {
            if (tok[i] !~ /^[0-9][0-9][0-9]$/) continue
            ok = 0
            split(allow, a, " ")
            for (j in a) if (a[j] == tok[i]) ok = 1
            if (!ok) print tok[i] " " year
          }
        }' | sort -u)

    [ -n "$found" ] || continue
    while read -r number dated; do
      [ -n "$number" ] || continue
      reason=$(printf '%s\n' "$exceptions" |
        awk -v f="$f" -v n="$number" '$1 == f && $2 == n { print $3 }')
      case "$reason" in
        history)
          [ "$dated" = "dated" ] ||
            note "$f: $number is allowed as history and the paragraph holding it no longer says when, so the reason cannot be re-derived"
          ;;
        "")
          note "$f: $number is a dependency count the README does not state (it states $readme_mac on macOS, $readme_lin on Linux, $readme_ships shipping)"
          ;;
        *)
          note "$f: $number is exempted for the reason \"$reason\", which this check does not know how to re-derive"
          ;;
      esac
    done <<EOF
$found
EOF
  done < <(git ls-files)
fi

# The verifier's size, which is the number the zero-dependency argument is spent
# against. "An auditor can read all of it before trusting any of it" is a claim about
# how much there is to read, and it was true when it was written and stopped being
# true without saying so. Measured 2026-08-10: the figure had said about 1,500 lines
# since 29 July, when the crate was 1,528; it is 3,575 now, because its own ECDSA
# P-384 and its RFC 3161 timestamp verification both arrived after the sentence did.
# The README's own prose already listed P-384 beside the stale count, which is the
# whole failure in one line: the words were updated and the number beside them was
# not, and nothing looked.
#
# Unlike the dependency count this is compared with a tolerance rather than exactly,
# and the reason is churn rather than laziness. A line count moves on every edit to
# the crate, a comment included, so an exact gate would refuse a push over a figure
# nobody would call wrong, and a gate that fires on non-faults is one somebody widens
# until it stops firing at all. The README states a figure rounded to the nearest
# hundred and the true count must sit within 5% of it: wide enough to survive
# ordinary work, and far too narrow to survive what actually happened here, which was
# a claim drifting to less than half of the truth.
verify_lines=$(git ls-files 'crates/trailryx-verify/*.rs' |
  while IFS= read -r f; do wc -l < "$f"; done |
  awk '{s += $1} END {print s + 0}')

if [ "$verify_lines" -eq 0 ]; then
  # Invariant 19 in miniature: a crate that moved or was renamed would otherwise
  # make this print a clean pass having measured nothing at all.
  note "trailryx-verify has no tracked Rust files, so its size was not measured"
else
  stated_lines=$(grep -oE 'about [0-9,]+ lines including' "$readme" |
    grep -oE '[0-9,]+' | tr -d ',' | sort -u)
  stated_count=$(printf '%s\n' "$stated_lines" | grep -c '[0-9]')
  if [ -z "$stated_lines" ]; then
    note "the README no longer states the verifier's size, and this check exists because that figure spent twelve days with no owner"
  elif [ "$stated_count" -ne 1 ]; then
    note "the README states $stated_count different sizes for the verifier ($(printf '%s' "$stated_lines" | tr '\n' ' ')), and invariant 16 allows one"
  else
    drift=$(awk -v a="$stated_lines" -v b="$verify_lines" \
      'BEGIN { d = a - b; if (d < 0) d = -d; printf "%d", (d * 100) / b }')
    [ "$drift" -le 5 ] ||
      note "the README says the verifier is about $stated_lines lines and it is $verify_lines, which is $drift% out"
  fi

  # The same figure, anywhere else this repository writes it down. Invariant 16 gives
  # a number in prose one owner, and this one has exactly the shape that rotted the
  # dependency count: a sentence somebody copies into a second file to make a point.
  #
  # It caught its own author on its first real run, refusing the push that added it
  # because `CLAUDE.md` had restated the superseded figure while explaining why this
  # check exists. That is the best evidence it works that there is, better than the
  # planted cases, and the fix was to take the number out of the prose rather than to
  # widen the check.
  #
  # Deliberately simpler than the dependency count's version of the same idea: there
  # is no `history` exception table here. Invariant 16 would allow a dated superseded
  # figure, and nothing in this tree needs one yet, so the machinery is not written
  # until something does. Adding it means copying the exceptions block above,
  # re-derived reason and all, rather than inventing a second convention.
  while IFS= read -r f; do
    [ "$f" = "$readme" ] && continue
    [ -f "$f" ] || continue
    grep -qE '[0-9] lines including' "$f" 2>/dev/null &&
      note "$f states a size for the verifier, and invariant 16 gives that figure one owner, which is $readme"
  done < <(git ls-files)
fi

# The image tag the README tells people to pull, against the version this
# workspace is. Added 2026-08-04, with v0.1.1, because that line is a number
# with an owner nobody appointed: it is correct on the day a release is cut and
# wrong from the next one onwards, and the person it misleads is a stranger
# following the install instructions, who has no way to know.
#
# Every occurrence, not the first: the pull line and the run line drift apart
# just as easily as either drifts from the manifest.
version=$(grep -m1 '^version = ' Cargo.toml | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
tags=$(grep -oE 'ghcr\.io/taipanbox/trailryx:v[0-9]+\.[0-9]+\.[0-9]+' "$readme" |
  grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
if [ -n "$tags" ]; then
  for tag in $tags; do
    [ "$tag" = "$version" ] ||
      note "the README says pull ghcr.io/taipanbox/trailryx:v$tag and this workspace is $version"
  done
else
  printf 'skipped the image tag: the README names no ghcr.io tag\n'
fi

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
