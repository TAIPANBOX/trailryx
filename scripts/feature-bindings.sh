#!/usr/bin/env bash
#
# Every scenario in features/*.feature is bound to a named test, and every binding
# names a test that exists. Both directions, because each one fails in its own way:
#
#   a scenario with no binding     the behaviour it describes is written down and
#                                  nothing checks it. A reader trusts the sentence.
#   a binding naming no test       the scenario points at a test that was renamed or
#                                  deleted, so the sentence outlived its check.
#
# The binding is a comment line inside the scenario, `# bound: <test fn name>`, and
# a scenario has exactly one. That is deliberately not a BDD runner: the value asked
# for is readable evidence, and a step-definition layer would add a second copy of
# every sentence to keep in step with the first. The gate checks the binding, not
# that the test asserts what the sentence says. Whether it does is what the red-first
# commit and the mutants in the pull request answer.
#
# With no feature files at all the gate says it measured nothing and fails. A
# directory that vanished must not read as a suite with zero scenarios passing.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

shopt -s nullglob
files=(features/*.feature)
if [ "${#files[@]}" -eq 0 ]; then
  echo "FAIL: no features/*.feature files, so this gate measured nothing"
  exit 1
fi

problems=0
scenarios=0
bindings=0

note() {
  printf 'FAIL: %s\n' "$1"
  problems=$((problems + 1))
}

test_exists() {
  # A test is a top-level fn in an integration-test file. A `fn` inside a module
  # or a unit test in src/ is not what a feature file binds to, and the search
  # is restricted to the tests directories so a same-named helper cannot satisfy it.
  grep -rqE "^fn $1\(" crates/*/tests --include=*.rs
}

for file in "${files[@]}"; do
  current=""
  bound=""
  line_no=0
  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))
    if [[ "$line" =~ ^[[:space:]]*Scenario(\ Outline)?: ]]; then
      if [ -n "$current" ] && [ -z "$bound" ]; then
        note "$file:$current has no '# bound:' line"
      fi
      current="$line_no"
      bound=""
      scenarios=$((scenarios + 1))
    elif [[ "$line" =~ ^[[:space:]]*#[[:space:]]*bound:[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*$ ]]; then
      name="${BASH_REMATCH[1]}"
      bindings=$((bindings + 1))
      if [ -z "$current" ]; then
        note "$file:$line_no binds '$name' outside any scenario"
      elif [ -n "$bound" ]; then
        note "$file:$line_no is a second binding in the scenario at line $current"
      else
        bound="$name"
      fi
      if ! test_exists "$name"; then
        note "$file:$line_no binds '$name', and no test of that name exists under crates/*/tests"
      fi
    fi
  done <"$file"
  if [ -n "$current" ] && [ -z "$bound" ]; then
    note "$file:$current has no '# bound:' line"
  fi
done

if [ "$scenarios" -eq 0 ]; then
  echo "FAIL: the feature files hold no scenario, so this gate measured nothing"
  exit 1
fi

if [ "$problems" -gt 0 ]; then
  exit 1
fi

if [ "$scenarios" -ne "$bindings" ]; then
  echo "FAIL: $scenarios scenario(s) but $bindings binding(s)"
  exit 1
fi

echo "OK: $scenarios scenario(s) across ${#files[@]} file(s), every one bound to a test that exists"
