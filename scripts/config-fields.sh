#!/usr/bin/env bash
#
# Every field of every configuration struct, against the code that is supposed to
# read it.
#
# This exists because of `Config::max_connections` on the SQL surface. It was
# declared with a reason next to it, "a read surface with none is a read surface that
# can be exhausted", and for four days nothing read it: `serve_on` spawned a task per
# accepted socket and counted nothing. A deployer who lowered the number got a server
# that behaved exactly as before and no way to find that out.
#
# That is worse than not having the field. An absent bound is a gap somebody can see;
# a declared bound with a paragraph of justification reads as a mitigation that has
# already been applied, and it is the sentence rather than the code that gets believed.
# Nothing about it announced itself: it compiled, it was documented, and the crate's
# own tests passed.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT.
#
# It proves a field is read by its own crate's `src`. It does NOT prove the field is
# obeyed: a limit read into a variable and then ignored passes this check, and only a
# test can hold that. So this is a floor under the honesty of a configuration struct,
# not a proof of enforcement, and the invariant in CLAUDE.md names the tests that do
# the other half.
#
# Tests are deliberately not counted as readers. A field exercised only by a test is
# still a field production never consults, which is the shape of the bug above.
#
# CAN IT FAIL? Yes, and it was watched failing rather than assumed to work: run
# against the commit before `serve_on` learned to count, it reports exactly
# `trailryx-sql::Config.max_connections` and nothing else.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

problems=0
checked=0

# Configuration structs are found by name rather than by a list somebody maintains: a
# list is a thing to forget when the next one is written.
while IFS=: read -r file _line decl; do
  crate=$(printf '%s' "$file" | cut -d/ -f2)
  name=$(printf '%s' "$decl" | sed -n 's/^pub struct \([A-Za-z]*\).*/\1/p')
  [ -n "$name" ] || continue

  fields=$(awk -v decl="pub struct $name {" '
    $0 == decl { inside = 1; next }
    inside && /^}/ { exit }
    inside { print }
  ' "$file" | sed -n 's/^ *pub \([a-z_0-9]*\): .*/\1/p')

  for field in $fields; do
    checked=$((checked + 1))
    # Its own crate's production code, and any use of the name: `config.field`,
    # `self.config().field`, `c.field`. A field read only by destructuring would be
    # missed and would have to teach this check about itself; nothing in the tree
    # does that today.
    if ! grep -rqE "\.${field}([^A-Za-z0-9_]|$)" "crates/$crate/src" --include="*.rs"; then
      printf '%s::%s.%s is declared and nothing in crates/%s/src reads it\n' \
        "$crate" "$name" "$field" "$crate"
      problems=$((problems + 1))
    fi
  done
done < <(grep -rn '^pub struct [A-Za-z]*\(Config\|Limits\|Policy\)\b' crates/*/src --include="*.rs")

if [ "$checked" -eq 0 ]; then
  # A check that measured nothing is not a check that passed.
  printf 'found no configuration struct at all, so this check measured nothing\n'
  exit 1
fi

if [ "$problems" -gt 0 ]; then
  printf 'a configuration field that nothing reads is a bound that is only a comment\n'
  exit 1
fi
printf '%d configuration fields, every one of them read\n' "$checked"
