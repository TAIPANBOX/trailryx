#!/usr/bin/env bash
#
# No `unsafe` anywhere in the crates.
#
# The workspace lint already forbids it, so this is a second pair of eyes on the
# lint itself rather than on the code: a lint can be relaxed in a manifest by
# somebody who meant well, and this notices.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`. It
# used to be written out in each of them, which is the shape the dependency check
# was in when its two copies disagreed and CI refused a push the hook had passed.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

pattern='^\s*unsafe\b|[^a-z_]unsafe\s*\{'

# The subject first. `grep` over a directory that is not there prints nothing and
# this exited 0, so a workspace whose crates moved or were renamed reported "no
# unsafe" having read no Rust at all. Found 2026-08-09 by the teeth harness,
# which takes a gate's subject away and requires it to say so.
rs_files=$(git ls-files 'crates/**/*.rs' 'crates/*.rs' | wc -l | tr -d ' ')
if [ "$rs_files" -eq 0 ]; then
  echo "FAIL: no .rs file under crates/ is tracked, so this measured nothing."
  echo "      It cannot say a workspace forbids unsafe if it read no Rust."
  echo "      If the crates moved, this check has to move with them."
  exit 1
fi

if grep -rIn --include='*.rs' -E "$pattern" crates; then
  echo "unsafe found in a workspace that forbids it"
  exit 1
fi
exit 0
