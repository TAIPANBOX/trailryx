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

if grep -rIn --include='*.rs' -E "$pattern" crates; then
  echo "unsafe found in a workspace that forbids it"
  exit 1
fi
exit 0
