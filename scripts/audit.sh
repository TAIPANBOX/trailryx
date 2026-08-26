#!/usr/bin/env bash
# Runs cargo-audit, and re-establishes the reason behind every silenced
# advisory before it lets one through.
#
# WHY AN IGNORE NEEDS A CHECK OF ITS OWN.
#
# An ignore is a claim that an advisory cannot reach us. The claim is usually
# true the day it is written, nothing notices when it stops being true, and it
# then protects nothing while still reading as a decision somebody made. This
# repository refuses that shape everywhere else: an invariant says what holds
# it, a "nothing found" needs a run where the same check finds something. An
# ignore is the same problem wearing a configuration file.
#
# So every entry in `.cargo/audit.toml` names a crate AND a reason, and both
# reasons in use here are facts rather than judgements, which means they can be
# re-derived on every run:
#
#   never-built     the crate is in Cargo.lock and in no build graph, because
#                   it sits behind an optional feature nothing enables.
#   dev-only        the crate is compiled, but only for tests: no path to it
#                   exists along normal dependency edges, so nothing a consumer
#                   builds contains it.
#
# The second is deliberately the weaker of the two and is written down as such.
# It says the code is not in a shipped artifact. It does not say the code is
# never executed here.
#
# WHY THE CARGO-AUDIT HALF CAN SKIP AND THE REACHABILITY HALF CANNOT.
#
# `cargo audit` needs the advisory database, so it needs the network and the
# tool. The reachability checks need neither: they are `cargo tree` against the
# manifest already on disk. A hook that demanded a network round trip on every
# push would get bypassed with `--no-verify`, which is worse than an honest
# skip, so the tool half announces its absence with the reason and the
# structural half always runs.
#
# This file is the ONE copy of this check. `.githooks/pre-push` and CI both
# call it.

set -uo pipefail

cd "$(dirname "$0")/.."

config=".cargo/audit.toml"
if [ ! -f "$config" ]; then
  echo "FAIL: $config is missing, so the ignore list has no single source"
  exit 1
fi

ids=$(grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' "$config" | sort -u)

# Each ignored advisory, the crate it concerns, and which of the two reasons is
# being claimed. An id present in the config and absent here is refused: the
# point of the file is that a reason exists and is checked, so a silent entry
# is the exact failure this script is for.
python3 - "$ids" <<'PY'
import re
import subprocess
import sys

REASONS = {
    # rkyv reaches Cargo.lock through the SQL facade's DataFusion stack, by way
    # of rust_decimal, where it sits behind an optional feature
    # (`rkyv = ["dep:rkyv"]`) that nothing in this graph turns on. rust_decimal
    # 1.42.1 is the latest published version, so no upgrade removes the entry.
    "RUSTSEC-2026-0235": ("rkyv", "never-built"),
    # time reaches us only through rcgen, the dev-dependency that generates the
    # certificates the federation transport's tests use. The fix is time 0.3.47,
    # which requires Rust 1.88 while this workspace declares 1.85, so taking it
    # would trade a stated portability floor for a stack-exhaustion bug in code
    # that only ever parses certificates this repository generated itself.
    "RUSTSEC-2026-0009": ("time", "dev-only"),
}

def tree(crate, edges=None):
    cmd = ["cargo", "tree", "-i", crate, "--all-features", "--target", "all"]
    if edges:
        cmd += ["--edges", edges]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        return ""
    return out.stdout if re.search(rf"^{re.escape(crate)} v", out.stdout, re.M) else ""

ids = [i for i in sys.argv[1].split() if i]
fail = False

if not ids:
    print("  (no advisories are silenced)")

for advisory in ids:
    entry = REASONS.get(advisory)
    if entry is None:
        print(f"FAIL: {advisory} is silenced but no reason is recorded for it here.")
        print("      Record the crate and the reason, or stop silencing it.")
        fail = True
        continue

    crate, reason = entry

    if reason == "never-built":
        found = tree(crate)
        if found:
            print(f"FAIL: {advisory} is silenced because '{crate}' is never built, "
                  f"and it IS in the build graph:")
            print(found.strip()[:600])
            fail = True
        else:
            print(f"  ok  {advisory}: '{crate}' is in no build graph, only in the lockfile")

    elif reason == "dev-only":
        shipped = tree(crate, edges="normal")
        if shipped:
            print(f"FAIL: {advisory} is silenced because '{crate}' is test-only, "
                  f"and it now reaches a normal dependency edge:")
            print(shipped.strip()[:600])
            fail = True
        elif not tree(crate):
            print(f"FAIL: {advisory} is silenced as test-only but '{crate}' is in no graph "
                  f"at all, so the entry is stale and should be removed.")
            fail = True
        else:
            print(f"  ok  {advisory}: '{crate}' is reached only through dev-dependencies")

    else:
        print(f"FAIL: {advisory} claims an unknown reason {reason!r}")
        fail = True

if fail:
    print()
    print("An ignore whose reason has stopped holding is worse than no ignore: it")
    print("reports zero for a vulnerability that now reaches code somebody runs.")
    sys.exit(1)
PY
reach=$?
[ "$reach" -eq 0 ] || exit "$reach"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "  skipped  cargo audit: cargo-audit is not installed (cargo install cargo-audit)."
  echo "           The reachability checks above ran; the advisory database did not."
  exit 0
fi

# THE ADVISORY DATABASE MUST BE CLEAN, AND THIS IS NOT PEDANTRY.
#
# `cargo audit` fetches by pulling into ~/.cargo/advisory-db, and `git pull`
# never removes an UNTRACKED file. It then reads the DIRECTORY rather than git
# HEAD, so any stale file that ever landed there is loaded as an advisory
# forever while every subsequent fetch reports success.
#
# On 2026-08-09 that cost hours across this estate. Upstream renamed an advisory
# between two crate directories; the old path survived locally as untracked,
# cargo-audit saw the id twice, and refused to load the ENTIRE database with
#
#   error loading advisory database: parse error: duplicate advisory ID
#
# `--ignore` does not help: the failure is at database LOAD, before any ignore
# is evaluated. The condition is permanent until somebody runs `git clean`, and
# it looks exactly like an upstream outage. It was not one: `git grep -l <id>
# HEAD -- crates/` returned a single path throughout.
#
# The diagnosis is one line and nobody runs it, so it runs here. Naming the
# files is the whole value, because cargo-audit's own error names an advisory
# id and sends a reader to the wrong repository.
# ASKING ANOTHER REPOSITORY A QUESTION FROM INSIDE A HOOK NEEDS THE ENVIRONMENT
# CLEARED, AND THIS SCRIPT LEARNED THAT THE EXPENSIVE WAY.
#
# git runs a hook with GIT_DIR set to the repository being pushed. `git -C
# <other repo>` changes the DIRECTORY and does not clear that variable, so the
# command below was reading the advisory database's working tree against
# TRAILRYX's index. Every one of the database's 1221 entries then reports as
# untracked, deterministically, on every push from the hook and never from a
# terminal, which is why it read as a flaky machine rather than as a bug here.
# Measured 2026-08-26: `git -C ~/.cargo/advisory-db status --porcelain` returns
# nothing in a shell and 1221 lines with GIT_DIR set.
#
# The false positive cost push attempts across this estate all day. The half
# that is worse than the wasted time is the remediation this check prints: `git
# -C <db> clean -fd`. Harmless in a terminal, where nothing is untracked. In
# the environment the message actually appears in, it deletes the advisory
# database.
#
# So every git command aimed at a repository that is not this one clears the
# three variables git exports into a hook. GIT_INDEX_FILE is in the list even
# though GIT_DIR alone caused this: a check that guards against one of a family
# invites the next member.
dbgit() { env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git "$@"; }

db="${CARGO_HOME:-$HOME/.cargo}/advisory-db"
if [ -d "$db/.git" ]; then
  dirty="$(dbgit -C "$db" status --porcelain 2>/dev/null || true)"
  if [ -n "$dirty" ]; then
    echo "FAIL: the advisory database at $db has files git does not track."
    echo
    printf '%s\n' "$dirty" | sed 's/^/      /'
    echo
    echo "      cargo-audit reads that DIRECTORY, not git HEAD, so these are"
    echo "      loaded as advisories on every run and no upstream fix will ever"
    echo "      clear them. A duplicate id among them makes cargo-audit refuse"
    echo "      the whole database, which looks like an upstream outage and is"
    echo "      not one."
    echo
    echo "      Fix it with:  git -C $db clean -fd"
    echo "      (from a terminal. NOT from inside a hook, where GIT_DIR points"
    echo "       at the repository being pushed and this would delete the"
    echo "       database rather than tidy it.)"
    exit 1
  fi
else
  # Not a failure and not a pass either. A fresh runner has no database until
  # `cargo audit` below creates one, so there is nothing here to be clean or
  # dirty. Said out loud because the alternative is a check that reports
  # nothing and reads as agreement, which is the shape invariant 19 is about.
  echo "note: no advisory database at $db yet, so its cleanliness was not checked."
fi

args=()
for id in $ids; do
  args+=(--ignore "$id")
done
cargo audit "${args[@]}"
