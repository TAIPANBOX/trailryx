#!/usr/bin/env bash
# Checks that the gates in `scripts/` still FAIL on the faults they exist to
# catch, still PASS on what they must not catch, and REFUSE to report success
# when they measured nothing at all.
#
# WHY
#
# Every gate here parses text, and a text parser does not break loudly: it
# stops matching and reports success. The mutants that proved each one existed
# as prose, in commit messages and in the `*(gate: ...)*` markers in CLAUDE.md,
# which is a record of what was true once. Nothing ran them again.
#
# A gate that has quietly stopped catching anything looks exactly like a gate
# with nothing to catch, and stays that way until the fault it guards ships.
#
# WHY THE THIRD PROPERTY IS SEPARATE FROM THE FIRST
#
# Because here too it found a real hole, the sixth in the estate.
#
# `no-unsafe.sh` ran `grep -rIn --include='*.rs' ... crates`, and grep over a
# directory that is not there prints nothing and exits 1, so the script exited
# 0 having read no Rust at all. A workspace whose crates moved or were renamed
# reported "no unsafe" about nothing. The lint in the manifest is what forbids
# unsafe; this script is the second pair of eyes on the lint, and a second pair
# of eyes that cannot see is worse than none, because the first stops being
# checked. Fixed in the commit before this one.
#
# WHAT THIS ONE DELIBERATELY DOES NOT COVER, AND WHY
#
# Eighteen checks run in the hook and in CI. This harness covers six of them,
# and the ones left out are left out for stated reasons rather than by
# accident:
#
#   readme-numbers.sh, reproduce.sh, tls-builds.sh   they build or run the whole
#                                                    workspace; a case costs
#                                                    minutes and the harness
#                                                    would stop being run
#   kill-linux.sh                                    needs a Linux container,
#                                                    absent on a developer Mac
#   fips-build.sh                                    29s per case, borderline
#   deletion-only-push.sh                            not a check: it is the
#                                                    hook's decision about
#                                                    whether to run, and
#                                                    deletion-skip-cases.sh is
#                                                    the check that it behaves
#
# A harness that implies more coverage than it has is the same defect one level
# up, so the list above is in CLAUDE.md too.
#
# HOW IT MUTATES WITHOUT LEAVING A MESS
#
# It edits tracked files in place, so it refuses to start unless the tree is
# clean, restores with `git checkout` after every case, restores again from a
# trap on any exit path including a kill, and asserts the tree is clean before
# reporting success.
#
#
# A GATE THAT IS ALREADY FAILING CANNOT BE JUDGED
#
# A case expecting a gate to FAIL proves nothing if the gate was failing before
# the mutation. So every fail-case runs the gate on the UNMUTATED tree first
# and reports UNJUDGEABLE rather than a pass. Found on 2026-08-09 in it-rat,
# where one gate was legitimately red and a case against it would have been
# indistinguishable from a working one.
#
# A MUTATION THAT DID NOT APPLY PROVES NOTHING
#
# Every edit asserts it changed the file. A case whose edit applied nothing is
# a failure here, not a pass. That is not hypothetical: five such mutations
# were caught across idryx and tokenfuse on 2026-08-09, and three of the five
# had been verified BY HAND against the same gate minutes earlier. The hand
# version and the harness version differ only in how many layers of quoting sit
# between the text and python, which is exactly the difference nobody sees.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

# `--skip-if-dirty` exists for ONE caller, `.githooks/pre-push`, and the reason
# is worth stating because it is a deliberate hole. This script mutates tracked
# files, so it needs a clean tree; a push with uncommitted work in the tree is
# ordinary, and refusing it would make the hook something people disable. In
# CI the checkout is always clean, so the check runs there every time.
#
# The skip is LOUD. It prints why, and it is the only skip in this repository's
# gate that is allowed to exit 0, which is the shape everything else here
# exists to refuse. If that ever needs to change, change it toward running
# rather than toward silence.
skip_if_dirty=0
[ "${1:-}" = "--skip-if-dirty" ] && skip_if_dirty=1

if [ -n "$(git status --porcelain)" ]; then
	if [ "$skip_if_dirty" = 1 ]; then
		printf 'skipped: the tree is dirty, and this check mutates tracked files.\n'
		printf '         it runs on every CI checkout, which is always clean.\n'
		exit 0
	fi
	printf 'this script mutates tracked files, so it needs a clean tree.\n'
	printf 'commit or stash first; it restores with `git checkout` and cannot\n'
	printf 'tell your edits from its own.\n'
	exit 1
fi

# Untracked files too: a mutation may RENAME a tracked file, and `git checkout`
# restores the original while leaving the new name behind. And the INDEX, since
# a gate may read `git ls-files` rather than the disk, so a mutation has to move
# the file in both. Safe because this
# script refuses to start unless the tree is clean, so anything untracked
# during a run was created by the run. `-x` is deliberately absent: ignored
# build output is not ours to delete.
restore() {
	git reset -q --hard HEAD 2>/dev/null
	git clean -fdq 2>/dev/null
}
baseline_dir="$(mktemp -d)"

# One trap for both, because a second `trap ... EXIT` REPLACES the first
# rather than adding to it. Writing them separately disarmed `restore` on
# every interrupt path, which would leave a mutated tree behind on Ctrl-C.
cleanup() {
	restore
	rm -rf "$baseline_dir"
}
trap cleanup EXIT INT TERM


failures=0
cases=0

# run_case <name> <expect: fail|pass> <gate> <python edit> [required output]
#
# The needle separates "it failed" from "it failed for the reason this case is
# about". Without it, a case expecting failure is satisfied by any failure,
# including one this harness caused itself.
run_case() {
	local name="$1" expect="$2" gate="$3" edit="$4" needle="${5:-}"
	cases=$((cases + 1))

	# A gate that is ALREADY failing cannot be judged: a fail-case against it
	# passes while proving nothing, which is this harness committing the very
	# fault it exists to catch. Added estate-wide on 2026-08-09 after it-rat,
	# where `demo-bundle-current.sh` was red on a clean tree because the
	# published demo had fallen behind genaryx. Any case written against it
	# would have gone green having measured nothing.
	#
	# The result is cached per GATE rather than per case: the tree is restored
	# between cases, so a gate's verdict on the clean tree cannot change within
	# one run, and some of these gates compile or run a whole suite.
	if [ "$expect" = fail ]; then
		local key base_out
		key="$baseline_dir/$(printf '%s' "$gate" | cksum | tr -d ' ')"
		if [ ! -f "$key" ]; then
			if eval "$gate" >/dev/null 2>&1; then printf 'green' >"$key"; else printf 'red' >"$key"; fi
		fi
		base_out="$(cat "$key")"
		if [ "$base_out" = red ]; then
			printf 'UNJUDGEABLE  %s\n             the gate is already failing on a clean tree, so a\n             failure after the mutation would prove nothing\n' "$name"
			failures=$((failures + 1))
			return
		fi
	fi

	if ! python3 -c "$edit"; then
		printf 'BROKEN  %s\n        its mutation did not apply, so this case proved nothing\n' "$name"
		failures=$((failures + 1))
		restore
		return
	fi

	local out rc
	out=$(eval "$gate" 2>&1)
	rc=$?
	restore

	# Exit code first, then wording. Checking the needle before the expectation
	# turns "it did not fail at all" into "it failed for the wrong reason",
	# which sends the reader to look at prose when the gate is toothless.
	if [ "$expect" = fail ] && [ "$rc" -ne 0 ] && [ -n "$needle" ] &&
		! printf '%s' "$out" | grep -qF -- "$needle"; then
		printf 'WRONG REASON  %s\n              it failed, but not saying: %s\n' "$name" "$needle"
		failures=$((failures + 1))
		return
	fi
	if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
		printf 'TOOTHLESS  %s\n           the gate passed on a fault it exists to catch\n' "$name"
		failures=$((failures + 1))
	elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
		printf 'OVEREAGER  %s\n           the gate failed on something it must not catch\n' "$name"
		failures=$((failures + 1))
		printf '%s\n' "$out" | head -4 | sed 's/^/           /'
	else
		printf 'ok  %-58s (%s)\n' "$name" "$expect"
	fi
}

py() { printf 'def edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b, 1))\n%s\n' "$1"; }

echo "=== faults each gate must catch ==="

# invariant: no unsafe anywhere in the crates. The workspace lint forbids it and
# this is the second pair of eyes on the lint itself.
run_case "no-unsafe: an unsafe block in a crate" fail \
	'./scripts/no-unsafe.sh' \
	"$(py 'p = "crates/trailryx-anchor/src/lib.rs"
s = open(p).read()
open(p, "w").write(s + "\n#[allow(dead_code)]\nfn _teeth() { unsafe { } }\n")')" \
	"unsafe found"

# invariant 16: the hook and CI run the same NUMBER of checks. A check added to
# one and not the other is a laptop that says yes and a runner that says no.
run_case "gate-count: CI loses a check the hook still runs" fail \
	'./scripts/gate-count.sh' \
	"$(py 'edit(".github/workflows/ci.yml", "      - name: no unsafe\n        run: ./scripts/no-unsafe.sh\n", "")')" \
	"a green push is not a green pull request"

# A temp path two processes share is a file one of them watches go missing.
#
# The planted statement carries a semicolon on purpose: this gate accumulates a
# statement until one, which its own header calls coarse and enough. Without it
# the line is never counted at all, and the first version of this case sat
# there reading TOOTHLESS about a gate that was working.
run_case "temp-paths: a temp path that is not per process" fail \
	'./scripts/temp-paths.sh' \
	"$(py 'import subprocess
f = subprocess.run(["git", "ls-files", "crates/*/src/lib.rs"], capture_output=True, text=True).stdout.split()
assert f, "no lib.rs to edit"
p = f[0]
s = open(p).read()
open(p, "w").write(s + "\n#[allow(dead_code)]\nfn _teeth_tmp() -> std::path::PathBuf { let p = std::env::temp_dir().join(\"trailryx-fixture\"); p }\n")')" \
	"temp path"

echo
echo "=== and what they must NOT catch ==="

# The word `unsafe` inside a comment or a string is not an unsafe block, and a
# gate that flagged one would be flagging the prose that explains the rule.
# The advisory check asks another repository a question, and git hands a hook
# GIT_DIR pointing at the repository being pushed. `git -C <elsewhere>` changes
# the directory and keeps that variable, so the check read the advisory
# database's working tree against THIS repository's index and every one of its
# 1221 entries came back untracked. Deterministic, invisible from a terminal,
# and it cost push attempts across the estate on 2026-08-26 before anybody
# looked at the environment rather than at the database.
#
# Both cases run the gate the way the hook runs it. The `pass` one is the point:
# a check must give the same answer whether or not it inherited a hook's
# environment, and only running it under that environment can say so.
run_case "audit: the same answer under a hook's environment" pass \
	'GIT_DIR="$PWD/.git" ./scripts/audit.sh' \
	""

run_case "audit: the environment leak put back" fail \
	'GIT_DIR="$PWD/.git" ./scripts/audit.sh' \
	"$(py 'edit("scripts/audit.sh", "dirty=\"$(dbgit -C", "dirty=\"$(git -C")')" \
	"does not track"

run_case "no-unsafe: the word in a comment and in a string" pass \
	'./scripts/no-unsafe.sh' \
	"$(py 'p = "crates/trailryx-anchor/src/lib.rs"
s = open(p).read()
open(p, "w").write(s + "\n// this crate is unsafe-free and says so here\n#[allow(dead_code)]\nconst _TEETH: &str = \"unsafe\";\n")')"

# A per-process temp path is the idiom the workspace already uses.
run_case "temp-paths: a temp path carrying the process id" pass \
	'./scripts/temp-paths.sh' \
	"$(py 'import subprocess
f = subprocess.run(["git", "ls-files", "crates/*/src/lib.rs"], capture_output=True, text=True).stdout.split()
assert f, "no lib.rs to edit"
p = f[0]
s = open(p).read()
open(p, "w").write(s + "\n#[allow(dead_code)]\nfn _teeth_ok() -> std::path::PathBuf { let p = std::env::temp_dir().join(format!(\"trailryx-{}\", std::process::id())); p }\n")')"

echo
echo "=== and the one this estate learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

# THE HOLE. grep over a directory that is not there printed nothing and the
# script exited 0. This is the case that keeps the fix in place.
run_case "no-unsafe: no Rust left under crates/" fail \
	'./scripts/no-unsafe.sh' \
	"$(py 'import subprocess
subprocess.run(["git", "mv", "crates", "crates-elsewhere"], check=True)')" \
	"measured nothing"

run_case "gate-count: no checks left in the hook to count" fail \
	'./scripts/gate-count.sh' \
	"$(py 'import re
p = ".githooks/pre-push"
s = open(p).read()
# The hook\x27s checks are the lines beginning `step ` or `say `, which is what
# gate-count counts. Renaming the verb leaves a working hook and an uncountable
# one, which is exactly the state that must not read as zero problems.
out = re.sub(r"(?m)^(step|say) ", r"run_\\1 ", s)
assert out != s, "no step/say lines in the hook"
open(p, "w").write(out)')" \
	"measured nothing"

echo
if [ -n "$(git status --porcelain)" ]; then
	printf 'FAIL: this script left the tree dirty, so it cannot be trusted about anything above\n'
	git status --porcelain | head -5
	exit 1
fi

if [ "$failures" -gt 0 ]; then
	printf '%d of %d cases failed.\n' "$failures" "$cases"
	printf 'A gate that has quietly stopped catching anything looks exactly like a gate\n'
	printf 'with nothing to catch, and stays that way until the fault it guards ships.\n'
	exit 1
fi

printf 'OK: %d cases. Every gate fails on its own fault, passes on a non-fault,\n' "$cases"
printf '    and refuses to report success when it measured nothing.\n'
