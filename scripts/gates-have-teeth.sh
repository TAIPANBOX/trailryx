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
#   reproduce.sh, tls-builds.sh                      they build or run the whole
#                                                    workspace; a case costs
#                                                    minutes and the harness
#                                                    would stop being run
#   readme-numbers.sh, the path that runs the suite  the same reason. The path
#                                                    that counts from a recorded
#                                                    run is covered (the suite.sh
#                                                    section below), and it is
#                                                    the one CI takes
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
# `.teeth-crates-parked` is the one directory this script creates by name (the
# "no Rust left under crates/" case moves the workspace there), so it is ours
# to delete whole, ignored contents included: `git clean` without `-x` leaves
# an ignored file behind (a `.DS_Store` Finder writes into any directory it
# opens), and an emptied-but-present destination made the next run's `git mv`
# nest into it instead of renaming, then fail outright with "destination
# already exists" once the nested path had been left behind too. That
# happened live on 2026-09-12 with the previous destination, `crates-elsewhere`,
# which is a real directory of this repository and was never ours to remove.
restore() {
	git reset -q --hard HEAD 2>/dev/null
	git clean -fdq 2>/dev/null
	rm -rf .teeth-crates-parked
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

# Like `py()`, but replaces every occurrence rather than the first. A binary name
# in `components.json` is not a single occurrence: it is the component's `name`
# and its `checked.binary`, and one of the ten repeats a third time in its own
# `why` prose. A single-occurrence replace would leave the literal standing under
# the second mention and report a rename gate as TOOTHLESS on its own fault.
pyall() { printf 'def edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b))\n%s\n' "$1"; }

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

# invariant 45: one integration-test binary per crate. A second top-level file
# in a crate that already has `tests/it` is a second binary linking DataFusion.
run_case "one-test-binary: a second tests/*.rs beside tests/it" fail \
	'./scripts/one-test-binary-per-crate.sh' \
	"$(py 'import os
p = "crates/trailryx-store/tests/teeth_planted.rs"
assert os.path.isdir("crates/trailryx-store/tests/it"), "no tests/it to plant beside"
open(p, "w").write("#[test]\nfn teeth_planted() {}\n")')" \
	"integration-test binaries"

# invariant 24, the third kind of reason: the crate IS built, but only through
# the callers the reason was argued for, only inside a version range, and only
# until a named release (zstd and zstd-safe, until parquet and arrow-ipc 60).
# Each case plants one way that reason stops holding, in the lockfile, which
# the gate reads as text, so every one of them fails before `cargo audit` and
# costs no advisory-db fetch.
#
# The expiry is the one that matters most and has a case per crate: with only
# one of them planted, the other half of EXPIRES_AT could be deleted and every
# case here would still be red for the first.
run_case "audit: the zstd ignores outlive parquet 60" fail \
	'./scripts/audit.sh' \
	"$(py 'edit("Cargo.lock", "name = \"parquet\"\nversion = \"58.4.0\"", "name = \"parquet\"\nversion = \"60.0.0\"")')" \
	"has expired"

run_case "audit: the zstd ignores outlive arrow-ipc 60" fail \
	'./scripts/audit.sh' \
	"$(py 'edit("Cargo.lock", "name = \"arrow-ipc\"\nversion = \"58.4.0\"", "name = \"arrow-ipc\"\nversion = \"60.0.0\"")')" \
	"has expired"

run_case "audit: zstd moved out of the range its ignore was argued for" fail \
	'./scripts/audit.sh' \
	"$(py 'edit("Cargo.lock", "name = \"zstd\"\nversion = \"0.13.3\"", "name = \"zstd\"\nversion = \"0.14.3\"")')" \
	"outside the range"

run_case "audit: zstd-safe moved out of the range its ignore was argued for" fail \
	'./scripts/audit.sh' \
	"$(py 'edit("Cargo.lock", "name = \"zstd-safe\"\nversion = \"7.2.1\"", "name = \"zstd-safe\"\nversion = \"8.2.0\"")')" \
	"outside the range"

# A crate that starts to depend on zstd is a caller the reason was never argued
# for: it may call the stream API the two advisories are about.
run_case "audit: a new dependent of zstd that the ignore does not cover" fail \
	'./scripts/audit.sh' \
	"$(py 'import re
s = open("Cargo.lock").read()
t = re.sub(r"(name = \"arrow-select\"\nversion = \"[^\"]+\"\nsource = [^\n]+\nchecksum = [^\n]+\ndependencies = \[\n)", "\\1 \"zstd\",\n", s, count=1)
assert t != s, "no arrow-select block in Cargo.lock"
open("Cargo.lock", "w").write(t)')" \
	"depends on it too"

run_case "audit: a new dependent of zstd-safe that the ignore does not cover" fail \
	'./scripts/audit.sh' \
	"$(py 'import re
s = open("Cargo.lock").read()
t = re.sub(r"(name = \"arrow-select\"\nversion = \"[^\"]+\"\nsource = [^\n]+\nchecksum = [^\n]+\ndependencies = \[\n)", "\\1 \"zstd-safe\",\n", s, count=1)
assert t != s, "no arrow-select block in Cargo.lock"
open("Cargo.lock", "w").write(t)')" \
	"depends on it too"

# The subject taken away: zstd in no lockfile entry at all. An ignore that
# matches nothing is the "measured nothing" answer, not a pass.
run_case "audit: zstd in no lockfile, so its ignore matches nothing" fail \
	'./scripts/audit.sh' \
	"$(py 'edit("Cargo.lock", "name = \"zstd\"\nversion", "name = \"zstdx\"\nversion")')" \
	"matches nothing"

# An id with no recorded reason is still refused, now that there are three
# kinds of reason to be recorded.
run_case "audit: an ignored id with no recorded reason" fail \
	'./scripts/audit.sh' \
	"$(py 'edit(".cargo/audit.toml", "  \"RUSTSEC-2026-0403\",\n", "  \"RUSTSEC-2026-0403\",\n  \"RUSTSEC-2026-9999\",\n")')" \
	"no reason is recorded"

# Deliberately NOT here: a case that removes the two zstd ignores and requires
# cargo-audit itself to name the advisories again. The job that runs this
# harness has no cargo-audit, so audit.sh skips that half and exits 0, and such
# a case would read TOOTHLESS about a gate that is working. The `cargo audit`
# step of the other job is what pins that direction: it fails the day the
# lockfile carries an advisory nobody ignored.

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

# There is deliberately NO `fail` case putting the leak back, and the reason is
# the harness's own rule rather than laziness. The check sits behind
# `[ -d "$db/.git" ]`, and a fresh CI runner has no advisory database until
# `cargo audit` creates one, which happens AFTER this check. So on CI the leak
# changes nothing, the gate passes, and the case reports TOOTHLESS: the gate
# passed on a fault it exists to catch. It did exactly that on the first run of
# this branch, which is the harness working.
#
# Making it bite everywhere would mean pointing CARGO_HOME at a fixture, and
# CARGO_HOME is also where the crate registry lives, so `cargo audit` two lines
# later would fetch the world. That is a bigger change to a security gate than
# this fix earns.
#
# So the fail direction is pinned by the commit that found it and by the
# measurement in audit.sh's own comment, and not by this harness. Said here
# rather than left as an absence somebody reads as coverage.

# The bounded reason on the lockfile exactly as it stands. A gate that failed
# here would be refusing the one state the repository is meant to be in, and the
# fail cases above would all pass for the wrong reason.
run_case "audit: the zstd ignores hold on the lock as it stands" pass \
	'./scripts/audit.sh' \
	""

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

# The way a test is meant to be added: a module of the one binary. A gate that
# refused this would refuse the fix for the thing it checks.
run_case "one-test-binary: a new module under tests/it" pass \
	'./scripts/one-test-binary-per-crate.sh' \
	"$(py 'p = "crates/trailryx-store/tests/it/teeth_planted.rs"
open(p, "w").write("#[test]\nfn teeth_planted() {}\n")
edit("crates/trailryx-store/tests/it/main.rs", "mod two_verifiers;\n", "mod two_verifiers;\nmod teeth_planted;\n")')"

echo
echo "=== and the one this estate learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

# THE HOLE. grep over a directory that is not there printed nothing and the
# script exited 0. This is the case that keeps the fix in place.
# The destination is a name only this script uses, so it cannot already exist
# as a repository directory (`crates-elsewhere` did, and `git mv` into an
# existing directory nests rather than renames). A leftover from an interrupted
# run is removed first, so the move is a rename every time; `restore` removes
# the same name afterwards, ignored contents included.
run_case "no-unsafe: no Rust left under crates/" fail \
	'./scripts/no-unsafe.sh' \
	"$(py 'import shutil, subprocess
shutil.rmtree(".teeth-crates-parked", ignore_errors=True)
subprocess.run(["git", "mv", "crates", ".teeth-crates-parked"], check=True)')" \
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

# A loop over a glob that matches nothing finds no crate with two binaries, and
# that must read as nothing measured, not as one binary each.
run_case "one-test-binary: no crates left to count" fail \
	'./scripts/one-test-binary-per-crate.sh' \
	"$(py 'import shutil, subprocess
shutil.rmtree(".teeth-crates-parked", ignore_errors=True)
subprocess.run(["git", "mv", "crates", ".teeth-crates-parked"], check=True)')" \
	"measured nothing"

echo
echo "=== compat/1.0.json, the surface trailryx's 1.0 will freeze (invariant 43) ==="

# A frozen name absent from every file its kind's `where` names, whether the code
# renamed it or the manifest just outlived the code. Global replace: a binary name
# in components.json is both a `name` and a `checked.binary`, sometimes a third
# time in its own prose, and a rename that missed one of those would leave the
# gate passing on exactly the drift it exists to catch.
run_case "compat-surface: a frozen binary renamed in components.json" fail \
	'./scripts/compat-surface.sh' \
	"$(pyall 'edit("components.json", "trailryx-jsonl", "trailryx-jsonl-renamed")')" \
	"'trailryx-jsonl' is promised"

# An environment name the code stops reading. `TRAILRYX_S3_BUCKET` is one
# occurrence in `components.json`, the only file this manifest names for `env`
# that mentions it, so a single replace is the whole of the drift.
run_case "compat-surface: an env name gone from components.json" fail \
	'./scripts/compat-surface.sh' \
	"$(py 'edit("components.json", "TRAILRYX_S3_BUCKET", "TRAILRYX_S3_BUCKET_RENAMED")')" \
	"'TRAILRYX_S3_BUCKET' is promised"

# A schema string the mapper stops accepting. Losing v0.2 silently would refuse
# every producer still on it with `UnknownSchema`, which reads to an operator as a
# malformed line rather than as a version this reader dropped.
run_case "compat-surface: an agent-event schema string gone" fail \
	'./scripts/compat-surface.sh' \
	"$(py 'edit("crates/trailryx-agentevent/src/lib.rs", "\"taipanbox.dev/agent-event/v0.2\"", "\"taipanbox.dev/agent-event/v0.2-renamed\"")')" \
	"'taipanbox.dev/agent-event/v0.2' is promised"

# The human form, edited by hand rather than rendered. This is the same failure
# invariant 16 names for the README's own numbers: a copy with no gate rots first,
# and the rendering is the one place this promise is written for a reader rather
# than for the check.
run_case "compat-surface: COMPATIBILITY.md edited by hand" fail \
	'./scripts/compat-surface.sh' \
	"$(py 'edit("COMPATIBILITY.md", "# Compatibility", "# Compatibility (hand-edited)")')" \
	"is not the rendering of"

# An additive name is documentation for a reader and is never checked against the
# code, by design: a detector, a dev-tool, a schema version this reader accepts
# next are all additive rather than frozen, and adding one must not fail the gate
# the way adding a FROZEN one must. The mutation edits the manifest and regenerates
# the rendering as part of the same step, so the case is judged on the property it
# names rather than on the unrelated fact that a hand-edited doc would also fail.
run_case "compat-surface: an additive name added" pass \
	'./scripts/compat-surface.sh' \
	"$(cat <<'PY'
import json
import subprocess

p = "compat/1.0.json"
m = json.load(open(p))
before = len(m["additive"])
m["additive"].append("a teeth-test additive name, never checked against the code")
assert len(m["additive"]) == before + 1, "additive list did not grow"
json.dump(m, open(p, "w"), indent=2)
open(p, "a").write("\n")
r = subprocess.run(["./scripts/compat-surface.sh", "--write"], capture_output=True, text=True)
assert r.returncode == 0, "regenerating after the additive edit failed:\n" + r.stdout + r.stderr
PY
)"

# The manifest itself gone. Every other case above assumes compat/1.0.json is
# there to compare against; this is the check on that assumption, and the answer
# has to be "measured nothing" rather than a silent pass on an absent promise.
run_case "compat-surface: the manifest is gone" fail \
	'./scripts/compat-surface.sh' \
	"$(cat <<'PY'
import os
os.remove("compat/1.0.json")
PY
)" \
	"measured nothing"

# A file a `where` entry names, gone. The check cannot tell "this name left the
# code" from "the file it lived in left the repository", and it must not try:
# both are measured nothing rather than a pass, because a literal cannot be found
# in a file that is not there either way.
run_case "compat-surface: a file a where entry names is gone" fail \
	'./scripts/compat-surface.sh' \
	"$(cat <<'PY'
import os
os.remove("crates/trailryx-otlp/tests/it/jsonenc_is_otlp_json.rs")
PY
)" \
	"measured nothing"

# ---------------------------------------------------------------------------
# feature-bindings.sh: every scenario bound to a test, both ways, and a missing
# subject measured as nothing rather than as a pass.
# ---------------------------------------------------------------------------

# A scenario with its binding removed. The sentence still describes a behaviour, and
# nothing checks it: exactly the gap the gate exists to close.
run_case "feature-bindings: a scenario with no binding" fail \
	'./scripts/feature-bindings.sh' \
	"$(py 'edit("features/agent-event-v1.0.feature", "    # bound: an_established_subject_under_v0_3_still_maps\n", "")')" \
	"has no '# bound:' line"

# A binding renamed to a test that does not exist. The scenario now points at nothing,
# which is what a rename or a deletion leaves behind if nobody follows the reference.
run_case "feature-bindings: a binding naming no test" fail \
	'./scripts/feature-bindings.sh' \
	"$(py 'edit("features/agent-event-v1.0.feature", "# bound: under_v1_0_the_claim_prefix_is_not_stripped", "# bound: under_v1_0_the_claim_prefix_is_renamed")')" \
	"no test of that name exists"

# Every scenario keyword turned into something else. The bindings are then outside any
# scenario, and the gate must say it measured nothing rather than report zero problems
# over a file that holds no scenarios at all.
run_case "feature-bindings: a feature file with no scenarios" fail \
	'./scripts/feature-bindings.sh' \
	"$(pyall 'edit("features/agent-event-v1.0.feature", "  Scenario:", "  Example:")')" \
	"measured nothing"

# The whole feature directory gone. A suite that vanished must not read as a suite with
# zero scenarios all bound.
run_case "feature-bindings: no feature files at all" fail \
	'./scripts/feature-bindings.sh' \
	"$(cat <<'PY'
import shutil
shutil.rmtree("features")
PY
)" \
	"measured nothing"

# A no-op edit on the committed tree. The gate must pass a feature file it has no
# reason to object to; a binding gate that fails everything would be as useless as one
# that passes everything.
run_case "feature-bindings: the committed tree passes" pass \
	'./scripts/feature-bindings.sh' \
	"$(py 'edit("features/agent-event-v1.0.feature", "Then both read to the same record", "Then both read to the same record")')"


# ---------------------------------------------------------------------------
# suite.sh counts, and readme-numbers.sh reading a recorded run instead of running
# the suite again. CI takes this path, so it is the one that has to bite.
#
# The recorded run is built from the README's own table, so it agrees with the
# README on the committed tree by construction, and every fault below is a change to
# the record alone. It lives outside the tree, which is why `restore` does not reach
# it and why it is rebuilt before each case.
# ---------------------------------------------------------------------------

TEETH_REC="$baseline_dir/suite-record.txt"
export TEETH_REC

fresh_record() {
	python3 - "$TEETH_REC" <<'PY'
import os, re, subprocess, sys

out = sys.argv[1]
head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
rows = []
for line in open("README.md"):
    if not line.startswith("| `trailryx-"):
        continue
    fields = line.split("|")
    crate = re.match(r"\s*`(trailryx-[a-z0-9-]+)`", fields[1]).group(1)
    count = fields[-2].strip()
    if count != "-":
        rows.append((crate, int(count)))
assert rows, "no crate rows in the README"

lines = ["suite-head: " + head]
exes = {}
for i, (crate, n) in enumerate(rows):
    exes[crate] = "/w/target/debug/deps/%s-%016x" % (crate.replace("-", "_"), i)
    lines.append(
        '{"reason":"compiler-artifact","package_id":"path+file:///w/crates/%s#1.0.0",'
        '"manifest_path":"/w/crates/%s/Cargo.toml","target":{"kind":["lib"],"name":"%s"},'
        '"profile":{"test":true},"features":[],"filenames":["%s"],"executable":"%s","fresh":true}'
        % (crate, crate, crate.replace("-", "_"), exes[crate], exes[crate])
    )
lines.append("    Finished `test` profile [optimized + debuginfo] target(s)")
for crate, n in rows:
    lines.append("     Running unittests src/lib.rs (target/debug/deps/%s)" % os.path.basename(exes[crate]))
    lines.append("")
    lines.append("running %d tests" % n)
    lines.append("." * n)
    lines.append(
        "test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s" % n
    )
    lines.append("")
lines.append("suite-exit-status: 0")
open(out, "w").write("\n".join(lines) + "\n")
PY
}

noop_on_record="$(py 'import os
edit(os.environ["TEETH_REC"], "suite-exit-status: 0", "suite-exit-status: 0")')"

# A run that failed. Its counts are the counts of a run that stopped somewhere, and a
# partial count reads exactly like a measurement.
fresh_record
run_case "suite-counts: a recorded run that exited non-zero" fail \
	'./scripts/suite.sh counts "$TEETH_REC"' \
	"$(py 'import os
edit(os.environ["TEETH_REC"], "suite-exit-status: 0", "suite-exit-status: 101")')" \
	"does not end in a clean run"

# A run that was killed: no exit status was ever written.
fresh_record
run_case "suite-counts: a recorded run with no exit status" fail \
	'./scripts/suite.sh counts "$TEETH_REC"' \
	"$(py 'import os
edit(os.environ["TEETH_REC"], "suite-exit-status: 0", "")')" \
	"does not end in a clean run"

# A record is evidence about one tree. One made at another commit counts another tree.
fresh_record
run_case "suite-counts: a recorded run from another commit" fail \
	'./scripts/suite.sh counts "$TEETH_REC"' \
	"$(py 'import os
edit(os.environ["TEETH_REC"], "suite-head: ", "suite-head: 0000")')" \
	"was made at commit"

# A result that no header owns would be added to the total and to nobody, which is
# how a total and a table come apart without either being wrong about its own sum.
fresh_record
run_case "suite-counts: a result line no header owns" fail \
	'./scripts/suite.sh counts "$TEETH_REC"' \
	"$(py 'import os
edit(os.environ["TEETH_REC"], "{\"reason\"", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n{\"reason\"")')" \
	"belong to no crate"

# A test binary that no build message accounts for. The run happened, and nobody can
# say whose it was.
fresh_record
run_case "suite-counts: a binary no build message accounts for" fail \
	'./scripts/suite.sh counts "$TEETH_REC"' \
	"$(py 'import os
edit(os.environ["TEETH_REC"], "(target/debug/deps/trailryx_sim-", "(target/debug/deps/nothing_")')" \
	"belong to no crate"

# Nothing counted at all must be said, not reported as zero tests in agreement with
# nothing. Invariant 19: a check that cannot fail reports zero for ever.
fresh_record
run_case "suite-counts: a recorded run with no results" fail \
	'./scripts/suite.sh counts "$TEETH_REC"' \
	"$(pyall 'import os
edit(os.environ["TEETH_REC"], "test result: ok.", "test outcome: ok.")')" \
	'no "test result" line at all'

# A binary that was announced and never reported. Its tests are in no count, and the
# total still adds up to something, which is the quiet way for a count to be short.
fresh_record
run_case "suite-counts: a run header with no result after it" fail \
	'./scripts/suite.sh counts "$TEETH_REC"' \
	"$(py 'import os
edit(os.environ["TEETH_REC"], "     Running unittests src/lib.rs (target/debug/deps/trailryx_sim-0000000000000000)", "     Running unittests src/lib.rs (target/debug/deps/trailryx_sim-0000000000000000)\n\n     Running unittests src/lib.rs (target/debug/deps/trailryx_sim-0000000000000000)")')" \
	"run header(s)"

# And the non-fault: a clean run for this commit is counted, with a total.
fresh_record
run_case "suite-counts: a clean recorded run is counted" pass \
	'./scripts/suite.sh counts "$TEETH_REC" | grep "^total [1-9]" >/dev/null' \
	"$noop_on_record"

# readme-numbers.sh itself, reading the record. One crate runs one test more than its
# row says: the table is out of date, and it must be named.
fresh_record
run_case "readme-numbers: a crate row the recorded run disagrees with" fail \
	'TRAILRYX_SUITE_RECORD="$TEETH_REC" ./scripts/readme-numbers.sh' \
	"$(py 'import os, re
p = os.environ["TEETH_REC"]
s = open(p).read()
m = re.search(r"running (\d+) tests\n(\.*)\ntest result: ok\. (\d+) passed", s)
assert m
n = int(m.group(1)) + 1
new = "running %d tests\n%s\ntest result: ok. %d passed" % (n, "." * n, n)
open(p, "w").write(s.replace(m.group(0), new, 1))')" \
	"the table says"

# The same record, a README that still agrees with it, and a gate that must not object.
# Without this the case above would be satisfied by a gate that fails everything.
fresh_record
run_case "readme-numbers: a recorded run that agrees passes" pass \
	'TRAILRYX_SUITE_RECORD="$TEETH_REC" ./scripts/readme-numbers.sh' \
	"$noop_on_record"

# A record the gate cannot read must stop it, not send it to run the suite instead:
# a silent fallback would turn a broken record into a slow pass.
fresh_record
run_case "readme-numbers: an unreadable recorded run stops the gate" fail \
	'TRAILRYX_SUITE_RECORD="$TEETH_REC" ./scripts/readme-numbers.sh' \
	"$(py 'import os
edit(os.environ["TEETH_REC"], "suite-exit-status: 0", "suite-exit-status: 101")')" \
	"the recorded suite run could not be read"

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
