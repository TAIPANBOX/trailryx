#!/bin/sh
# Build the offline verifier twice, from two different directories, and refuse if
# the two binaries differ by a byte.
#
# WHY THIS EXISTS
#
# `trailryx-verify` is the answer to "who checked your code". That answer is worth
# less if the binary an auditor runs cannot be shown to come from the source they
# read. The usual thing that breaks it is the build path: rustc embeds paths in
# panic messages and debug info, so a binary built in /home/alice differs from one
# built in /build, and neither can be compared against the other.
#
# So this measures the property rather than asserting it, and it uses paths of
# deliberately DIFFERENT LENGTHS. Two paths of the same length would hide a
# length-dependent embedding, which is the failure this check is for. An earlier
# version of this used `rb1` and `rb2` and proved less than it looked like.
#
# WHAT IT DOES NOT PROVE
#
# Nothing about a different toolchain. Byte-identical output needs the same rustc,
# and `rust-toolchain.toml` says `stable`, which moves. That is deliberate: pinning
# it would stop the gate from telling us when a new compiler breaks the build. So a
# digest is only meaningful next to a version, and this script prints both. See
# `docs/reproducing.md`.
#
# Nothing about other platforms either. A macOS binary and a Linux binary are
# different by construction; the claim is per target, not across targets.

set -eu

BIN="${1:-trailryx-verify}"
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

short="$work/a"
long="$work/one-rather-longer-directory-name"

for dir in "$short" "$long"; do
    mkdir -p "$dir"
    # Everything git tracks, and nothing it does not: a stray file in the working
    # tree must not be able to change the answer.
    (cd "$root" && git archive HEAD) | tar -x -C "$dir"
done

echo "toolchain: $(rustc --version)"
echo "cargo:     $(cargo --version)"
echo "source:    $(cd "$root" && git rev-parse HEAD)"
echo "binary:    $BIN"

for dir in "$short" "$long"; do
    # --locked so the lockfile cannot be resolved differently between the two, and
    # --release because that is what anybody would actually run.
    (cd "$dir" && cargo build --release --locked --quiet --bin "$BIN")
done

digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

one=$(digest "$short/target/release/$BIN")
two=$(digest "$long/target/release/$BIN")

echo "from $(printf %s "$short" | wc -c | tr -d ' ') chars of path: $one"
echo "from $(printf %s "$long" | wc -c | tr -d ' ') chars of path: $two"

if [ "$one" != "$two" ]; then
    echo
    echo "FAIL: the same source produced two different binaries, so a build cannot be"
    echo "      checked against the source it came from. The usual cause is a path"
    echo "      embedded in the output; --remap-path-prefix is the usual fix."
    exit 1
fi

# A path is the likeliest thing to leak, so it is checked directly as well as
# through the comparison: two builds could agree and still both embed a path, if
# the paths happened not to reach the binary in a length-sensitive way.
if command -v strings >/dev/null 2>&1; then
    if strings "$short/target/release/$BIN" | grep -q "$work"; then
        echo
        echo "FAIL: the build directory appears inside the binary, so the two matched by"
        echo "      luck rather than by being path-independent."
        exit 1
    fi
fi

echo
echo "reproducible: $one"
