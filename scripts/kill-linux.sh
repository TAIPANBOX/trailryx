#!/bin/sh
# The kill run on real ext4 and real xfs, inside a Linux container on this Mac.
#
# What this buys: the roadmap asks for ext4 and xfs, and the run so far was APFS.
# What it does not buy: a power cut. This test kills a *process*; the kernel and
# its page cache survive, so what is under test is our recovery from a torn write,
# not the filesystem's behaviour when the machine loses power.
#
# This file used to end that paragraph with "a cloud VM would not buy that
# either, which is why this runs locally and free". That was wrong, and it was
# wrong in the direction that let us stop looking. Both providers document the
# opposite in as many words. AWS on `stop-instances --force`: the instance
# "shuts down forcibly without flushing the file system caches and metadata",
# and bypassing the graceful shutdown "might result in data loss or corruption
# (for example, memory contents not flushed to disk or loss of in-flight IOs)".
# GCP on `instances reset`: it "forcibly wipes the memory contents" and does not
# perform a clean shutdown of the guest OS. That is precisely the page cache
# this test cannot take away, so a forced stop is a strictly harsher run than
# anything reachable here, and the honest reason this file runs locally is that
# it is free, not that the cloud has nothing to add.
#
# Read from the providers' own documentation, 2026-08-04. The cloud run itself
# is still in VALIDATION.md under *not yet measured*, where it belongs until it
# has been done.
set -e

echo "=== встановлюю інструменти файлових систем"
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq xfsprogs e2fsprogs cmake clang >/dev/null 2>&1
echo "    ok: $(mkfs.xfs -V 2>&1 | head -1), $(mkfs.ext4 -V 2>&1 | head -1)"

echo "=== збираю trailryx-kill під linux/aarch64"
cd /src
cargo build --release --bin trailryx-kill 2>&1 | tail -3

for fs in ext4 xfs; do
  echo
  echo "=== $fs"
  img=/$fs.img
  mnt=/mnt/$fs
  mkdir -p "$mnt"
  # xfs refuses anything under 300MB, ext4 does not care.
  dd if=/dev/zero of="$img" bs=1M count=512 status=none
  if [ "$fs" = ext4 ]; then mkfs.ext4 -q -F "$img"; else mkfs.xfs -q -f "$img"; fi
  mount -o loop "$img" "$mnt"
  grep " $mnt " /proc/mounts
  # The harness puts its directory in the temp dir, so this is how it is aimed
  # at the filesystem under test.
  TMPDIR="$mnt" /target/release/trailryx-kill run 40
  umount "$mnt"
done
