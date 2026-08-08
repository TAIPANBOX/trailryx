#!/usr/bin/env bash
#
# Append rate on one shard, at five sync policies, on this machine's filesystem.
#
# NOT a gate, and it must not become one. The number it prints is a property of the
# disk under it: a laptop on APFS, a CI runner's network-backed volume and a server
# with a battery-backed controller disagree by more than an order of magnitude, and a
# check that refused a push over that would be refusing the hardware. It lives in
# `VALIDATION.md` under *measured on demand*, with its date and this command.
#
# Run it twice and quote the second. The first pays for a cold page cache and for
# whatever the machine was doing when it started, which is the same reason the gate
# timing section quotes its second run.
#
# What the answer is for: `sync_every` is the only field between a durable record and
# a fast one, and until this existed the repository said, correctly and unhelpfully,
# that throughput had never been measured. A caller putting this in front of a live
# event stream needs the curve, not the ends.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

cargo run --quiet --release --bin trailryx-rate -- "$@"
