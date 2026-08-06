#!/usr/bin/env bash
#
# Invariant 18: no test waits without a bound.
#
# A hanging test reports nothing at all. Not a failure, not a name, not a line of
# output, which is less than a wrong answer tells you. It has already cost this
# repository once: teaching the S3 fake to refuse a malformed request turned one
# failing test into a run that never ended, and finding that cost more than the bug it
# was hiding.
#
# WHAT THIS CHECKS, and it is deliberately two narrow things rather than one broad one,
# because both have a bounded form in the same API and so can be asked mechanically:
#
#   1. A bare `.recv()` in test code. `recv_timeout` is the same call with a bound, so
#      the bare one is never necessary and a test that waits on a channel forever is
#      waiting on a thread that may already be stuck.
#   2. A test file that ACCEPTS a blocking connection and never sets a read timeout.
#      `accept()` hands back a socket whose reads block for ever by default, and
#      `set_read_timeout` is the one line that bounds them.
#
# Rule 2 asks about `accept()` and not about `TcpStream::connect`, and the narrowing
# was forced by a real case rather than chosen. Keying it on either one flagged
# `crates/trailryx-http/src/tls.rs`, which connects to port 1 expecting to be refused,
# returns early when it is, and never reads a byte. Taking a socket is not the same as
# waiting on one. What makes the accepting side different is not the direction: a fake
# server reads whatever the code under test sends, and the code under test is the thing
# that might be broken, so the fake is where a bug arrives as silence.
#
# The two are halves of one failure and the fix for either alone is not enough, which
# is why both are here. `crates/trailryx-azure/tests/blob.rs` had neither: its fake
# server blocked in `serve` on a client that had connected and said nothing, so the
# thread stayed alive, so the channel never closed, so the test's `recv()` waited for a
# message from a thread that was never going to send one. `crates/trailryx-s3/tests/
# store.rs` is the same fake with both bounds, and it is the file to copy.
#
# WHAT IT DOES NOT CHECK, said out loud because a check that hides its own limit is
# worse than one that states it:
#
#   - **Async waits.** `crates/trailryx-sql/tests/wire.rs` and
#     `crates/trailryx-federation-grpc/tests/across_two_environments.rs` hand their
#     listener to a server library and then wait as a CLIENT, where the bound would be
#     `tokio::time::timeout` around the client call rather than a socket option. That
#     is a real gap and it is not flagged here, because a grep cannot tell an await
#     that can hang from one that cannot, and a check that cries wolf on every `.await`
#     would be turned off within a week.
#   - **`join()` on a thread**, which std cannot bound at all. There is no
#     `join_timeout`, so there is nothing to demand.
#   - **A subprocess that never exits.** `Command::output()` waits for ever by design
#     and every caller here runs a tool that terminates.
#   - **A client that connects and reads**, for the reason rule 2 gives above: the one
#     test that does it here bounds itself, and every phrasing that catches it also
#     catches the connect that expects to be refused.
#   - **Busy loops.** A `loop` around a condition with a `sleep` in it is unbounded and
#     unrecognisable to a grep.
#
# One file, called by both `.githooks/pre-push` and `.github/workflows/ci.yml`.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

problems=0
waits=0

note() {
  printf '%s\n' "$1"
  problems=$((problems + 1))
}

# Test code is a file under a `tests/` directory, or any tracked Rust file that
# declares a test. The second half matters: a `#[cfg(test)]` module inside `src/` is
# test code that a `tests/`-only scan would not see.
tests=$(
  {
    git ls-files 'crates/*/tests/*.rs'
    git grep -l -E '#\[(tokio::)?test\]' -- 'crates/*.rs'
  } | sort -u
)

for f in $tests; do
  [ -f "$f" ] || continue

  # 1. A channel wait with no bound. `recv_timeout` is the bounded form of the same
  # call, so there is nothing to weigh up: the bare one is refused.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    waits=$((waits + 1))
    note "$f:${line%%:*}: a bare .recv() waits for ever, and recv_timeout is the same call with a bound"
  done < <(grep -n '\.recv()' "$f" || true)

  # 2. A blocking socket with no read timeout. Async sockets are a different shape and
  # a different bound, so a file that uses `tokio::net` is out of scope here rather
  # than quietly passing: the header says so and the debt list repeats it.
  if grep -q 'tokio::net' "$f"; then
    continue
  fi
  accepts=$(grep -c '\.accept()' "$f")
  if [ "$accepts" -gt 0 ]; then
    waits=$((waits + accepts))
    grep -q 'set_read_timeout' "$f" ||
      note "$f: accepts a blocking connection and never calls set_read_timeout, so a client that connects and says nothing hangs the run"
  fi
done

if [ "$problems" -gt 0 ]; then
  printf 'crates/trailryx-s3/tests/store.rs is the fake with both bounds, and is the one to copy\n'
  exit 1
fi

# The count is printed rather than a bare "ok", so one run can be compared with the
# last. It counts waits examined, not files, because a file growing a second wait is
# the change worth seeing.
printf '%d bounded waits in test code\n' "$waits"
exit 0
