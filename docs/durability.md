# The durability contract

> Every sequence number reported as acked survives any crash.

That is the whole promise. Everything else in Trailryx rests on it: a proof over
records that might not be there proves nothing, and an audit trail with an
unexplained hole is worse than no audit trail, because it looks complete.

This document says exactly what is promised, when, and what is deliberately not
promised. It is written down because the failure mode is silent, and because
"we call fsync" is not a contract.

---

## 1. States a record passes through

| State | Meaning | Survives a crash |
|---|---|---|
| **pending** | some bytes are on the file, the frame is incomplete | no |
| **written** | the whole frame is on the file | maybe |
| **acked** | a successful `sync` covered it | **yes** |

Only the third is a promise. `written` is deliberately weaker than it sounds:
the bytes have been handed to the operating system and nothing more has been
claimed about them.

## 2. What `sync` does

`sync` calls `fsync` and, **only if it returns success**, moves the acked
watermark up to whatever was written.

A failed sync promises nothing and moves nothing. The journal marks itself
degraded and keeps the watermark exactly where it was. This is one line of code
and it is the single most important line in the write path.

## 3. What happens after a crash

Recovery walks the file from the segment header and accepts the longest prefix
where, for every frame in order:

1. the frame parses and its CRC matches;
2. the record body decodes, including re-parsing every identifier;
3. `seq` is exactly one more than the previous;
4. `prev_hash` equals the running chain head;
5. the stored chain link equals `chain_step(prev_hash, seq, body)`;
6. the record names this shard and this segment.

Everything after the first failure is **discarded and truncated away**.

Truncation is not optional. Appending after bytes that failed to verify would
break the journal permanently: every later recovery would stop at that same
offset while the writer kept believing it was making progress. The store would
freeze while pretending to accept writes, which is the worst available outcome.

### A torn tail is not an incident

Recovery reports *why* it stopped, and the distinction is operational:

- **TornTail**: a frame was cut short. This is the ordinary shape of a crash.
- **ChainBroken**: a frame parsed cleanly but did not follow from the previous
  one. That is not something a disk does. Either history was rewritten or the
  writer is wrong, and either way it is an incident.
- **WrongOwner**: a record inside the file belongs to a different shard or
  segment than the header. One file cannot be two journals.

An operator should never have to guess which happened.

Separately, if less comes back than had been promised durable, recovery reports
a **durability violation** carrying both numbers. The watermark still drops,
because pretending otherwise would be worse, but it never drops in silence.

### The file knows whose it is

The segment header carries the shard and the segment id, the chain begins at a
hash **of the header** rather than at zero, and every recovered record is
checked against the header. Opening one shard's file under another shard's
identity is refused outright rather than accepted: a file is perfectly
consistent with itself, so checking records against the file's own header would
have adopted the lot.

## 4. Writes that are refused

A device that accepts only part of a frame, or refuses it outright, leaves the
record **pending**. The next attempt continues the same record from exactly
where it stopped.

No new record is started while one is outstanding. This is not an optimisation:
starting a new record after an abandoned partial one leaves orphaned bytes in
the middle of the stream, recovery stops at them, and everything written
afterwards becomes unreachable while the acked watermark keeps climbing. The
simulator found precisely this in stage 0, reporting `promised=13 recovered=3`.

## 5. Loss is counted, never swallowed

If the store cannot keep a record, it counts a gap and the count is visible.
Writes stay fail-open with respect to the emitter's traffic, because blocking an
agent's work to record it is the wrong trade, but **a lost record is itself an
event**. Silent loss is the one behaviour that would make the whole product
dishonest.

## 6. Duplicates

Accepting a record is idempotent on record id, within a bounded window, so
at-least-once sources are safe to point at the store. The window is bounded on
purpose: an unbounded set is a slow leak that only appears in the deployments
that matter. A source retrying older than the window produces a duplicate that
lands in the journal, where it is visible, rather than being silently absorbed.

Integrity does not depend on this. The chain binds position as well as content,
so a duplicate is detectable even if deduplication misses it entirely.

## 7. What is not promised

- **Nothing about unsynced data.** After a crash a random prefix of the unsynced
  tail may have survived. Code that assumes all or nothing is wrong in both
  directions, and the simulator models exactly this.
- **Nothing against a disk that lies.** A device that reports a successful flush
  it did not perform breaks the contract, and nothing in software can prevent
  it. What the simulator guarantees is that we **notice**: a dedicated test
  fails if the crash model ever stops catching a lying `fsync`.
- **Not tamper-proof.** The chain proves the sequence was not edited in place.
  It does not prove the file was not rewritten wholesale by whoever holds the
  signing key. Segment signatures and, later, external anchoring address that.

## 8. `fsync` and `io_uring`

When the io_uring backend arrives, `fsync` goes **outside the ring**, as
PostgreSQL does. In io_uring, `fsync` is blocking and is executed by fallback
worker threads, and it cannot be issued from rings in polled mode at all. Routing
it through the ring buys nothing and costs a thread pool on the critical path.

The related trap is `O_DIRECT_NO_FSYNC`, which produces a real write hole: the
log reports data as flushed when nothing made it durable. We do not use it.

## 9. One walk, not two

Recovery and reading use the same function, applying the same six rules. Two
implementations of "read the journal" means two sets of rules about what counts
as valid, and the weaker one becomes the foundation of whatever gets built next.
The first version's reader checked the chain link but not the sequence or the
previous head, and returned a silent prefix when it stopped early.

## 10. How this is verified

- The crash point is walked across **every step** of a run, not sampled.
- The contract is checked across **thousands of seeds** with an unreliable but
  honest disk: short writes, sync errors, out of space, torn tails, power cuts.
- A separate test asserts the harness still **catches** a lying `fsync`, so the
  crash model cannot quietly go soft.
- Every single-bit flip in a frame is confirmed to be detected.
- Recovery is exercised for the case where it must report tampering rather than
  a crash.

Real disks lie in ways a model does not. A real `kill -9` run on ext4 and xfs is
part of stage 13, as a complement to the simulator and not a replacement for it.
