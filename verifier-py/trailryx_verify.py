#!/usr/bin/env python3
"""A second, independent verifier for a Trailryx evidence pack.

    python3 verifier-py/trailryx_verify.py incident-4471.trxevid

WHY THIS EXISTS
---------------
`docs/planning/trailryx-plan.md` asks for it by name, under R6: two
implementations that agree prove the FORMAT rather than the author. The Rust
verifier answers "who checked your code" with "read it, it has no dependencies".
This answers a different question: whether the format is written down well enough
that somebody else's program reaches the same verdict.

It shares no code with the Rust one. It uses Python's standard library and
nothing else: `hashlib` has SHA-384, and every root, chain link and index key
below is recomputed from the bytes in the pack.

WHAT IT PROVES
--------------
That an independent program, reading the same file, recomputes every hash the
pack commits to and agrees on the verdict. Where the two disagree, one of them is
wrong and the format is ambiguous, and both are worth knowing.

WHAT IT DOES NOT PROVE
----------------------
Said plainly, because the honest limit is narrower than the headline:

* **It was written by reading the Rust.** A genuinely independent reimplementation
  would come from a specification and a different person. This one would not catch
  a defect that consists of the same misunderstanding twice. What it does catch is
  every place the format is under-documented, because those are the places writing
  this required guessing, and it catches a change to one side that the other did
  not follow.
* **It does not check signatures.** ECDSA over P-384 in pure Python is several
  hundred lines of modular arithmetic whose bugs are silent, and the point here is
  the format rather than the curve. Where a pack carries a signature this reports
  it as unchecked and names the command that checks it, which is the same split the
  Rust verifier makes for a timestamp token and for the same reason.
* **It is not a replacement.** It is a second opinion. A pack is VERIFIED when both
  say so.
"""

import hashlib
import sys

MAGIC = b"TRXEVID"
MIN_VERSION = 2
MAX_VERSION = 3
HASH_BYTES = 48

SECTION_END = 0
SECTION_HEADER = 1
SECTION_SHARD = 2
SECTION_SEGMENT = 3
SECTION_RECORDS = 4
SECTION_SIGNATURE = 5
SECTION_WITNESS = 6
SECTION_ANCHOR = 7

# A ceiling on anything the pack asks us to allocate. The pack comes from the
# party being audited, so a length field is an instruction from them.
MAX_ITEMS = 100_000_000

CHAIN_DOMAIN = b"trailryx/chain/v1\x00"
MANIFEST_DOMAIN = b"trailryx/segment-manifest/v1\x00"
STORE_LEAF_DOMAIN = b"trailryx/store-leaf/v1\x00"

PROVABLE_DIMENSIONS = ("id", "recorded_at", "agent_id", "run_id", "event_type")


class Broken(Exception):
    """The pack does not parse. Distinct from a finding: nothing can be said."""


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def sha384(*parts):
    h = hashlib.sha384()
    for part in parts:
        h.update(part)
    return h.digest()


def leaf_hash(data):
    """RFC 6962 leaf: a 0x00 prefix, which is what stops a leaf standing in for
    an internal node."""
    return sha384(b"\x00", data)


def node_hash(left, right):
    return sha384(b"\x01", left, right)


def merkle_root(leaves):
    """RFC 6962. The split point of n leaves is the largest power of two strictly
    below n, so three leaves split 2 + 1 and not 1 + 2. Iterative rather than
    recursive: a pack chooses the leaf count."""
    if not leaves:
        return sha384(b"")
    stack = [(0, len(leaves))]
    results = {}
    order = []
    while stack:
        span = stack.pop()
        order.append(span)
        start, end = span
        n = end - start
        if n > 1:
            k = 1
            while k << 1 < n:
                k <<= 1
            stack.append((start, start + k))
            stack.append((start + k, end))
    for span in reversed(order):
        start, end = span
        n = end - start
        if n == 1:
            results[span] = leaves[start]
        else:
            k = 1
            while k << 1 < n:
                k <<= 1
            results[span] = node_hash(
                results[(start, start + k)], results[(start + k, end)]
            )
    return results[(0, len(leaves))]


def chain_step(prev, seq, record_bytes):
    return sha384(
        CHAIN_DOMAIN,
        prev,
        seq.to_bytes(8, "big"),
        len(record_bytes).to_bytes(8, "big"),
        record_bytes,
    )


def entry_leaf(key, seq, link):
    return sha384(
        b"\x00", len(key).to_bytes(8, "big"), key, seq.to_bytes(8, "big"), link
    )


def manifest_root(segment):
    parts = [
        MANIFEST_DOMAIN,
        segment["format_version"].to_bytes(2, "big"),
        segment["segment"].to_bytes(8, "big"),
        segment["shard"].to_bytes(2, "big"),
        segment["records"].to_bytes(8, "big"),
        segment["history_root"],
        segment["chain_before"],
        segment["chain_after"],
        len(segment["index_roots"]).to_bytes(8, "big"),
    ]
    for name, root in segment["index_roots"]:
        parts.append(len(name).to_bytes(8, "big"))
        parts.append(name.encode("utf-8"))
        parts.append(root)
    parts.append(segment["first_recorded_at"].to_bytes(8, "big"))
    parts.append(segment["last_recorded_at"].to_bytes(8, "big"))
    parts.append(segment["algorithms"])
    return sha384(*parts)


def shard_leaf(shard, segments, root):
    return leaf_hash(
        sha384(
            STORE_LEAF_DOMAIN,
            shard.to_bytes(2, "big"),
            segments.to_bytes(8, "big"),
            root,
        )
    )


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


class Reader:
    """Big-endian, explicit lengths, no varints. Every accessor slices; nothing
    allocates from a length field."""

    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def take(self, n, what):
        end = self.pos + n
        if n < 0 or end > len(self.buf):
            raise Broken(f"truncated: {what}")
        out = self.buf[self.pos : end]
        self.pos = end
        return out

    def u8(self, what):
        return self.take(1, what)[0]

    def u16(self, what):
        return int.from_bytes(self.take(2, what), "big")

    def u32(self, what):
        return int.from_bytes(self.take(4, what), "big")

    def u64(self, what):
        return int.from_bytes(self.take(8, what), "big")

    def hash(self, what):
        return self.take(HASH_BYTES, what)

    def bytes(self, what):
        return self.take(self.u32(what), what)

    def string(self, what):
        raw = self.bytes(what)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Broken(f"not utf-8: {what}") from exc

    def count(self, what):
        n = self.u64(what)
        if n > MAX_ITEMS:
            raise Broken(f"too many: {what}")
        return n

    def done(self):
        return self.pos >= len(self.buf)


def parse(raw):
    """The pack, section by section."""
    if raw[: len(MAGIC)] != MAGIC:
        raise Broken("bad magic")
    r = Reader(raw)
    r.take(len(MAGIC), "the magic")
    version = r.u8("the version")
    if not MIN_VERSION <= version <= MAX_VERSION:
        raise Broken(f"unknown pack version {version}")

    pack = {
        "version": version,
        "header": None,
        "signature": None,
        "witnesses": [],
        "anchors": [],
        "shards": [],
        "segments": [],
        "record_sets": [],
    }

    while True:
        kind = r.u8("a section kind")
        if kind == SECTION_END:
            break
        length = r.count("a section length")
        body = r.take(length, "a section body")
        s = Reader(body)

        if kind == SECTION_HEADER:
            pack["header"] = {
                "tenant": s.string("the tenant"),
                "generated_at": s.u64("the timestamp"),
                "store_root": s.hash("the store root"),
                "shard_count": s.u32("the shard count"),
                "algorithms": s.take(3, "the algorithms"),
            }
        elif kind == SECTION_SHARD:
            pack["shards"].append(
                {
                    "shard": s.u16("a shard index"),
                    "segment_count": s.u32("a segment count"),
                    "root": s.hash("a shard root"),
                }
            )
        elif kind == SECTION_SEGMENT:
            segment = {
                "format_version": s.u16("a format version"),
                "segment": s.u64("a segment id"),
                "shard": s.u16("a shard index"),
                "records": s.u64("a record count"),
                "history_root": s.hash("a history root"),
                "chain_before": s.hash("a chain head"),
                "chain_after": s.hash("a chain head"),
            }
            n = s.count("an index-root count")
            segment["index_roots"] = [
                (s.string("a dimension name"), s.hash("an index root"))
                for _ in range(n)
            ]
            segment["first_recorded_at"] = s.u64("a first timestamp")
            segment["last_recorded_at"] = s.u64("a last timestamp")
            segment["algorithms"] = s.take(3, "the algorithms")
            pack["segments"].append(segment)
        elif kind == SECTION_RECORDS:
            shard = s.u16("a shard index")
            segment = s.u64("a segment id")
            n = s.count("a record count")
            pack["record_sets"].append(
                {
                    "shard": shard,
                    "segment": segment,
                    "records": [s.bytes("a record body") for _ in range(n)],
                }
            )
        elif kind == SECTION_SIGNATURE:
            pack["signature"] = {
                "algorithm": s.string("a signature algorithm"),
                "public_key": s.bytes("a public key"),
                "signature": s.bytes("a signature"),
            }
        elif kind == SECTION_WITNESS:
            pack["witnesses"].append(
                {
                    "witness": s.string("a witness name"),
                    "seen_at": s.u64("a witness timestamp"),
                    "algorithm": s.string("a signature algorithm"),
                    "public_key": s.bytes("a public key"),
                    "signature": s.bytes("a signature"),
                }
            )
        elif kind == SECTION_ANCHOR:
            pack["anchors"].append(
                {
                    "kind": s.u8("an anchor kind"),
                    "authority": s.string("an anchor authority"),
                    "algorithm": s.string("an anchor algorithm"),
                    "root": s.hash("an anchored root"),
                    "challenge": s.bytes("an anchor challenge"),
                    "evidence": s.bytes("anchor evidence"),
                }
            )
        else:
            raise Broken(f"unknown section {kind}")

        if not s.done():
            raise Broken(f"section {kind} has bytes nobody read")

    if pack["header"] is None:
        raise Broken("no header")
    return pack


# ---------------------------------------------------------------------------
# The canonical record, walked far enough to build the index
# ---------------------------------------------------------------------------


class RecordCursor:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def byte(self):
        if self.pos >= len(self.buf):
            raise Broken("a record ends inside a field")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def take(self, n):
        end = self.pos + n
        if end > len(self.buf):
            raise Broken("a record ends inside a field")
        out = self.buf[self.pos : end]
        self.pos = end
        return out

    def varint(self):
        """LEB128, as the journal writes it."""
        value = 0
        shift = 0
        while True:
            if shift >= 64:
                raise Broken("a varint wider than 64 bits")
            b = self.byte()
            value |= (b & 0x7F) << shift
            if b & 0x80 == 0:
                return value
            shift += 7

    def zigzag(self):
        v = self.varint()
        return (v >> 1) ^ -(v & 1)

    def bytes(self):
        return self.take(self.varint())

    def string(self):
        return self.bytes().decode("utf-8")

    def u128(self):
        return int.from_bytes(self.take(16), "big")

    def hash(self):
        self.take(HASH_BYTES)

    def opt(self, f):
        if self.byte() == 1:
            f()

    def seq(self, f):
        for _ in range(self.varint()):
            f()


def record_fields(body):
    """The five provable dimensions and the sequence number.

    Fields are found by counting past the ones in front, so this is a
    transcription of the canonical writing order and has to change with it. Said
    here rather than discovered.
    """
    c = RecordCursor(body)
    record_id = c.u128()
    c.bytes()  # tenant
    c.varint()  # shard
    agent_id = c.string()
    run_id = c.string()
    c.opt(c.bytes)  # parent run id
    c.seq(c.bytes)  # on behalf of

    c.varint()  # occurred at
    c.opt(c.varint)  # decided at
    recorded_at = c.varint()
    c.opt(c.varint)  # knowledge as of
    c.opt(c.varint)  # clock skew

    event_type = c.byte()
    c.byte()  # severity

    c.opt(c.bytes)  # policy version
    c.opt(c.zigzag)  # budget remaining
    c.opt(c.hash)  # memory ref
    c.opt(c.bytes)  # model
    c.opt(c.varint)  # temperature
    c.opt(c.varint)  # max tokens
    c.opt(c.hash)  # prompt hash
    c.seq(c.bytes)  # tool manifest
    c.seq(c.bytes)  # identity chain

    c.seq(c.u128)  # caused by

    c.opt(c.byte)  # verdict
    c.opt(c.byte)  # error
    c.opt(c.varint)  # latency
    c.opt(c.varint)  # tokens in
    c.opt(c.varint)  # tokens out
    c.opt(c.zigzag)  # cost

    def payload():
        c.hash()
        c.varint()
        c.byte()
        c.hash()

    c.opt(payload)

    seq = c.varint()
    return {
        "id": record_id,
        "recorded_at": recorded_at,
        "agent_id": agent_id,
        "run_id": run_id,
        "event_type": event_type,
        "seq": seq,
    }


def index_key(dimension, fields):
    """Big-endian for numbers, so byte order is value order. A key whose
    lexicographic order disagreed with its semantic order would make every range
    answer wrong in a way no proof could catch."""
    if dimension == "id":
        return fields["id"].to_bytes(16, "big")
    if dimension == "recorded_at":
        return fields["recorded_at"].to_bytes(8, "big")
    if dimension == "agent_id":
        return fields["agent_id"].encode("utf-8")
    if dimension == "run_id":
        return fields["run_id"].encode("utf-8")
    if dimension == "event_type":
        return bytes([fields["event_type"]])
    return None


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

NOTE, WEAK, BROKEN = "note", "weak", "broken"


class Report:
    def __init__(self):
        self.findings = []
        self.records_checked = 0
        self.segments_checked = 0

    def add(self, level, check, detail):
        self.findings.append((level, check, detail))

    def verified(self):
        return not any(level == BROKEN for level, _, _ in self.findings)

    def render(self):
        lines = [f"[{level}] {check}: {detail}" for level, check, detail in self.findings]
        lines.append(
            f"{self.records_checked} records in {self.segments_checked} segments"
        )
        lines.append("VERIFIED" if self.verified() else "BROKEN")
        return "\n".join(lines)


def verify(raw):
    pack = parse(raw)
    report = Report()
    header = pack["header"]

    by_shard = {}
    for segment in pack["segments"]:
        by_shard.setdefault(segment["shard"], []).append(segment)
    records_for = {
        (rs["shard"], rs["segment"]): rs["records"] for rs in pack["record_sets"]
    }
    if len(records_for) != len(pack["record_sets"]):
        report.add(BROKEN, "duplicate", "two record sets for one segment")

    # Every section must be reached from the header's shard list. A section nobody
    # walked to carries the authority of a pack that was called VERIFIED.
    listed = {s["shard"] for s in pack["shards"]}
    for segment in pack["segments"]:
        if segment["shard"] not in listed:
            report.add(
                BROKEN,
                "orphan-segment",
                f"segment {segment['segment']} names shard {segment['shard']}, "
                "which the pack does not list",
            )
    if len(pack["shards"]) != header["shard_count"]:
        report.add(
            BROKEN,
            "shard-count",
            f"the header says {header['shard_count']} shards and {len(pack['shards'])} are here",
        )

    store_leaves = []
    for shard in sorted(pack["shards"], key=lambda s: s["shard"]):
        segments = sorted(by_shard.get(shard["shard"], []), key=lambda s: s["segment"])
        if len(segments) != shard["segment_count"]:
            report.add(
                BROKEN,
                "segment-count",
                f"shard {shard['shard']} says {shard['segment_count']} segments "
                f"and {len(segments)} are here",
            )

        previous = None
        for segment in segments:
            report.segments_checked += 1
            bodies = records_for.get((segment["shard"], segment["segment"]))
            if bodies is None:
                report.add(
                    WEAK,
                    "records-present",
                    f"segment {segment['segment']} carries no records, so only its "
                    "manifest was checked",
                )
            else:
                check_segment(segment, bodies, report)

            if previous is not None and previous["chain_after"] != segment["chain_before"]:
                report.add(
                    BROKEN,
                    "chain-across-segments",
                    f"segment {segment['segment']} does not continue "
                    f"{previous['segment']}",
                )
            previous = segment

        derived = merkle_root([leaf_hash(manifest_root(s)) for s in segments])
        if derived != shard["root"]:
            report.add(
                BROKEN,
                "shard-root",
                f"shard {shard['shard']}'s root is not the root of its segments",
            )
        store_leaves.append(
            shard_leaf(shard["shard"], len(segments), shard["root"])
        )

    if merkle_root(store_leaves) != header["store_root"]:
        report.add(
            BROKEN, "store-root", "the store root is not the root of the shard list"
        )
    else:
        report.add(NOTE, "store-root", "recomputed from the shards")

    # Signatures are not checked here, and the report says so rather than being
    # silent about it: a reader who saw no finding would assume there was nothing
    # to say.
    if pack["signature"]:
        report.add(
            WEAK,
            "root-signature",
            f"a {pack['signature']['algorithm']} signature is present and this verifier "
            "does not check signatures; use the Rust verifier or openssl",
        )
    else:
        report.add(
            WEAK,
            "root-signature",
            "no signature, so this pack proves it is self-consistent and not who published it",
        )
    for witness in pack["witnesses"]:
        report.add(
            WEAK,
            "witness",
            f"{witness['witness']} attests, unchecked here",
        )
    for anchor in pack["anchors"]:
        if anchor["root"] != header["store_root"]:
            report.add(
                BROKEN,
                "anchor",
                f"the evidence from {anchor['authority']!r} is over a different root "
                "than this pack's",
            )
        else:
            report.add(
                WEAK,
                "anchor",
                f"{anchor['authority']!r} anchored this root, unchecked here",
            )

    return report


def check_segment(segment, bodies, report):
    if len(bodies) != segment["records"]:
        report.add(
            BROKEN,
            "record-count",
            f"segment {segment['segment']} says {segment['records']} records "
            f"and carries {len(bodies)}",
        )

    link = segment["chain_before"]
    links = []
    fields = []
    for body in bodies:
        try:
            f = record_fields(body)
        except Broken as exc:
            report.add(
                BROKEN,
                "record-decodes",
                f"a record in segment {segment['segment']} does not decode: {exc}",
            )
            return
        link = chain_step(link, f["seq"], body)
        links.append(link)
        fields.append(f)
        report.records_checked += 1

    if links and link != segment["chain_after"]:
        report.add(
            BROKEN,
            "chain-within-segment",
            f"segment {segment['segment']}'s records do not chain to its own head",
        )
    elif not links and segment["chain_before"] != segment["chain_after"]:
        report.add(
            BROKEN,
            "chain-within-segment",
            f"segment {segment['segment']} is empty and its chain moved",
        )

    if merkle_root([leaf_hash(l) for l in links]) != segment["history_root"]:
        report.add(
            BROKEN,
            "history-root",
            f"segment {segment['segment']}'s history root is not the root of its links",
        )

    # Contiguous FROM ONE, not merely increasing. One segment is one journal file
    # and a journal numbers each file from one, so the whole sequence is known in
    # advance and every number in it has to be present.
    #
    # The first version of this check compared each record to the one before it,
    # which is weaker in a way that matters: a segment whose records all shifted by
    # the same amount would have passed, and so would one missing its first record.
    # The Rust verifier had already been strengthened past that, and running the two
    # against each other is what surfaced the difference. That is the whole reason
    # for having a second implementation.
    for position, f in enumerate(fields):
        expected = position + 1
        if f["seq"] != expected:
            report.add(
                BROKEN,
                "sequence-contiguous",
                f"segment {segment['segment']} has seq {f['seq']} at position "
                f"{position} where {expected} was expected, so a record is missing",
            )
            break

    for name, root in segment["index_roots"]:
        entries = []
        for f, l in zip(fields, links):
            key = index_key(name, f)
            if key is None:
                report.add(
                    WEAK,
                    "index-dimension",
                    f"segment {segment['segment']} indexes {name!r}, which this "
                    "verifier does not know how to key",
                )
                entries = None
                break
            entries.append((key, f["seq"], l))
        if entries is None:
            continue
        entries.sort(key=lambda e: (e[0], e[1]))
        # Strict sortedness is what a completeness proof stands on: a duplicate key
        # and sequence pair would make a boundary entry ambiguous.
        for a, b in zip(entries, entries[1:]):
            if (a[0], a[1]) == (b[0], b[1]):
                report.add(
                    BROKEN,
                    "index-strictly-sorted",
                    f"segment {segment['segment']}'s {name} index has a repeated key",
                )
                break
        derived = merkle_root([entry_leaf(k, s, l) for k, s, l in entries])
        if derived != root:
            report.add(
                BROKEN,
                "index-root",
                f"segment {segment['segment']}'s {name} index root does not match "
                "its own entries",
            )

    for dimension in PROVABLE_DIMENSIONS:
        if dimension not in [name for name, _ in segment["index_roots"]]:
            report.add(
                WEAK,
                "index-dimension",
                f"segment {segment['segment']} has no {dimension} index, so no "
                "completeness proof on that dimension is possible",
            )


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().split("\n\n")[0])
        print("\nusage: trailryx_verify.py PACK")
        return 2
    try:
        with open(argv[1], "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        print(f"cannot read {argv[1]}: {exc}")
        return 2
    try:
        report = verify(raw)
    except Broken as exc:
        print(f"[broken] pack: {exc}")
        print("BROKEN")
        return 1
    print(report.render())
    return 0 if report.verified() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
