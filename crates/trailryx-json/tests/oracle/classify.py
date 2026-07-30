#!/usr/bin/env python3
"""Oracle one: what CPython's `json` module does with each case.

Reads the corpus TSV on stdin (name, hex, verdict) and writes `name<TAB>accept`
or `name<TAB>reject` for every row.

`json.loads` takes text, not bytes, when it is asked a question about encoding,
so the hex is decoded to bytes and then `bytes.decode("utf-8")` is called inside
the same `try` as the parse. That ordering is the whole point of the script: a
case whose bytes are not UTF-8 has to come back as `reject`, and if the decode
were outside the `try` the script would die on the first overlong sequence and
report nothing for the two hundred cases behind it.

The exception net is deliberately `Exception` and not `json.JSONDecodeError`.
CPython's C scanner recurses per container, so a deeply nested document raises
`RecursionError`, and a very long integer literal raises `ValueError` from the
4300-digit conversion limit added in 3.11. Both are refusals; catching only
`JSONDecodeError` would turn them into a crashed run.

Usage:  python3 cases.py | python3 classify.py
"""

import json
import sys


def verdict(raw: bytes) -> str:
    try:
        json.loads(raw.decode("utf-8"))
    except Exception:
        return "reject"
    return "accept"


def main() -> None:
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        name, hexbytes = line.split("\t")[:2]
        sys.stdout.write(f"{name}\t{verdict(bytes.fromhex(hexbytes))}\n")


if __name__ == "__main__":
    main()
