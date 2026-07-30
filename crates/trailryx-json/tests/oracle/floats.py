#!/usr/bin/env python3
"""Oracle four: the exact bits CPython's strtod produces for a float literal.

Reads one literal per line on stdin, writes `literal<TAB>hexbits`, where the bits
are the IEEE 754 binary64 encoding in big-endian order, sixteen hex digits.

This is the only oracle that compares a *value* rather than a verdict, and it
exists because "the number parsed" is not a claim anyone can check by eye.
`1.000000000000000005` and `1.0` print the same at seventeen significant digits
and differ in no bit at all, while `2.2250738585072011e-308` and its neighbour
differ in one bit and print differently in every language. Comparing the bits
compares what actually happened.

Big-endian on purpose: the bytes then read in the same order as the sign,
exponent and mantissa fields, so a wrong exponent is visible in the first four
hex digits without decoding anything.

A literal `float()` cannot read is a hard failure rather than a skipped line.
The input to this script is a list of literals somebody chose, so a literal that
does not convert means the list is wrong, and emitting fifteen good rows and
silently dropping the sixteenth is how a rounding bug survives a test suite.

Usage:  printf '1e999\n-0\n0.1\n' | python3 floats.py
"""

import struct
import sys


def main() -> None:
    for raw in sys.stdin:
        literal = raw.strip()
        if not literal:
            continue
        try:
            value = float(literal)
        except ValueError as e:
            raise SystemExit(f"not a float literal: {literal!r} ({e})") from e
        bits = struct.pack(">d", value).hex()
        sys.stdout.write(f"{literal}\t{bits}\n")


if __name__ == "__main__":
    main()
