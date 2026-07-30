#!/usr/bin/env node
// Oracle two: what node's JSON.parse does with each case.
//
// Reads the same corpus TSV on stdin (name, hex, verdict) and writes the same
// two columns as classify.py, so the two outputs can be joined on the name.
//
// The encoding check has to happen before JSON.parse ever sees the text, and
// this is the trap in writing this script: Buffer.prototype.toString("utf8") is
// LOSSY. It does not fail on invalid UTF-8, it substitutes U+FFFD, so
// `["\xc0\xaf"]` arrives at the parser as a perfectly well-formed document
// containing two replacement characters and JSON.parse accepts it. Reporting
// that as `accept` would be reporting on repaired bytes rather than on the bytes
// in the case, and the whole class of encoding divergences would vanish from the
// disagreement map. So the buffer is re-encoded and compared byte for byte
// first, and a mismatch is a reject on the grounds of the encoding.
//
// The two BOM-carrying UTF-16 and UTF-32 cases are valid UTF-8 byte sequences in
// their own right, so they survive the round-trip and reach JSON.parse, which
// refuses them for its own reasons. That is the honest answer for this oracle:
// node has no encoding sniffer, and pretending it had one would put our own
// policy into the oracle's column.
//
// Usage:  python3 cases.py | node classify.js

"use strict";

function isValidUtf8(buf) {
  const text = buf.toString("utf8");
  return Buffer.from(text, "utf8").equals(buf);
}

function verdict(buf) {
  if (!isValidUtf8(buf)) {
    return "reject";
  }
  try {
    JSON.parse(buf.toString("utf8"));
  } catch {
    // Includes the RangeError a deeply nested document raises when V8 runs out
    // of stack, which is a refusal and not a crash of this script.
    return "reject";
  }
  return "accept";
}

function main() {
  const stdin = require("fs").readFileSync(0, "utf8");
  const out = [];
  for (const line of stdin.split("\n")) {
    if (line === "") {
      continue;
    }
    const [name, hex] = line.split("\t");
    out.push(`${name}\t${verdict(Buffer.from(hex, "hex"))}`);
  }
  process.stdout.write(out.length ? out.join("\n") + "\n" : "");
}

main();
