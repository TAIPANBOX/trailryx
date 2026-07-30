#!/usr/bin/env python3
r"""Oracle three: the scalars CPython read, in document order, canonically.

Reads the corpus TSV on stdin and writes `name<TAB>canonical` for every case
CPython accepts. Cases CPython rejects produce no row: this oracle answers "what
was in the document", and a document that did not parse has no answer.

The canonical form is the one `trailryx_json::validate::scalars` returns, one
line per scalar in document order:

    null
    true
    false
    num:<the producer's own digits>
    str:<the string, unescaped>
    name:<key>          immediately before each object member's value

Object and array boundaries are deliberately absent. What the format is for is
catching a *reordering* or a *rounding*, and a member name emitted next to its
value catches the first while the literal digits catch the second.

# Why parse_int and parse_float are hijacked

`json.loads("[1.000000000000000005]")` returns `1.0`, and comparing that against
a reader that kept the digits would compare CPython's rounding against ours
rather than the documents. So `parse_int`, `parse_float` and `parse_constant`
all return a `Num`, which is a `str` subclass holding the literal exactly as the
producer wrote it. `Num` subclasses `str` so nothing else has to change, and the
walk tests for `Num` before `str` so a number is never mistaken for a string.

`parse_constant` covers `NaN`, `Infinity` and `-Infinity`, which CPython accepts
and trailryx refuses. Those rows are emitted anyway, as `num:NaN` and friends,
because an oracle that quietly dropped the cases we diverge on would be hiding
the divergence rather than recording it.

# Escaping, and why the field can be compared byte for byte

A canonical document contains newlines by construction, and a string value can
contain a tab, a NUL or a newline of its own, so the field is escaped before it
reaches the TSV. Each scalar line is escaped on its own:

    backslash                 ->  \\
    any character below 0x20  ->  \xNN     (lowercase hex, so \n is \x0a)
    U+D800..U+DFFF            ->  \uNNNN   (lone surrogates, see below)

and the escaped lines are then joined by the two characters `\` and `n`. That
ordering matters: escaping a real newline as `\x0a` and using `\n` only as the
separator is what keeps one string containing a newline distinguishable from two
scalars, which the obvious escaping does not.

The surrogate rule exists because CPython will hand back a `str` holding a lone
surrogate (from `"\ud800"`), and that string cannot be encoded as UTF-8 at all.
Writing it raw would put invalid UTF-8 in the corpus output and take down any
reader of this file. trailryx refuses those documents outright, so the escape is
only ever exercised by rows nothing compares against.

Usage:  python3 cases.py | python3 values.py
"""

import json
import sys


class Num(str):
    """A number's literal text, kept out of `float`'s hands."""

    __slots__ = ()


class Obj:
    """An object as the ordered pairs it was written as.

    A `dict` would be wrong twice over: it drops one half of every duplicate
    member name, which is the case this crate refuses and therefore has to be
    able to see, and before 3.7 it would have lost the order too.
    """

    __slots__ = ("pairs",)

    def __init__(self, pairs: list[tuple[str, object]]) -> None:
        self.pairs = pairs


def scalars(doc: object) -> list[str]:
    """Every scalar in `doc`, in document order.

    Iterative over an explicit stack, not recursive. The corpus holds a hundred
    thousand nested arrays that CPython's parser accepts, and a recursive walk
    would raise `RecursionError` on a document that parsed cleanly, which reads
    as a broken oracle rather than as a deep document.
    """
    out: list[str] = []
    # Each entry is either ("emit", text) or ("walk", value).
    stack: list[tuple[str, object]] = [("walk", doc)]
    while stack:
        what, item = stack.pop()
        if what == "emit":
            out.append(str(item))
            continue
        if isinstance(item, Obj):
            todo: list[tuple[str, object]] = []
            for key, value in item.pairs:
                todo.append(("emit", "name:" + key))
                todo.append(("walk", value))
            stack.extend(reversed(todo))
        elif isinstance(item, list):
            stack.extend(reversed([("walk", e) for e in item]))
        elif isinstance(item, Num):
            out.append("num:" + str(item))
        elif isinstance(item, str):
            out.append("str:" + item)
        elif item is None:
            out.append("null")
        elif item is True:
            out.append("true")
        elif item is False:
            out.append("false")
        else:
            raise SystemExit(f"unexpected value of type {type(item).__name__}")
    return out


def escape(line: str) -> str:
    out: list[str] = []
    for ch in line:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append(f"\\x{code:02x}")
        elif 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def canonical(raw: bytes) -> str | None:
    """The canonical form, or `None` when CPython would not read the bytes."""
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            parse_int=Num,
            parse_float=Num,
            parse_constant=Num,
            object_pairs_hook=Obj,
        )
    except Exception:
        return None
    return "\\n".join(escape(line) for line in scalars(doc))


def main() -> None:
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        name, hexbytes = line.split("\t")[:2]
        text = canonical(bytes.fromhex(hexbytes))
        if text is not None:
            sys.stdout.write(f"{name}\t{text}\n")


if __name__ == "__main__":
    main()
