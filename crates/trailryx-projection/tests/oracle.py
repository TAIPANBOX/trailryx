"""Read a Trailryx projection with pyarrow and check every cell.

Deliberately not our code. The Parquet writer in this repository is
hand-written, and a hand-written encoder checked only by its author is an
encoder that is Parquet-shaped rather than Parquet. This script takes the file
and a table of what the writer believed it wrote, and makes somebody else's
reader settle the argument.

Usage: oracle.py <parquet file> <expected tsv>

The TSV is one line per cell: column, row, value, with a leading marker for a null
so a genuinely empty string stays distinguishable.

A list column's cell is the elements joined with commas, and the reader is required
to hand back an actual list for it rather than a string. That direction of the check
is the point: the columns used to be comma-joined strings, and a reader that returned
a string would now be reading a file whose schema says list. Comparing only the
rendered text would have passed either way.
"""

import sys
import pyarrow as pa
import pyarrow.parquet as pq

NULL = "\\0NULL"
LIST_MARKER = "\\0LIST"


def main() -> int:
    table = pq.read_table(sys.argv[1])
    expected = {}
    with open(sys.argv[2], encoding="utf-8") as handle:
        for line in handle:
            column, row, value = line.rstrip("\n").split("\t", 2)
            expected[(column, int(row))] = value

    columns = set(table.column_names)
    wanted = {c for c, _ in expected}
    if columns != wanted:
        print(f"columns differ: only in file {columns - wanted}, only expected {wanted - columns}")
        return 1

    checked = 0
    lists = 0
    for name in table.column_names:
        field = table.schema.field(name)
        values = table.column(name).to_pylist()
        is_list = pa.types.is_list(field.type) or pa.types.is_large_list(field.type)

        # A column the writer says is a list must arrive as one. This is the half of
        # the check that a text comparison cannot make.
        wants_list = any(
            expected[(name, row)].startswith(LIST_MARKER) for row in range(len(values))
        )
        if wants_list != is_list:
            print(
                f"{name}: the writer says {'a list' if wants_list else 'a scalar'} "
                f"and pyarrow read {field.type}"
            )
            return 1
        if is_list:
            lists += 1
            if not pa.types.is_string(field.type.value_type):
                print(f"{name}: list elements read as {field.type.value_type}, not string")
                return 1
            if field.type.value_field.nullable:
                print(f"{name}: list elements are nullable, and a validated token is not")
                return 1

        for row, actual in enumerate(values):
            want = expected[(name, row)]
            if is_list:
                if actual is None:
                    print(f"{name} row {row}: a list column must never be null")
                    return 1
                if any(e is None for e in actual):
                    print(f"{name} row {row}: a null element inside a list")
                    return 1
                got = LIST_MARKER + ",".join(actual)
            else:
                got = NULL if actual is None else str(actual)
            if got != want:
                print(f"{name} row {row}: file has {got!r}, writer meant {want!r}")
                return 1
            checked += 1

    print(
        f"pyarrow read {table.num_rows} rows, {len(table.column_names)} columns "
        f"({lists} of them lists), {checked} cells, all matching"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
