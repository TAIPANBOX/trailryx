"""Read a Trailryx projection with pyarrow and check every cell.

Deliberately not our code. The Parquet writer in this repository is
hand-written, and a hand-written encoder checked only by its author is an
encoder that is Parquet-shaped rather than Parquet. This script takes the file
and a table of what the writer believed it wrote, and makes somebody else's
reader settle the argument.

Usage: oracle.py <parquet file> <expected tsv>

The TSV is one line per cell: column, row, value, with an empty third field for
a null and a leading marker so a genuinely empty string stays distinguishable.
"""

import sys
import pyarrow.parquet as pq

NULL = "\\0NULL"


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
    for name in table.column_names:
        values = table.column(name).to_pylist()
        for row, actual in enumerate(values):
            want = expected[(name, row)]
            got = NULL if actual is None else str(actual)
            if got != want:
                print(f"{name} row {row}: file has {got!r}, writer meant {want!r}")
                return 1
            checked += 1

    print(f"pyarrow read {table.num_rows} rows, {len(table.column_names)} columns, {checked} cells, all matching")
    return 0


if __name__ == "__main__":
    sys.exit(main())
