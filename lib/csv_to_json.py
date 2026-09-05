"""Turn a CSV into a JSON array of objects. Used for the exclusions file.

Leading '#' lines are comments and are dropped before the header is read, so
the file can explain itself without confusing the parser.
"""
import csv
import json
import sys


def main(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        lines = [ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]

    rows = []
    for row in csv.DictReader(lines):
        if not any((v or "").strip() for v in row.values() if v is not None):
            continue
        rows.append({
            (k or "").strip(): (v or "").strip()
            for k, v in row.items() if k
        })
    json.dump(rows, sys.stdout)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: csv_to_json.py <file.csv>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
