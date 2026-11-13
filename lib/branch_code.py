"""Fold the code findings from other branches into the default branch's.

The code pass reads the default branch, and then each other branch that
differs from it.  The same weakness on three branches is one problem, and the
app keys a code finding on repository, file, rule, the matched text and which
occurrence of it this is, with no branch in it.  Sent as three rows it would
not be one finding seen three times: the occurrence numbering would read the
copies as a second and third identical match in the file, and make two
findings that exist nowhere.

So rows are matched here the way the app will match them, and a match keeps
one row whose branches list every branch it was seen on.  A row only some
branch has is kept with that branch alone.  The normalization is the app's own
(app.core.ingest._normalize_match), copied rather than imported because the
scanner does not load the app.

Usage: branch_code.py <default rows JSON> <manifest JSON>
  manifest: [{"branch": name, "also": [names with the same tree], "rows": path}]
Prints the merged rows.
"""

from __future__ import annotations

import json
import re
import sys

_PADDING = re.compile(r"\s*([^\w\s])\s*")


def normalize(value) -> str:
    text = " ".join(str(value or "").split())
    return _PADDING.sub(r"\1", text)[:200]


def keyed(rows: list) -> list:
    """-> [(key, row)] with the occurrence counted the way ingest counts it."""
    seen, out = {}, []
    for row in sorted(rows, key=lambda r: (str(r.get("file") or ""),
                                           int(r.get("start_line") or 0))):
        base = (row.get("file") or "", row.get("rule_name") or row.get("rule") or "",
                normalize(row.get("matched")))
        n = seen.get(base, 0)
        seen[base] = n + 1
        out.append((base + (n,), row))
    return out


def merge(default_rows: list, manifest: list, load) -> list:
    merged = {}
    order = []
    for key, row in keyed(default_rows):
        merged[key] = row
        order.append(key)
    for entry in manifest:
        names = [entry["branch"]] + [b for b in entry.get("also") or [] if b != entry["branch"]]
        for key, row in keyed(load(entry["rows"])):
            if key in merged:
                have = merged[key].setdefault("branches", [])
                if not have and merged[key].get("branch"):
                    have.append(merged[key]["branch"])
                for name in names:
                    if name not in have:
                        have.append(name)
            else:
                row = dict(row)
                row["branch"] = entry["branch"]
                row["branches"] = list(names)
                merged[key] = row
                order.append(key)
    return [merged[k] for k in order]


def _load(path: str) -> list:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def main(argv) -> int:
    default_rows = _load(argv[1])
    try:
        with open(argv[2], encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError):
        manifest = []
    json.dump(merge(default_rows, manifest if isinstance(manifest, list) else [], _load),
              sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
