#!/usr/bin/env python3
"""Which findings a change added, given a review of its base and its head.

lib/gate.sh reviews the files a change touched twice: as they were at the
merge base, and as they are at the head.  This works out which head findings
the base already had, so a pull request is only ever held up by its own work.

Fingerprints cannot answer that on their own.  For code and IaC findings they
include the start line (see fingerprint_for in lib/sarif.py), so one line added
near the top of a file gives every finding under it a new fingerprint.  A gate
matching on fingerprints would block on code that only moved, and would do it
on the first PR anybody opened.

So the diff does the work.  git diff -U0 says exactly which base lines were
removed and where every other base line ended up.  A base finding is moved to
its new line, and a head finding with the same kind, rule and file on that
line is the same finding.  A credential is matched on its secret fingerprint
instead, which is a hash of the value and has no line in it, so a key moved to
another file is still the old key.

What comes out is the head review with three things added to every finding:
new, whether this change introduced it; on_changed_line, whether it sits on a
line the change wrote; and introduced_in, "tree" for the head files and
"history" for a credential that only ever existed in one of the commits.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# git's C style quoting, which it uses for any path with a space, a quote or a
# byte outside ASCII.  Getting one of these wrong files every hunk under the
# wrong name, and the whole file then looks new.
_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13,
            '"': 34, "\\": 92}


def unquote(path: str) -> str:
    if not (len(path) >= 2 and path[0] == '"' and path[-1] == '"'):
        return path
    body, out, i = path[1:-1], bytearray(), 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
            continue
        nxt = body[i + 1:i + 2]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
        elif re.match(r"[0-7]{3}", body[i + 1:i + 4]):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            out += b"\\"
            i += 1
    return out.decode("utf-8", "replace")


def _side(path: str, prefix: str):
    path = unquote(path.strip())
    if path == "/dev/null":
        return None
    return path[len(prefix):] if path.startswith(prefix) else path


class FileDiff:
    """The hunks of one file, and what they say about its lines."""

    def __init__(self):
        # (base_start, base_count, head_start, head_count), in order.
        self.hunks = []

    def changed_head_lines(self) -> set:
        lines = set()
        for _, _, c, d in self.hunks:
            lines.update(range(c, c + d))
        return lines

    def map_line(self, line: int):
        """(head line, None) for a base line that survived, or (None, hunk)
        for one the change removed or rewrote."""
        offset = 0
        for index, (a, b, c, d) in enumerate(self.hunks):
            if b == 0:
                # Pure insertion: -a,0 means the new lines go after base line
                # a, so a itself and everything above it stay put.
                if line <= a:
                    break
                offset += d
                continue
            if line < a:
                break
            if line < a + b:
                return None, index
            offset += d - b
        return line + offset, None

    def hunk_of_head_line(self, line: int):
        for index, (_, _, c, d) in enumerate(self.hunks):
            if c <= line < c + d:
                return index
        return None


def parse_diff(text: str) -> dict:
    """head path -> FileDiff, for every file the diff names."""
    files, current, old, new = {}, None, None, None
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current, old, new = None, None, None
            continue
        if raw.startswith("rename from "):
            old = unquote(raw[len("rename from "):])
            continue
        if raw.startswith("rename to "):
            new = unquote(raw[len("rename to "):])
            # A rename with no content change has no --- or +++ lines, and
            # its lines all map to themselves.
            current = files.setdefault(new, FileDiff())
            continue
        if raw.startswith("--- "):
            old = _side(raw[4:], "a/")
            continue
        if raw.startswith("+++ "):
            new = _side(raw[4:], "b/")
            current = files.setdefault(new, FileDiff()) if new else None
            continue
        match = HUNK.match(raw)
        if match and current is not None:
            a, b, c, d = match.groups()
            current.hunks.append((int(a), 1 if b is None else int(b),
                                  int(c), 1 if d is None else int(d)))
    return files


def relative(path: str, *roots: str) -> str:
    path = path or ""
    for root in roots:
        if root and path.startswith(root.rstrip("/") + "/"):
            return path[len(root.rstrip("/")) + 1:]
    return path


def _load(path: str) -> dict:
    with open(path) as handle:
        return json.load(handle)


def _advisories(f: dict) -> set:
    return {a for a in [f.get("rule"), f.get("id")] + list(f.get("aliases") or []) if a}


def _package(f: dict) -> tuple:
    package = f.get("package") or {}
    return ((package.get("name") or "").lower(), (package.get("type") or "").lower())


def compare_deps(head_deps: list, base_deps: list) -> list:
    """A dependency finding is new when the base did not have that advisory
    against that package at any version.

    The version is left out on purpose.  An upgrade that is still vulnerable
    to the same advisory is not this change's problem, and blocking it would
    punish somebody for moving in the right direction.  Advisories are
    compared with their aliases, because grype names a flaw by its GHSA id
    and osv-scanner by its CVE, and either may answer on either side.
    """
    index = {}
    for f in base_deps:
        index.setdefault(_package(f), []).append(_advisories(f))
    out = []
    for f in head_deps:
        f = dict(f)
        f["kind"] = "dependency"
        f["introduced_in"] = "tree"
        f["on_changed_line"] = None
        mine = _advisories(f)
        f["new"] = not any(mine & theirs for theirs in index.get(_package(f), ()))
        out.append(f)
    return out


def compare(head: dict, base: dict, history: dict, diff_text: str,
            renames: dict, head_root: str = "", base_root: str = "",
            repo_root: str = "") -> list:
    files = parse_diff(diff_text)
    # renames is new -> old.  The base findings are filed under their old
    # names, and are compared under the new ones.
    to_head = {old: new for new, old in renames.items()}

    head_findings = [dict(f) for f in head.get("findings") or []]
    for f in head_findings:
        f["file"] = relative(f.get("file"), head_root, repo_root)
    base_findings = [dict(f) for f in base.get("findings") or []]
    for f in base_findings:
        f["file"] = to_head.get(relative(f.get("file"), base_root, repo_root),
                                relative(f.get("file"), base_root, repo_root))

    base_secrets = {f.get("fingerprint") for f in base_findings
                    if f.get("kind") == "credential" and f.get("fingerprint")}

    # Where every base finding is now, or which hunk took it away.
    at_line, in_hunk, by_resource = {}, {}, {}
    for index, f in enumerate(base_findings):
        key = (f.get("kind"), f.get("rule"), f.get("file"))
        if f.get("kind") == "misconfiguration" and f.get("resource"):
            by_resource.setdefault(key + (f.get("resource"),), []).append(index)
        fd = files.get(f.get("file"))
        line = int(f.get("line") or 0)
        moved, hunk = (fd.map_line(line) if fd else (line, None))
        if moved is not None:
            at_line.setdefault(key + (moved,), []).append(index)
        else:
            in_hunk.setdefault(key + (hunk,), []).append(index)

    used = set()

    def take(bucket):
        for index in bucket or ():
            if index not in used:
                used.add(index)
                return True
        return False

    out = []
    pending = []
    for f in head_findings:
        fd = files.get(f.get("file"))
        line = int(f.get("line") or 0)
        if fd is not None:
            f["on_changed_line"] = line in fd.changed_head_lines()
        else:
            # Not in the diff at all means a file git could not diff line by
            # line.  Saying "changed" is the safe answer, as it is in the
            # editor: hiding a finding on a failed lookup is the wrong way to
            # be wrong.
            f["on_changed_line"] = True
        f["introduced_in"] = "tree"
        key = (f.get("kind"), f.get("rule"), f.get("file"))

        if f.get("kind") == "credential" and f.get("fingerprint"):
            f["new"] = f["fingerprint"] not in base_secrets
        elif f.get("kind") == "misconfiguration" and f.get("resource"):
            f["new"] = not take(by_resource.get(key + (f.get("resource"),)))
        else:
            f["new"] = not take(at_line.get(key + (line,)))
            if f["new"] and fd is not None:
                pending.append((f, key, fd.hunk_of_head_line(line)))
        out.append(f)

    # Second pass.  A finding on a line the change rewrote, with the same
    # rule in the same file on a line that hunk removed, is the old finding
    # edited rather than a new one: an import reordered, a string reworded.
    # Only within one hunk, so a new instance somewhere else still counts.
    for f, key, hunk in pending:
        if hunk is not None and take(in_hunk.get(key + (hunk,))):
            f["new"] = False

    # Credentials from the commits.  The ones still in the head tree are
    # already above, so only the ones somebody added and then took out again
    # are left.  Those were pushed, so they still count.
    seen = {f.get("fingerprint") for f in out
            if f.get("kind") == "credential" and f.get("fingerprint")}
    for f in history.get("findings") or []:
        fp = f.get("fingerprint")
        if not fp or fp in seen:
            continue
        seen.add(fp)
        f = dict(f)
        f["file"] = relative(f.get("file"), repo_root)
        f["introduced_in"] = "history"
        f["on_changed_line"] = None
        f["new"] = fp not in base_secrets
        out.append(f)
    return out


def counts(findings: list) -> dict:
    def tally(rows):
        result = {"total": len(rows)}
        for kind in ("credential", "code", "misconfiguration", "dependency"):
            result[kind] = sum(1 for f in rows if f.get("kind") == kind)
        return result
    added = [f for f in findings if f.get("new")]
    return {"all": tally(findings), "new": tally(added),
            "existing": len(findings) - len(added)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--history", required=True)
    parser.add_argument("--diff", required=True)
    parser.add_argument("--renames", required=True)
    parser.add_argument("--head-deps", default="")
    parser.add_argument("--base-deps", default="")
    parser.add_argument("--head-root", default="")
    parser.add_argument("--base-root", default="")
    parser.add_argument("--repo-root", default="")
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--head-ref", default="")
    parser.add_argument("--merge-base", default="")
    args = parser.parse_args()

    head = _load(args.head)
    with open(args.diff, encoding="utf-8", errors="replace") as handle:
        diff_text = handle.read()
    findings = compare(head, _load(args.base), _load(args.history), diff_text,
                       _load(args.renames), args.head_root, args.base_root,
                       args.repo_root)
    if args.head_deps:
        findings += compare_deps(_load(args.head_deps),
                                 _load(args.base_deps) if args.base_deps else [])
    doc = {
        "generator": head.get("generator"),
        "reviewed": args.repo_root,
        "base": args.base_ref,
        "head": args.head_ref,
        "merge_base": args.merge_base,
        "findings": findings,
        "counts": counts(findings),
    }
    json.dump(doc, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
