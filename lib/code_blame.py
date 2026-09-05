"""Who last touched the line a finding sits on.

semgrep says where a finding is.  git says who wrote that line and when, and
the clone is still on disk at this point in the scan, which is the only moment
the question is cheap to ask.  Secrets have carried this since the beginning
because the secrets pass walks commits anyway; code findings never have, so a
report could say a repository had eight hundred problems and nothing about who
to talk to.

Blame is the last person to touch the line.  That is not the same as the person
who introduced the problem, and this does not pretend otherwise: it is what git
can answer in one pass, and it is enough to route a finding to somebody who
knows the code.

One blame per file, not per finding.  A file with sixty findings would
otherwise cost sixty processes, and some repositories here have exactly that.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone

# git blame porcelain opens each group with "<sha> <orig> <final> [<count>]".
HEADER = re.compile(r"^([0-9a-f]{40}) \d+ (\d+)")

# A line that is not committed yet blames to all zeros.  There is no author to
# report and pretending otherwise would be worse than saying nothing.
UNCOMMITTED = "0" * 40

# git only repeats a commit's details the first time it sees it, so anything
# after that has to come from what we already read.
CARRIED = ("author", "author-mail", "committer-time", "author-time")

# argv has a limit and some files carry hundreds of findings.
BATCH = 150


def _run(root: str, path: str, lines: list) -> str:
    args = ["git", "-C", root, "blame", "--porcelain"]
    for number in lines:
        args += ["-L", f"{number},{number}"]
    args += ["--", path]
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout if done.returncode == 0 else ""


def _parse(text: str) -> dict:
    """-> {line number: {commit, author, mail, when}}"""
    known: dict = {}
    found: dict = {}
    rows = text.splitlines()
    index = 0
    while index < len(rows):
        header = HEADER.match(rows[index])
        if header is None:
            index += 1
            continue
        sha, final = header.group(1), int(header.group(2))
        index += 1
        details = dict(known.get(sha, {}))
        while index < len(rows) and not rows[index].startswith("\t"):
            key, _, value = rows[index].partition(" ")
            if key in CARRIED:
                details[key] = value
            index += 1
        # The content line itself, which we do not want.
        if index < len(rows) and rows[index].startswith("\t"):
            index += 1
        known[sha] = details
        found[final] = (sha, details)
    return found


def _stamp(details: dict) -> str:
    """The commit date as ISO 8601 UTC, or empty if git gave us nothing."""
    raw = details.get("committer-time") or details.get("author-time") or ""
    try:
        moment = datetime.fromtimestamp(int(raw), tz=timezone.utc)
    except (TypeError, ValueError):
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def blame(findings: list, repo_root: str) -> list:
    """Attach a blame block to every finding we can place in git history."""
    by_path: dict = {}
    for finding in findings:
        path = str(finding.get("path") or "").lstrip("./")
        line = (finding.get("start") or {}).get("line") or 0
        if path and line > 0:
            by_path.setdefault(path, []).append(finding)

    for path, rows in by_path.items():
        wanted = sorted({(r.get("start") or {}).get("line") for r in rows})
        placed: dict = {}
        for start in range(0, len(wanted), BATCH):
            placed.update(_parse(_run(repo_root, path, wanted[start:start + BATCH])))
        for finding in rows:
            hit = placed.get((finding.get("start") or {}).get("line"))
            if hit is None:
                continue
            sha, details = hit
            if sha == UNCOMMITTED:
                continue
            finding["blame"] = {
                "commit": sha,
                "author_name": details.get("author", ""),
                "author_email": details.get("author-mail", "").strip("<>"),
                "committed_at": _stamp(details),
            }
    return findings


def main() -> int:
    """Read a semgrep report, write it back with blame on every finding."""
    repo_root = sys.argv[2] if len(sys.argv) > 2 else "."
    raw = open(sys.argv[1]).read() if len(sys.argv) > 1 and sys.argv[1] != "-" \
        else sys.stdin.read()
    try:
        document = json.loads(raw or '{"results": []}')
    except ValueError:
        # A broken report must not take the scan down.
        sys.stderr.write("code_blame: unreadable semgrep output\n")
        sys.stdout.write(raw)
        return 0
    document["results"] = blame(document.get("results", []), repo_root)
    json.dump(document, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
