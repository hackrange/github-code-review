"""Scan scope as a spreadsheet: Organization, Repository, Branch, VulnerabilityScanning.

The export is one row per branch with what that branch gets now, yes for the
full scan and no for credentials only.  The import reads the same columns
back and works out the smallest set of changes that makes it true.

A row with no branch is about the whole repository: no makes every branch,
new ones included, credentials only, and yes puts the repository back on the
full scan.  A blank VulnerabilityScanning means yes.

Credentials are scanned everywhere whatever this says.  A no only turns off
the dependency, code and configuration passes.

A row that already matches what the branch gets changes nothing, so an
export can be edited and handed straight back, and a branch's own setting is
never thrown away just because it happens to agree with the repository today.
When a row does need a change and the branch's own setting is what is in the
way, that setting is dropped rather than a second one written over it, which
keeps thousands of rows from turning into thousands of overrides.
"""
from __future__ import annotations

import csv
import io

from app.core import scan_scope
from app.core.reports import spreadsheet_row

COLUMNS = ["Organization", "Repository", "Branch", "VulnerabilityScanning"]
YES = {"", "yes", "y", "true", "1", "on", "null", "none"}
NO = {"no", "n", "false", "0", "off"}
MAX_ROWS = 100000


def export(session, repos) -> str:
    """Every branch of every repository given, and what it gets now."""
    rules = scan_scope.rules(session, [r.full_name for r in repos])
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    for repo in sorted(repos, key=lambda r: (r.organization or "", r.name or "")):
        rule = rules.get(repo.full_name) or scan_scope.Rule()
        names = set(scan_scope.known_branches(session, repo.full_name))
        names.update(rule.overrides)
        for name in sorted(names):
            writer.writerow(spreadsheet_row({
                "Organization": repo.organization or "",
                "Repository": repo.name or "",
                "Branch": name,
                "VulnerabilityScanning": "yes" if rule.full_scan(name)[0] else "no"}))
    return out.getvalue()


def _cell(value) -> str:
    """A cell as typed, without the apostrophe the export puts on risky ones."""
    text = (value or "").strip()
    if len(text) > 1 and text[0] == "'" and text[1] in "=+-@\t\r":
        text = text[1:]
    return text


def parse(text: str) -> tuple:
    """CSV text -> (rows, problems).  rows are dicts, problems are strings.

    The header is optional.  Without one the columns are taken in the order
    above, which is what somebody typing a few lines by hand will write.
    """
    rows, problems = [], []
    reader = csv.reader(io.StringIO(text))
    for number, cells in enumerate(reader, start=1):
        if number > MAX_ROWS:
            problems.append(f"Stopped at {MAX_ROWS} rows.")
            break
        if not cells or not any(c.strip() for c in cells):
            continue
        if number == 1 and [c.strip().lower() for c in cells[:2]] == [
                "organization", "repository"]:
            continue
        cells = [_cell(c) for c in cells] + ["", "", "", ""]
        org, name, branch, scan = cells[:4]
        if not org or not name:
            problems.append(f"Line {number}: needs an organization and a repository.")
            continue
        answer = scan.lower()
        if answer in YES:
            full = True
        elif answer in NO:
            full = False
        else:
            problems.append(f"Line {number}: VulnerabilityScanning is {scan!r}, "
                            "not yes, no or blank.")
            continue
        if " " in branch:
            problems.append(f"Line {number}: {branch!r} is not a branch name.")
            continue
        rows.append({"line": number, "repository": f"{org}/{name}",
                     "branch": branch, "full": full})
    return rows, problems


def plan(session, rows, allowed) -> tuple:
    """What has to change to make the rows true.  -> (changes, unknown, same).

    changes is {repository: [(branch, mode, patterns), ...]} in the shape
    scan_scope.apply_batch takes.  allowed is the set of repositories this
    person can see; anything else counts as unknown, the same as one that is
    not there.  A repository named twice with different answers for the same
    branch takes the last line, as a spreadsheet read top to bottom would.
    """
    wanted = {}
    unknown = []
    for row in rows:
        if row["repository"] not in allowed:
            unknown.append(row)
            continue
        wanted.setdefault(row["repository"], {})[row["branch"]] = row["full"]

    rules = scan_scope.rules(session, sorted(wanted))
    changes, same = {}, 0
    for repository, branches in sorted(wanted.items()):
        current = rules.get(repository) or scan_scope.Rule()
        after = scan_scope.Rule(current.mode, list(current.full),
                                dict(current.overrides))
        steps = []
        if "" in branches:
            mode = "all" if branches[""] else "credentials"
            if after.mode != mode:
                steps.append(("", mode, ""))
                after.mode, after.full = mode, []
            else:
                same += 1
        for branch, full in sorted(branches.items()):
            if not branch:
                continue
            if after.full_scan(branch)[0] == full:
                same += 1
                continue
            # It has to change.  If the branch's own setting is what is in
            # the way, dropping it is enough; otherwise it gets one.
            inherited = scan_scope.Rule(after.mode, after.full).full_scan(branch)[0]
            if full == inherited and branch in after.overrides:
                steps.append((branch, "inherit", ""))
            else:
                steps.append((branch, "full" if full else "credentials", ""))
        if steps:
            changes[repository] = steps
    return changes, unknown, same
