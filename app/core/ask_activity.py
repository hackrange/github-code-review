"""Recent commits in some repositories, by some people, with short diffs.

Read only, in both directions.  The database is read on the select only
session, and the repositories are read with the git commands on
ask_diff.READ_ONLY_GIT and nothing else: a clone of recent history without
file contents, in memory, gone on the way out.  Nothing here can push,
commit or change a branch.

The scope comes from the question: a query picks the repositories, and the
plan names the people, the number of days and, optionally, parts of a path.
Every branch is read, because a change somebody is working on usually lives
on a branch before it reaches the default one.  Merges are left out, since a
merge says who pressed the button rather than who wrote the change.

Findings that appeared in those repositories in the same window come along,
so a question about recent work can be answered with what the scanners
noticed as well.
"""

from __future__ import annotations

import logging
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("gcr.ask.activity")

MAX_REPOS = 6
MAX_COMMITS = 40          # across every repository
DIFF_LINES = 60           # per commit
TOTAL_DIFF_LINES = 1500
MAX_DAYS = 90
TOTAL_SECONDS = 80

_PERSON = re.compile(r"[\w .@'+-]{2,80}", re.UNICODE)
_PATH_PART = re.compile(r"[A-Za-z0-9._/ -]{1,120}")


def clean_spec(spec) -> dict:
    """The plan's activity settings, checked.  Anything odd is dropped."""
    spec = spec if isinstance(spec, dict) else {}
    authors = spec.get("authors") or []
    if isinstance(authors, str):
        authors = [authors]
    people = []
    for name in authors if isinstance(authors, list) else []:
        if isinstance(name, str) and _PERSON.fullmatch(name.strip()) \
                and name.strip() not in people:
            people.append(name.strip())
    try:
        days = int(spec.get("days") or 14)
    except (TypeError, ValueError):
        days = 14
    paths = []
    for part in spec.get("paths") or [] if isinstance(spec.get("paths"), list) else []:
        if isinstance(part, str) and _PATH_PART.fullmatch(part.strip()) and ".." not in part:
            paths.append(part.strip().lower())
    return {"authors": people[:6], "days": max(1, min(MAX_DAYS, days)),
            "paths": paths[:8]}


def _load(repo_ids: list) -> list:
    from app.core.ask_diff import reach
    from app.core.db import read_only_session
    from app.core.models import Repository

    out = []
    with read_only_session(seconds=15) as db:
        rows = db.query(Repository).filter(Repository.id.in_(repo_ids[:MAX_REPOS])).all()
        order = {rid: i for i, rid in enumerate(repo_ids)}
        rows.sort(key=lambda r: order.get(r.id, 0))
        for repo in rows:
            item = {"repo_id": repo.id, "repository": repo.full_name,
                    "default_branch": repo.default_branch or "",
                    "archived": bool(repo.archived), "commits": [], "error": ""}
            item.update(reach(db, repo.connection or ""))
            out.append(item)
    return out


def _findings(repo_names: list, since: datetime) -> list:
    """Findings first seen in these repositories inside the window.  SELECT only."""
    from app.core.db import read_only_session
    from app.core.models import Finding, FindingKind

    out = []
    with read_only_session(seconds=15) as db:
        rows = (db.query(Finding)
                .filter(Finding.repository.in_(repo_names),
                        Finding.first_found_at >= since)
                .order_by(Finding.risk_score.desc(), Finding.id.desc())
                .limit(60).all())
        for f in rows:
            level = f.custom_severity or f.severity
            out.append({
                "finding_id": f.id, "id": f.vuln_id, "repository": f.repository,
                "branch": f.branch or "",
                "severity": getattr(level, "value", str(level)),
                "kind": getattr(f.kind, "value", str(f.kind)),
                "state": "excepted" if f.excepted else getattr(f.state, "value", str(f.state)),
                "title": (f.title or "")[:200],
                "where": (f.file_path or f.manifest_path or "")[:300],
                "author": ("" if f.kind == FindingKind.CREDENTIAL and not f.author_name
                           else (f.author_name or f.author_login or "")),
                "first_found": f.first_found_at.strftime("%Y-%m-%d") if f.first_found_at else "",
            })
    return out


def _read_repo(item: dict, spec: dict, since: datetime, deadline: float,
               budget: dict) -> None:
    from app.core.ask_diff import _REPO, _git
    from app.core.code_reasoning import mask
    from app.core.recheck import _credential_args, memory_dir

    if not _REPO.fullmatch(item["repository"] or ""):
        item["error"] = "The repository name is not one this can fetch."
        return
    if not item["token"]:
        item["error"] = "There is no credential for that account."
        return

    with tempfile.TemporaryDirectory(prefix="gcr-activity-", dir=memory_dir() or None) as tmp:
        work = Path(tmp)
        token_file = work / "token"
        token_file.write_text(item["token"])
        token_file.chmod(0o600)
        cred = _credential_args(token_file, item["provider"])
        dest = work / "repo"
        try:
            stamp = (since - timedelta(days=1)).strftime("%Y-%m-%d")
            # A date limited clone takes one branch unless told otherwise,
            # and work in progress lives on the others.
            ok, _out, why = _git(["clone", "--quiet", "--filter=blob:none", "--no-checkout",
                                  "--no-single-branch", "--no-tags",
                                  "--shallow-since=" + stamp, "--",
                                  "%s/%s.git" % (item["web"], item["repository"]),
                                  str(dest)], work, cred, deadline=deadline)
            if not ok:
                # A repository nobody committed to in the window refuses a
                # date limited clone, which is itself the answer.
                if "shallow" in (why or "").lower() or "no commits" in (why or "").lower():
                    item["note"] = "No commits on any branch in the window."
                else:
                    item["error"] = why or "The repository could not be fetched."
                return
            args = ["log", "--remotes", "--no-merges", "--date=short",
                    "--since=" + since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "--regexp-ignore-case", "--fixed-strings",
                    "--format=%H%x1f%ad%x1f%an%x1f%ae%x1f%s%x1f%D"]
            # Fixed strings, so a name is matched as typed and never read as
            # a pattern.  Several names are OR'd by git.
            for person in spec["authors"]:
                args.append("--author=" + person)
            ok, out, why = _git(args, dest, cred, deadline=deadline)
            if not ok:
                item["error"] = why or "The history could not be read."
                return
            seen = set()
            for line in out.splitlines():
                parts = line.split("\x1f")
                if len(parts) < 6 or parts[0] in seen:
                    continue
                seen.add(parts[0])
                if budget["commits"] >= MAX_COMMITS:
                    item["more"] = True
                    break
                sha = parts[0]
                ok, files, _why = _git(["show", "--no-color", "--format=", "--name-status",
                                        sha], dest, cred, deadline=deadline)
                touched = [f for f in files.splitlines() if f.strip()][:40] if ok else []
                if spec["paths"] and not any(
                        p in f.lower() for p in spec["paths"] for f in touched):
                    continue
                commit = {"sha": sha[:12], "date": parts[1], "author": mask(parts[2])[:80],
                          "email": parts[3][:120], "subject": mask(parts[4])[:200],
                          "branches": ", ".join(
                              b.strip()[len("origin/"):] for b in parts[5].split(",")
                              if b.strip().startswith("origin/")
                              and b.strip() != "origin/HEAD")[:200],
                          "files": [mask(f)[:200] for f in touched], "diff": "",
                          "truncated": False}
                if budget["lines"] < TOTAL_DIFF_LINES:
                    ok, diff, _why = _git(["show", "--no-color", "--no-ext-diff", "--format=",
                                           "--unified=2", sha], dest, cred, deadline=deadline)
                    if ok:
                        lines = [l for l in diff.splitlines()
                                 if not l.startswith(("index ", "new file mode", "deleted file mode"))]
                        room = min(DIFF_LINES, TOTAL_DIFF_LINES - budget["lines"])
                        commit["truncated"] = len(lines) > room
                        commit["diff"] = mask("\n".join(lines[:room]))
                        budget["lines"] += min(len(lines), room)
                item["commits"].append(commit)
                budget["commits"] += 1
            if not item["commits"] and not item.get("note"):
                item["note"] = "No matching commits in the window."
        finally:
            token_file.unlink(missing_ok=True)


def activity(repo_ids: list, spec) -> dict:
    """-> {since, authors, days, paths, repositories: [...], findings: [...]}"""
    from app.core.recheck import _slots

    spec = clean_spec(spec)
    ids = [i for i in repo_ids if isinstance(i, int) and not isinstance(i, bool)]
    ids = list(dict.fromkeys(ids))[:MAX_REPOS]
    since = datetime.now(timezone.utc) - timedelta(days=spec["days"])
    result = {"since": since.strftime("%Y-%m-%d"), "days": spec["days"],
              "authors": spec["authors"], "paths": spec["paths"],
              "repositories": [], "findings": []}
    if not ids:
        return result
    repos = _load(ids)
    deadline = time.monotonic() + TOTAL_SECONDS
    budget = {"commits": 0, "lines": 0}
    if not _slots.acquire(timeout=10):
        for item in repos:
            item["error"] = "The server is busy reading code.  Ask again shortly."
    else:
        try:
            for item in repos:
                if time.monotonic() > deadline - 5:
                    item["error"] = "Out of time for this question.  Ask about fewer repositories."
                    continue
                try:
                    _read_repo(item, spec, since, deadline, budget)
                except Exception:  # noqa: BLE001 - one bad repository is not the answer
                    log.exception("activity for %s failed", item["repository"])
                    item["error"] = "The history could not be read."
        finally:
            _slots.release()
    for item in repos:
        for key in ("token", "web", "provider"):
            item.pop(key, None)
    result["repositories"] = repos
    result["findings"] = _findings([r["repository"] for r in repos], since)
    return result


def for_model(result: dict, send_code: bool) -> dict:
    slim = {k: result[k] for k in ("since", "days", "authors", "paths")}
    slim["repositories"] = []
    for repo in result["repositories"]:
        entry = {"repository": repo["repository"], "error": repo["error"],
                 "note": repo.get("note", ""), "more_commits": repo.get("more", False),
                 "commits": []}
        for c in repo["commits"]:
            row = {k: c[k] for k in ("sha", "date", "author", "subject", "branches", "files")}
            if send_code and c["diff"]:
                row["diff"] = c["diff"][:2500]
            entry["commits"].append(row)
        slim["repositories"].append(entry)
    slim["findings_in_window"] = result["findings"][:30]
    return slim
