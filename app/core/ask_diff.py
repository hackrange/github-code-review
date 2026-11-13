"""What changed in the code behind a finding, as a diff.  Read only.

The findings table does not keep the code as it was: the snippet for most
code findings is the engine's placeholder.  The history does keep it.  Every
finding knows its file, its branch, the last scan that saw it and, once it
is gone, the scan that stopped seeing it.  So the branch as it stood at
those two moments can be compared, and the difference in that one file is
the change, whoever made it and however it was merged.

  fixed   the file at the last scan that saw it, against the file at the
          scan that marked it fixed.  That is the fix.
  open    the file when it was first found, against the file now.

A clone of the one branch's recent history, without file contents,, in memory where there is some, gone on
the way out.  Commit dates are read along the branch's own line of merges,
so a change made on a side branch weeks earlier and merged in between the
two scans still lands in the window.

Never for a credential: the diff would print the secret.  Secret looking
values are masked in everything else, and the result is never stored.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("gcr.ask.diff")

MAX_DIFFS = 3
MAX_LINES = 400
GIT_TIMEOUT = 60
# For every diff in one question together, so a large repository cannot hold
# the request open past what the load balancer in front will wait for.
TOTAL_SECONDS = 75

_BRANCH = re.compile(r"[A-Za-z0-9._/+-]{1,255}")
_REPO = re.compile(r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)+")


def _safe_branch(name: str) -> bool:
    return bool(name and _BRANCH.fullmatch(name) and not name.startswith("-")
                and ".." not in name and not name.endswith((".lock", "/")))


def _safe_path(path: str) -> bool:
    if not path or len(path) > 1024 or path.startswith(("/", "-")) or "\\" in path:
        return False
    if any(ord(ch) < 32 for ch in path):
        return False
    return ".." not in path.split("/")


def _utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _git(args: list, cwd: Path, cred: list, timeout: int = GIT_TIMEOUT,
         deadline: float = 0) -> tuple:
    """-> (ok, stdout, short error).  Never raises, never echoes a credential."""
    if deadline:
        left = deadline - time.monotonic()
        if left < 2:
            return False, "", "out of time for this question"
        timeout = min(timeout, left)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/false")
    try:
        done = subprocess.run(["git", "-C", str(cwd)] + cred + args,
                              capture_output=True, text=True, timeout=timeout,
                              env=env, errors="replace")
    except subprocess.TimeoutExpired:
        return False, "", "git took too long"
    if done.returncode != 0:
        from app.core.recheck import _explain_clone

        lines = (done.stderr or "").strip().splitlines()
        return False, "", _explain_clone(lines[-1] if lines else "git failed")[:300]
    return True, done.stdout, ""


def load(finding_ids: list) -> list:
    """The findings to diff, and how to reach each one's code.  SELECT only."""
    from app.core import connections as connection_store, scanner_config
    from app.core.db import read_only_session
    from app.core.models import Finding, FindingKind, Repository

    out = []
    with read_only_session(seconds=15) as db:
        rows = (db.query(Finding).filter(Finding.id.in_(list(finding_ids)[:MAX_DIFFS]))
                .all())
        order = {fid: i for i, fid in enumerate(finding_ids)}
        rows.sort(key=lambda r: order.get(r.id, 0))
        for f in rows:
            item = {"finding_id": f.id, "vuln_id": f.vuln_id,
                    "repository": f.repository, "file": f.file_path or "",
                    "line": f.line or 0, "title": (f.title or "")[:200],
                    "kind": getattr(f.kind, "value", str(f.kind)),
                    "state": getattr(f.state, "value", str(f.state)),
                    "branch": f.branch or "", "error": ""}
            if f.kind == FindingKind.CREDENTIAL:
                item["error"] = ("Not shown for a credential, because the diff "
                                 "would print the secret.")
                out.append(item)
                continue
            if f.package_name:
                item["package"] = "%s %s%s" % (
                    f.package_name, f.package_version or "",
                    (", fixed in " + f.fixed_in) if f.fixed_in else "")
            fixed = item["state"] == "fixed" and f.resolved_at is not None
            item["mode"] = "fixed" if fixed else "open"
            item["before_at"] = _utc(f.last_found_at if fixed else f.first_found_at)
            item["after_at"] = _utc(f.resolved_at) if fixed else None
            if not item["branch"]:
                repo = db.query(Repository).filter(
                    Repository.full_name == f.repository).one_or_none()
                item["branch"] = repo.default_branch if repo else ""
            connection = (connection_store.by_name(db, f.connection)
                          if f.connection else None)
            item["provider"] = getattr(connection, "provider", None) or "github"
            item["web"] = ((connection.web_url if connection is not None else None)
                           or "https://github.com").rstrip("/")
            item["token"] = scanner_config.scanner_env(
                db, {}, connection=connection).get("GHSCAN_TOKEN", "")
            out.append(item)
    return out


def _one(item: dict, work: Path, deadline: float = 0) -> None:
    """Fill item with diff, commits and window, or an error.  In place."""
    from app.core.code_reasoning import mask
    from app.core.recheck import _credential_args

    if not (_REPO.fullmatch(item["repository"] or "") and _safe_branch(item["branch"])
            and _safe_path(item["file"])):
        item["error"] = "The repository, branch or file name is not one this can fetch."
        return
    if not item["token"]:
        item["error"] = "There is no credential for that account."
        return
    if item["before_at"] is None:
        item["error"] = "There is no date to compare from."
        return

    token_file = work / "token"
    token_file.write_text(item["token"])
    token_file.chmod(0o600)
    cred = _credential_args(token_file, item["provider"])
    dest = work / "repo"
    try:
        # History back to a month before the earlier moment, without file
        # contents.  Enough for almost every finding, and bounded however old
        # and large the repository is.  Deepened once if it was not enough.
        def since(days):
            return (item["before_at"] - timedelta(days=days)).strftime("%Y-%m-%d")

        url = "%s/%s.git" % (item["web"], item["repository"])
        ok, _out, why = _git(["clone", "--quiet", "--filter=blob:none", "--no-checkout",
                              "--single-branch", "--branch=" + item["branch"],
                              "--no-tags", "--shallow-since=" + since(30), "--",
                              url, str(dest)], work, cred, deadline=deadline)
        quiet = False
        if not ok:
            # A branch with no commits in that month refuses a date limited
            # clone.  Then it has not moved since before the finding, which
            # one commit is enough to show.
            ok, _out, why = _git(["clone", "--quiet", "--filter=blob:none", "--no-checkout",
                                  "--single-branch", "--branch=" + item["branch"],
                                  "--no-tags", "--depth=1", "--", url, str(dest)],
                                 work, cred, deadline=deadline)
            quiet = ok
        if not ok:
            item["error"] = why or "The branch could not be fetched."
            return

        def commit_before(when):
            stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
            ok, out, _why = _git(["rev-list", "-1", "--first-parent",
                                  "--before=" + stamp, "HEAD"], dest, cred, deadline=deadline)
            return out.strip() if ok else ""

        if quiet:
            before = after = commit_before(item["before_at"])
        else:
            before = commit_before(item["before_at"])
            if not before:
                _git(["fetch", "--quiet", "--filter=blob:none", "--no-tags",
                      "--shallow-since=" + since(400), "origin"], dest, cred,
                     deadline=deadline)
                before = commit_before(item["before_at"])
            if item["after_at"]:
                after = commit_before(item["after_at"])
            else:
                ok, out, _why = _git(["rev-parse", "HEAD"], dest, cred, deadline=deadline)
                after = out.strip() if ok else ""
        if not before or not after:
            item["error"] = ("The branch has no commit from before %s within the "
                             "last year of its history, so there is nothing to "
                             "compare against." % item["before_at"].strftime("%Y-%m-%d"))
            return
        item["before_commit"], item["after_commit"] = before[:12], after[:12]
        if before == after:
            item["diff"] = ""
            item["note"] = "The branch did not move between those two moments."
            return

        ok, log_out, _why = _git(["log", "--no-color", "--format=%h %ad %an: %s",
                                  "--date=short", "%s..%s" % (before, after),
                                  "--", item["file"]], dest, cred, deadline=deadline)
        commits = [mask(line)[:200] for line in log_out.splitlines()[:20]] if ok else []
        ok, diff, why = _git(["diff", "--no-color", "--no-ext-diff", "--unified=5",
                              before, after, "--", item["file"]], dest, cred, deadline=deadline)
        if not ok:
            item["error"] = why or "The diff could not be read."
            return
        lines = diff.splitlines()
        item["commits"] = commits
        item["truncated"] = len(lines) > MAX_LINES
        item["diff"] = mask("\n".join(lines[:MAX_LINES]))
        if not lines:
            item["note"] = ("The file did not change between those two moments.  "
                            "The finding may have gone because of a change "
                            "somewhere else, or because the rule changed.")
    finally:
        token_file.unlink(missing_ok=True)


def diffs(finding_ids: list) -> list:
    """Up to MAX_DIFFS findings, each with its diff or a reason there is none."""
    from app.core.recheck import _slots, memory_dir

    ids = []
    for value in finding_ids:
        if isinstance(value, int) and not isinstance(value, bool) and value not in ids:
            ids.append(value)
        if len(ids) >= MAX_DIFFS:
            break
    if not ids:
        return []
    items = load(ids)
    if not _slots.acquire(timeout=10):
        for item in items:
            item.setdefault("error", "")
            item["error"] = item["error"] or "The server is busy reading code.  Ask again shortly."
        return [_public(i) for i in items]
    deadline = time.monotonic() + TOTAL_SECONDS
    try:
        for item in items:
            if item["error"]:
                continue
            if time.monotonic() > deadline - 5:
                item["error"] = "Out of time for this question.  Ask about this one on its own."
                continue
            with tempfile.TemporaryDirectory(prefix="gcr-diff-",
                                             dir=memory_dir() or None) as tmp:
                try:
                    _one(item, Path(tmp), deadline)
                except Exception:  # noqa: BLE001 - one bad repo is not the answer
                    log.exception("diff for finding %s failed", item["finding_id"])
                    item["error"] = "The diff could not be made."
    finally:
        _slots.release()
    return [_public(i) for i in items]


def _public(item: dict) -> dict:
    """Without the token, with dates as text."""
    out = {k: v for k, v in item.items() if k not in ("token", "web", "provider")}
    for key in ("before_at", "after_at"):
        value = out.get(key)
        out[key] = value.strftime("%Y-%m-%d %H:%M UTC") if isinstance(value, datetime) else ""
    out.setdefault("diff", "")
    out.setdefault("commits", [])
    out.setdefault("note", "")
    out["link"] = f"/findings/{item['finding_id']}"
    return out
