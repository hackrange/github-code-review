"""Repositories and branches nobody has touched lately.

A repository is stale when nothing landed in it for the number of days set on
the Notifications page, 180 by default: no push the host knows of, no commit
on its default branch, and no commit on any branch.  A branch is stale when
its newest commit is that old.

Branches are listed only in repositories that are not stale themselves.  A
stale repository's branches are stale by definition, and naming each one
would bury the few branches worth a look under thousands of rows.  The
repository row says how many branches it holds instead.

Branch dates come from the scanner, which reads them off the clone.  A
repository not scanned since this release has none yet, and the report says
how many those are rather than calling their branches fresh.

Written to the report folder with the other files, and mailed on the schedule
set on the Staleness tab of the Notifications page.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from app.core import settings_store as store

log = logging.getLogger("gcr.staleness")

DEFAULT_DAYS = 180
CSV_NAME = "staleness.csv"
JSON_NAME = "staleness.json"
COLUMNS = ["kind", "organization", "repository", "branch", "default_branch",
           "last_activity", "days_idle", "last_push", "last_default_commit",
           "branches", "archived", "application", "application_owner",
           "technical_owner", "url"]
# How many repositories the digest names before pointing at the attachment.
DIGEST_LINES = 40


def days(session) -> int:
    try:
        value = int(store.get(session, "notify.stale_days") or DEFAULT_DAYS)
    except (TypeError, ValueError):
        value = DEFAULT_DAYS
    return min(max(value, 1), 3650)


def _aware(value):
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _date(value) -> str:
    return value.strftime("%Y-%m-%d") if value else ""


def _branch_url(base: str, provider: str, branch: str) -> str:
    if not base:
        return ""
    middle = "/-/tree/" if provider == "gitlab" else "/tree/"
    return base.rstrip("/") + middle + quote(branch, safe="")


def find(session, limit_days: int = None, now: datetime = None,
         include_archived: bool = None) -> dict:
    """Everything stale as of now.  -> {days, cutoff, repositories, branches, ...}"""
    from app.core import tagging
    from app.core.models import Connection, Repository

    limit_days = limit_days or days(session)
    if include_archived is None:
        include_archived = bool(store.get(session, "notify.stale_include_archived"))
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=limit_days)
    repos = session.query(Repository).order_by(Repository.full_name).all()
    applies = tagging.effective_many(session, repos)
    providers = {c.id: (c.provider or "github") for c in session.query(Connection)}

    stale_repos, stale_branches = [], []
    active = unknown = undated = skipped_archived = 0
    for repo in repos:
        if repo.archived and not include_archived:
            skipped_archived += 1
            continue
        try:
            dates = json.loads(repo.branch_dates or "{}") or {}
        except ValueError:
            dates = {}
        branch_times = {name: datetime.fromtimestamp(int(ts), timezone.utc)
                        for name, ts in dates.items() if isinstance(ts, (int, float))}
        pushed = _aware(repo.pushed_at)
        default_commit = _aware(repo.default_committed_at)
        known = [t for t in [pushed, default_commit, *branch_times.values()] if t]
        if not known:
            # Nothing says when it last moved.  Not stale on no evidence.
            unknown += 1
            continue
        last = max(known)
        said = applies.get(repo.id) or {}
        base = {
            "organization": repo.organization,
            "repository": repo.full_name,
            "default_branch": repo.default_branch or "",
            "application": (said.get("application_name") or {}).get("value", ""),
            "application_owner": (said.get("application_owner") or {}).get("value", ""),
            "technical_owner": (said.get("technical_owner") or {}).get("value", ""),
            "archived": bool(repo.archived),
        }
        try:
            present = json.loads(repo.branch_names_present or "[]") or []
        except ValueError:
            present = []
        if last < cutoff:
            stale_repos.append(dict(
                base, kind="repository", branch="", last_activity=_date(last),
                days_idle=(now - last).days, last_push=_date(pushed),
                last_default_commit=_date(default_commit),
                branches=len(present) or len(branch_times), url=repo.html_url or ""))
            continue
        active += 1
        if not branch_times:
            undated += 1
            continue
        provider = providers.get(repo.connection_id, "github")
        for name, when in sorted(branch_times.items()):
            if name == repo.default_branch or when >= cutoff:
                continue
            stale_branches.append(dict(
                base, kind="branch", branch=name, last_activity=_date(when),
                days_idle=(now - when).days, last_push=_date(pushed),
                last_default_commit=_date(default_commit), branches="",
                url=_branch_url(repo.html_url or "", provider, name)))
    stale_repos.sort(key=lambda r: (-r["days_idle"], r["repository"]))
    stale_branches.sort(key=lambda r: (r["repository"], -r["days_idle"], r["branch"]))
    return {"days": limit_days, "cutoff": _date(cutoff),
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "include_archived": include_archived,
            "repositories": stale_repos, "branches": stale_branches,
            "counts": {"repositories": len(stale_repos), "branches": len(stale_branches),
                       "active_repositories": active, "no_dates": unknown,
                       "no_branch_dates": undated, "archived_left_out": skipped_archived}}


def csv_text(found: dict) -> str:
    from app.core.reports import _quote_formula

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(COLUMNS)
    for row in found["repositories"] + found["branches"]:
        writer.writerow([_quote_formula(str("yes" if c == "archived" and row[c] else
                                            "" if c == "archived" else row.get(c, "")))
                         for c in COLUMNS])
    return out.getvalue()


def write(session, reports_dir=None) -> dict:
    """staleness.csv and staleness.json in the report folder.  -> the counts"""
    from pathlib import Path

    from app.core.reports import _write_atomic, output_dir

    reports_dir = Path(reports_dir) if reports_dir else output_dir(session)
    found = find(session)
    _write_atomic(reports_dir / CSV_NAME, csv_text(found))
    _write_atomic(reports_dir / JSON_NAME, json.dumps(found, indent=2) + "\n")
    return found["counts"]


# ------------------------------------------------------------------ digest

def recipients(session) -> list:
    from app.core import notify

    own = notify._split(store.get(session, "notify.stale_to"))
    return own or notify.recipients(session)


class _When:
    """A schedule shaped the way external_schedule.next_run reads one."""

    def __init__(self, session):
        freq = str(store.get(session, "notify.stale_frequency") or "weekly")
        self.frequency = freq if freq in ("weekly", "monthly") else "weekly"
        self.time_of_day = str(store.get(session, "notify.stale_time") or "08:00")
        self.weekday = int(store.get(session, "notify.stale_weekday") or 0)
        self.day_of_month = int(store.get(session, "notify.stale_day") or 1)
        self.run_on = ""


def next_due(session, after: datetime = None):
    from app.core import external_schedule

    return external_schedule.next_run(_When(session), after or datetime.now(timezone.utc))


def describe_schedule(session) -> str:
    from app.core import external_schedule

    return external_schedule.describe(_When(session))


def message(found: dict) -> tuple:
    """-> (title, lines)"""
    c = found["counts"]
    title = (f"Staleness: {c['repositories']} repositor{'ies' if c['repositories'] != 1 else 'y'}"
             f" and {c['branches']} branch{'es' if c['branches'] != 1 else ''} with no commit"
             f" in {found['days']} days")
    lines = []
    by_org = {}
    for row in found["repositories"]:
        by_org[row["organization"]] = by_org.get(row["organization"], 0) + 1
    if by_org:
        lines.append("Stale repositories by organization: " + ", ".join(
            f"{org} {n}" for org, n in sorted(by_org.items(), key=lambda x: (-x[1], x[0]))))
    for row in found["repositories"][:DIGEST_LINES]:
        owner = row["technical_owner"] or row["application_owner"]
        lines.append(f"{row['repository']}: last commit {row['last_activity']}, "
                     f"{row['days_idle']} days ago" + (f", owner {owner}" if owner else ""))
    if len(found["repositories"]) > DIGEST_LINES:
        lines.append(f"and {len(found['repositories']) - DIGEST_LINES} more repositories")
    branch_repos = len({b["repository"] for b in found["branches"]})
    if found["branches"]:
        lines.append(f"{c['branches']} stale branches in {branch_repos} active "
                     f"repositor{'ies' if branch_repos != 1 else 'y'}.")
    if c["no_branch_dates"]:
        lines.append(f"{c['no_branch_dates']} active repositories have not been scanned since "
                     f"branch dates were recorded, so their branches are not in this yet.")
    lines.append("Every row is in the attached staleness.csv, and in the report files.")
    return title, lines


def send(session, found: dict = None) -> dict:
    """Mail the digest now.  -> {channel: sent}"""
    from app.core import notify

    found = found or find(session)
    to = recipients(session)
    if not to:
        return {}
    title, lines = message(found)
    stamp = found["generated_at"][:10]
    sheet = {"name": f"staleness-{stamp}.csv", "text": csv_text(found)}
    root = notify.base_url(session)
    link = f"{root}/reports" if root else ""
    body = notify.text_message(session, title, lines, None, link, "")
    html = (notify.html_message(session, title, lines, None, link, "")
            if notify.mail_format(session) == "html" else "")
    if (store.get(session, "notify.mail_transport") or "smtp").lower() == "graph":
        return {"microsoft 365": notify.send_graph(session, title, body, html, to, sheet)}
    return {"email": notify.send_email(session, title, body, html, to, sheet)}


def tick(now: datetime = None) -> dict:
    """The scheduler's check, every few minutes.  Sends when the digest is due."""
    from app.core.audit import record
    from app.core.db import session_scope

    now = now or datetime.now(timezone.utc)
    with session_scope() as db:
        if not store.get(db, "notify.stale_enabled"):
            return {}
        due_text = store.get(db, "notify.stale_next") or ""
        try:
            due = _aware(datetime.fromisoformat(due_text)) if due_text else None
        except ValueError:
            due = None
        if due is None:
            store.set_value(db, "notify.stale_next", next_due(db, now).isoformat(), "scheduler")
            return {"armed": True}
        if due > now:
            return {}
        try:
            found = find(db, now=now)
            sent = send(db, found)
        except Exception as exc:  # noqa: BLE001 - a background job must not take the scheduler down
            log.warning("staleness digest failed: %s", exc)
            sent, found = {}, {"counts": {}}
        ok = bool(sent) and all(sent.values())
        # Moved on either way, so a mail server that is down is tried again at
        # the next due time rather than every few minutes all day.
        store.set_value(db, "notify.stale_next", next_due(db, now).isoformat(), "scheduler")
        store.set_value(db, "notify.stale_last", {
            "at": now.isoformat(), "ok": ok, "counts": found.get("counts", {}),
            "sent": sent}, "scheduler")
        record(db, "notifications.staleness", actor="scheduler",
               detail="%s; %s" % (json.dumps(found.get("counts", {})),
                                  ", ".join(f"{k}: {'ok' if v else 'failed'}"
                                            for k, v in sorted(sent.items()))
                                  or "no recipients, nothing sent"),
               outcome="ok" if ok else "warn")
        return {"sent": sent}
