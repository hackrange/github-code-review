"""Every web application, the repositories behind it, and when their code moved.

The question this answers is which sites may want another penetration test
because the code behind them changed since somebody last looked.  A test is a
point in time, and the code under a site keeps moving after it.

A web application here is whatever repositories were marked as part of one,
grouped by the application name that applies to them, their own or their
connection's.  A marked repository with no name is its own application, named
after itself, rather than being lumped in with every other unnamed one.

"Changed" is the newest commit on the default branch, as of the last scan that
read it.  It is not a deployment: nothing here can see what is running.  Until
a scan has read a repository, the host's last push is shown instead and says
so, because that moves for a push to any branch and claims less.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.core import tagging
from app.core.models import Repository, WebAppTest

# The windows the page offers, in days.
WINDOWS = (7, 30, 90, 180, 365)

TEST_KINDS = {"pentest": "Penetration test", "dast": "Dynamic scan (DAST)"}

# How far back the scanner reads commit times, and how many it keeps.  A test
# older than this, or a busier history, gives a floor rather than a count.
COMMIT_DAYS = 730
COMMIT_CAP = 1500


def app_key(name: str, full_name: str) -> str:
    """The key a test is recorded against: the application, or the repository."""
    name = (name or "").strip()
    return name.casefold() if name else "repo:" + (full_name or "").casefold()


def _times(repo) -> list | None:
    """The default branch's commit times, or None when no scan has read them."""
    raw = getattr(repo, "default_commit_times", "") or ""
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return [int(t) for t in value if isinstance(t, int)] if isinstance(value, list) else None


def _aware(value):
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def changed(repo, now=None) -> dict:
    """When this repository's code last moved, where that came from, how long ago.

    -> {"at", "source", "days"}.  source is "commit" for the default branch,
    "push" for the host's last push to anything, and "" when nobody knows.
    """
    now = now or datetime.now(timezone.utc)
    at, source = _aware(repo.default_committed_at), "commit"
    if at is None:
        at, source = _aware(repo.pushed_at), "push"
    if at is None:
        return {"at": None, "source": "", "days": None}
    return {"at": at, "source": source,
            "days": max(0, (now - at).days)}


def inventory(session, base=None, counts=None, now=None) -> list:
    """Every web application this person can see, most recently changed first.

    `base` is the query to start from, rbac.visible_repositories for anybody
    who does not see the whole estate.  `counts` maps a repository name to its
    open findings by severity, when the caller has them.
    """
    now = now or datetime.now(timezone.utc)
    query = base if base is not None else session.query(Repository)
    rows = (query.filter(Repository.web_app.is_(True))
            .order_by(Repository.full_name).all())
    applies = tagging.effective_many(session, rows)
    counts = counts or {}

    apps = {}
    for repo in rows:
        said = applies.get(repo.id, {})
        name = (said.get("application_name") or {}).get("value", "").strip()
        # Matched without case, so "Payments" and "payments" are one
        # application rather than two that each look half tested.
        key = app_key(name, repo.full_name)
        app = apps.setdefault(key, {
            "key": key,
            "name": name or repo.full_name, "named": bool(name),
            "urls": [], "repos": [], "owners": [], "technical": []})
        for url in tagging.web_urls(repo.web_app_urls)[0]:
            if url not in app["urls"]:
                app["urls"].append(url)
        for field, into in (("application_owner", "owners"),
                            ("technical_owner", "technical")):
            for one in tagging._owners(
                    (said.get(field) or {}).get("value", "")).split(", "):
                if one and one not in app[into]:
                    app[into].append(one)
        moved = changed(repo, now)
        app["repos"].append({
            "id": repo.id, "full_name": repo.full_name, "name": repo.name,
            "default_branch": repo.default_branch or "",
            "archived": bool(repo.archived),
            "changed_at": moved["at"], "source": moved["source"],
            "days": moved["days"],
            "commits_90d": repo.default_commits_90d,
            "commit_times": _times(repo),
            "last_scanned_at": _aware(repo.last_scanned_at),
            "open": counts.get(repo.full_name, {}),
        })

    out = []
    for app in apps.values():
        # Newest change first inside an application too, so the repository
        # that moved is the one read first.
        app["repos"].sort(key=lambda r: (r["days"] is None,
                                         r["days"] if r["days"] is not None else 0,
                                         r["full_name"]))
        known = [r["days"] for r in app["repos"] if r["days"] is not None]
        app["days"] = min(known) if known else None
        # Whether that newest change is a commit on a default branch or only
        # a push somewhere, for the application's own line.
        newest = app["repos"][0]
        app["source"] = newest["source"] if app["days"] is not None else ""
        app["changed_at"] = newest["changed_at"] if app["days"] is not None else None
        out.append(app)
    out.sort(key=lambda a: (a["days"] is None,
                            a["days"] if a["days"] is not None else 0,
                            a["name"].casefold()))
    return out


def tests_by_key(session) -> dict:
    """Every recorded test, newest first, by application key."""
    out = {}
    for row in (session.query(WebAppTest)
                .order_by(WebAppTest.tested_at.desc(), WebAppTest.id.desc())):
        out.setdefault(row.app_key, []).append({
            "id": row.id, "kind": row.kind,
            "kind_name": TEST_KINDS.get(row.kind, row.kind),
            "tested_at": _aware(row.tested_at), "tested_by": row.tested_by or "",
            "report_ref": row.report_ref or "", "note": row.note or "",
            "recorded_by": row.recorded_by or "",
            "recorded_at": _aware(row.recorded_at)})
    return out


def since(repo: dict, when) -> dict:
    """What changed in one repository after a date.  -> {"changed", "commits", "exact"}.

    changed is True, False, or None when nothing is known.  commits is a
    count, or None when no scan has read the commit times yet; exact is
    False when the test is older than what was read, so the count is a floor.
    """
    if repo["changed_at"] is None:
        return {"changed": None, "commits": None, "exact": False}
    changed = repo["changed_at"] > when
    times = repo.get("commit_times")
    if times is None:
        return {"changed": changed, "commits": None, "exact": False}
    stamp = when.timestamp()
    count = sum(1 for t in times if t > stamp)
    window_start = datetime.now(timezone.utc).timestamp() - COMMIT_DAYS * 86400
    exact = stamp >= window_start and len(times) < COMMIT_CAP
    return {"changed": changed or count > 0, "commits": count, "exact": exact}


def judge(apps: list, tests: dict, max_age_days: int = 0, now=None) -> list:
    """Say for each application whether it is due for another test, and why.

    Due when it was never tested, when the code behind it changed since its
    last test, or when that test is older than max_age_days (0 for no limit).
    Archived repositories are left out: their code is not shipping.  A
    commit is not a deployment, so this says the code changed, not that the
    site did.
    """
    now = now or datetime.now(timezone.utc)
    for app in apps:
        history = tests.get(app["key"], [])
        app["tests"] = history
        last = history[0] if history else None
        app["last_test"] = last
        live = [r for r in app["repos"] if not r["archived"]]
        reasons, commits, exact, changed = [], 0, True, False
        if last is None:
            status = "never"
            reasons.append("never tested")
        else:
            unknown = False
            for repo in live:
                moved = since(repo, last["tested_at"])
                repo["since_test"] = moved
                if moved["changed"]:
                    changed = True
                if moved["commits"] is None:
                    if moved["changed"]:
                        exact = False
                    elif moved["changed"] is None:
                        unknown = True
                else:
                    commits += moved["commits"]
                    exact = exact and moved["exact"]
            if changed:
                if commits:
                    reasons.append(f"{commits}{'' if exact else '+'} change"
                                   f"{'' if commits == 1 else 's'} since the last test")
                else:
                    reasons.append("code changed since the last test")
            age = (now - last["tested_at"]).days
            if max_age_days and age > max_age_days:
                reasons.append(f"tested {age} days ago, more than the "
                               f"{max_age_days} allowed")
            status = "due" if reasons else "current"
            if status == "current" and unknown:
                reasons.append("some code has not been read since the test")
        app["due"] = {"status": status, "is_due": status in ("never", "due"),
                      "reasons": reasons, "commits": commits if last else None,
                      "exact": exact, "changed": changed}
    return apps


def narrow(apps: list, search: str = "", within: int = 0,
           due_only: bool = False) -> list:
    """The applications a search and a window leave.

    A search matches the application, any of its addresses, owners or
    repositories.  A window keeps an application when any repository behind
    it changed inside it, which is the whole point: one busy repository is
    enough to make a site worth looking at again.
    """
    needle = (search or "").strip().casefold()
    kept = []
    for app in apps:
        if within and (app["days"] is None or app["days"] > within):
            continue
        if due_only and not (app.get("due") or {}).get("is_due"):
            continue
        if needle:
            hay = " ".join([app["name"], *app["urls"], *app["owners"],
                            *app["technical"],
                            *[r["full_name"] for r in app["repos"]]]).casefold()
            if needle not in hay:
                continue
        kept.append(app)
    return kept


def summary(apps: list) -> dict:
    """The numbers across the top of the page, over what is shown."""
    return {
        "applications": len(apps),
        "repositories": sum(len(a["repos"]) for a in apps),
        "week": sum(1 for a in apps if a["days"] is not None and a["days"] <= 7),
        "month": sum(1 for a in apps if a["days"] is not None and a["days"] <= 30),
        "quarter": sum(1 for a in apps if a["days"] is not None and a["days"] <= 90),
        "unknown": sum(1 for a in apps if a["days"] is None),
        "due": sum(1 for a in apps if (a.get("due") or {}).get("is_due")),
        "never": sum(1 for a in apps
                     if (a.get("due") or {}).get("status") == "never"),
    }


def for_repository(session, repo, now=None) -> dict:
    """The web application one repository is part of.  -> {} when it is none.

    For the security report and the diagram.  `urls` are this repository's
    own addresses, since those are what its code answers on.  `others` are
    the rest of the application, so a report on one part says what else the
    same site is made of.
    """
    if repo is None or not getattr(repo, "web_app", False):
        return {}
    for app in inventory(session, now=now):
        mine = next((r for r in app["repos"] if r["id"] == repo.id), None)
        if mine is None:
            continue
        return {
            "name": app["name"], "named": app["named"],
            "urls": tagging.web_urls(repo.web_app_urls)[0],
            "all_urls": app["urls"],
            "owners": app["owners"], "technical": app["technical"],
            "days": mine["days"], "source": mine["source"],
            "changed_at": (mine["changed_at"].strftime("%Y-%m-%d")
                           if mine["changed_at"] else ""),
            "commits_90d": mine["commits_90d"],
            "others": [{"repository": r["full_name"], "days": r["days"],
                        "source": r["source"]}
                       for r in app["repos"] if r["id"] != repo.id],
        }
    return {}


def hosts(urls: list) -> list:
    """The hosts a list of addresses is served from.  -> [(host, scheme, urls)]

    One per host and port, in the order first seen, so production and staging
    on two names are two web servers and two paths on one name are one.
    """
    from urllib.parse import urlparse

    out = {}
    for url in urls or []:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        if not host:
            continue
        entry = out.setdefault(host, [host, parsed.scheme, []])
        if url not in entry[2]:
            entry[2].append(url)
    return [tuple(v) for v in out.values()]


# ------------------------------------------------------------------ tests

TEST_COLUMNS = ["application", "kind", "tested_at", "tested_by", "report", "note"]
MAX_TEST_ROWS = 5000


def kind_of(value: str) -> str:
    """dast or pentest, from what somebody typed, or empty."""
    text = (value or "").strip().casefold().replace(" ", "").replace("-", "")
    if text in ("dast", "dynamic", "dynamicscan", "dynamicscan(dast)", "scan"):
        return "dast"
    if text in ("pentest", "pen", "penetrationtest", "webpentest", "pt"):
        return "pentest"
    return ""


def date_of(value: str, now=None):
    """A test date: YYYY-MM-DD, not in the future.  -> datetime or None."""
    now = now or datetime.now(timezone.utc)
    try:
        when = datetime.strptime((value or "").strip()[:10], "%Y-%m-%d")
    except ValueError:
        return None
    when = when.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
    # The end of the day it was tested, so a commit that afternoon is not
    # counted as a change since.  Tomorrow is too far.
    if when.date() > now.date():
        return None
    return when


def find_app(apps: list, name: str):
    """The application a name means: its own name, or a repository behind it."""
    needle = (name or "").strip().casefold()
    if not needle:
        return None
    for app in apps:
        if app["name"].casefold() == needle or app["key"] == needle:
            return app
    for app in apps:
        if any(r["full_name"].casefold() == needle for r in app["repos"]):
            return app
    return None


def record_test(session, app: dict, kind: str, when, tested_by: str = "",
                report_ref: str = "", note: str = "", actor: str = ""):
    """Keep one test.  The same application, kind and day twice is one test."""
    from app.core.models import utcnow

    row = (session.query(WebAppTest)
           .filter(WebAppTest.app_key == app["key"])
           .filter(WebAppTest.kind == kind)
           .filter(WebAppTest.tested_at == when).one_or_none())
    if row is None:
        row = WebAppTest(app_key=app["key"], kind=kind, tested_at=when)
        session.add(row)
    row.app_name = app["name"][:320]
    row.tested_by = (tested_by or "")[:200]
    row.report_ref = (report_ref or "")[:500]
    row.note = (note or "")[:4000]
    row.recorded_by = (actor or "")[:120]
    row.recorded_at = utcnow()
    session.flush()
    return row


def import_tests(session, text: str, apps: list, actor: str = "") -> dict:
    """Tests from a spreadsheet: application, kind, tested_at, tested_by, report, note.

    The application is its name or any repository behind it.  A row that names
    nothing known, a kind that is neither, or a date that is not one is skipped
    and named, rather than guessed at.
    """
    import csv
    import io

    reader = csv.DictReader(io.StringIO(text))
    fields = [f.strip().casefold() for f in (reader.fieldnames or [])]
    if "application" not in fields or "tested_at" not in fields:
        return {"saved": 0, "problems": ["The file needs application and "
                                         "tested_at columns."]}
    saved, problems = 0, []
    for number, raw in enumerate(reader, start=2):
        if number - 1 > MAX_TEST_ROWS:
            problems.append(f"Stopped after {MAX_TEST_ROWS} rows.")
            break
        row = {(k or "").strip().casefold(): tagging._unquote((v or "").strip())
               for k, v in raw.items()}
        if not any(row.values()):
            continue
        app = find_app(apps, row.get("application", ""))
        if app is None:
            problems.append(f"Row {number}: no web application called "
                            f"{row.get('application', '')[:80]!r}.")
            continue
        kind = kind_of(row.get("kind") or "pentest")
        if not kind:
            problems.append(f"Row {number}: kind has to be pentest or dast.")
            continue
        when = date_of(row.get("tested_at", ""))
        if when is None:
            problems.append(f"Row {number}: tested_at has to be a date such as "
                            f"2026-03-31, and not in the future.")
            continue
        record_test(session, app, kind, when, row.get("tested_by", ""),
                    row.get("report", ""), row.get("note", ""), actor)
        saved += 1
    return {"saved": saved, "problems": problems}
