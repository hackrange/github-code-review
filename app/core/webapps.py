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

from datetime import datetime, timezone

from app.core import tagging
from app.core.models import Repository

# The windows the page offers, in days.
WINDOWS = (7, 30, 90, 180, 365)


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
        key = name.casefold() if name else f"\0{repo.full_name}"
        app = apps.setdefault(key, {
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


def narrow(apps: list, search: str = "", within: int = 0) -> list:
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
