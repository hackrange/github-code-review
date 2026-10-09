"""Which repositories recorded here a connection's token can no longer see.

Signing in proves the token works.  It says nothing about what the token can
read, and GitHub answers a private repository the token lost access to exactly
as it answers one that never existed: not found.  The scanner never sees it in
a listing, so it is not walked, and its findings stay frozen at the last scan
with nothing on any page saying so.  This is the check that says so.

GitHub tokens only.  A GitHub App mints its own short lived token per run, and
the other providers have their own idea of visibility.
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from sqlalchemy import select

from app.core.db import session_scope

log = logging.getLogger("gcr.reach")

TIMEOUT = 30
PAGE_CAP = 100       # 10,000 repositories per organization is plenty
CONFIRM_CAP = 200    # one request each, so a dead connection does not burn the hour


class _Missing(Exception):
    pass


def _get(api: str, token: str, path: str):
    """One GET.  -> parsed JSON, or raises _Missing on a 404."""
    req = urllib.request.Request(
        api.rstrip("/") + path,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "git-code-review"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as answer:
            return json.loads(answer.read() or b"null")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise _Missing(path) from None
        raise


def _listed(api: str, token: str, owner: str) -> set:
    """Every repository of one owner the token can list, lower cased."""
    quoted = urllib.parse.quote(owner)
    path = "/orgs/%s/repos?type=all&per_page=100&page=%%d" % quoted
    try:
        first = _get(api, token, path % 1) or []
    except _Missing:
        # Not an organization.  A user's own repositories, private ones
        # included, only come back through /user/repos.
        path = ("/user/repos?affiliation=owner,collaborator,organization_member"
                "&per_page=100&page=%d")
        first = _get(api, token, path % 1) or []
    names = set()
    for page in range(1, PAGE_CAP + 1):
        batch = first if page == 1 else (_get(api, token, path % page) or [])
        names.update((r.get("full_name") or "").lower() for r in batch)
        if len(batch) < 100:
            break
    return names


def _english(names: list) -> str:
    if len(names) <= 1:
        return "".join(names)
    if len(names) <= 5:
        return ", ".join(names[:-1]) + " and " + names[-1]
    return "%s and %d more" % (", ".join(names[:4]), len(names) - 4)


def check(connection_id: int) -> dict:
    """-> {"checked": bool, "missing": [...], "renamed": {old: new}, "detail": str}

    Never raises.  A check that cannot run says why in detail and leaves
    checked False, so the caller does not report a clean bill it never got.
    """
    from app.core import connections as connection_store
    from app.core.models import Repository

    with session_scope() as db:
        row = connection_store.by_id(db, connection_id)
        if row is None:
            return {"checked": False, "missing": [], "renamed": {}, "detail": ""}
        name = row.name
        provider = (row.provider or "github")
        method = (row.auth_method or "pat")
        api = row.api_url or "https://api.github.com"
        token = connection_store.secret_of(row, "token")
        known = sorted(db.scalars(
            select(Repository.full_name)
            .where(Repository.connection == name,
                   Repository.archived.is_(False))))

    result = {"checked": False, "missing": [], "renamed": {}, "detail": ""}
    if provider != "github" or method != "pat" or not token or not known:
        return result

    try:
        owners = sorted({full.split("/", 1)[0] for full in known})
        seen = set()
        for owner in owners:
            seen |= _listed(api, token, owner)
        absent = [full for full in known if full.lower() not in seen]

        # A listing can disagree with direct access (a renamed repository is
        # listed under its new name), so ask about each one before naming it.
        for full in absent[:CONFIRM_CAP]:
            try:
                about = _get(api, token, "/repos/" + urllib.parse.quote(full))
            except _Missing:
                result["missing"].append(full)
                continue
            now = (about or {}).get("full_name") or full
            if now.lower() != full.lower():
                result["renamed"][full] = now
        result["missing"] += absent[CONFIRM_CAP:]
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("reach check for %s did not finish: %s", name, exc)
        result["detail"] = ("Could not list what this token can see, so the "
                            "repositories were not checked: %s." % exc)
        return result

    result["checked"] = True
    parts = []
    if result["missing"]:
        count = len(result["missing"])
        parts.append(
            "%d repositor%s recorded here %s not visible to this token, so "
            "%s not being scanned: %s.  Give the token's account access "
            "again.  If %s deleted, nothing needs doing." % (
                count, "y" if count == 1 else "ies",
                "is" if count == 1 else "are",
                "it is" if count == 1 else "they are",
                _english([full.split("/", 1)[1] for full in result["missing"]]),
                "it was" if count == 1 else "they were"))
    if result["renamed"]:
        parts.append("Renamed on GitHub: %s." % _english(
            ["%s is now %s" % (old, new) for old, new in result["renamed"].items()]))
    result["detail"] = "  ".join(parts)
    return result
