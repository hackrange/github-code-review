"""Which organizations nobody has a connection for.

A fine grained token reaches one organization, so an estate is one connection
per organization, and nothing says so when a new one turns up.  Those
organizations then go unscanned, and an organization that is never scanned has
no findings, which looks exactly like a clean one.

The account behind the tokens already knows the whole list, and GitHub tells
any of its tokens.  A token asking for /user/repos gets an x-github-sso header
back naming, by id, every organization of that account it was not let into.
Add the ones it was let into and that is the account's whole membership, from a
token that can only read one of them.  No new permission and no new credential.

The same answer catches two quieter mistakes.  A connection limited to an
organization its token cannot reach scans nothing, and so does a token whose
resource owner is the account rather than an organization.  Both still sign in
fine, so the Connections page says they work.

GitHub tokens only.  A GitHub App's installations are their own list, and the
other providers have no idea of an organization quite like this one.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from app.core import settings_store as store

log = logging.getLogger("gcr.coverage")

TIMEOUT = 30
PAGE_CAP = 20   # 2,000 organizations is more than any one account belongs to


class _Missing(Exception):
    pass


def _call(api: str, token: str, path: str):
    """One GET.  -> (parsed JSON, headers lower cased), or raises _Missing."""
    req = urllib.request.Request(
        api.rstrip("/") + path,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "git-code-review"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as answer:
            headers = {k.lower(): v for k, v in answer.headers.items()}
            return json.loads(answer.read() or b"null"), headers
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise _Missing(path) from None
        raise


def hidden_ids(headers: dict) -> set:
    """The organization ids an x-github-sso header says were left out.

    It reads "partial-results; organizations=1,2,3".  Anything else, including
    no header at all, means nothing was left out.
    """
    value = (headers or {}).get("x-github-sso", "")
    if "partial-results" not in value or "organizations=" not in value:
        return set()
    listed = value.split("organizations=", 1)[1].split(";", 1)[0]
    return {part.strip() for part in listed.split(",") if part.strip().isdigit()}


def _split(value) -> list:
    if isinstance(value, (list, tuple)):
        value = ",".join(str(v) for v in value)
    return [part.strip() for part in
            str(value or "").replace("\n", ",").split(",") if part.strip()]


def ignored(session) -> list:
    """Organizations somebody said are fine without a connection."""
    return _split(store.get(session, "notify.org_gaps_ignore"))


def _ask(api: str, token: str) -> dict:
    """What one token says about its account.  -> login, own and hidden ids."""
    me, _ = _call(api, token, "/user")
    own = {}
    for page in range(1, PAGE_CAP + 1):
        batch, _ = _call(api, token, "/user/orgs?per_page=100&page=%d" % page)
        for org in batch or []:
            own[str(org.get("id"))] = org.get("login") or ""
        if len(batch or []) < 100:
            break
    # The header is the point of this call, not the body.  One page carries it.
    _, headers = _call(api, token,
                       "/user/repos?affiliation=organization_member&per_page=1")
    return {"login": (me or {}).get("login") or "", "own": own,
            "hidden": hidden_ids(headers)}


def survey() -> dict:
    """Ask every GitHub token, and say which organizations nothing covers.

    -> {"checked_at", "accounts", "members", "missing", "problems", "skipped"}

    Never raises.  A token that cannot be asked goes in skipped with the
    reason, so a short list is never mistaken for a complete one.
    """
    from app.core import connections as connection_store
    from app.core.db import session_scope

    with session_scope() as db:
        leave_out = {name.lower() for name in ignored(db)}
        off = {}
        rows = []
        for row in connection_store.all_connections(db):
            if (row.provider or "github") != "github":
                continue
            if not row.enabled:
                for org in row.scope_orgs():
                    off.setdefault(org.lower(), row.name)
                continue
            rows.append({"name": row.name,
                         "method": row.auth_method or "pat",
                         "api": row.api_url or "https://api.github.com",
                         "token": connection_store.secret_of(row, "token"),
                         "scope": [o for o in row.scope_orgs() if o != "*"]})

    result = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "accounts": [], "members": 0, "missing": [], "problems": [],
              "skipped": []}

    asked = []
    for row in rows:
        if row["method"] != "pat" or not row["token"]:
            result["skipped"].append({"connection": row["name"],
                                      "detail": "Not a personal access token."})
            continue
        try:
            asked.append(dict(row, **_ask(row["api"], row["token"])))
        except urllib.error.HTTPError as exc:
            result["skipped"].append({"connection": row["name"],
                                      "detail": "GitHub answered %d." % exc.code})
        except Exception as exc:  # one bad token must not hide the rest
            result["skipped"].append({"connection": row["name"],
                                      "detail": str(exc)[:200]})

    # Each account's whole membership.  Every token of one account sees the
    # same list from a different side, so all of them go in.
    members, names, ask_with = {}, {}, {}
    for one in asked:
        ids = members.setdefault(one["login"], set())
        ids.update(one["own"])
        ids.update(one["hidden"])
        names.update(one["own"])
        ask_with.setdefault(one["login"], one)

    for login, ids in members.items():
        via = ask_with[login]
        for org_id in sorted(ids - set(names)):
            try:
                about, _ = _call(via["api"], via["token"],
                                 "/organizations/%s" % org_id)
                names[org_id] = (about or {}).get("login") or ""
            except Exception:
                names[org_id] = ""
            if not names[org_id]:
                names[org_id] = "organization %s" % org_id

    covered, reached_by, scoped_to = set(), {}, {}
    for one in asked:
        for org in one["scope"]:
            scoped_to.setdefault(org.lower(), one["name"])

        account = members.get(one["login"], set())
        reached = account - one["hidden"]
        reached_names = sorted((names[i] for i in reached), key=str.lower)
        for org_id in reached:
            reached_by.setdefault(org_id, []).append(one["name"])

        if account and not reached:
            result["problems"].append({
                "connection": one["name"],
                "detail": ("The token reaches none of the %d organizations "
                           "%s belongs to.  Its resource owner is probably the "
                           "account rather than an organization, or an "
                           "organization owner has not approved it yet."
                           % (len(account), one["login"]))})
            continue

        if not one["scope"]:
            covered |= reached
            continue

        in_account = {names[i].lower(): i for i in account}
        for org in one["scope"]:
            org_id = in_account.get(org.lower())
            if org_id in reached:
                covered.add(org_id)
            elif org_id is None:
                result["problems"].append({
                    "connection": one["name"],
                    "detail": ("Limited to %s, which is not an organization %s "
                               "belongs to.  It may have been renamed.  The "
                               "token reaches %s."
                               % (org, one["login"],
                                  ", ".join(reached_names) or "nothing"))})
            else:
                result["problems"].append({
                    "connection": one["name"],
                    "detail": ("Limited to %s, but the token cannot reach it.  "
                               "The token reaches %s."
                               % (org, ", ".join(reached_names) or "nothing"))})

    everyone = set().union(*members.values()) if members else set()
    result["accounts"] = sorted(members)
    result["members"] = len(everyone)
    for org_id in sorted(everyone - covered, key=lambda i: names[i].lower()):
        name = names[org_id]
        if name.lower() in leave_out:
            continue
        if org_id in reached_by:
            note = ("Reached by %s, but that connection is limited to "
                    "another organization." % ", ".join(sorted(reached_by[org_id])))
        elif name.lower() in scoped_to:
            note = ("Connection %s is limited to it, but its token cannot "
                    "reach it." % scoped_to[name.lower()])
        elif name.lower() in off:
            note = "Connection %s is turned off." % off[name.lower()]
        else:
            note = "No connection."
        # With more than one account, say whose membership this came from.  An
        # organization only a person belongs to needs the service account
        # added before any token of its can reach it.
        belongs = sorted(login for login, ids in members.items() if org_id in ids)
        if len(members) > 1 and len(belongs) < len(members):
            note += "  Only %s %s a member." % (
                " and ".join(belongs), "is" if len(belongs) == 1 else "are")
        result["missing"].append({"org": name, "id": org_id, "note": note})
    return result


def gaps(result: dict) -> int:
    return len((result or {}).get("missing", [])) + len((result or {}).get("problems", []))


def message(result: dict) -> tuple:
    """-> (title, lines) for one result."""
    missing = result.get("missing", [])
    problems = result.get("problems", [])
    parts = []
    if missing:
        parts.append("%d organization(s) have no connection" % len(missing))
    if problems:
        parts.append("%d connection(s) scan nothing they should"
                     % len(problems))
    title = "Git Code Review: " + ", ".join(parts)
    lines = ["%s: %s" % (item["org"], item["note"]) for item in missing]
    lines += ["Connection %s: %s" % (item["connection"], item["detail"])
              for item in problems]
    if result.get("skipped"):
        lines.append("%d connection(s) could not be asked, so this list may be "
                     "short." % len(result["skipped"]))
    return title, lines


def save(session, result: dict, actor: str = "") -> None:
    store.set_value(session, "notify.org_gaps_last", result, actor)


def last(session) -> dict:
    value = store.get(session, "notify.org_gaps_last")
    return value if isinstance(value, dict) else {}


def send(session, result: dict) -> dict:
    """Every configured way out, and which of them worked.  {} if no gaps."""
    from app.core import notify

    if not gaps(result):
        return {}
    title, lines = message(result)
    root = notify.base_url(session)
    return notify._fan_out(
        session, title, lines, f"{root}/connections" if root else "",
        {"kind": "org_coverage", "missing": result.get("missing", []),
         "problems": result.get("problems", [])})


def weekly() -> None:
    """The scheduled check.  Quiet unless it is switched on and finds a gap."""
    from app.core.audit import record
    from app.core.db import session_scope

    with session_scope() as db:
        if not store.get(db, "notify.org_gaps_enabled"):
            return
    try:
        result = survey()
    except Exception as exc:  # a background job must not take the scheduler down
        log.warning("organization check failed: %s", exc)
        return
    with session_scope() as db:
        save(db, result, "scheduler")
        sent = send(db, result)
        record(db, "notifications.org_coverage", actor="scheduler",
               detail="%d missing, %d problem(s); %s" % (
                   len(result["missing"]), len(result["problems"]),
                   ", ".join(f"{k}: {'ok' if v else 'failed'}"
                             for k, v in sorted(sent.items())) or "nothing sent"),
               outcome="ok" if not sent or all(sent.values()) else "warn")
