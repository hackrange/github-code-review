"""GitHub accounts, one row per credential.

A fine grained token reaches exactly one resource owner.  An estate spread
across twenty six organizations therefore needs twenty six tokens, and there
has to be somewhere to put them.  This is that somewhere.

Credentials are encrypted with the installation key, the same as the settings.
They are handed to the scanner through the environment at scan time and never
written to a file.
"""

from __future__ import annotations

import logging

from app.core import settings_store as store
from app.core.models import Connection

log = logging.getLogger("gcr.connections")

# The one made from the old single credential settings, so an install that
# predates this keeps working without anybody doing anything.
DEFAULT_NAME = "default"


def all_connections(session, enabled_only: bool = False) -> list:
    query = session.query(Connection)
    if enabled_only:
        query = query.filter(Connection.enabled.is_(True))
    return query.order_by(Connection.name).all()


def by_name(session, name: str):
    return (session.query(Connection)
            .filter(Connection.name == (name or "").strip()).one_or_none())


def by_id(session, connection_id):
    try:
        wanted = int(connection_id)
    except (TypeError, ValueError):
        return None
    return session.query(Connection).filter(Connection.id == wanted).one_or_none()


def secret_of(connection, field: str) -> str:
    """Decrypt one of the credential fields."""
    raw = getattr(connection, field, "") or ""
    if not raw:
        return ""
    # Stored the same way the settings are, so the same key reads it back.
    return store._decrypt(raw)


def put_secret(connection, field: str, value: str) -> None:
    """Encrypt on the way in.  An empty value leaves what is there alone."""
    if value == "":
        return
    setattr(connection, field, store._encrypt(value))


def configured(connection) -> bool:
    """Has this one got enough to reach GitHub with."""
    if connection.auth_method == "app":
        return bool(connection.app_id and secret_of(connection, "app_key"))
    return bool(secret_of(connection, "token"))


def usable(session) -> list:
    """The connections a scan should work through."""
    return [row for row in all_connections(session, enabled_only=True)
            if configured(row)]


def adopt_settings(session, actor: str = "setup") -> bool:
    """Make the first connection out of the old single credential settings.

    Runs once.  Before this existed there was one token in the settings table,
    and everything that used it should carry on working without anybody
    touching the Connections page first.
    """
    if session.query(Connection).count():
        return False

    token = store.get(session, "github.token") or ""
    app_key = store.get(session, "github.app_key") or ""
    if not (token or app_key):
        return False

    row = Connection(
        name=DEFAULT_NAME,
        enabled=True,
        api_url=store.get(session, "github.api_url") or "https://api.github.com",
        web_url=store.get(session, "github.web_url") or "https://github.com",
        auth_method=store.get(session, "github.auth_method") or "pat",
        app_id=store.get(session, "github.app_id") or "",
        app_installation=store.get(session, "github.app_installation") or "",
        organizations=", ".join(store.get(session, "scan.organizations") or []),
        repositories=", ".join(store.get(session, "scan.repositories") or []),
        created_by=actor,
    )
    put_secret(row, "token", token)
    put_secret(row, "app_key", app_key)
    session.add(row)
    session.flush()
    log.info("made the first connection from the existing settings")
    return True


# Findings to read when working out which branches an account has.  History
# that predates branch_names is the only place those names exist, and a large
# estate has enough findings that reading all of them to fill in a picker is
# not a fair trade.  The answer says when it stopped.
FINDING_SCAN_LIMIT = 50000


def discovered_branches(session, connection, limit: int = 500) -> dict:
    """Branch names past scans of this account actually found.

    A branch filter typed from memory is a filter that silently matches
    nothing, so the box offers what is really there.  Two sources, because one
    of them is new:

    * ``Repository.branch_names``, written by every scan from what it walked.
      Complete, and the right answer.
    * the branches recorded on findings, for scans that ran before that column
      existed.  Only branches carrying a finding appear, which is why the
      answer says where its names came from rather than implying a full list.
    """
    import json as json_module

    from app.core.models import Finding, Repository

    counts: dict = {}
    defaults: dict = {}

    def note(name: str, repo_key: str, is_default: bool = False) -> None:
        name = (name or "").strip()
        if not name:
            return
        counts.setdefault(name, set()).add(repo_key)
        if is_default:
            defaults.setdefault(name, set()).add(repo_key)

    def owned(query, model):
        # Rows carry both the id and the name.  The id is the right answer; the
        # name is all that rows written before connections had ids have, and
        # those are exactly the old scans this is here to read.
        from sqlalchemy import or_
        return query.filter(or_(model.connection_id == connection.id,
                                model.connection == connection.name))

    repos = 0
    from_scans = False
    query = session.query(Repository.full_name, Repository.branch_names,
                          Repository.default_branch)
    for full_name, names, default_branch in owned(query, Repository):
        repos += 1
        try:
            walked = json_module.loads(names or "[]")
        except (TypeError, ValueError):
            walked = []
        if walked:
            from_scans = True
        for name in walked:
            note(str(name), full_name, str(name) == (default_branch or ""))
        # The default branch is worth offering even when nothing walked it.
        note(default_branch or "", full_name, True)

    # Anything a finding remembers that the repositories do not.
    from_findings = False
    truncated = False
    seen = 0
    query = session.query(Finding.repository, Finding.branch, Finding.branches)
    for repository, branch, branch_json in owned(query, Finding).limit(
            FINDING_SCAN_LIMIT + 1):
        seen += 1
        if seen > FINDING_SCAN_LIMIT:
            truncated = True
            break
        try:
            names = json_module.loads(branch_json or "[]")
        except (TypeError, ValueError):
            names = []
        for name in (names or ([branch] if branch else [])):
            if str(name) not in counts:
                from_findings = True
            note(str(name), repository or "")

    ranked = sorted(
        counts.items(),
        key=lambda item: (-len(defaults.get(item[0], ())), -len(item[1]),
                          item[0].lower()))
    branches = [{"name": name,
                 "repositories": len(repo_keys),
                 "default_for": len(defaults.get(name, ()))}
                for name, repo_keys in ranked[:limit]]

    if from_scans and from_findings:
        source = "both"
    elif from_scans:
        source = "scans"
    elif from_findings or branches:
        source = "findings"
    else:
        source = "none"

    return {"connection": connection.name,
            "repositories": repos,
            "total": len(counts),
            "branches": branches,
            "source": source,
            "truncated": truncated}


def normalize_urls(provider: str, web: str, api: str) -> tuple:
    """Take whatever somebody pasted and make two addresses out of it.

    People paste the URL they just proved works in a browser, which for GitLab
    is usually /api/v4/projects, and they paste it with or without a trailing
    slash and sometimes without a scheme.  All of that is the same intent, so
    it is translated rather than refused.

    The API base has to be /api/v4 and nothing deeper: the scanner appends its
    own paths, so a base ending in /projects turns every request into
    /api/v4/projects/groups/... and finds nothing.
    """
    import re

    def tidy(value: str) -> str:
        value = (value or "").strip()
        if not value:
            return ""
        if not value.startswith(("http://", "https://")):
            # A bare host is what somebody types when they are thinking of the
            # site rather than a URL.
            value = "https://" + value.lstrip("/")
        return value.rstrip("/")

    web = tidy(web)
    api = tidy(api)

    if provider == "gitlab":
        if not web and api:
            # Work backwards: the instance is whatever sits above /api/v4.
            web = re.sub(r"/api/v\d+(/.*)?$", "", api).rstrip("/")
        if api:
            # Cut anything below the version back to the base, and add the base
            # when it is missing entirely.
            match = re.search(r"^(.*?/api/v\d+)(/.*)?$", api)
            api = match.group(1) if match else api.rstrip("/") + "/api/v4"
        elif web:
            api = web + "/api/v4"
    elif provider == "bitbucket":
        # Bitbucket Cloud is one address for everybody; there is no self hosted
        # variant of it to point somewhere else.
        api = api or "https://api.bitbucket.org/2.0"
        web = web or "https://bitbucket.org"
    elif provider == "azure":
        # The organization goes in the path at call time, not here.
        api = api or "https://dev.azure.com"
        web = web or "https://dev.azure.com"
    elif provider == "assembla":
        api = api or "https://api.assembla.com/v1"
        web = web or "https://app.assembla.com"
    elif provider == "beanstalk":
        # One address per account, so there is no default worth guessing: the
        # account name is half of the hostname.
        pass
    elif provider == "gcsr":
        api = api or "https://sourcerepo.googleapis.com/v1"
        web = web or "https://source.cloud.google.com"
    elif provider == "codecommit":
        # Signed calls through the AWS CLI, so there is no address to set.
        api = api or ""
        web = web or "https://console.aws.amazon.com/codesuite/codecommit"
    elif provider in ("subversion", "perforce"):
        # Whatever the server is.  There is no API and no default: an empty
        # address here is a connection that cannot work, and the check on the
        # connections page says so.
        pass
    else:
        if not api:
            api = "https://api.github.com"
        if not web:
            web = "https://github.com"

    return web, api


# --- removing what a connection left behind ---------------------------------

# Every table that names a connection.  Written out rather than discovered,
# because a table added later should be a deliberate decision about whether
# its rows belong to a connection, not something a loop quietly starts
# deleting.
CONNECTION_TABLES = (
    ("findings", "connection"),
    ("components", "connection"),
    ("repo_access", "connection"),
    ("trend_points", "connection"),
    ("repositories", "connection"),
)

# Scan runs are the exception and are deliberately kept.  They are the record
# of what was done and when, they carry no findings, and deleting them would
# make the history of the estate disagree with the audit log.
KEEP = ("scan_runs",)


def leftovers(session) -> list:
    """-> [{name, findings, ...}] for connection names with no connection row.

    A connection can be deleted while everything it brought in stays, which is
    the right default: removing the way in should not silently remove the
    evidence.  The cost is that the name goes on appearing in filters and
    reports for ever, with nothing behind it a reader can act on.

    So the names are found rather than remembered, by asking which ones appear
    in the data and do not appear in the connection list.
    """
    from sqlalchemy import text

    known = {row[0] for row in session.execute(
        text("select name from connections")).all() if row[0]}

    seen = {}
    for table, column in CONNECTION_TABLES:
        for name, total in session.execute(text(
                "select %s, count(*) from %s where %s <> '' group by %s"
                % (column, table, column, column))).all():
            if not name or name in known:
                continue
            seen.setdefault(name, {"name": name, "total": 0})
            seen[name][table] = total
            seen[name]["total"] += total

    return sorted(seen.values(), key=lambda row: -row["total"])


def counts_for(session, name: str) -> dict:
    """What a flush would remove, so somebody can see it before agreeing."""
    from sqlalchemy import text

    out = {"name": name, "total": 0}
    for table, column in CONNECTION_TABLES:
        total = session.execute(
            text("select count(*) from %s where %s = :name" % (table, column)),
            {"name": name}).scalar() or 0
        out[table] = total
        out["total"] += total
    out["scan_runs"] = session.execute(
        text("select count(*) from scan_runs where connection = :name"),
        {"name": name}).scalar() or 0
    return out


def flush(session, name: str, actor: str = "") -> dict:
    """Remove everything a connection brought in.  -> what was removed.

    Deliberately not reversible and deliberately not quiet.  The counts come
    back so the caller can say what happened rather than "done", and the audit
    entry names them for the same reason.

    The scan history is left alone.  It is the record of what ran and when,
    it holds no findings, and removing it would leave the audit log describing
    scans that no longer appear anywhere.
    """
    from sqlalchemy import text

    name = (name or "").strip()
    if not name:
        return {"removed": 0}

    removed = counts_for(session, name)
    for table, column in CONNECTION_TABLES:
        session.execute(
            text("delete from %s where %s = :name" % (table, column)),
            {"name": name})
    session.flush()
    log.warning("flushed %d row(s) left by connection %s, requested by %s",
                removed["total"], name, actor or "?")
    return removed
