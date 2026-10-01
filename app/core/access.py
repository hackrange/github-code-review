"""Blast radius: who can reach what, and what that lets them do.

The question this answers is not "what does this repository allow".  It is "if
this person's account is taken tomorrow, what can whoever holds it do".  Those
are different questions and only the second one is worth losing sleep over.

GitHub already works out the effective permission, folding together what the
organization grants everybody, what a team grants, and anything granted to
somebody by name.  The scanner asks for that answer on every run.  Until now it
was collected and thrown away; this keeps it.

One thing worth saying plainly, because it decides how the page reads: pull and
clone are the same permission.  Somebody with read can take a full copy of
every commit, every branch and everything ever committed and later deleted.
For a repository that has held a credential, read is not a small thing, and a
report that says "read" without saying that is not telling anybody the truth.
"""

from __future__ import annotations

import logging

from app.core.models import RepoAccess, utcnow

log = logging.getLogger("gcr.access")

# Worst to least, which is the order anybody reading this cares about.
LEVELS = ["admin", "maintain", "write", "triage", "read"]
RANK = {name: len(LEVELS) - i for i, name in enumerate(LEVELS)}

# What each level actually lets somebody do.  GitHub's own words are a role
# name; these are the actions, which is what a person is really asking about.
CAPABILITIES = {
    "read":     ("clone and pull", "read every commit ever made"),
    "triage":   ("clone and pull", "read every commit ever made",
                 "manage issues and pull requests"),
    "write":    ("clone and pull", "read every commit ever made",
                 "push and commit", "merge pull requests"),
    "maintain": ("clone and pull", "read every commit ever made",
                 "push and commit", "merge pull requests",
                 "change most settings"),
    "admin":    ("clone and pull", "read every commit ever made",
                 "push and commit", "merge pull requests",
                 "change most settings", "grant access to others",
                 "delete the repository"),
}

# Names that give away an account nobody reads the mail for.  Not a rule, a
# hint: the report says why it thinks so rather than asserting it.
MACHINE_HINTS = ("svc-", "svc_", "service-", "bot-", "-bot", "[bot]",
                 "automation", "jenkins", "deploy", "ci-", "-ci",
                 "github-actions", "dependabot", "renovate")


def looks_like_machine(login: str, account_type: str = "User") -> bool:
    """A service account or an app, as far as anybody can tell from a name."""
    if (account_type or "").lower() == "bot":
        return True
    name = (login or "").lower()
    if any(hint in name for hint in MACHINE_HINTS):
        return True
    # A login that is a long run of hex is an app, not a person.
    stripped = name.replace("-", "").replace("_", "")
    return len(stripped) >= 24 and all(c in "0123456789abcdef" for c in stripped)


def capabilities(permission: str) -> tuple:
    return CAPABILITIES.get((permission or "read").lower(), CAPABILITIES["read"])


def worst(permissions) -> str:
    """The highest of several, which is the one that matters."""
    best, name = 0, "read"
    for item in permissions:
        if RANK.get(item, 0) > best:
            best, name = RANK.get(item, 0), item
    return name


def record_access(session, document: dict, connection=None) -> int:
    """Keep the access block from one scanner report.

    Replaces what is held for each repository the report covers, and leaves
    every other repository alone, so scanning one organization does not wipe
    what is known about the rest.
    """
    block = (document or {}).get("access") or {}
    users = block.get("users") or []
    if not users:
        return 0

    name = getattr(connection, "name", "") or ""
    seen = utcnow()

    # Flattened: the report groups by person, the table is one row per pair.
    rows, repos = [], set()
    for person in users:
        login = person.get("login")
        if not login:
            continue
        for entry in person.get("repositories") or []:
            repository = entry.get("repository")
            if not repository:
                continue
            repos.add(repository)
            rows.append({
                "organization": repository.split("/")[0],
                "repository": repository,
                "login": login,
                "permission": (entry.get("permission") or "read").lower(),
                "affiliation": entry.get("affiliation") or "inherited",
                "outside_collaborator": bool(entry.get("outside_collaborator")
                                             or person.get("outside_collaborator")),
                "account_type": person.get("type") or "User",
                "site_admin": bool(person.get("site_admin")),
                "html_url": person.get("html_url") or "",
                "connection": name,
                "seen_at": seen,
            })

    if repos:
        session.query(RepoAccess).filter(
            RepoAccess.repository.in_(list(repos))).delete(
                synchronize_session=False)
    for row in rows:
        session.add(RepoAccess(**row))
    session.flush()
    log.info("access: %d people across %d repositories", len(users), len(repos))
    return len(rows)


def owner_context(session) -> dict:
    """What the connection says each organization is, and who answers for it.

    An audit is not a list of logins.  "Twenty four people can push to this"
    means nothing until somebody says what this is, who owns it and what it
    holds.  The connection already carries all three, so the report should not
    make anybody go and look them up.
    """
    from app.core.models import Connection

    out = {}
    for row in session.query(Connection).all():
        for org in (row.scope_orgs() if hasattr(row, "scope_orgs")
                    else [o.strip() for o in (row.organizations or "").split(",")]):
            if not org:
                continue
            out[org] = {
                "connection": row.name,
                "application": row.application_name or "",
                "application_owner": row.application_owner or "",
                "technical_owner": row.technical_owner or "",
                "holds": row.sensitivity or "",
                "provider": row.provider or "",
            }
    return out


def _within(query, column, repositories):
    """Narrow a query to the repositories somebody may see.

    None means everything.  An empty set means nothing, and is said as a
    condition that matches no row rather than an empty IN, which some engines
    refuse.
    """
    if repositories is None:
        return query
    if not repositories:
        return query.filter(column.is_(None))
    return query.filter(column.in_(list(repositories)))


def organizations(session, repositories=None) -> list:
    """One row per organization, worst first.

    `repositories` is rbac.visible_repository_names: None for the whole
    estate, otherwise only those repositories are counted, and an organization
    the person has none of in does not appear at all.
    """
    from sqlalchemy import func

    def scoped(query):
        return _within(query, RepoAccess.repository, repositories)

    rows = (scoped(session.query(
                RepoAccess.organization,
                func.count(func.distinct(RepoAccess.repository)),
                func.count(func.distinct(RepoAccess.login))))
            .group_by(RepoAccess.organization).all())

    out = []
    for org, repo_count, people in rows:
        admins = (scoped(session.query(func.count(func.distinct(RepoAccess.login))))
                  .filter(RepoAccess.organization == org,
                          RepoAccess.permission == "admin").scalar() or 0)
        outside = (scoped(session.query(func.count(func.distinct(RepoAccess.login))))
                   .filter(RepoAccess.organization == org,
                           RepoAccess.outside_collaborator.is_(True)).scalar() or 0)
        writers = (scoped(session.query(func.count(func.distinct(RepoAccess.login))))
                   .filter(RepoAccess.organization == org,
                           RepoAccess.permission.in_(["write", "maintain", "admin"]))
                   .scalar() or 0)
        out.append({"organization": org, "repositories": repo_count,
                    "people": people, "admins": admins, "writers": writers,
                    "outside": outside,
                    "unprotected": unprotected_repos(session, org, repositories)})

    context = owner_context(session)
    for row in out:
        row.update(context.get(row["organization"], {}))
    return sorted(out, key=lambda row: (-row["admins"], -row["people"]))


def unprotected_repos(session, organization: str = "", repositories=None) -> int:
    """Repositories somebody can push to whose default branch is not protected.

    On its own an unprotected branch is a policy question.  With a list of
    people who can push to it, it is the answer to "who can put code in front
    of customers without anybody else seeing it first".
    """
    from app.core.models import Repository

    query = _within(session.query(Repository).filter(
        Repository.default_branch_protected.is_(False)),
        Repository.full_name, repositories)
    if organization:
        query = query.filter(Repository.organization == organization)
    names = {r.full_name for r in query.all()}
    if not names:
        return 0
    reachable = {row.repository for row in session.query(RepoAccess)
                 .filter(RepoAccess.repository.in_(list(names)),
                         RepoAccess.permission.in_(["write", "maintain", "admin"]))
                 .all()}
    return len(reachable)


def people(session, organization: str = "", repositories=None) -> list:
    """Everybody with any access, worst first.  Empty organization means all.

    One row per person, because the question is about the person: how much of
    this organization does their account reach, and what can it do there.
    """
    query = _within(session.query(RepoAccess), RepoAccess.repository, repositories)
    if organization:
        query = query.filter(RepoAccess.organization == organization)
    rows = query.all()

    grouped = {}
    for row in rows:
        entry = grouped.setdefault(row.login, {
            "login": row.login, "account_type": row.account_type,
            "site_admin": row.site_admin, "html_url": row.html_url,
            "outside": False, "repositories": [], "affiliations": set(),
        })
        entry["repositories"].append({"repository": row.repository,
                                      "permission": row.permission,
                                      "affiliation": row.affiliation})
        entry["affiliations"].add(row.affiliation)
        entry["outside"] = entry["outside"] or row.outside_collaborator

    out = []
    for entry in grouped.values():
        levels = [r["permission"] for r in entry["repositories"]]
        highest = worst(levels)
        entry["highest"] = highest
        entry["capabilities"] = capabilities(highest)
        entry["repo_count"] = len(entry["repositories"])
        entry["admin_of"] = [r["repository"] for r in entry["repositories"]
                             if r["permission"] == "admin"]
        entry["can_push"] = sum(1 for level in levels
                                if RANK.get(level, 0) >= RANK["write"])
        entry["machine"] = looks_like_machine(entry["login"], entry["account_type"])
        entry["affiliations"] = sorted(entry["affiliations"])
        entry["repositories"].sort(
            key=lambda r: (-RANK.get(r["permission"], 0), r["repository"]))
        out.append(entry)

    return sorted(out, key=lambda e: (-RANK.get(e["highest"], 0),
                                      -e["repo_count"], e["login"].lower()))


def rows_for_export(session, organization: str = "", repositories=None) -> list:
    """One row per person per repository, which is what a spreadsheet wants."""
    query = _within(session.query(RepoAccess), RepoAccess.repository, repositories)
    if organization:
        query = query.filter(RepoAccess.organization == organization)
    # Resolved once per repository rather than once per row.  A repository
    # says what it is where somebody has tagged it, and falls back to the
    # connection where nobody has, so the export carries the answer that
    # actually applies rather than the account level one.
    from app.core import tagging
    from app.core.models import Repository

    repos = _within(session.query(Repository), Repository.full_name, repositories)
    if organization:
        repos = repos.filter(Repository.organization == organization)
    tags = {}
    for repo in repos.all():
        resolved = tagging.effective(session, repo)
        tags[repo.full_name] = {
            "application": resolved["application_name"]["value"],
            "application_owner": resolved["application_owner"]["value"],
            "technical_owner": resolved["technical_owner"]["value"],
            "holds": resolved["sensitivity"]["value"],
            "tagged": resolved["technical_owner"]["from"],
        }

    context = owner_context(session)
    out = []
    for row in query.order_by(RepoAccess.organization, RepoAccess.login,
                              RepoAccess.repository).all():
        allowed = capabilities(row.permission)
        owner = tags.get(row.repository) or context.get(row.organization, {})
        out.append({
            "organization": row.organization,
            "application": owner.get("application", ""),
            "application_owner": owner.get("application_owner", ""),
            "technical_owner": owner.get("technical_owner", ""),
            "holds": owner.get("holds", ""),
            "ownership_from": owner.get("tagged", "connection"),
            "repository": row.repository,
            "login": row.login,
            "permission": row.permission,
            "granted": row.affiliation,
            "outside_collaborator": "yes" if row.outside_collaborator else "no",
            "looks_like_machine": "yes" if looks_like_machine(
                row.login, row.account_type) else "no",
            "can_clone_and_pull": "yes",
            "can_push_and_commit": "yes" if RANK.get(row.permission, 0)
                                   >= RANK["write"] else "no",
            "can_grant_access": "yes" if row.permission == "admin" else "no",
            "capabilities": "; ".join(allowed),
        })
    return out
