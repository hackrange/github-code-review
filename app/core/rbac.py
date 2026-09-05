"""Who can see what, and who can do what.

Two separate questions.  Role answers "can this person waive things".  Scope
answers "is this repo any of their business".  Both get asked, every time.

The scope check is the one that stops IDOR.  Every lookup by id goes through
visible_finding, so guessing a finding id from another team gets you a 404
rather than somebody else's secret.
"""

from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.orm import Session as OrmSession

from app.core.models import Finding, Repository, User, UserRole

# What each role is allowed to do.  Keep this boring and explicit.
PERMISSIONS = {
    UserRole.ADMIN: {
        "findings.read", "findings.export",
        "waiver.request", "waiver.approve", "waiver.revoke",
        "scan.run", "scan.history.delete",
        # Deleting findings outright.  Admin only, and deliberately not the
        # same thing as waiving: a waiver is a decision with a reason and an
        # expiry, this just removes the rows.  The next scan finds them again
        # if the code still says so, so it clears history, it does not silence
        # anything.
        "findings.delete",
        # Regrading one finding, which severity_rules cannot do: a rule level
        # override moves every finding that rule ever produced.
        "finding.regrade",
        "repo.certify",
        # Looking at the product as somebody else, to see what they see.
        # Read only: see the note on Session.impersonating_id.
        "user.impersonate",
        "schedule.read", "schedule.write",
        "repo.read", "repo.write",
        # Writing the sentence that says what a repository is for.  An
        # administrator only: it is read as authoritative, so it has to be
        # written by somebody who is.
        "repo.describe",
        "user.read", "user.write",
        "settings.read", "settings.write",
        "exclusion.read", "exclusion.write",
        # Asking for a rule to be set aside, and agreeing to somebody else's
        # request.  Both live here for now, but they are separate permissions
        # on purpose: a mute still cannot be approved by the person who asked
        # for it, whatever role they hold.
        "rule.mute.request", "rule.mute.approve",
        "audit.read",
    },
    UserRole.DEVELOPER: {
        "findings.read", "findings.export",
        # A developer can ask for an exception.  Only an admin signs it off.
        "waiver.request",
        "scan.run",
        "repo.read",
        "schedule.read",
        # A developer can ask for a noisy rule to be set aside.  Somebody else
        # has to agree, the same as an exception.
        "rule.mute.request",
        # A developer can see the exclusions covering their own repositories.
        # Writing one is the same decision as approving a waiver, so it stays
        # with the admins.
        "exclusion.read",
    },
    UserRole.READER: {
        "findings.read", "findings.export",
        "repo.read", "schedule.read", "exclusion.read",
    },
}


def can(user: User, permission: str) -> bool:
    if user is None or user.disabled:
        return False
    return permission in PERMISSIONS.get(user.role, set())


def require(user: User, permission: str) -> None:
    """Raise the right HTTP error if they are not allowed.

    403 and not 404 here, because the person is signed in and the answer to
    "may I" is genuinely no.  Hiding that would just be confusing.
    """
    if not can(user, permission):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Not allowed")


def sees_everything(user: User) -> bool:
    """Admins and readers see the whole estate.  Developers do not."""
    return user.role in (UserRole.ADMIN, UserRole.READER)


def scope_pairs(user: User) -> list:
    """The org and repo pairs a developer has been given.

    Their own, plus everything from the groups they are in.  Repository is
    empty when the whole org is in scope.
    """
    pairs = [(s.organization or "", s.repository or "")
             for s in (user.scopes or [])]
    for group in (getattr(user, "groups", None) or []):
        pairs.extend(group.pairs())

    # A group and a personal scope often name the same thing.
    seen, unique = set(), []
    for pair in pairs:
        key = (pair[0].lower(), pair[1].lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(pair)
    return unique


def repositories_on_the_host(session, user) -> list:
    """What this person can reach on the host being scanned.

    Read from what the last scan collected, so access granted on GitHub shows
    up here without anybody keeping a second list of it in step.  An account
    with no login set reaches nothing this way, which is not the same as
    reaching nothing at all: whatever an administrator assigned still counts.
    """
    from app.core.models import RepoAccess

    login = (getattr(user, "github_login", "") or "").strip()
    if not login:
        return []
    return [row.repository for row in
            session.query(RepoAccess.repository)
            .filter(RepoAccess.login == login).distinct().all()]


def in_scope(user: User, organization: str, repository: str,
             session=None) -> bool:
    """Whether this person may act on one repository.

    Pass the session and access on the host counts too.  Without it only what
    an administrator assigned is considered, which is the right answer for the
    places that ask before anything has been scanned.
    """
    if sees_everything(user):
        return True
    repo_name = (repository or "").split("/")[-1]
    wanted_org = (organization or "").lower()
    for scope_org, scope_repo in scope_pairs(user):
        if scope_org.lower() != wanted_org:
            continue
        if not scope_repo:
            return True
        if scope_repo.lower() in {repo_name.lower(), (repository or "").lower()}:
            return True

    if session is not None and repository:
        full = repository if "/" in repository else f"{organization}/{repository}"
        for reachable in repositories_on_the_host(session, user):
            if reachable.lower() == full.lower():
                return True
    return False


def _scope_filter(user: User, session=None):
    """A SQL condition matching only what this user may see.

    Two ways in, and either is enough.  An administrator can assign an
    organization or a repository by hand, and whatever this person can reach on
    the host counts as well.

    A developer with neither matches nothing.  That is deliberate: a new
    account should see an empty screen, not the whole company.
    """
    if sees_everything(user):
        return None

    clauses = []
    for org, repo in scope_pairs(user):
        if repo:
            clauses.append(
                (Finding.organization == org)
                & (or_(Finding.repository == repo,
                       Finding.repository == f"{org}/{repo}"))
            )
        else:
            clauses.append(Finding.organization == org)

    # One IN rather than a clause each.  Somebody with two hundred
    # repositories would otherwise build a query with two hundred branches in
    # it, on every page they open.
    if session is not None:
        reachable = repositories_on_the_host(session, user)
        if reachable:
            clauses.append(Finding.repository.in_(reachable))

    if not clauses:
        # Nothing assigned and nothing reachable means nothing visible.
        return Finding.id.is_(None)
    return or_(*clauses)


def visible_findings(session: OrmSession, user: User):
    """A query already narrowed to what this user may see.

    Start every findings list from here.  Do not filter later, do not filter
    in the template, and do not trust an org name that arrived in the query
    string.
    """
    query = session.query(Finding)
    condition = _scope_filter(user, session)
    if condition is not None:
        query = query.filter(condition)
    return query


def visible_finding(session: OrmSession, user: User, finding_id: int):
    """One finding, by id, only if this user may see it.

    Returns None when they may not, and the caller turns that into a 404.  A
    developer poking at ids from another team learns nothing from the answer.
    """
    try:
        wanted = int(finding_id)
    except (TypeError, ValueError):
        return None
    return visible_findings(session, user).filter(Finding.id == wanted).one_or_none()


def component_scope(session: OrmSession, user: User):
    """A SQL condition over the software inventory, or None for see everything.

    Handed back as a condition rather than a query because the Software page
    asks the same narrowed question several ways at once: a page of rows, a
    count, an ecosystem rollup.  Building each of those from a query object
    means wrapping it in a subquery and losing the columns.

    Same rule as the findings.  A component list names every repository and
    what each one is built from, which tells somebody outside their scope more
    about the estate than the findings would.
    """
    from app.core.models import Component

    if sees_everything(user):
        return None

    clauses = []
    for org, repo in scope_pairs(user):
        if repo:
            clauses.append((Component.organization == org)
                           & (or_(Component.repository == repo,
                                  Component.repository == f"{org}/{repo}")))
        else:
            clauses.append(Component.organization == org)
    reachable = repositories_on_the_host(session, user)
    if reachable:
        clauses.append(Component.repository.in_(reachable))

    if not clauses:
        return Component.id.is_(None)
    return or_(*clauses)


def visible_components(session: OrmSession, user: User):
    """The software inventory, narrowed to what this user may see."""
    from app.core.models import Component

    query = session.query(Component)
    condition = component_scope(session, user)
    return query if condition is None else query.filter(condition)


def visible_repositories(session: OrmSession, user: User):
    query = session.query(Repository)
    if sees_everything(user):
        return query

    clauses = []
    for org, repo in scope_pairs(user):
        if repo:
            clauses.append((Repository.organization == org)
                           & (or_(Repository.name == repo,
                                  Repository.full_name == f"{org}/{repo}")))
        else:
            clauses.append(Repository.organization == org)
    reachable = repositories_on_the_host(session, user)
    if reachable:
        clauses.append(Repository.full_name.in_(reachable))

    if not clauses:
        return query.filter(Repository.id.is_(None))
    return query.filter(or_(*clauses))
