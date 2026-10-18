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
        # Looking at how the numbers have moved, and turning a view of that
        # into a document somebody outside the security team can read.
        #
        # Both go to developers too.  A developer can already export every
        # finding they can see as a file, so a chart of the same rows and a
        # summary of them is not a wider disclosure, and a team that cannot
        # see whether its own numbers are improving cannot be asked to improve
        # them.  The report is built from the same scoped query as everything
        # else, so it can never contain a repository the reader could not open
        # directly.
        "trend.read", "report.generate",
        "waiver.request", "waiver.approve", "waiver.revoke",
        "scan.run", "scan.history.delete",
        # Seeing every scan, and stopping any of them.  A developer keeps
        # "scan.run" so they can re-read a repository of their own, and with it
        # they see and may stop the runs they started.  Somebody else's nightly
        # sweep is not theirs to end.
        "scan.read.any", "scan.stop.any",
        # The report files on disk.  Generating a report is scoped to what the
        # reader may see and stays with everybody; the files a scan left behind
        # are the whole estate's, whoever asked for them.
        "report.files",
        # Deleting findings outright.  Admin only, and deliberately not the
        # same thing as waiving: a waiver is a decision with a reason and an
        # expiry, this just removes the rows.  The next scan finds them again
        # if the code still says so, so it clears history, it does not silence
        # anything.
        "findings.delete",
        # Regrading one finding, which severity_rules cannot do: a rule level
        # override moves every finding that rule ever produced.
        "finding.regrade",
        # Asking a language model about one finding.  It costs money per
        # question and sends what the finding is about outside this
        # installation, so it is a permission of its own rather than something
        # every reader can press.
        "finding.validate",
        "repo.certify",
        # Saying a branch is not one anybody is expected to sign off.  A
        # separate permission from certifying, and administrators only,
        # because it removes work from a list permanently rather than
        # recording that the work was done.  Certifying may reasonably move to
        # a reviewer role one day; this should not go with it.
        "repo.certify.exempt",
        # Saying which branches ship.  Administrators only: it takes findings
        # off everybody's work list and out of the report files, the same
        # weight as an exclusion.  A developer asks through a waiver instead.
        "repo.scope",
        # Asking a model to draw how a repository fits together.  It sends the
        # code outside this installation and costs money per drawing, so the
        # same people who may ask about a finding.  Anybody who can see the
        # repository can look at the result.
        "repo.diagram",
        # Asking a model for a written security assessment of one repository
        # branch.  The same weight as a diagram: it sends code outside this
        # installation and costs money per report.  Anybody who can see the
        # finding it was asked from can read the result.
        "repo.assess",
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
        "utilization.read",
    },
    UserRole.DEVELOPER: {
        "findings.read", "findings.export",
        "trend.read", "report.generate",
        # A developer can ask for an exception.  Only an admin signs it off.
        "waiver.request",
        "scan.run",
        "repo.read",
        # A developer can ask for a noisy rule to be set aside.  Somebody else
        # has to agree, the same as an exception.
        "rule.mute.request",
        # Saying what a repository holds, who owns it and where it is served,
        # for an administrator to approve.  Nothing moves until one does.
        "repo.propose",
        # Deliberately not here: "finding.validate".  Asking a model costs money
        # per question, sends the finding and its code outside this
        # installation, and now lowers grades and teaches rules that apply to
        # everyone, so it is an administrator's decision.  What has been
        # learned still applies to a developer's findings on every scan.
        # Also deliberately not here: the schedules, the exclusions and the report
        # files.  Each of those is a statement about the whole estate rather
        # than about this person's repositories, and a page that shows one
        # team when every account is on it is a leak whichever way it is read.
        # "exclusion.read" in particular was here so a developer could see the
        # rules covering their own repositories, and it showed them all of them.
    },
    UserRole.READER: {
        "findings.read", "findings.export",
        "trend.read", "report.generate",
        "repo.read", "repo.propose",
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


def in_scan_group(user: User) -> bool:
    """Whether a scanning group decides everything this person sees.

    Two ways in, and never both.  Somebody in a group, Digital Engineering
    say, sees what their groups cover and nothing else, whatever their login
    reaches on the host.  Somebody in no group sees what their login reaches
    and nothing else.  A group meant to fence a contractor in would otherwise
    widen back out through whatever their login happens to carry.

    Administrators are the exception.  They are the ones who edit the groups,
    so narrowing them would hide nothing they could not undo.
    """
    if user.role == UserRole.ADMIN:
        return False
    return bool(getattr(user, "groups", None))


def sees_everything(user: User) -> bool:
    """Only administrators see the whole estate.

    Readers used to as well.  The role now says what somebody may do, and
    what they may see comes from their groups or their login, the same as
    for a developer.  See in_scan_group.
    """
    return user.role == UserRole.ADMIN


def scope_pairs(user: User) -> list:
    """The org and repo pairs this person's scanning groups cover.

    Empty for anybody in no group, who sees what their login reaches instead.
    Scopes typed onto an account used to count here too and no longer do: the
    rows are left in user_scopes, unread.  Repository is empty when the whole
    org is in scope.
    """
    pairs = []
    if in_scan_group(user):
        for group in user.groups:
            pairs.extend(group.pairs())

    # Two groups often name the same thing.
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
    up here without anybody keeping a second list of it in step.  For anybody
    in no scanning group this is all they see, so an account with no login
    set and no group sees nothing.
    """
    from app.core.models import RepoAccess

    # A scanning group is all a member gets, so their login adds nothing.
    # Out of one, this is all they get.
    if in_scan_group(user):
        return []
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


def _scope_filter(user: User, session=None, model=None):
    """A SQL condition matching only what this user may see.

    One way in or the other, never both: the scanning groups this person is
    in, or, when they are in none, whatever they can reach on the host.

    Somebody with neither matches nothing.  That is deliberate: a new
    account should see an empty screen, not the whole company.
    """
    # The same condition, over any table that names an organization and a
    # repository.  Findings are one such table and the trend points are
    # another, and writing the rule twice is how two tables end up disagreeing
    # about who may see what.
    model = model or Finding

    if sees_everything(user):
        return None

    clauses = []
    for org, repo in scope_pairs(user):
        if repo:
            clauses.append(
                (model.organization == org)
                & (or_(model.repository == repo,
                       model.repository == f"{org}/{repo}"))
            )
        else:
            clauses.append(model.organization == org)

    # One IN rather than a clause each.  Somebody with two hundred
    # repositories would otherwise build a query with two hundred branches in
    # it, on every page they open.
    if session is not None:
        reachable = repositories_on_the_host(session, user)
        if reachable:
            clauses.append(model.repository.in_(reachable))

    if not clauses:
        # Nothing assigned and nothing reachable means nothing visible.
        return model.id.is_(None)
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


def visible(session: OrmSession, user: User, model=None):
    """visible_findings for any table carrying organization and repository.

    The summary tables are narrowed by exactly the same condition, so a count
    read from one can never include a repository the reader cannot open.
    """
    if model is None or model is Finding:
        return visible_findings(session, user)
    query = session.query(model)
    condition = _scope_filter(user, session, model=model)
    if condition is not None:
        query = query.filter(condition)
    return query


def visible_trends(session: OrmSession, user: User):
    """The history this user may see, narrowed the same way the findings are.

    Deliberately the same condition rather than a second one that looks like
    it: a chart that showed a repository somebody cannot open would be a leak
    that is harder to notice than a list, because nobody reads a chart looking
    for a name they should not know.
    """
    from app.core.models import TrendPoint

    query = session.query(TrendPoint)
    condition = _scope_filter(user, session, model=TrendPoint)
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


def visible_certifications(session: OrmSession, user: User):
    """The sign offs on repositories this user may see.

    A certification names a repository by its full name and carries no
    organization of its own, so the scope cannot be spelled out again here the
    way it is for findings.  It is taken from the repositories instead, as a
    subquery, so there is one rule about who may see a repository rather than
    two that have to be kept saying the same thing.

    Certifications are the one place where the count is read as reassurance.
    An unscoped number on a dashboard tells somebody with four repositories
    that four hundred branches elsewhere have been reviewed, which is true and
    is not an answer to the question they were asking.
    """
    from app.core.models import Certification

    return _by_visible_repository(session, user, Certification)


def visible_certification_exemptions(session: OrmSession, user: User):
    """The branches marked as not expecting a sign off, scoped the same way.

    Narrowed with the certifications rather than left whole, because the two
    are read together: a coverage figure built from one reader's branches and
    everybody's exemptions is a percentage of nothing anybody can check.
    """
    from app.core.models import CertificationExemption

    return _by_visible_repository(session, user, CertificationExemption)


def _by_visible_repository(session: OrmSession, user: User, model):
    """Narrow a table that names a repository by full name and nothing else.

    Certifications and their exemptions both do.  Neither carries an
    organization, so the scope cannot be spelled out again the way it is for
    findings; it is taken from the repositories instead, as a subquery, so
    there is one rule about who may see a repository rather than several that
    have to be kept saying the same thing.
    """
    query = session.query(model)
    if sees_everything(user):
        return query
    names = (visible_repositories(session, user)
             .with_entities(Repository.full_name).scalar_subquery())
    return query.filter(model.repository.in_(names))


def visible_repositories(session: OrmSession, user: User):
    query = session.query(Repository)
    if sees_everything(user):
        return query

    clauses = []
    for org, repo in scope_pairs(user):
        if repo:
            # A scope can name the repository either way, the same as the
            # finding filter above accepts.  Matching only the short form left
            # a scope written as org/name seeing its findings and none of its
            # repositories.
            clauses.append((Repository.organization == org)
                           & (or_(Repository.name == repo,
                                  Repository.full_name == repo,
                                  Repository.full_name == f"{org}/{repo}")))
        else:
            clauses.append(Repository.organization == org)
    reachable = repositories_on_the_host(session, user)
    if reachable:
        clauses.append(Repository.full_name.in_(reachable))

    if not clauses:
        return query.filter(Repository.id.is_(None))
    return query.filter(or_(*clauses))


def visible_repository_names(session: OrmSession, user: User):
    """The full names this person may see.  -> None when that is everything.

    For the pages built from tables that hold no findings, such as who can
    reach what and how repositories are tagged.  Those were read whole for
    anybody with repo.read, so a developer given one repository got the access
    map and the owners of every repository on the estate.  None rather than a
    set of every name, so the roles that see everything do not pay for
    building one.
    """
    if sees_everything(user):
        return None
    return {name for (name,) in
            visible_repositories(session, user).with_entities(Repository.full_name)}
