"""The pages.

Every list starts from rbac.visible_findings so scope is applied in the query,
not in the template.  Every lookup by id goes through rbac.visible_finding, so
an id from another team comes back as nothing rather than as somebody else's
secret.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import case, distinct, func, literal, or_ as sa_or

from app.config import APP_NAME, VERSION, settings
from app.core import baseline as baseline_filter
from app.core import branch_scope
from app.core import rbac, recommendation, repo_context, risk
from app.core.db import session_scope
from app.core.models import (
    AuditEvent, Finding, FindingKind, FindingState, Repository, ScanRun,
    Schedule, Severity, User, UserRole, Waiver, WaiverStatus,
)
from app.web.render import notice_class, page, render_partial
from app.core.reports import spreadsheet_row
from app.web import oneshot as _oneshot
from app.web.security import clean_notice, clean_text, current_user

log = logging.getLogger("gcr.pages")
router = APIRouter()

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]

# What the page size selector offers.
PAGE_SIZES = [100, 500, 1000]


def _scanning_now() -> set:
    """Accounts with a scan in flight, for the buttons that must not offer one.

    Imported here rather than at the top because the scanner pulls in the whole
    engine stack, and the pages that need this are otherwise cheap.
    """
    from app.core import scanner

    try:
        return scanner.connections_scanning_now()
    except Exception:            # noqa: BLE001 - a button is not worth a 500
        return set()


def _scanning_now_ids() -> set:
    """The same accounts by id, which is the answer that cannot go stale.

    Handed to the pages alongside the names.  A repository row written before
    somebody renamed its account still carries the old name, and matching on
    that alone leaves the button live during a scan that already covers it.
    """
    from app.core import scanner

    try:
        return scanner.connection_ids_scanning_now()
    except Exception:            # noqa: BLE001 - a button is not worth a 500
        return set()


def _branch_finding_counts(db, user):
    """-> count(repository, branch).  Open findings this reader can see.

    One grouped query for the whole page.  Counting each badge on its own was
    two thousand queries and four seconds on the repositories page.  A badge
    with no branch counts the whole repository.  Names match without case,
    the way MariaDB compares them.
    """
    by_branch, by_repo = {}, {}
    for repository, branch, total in (
            rbac.visible_findings(db, user)
            .filter(Finding.state == FindingState.OPEN)
            .filter(Finding.out_of_scope.is_(False))
            .with_entities(Finding.repository, Finding.branch,
                           func.count(Finding.id))
            .group_by(Finding.repository, Finding.branch).all()):
        repo_key = (repository or "").casefold()
        key = (repo_key, (branch or "").casefold())
        by_branch[key] = by_branch.get(key, 0) + total
        by_repo[repo_key] = by_repo.get(repo_key, 0) + total

    def count(repository: str, branch: str) -> int:
        repo_key = (repository or "").casefold()
        if not branch:
            return by_repo.get(repo_key, 0)
        return by_branch.get((repo_key, branch.casefold()), 0)

    return count


def _compare_url(db, row) -> str:
    """Where to see what arrived on a branch since it was signed off.

    A certification records the commit that was reviewed.  The scan records
    where the branch is now.  Two commits and the repository's own address are
    everything a compare view needs, and every host this product speaks to
    offers one at the same shape.

    Empty when either commit is missing, because a link that goes somewhere
    unhelpful is worse than no link: the reader clicks it, learns nothing and
    trusts the next one less.
    """
    from app.core import certification as _c
    from app.core.models import Repository

    base = (row.commit_sha or "").strip()
    if not base:
        return ""
    head = (_c.head_of(db, row.repository, row.branch) or "").strip()
    if not head or head == base:
        return ""
    repo = (db.query(Repository)
            .filter(Repository.full_name == row.repository).one_or_none())
    home = (getattr(repo, "html_url", "") or "").strip().rstrip("/")
    if not home:
        return ""
    return "%s/compare/%s...%s" % (home, base, head)


def report_url_fetcher(allowed: str = ""):
    """-> a fetcher for the report typesetter that refuses to go anywhere.

    The typesetter resolves whatever the page it is given references, and the
    page is built from findings: repository names, file paths, rule names,
    commit messages, author names.  Every one of those is chosen by whoever
    can commit to a scanned repository.

    Nothing gets through today.  Those values are escaped on the way in, the
    template carries no external reference but the logo, and the logo is
    checked for its scheme where it is set.  Both of those facts are one
    careless edit away from being untrue, and neither edit would look
    dangerous: a `| safe` on a field somebody wanted to render as markup, or
    an image added to a header.  This is the guard that does not depend on
    anybody remembering.

    A data URI is an image already in hand rather than an address, so it is
    allowed.  So is the logo an administrator typed in, exactly, and nothing
    that merely resembles it.  Everything else is this server making a request
    because a page told it to, which is the whole of CWE-918.

    Two shapes, because the library changed under this.  WeasyPrint 70 fixed
    its own server side request forgery by replacing the fetcher function with
    a class that takes a list of protocols, so that is what an install on 70
    gets, with the allowlist on top of it.  An older install gets the callable
    the earlier versions take.  The rule is the same either way; only the way
    of saying it moved.
    """
    def permitted(url) -> bool:
        target = str(url)
        return (target.lower().startswith("data:")
                or bool(allowed) and target == allowed)

    def refuse(url):
        log.warning("a report tried to fetch %.120r while being typeset; "
                    "refused", str(url))

    try:                            # WeasyPrint 70 and later
        from weasyprint.urls import URLFetcher, URLFetchingError

        class _ReportFetcher(URLFetcher):
            def fetch(self, url, *args, **kwargs):
                if not permitted(url):
                    refuse(url)
                    raise URLFetchingError(
                        "This report may not fetch anything but its logo.")
                return super().fetch(url, *args, **kwargs)

        # The protocol list is the library's own guard against this, kept as
        # well as the allowlist rather than instead of it: two ways to say no
        # cost nothing, and the one above is about addresses rather than
        # schemes.
        return _ReportFetcher(allowed_protocols=("data", "https"))
    except ImportError:             # WeasyPrint 69 and earlier
        from weasyprint.urls import default_url_fetcher

        def fetch(url, *args, **kwargs):
            if not permitted(url):
                refuse(url)
                raise ValueError(
                    "This report may not fetch anything but its logo.")
            return default_url_fetcher(url, *args, **kwargs)

        return fetch


def _shared(db, user: User) -> dict:
    """The handful of things the shell needs on every page."""
    pending = 0
    if rbac.can(user, "waiver.approve"):
        pending = (db.query(func.count(Waiver.id))
                   .filter(Waiver.status == WaiverStatus.REQUESTED).scalar()) or 0

    # Changes to repositories somebody asked for and nobody has decided.
    proposed = 0
    if rbac.can(user, "repo.write"):
        from app.core import proposals
        proposed = proposals.pending_count(db)

    last = (db.query(ScanRun)
            .filter(ScanRun.status == "finished")
            .order_by(ScanRun.finished_at.desc())
            .first())
    return {
        "user": user,
        "pending_waivers": pending,
        "pending_proposals": proposed,
        "can_see_proposals": rbac.can(user, "repo.write"),
        "last_scan": _ago(last.finished_at) if last and last.finished_at else "",
        # The shell decides whether to offer the link, so a role without the
        # permission is not shown a page it would be refused at.
        "can_see_trends": rbac.can(user, "trend.read"),
        # Whether findings on branches that do not ship can be asked for at
        # all.  Everybody else never sees them.  See app.core.scan_scope.
        "can_see_out_of_scope": rbac.can(user, "repo.scope"),
        # The navigation asks the same questions the routes do, so it stops
        # offering pages that will refuse.  Hiding a link is not the guard:
        # the address still works, and the guard is on the route.
        "can_see_scans": rbac.can(user, "scan.run"),
        "can_see_schedules": rbac.can(user, "schedule.read"),
        "can_see_exclusions": rbac.can(user, "exclusion.read"),
        "can_see_report_files": rbac.can(user, "report.files"),
    }


# A filtered export of a large estate is a big file.  This is generous and
# still bounded, and the file says when it was trimmed.
MAX_EXPORT_ROWS = 50000


# What a column header may sort on.  A allowlist rather than a column name out
# of the query string, because that is a query string reaching the database.
SORTABLE = {
    "priority":   None,                    # the default, worked out below
    "severity":   Finding.severity,
    # The queue position.  This is what the score is for: a total order over
    # four thousand findings, which twelve severity and impact buckets cannot
    # give anybody.
    "score":      Finding.risk_score,
    "confidence": Finding.confidence,
    "repository": Finding.repository,
    "kind":       Finding.kind,
    "rule":       Finding.rule,
    "file":       Finding.file_path,
    "found":      Finding.last_found_at,
    # Days since this product first saw it.  Fewest days is newest, so the
    # direction is turned round below: ascending days is the newest first.
    "discovered": Finding.first_found_at,
    "id":         Finding.vuln_id,
}

# Columns shown as an age in days rather than a date, where the order a person
# means by "ascending" is the reverse of the date's.
AGE_COLUMNS = {"discovered"}


def _sort_order(sort: str, direction: str):
    """Order by whichever column was clicked, priority by default."""
    if sort not in SORTABLE or sort == "priority":
        return [_priority_order(), Finding.last_found_at.desc()]
    column = SORTABLE[sort]
    if sort in AGE_COLUMNS:
        direction = "asc" if direction == "desc" else "desc"
    ordered = column.desc() if direction == "desc" else column.asc()
    # A stable second key, or rows with equal values shuffle between pages.
    return [ordered, Finding.id.asc()]


def _expiry_window(days: int) -> dict:
    """What an expiry picker may offer: the default, and both ends of it.

    The rule about which dates are allowed lived only on the server, so the
    calendar offered every date there is and a waiver dated yesterday came
    back as a 400 after the reason had been typed out.  Now the picker cannot
    reach a date the server will refuse.

    Worked out in UTC, because UTC is what the server compares against.  A
    browser doing this locally would rule out a date the server accepts, or
    offer one it does not, depending on which side of midnight the reader is.
    """
    from app.web.routes_api import MAX_WAIVER_DAYS

    now = datetime.now(timezone.utc)
    return {
        "default_expiry": (now + timedelta(days=days)).strftime("%Y-%m-%d"),
        # Tomorrow.  Today is a date that has already passed by the time the
        # server reads it, which is a rejection rather than a same day waiver.
        "expiry_min": (now + timedelta(days=1)).strftime("%Y-%m-%d"),
        "expiry_max": (now + timedelta(days=MAX_WAIVER_DAYS)).strftime("%Y-%m-%d"),
        # For the pickers that run the other way.  A baseline is a line drawn
        # through dates that have already happened, so its calendar stops
        # today rather than starting tomorrow.
        "today": now.strftime("%Y-%m-%d"),
    }


def _walked_branches(db, user, repository: str) -> set:
    """Every branch the last scan walked in this repository.

    The boxes on this page are built out of findings, which is right for a
    chart and wrong for the word "all": a branch with nothing open has no
    findings to name it, so a repository of three branches offered one and
    "All branches" read as that one.  The seal beside the grid counts every
    branch that was walked, so the two disagreed on screen and the missing
    seal looked like a fault.

    Only for a repository.  At the estate level this is thousands of names in
    a box nobody can use, and the question it answers is not being asked.
    """
    from app.core.models import Repository

    if not repository:
        return set()
    rows = (rbac.visible_repositories(db, user)
            .filter(Repository.full_name == repository)
            .with_entities(Repository.branch_names).all())
    out = set()
    for (names,) in rows:
        try:
            walked = json.loads(names or "[]")
        except (TypeError, ValueError):
            walked = []
        out.update(name for name in walked if name)
    return out


def _branches_read_in(db, user, repository: str, since) -> set:
    """The branches the last scan walked, when that scan is inside the period.

    _walked_branches answers "what is there now", which is the right answer to
    the question it was written for and the wrong one here.  Offered under a
    period of Today, it put back every branch of a repository last read a
    month ago, which is exactly the list the period had just removed.

    The repository's own last scan carries the date, so it is asked first.  A
    scan outside the window read none of these branches during it, whatever
    the branch list says is there today.
    """
    from app.core.models import Repository

    if not repository:
        return set()
    recent = (rbac.visible_repositories(db, user)
              .filter(Repository.full_name == repository)
              .filter(Repository.last_scanned_at.isnot(None))
              .filter(Repository.last_scanned_at >= since)
              .count())
    if not recent:
        return set()
    return _walked_branches(db, user, repository)


def _labels(db) -> list:
    """The sensitivity labels this install uses."""
    from app.core import settings_store as _store

    return _store.sensitivity_labels(db)


def _priority_order():
    """Worst first, where worst means impact and certainty together.

    Severity answers "how bad if this is real"; confidence answers "is it real
    at all".  Sorting on severity alone put a low confidence audit rule above a
    finding somebody had proved, which is how a wall of criticals stops meaning
    anything.  Severity is left exactly as it is and reported as it is: this
    only changes what comes first.

    Worked out in the query rather than stored, so it is right for the
    thousands of findings that were scanned before confidence was recorded.
    """
    # Unrated confidence sits between medium and high rather than at the
    # bottom: nothing is known about it, which is not the same as knowing it
    # is weak.  A credential somebody proved still works outranks everything,
    # and a vulnerability on the CISA exploited list is not theoretical.  A
    # package nothing imports moves down the list rather than out of it.
    #
    # The formula lives in app.core.summary, so the summary tables rank a
    # page exactly the way this does.
    from app.core import summary

    return summary.priority(Finding).desc()


def _filtered_findings(db, user, params, model=None):
    """The findings query behind the Findings page, filters and all.

    Shared with the export, so the number in the file is the number on the
    screen.  Two copies of this logic would drift within a week.

    `model` is Finding by default.  A summary table carrying the same column
    names can be passed instead, once _summary_can_filter has said every
    filter asked for is one that table can answer.
    """
    model = model or Finding
    query = rbac.visible(db, user, model)

    severity = params.get("severity", "")
    kind = params.get("kind", "")
    state = params.get("state", "open")
    org = params.get("org", "")
    connection = clean_text(params.get("connection", ""), "Connection",
                            limit=120, required=False)
    search = (params.get("q", "") or "").strip()[:120]
    exception = params.get("exception", "without")
    confidence = (params.get("confidence", "") or "").strip().lower()
    if confidence not in {"", "high", "medium", "low", "unrated"}:
        confidence = ""
    # The work list by default.  Set aside is not deleted: "any" shows
    # everything, and the count beside the filter says how much there is.
    triage = (params.get("triage", "work") or "").strip().lower()
    if triage not in {"work", "any", "third_party", "advisory", "not_applicable"}:
        triage = "work"
    if exception not in {"without", "with", "any"}:
        exception = "without"

    if severity in SEVERITIES:
        query = query.filter(model.severity == Severity(severity))
    if kind in {k.value for k in FindingKind}:
        query = query.filter(model.kind == FindingKind(kind))
    if state in {s.value for s in FindingState}:
        query = query.filter(model.state == FindingState(state))
    if connection:
        query = query.filter(model.connection == connection)
    if exception == "without":
        query = query.filter(model.excepted.is_(False))
    elif exception == "with":
        query = query.filter(model.excepted.is_(True))

    # These two were shown as badges on every row and could not be filtered on,
    # so the only way to see just them was to read the whole list.  They are
    # the two the dashboard puts a number against, and a number nobody can
    # click is a number nobody can act on.
    if str(params.get("malicious", "")) == "1":
        query = query.filter(model.malicious.is_(True))
    if str(params.get("exploited", "")) == "1":
        query = query.filter(model.known_exploited.is_(True))
    if str(params.get("verified", "")) == "1":
        query = query.filter(model.verified.is_(True))
    # Findings on repositories that have been archived.  Kept out of the
    # dashboard's counts because nobody can act on them, and reachable here so
    # that the number set aside is a number somebody can open.  Never filtered
    # out of this list by default: the findings are open, they are real, and
    # the record of what a repository held when it was retired is the part
    # somebody asks about later.
    # New or changed recently.
    #
    # Two dates, because "recent" means two different things and a filter that
    # picked one would quietly hide the other.  A finding is recent if this
    # product first saw it inside the window, or if the code it sits on was
    # committed inside the window.  The first answers "what has turned up",
    # the second "what has somebody touched", and a reviewer asking for the
    # last week wants both.
    #
    # The commit date is not known for every kind: it is recorded for
    # credentials, for most code findings, and for a vulnerable package whose
    # declaring file the scanner could date, which is the last change to that
    # file rather than to any one line.  A misconfiguration has nothing to blame
    # at all.  Those still match on the date they were first seen, so nothing is
    # excluded for want of a date it could never have had.
    since_days = (params.get("since", "") or "").strip()
    if since_days in ("1", "7", "14", "30"):
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(since_days))
        query = query.filter(sa_or(model.first_found_at >= cutoff,
                                   model.committed_at >= cutoff))

    archived_want = str(params.get("archived", ""))
    if archived_want in ("0", "1"):
        _archived = (db.query(Repository.full_name)
                     .filter(Repository.archived.is_(True)).scalar_subquery())
        query = (query.filter(model.repository.in_(_archived))
                 if archived_want == "1"
                 else query.filter(model.repository.notin_(_archived)))

    # The engine's own confidence.  A rule from an audit ruleset says "somebody
    # should look at this", not "this is a bug", and being able to set those
    # aside as a group is the difference between triage and an exception per
    # finding.  Anything scanned before this was recorded is unrated.
    if confidence == "unrated":
        query = query.filter(sa_or(model.confidence.is_(None),
                                   model.confidence == ""))
    elif confidence:
        query = query.filter(model.confidence == confidence)

    # Anything scanned before there was a fidelity pass has no verdict, and has
    # to stay in the work list rather than quietly leave it.
    if triage == "work":
        query = query.filter(sa_or(model.triage.is_(None),
                                   model.triage == "",
                                   model.triage == "review"))
    elif triage != "any":
        query = query.filter(model.triage == triage)

    # Whether the application can reach the vulnerable package.  Anything
    # scanned before there was a verdict is unrated and stays in the list: a
    # blank is not the same as unlikely, and treating it as one would quietly
    # hide the backlog.
    reach = (params.get("reach", "") or "").strip().lower()
    if reach == "unrated":
        query = query.filter(sa_or(model.reachability.is_(None),
                                   model.reachability == ""))
    elif reach in {"reachable", "unlikely", "unknown"}:
        query = query.filter(model.reachability == reach)
    elif reach == "any":
        pass
    else:
        # Nothing asked for: leave out the ones the code does not reach.
        #
        # Half of every dependency finding on a real estate is a hole in a
        # package the application never imports.  It is a true statement about
        # the package and not a thing anybody can act on this week, and mixed
        # into the same list it doubles the work while changing none of it.
        #
        # Hidden, never dropped: the count of what this left out is on the page
        # with one click to see it, because a filter somebody cannot see is
        # indistinguishable from a scanner that missed something.  A blank
        # verdict still shows - it means nobody worked it out, which is not the
        # same claim as unreachable.
        query = query.filter(sa_or(model.reachability.is_(None),
                                   model.reachability != "unlikely"))

    # Findings only on branches that do not ship.  Off the list for everybody,
    # and only somebody who can change the scope can ask to see them, so they
    # can be checked before a branch goes back.  See app.core.scan_scope.
    scope = (params.get("scope", "") or "").strip().lower()
    if not rbac.can(user, "repo.scope"):
        scope = ""
    if scope == "out":
        query = query.filter(model.out_of_scope.is_(True))
    elif scope != "any":
        query = query.filter(model.out_of_scope.is_(False))

    # Which side of the baseline.  The work by default.  This does nothing at
    # all until somebody draws a line, because an organization without one has
    # every finding counted as new, so an install that never touches this sees
    # exactly what it saw before.
    since = (params.get("baseline", "new") or "new").strip().lower()
    if since not in baseline_filter.MODES:
        since = "new"
    query = baseline_filter.apply(db, query, since)

    if org:
        query = query.filter(model.organization == org)
    # A repository and a branch, exactly rather than by search.
    #
    # These exist so the heatmap on the trends page can hand somebody the rows
    # behind a number.  Done through the free text box instead, a repository
    # called api would also match one called api-gateway, and a drill down
    # that lands on a different number than the one clicked is worse than no
    # link at all.
    repo = clean_text(params.get("repo", ""), "Repository", limit=320,
                      required=False)
    if repo:
        query = query.filter(model.repository == repo)
    branch = clean_text(params.get("branch", ""), "Branch", limit=255,
                        required=False)
    if branch:
        # Every branch the finding sits on, not the one name it happens to be
        # filed under.  A finding on develop and master is one finding on two
        # branches, and asking for master has to return it.
        query = query.filter(branch_scope.matches(branch))
    # The two axes of the risk matrix, so a cell in it opens its own rows.
    # An allowlist rather than the value as it arrives, because these go
    # straight into a comparison and the list of legal answers is four words
    # long.
    impact = (params.get("impact", "") or "").strip().lower()
    if impact in ("low", "medium", "high"):
        query = query.filter(model.impact == impact)
    likelihood = (params.get("likelihood", "") or "").strip().lower()
    if likelihood in ("unlikely", "possible", "likely", "happening now"):
        query = query.filter(model.likelihood == likelihood)
    if search:
        like = f"%{search}%"
        bare = search.strip().upper()
        id_like = f"%{bare if bare.startswith('GCR-') else 'GCR-' + bare}%"
        query = query.filter(
            # The fingerprint is what a report, a SARIF upload and this page
            # all call the same finding, so pasting one in should land on it.
            Finding.fingerprint.ilike(like)
            | Finding.vuln_id.ilike(id_like)
            | Finding.organization.ilike(like)
            | Finding.repository.ilike(like)
            | Finding.branch.ilike(like)
            | Finding.branches.ilike(like)
            | Finding.file_path.ilike(like)
            | Finding.rule.ilike(like)
            | Finding.title.ilike(like)
            | Finding.package_name.ilike(like)
            | Finding.package_version.ilike(like)
            | Finding.vulnerability_id.ilike(like)
            | Finding.cwe.ilike(like)
            | Finding.author_name.ilike(like)
            | Finding.author_login.ilike(like)
            | Finding.author_email.ilike(like)
            | Finding.commit_sha.ilike(like))
    return query


def _summary_can_filter(db, params) -> bool:
    """Whether every filter in these params is one the summary tables answer.

    A text search, a recent-days window and a branch all need columns the
    summaries do not keep.  A baseline only matters once somebody has drawn
    one, and then it needs the dates.  Any of those and the page asks the
    findings table, the way it always did.
    """
    if (params.get("q", "") or "").strip():
        return False
    if (params.get("since", "") or "").strip() in ("1", "7", "14", "30"):
        return False
    if (params.get("branch", "") or "").strip():
        return False
    mode = (params.get("baseline", "new") or "new").strip().lower()
    if mode in ("new", "backlog", "") or mode not in baseline_filter.MODES:
        if baseline_filter.dates(db):
            return False
    return True


def _ago(when) -> str:
    if not when:
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - when
    minutes = int(delta.total_seconds() // 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


@router.get("/")
def dashboard(request: Request, user: User = Depends(current_user)):
    with session_scope() as db:
        everything_open = rbac.visible_findings(db, user).filter(
            Finding.state == FindingState.OPEN)

        # Findings on archived repositories are set aside, not hidden.
        #
        # The dashboard answers "how much is there to do".  Code that can no
        # longer be changed is not work anybody can do, and leaving it in means
        # a number that never goes down however much gets fixed, which is how a
        # dashboard stops being read.
        #
        # Set aside rather than removed.  They are still open, they are still
        # in the findings list, in every report and in the export, and the
        # count that was left out is shown below so nothing goes quiet.  The
        # record of what a repository held when it was retired is the part
        # somebody asks about later.
        archived_names = [name for (name,) in
                          rbac.visible_repositories(db, user)
                          .filter(Repository.archived.is_(True))
                          .with_entities(Repository.full_name).all()]
        query = everything_open.filter(Finding.out_of_scope.is_(False))
        if archived_names:
            query = query.filter(Finding.repository.notin_(archived_names))

        # From the summary tables while they match the findings exactly, and
        # from the findings otherwise.  Both give the same numbers; one reads
        # a few thousand narrow rows and the other forty thousand wide ones.
        from app.core import grouping, summary
        from app.core.models import FindingCount, FindingGroup

        use_summary = summary.fresh()
        tally_model = FindingCount if use_summary else Finding
        tally = (rbac.visible(db, user, FindingCount)
                 .filter(FindingCount.state == FindingState.OPEN)
                 if use_summary else everything_open)
        # Not deployed is set aside the same way: still open, still in the
        # findings list behind a filter, and counted below the tiles.
        not_deployed_q = tally.filter(tally_model.out_of_scope.is_(True))
        # Said only to somebody who can change the scope.  For everybody else
        # these are not there at all.
        not_deployed = ((summary.total(not_deployed_q) if use_summary
                         else not_deployed_q.count())
                        if rbac.can(user, "repo.scope") else 0)
        tally = tally.filter(tally_model.out_of_scope.is_(False))
        live = tally
        if archived_names:
            live = tally.filter(tally_model.repository.notin_(archived_names))
        set_aside = 0
        if archived_names:
            aside = tally.filter(tally_model.repository.in_(archived_names))
            set_aside = summary.total(aside) if use_summary else aside.count()

        # Two counts, and the headline is the one somebody can act on.
        #
        # The list groups by the upgrade that fixes a set of advisories, and a
        # dashboard that kept counting advisories would disagree with the page
        # it links to.  A number that contradicts the screen behind it does not
        # get explained by a tooltip, it gets distrusted, and then so does the
        # other one.
        #
        # Both are kept because both questions are real.  "How much work is
        # there" is answered in actions; "are we affected by this advisory" is
        # answered in advisories, and an auditor asking the second will not
        # take a group as an answer.
        if use_summary:
            groups_live = (rbac.visible(db, user, FindingGroup)
                           .filter(FindingGroup.state == FindingState.OPEN)
                           .filter(FindingGroup.out_of_scope.is_(False)))
            if archived_names:
                groups_live = groups_live.filter(
                    FindingGroup.repository.notin_(archived_names))
            counts = summary.actions_by_severity(groups_live)
            advisory_counts = summary.by_severity(live)
            weight = FindingCount.findings
        else:
            counts, advisory_counts = grouping.counts_by_severity(query)
            weight = literal(1)

        # Four tallies in one pass over the same rows, rather than four.
        # Malicious is counted apart from exploited because nothing about
        # upgrading a package that is itself the attack helps.
        by_kind = {}
        exploited = malicious = verified = 0
        for kind, total, known, bad, real in (live.with_entities(
                tally_model.kind,
                func.sum(weight),
                func.sum(case((tally_model.known_exploited.is_(True), weight),
                              else_=0)),
                func.sum(case((tally_model.malicious.is_(True), weight),
                              else_=0)),
                func.sum(case((tally_model.verified.is_(True), weight),
                              else_=0)))
                .group_by(tally_model.kind).all()):
            by_kind[getattr(kind, "value", str(kind))] = int(total or 0)
            exploited += int(known or 0)
            malicious += int(bad or 0)
            verified += int(real or 0)

        # The same three kinds, each thing counted once.  A secret is its own
        # identity, so it is the secret.  A code weakness is a rule in a file,
        # however many lines repeat it.  A vulnerable package is a name at a
        # version, however many advisories and repositories carry it.  Read
        # from the findings, since the summaries do not keep these columns,
        # and from the same rows as the headline numbers.
        def _joined(*cols):
            out = func.coalesce(cols[0], "")
            for col in cols[1:]:
                out = out + "\x1f" + func.coalesce(col, "")
            return out
        _once = query.with_entities(
            func.count(distinct(case(
                (Finding.kind == FindingKind.CREDENTIAL, Finding.fingerprint)))),
            func.count(distinct(case(
                (Finding.kind == FindingKind.CODE,
                 _joined(Finding.repository, Finding.file_path, Finding.rule))))),
            func.count(distinct(case(
                (Finding.kind == FindingKind.DEPENDENCY,
                 _joined(Finding.package_name, Finding.package_version)))))).one()
        unique_by_kind = {"credential": int(_once[0] or 0),
                          "code": int(_once[1] or 0),
                          "dependency": int(_once[2] or 0)}

        # Where the security sign offs stand.  Amber is counted apart from
        # green on purpose: a review that no longer describes the code is the
        # one somebody has to look at, and one number covering both would
        # report it as though it still held.
        from app.core import certification as _cert

        # Coverage, not a tally.  How many of the branches somebody could sign
        # off have been, out of how many there are to do.  A count of
        # certifications only ever goes up and says nothing about what is
        # left, which is the number anybody looking at this tile wants.
        #
        # All three queries are narrowed the same way, so a developer sees
        # coverage of their own branches and an administrator sees coverage of
        # the estate.
        #
        # Somebody who sees everything is shown the plain number they have
        # always been shown, because for them the tile has always meant the
        # whole estate and changing what a familiar number counts is worse
        # than leaving it.
        certified = _cert.counts(db)
        certified["scoped"] = not rbac.sees_everything(user)
        if certified["scoped"]:
            mine = _cert.counts(db, rbac.visible_certifications(db, user))
            certified["mine_stale"] = mine["stale"]
            certified.update(_cert.coverage(
                db,
                rbac.visible_repositories(db, user),
                rbac.visible_certifications(db, user),
                rbac.visible_certification_exemptions(db, user)))
            certified["visible_repositories"] = (
                rbac.visible_repositories(db, user).count())

        # The fifteen worst.  The summary narrows the candidates to the
        # findings that can possibly be among them, and the findings table
        # still does the ordering, so ties break on last seen as they always
        # did.
        ranked = query
        if use_summary:
            candidates = summary.top_candidates(groups_live, 15)
            if candidates is not None:
                ranked = query.filter(Finding.id.in_(candidates or [0]))
        worst = (ranked.order_by(_priority_order(), Finding.last_found_at.desc())
                 .limit(15).all())

        top_repos = [(name, int(n or 0)) for name, n in
                     live.with_entities(tally_model.repository,
                                        func.sum(weight).label("n"))
                     .group_by(tally_model.repository)
                     .order_by(func.sum(weight).desc(),
                               tally_model.repository)
                     .limit(8).all()]

        runs = (db.query(ScanRun).order_by(ScanRun.started_at.desc())
                .limit(5).all())

        context = _shared(db, user)
        context.update(active_page="dashboard", counts=counts, by_kind=by_kind,
                       unique_by_kind=unique_by_kind,
                       exploited=exploited, verified=verified, worst=worst,
                       malicious=malicious,
                       top_repos=top_repos, runs=runs,
                       certified=certified,
                       advisory_counts=advisory_counts,
                       advisory_total=sum(advisory_counts.values()),
                       archived_set_aside=set_aside,
                       archived_repositories=len(archived_names),
                       not_deployed=not_deployed,
                       total=sum(counts.values()))
        return page(request, "dashboard.html", **context)


@router.get("/trends")
def trends_page(request: Request, user: User = Depends(current_user)):
    """How the numbers have moved, at whatever scope somebody asks for.

    Every filter narrows the same query, and the report is generated from
    exactly this scope, so what somebody exports is what they were looking at
    rather than a second thing assembled separately that might disagree.
    """
    from datetime import datetime, timedelta, timezone

    from app.core import trends

    rbac.require(user, "trend.read")
    params = request.query_params

    basis = (params.get("basis", "actions") or "actions").strip().lower()
    if basis not in ("actions", "advisories"):
        basis = "actions"

    organization = clean_text(params.get("org", ""), "Organization",
                              limit=255, required=False)
    repository = clean_text(params.get("repo", ""), "Repository",
                            limit=320, required=False)
    branch = clean_text(params.get("branch", ""), "Branch",
                        limit=255, required=False)
    connection = clean_text(params.get("connection", ""), "Connection",
                            limit=120, required=False)
    try:
        window = int(params.get("days", "30"))
    except ValueError:
        window = 30
    if window not in (1, 7, 30, 90, 365):
        window = 30

    # A repository names its own organization, so picking one and then a
    # repository somewhere else would silently return nothing.  The narrower
    # of the two wins, which is what somebody clicking through a drill down
    # expects.
    if repository and "/" in repository:
        organization = repository.split("/")[0]

    since = datetime.now(timezone.utc) - timedelta(days=window)

    with session_scope() as db:
        base = rbac.visible_trends(db, user)
        scope = {"organization": organization, "repository": repository,
                 "branch": branch, "connection": connection, "since": since}

        points = trends.series(db, basis=basis, base=base, **scope)

        # The heatmap reads the findings, not the daily rollup.
        #
        # Every cell links to the rows behind it, and the rollup is only
        # written when a scan runs, so on any day without one the number in
        # the cell and the number on the page it opens would disagree.  A
        # drill down that lands on a different number is worse than no link,
        # and it is the kind of wrong that makes somebody stop believing the
        # rest of the screen.  It is also the same call the report makes, so
        # the page and the document cannot drift apart.
        from app.core import report_data

        axis = ("branch" if repository else
                "repository" if organization else "organization")

        # What this period actually read, and what the page may therefore name.
        #
        # The chart honoured the period because it is drawn from the rollup.
        # Everything beside it was drawn from the findings as they stand now,
        # and a finding carries no notion of a period at all, so Today still
        # listed every branch and repository the estate has ever held.
        #
        # The rollup cannot answer this either, which is the part that is easy
        # to get wrong.  It snapshots every open finding in the estate each
        # time any scan anywhere finishes, so a repository nobody has looked
        # at in a month still has a row dated today.  The day on that row is
        # when the snapshot was taken, not when the code was read.
        #
        # The repository's own last scan is the only record of when this code
        # was read, so that is what the period is applied to.  It is the same
        # evidence the staleness note further down this page already uses.
        read_in_period = {name for (name,) in
                          rbac.visible_repositories(db, user)
                          .filter(Repository.last_scanned_at.isnot(None))
                          .filter(Repository.last_scanned_at >= since)
                          .with_entities(Repository.full_name).all() if name}
        here = set(read_in_period)
        if repository:
            here &= {repository}
        elif organization:
            here = {name for name in here
                    if name.split("/")[0] == organization}

        # Which rows the period leaves, by the name each row carries.
        named = (here if axis == "repository" else
                 _branches_read_in(db, user, repository, since)
                 if axis == "branch" else
                 {name.split("/")[0] for name in here})

        # Applied to the rows and never to the counts.
        #
        # Every total on this table is a link, and the list it opens has no
        # notion of a period at all.  Narrowing the query behind the number
        # would leave an organization cell reading nine over a list of ten,
        # and a drill down that lands on a different number is worse than no
        # link: it is the kind of wrong that makes somebody stop believing the
        # rest of the screen.  So the period decides which rows are here, and
        # a row that is here still says what clicking it will show.

        # Every row at this scope, not the busiest handful.  The table sorts
        # and pages now, and paging over a list that was already cut to twelve
        # would offer a second page of a truncation: the rows nobody can reach
        # are exactly the ones somebody sorting by a column is looking for.
        # Counted from the summary table while it matches the findings.  Not
        # for a branch: matching one needs each finding's branch list.
        from app.core import summary
        from app.core.models import FindingBranch, FindingCount

        counted = (FindingCount if summary.fresh() and not branch
                   and axis != "branch" else Finding)
        every_row = [row for row in report_data.hotspots(
            report_data._scoped(rbac.visible(db, user, counted),
                                organization, repository, branch, connection,
                                model=counted),
            axis=axis, limit=None, model=counted) if row["name"] in named]
        grid = {"axis": axis, "rows": every_row}
        # The matrix names no repository and no branch, so there is nothing on
        # it for the period to remove, and it is the same query the totals in
        # the table are counted from.  Narrowing one and not the other is how
        # two panels on one screen start disagreeing.
        matrix = report_data.risk_matrix(
            report_data._scoped(rbac.visible(db, user, counted),
                                organization, repository, branch, connection,
                                model=counted),
            model=counted)
        # What the two panels above left out because the host retired the
        # repository.  Said on the page rather than left to be noticed: a
        # figure that quietly got smaller is the one nobody can explain later.
        set_aside = report_data.archived_aside(
            rbac.visible(db, user, counted),
            organization, repository, branch, connection, model=counted)
        # A seal, only where everything on screen is signed off.
        #
        # Scoped through the same three queries the dashboard tile uses, so a
        # developer is never shown a mark earned by branches they cannot see.
        from app.core import certification as _cert

        seal = _cert.scope_seal(
            db,
            rbac.visible_repositories(db, user),
            rbac.visible_certifications(db, user),
            rbac.visible_certification_exemptions(db, user),
            organization, repository, branch)
        # The same mark, per row, where the rows are repositories.
        #
        # The seal above is about the whole scope, so a page listing forty
        # repositories of which six are fully signed off shows no seal at all,
        # and the six have nothing on screen saying so.  Worked out once for
        # the list rather than once per row: a table cannot afford a query
        # each, and a mark worked out by a different rule than the seal next
        # to it is two marks that will disagree.
        sealed = (_cert.sealed_repositories(
            db,
            rbac.visible_repositories(db, user),
            rbac.visible_certifications(db, user),
            rbac.visible_certification_exemptions(db, user))
            if axis == "repository" else set())
        options = trends.choices(db, base=base, connection=connection,
                                 organization=organization,
                                 repository=repository, since=since,
                                 within=read_in_period)
        # The daily rollup files each finding under one branch name, so a
        # branch that only ever comes second in a finding's list is missing
        # from that box even though the table below counts it.  Offer it, or
        # the reader is told master has nothing on it by a filter that cannot
        # name master.
        #
        # Only where the period reaches it.  The finding has to sit in a
        # repository this period read and have been seen inside it, and the
        # branches the last scan walked count only when that scan itself
        # landed inside the window, or this union would put straight back
        # every name the period had just taken out.
        if summary.branches_fresh():
            # Not DISTINCT, for the same reason as on the findings list.
            mentioned = {name for (name,) in report_data._scoped(
                rbac.visible(db, user, FindingBranch), organization,
                repository, "", connection, model=FindingBranch)
                .filter(FindingBranch.repository.in_(sorted(here)))
                .filter(FindingBranch.last_found_at >= since)
                .with_entities(FindingBranch.name).all() if name}
        else:
            mentioned = set(branch_scope.names(report_data._scoped(
                rbac.visible_findings(db, user), organization, repository,
                "", connection)
                .filter(Finding.repository.in_(sorted(here)))
                .filter(Finding.last_found_at >= since)))
        options["branches"] = sorted(
            set(options.get("branches") or []) | mentioned
            | _branches_read_in(db, user, repository, since))

        # Where the recorded history starts.  Everything before it was worked
        # out from when findings were first seen and resolved, and its
        # severities are today's applied backwards, so the chart marks it
        # rather than drawing one line across two different things.
        first_snapshot = None
        for point in points:
            if point["source"] == trends.SNAPSHOT:
                first_snapshot = point["day"]
                break

        # How old the newest reading is.
        #
        # The rollup writes a row per branch and severity out of what is open,
        # so a scope with nothing open writes no row at all.  There is no zero
        # row, which means a scope that emptied and a scope that stopped being
        # scanned draw the same picture: a line that ends and says nothing.
        # The chart then stretches whatever days it has across the full width,
        # so three days of a seven day window look like seven.
        #
        # The document already says this.  The screen did not, so somebody
        # reading a flat line that stopped two days ago had no way to tell it
        # was not today's answer.
        newest = points[-1]["day"] if points else None
        stale_days = 0
        if newest is not None:
            stale_days = (datetime.now(timezone.utc).date() - newest.date()).days

        from app.core import charts

        # The shade on a cell is worked out against every row at this scope,
        # before any of it is cut into pages.  Doing it per page would make
        # the darkest row on page four look as bad as the worst in the
        # estate, which is a picture that changes meaning when you turn a
        # page.
        shaded = charts.heat_levels(every_row)

        # Which column somebody asked to sort on, and which way.  Nothing
        # means the order the rows arrive in, which is worst first by grade
        # rather than by volume: two hundred informational findings should
        # not outrank three criticals unless somebody asks for that.
        sort = (params.get("sort", "") or "").strip().lower()
        if sort not in ("name", "critical", "high", "medium", "low", "info",
                        "total"):
            sort = ""
        direction = (params.get("dir", "") or "").strip().lower()
        if direction not in ("asc", "desc"):
            direction = "asc" if sort == "name" else "desc"
        if sort == "name":
            shaded.sort(key=lambda row: str(row.get("name", "")).lower(),
                        reverse=(direction == "desc"))
        elif sort:
            # A stable sort over a list that is already worst first, so rows
            # tied on the chosen column stay in a sensible order rather than
            # in whatever order the database handed them over.
            shaded.sort(key=lambda row: row.get(sort, 0),
                        reverse=(direction == "desc"))

        per_rows = 25
        try:
            heat_page_no = int(params.get("hpage", "1"))
        except ValueError:
            heat_page_no = 1
        heat_pages = max(1, (len(shaded) + per_rows - 1) // per_rows)
        heat_page_no = min(max(1, heat_page_no), heat_pages)
        first_row = (heat_page_no - 1) * per_rows
        page_rows = shaded[first_row:first_row + per_rows]

        # The scope this page is at, as a query string, so every link on it
        # carries the filters instead of rebuilding them where they could be
        # read differently.
        scope_query = urlencode({name: value for name, value in (
            ("org", organization), ("repo", repository),
            ("branch", branch), ("connection", connection),
            ("basis", basis), ("days", window)) if value})

        context = _shared(db, user)
        context.update(
            active_page="trends", points=points, heat=grid,
            matrix=matrix,
            chart=charts.stacked_area(points),
            heat_rows=page_rows,
            heat_sealed=sealed,
            heat_sort=sort, heat_dir=direction,
            heat_total=len(shaded), heat_page_no=heat_page_no,
            heat_pages=heat_pages, heat_per=per_rows,
            heat_first=first_row + 1 if page_rows else 0,
            heat_last=first_row + len(page_rows),
            scope_query=scope_query,
            basis=basis, window=window, options=options,
            first_snapshot=first_snapshot,
            newest_reading=newest, stale_days=stale_days,
            archived_aside=set_aside, seal=seal,
            filters={"org": organization, "repo": repository,
                     "branch": branch, "connection": connection,
                     "basis": basis, "days": window},
            can_report=rbac.can(user, "report.generate"),
            # The report is built from exactly this scope, so the link
            # carries the filters rather than rebuilding them at the far end
            # where they could be read differently.
            report_query=urlencode({name: value for name, value in (
                ("org", organization), ("repo", repository),
                ("branch", branch), ("connection", connection),
                ("basis", basis), ("days", window)) if value}),
            scope_label=(branch and f"{repository} on {branch}")
                        or repository or organization or "every repository",
        )
        return page(request, "trends.html", **context)


@router.get("/trends/report")
def trends_report(request: Request, user: User = Depends(current_user)):
    """The trends view as a document, for people who will not open the app.

    Built from the same filters the page uses and from the same scoped query,
    so a report can never contain a repository the person asking for it could
    not open directly, and can never disagree with the screen it came from.
    """
    from datetime import datetime, timedelta, timezone

    from app.core import certification as _cert
    from app.core import charts, report_text, settings_store, trends

    rbac.require(user, "report.generate")
    params = request.query_params

    basis = (params.get("basis", "actions") or "actions").strip().lower()
    if basis not in ("actions", "advisories"):
        basis = "actions"
    organization = clean_text(params.get("org", ""), "Organization",
                              limit=255, required=False)
    repository = clean_text(params.get("repo", ""), "Repository",
                            limit=320, required=False)
    branch = clean_text(params.get("branch", ""), "Branch",
                        limit=255, required=False)
    connection = clean_text(params.get("connection", ""), "Connection",
                            limit=120, required=False)
    try:
        window = int(params.get("days", "30"))
    except ValueError:
        window = 30
    if window not in (1, 7, 30, 90, 365):
        window = 30

    now = datetime.now(timezone.utc)
    since = now - timedelta(days=window)

    with session_scope() as db:
        base = rbac.visible_trends(db, user)
        points = trends.series(db, basis=basis, base=base,
                               organization=organization, repository=repository,
                               branch=branch, connection=connection, since=since)

        # The assessment itself, read from the findings rather than from the
        # daily rollup.  The rollup knows how many there were and nothing
        # about what they are, and a report that only knows the first is a
        # chart with a cover page on it.
        from app.core import report_data

        axis = ("branch" if repository else
                "repository" if organization else "organization")
        data = report_data.assemble(
            db, rbac.visible_findings(db, user),
            organization=organization, repository=repository,
            branch=branch, connection=connection, axis=axis)
        heat_rows = charts.heat_levels(data["hotspots"])
        grid = {"axis": axis, "rows": data["hotspots"]}
        matrix = report_data.risk_matrix(
            report_data._scoped(rbac.visible_findings(db, user),
                                organization, repository, branch, connection))

        scope_label = ((branch and repository and "%s on %s" % (repository, branch))
                       or repository or organization or "All repositories")

        # The sign off, where this report is about exactly the thing that was
        # signed off.  Only a single branch of a single repository: a
        # certification covers one branch, and putting a seal on a report
        # covering forty of them would be claiming something nobody said.
        seal = None
        # Only a repository this person may see.  The seal carries the
        # reviewer's name and note, and whether one exists at all says the
        # repository and branch do; asking for somebody else's printed both.
        allowed = rbac.visible_repository_names(db, user)
        if repository and branch and (allowed is None or repository in allowed):
            row = _cert.for_branch(db, repository, branch)
            if row is not None:
                state = _cert.status(db, row)
                # Only a person's.  The seal on the cover says somebody read
                # this branch and put their name to it, which is not what a
                # scan finding nothing says, and the cover of a report is the
                # last place to blur that.  An automatic badge is still shown
                # on every page in the app, and the sentence further down this
                # report counts it separately.
                if state["state"] == _cert.ACTIVE and not row.automatic:
                    seal = {"repository": repository, "branch": branch,
                            "by": row.certified_by, "at": row.certified_at,
                            "expires": row.expires_at, "note": row.note}

        pass

        # The name on the cover.  Whatever the person is actually called, and
        # their sign in name only when that is all there is: a document that
        # says "Prepared for admin" reads like something nobody checked.
        prepared_for = (getattr(user, "display_name", "") or "").strip() \
            or (getattr(user, "email", "") or "").strip() \
            or getattr(user, "username", "")

        context = {
            "title": "Security Assessment",
            "scope_label": scope_label,
            "prepared_for": prepared_for,
            "organization_name": settings_store.get(db, "report.organization_name", ""),
            "logo": (settings_store.get(db, "report.logo", "") or "").strip(),
            "footer_text": settings_store.get(db, "report.footer", ""),
            "period_label": "%s to %s" % (since.strftime("%d %B %Y"),
                                          now.strftime("%d %B %Y")),
            "issued_at": now.strftime("%d %B %Y"),
            "basis": basis,
            "latest": data["severity"],
            "chart": charts.stacked_area(points, width=880, height=250),
            "heat": grid,
            "heat_rows": heat_rows,
            "matrix": matrix,
            "summary": report_text.assessment(data, scope_label),
            "context": report_text.context(data),
            "standing": report_text.standing_sentence(data),
            "movement": report_text.headline(scope_label, points, basis),
            "basis_note": report_text.basis_note(basis),
            "history_note": report_text.history_note(points),
            "hotspot_note": report_text.hotspot_note(data["hotspots"], axis),
            "certified_note": report_text.certified_note(
                _cert.counts(db, rbac.visible_certifications(db, user))),
            "seal": seal,
            "recommendations": report_text.what_matters(data),
            "data": data,
        }
        html = render_partial("report_pdf.html", **context)

    try:
        from weasyprint import HTML
    except Exception:
        log.exception("weasyprint is not available")
        raise HTTPException(
            status_code=503,
            detail="Reports need the typesetting libraries, which are not "
                   "installed on this server.")

    pdf = HTML(string=html, base_url=str(request.base_url),
               url_fetcher=report_url_fetcher(context.get("logo") or "")
               ).write_pdf()

    stem = (repository or organization or "all-repositories").replace("/", "-")
    name = "security-assessment-%s-%s.pdf" % (stem, now.strftime("%Y-%m-%d"))
    log.info("report generated for %s by %s", scope_label,
             getattr(user, "username", "?"))
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="%s"' % name})


@router.get("/findings")
def findings(request: Request, user: User = Depends(current_user)):
    params = request.query_params
    severity = params.get("severity", "")
    kind = params.get("kind", "")
    # "any" is every state.  The query already reads anything it does not
    # recognise as no state filter at all, so it is named that here and the
    # dropdown says what the list underneath it is actually showing.
    state = params.get("state", "open")
    if state not in {s.value for s in FindingState}:
        state = "any"
    org = params.get("org", "")
    # Carried so the paging links keep them.  The builder applies these;
    # they are read here only so a second page of a drilled down list is
    # still the same list.
    repo_filter = clean_text(params.get("repo", ""), "Repository",
                             limit=320, required=False)
    branch_filter = clean_text(params.get("branch", ""), "Branch",
                               limit=255, required=False)
    search = (params.get("q", "") or "").strip()[:120]
    # without: the work list.  with: what somebody signed off.  any: both.
    connection = clean_text(params.get("connection", ""), "Connection",
                            limit=120, required=False)
    exception = params.get("exception", "without")
    if exception not in {"without", "with", "any"}:
        exception = "without"
    confidence = (params.get("confidence", "") or "").strip().lower()
    if confidence not in {"", "high", "medium", "low", "unrated"}:
        confidence = ""
    # The work list by default.  Set aside is not deleted: "any" shows
    # everything, and the count beside the filter says how much there is.
    triage = (params.get("triage", "work") or "").strip().lower()
    if triage not in {"work", "any", "third_party", "advisory", "not_applicable"}:
        triage = "work"
    reach = (params.get("reach", "") or "").strip().lower()
    if reach not in {"", "reachable", "unlikely", "unknown", "unrated"}:
        reach = ""
    scope = (params.get("scope", "") or "").strip().lower()
    if scope not in {"", "any", "out"} or not rbac.can(user, "repo.scope"):
        scope = ""
    since = (params.get("baseline", "new") or "new").strip().lower()
    if since not in baseline_filter.MODES:
        since = "new"
    # How far back "recent" reaches, empty meaning all of it.  Read here as
    # well as in the query so the dropdown comes back on what was chosen.
    since_choice = (params.get("since", "") or "").strip()
    if since_choice not in ("1", "7", "14", "30"):
        since_choice = ""
    # The three the dashboard links to.  Read here so sorting, paging and a
    # bulk action keep them: without that, sorting the live credentials list
    # by any column came back as every finding there is.
    flags = {name: "1" for name in ("exploited", "verified", "malicious")
             if str(params.get(name, "")) == "1"}
    sort = (params.get("sort", "") or "").strip().lower()
    if sort not in SORTABLE:
        sort = "priority"
    # One row per thing somebody would do, rather than one per advisory.
    #
    # On by default because the ungrouped list is the one that produced the
    # complaint: fifty six rows for one apt upgrade.  Off is a click away and
    # the count of what was folded is on every row, so nothing is hidden, it
    # is only counted once.
    grouped = (params.get("group", "action") or "action").strip().lower()
    if grouped not in {"action", "none"}:
        grouped = "action"
    # Sorting by a column is a statement about individual rows, so choosing
    # one turns the folding off rather than silently ignoring the click.
    if sort != "priority":
        grouped = "none"
    direction = "asc" if (params.get("dir", "") or "").lower() == "asc" else "desc"
    try:
        offset = max(0, int(params.get("offset", "0")))
    except ValueError:
        offset = 0

    # How many rows at a time.  A thousand is a lot of markup, so it is a
    # choice rather than the default.
    try:
        limit = int(params.get("per_page", "100"))
    except ValueError:
        limit = 100
    if limit not in PAGE_SIZES:
        limit = 100

    with session_scope() as db:
        # The same builder the export uses, so the count on the page and the
        # rows in the file are always the same set.
        query = _filtered_findings(db, user, params)

        # The summary tables answer the default view and most filtered ones,
        # and only while they match the findings exactly.  Anything else is
        # asked of the findings table, which is always right and slower.
        from app.core import summary
        from app.core.models import FindingBranch, FindingCount, FindingGroup

        counted = summary.fresh() and _summary_can_filter(db, params)

        def _how_many(wanted, narrow=None):
            """Findings matching these params, from the summary when it can."""
            if summary.fresh() and _summary_can_filter(db, wanted):
                picked = _filtered_findings(db, user, wanted, model=FindingCount)
                return summary.total(narrow(FindingCount, picked)
                                     if narrow else picked)
            picked = _filtered_findings(db, user, wanted)
            return (narrow(Finding, picked) if narrow else picked).count()

        def _visible_count(narrow=None):
            model = FindingCount if summary.fresh() else Finding
            picked = rbac.visible(db, user, model)
            if narrow:
                picked = narrow(model, picked)
            return (summary.total(picked) if model is FindingCount
                    else picked.count())

        if grouped == "action":
            from app.core import grouping
            paged = None
            if counted and state == "open":
                paged = grouping.page_of_groups_from_summary(
                    db, query,
                    _filtered_findings(db, user, params, model=FindingGroup),
                    offset, limit)
            groups, total = (paged if paged is not None else
                             grouping.page_of_groups(db, query, offset, limit))
            rows = [g["lead"] for g in groups]
            # Findings behind the page, for the tick boxes and the counts.
            folded = sum(g["count"] for g in groups) - len(groups)
        else:
            from app.core import grouping
            folded = 0
            total = query.count()
            rows = (query.order_by(*_sort_order(sort, direction))
                    .offset(offset).limit(limit).all())
            # One group per finding, so the template has one shape to render
            # rather than two branches that drift apart.
            groups = [grouping.summarize([f]) for f in rows]

        # How many the default view is holding back, so the page can say so.
        # Only worth asking when nobody chose a reachability filter, which is
        # the one case where something is being left out without being asked
        # for.
        # Against findings, never against groups.  `total` counts rows on the
        # screen and switches meaning with the fold, so subtracting from it
        # would report a number of hidden findings that changed when somebody
        # pressed a button that hides nothing.
        hidden_unreachable = 0
        if not (params.get("reach", "") or "").strip():
            wider = dict(params)
            wider["reach"] = "any"
            # The default leaves out exactly the unlikely ones, so counting
            # those is the difference, in one scan instead of two.
            hidden_unreachable = _how_many(
                wider, lambda m, q: q.filter(m.reachability == "unlikely"))

        # And the ones on branches that do not ship, counted the same way.
        hidden_out_of_scope = 0
        if not scope and rbac.can(user, "repo.scope"):
            hidden_out_of_scope = _how_many(
                dict(params, scope="any"),
                lambda m, q: q.filter(m.out_of_scope.is_(True)))

        # The lists behind the four "where" dropdowns.
        #
        # Each one is narrowed by the choices above it and not by itself.  Not
        # by itself, because a dropdown that only offers what is already
        # selected is a dropdown you cannot change your mind with.  Narrowed by
        # the ones above, because the whole point of a drill down is that
        # picking an organization stops offering the four hundred repositories
        # in the other twenty five.
        #
        # These deliberately ignore severity, state, triage and the rest.  A
        # repository whose findings are all waived should still be pickable, or
        # the filter that would show you them is the one that hid it.
        # Read from the summaries when they are current, since these ignore
        # every filter but the three above them.
        where = FindingCount if summary.fresh() else Finding

        def _narrowed(model=None, **fixed):
            model = model or where
            picked = rbac.visible(db, user, model)
            if fixed.get("connection"):
                picked = picked.filter(model.connection == fixed["connection"])
            if fixed.get("org"):
                picked = picked.filter(model.organization == fixed["org"])
            if fixed.get("repo"):
                picked = picked.filter(model.repository == fixed["repo"])
            return picked

        def _choices(name, **fixed):
            column = getattr(where, name)
            picked = _narrowed(**fixed)
            return sorted({r[0] for r in
                           picked.with_entities(column).distinct().all() if r[0]})

        orgs = _choices("organization", connection=connection)
        repo_choices = _choices("repository", connection=connection, org=org)
        # Not the primary branch column: a branch that only ever comes second
        # in a finding's list still has findings on it, and a box that cannot
        # offer it reads as a branch nobody has scanned.
        if summary.branches_fresh():
            # Not DISTINCT: the database would fold two names that differ
            # only by case into one, and git treats them as two branches.
            branch_choices = sorted({r[0] for r in _narrowed(
                FindingBranch, connection=connection, org=org, repo=repo_filter)
                .with_entities(FindingBranch.name).all() if r[0]})
        else:
            branch_choices = branch_scope.names(_narrowed(
                Finding, connection=connection, org=org, repo=repo_filter))
        # A selection that the narrowing has made unavailable still has to be
        # in its own list, or the box would show something other than what is
        # actually being filtered on and the page would be lying about itself.
        for chosen, options in ((org, orgs), (repo_filter, repo_choices),
                                (branch_filter, branch_choices)):
            if chosen and chosen not in options:
                options.append(chosen)
                options.sort()

        context = _shared(db, user)
        context.update(
            active_page="findings", rows=rows, total=total, offset=offset,
            limit=limit, orgs=orgs, repo_choices=repo_choices,
            branch_choices=branch_choices, severities=SEVERITIES,
            kinds=[k.value for k in FindingKind],
            states=[s.value for s in FindingState],
            filters={"severity": severity, "kind": kind, "state": state,
                     "org": org, "q": search, "exception": exception,
                     "repo": repo_filter, "branch": branch_filter,
                     "connection": connection, "per_page": limit,
                     "confidence": confidence, "sort": sort, "dir": direction,
                     "triage": triage, "baseline": since, "reach": reach,
                     "scope": scope,
                     "since": since_choice, "group": grouped,
                     "exploited": flags.get("exploited", ""),
                     "verified": flags.get("verified", ""),
                     "malicious": flags.get("malicious", "")},
            show_discovered=bool(flags.get("verified")) or kind == "credential",
            hidden_unreachable=hidden_unreachable,
            hidden_out_of_scope=hidden_out_of_scope,
            groups=groups, grouped=grouped, folded=folded,
            page_sizes=PAGE_SIZES,
            connections=sorted({c[0] for c in
                                rbac.visible(db, user, where)
                                .with_entities(where.connection).distinct().all()
                                if c[0]}),
            # Everything except offset, so the paging links keep the filters
            # without carrying the old page number along with them.
            page_query=urlencode({name: value for name, value in
                                  (("severity", severity), ("kind", kind),
                                   ("state", state), ("org", org),
                                   ("repo", repo_filter),
                                   ("branch", branch_filter),
                                   ("q", search), ("exception", exception),
                                   ("confidence", confidence),
                                   ("reach", reach),
                                   ("scope", scope),
                                   ("connection", connection),
                                   ("triage", triage if triage != "work" else ""),
                                   ("baseline", since if since != "new" else ""),
                                   ("since", since_choice),
                                   ("exploited", flags.get("exploited", "")),
                                   ("verified", flags.get("verified", "")),
                                   ("malicious", flags.get("malicious", "")),
                                   ("sort", sort if sort != "priority" else ""),
                                   ("dir", direction if sort != "priority" else ""))
                                  if value}),
            excepted_total=_visible_count(
                lambda m, q: q.filter(m.excepted.is_(True))),
            # How much the fidelity pass set aside, so nothing feels concealed.
            #
            # Counted with the lane filter lifted and everything else kept: the
            # builder applies the lane too, so asking it for the work list and
            # then counting what is not in the work list always gave zero.
            set_aside=(_how_many(
                dict(params, triage="any"),
                lambda m, q: q.filter(m.triage.in_(
                    ["third_party", "advisory", "not_applicable"])))
                if triage == "work" else 0),
            # What is behind the line, counted with every other filter still
            # on, so switching the filter over lands on this same number.
            backlog_total=(_how_many(dict(params, baseline="backlog"))
                           if since == "new" else 0),
            baseline_dates=baseline_filter.dates(db),
            can_set_baseline=rbac.can(user, "settings.write"),
            can_waive=rbac.can(user, "waiver.request"),
            can_delete=rbac.can(user, "findings.delete"),
            can_regrade=rbac.can(user, "finding.regrade"),
            can_validate_ai=_can_validate_ai(db, user),
            # Not the filtered count.  The delete-everything dialog has to
            # say how many rows actually go, which is rarely the number on
            # screen.
            all_total=(_visible_count()
                       if rbac.can(user, "findings.delete") else 0),
            **_expiry_window(90),
        )
        return page(request, "findings.html", **context)


# Registered before /findings/{finding_id}, or "export" is read as an id and
# the route below answers with a 422 about parsing an integer.
@router.get("/findings/export")
def export_findings(request: Request, user: User = Depends(current_user)):
    """Everything the current filters match, as a file.

    Not the page somebody is looking at: the whole set behind the count.  Filter
    to the 858 critical ones, press export, get 858 rows.

    It runs through the same scope filter as the page, so a developer exporting
    "all critical" gets all critical in their own repositories.  That is why
    this one is open to them while the whole estate report on the Reports page
    is not.
    """
    import csv as csv_module
    import io as io_module
    import json as json_module

    from fastapi.responses import StreamingResponse

    from app.core.reports import CSV_COLUMNS, as_dict, as_row, repo_facts

    rbac.require(user, "findings.export")

    params = request.query_params
    wants = "json" if params.get("format", "csv").lower() == "json" else "csv"

    with session_scope() as db:
        query = _filtered_findings(db, user, params)
        rows = (query.order_by(_priority_order(), Finding.last_found_at.desc())
                .limit(MAX_EXPORT_ROWS + 1).all())
        trimmed = len(rows) > MAX_EXPORT_ROWS
        rows = rows[:MAX_EXPORT_ROWS]

        facts = repo_facts(db, rows)

        if wants == "json":
            body = json_module.dumps({
                "generator": {"name": APP_NAME, "version": VERSION},
                "generated_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "filters": {name: value for name, value in params.items()
                            if name not in {"format", "offset"}},
                "count": len(rows),
                "truncated": trimmed,
                "findings": [as_dict(row, facts) for row in rows],
            }, indent=2) + "\n"
        else:
            buffer = io_module.StringIO()
            writer = csv_module.DictWriter(buffer, fieldnames=CSV_COLUMNS,
                                           extrasaction="ignore",
                                           lineterminator="\n")
            writer.writeheader()
            for row in rows:
                writer.writerow(spreadsheet_row(as_row(row, facts)))
            body = buffer.getvalue()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    media = "application/json" if wants == "json" else "text/csv"
    return StreamingResponse(
        io_module.StringIO(body), media_type=media,
        headers={"Content-Disposition":
                 f'attachment; filename="findings-{stamp}.{wants}"'})


@router.get("/findings/{finding_id}")
def finding_detail(finding_id: int, request: Request, msg: str = "",
                   kind: str = "", user: User = Depends(current_user)):
    with session_scope() as db:
        row = rbac.visible_finding(db, user, finding_id)
        # Only on branches that do not ship is not there for anybody who
        # cannot change the scope, link or no link.
        if row is not None and row.out_of_scope and not rbac.can(user, "repo.scope"):
            row = None
        if row is None:
            # Out of scope and does not exist look the same on purpose.
            raise HTTPException(status_code=404, detail="No such finding.")

        waiver = db.query(Waiver).filter(Waiver.finding_id == row.id).one_or_none()
        # The same rule as the Exceptions page: somebody who cannot approve
        # one sees only their own.  An exception is an argument a person made,
        # with their reasons in it, and two developers sharing a repository
        # were reading each other's here.
        if (waiver is not None and not rbac.can(user, "waiver.approve")
                and (waiver.requested_by or "").lower() != user.username.lower()):
            waiver = None

        # Which host it came from, so the link out is not labeled GitHub for
        # everybody.  The connection knows; fall back on the link itself for a
        # finding that predates connections.
        from app.core import connections as connection_store

        provider = ""
        if row.connection:
            source = connection_store.by_name(db, row.connection)
            provider = getattr(source, "provider", "") or ""
        if not provider:
            host = (row.url or "").lower()
            provider = ("gitlab" if "gitlab" in host
                        else "bitbucket" if "bitbucket" in host
                        else "github" if "github" in host else "")
        host_name = {"github": "GitHub", "gitlab": "GitLab",
                     "bitbucket": "Bitbucket", "azure": "Azure Repos",
                     "assembla": "Assembla", "beanstalk": "Beanstalk",
                     "codecommit": "AWS CodeCommit",
                     "gcsr": "Cloud Source Repositories",
                     "gitea": "Gitea", "forgejo": "Forgejo",
                     "subversion": "Subversion",
                     "perforce": "Perforce"}.get(provider, "")

        # What the repository is and who can reach it.  A hardcoded password
        # means one thing in the payment gateway and another in a brochure
        # site, and the person reading this is the one who has to tell them
        # apart.  The impact half of the assessment reads the same two fields.
        # Every branch this finding is on, not just the one it was filed
        # against.  A finding on the default branch is in what ships; the same
        # finding on one stale feature branch is not the same problem, and the
        # page cannot let somebody tell them apart without saying which.
        try:
            on_branches = json.loads(row.branches or "[]") or []
        except (TypeError, ValueError):
            on_branches = []
        if row.branch and row.branch not in on_branches:
            on_branches.insert(0, row.branch)

        # Has security signed this branch off, and does that still describe
        # what is there.  head_sha is left empty deliberately: the finding's
        # own commit is where the finding was found, not where the branch is
        # now, and using it would report staleness that is not there.  The
        # signal that does the work is whether findings have arrived since.
        from app.core import certification as certification_store

        certification = certification_store.status(
            db, certification_store.for_branch(db, row.repository, row.branch))
        # And whether anybody has said a sign off is not expected here.  Read
        # separately because it is a separate claim: it does not certify the
        # branch, it takes it out of the count of branches still owed one.
        exemption = certification_store.exemption(db, row.repository, row.branch)
        # What signing this branch off would be covering.
        #
        # The form asked somebody to vouch for a branch without telling them
        # what was open on it.  One was signed off twelve minutes after a
        # medium advisory landed on it, by somebody who had no way of knowing
        # from the page in front of them.  The badge was right and the reader
        # was not informed, which is a worse failure than a wrong badge.
        _branch_now = (rbac.visible_findings(db, user)
                       .filter(Finding.state == FindingState.OPEN)
                       .filter(Finding.out_of_scope.is_(False))
                       .filter(Finding.repository == row.repository))
        if row.branch:
            _branch_now = _branch_now.filter(Finding.branch == row.branch)
        covering = {"total": _branch_now.count()}
        for _sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            covering[_sev.value] = _branch_now.filter(
                Finding.severity == _sev).count()

        # Which of those branches get a full scan, and whether this finding is
        # marked not deployed because none of them do.
        from app.core import scan_scope

        _scope_rule = scan_scope.rule_for(db, row.repository)
        _drawn, _can_draw = _diagram_flags(db, user)
        branch_scan = {name: dict(zip(("full", "source"),
                                      _scope_rule.full_scan(name)))
                       for name in (on_branches or [row.branch or ""])}

        about = repo_context.for_repository(db, row.repository)

        # What this repository says for itself, as opposed to what it inherits,
        # for the administrator's edit form.  The form shows the repository's
        # own answers and leaves the connection's as the hint.
        can_tag = bool(about) and rbac.can(user, "repo.write")
        repo_own, tag_labels = {}, []
        if can_tag:
            from app.core import tagging

            _own_row = db.get(Repository, about["id"])
            if _own_row is not None:
                repo_own = {field: (getattr(_own_row, field, "") or "")
                            for field in tagging.FIELDS}
                repo_own["holds"] = tagging.split_labels(repo_own["sensitivity"])
                repo_own["web_app"] = bool(_own_row.web_app)
                repo_own["web_app_urls"] = _own_row.web_app_urls or ""
                tag_labels = tagging.labels(db) + [
                    x for x in repo_own["holds"] if x not in tagging.labels(db)]
            else:
                can_tag = False

        # Everybody else who can see this repository can ask for a change
        # instead, and sees what they last asked for until it is decided.
        can_propose = (bool(about) and not can_tag
                       and rbac.can(user, "repo.propose"))
        proposed = {}
        if can_propose:
            from app.core import proposals, tagging

            _own_row = db.get(Repository, about["id"])
            if _own_row is None:
                can_propose = False
            else:
                _asked = proposals.mine(db, _own_row.id, user.username)
                proposed = (proposals.wanted(_asked) if _asked
                            else proposals.current(_own_row))
                proposed["holds"] = tagging.split_labels(proposed["sensitivity"])
                proposed["asked_at"] = _asked.proposed_at if _asked else None
                tag_labels = tagging.labels(db) + [
                    x for x in proposed["holds"]
                    if x not in tagging.labels(db)]

        risk_context = {"sensitivity": about.get("sensitivity"),
                        "visibility": about.get("visibility"),
                        "people_total": about.get("people_total")} if about else {}

        # What a language model said about this finding, when somebody asked,
        # and whether asking again is on offer here.
        from app.core import ai, analysis

        ai_cfg = ai.config(db)
        analyses = analysis.for_finding(db, row.id)

        # The written security report on this finding's branch, if there is
        # one, and whether this person may ask for one.
        from app.core import assessment

        report = assessment.view(assessment.current(
            db, row.repository,
            row.branch or (about or {}).get("default_branch", "") or ""))

        context = _shared(db, user)
        context.update(active_page="findings", f=row, waiver=waiver,
                       host_name=host_name,
                       can_waive=rbac.can(user, "waiver.request"),
                       can_approve=rbac.can(user, "waiver.approve"),
                       can_exclude=rbac.can(user, "exclusion.write"),
                       can_regrade=rbac.can(user, "finding.regrade"),
                       can_describe=rbac.can(user, "repo.describe"),
                       repo_info=about,
                       can_tag=can_tag, repo_own=repo_own,
                       tag_labels=tag_labels,
                       can_propose=can_propose, proposed=proposed,
                       can_scan=rbac.can(user, "scan.run"),
                       scanning_now=_scanning_now(),
                       scanning_now_ids=_scanning_now_ids(),
                       on_branches=on_branches,
                       branch_scan=branch_scan,
                       scope_text=scan_scope.describe(
                           _scope_rule, (about or {}).get("default_branch", "")),
                       can_scope=rbac.can(user, "repo.scope"),
                       has_diagram=row.repository in _drawn,
                       can_draw=_can_draw,
                       certification=certification,
                       exemption=exemption,
                       covering=covering,
                       can_certify=rbac.can(user, "repo.certify"),
                       can_exempt=rbac.can(user, "repo.certify.exempt"),
                       # Both halves of what the grade is standing in for.
                       # Worked out here rather than read off the finding so
                       # that a repository tagged since the last scan reads
                       # correctly straight away, instead of on the next one.
                       assessment=risk.assess(row, risk_context),
                       recommendation=recommendation.for_finding(row,
                                                                 risk_context),
                       analyses=analyses,
                       **_ai_grade_context(db, row),
                       # Offered only when a provider is on and complete.
                       # Half set up shows nothing here; the AI page is where
                       # that gets said.
                       can_validate=(rbac.can(user, "finding.validate")
                                     and ai.enabled(ai_cfg)
                                     and not ai.missing(ai_cfg)),
                       ai_model=ai.describe_model(ai_cfg),
                       ai_sends_code=(bool(ai_cfg.get("ai.send_code"))
                                      and row.kind != FindingKind.CREDENTIAL),
                       report=report,
                       report_fp=assessment.awaiting_for(report, row.id),
                       can_assess=(rbac.can(user, "repo.assess")
                                   and ai.enabled(ai_cfg)
                                   and not ai.missing(ai_cfg)),
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind),
                       **_expiry_window(90))
        return page(request, "finding_detail.html", **context)


@router.get("/waivers")
def waivers(request: Request, q: str = "", status: str = "", page_no: int = 1,
            per: int = 100, user: User = Depends(current_user)):
    """Exceptions, filtered and paged.

    One waived finding tends to come with a hundred siblings: the same file, the
    same reason, the same afternoon.  Five hundred of those on one page is not a
    list anybody reads, so it filters and pages like the findings list does.
    """
    query = clean_text(q, "search", limit=200, required=False)
    wanted = (status or "").strip().lower()
    if wanted not in {"", "requested", "approved", "rejected", "revoked", "expired"}:
        wanted = ""
    per = 100 if per not in (25, 50, 100, 250, 500) else per
    page_no = max(1, page_no)

    with session_scope() as db:
        # A subquery, not a list.  Reading every finding the user can see into
        # Python to collect its id took three and a half seconds on its own.
        shown = rbac.visible_findings(db, user)
        # An exception on a finding that is only on branches that do not ship
        # goes with it, except for somebody who can change the scope.
        if not rbac.can(user, "repo.scope"):
            shown = shown.filter(Finding.out_of_scope.is_(False))
        visible_ids = shown.with_entities(Finding.id).scalar_subquery()
        base = db.query(Waiver).filter(Waiver.finding_id.in_(visible_ids))
        # And, for anybody who cannot approve one, only their own.
        #
        # The repository scope above is the wrong test on its own.  Two
        # developers on the same team see the same repositories, so it showed
        # each of them the other's requests: what they asked to set aside, the
        # reason they gave, and whether somebody agreed.  An exception is an
        # argument a person made and had judged, which is nearer to their
        # review than to the finding it sits on.
        if not rbac.can(user, "waiver.approve"):
            base = base.filter(Waiver.requested_by == user.username)

        now = datetime.now(timezone.utc)
        if wanted == "expired":
            base = base.filter(Waiver.expires_at.isnot(None),
                               Waiver.expires_at < now.replace(tzinfo=None))
        elif wanted:
            base = base.filter(Waiver.status == wanted)

        if query:
            needle = f"%{query}%"
            # The reason and the ticket live on the waiver; the repository and
            # the path live on the finding, so that half is matched by id.
            matching = (rbac.visible_findings(db, user)
                        .filter(sa_or(Finding.repository.ilike(needle),
                                      Finding.file_path.ilike(needle),
                                      Finding.package_name.ilike(needle)))
                        .with_entities(Finding.id).scalar_subquery())
            base = base.filter(sa_or(Waiver.reason.ilike(needle),
                                     Waiver.ticket.ilike(needle),
                                     Waiver.requested_by.ilike(needle),
                                     Waiver.finding_id.in_(matching)))

        total = base.count()
        pages = max(1, (total + per - 1) // per)
        page_no = min(page_no, pages)
        rows = (base.order_by(Waiver.status, Waiver.requested_at.desc())
                .offset((page_no - 1) * per).limit(per).all())

        findings_by_id = {}
        if rows:
            for f in db.query(Finding).filter(Finding.id.in_(
                    [w.finding_id for w in rows] or [0])).all():
                findings_by_id[f.id] = f

        context = _shared(db, user)
        context.update(active_page="waivers", rows=rows,
                       findings=findings_by_id,
                       now=now,
                       q=query, status=wanted,
                       page_no=page_no, pages=pages, per=per, total=total,
                       shown=len(rows),
                       can_approve=rbac.can(user, "waiver.approve"),
                       can_revoke=rbac.can(user, "waiver.revoke"))
        return page(request, "waivers.html", **context)


@router.get("/certifications")
def certification_detail(request: Request, repo: str = "", branch: str = "",
                         msg: str = "", kind: str = "",
                         user: User = Depends(current_user)):
    """One sign off, with what changed and the two things you can do about it.

    The certify and withdraw forms used to live only on a finding, and they act
    on that finding's repository and branch.  That works until the branch has
    no findings on it, which is exactly the branch a scan signs off
    automatically.  Push to one of those and the badge stops reading as
    current, and there is no finding anywhere on that branch to open the form
    from.  It could not be signed off again, withdrawn, or made to go away by
    any route in the product.

    So this is addressed by repository and branch rather than through a
    finding, and it is what the repository name on the certifications list
    links to.
    """
    from app.core import certification as _cert
    from app.core.models import Repository as _Repo

    repository = clean_text(repo, "Repository", limit=320, required=False)
    branch_name = clean_text(branch, "Branch", limit=255, required=False)

    with session_scope() as db:
        # Through the repository scope, so a name in the query string cannot
        # reach a repository this reader may not open.  Absent and forbidden
        # answer the same way.
        owner = (rbac.visible_repositories(db, user)
                 .filter(_Repo.full_name == repository).one_or_none())
        if owner is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        # A branch with no sign off on it opens too, rather than 404ing.
        #
        # The branches short of a seal are the clean ones by definition: no
        # findings, so no finding to reach the form from, and no sign off yet
        # so nothing to look up either.  Those are exactly the names the seal
        # now lists as outstanding, and a link that answers "no such thing" is
        # how a reader learns the list is wrong when it is right.
        #
        # Only for a branch this install has actually walked.  Any other name
        # in the query string is not a branch, and opening a sign off form on
        # one would let somebody certify a string they typed.
        row = _cert.for_branch(db, repository, branch_name)
        if row is None:
            if (branch_name or owner.default_branch or "") not in \
                    _walked_branches(db, user, repository) | {
                        owner.default_branch or ""}:
                raise HTTPException(
                    status_code=404,
                    detail="The last scan of that repository did not walk "
                           "that branch.")
            state = {"state": _cert.NONE, "why": "", "certification": None}
        else:
            state = _cert.status(db, row)
        head = _cert.head_of(db, repository, branch_name) or ""
        compare = (_compare_url(db, row)
                   if row is not None and state.get("moved") else "")
        found = (rbac.visible_findings(db, user)
                 .filter(Finding.state == FindingState.OPEN)
                 .filter(Finding.out_of_scope.is_(False))
                 .filter(Finding.repository == repository))
        if branch_name:
            found = found.filter(Finding.branch == branch_name)
        drawn, can_draw = _diagram_flags(db, user)
        context = _shared(db, user)
        # A certified repository is still a repository somebody wants to
        # understand, so its diagram is offered here too.
        context.update(repo_id=owner.id, drawn=repository in drawn,
                       can_draw=can_draw)
        context.update(active_page="repositories", repository=repository,
                       branch=branch_name, row=row, state=state, head=head,
                       pushed_at=owner.pushed_at,
                       last_scanned=owner.last_scanned_at,
                       compare=compare, findings_count=found.count(),
                       can_certify=rbac.can(user, "repo.certify"),
                       message=clean_notice(msg, limit=300),
                       kind=("warn" if kind == "warn" else "ok"),
                       **_expiry_window(90))
        return page(request, "certification.html", **context)


@router.get("/repositories")
def repositories(request: Request, user: User = Depends(current_user),
                 msg: str = "", kind: str = ""):
    from app.core import certification as _cert
    from app.core import scan_scope

    # The dashboard tile for certified branches linked here with a filter that
    # did not exist, so the number opened a list of everything.  A count that
    # cannot be opened is a count somebody has to take on trust.
    wanted = (request.query_params.get("certified", "") or "").strip().lower()
    if wanted not in {"", "active", "stale", "rescanning", "unknown", "lapsed",
                      "revoked", "not_applicable"}:
        wanted = ""

    with session_scope() as db:
        rows = (rbac.visible_repositories(db, user)
                .order_by(Repository.organization, Repository.name)
                .limit(1000).all())

        # Every sign off, with the state worked out now rather than stored:
        # a branch that has moved since it was reviewed is amber whether or
        # not anybody has looked at it since.
        seen = set(row.full_name for row in rows)
        badges = []
        mine = [row for row in _cert.all_certifications(db)
                if row.repository in seen]
        finding_count = _branch_finding_counts(db, user)
        for row, state in zip(mine, _cert.statuses(db, mine)):
            badges.append({"repository": row.repository, "branch": row.branch,
                           "state": state["state"], "why": state.get("why", ""),
                           "by": row.certified_by, "at": row.certified_at,
                           "expires": row.expires_at, "note": row.note,
                           # Shown, not implied by the author's name.  A
                           # reader scanning this list has to be able to tell
                           # a scan finding nothing from somebody reading it.
                           "automatic": bool(row.automatic),
                           # Why it went amber, because the answer decides
                           # where a reader should be sent.  A branch that
                           # moved has no findings to show by definition, and
                           # offering a findings list for it sends somebody to
                           # an empty page and leaves them with no way to judge
                           # whether the sign off still holds.  What they need
                           # there is the code that arrived since.
                           "moved": bool(state.get("moved")),
                           "compare": _compare_url(db, row)
                           if state.get("moved") else "",
                           # How much is open on that branch, so the branch
                           # name is a way in when there is something to read
                           # and plain text when there is not.  A link that
                           # opens an empty page is worse than no link.
                           "findings": finding_count(
                               row.repository, row.branch)})
        # Branches nobody is expected to sign off, listed beside the sign
        # offs.  They belong on the same page: this is the only place an
        # administrator can find what has been marked, and a decision that
        # cannot be found again is one nobody can review.  A branch with no
        # findings on it has no other route back.
        for row in _cert.all_exemptions(db,
                                        rbac.visible_certification_exemptions(
                                            db, user)):
            if row.repository not in seen:
                continue
            badges.append({"repository": row.repository, "branch": row.branch,
                           "state": _cert.NOT_APPLICABLE,
                           "why": row.reason, "by": row.marked_by,
                           "at": row.marked_at, "expires": None,
                           "note": row.reason, "automatic": False})
        badges.sort(key=lambda b: (b["repository"], b["branch"]))

        # The same badge again, beside the branch it is about, in the
        # repository table lower down.  Worked out before the state filter
        # runs: narrowing the card above to the amber ones is a question about
        # the card, and it must not quietly blank the column that tells
        # somebody going down the rows whether this repository's own default
        # branch has been read.
        #
        # Only the default branch.  A sign off on a release branch is not a
        # fact about the branch named in that cell, and a green mark beside a
        # name it is not about is the kind nobody can rely on afterwards.
        default_of = {row.full_name: (row.default_branch or "") for row in rows}
        certified_default = {}
        for badge in badges:
            default_branch = default_of.get(badge["repository"], "")
            # A certification names the branch a finding was on, and one on
            # the default branch may carry no branch at all.  coverage()
            # resolves it the same way.
            if (badge["branch"] or default_branch) != default_branch:
                continue
            # A sign off and an exemption can both exist for one branch, and
            # the exemption is the one that decides: nobody was ever going to
            # be asked to review this.  Again the same order coverage() takes,
            # so the column and the percentage cannot disagree.
            held = certified_default.get(badge["repository"])
            if held and held["state"] == _cert.NOT_APPLICABLE:
                continue
            certified_default[badge["repository"]] = badge

        # Every sign off on each repository, any branch, for the
        # Certification filter and column in the table.  Also taken before
        # the state filter, for the same reason as the column above.
        certs_by_repo = {}
        for badge in badges:
            if badge["state"] == "revoked":
                continue
            certs_by_repo.setdefault(badge["repository"], []).append(
                dict(badge, branch=badge["branch"]
                     or default_of.get(badge["repository"], "")))

        if wanted:
            badges = [b for b in badges if b["state"] == wanted]

        counts = {}
        for repo_name, severity, total in (
                rbac.visible_findings(db, user)
                .filter(Finding.state == FindingState.OPEN)
                .filter(Finding.out_of_scope.is_(False))
                .with_entities(Finding.repository, Finding.severity,
                               func.count(Finding.id))
                .group_by(Finding.repository, Finding.severity).all()):
            key = repo_name or ""
            counts.setdefault(key, {})[getattr(severity, "value", "")] = total

        # The Scope column.  Only repositories somebody set have a rule.
        scope_rules = scan_scope.rules(db, [row.full_name for row in rows])
        scopes = {}
        for row in rows:
            rule = scope_rules.get(row.full_name)
            scopes[row.full_name] = {
                "text": scan_scope.describe(rule, row.default_branch),
                "set": rule is not None,
                # For the Scope filter above the table.
                "mode": rule.mode if rule is not None else "all",
                "default_out": scan_scope.default_left_out(
                    rule, row.default_branch)}

        # Every branch the last scan saw, for the branch= and branch!= terms
        # in the search box.  Read off the rows already loaded, so it costs
        # no query, and falls back the same way known_branches() does.
        branches = {}
        for row in rows:
            names = []
            for column in (row.branch_names_present, row.branch_names):
                try:
                    names = [str(n) for n in (json.loads(column or "[]") or [])
                             if n and " " not in str(n)]
                except (TypeError, ValueError):
                    names = []
                if names:
                    break
            if not names and row.default_branch:
                names = [row.default_branch]
            branches[row.full_name] = sorted(set(names))

        drawn, can_draw = _diagram_flags(db, user)

        # The application, its owners, what it holds and who is told, for the
        # Application column.  One read of the connections for the whole list.
        from app.core import tagging
        about = tagging.effective_many(db, rows)
        told = {row.id: tagging.notify_addresses(row, about.get(row.id, {}))
                for row in rows}
        web = {row.id: tagging.web_urls(row.web_app_urls)[0]
               for row in rows if row.web_app}

        context = _shared(db, user)
        context.update(branches=branches, certs_by_repo=certs_by_repo,
                       about=about, told=told, web=web,
                       can_tag=rbac.can(user, "repo.write"),
                       sensitivity_labels=tagging.labels(db))
        # The certified card names repositories, and its diagram link needs
        # the id the main table already has.
        context.update(drawn=drawn, can_draw=can_draw,
                       repo_ids={row.full_name: row.id for row in rows})
        context.update(scopes=scopes, can_scope=rbac.can(user, "repo.scope"),
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind))
        context.update(active_page="repositories", rows=rows, counts=counts,
                       can_scan=rbac.can(user, "scan.run"),
                       scanning_now=_scanning_now(),
                       scanning_now_ids=_scanning_now_ids(),
                       certified=badges, certified_filter=wanted,
                       can_certify=rbac.can(user, "repo.certify"),
                       certified_default=certified_default)
        return page(request, "repositories.html", **context)


@router.get("/repositories/web-apps.csv")
def export_web_apps(request: Request, user: User = Depends(current_user)):
    """Every repository that is part of a web application, and where it is.

    For whatever runs dynamic scans, usually another system, so it knows which
    code sits behind which site and who to ask.  Only what this person can see.
    """
    rbac.require(user, "repo.read")
    from app.core import tagging

    with session_scope() as db:
        body = tagging.web_apps_csv(db, base=rbac.visible_repositories(db, user))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(
        content=body, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="web-applications-{stamp}.csv"'})


@router.get("/repositories/{repo_id:int}")
def repository_about(repo_id: int, request: Request, msg: str = "",
                     kind: str = "", user: User = Depends(current_user)):
    """One repository: what it holds, what it is, who owns it, who is told.

    Anybody who can see the repository can read this.  Only somebody who can
    change repositories gets the form, which saves through the same route the
    finding page's form does.
    """
    from app.core import tagging

    with session_scope() as db:
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        applies = tagging.effective(db, repo)
        own = {field: (getattr(repo, field, "") or "")
               for field in tagging.FIELDS + ("notify_extra", "web_app_urls")}
        own["holds"] = tagging.split_labels(own["sensitivity"])
        offered = tagging.labels(db)
        labels = offered + [x for x in own["holds"] if x not in offered]
        open_count = (rbac.visible_findings(db, user)
                      .filter(Finding.repository == repo.full_name)
                      .filter(Finding.state == FindingState.OPEN)
                      .filter(Finding.out_of_scope.is_(False)).count())
        context = _shared(db, user)
        context.update(active_page="repositories", repo=repo, applies=applies,
                       own=own, tag_labels=labels, open_count=open_count,
                       web_urls=tagging.web_urls(repo.web_app_urls)[0],
                       told=tagging.notify_addresses(repo, applies),
                       can_tag=rbac.can(user, "repo.write"),
                       can_scope=rbac.can(user, "repo.scope"),
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind))
        return page(request, "repository.html", **context)


@router.get("/repositories/proposals")
def repository_proposals(request: Request, msg: str = "", kind: str = "",
                         user: User = Depends(current_user)):
    """Changes to repositories that people asked for, waiting on a decision.

    Each shows what the repository says now beside what was asked, and a
    form holding the whole record as it would be, so the reviewer can fix
    it up before approving.
    """
    rbac.require(user, "repo.write")

    from app.core import proposals, tagging
    from app.core.models import RepoProposal

    with session_scope() as db:
        offered = tagging.labels(db)
        waiting = []
        for row in (db.query(RepoProposal)
                    .filter(RepoProposal.status == proposals.PENDING)
                    .order_by(RepoProposal.proposed_at)):
            now, asked = proposals.current(row.repo), proposals.changes(row)
            form = proposals.wanted(row)
            form["holds"] = tagging.split_labels(form["sensitivity"])
            own = tagging.split_labels(row.repo.sensitivity or "")
            waiting.append({
                "id": row.id, "repo": row.repo,
                "proposed_by": row.proposed_by,
                "proposed_at": row.proposed_at, "finding_id": row.finding_id,
                "rows": [{"label": proposals.LABELS[f], "field": f,
                          "now": now[f], "asked": asked[f]}
                         for f in proposals.FIELDS if f in asked],
                "form": form,
                "labels": offered + [x for x in own + form["holds"]
                                     if x not in offered],
            })
        decided = (db.query(RepoProposal)
                   .filter(RepoProposal.status != proposals.PENDING)
                   .order_by(RepoProposal.decided_at.desc()).limit(25).all())
        decided = [{"repo": r.repo, "status": r.status,
                    "proposed_by": r.proposed_by,
                    "decided_by": r.decided_by, "decided_at": r.decided_at,
                    "fields": ", ".join(proposals.LABELS[f]
                                        for f in proposals.changes(r))}
                   for r in decided]
        context = _shared(db, user)
        context.update(active_page="proposals", waiting=waiting,
                       decided=decided,
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind))
        return page(request, "proposals.html", **context)


def _scope_repo(db, user, repository: str):
    """The repository, if this person may see it.  Absent and hidden match."""
    if not repository:
        return None
    return (rbac.visible_repositories(db, user)
            .filter(Repository.full_name == repository).one_or_none())


@router.get("/repositories/{repo_id}/scope")
def repository_scope(repo_id: int, request: Request, msg: str = "",
                     kind: str = "", user: User = Depends(current_user)):
    """Which branches of one repository ship, and what changed it last."""
    rbac.require(user, "repo.scope")
    from app.core import scan_scope

    with session_scope() as db:
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        rule = scan_scope.rule_for(db, repo.full_name)
        names = set(scan_scope.known_branches(db, repo.full_name))
        names.update(rule.overrides)
        # Branches with open findings on them, so a branch the last scan did
        # not list but that still carries findings is offered too.
        names.update(branch_scope.names(
            rbac.visible_findings(db, user)
            .filter(Finding.repository == repo.full_name)
            .filter(Finding.state == FindingState.OPEN)))
        branches = []
        for name in sorted(names):
            full, source = rule.full_scan(name)
            branches.append({"name": name, "full": full, "source": source,
                             "default": name == repo.default_branch})
        stored = scan_scope.settings_of(db, repo.full_name)
        hidden = (rbac.visible_findings(db, user)
                  .filter(Finding.repository == repo.full_name)
                  .filter(Finding.state == FindingState.OPEN)
                  .filter(Finding.out_of_scope.is_(True)).count())
        context = _shared(db, user)
        context.update(active_page="repositories", repo=repo, rule=rule,
                       branches=branches, stored=stored,
                       labels=scan_scope.REPO_LABELS,
                       describe=scan_scope.describe(rule, repo.default_branch),
                       default_left_out=scan_scope.default_left_out(
                           rule, repo.default_branch),
                       history=scan_scope.history(db, repo.full_name),
                       hidden=hidden,
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind))
        return page(request, "scope.html", **context)


@router.post("/repositories/{repo_id}/scope/confirm")
async def repository_scope_confirm(repo_id: int, request: Request,
                                   user: User = Depends(current_user)):
    """What the ticked branches of one repository would change.

    The same page and the same counts as a connection's bulk page, for one
    repository.  Posted, because a repository can have thousands of branches.
    """
    from app.web.security import check_csrf

    form = await request.form(max_fields=MAX_SCOPE_FIELDS)
    await check_csrf(request)
    rbac.require(user, "repo.scope")
    from app.core import scan_scope

    action = str(form.get("action", "") or "")
    if action not in scan_scope.ACTIONS:
        raise HTTPException(status_code=400, detail="Pick what to do with them.")
    with session_scope() as db:
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        branches = sorted({str(v).strip() for v in form.getlist("branch")
                           if str(v).strip()})
        if not branches:
            raise HTTPException(status_code=400, detail="Tick a branch first.")
        plan = scan_scope.batch([], [(repo.full_name, b) for b in branches], action)
        changes = plan.get(repo.full_name, [])
        impact = scan_scope.preview(db, repo.full_name, "", "", "",
                                    findings=rbac.visible_findings(db, user),
                                    changes=changes)
        totals = {"hide": dict(impact["hide"]), "show": dict(impact["show"]),
                  "hide_total": impact["hide_total"],
                  "show_total": impact["show_total"]}
        context = _shared(db, user)
        context.update(active_page="repositories", connection=None,
                       apply_url=f"/repositories/{repo.id}/scope/apply",
                       cancel_url=f"/repositories/{repo.id}/scope",
                       rows=[{"repository": repo.full_name, "impact": impact,
                              "branches": branches, "whole": False}],
                       totals=totals, action=action, severities=SEVERITIES,
                       ticked_repos=[],
                       ticked_pairs=[f"{repo.full_name} {b}" for b in branches],
                       default_leaves=([repo.full_name]
                                       if impact["default_leaves"] else []),
                       today=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        return page(request, "connection_scope_confirm.html", **context)


@router.get("/scope/export.csv")
def scope_export(request: Request, user: User = Depends(current_user)):
    """Every branch and whether it gets the vulnerability scans, as CSV.

    The same columns the import reads, so it can be edited and handed back.
    Administrators only, like changing it.
    """
    rbac.require(user, "repo.scope")
    from app.core import scope_csv

    with session_scope() as db:
        repos = rbac.visible_repositories(db, user).all()
        body = scope_csv.export(db, repos)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(
        content=body, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="scan-scope-{stamp}.csv"'})


@router.get("/scope/import")
def scope_import_page(request: Request, user: User = Depends(current_user)):
    """Where the CSV goes in."""
    rbac.require(user, "repo.scope")
    with session_scope() as db:
        context = _shared(db, user)
        context.update(active_page="repositories")
        return page(request, "scope_import.html", **context)


@router.post("/scope/import")
async def scope_import_check(request: Request, user: User = Depends(current_user)):
    """What a CSV would change, before anything does.

    Read, worked out and shown, and nothing written.  The page that comes
    back carries the changes themselves rather than the file, so what gets
    applied is exactly what was shown.
    """
    from app.web.security import check_csrf
    from app.core import scan_scope, scope_csv

    form = await request.form()
    await check_csrf(request)
    rbac.require(user, "repo.scope")
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise HTTPException(status_code=400, detail="Choose a file first.")
    raw = await upload.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="That file is larger than 10MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", "replace")

    rows, problems = scope_csv.parse(text)
    with session_scope() as db:
        allowed = {name for (name,) in rbac.visible_repositories(db, user)
                   .with_entities(Repository.full_name).all()}
        changes, unknown, same = scope_csv.plan(db, rows, allowed)
        visible = rbac.visible_findings(db, user)
        listing = []
        totals = {"hide": {}, "show": {}, "hide_total": 0, "show_total": 0}
        for repository, steps in sorted(changes.items()):
            impact = scan_scope.preview(db, repository, "", "", "",
                                        findings=visible, changes=steps)
            listing.append({"repository": repository, "impact": impact,
                            "steps": steps})
            for side in ("hide", "show"):
                for level, n in impact[side].items():
                    totals[side][level] = totals[side].get(level, 0) + n
                totals[side + "_total"] += impact[side + "_total"]
        context = _shared(db, user)
        context.update(active_page="repositories", rows=listing, totals=totals,
                       severities=SEVERITIES, problems=problems,
                       unknown=sorted({r["repository"] for r in unknown}),
                       same=same, read=len(rows),
                       steps=sum(len(r["steps"]) for r in listing),
                       default_leaves=[r["repository"] for r in listing
                                       if r["impact"]["default_leaves"]],
                       today=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        return page(request, "scope_import_confirm.html", **context)


def _diagram_flags(db, user) -> tuple:
    """Which repositories have a drawing, and whether this person may make one."""
    from app.core import ai
    from app.core.models import RepoDiagram

    drawn = {name for (name,) in db.query(RepoDiagram.repository)
             .filter(RepoDiagram.graph.isnot(None))
             .filter(RepoDiagram.graph != "").all()}
    cfg = ai.config(db)
    can_draw = (rbac.can(user, "repo.diagram") and ai.enabled(cfg)
                and not ai.missing(cfg))
    return drawn, can_draw


def _diagram_context(db, user, repo) -> dict:
    """The stored drawing for a repository, and what this person may do."""
    from app.core import ai, diagram

    from app.core import proposals, tagging
    from app.core.models import RepoProposal

    cfg = ai.config(db)
    ai_ready = ai.enabled(cfg) and not ai.missing(cfg)
    drawn = diagram.view(diagram.current(db, repo.full_name))

    # Web addresses the drawing found that the repository does not list,
    # for an administrator to add or anybody else to propose.  Ones already
    # waiting on Proposed Updates say so rather than being offered again.
    can_add = rbac.can(user, "repo.write")
    can_offer = can_add or rbac.can(user, "repo.propose")
    found = []
    if drawn and drawn["ready"] and can_offer:
        waiting = []
        for row in (db.query(RepoProposal)
                    .filter(RepoProposal.repo_id == repo.id)
                    .filter(RepoProposal.status == proposals.PENDING)):
            waiting += tagging.web_urls(
                proposals.changes(row).get("web_app_urls", ""))[0]
        found = diagram.suggestions(
            drawn["graph"], tagging.web_urls(repo.web_app_urls)[0], waiting)
    return {"diagram": drawn,
            "can_draw": rbac.can(user, "repo.diagram") and ai_ready,
            "ai_model": ai.describe_model(cfg) if ai_ready else "",
            "ai_sends_code": bool(cfg.get("ai.send_code")),
            "found_urls": found, "can_add_urls": can_add}


@router.get("/repositories/{repo_id}/diagram")
def repository_diagram(repo_id: int, request: Request, msg: str = "",
                       kind: str = "", user: User = Depends(current_user)):
    """How a repository's default branch fits together, as a model read it."""
    with session_scope() as db:
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        context = _shared(db, user)
        context.update(active_page="repositories", repo=repo,
                       **_diagram_context(db, user, repo),
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind))
        return page(request, "diagram.html", **context)


@router.get("/repositories/{repo_id}/diagram.pdf")
def repository_diagram_pdf(repo_id: int, request: Request,
                           user: User = Depends(current_user)):
    """The same drawing as a landscape PDF, one flow per page after it."""
    with session_scope() as db:
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        context = _diagram_context(db, user, repo)
        if not (context["diagram"] and context["diagram"]["ready"]):
            raise HTTPException(status_code=404, detail="No diagram yet.")
        context.update(repo=repo, app_name=APP_NAME,
                       now=datetime.now(timezone.utc))
        html = render_partial("diagram_pdf.html", **context)
        name = "diagram-%s-%s.pdf" % (repo.full_name.replace("/", "-"),
                                      datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    try:
        from weasyprint import HTML
    except Exception:
        log.exception("weasyprint is not available")
        raise HTTPException(
            status_code=503,
            detail="PDFs need the typesetting libraries, which are not "
                   "installed on this server.")
    pdf = HTML(string=html, base_url=str(request.base_url),
               url_fetcher=report_url_fetcher("")).write_pdf()
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % name})


@router.get("/findings/{finding_id}/assessment.pdf")
def finding_assessment_pdf(finding_id: int, request: Request,
                           user: User = Depends(current_user)):
    """The security report on this finding's branch, typeset now.

    Typeset on download rather than stored, so the logo, the name on the
    cover and the footer are always the ones set today.
    """
    from app.core import assessment, settings_store

    with session_scope() as db:
        row = rbac.visible_finding(db, user, finding_id)
        if row is None or (row.out_of_scope and not rbac.can(user, "repo.scope")):
            raise HTTPException(status_code=404, detail="No such finding.")
        report = assessment.view(assessment.current(
            db, row.repository, row.branch or _default_branch(db, row.repository)))
        if not (report and report["ready"]):
            raise HTTPException(status_code=404, detail="No report yet.")
        organization = settings_store.get(db, "report.organization_name", "") or ""
        context = assessment.document_context(report)
        context.update(
            title="Security Assessment: %s" % row.repository,
            organization_name=organization,
            logo=(settings_store.get(db, "report.logo", "") or "").strip(),
            footer_text=settings_store.get(db, "report.footer", "") or "",
            issued_at=(report["row"].created_at or datetime.now(timezone.utc))
            .strftime("%B %d, %Y").replace(" 0", " "))
        html = render_partial("assessment_pdf.html", **context)
        name = "security-assessment-%s-%s-%s.pdf" % (
            row.repository.replace("/", "-"),
            re.sub(r"[^A-Za-z0-9._-]+", "-", report["result"]["branch"] or "default"),
            datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    try:
        from weasyprint import HTML
    except Exception:
        log.exception("weasyprint is not available")
        raise HTTPException(
            status_code=503,
            detail="Reports need the typesetting libraries, which are not "
                   "installed on this server.")

    def finisher(_document, pdf):
        # The document says whose assessment it is, not what typeset it.
        import pydyf
        who = organization or "Security Assessment"
        pdf.info["Producer"] = pydyf.String(who)
        pdf.info["Creator"] = pydyf.String(who)

    pdf = HTML(string=html, base_url=str(request.base_url),
               url_fetcher=report_url_fetcher(context.get("logo") or "")
               ).write_pdf(finisher=finisher)
    log.info("security report on %s downloaded by %s", row.repository,
             getattr(user, "username", "?"))
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="%s"' % name})


def _default_branch(db, repository: str) -> str:
    repo = db.query(Repository).filter(Repository.full_name == repository).first()
    return (repo.default_branch if repo else "") or ""


def _connection_repos(db, user, connection):
    """The repositories under one connection that this person may see."""
    return (rbac.visible_repositories(db, user)
            .filter(sa_or(Repository.connection_id == connection.id,
                          Repository.connection == connection.name))
            .order_by(Repository.organization, Repository.name).all())


@router.get("/connections/{connection_id}/scope")
def connection_scope(connection_id: int, request: Request, msg: str = "",
                     kind: str = "", user: User = Depends(current_user)):
    """Every repository and branch under one account, to scope in bulk.

    For the accounts with thousands of branches, where one at a time from a
    finding is no way to work.  Ticking a repository or a branch and choosing
    credentials only leaves the credential pass on it and nothing else.
    """
    rbac.require(user, "repo.scope")
    from app.core import connections as connection_store, scan_scope

    with session_scope() as db:
        connection = connection_store.by_id(db, connection_id)
        if connection is None:
            raise HTTPException(status_code=404, detail="No such connection.")
        repos = _connection_repos(db, user, connection)
        all_rules = scan_scope.rules(db, [r.full_name for r in repos])
        listing = []
        for repo in repos:
            rule = all_rules.get(repo.full_name) or scan_scope.Rule()
            names = set(scan_scope.known_branches(db, repo.full_name))
            names.update(rule.overrides)
            branches = []
            for name in sorted(names):
                full, source = rule.full_scan(name)
                branches.append({"name": name, "full": full, "source": source,
                                 "default": name == repo.default_branch})
            listing.append({"repo": repo, "rule": rule,
                            "text": scan_scope.describe(rule, repo.default_branch),
                            "default_out": scan_scope.default_left_out(
                                rule, repo.default_branch),
                            "branches": branches,
                            "credentials_only": sum(1 for b in branches if not b["full"])})
        context = _shared(db, user)
        context.update(active_page="connections", connection=connection,
                       listing=listing,
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind))
        return page(request, "connection_scope.html", **context)


# Ticked branches on one connection's scope page.  The largest account seen
# held a few thousand, so this is room for that with plenty over.
MAX_SCOPE_FIELDS = 25000


@router.post("/connections/{connection_id}/scope/confirm")
async def connection_scope_confirm(connection_id: int, request: Request,
                                   user: User = Depends(current_user)):
    """What the ticked boxes would change, before anything does.

    A POST rather than the GET the single change uses, because a few thousand
    ticked branches do not fit in an address.
    """
    from app.web.security import check_csrf

    # Read first, with room for every branch of a large account.  The form is
    # kept, so the CSRF check below reads this copy rather than parsing again
    # with the default limit of a thousand fields and finding no token.
    await request.form(max_fields=MAX_SCOPE_FIELDS)
    await check_csrf(request)
    rbac.require(user, "repo.scope")
    from app.core import connections as connection_store, scan_scope

    form = await request.form(max_fields=MAX_SCOPE_FIELDS)
    action = str(form.get("action", "") or "")
    ticked_repos = [str(v) for v in form.getlist("repo") if str(v).strip()]
    ticked_pairs = []
    for raw in form.getlist("pair"):
        repository, _, branch = str(raw).partition(" ")
        if repository and branch:
            ticked_pairs.append((repository, branch))
    if action not in scan_scope.ACTIONS:
        raise HTTPException(status_code=400, detail="Pick what to do with them.")
    if not ticked_repos and not ticked_pairs:
        raise HTTPException(status_code=400, detail="Tick something first.")

    with session_scope() as db:
        connection = connection_store.by_id(db, connection_id)
        if connection is None:
            raise HTTPException(status_code=404, detail="No such connection.")
        allowed = {r.full_name for r in _connection_repos(db, user, connection)}
        plan = scan_scope.batch([r for r in ticked_repos if r in allowed],
                                [p for p in ticked_pairs if p[0] in allowed],
                                action)
        rows = []
        totals = {"hide": {}, "show": {}, "hide_total": 0, "show_total": 0}
        visible = rbac.visible_findings(db, user)
        for repository, changes in sorted(plan.items()):
            impact = scan_scope.preview(db, repository, "", "", "",
                                        findings=visible, changes=changes)
            rows.append({"repository": repository, "impact": impact,
                         "branches": [b for b, _, _ in changes if b],
                         "whole": any(not b for b, _, _ in changes)})
            for side in ("hide", "show"):
                for level, n in impact[side].items():
                    totals[side][level] = totals[side].get(level, 0) + n
                totals[side + "_total"] += impact[side + "_total"]
        context = _shared(db, user)
        context.update(active_page="connections", connection=connection,
                       apply_url=f"/connections/{connection.id}/scope/apply",
                       cancel_url=f"/connections/{connection.id}/scope",
                       rows=rows, totals=totals, action=action,
                       severities=SEVERITIES,
                       ticked_repos=[r for r in ticked_repos if r in allowed],
                       ticked_pairs=[f"{r} {b}" for r, b in ticked_pairs if r in allowed],
                       default_leaves=[r["repository"] for r in rows
                                       if r["impact"]["default_leaves"]],
                       today=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        return page(request, "connection_scope_confirm.html", **context)


@router.get("/scope/confirm")
def confirm_scope(request: Request, user: User = Depends(current_user)):
    """What a scope change would do, with the form that makes it.

    A page of its own rather than a dialog, so the counts are worked out by
    the server from the findings as they are now, and so the same page serves
    one branch, one repository and a ticked set of them.
    """
    rbac.require(user, "repo.scope")
    return _confirm_scope(request, user, request.query_params)


@router.post("/scope/confirm")
async def confirm_scope_post(request: Request, user: User = Depends(current_user)):
    """The same page for a ticked set too long for an address.

    Four hundred repositories in a query string is about 25 KB, and the load
    balancer drops a request line that size without a word: the browser shows
    the connection closed, not an error anybody can read.  The repositories
    page posts its ticks here instead.
    """
    from app.web.security import check_csrf

    # Read with room first, so the CSRF check reads this copy rather than
    # parsing again with the default limit of a thousand fields.
    form = await request.form(max_fields=MAX_SCOPE_FIELDS)
    await check_csrf(request)
    rbac.require(user, "repo.scope")
    return _confirm_scope(request, user, form)


def _confirm_scope(request: Request, user: User, params):
    from app.core import scan_scope

    wanted = [r.strip() for r in params.getlist("repo") if r.strip()]
    branch = clean_text(params.get("branch", ""), "Branch", limit=255,
                        required=False)
    mode = (params.get("mode", "") or "").strip()
    patterns = clean_text(params.get("patterns", ""), "Branches", limit=4000,
                          required=False)
    back = (params.get("back", "") or "/repositories").strip()
    if not back.startswith("/") or back.startswith("//"):
        back = "/repositories"
    if not wanted:
        raise HTTPException(status_code=400,
                            detail="Tick at least one repository first.")
    if len(wanted) > 500:
        raise HTTPException(status_code=400,
                            detail="At most 500 repositories at a time.")
    if branch and len(wanted) != 1:
        raise HTTPException(status_code=400, detail=(
            "A branch setting is for one repository at a time."))

    with session_scope() as db:
        rows, problem = [], ""
        totals = {"hide": {}, "show": {}, "hide_total": 0, "show_total": 0}
        for name in wanted:
            repo = _scope_repo(db, user, name)
            if repo is None:
                continue
            problem = problem or scan_scope.validate(name, branch, mode, patterns)
            impact = scan_scope.preview(db, name, branch, mode, patterns,
                                        findings=rbac.visible_findings(db, user))
            rows.append({"repository": name, "impact": impact})
            for side in ("hide", "show"):
                for level, n in impact[side].items():
                    totals[side][level] = totals[side].get(level, 0) + n
                totals[side + "_total"] += impact[side + "_total"]
        if not rows:
            raise HTTPException(status_code=404, detail="No such repository.")
        context = _shared(db, user)
        context.update(active_page="repositories", rows=rows, branch=branch,
                       mode=mode, patterns=patterns, back=back, totals=totals,
                       problem=problem, labels=scan_scope.REPO_LABELS,
                       severities=SEVERITIES,
                       default_leaves=[r["repository"] for r in rows
                                       if r["impact"]["default_leaves"]],
                       today=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        return page(request, "scope_confirm.html", **context)


@router.get("/scans")
def scans(request: Request, msg: str = "", kind: str = "",
          user: User = Depends(current_user)):
    from app.core import scanner

    # Somebody else's scans are somebody else's business.
    #
    # This page had no permission check at all, so every signed in account saw
    # every run over every organization in the estate: what was scanned, when,
    # by whom and how it went.  A developer keeps the runs they started,
    # because they can start them and need to see how they went.
    rbac.require(user, "scan.run")
    mine_only = not rbac.can(user, "scan.read.any")

    with session_scope() as db:
        query = db.query(ScanRun)
        if mine_only:
            query = query.filter(ScanRun.triggered_by == user.username)
        rows = (query.order_by(ScanRun.started_at.desc())
                .limit(100).all())

        # Runs that failed before there was a column to put the reason in
        # still have their output, so work it out from that rather than
        # showing them as a bare red badge forever.
        reasons = {}
        for row in rows:
            if row.status not in {"failed", "stopped", "empty"}:
                continue
            reasons[row.id] = (row.failure_reason
                               or scanner.failure_reason(row.log_excerpt or "",
                                                         row.exit_code))

        context = _shared(db, user)
        context.update(active_page="scans", rows=rows, reasons=reasons,
                       can_scan=rbac.can(user, "scan.run"),
                       can_clear=rbac.can(user, "scan.history.delete"),
                       scan_running=scanner.is_running(),
                       scan_full=scanner.is_full(),
                       scan_limit=scanner.concurrency(),
                       running_count=len(scanner.running_ids()),
                       message=clean_notice(msg, limit=300),
                       message_kind="error" if kind == "error" else "ok")
        return page(request, "scans.html", **context)


@router.get("/schedules")
def schedules(request: Request, user: User = Depends(current_user)):
    rbac.require(user, "schedule.read")
    from app.core import scheduler as scheduler_mod

    with session_scope() as db:
        rows = db.query(Schedule).order_by(Schedule.name).all()
        context = _shared(db, user)
        context.update(known_orgs=scheduler_mod.known_organizations(db),
                       active_page="schedules", rows=rows,
                       can_edit=rbac.can(user, "schedule.write"))
        return page(request, "schedules.html", **context)


@router.get("/reports")
def reports(request: Request, user: User = Depends(current_user)):
    rbac.require(user, "report.files")
    from app.core.reports import output_dir

    with session_scope() as db:
        report_dir = output_dir(db)
    json_path = report_dir / "vulnerabilities.json"
    csv_path = report_dir / "vulnerabilities.csv"

    def describe(path):
        try:
            stat = path.stat()
            return {"exists": True, "size": stat.st_size,
                    "modified": datetime.fromtimestamp(
                        stat.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")}
        except OSError:
            return {"exists": False, "size": 0, "modified": ""}

    from app.core.reports import sbom_files

    with session_scope() as db:
        context = _shared(db, user)
        context.update(active_page="reports",
                       json_file=describe(json_path), json_path=str(json_path),
                       csv_file=describe(csv_path), csv_path=str(csv_path),
                       openvex_file=describe(report_dir / "vex.openvex.json"),
                       cyclonedx_file=describe(report_dir / "vex.cyclonedx.json"),
                       sbom_rows=sbom_files(report_dir),
                       reports_dir=str(report_dir),
                       can_download=rbac.can(user, "report.files"))
        return page(request, "reports.html", **context)


# How many events one screen of the log is.  The search runs over the whole
# table and then takes this many, so "nothing matches" means nothing in the log
# rather than nothing in the last three hundred rows.
AUDIT_LIMIT = 300
AUDIT_OUTCOMES = ("ok", "warn", "error")


def _audit_query(db, search: str, outcome: str):
    """-> (rows, how many matched in total).

    Matched across every column somebody would think to type into: who did it,
    what they did, what they did it to, the note, and where from.
    """
    query = db.query(AuditEvent)
    if search:
        like = f"%{search}%"
        query = query.filter(
            AuditEvent.actor.ilike(like)
            | AuditEvent.action.ilike(like)
            | AuditEvent.target.ilike(like)
            | AuditEvent.detail.ilike(like)
            | AuditEvent.source_ip.ilike(like))
    if outcome in AUDIT_OUTCOMES:
        query = query.filter(AuditEvent.outcome == outcome)

    total = query.count()
    rows = query.order_by(AuditEvent.at.desc()).limit(AUDIT_LIMIT).all()
    return rows, total


# What a target names, and where that thing lives.  A log entry saying
# "GCR-1A2B3C4D5E6F" is a dead end until it is the finding.
def _audit_link(event) -> str:
    """-> a path this event's target opens, or "" when it names nothing here."""
    action = (event.action or "")
    target = (event.target or "").strip()
    if not target:
        return ""
    if target.upper().startswith("GCR-"):
        return f"/findings?q={target}"
    if action.startswith("user.") or action.startswith("group."):
        return "/users"
    if action.startswith("connection."):
        return "/connections"
    if action.startswith("exclusion."):
        return f"/exclusions?q={target.split(':')[0]}"
    if action.startswith("triage."):
        return "/triage"
    if action.startswith("severity."):
        return "/severity"
    if action.startswith("scan."):
        return "/scans"
    if action.startswith("waiver."):
        return "/waivers"
    if action.startswith("schedule."):
        return "/schedules"
    return ""


def _audit_summary(total: int, shown: int, filtered: bool) -> str:
    if total == 0:
        return "Nothing matches that." if filtered else "Nothing logged yet."
    what = "event" if total == 1 else "events"
    if total > shown:
        return f"Append only.  {shown} of {total} matching {what}, newest first."
    return f"Append only.  {total} {what}{' matching' if filtered else ''}."


def _audit_params(request: Request):
    params = request.query_params
    search = clean_text(params.get("q", ""), "Search", limit=200,
                        required=False)
    outcome = (params.get("outcome", "") or "").strip().lower()
    if outcome not in AUDIT_OUTCOMES:
        outcome = ""
    return search, outcome


@router.get("/audit/rows")
def audit_rows(request: Request, user: User = Depends(current_user)):
    """Just the rows, for the search box answering as somebody types.

    The same partial the page renders, so there is one definition of a row.
    The count rides on a header rather than in the markup, because the caller
    is replacing a table body and nothing else.
    """
    rbac.require(user, "audit.read")
    search, outcome = _audit_params(request)
    with session_scope() as db:
        rows, total = _audit_query(db, search, outcome)
        html = render_partial("audit_rows.html", rows=rows,
                              link_for=_audit_link, base=settings.base_path)
    response = HTMLResponse(html)
    response.headers["X-Audit-Summary"] = _audit_summary(
        total, len(rows), bool(search or outcome))
    # Nothing sets Cache-Control here.  The security middleware already refuses
    # a cache for everything behind the login, and more thoroughly than this
    # would; a second opinion would only be a weaker one somebody has to notice.
    return response


@router.get("/audit")
def audit(request: Request, user: User = Depends(current_user)):
    rbac.require(user, "audit.read")
    search, outcome = _audit_params(request)
    with session_scope() as db:
        rows, total = _audit_query(db, search, outcome)
        context = _shared(db, user)
        context.update(
            active_page="audit", rows=rows,
            link_for=_audit_link,
            limit=AUDIT_LIMIT,
            outcomes=AUDIT_OUTCOMES,
            filters={"q": search, "outcome": outcome},
            summary=_audit_summary(total, len(rows), bool(search or outcome)))
        return page(request, "audit.html", **context)


@router.get("/tagging/export")
def export_tagging(request: Request, user: User = Depends(current_user)):
    """Every repository and what is said about it, as a spreadsheet.

    The point of the round trip: tagging two hundred repositories through a
    form is data entry, and the answers usually already exist in somebody's
    asset list.
    """
    rbac.require(user, "repo.read")
    from app.core import tagging

    organization = clean_text(request.query_params.get("org", ""),
                              "Organization", limit=255, required=False)
    with session_scope() as db:
        body = tagging.to_csv(db, organization,
                              base=rbac.visible_repositories(db, user))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    name = f"tagging-{organization or 'all'}-{stamp}.csv"
    return Response(
        content=body, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/exclusions/export")
def export_exclusions(request: Request, user: User = Depends(current_user)):
    rbac.require(user, "exclusion.read")
    """The exclusions as a CSV, in the same shape the import takes.

    Whatever the search box is showing is what comes out, so a filtered set
    exports as a filtered set.  Round trips into another installation.
    """
    import io as io_module

    from fastapi.responses import StreamingResponse

    from app.core import exclusions as exclusions_store

    rbac.require(user, "exclusion.read")

    params = request.query_params
    search = clean_text(params.get("q", ""), "Search", limit=200, required=False)
    of_kind = params.get("type", "")
    if of_kind not in exclusions_store.KINDS:
        of_kind = ""
    status = params.get("status", "")
    if status not in {"live", "expired"}:
        status = ""

    wants = "json" if params.get("format", "csv").lower() == "json" else "csv"

    with session_scope() as db:
        rows = exclusions_store.visible(db, user, search=search, kind=of_kind,
                                        status=status)
        if wants == "json":
            import json as json_module
            body = json_module.dumps({
                "generator": {"name": APP_NAME, "version": VERSION},
                "generated_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "count": len(rows),
                "exclusions": exclusions_store.as_dicts(db, rules=rows),
            }, indent=2) + "\n"
        else:
            body = exclusions_store.to_csv(db, rules=rows)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    media = "application/json" if wants == "json" else "text/csv"
    return StreamingResponse(
        io_module.StringIO(body), media_type=media,
        headers={"Content-Disposition":
                 f'attachment; filename="exclusions-{stamp}.{wants}"'})


@router.get("/scans/export")
def export_scans(request: Request, user: User = Depends(current_user)):
    """The scan history as a CSV.

    What ran, when, how long it took, what it covered and what it found.  This
    is the record somebody hands an auditor who asks how often the estate is
    actually scanned.
    """
    import csv as csv_module
    import io as io_module

    from fastapi.responses import StreamingResponse

    # Narrowed the same way the page is.  A developer's own history is theirs
    # to take away; everybody else's is not, and a file is the one place a
    # scope is easiest to forget, because nothing on screen shows what came
    # out of it.
    rbac.require(user, "scan.run")
    mine_only = not rbac.can(user, "scan.read.any")

    wants = "json" if request.query_params.get("format", "csv").lower() == "json" else "csv"

    columns = ["run_id", "status", "trigger", "triggered_by", "started_at",
               "finished_at", "duration_minutes", "scope",
               "repositories_scanned", "repositories_failed",
               "repositories_skipped", "branches", "findings_new",
               "findings_updated", "findings_resolved", "exit_code"]

    def when(value):
        if not value:
            return ""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with session_scope() as db:
        _q = db.query(ScanRun)
        if mine_only:
            _q = _q.filter(ScanRun.triggered_by == user.username)
        rows = (_q.order_by(ScanRun.started_at.desc())
                .limit(5000).all())
        buffer = io_module.StringIO()
        writer = csv_module.DictWriter(buffer, fieldnames=columns,
                                       extrasaction="ignore",
                                       lineterminator="\n")
        writer.writeheader()
        for run in rows:
            minutes = ""
            if run.started_at and run.finished_at:
                start = run.started_at if run.started_at.tzinfo else run.started_at.replace(tzinfo=timezone.utc)
                end = run.finished_at if run.finished_at.tzinfo else run.finished_at.replace(tzinfo=timezone.utc)
                minutes = round((end - start).total_seconds() / 60, 1)
            writer.writerow(spreadsheet_row({
                "run_id": run.id,
                "status": run.status or "",
                "trigger": run.trigger or "",
                "triggered_by": run.triggered_by or "",
                "started_at": when(run.started_at),
                "finished_at": when(run.finished_at),
                "duration_minutes": minutes,
                "scope": run.scope or "",
                "repositories_scanned": run.repositories or 0,
                "repositories_failed": run.repositories_failed or 0,
                "repositories_skipped": run.repositories_skipped or 0,
                "branches": run.branches or 0,
                "findings_new": run.findings_new or 0,
                "findings_updated": run.findings_updated or 0,
                "findings_resolved": run.findings_resolved or 0,
                "exit_code": "" if run.exit_code is None else run.exit_code,
            }))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if wants == "json":
        import json as json_module
        history = list(csv_module.DictReader(
            io_module.StringIO(buffer.getvalue())))
        for entry in history:
            for key in ("run_id", "repositories_scanned", "repositories_failed",
                        "repositories_skipped", "branches", "findings_new",
                        "findings_updated", "findings_resolved"):
                entry[key] = int(entry[key] or 0)
        body = json_module.dumps({
            "generator": {"name": APP_NAME, "version": VERSION},
            "generated_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "count": len(history),
            "scans": history,
        }, indent=2) + "\n"
        return StreamingResponse(
            io_module.StringIO(body), media_type="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="scan-history-{stamp}.json"'})

    return StreamingResponse(
        io_module.StringIO(buffer.getvalue()), media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="scan-history-{stamp}.csv"'})


@router.get("/reports/download/{which}")
def download_report(which: str, request: Request,
                    user: User = Depends(current_user)):
    """Hand over one of the files on disk.

    Only for accounts that see the whole estate.  The files hold every finding
    in every organization, so letting a developer pull one would hand them
    everything their scope is there to keep out.  That applies to the SBOMs
    too: a component list names every repository and what each one is built
    from, which is the same disclosure by another route.
    """
    from fastapi.responses import FileResponse

    rbac.require(user, "findings.export")
    if not rbac.can(user, "report.files"):
        raise HTTPException(
            status_code=403,
            detail="These files cover every organization. Use the Findings "
                   "page, which only shows what you have been given.")

    from app.core import reports as reports_mod

    names = {"json": ("vulnerabilities.json", "application/json"),
             "csv": ("vulnerabilities.csv", "text/csv"),
             "vex-openvex": ("vex.openvex.json", "application/json"),
             "vex-cyclonedx": ("vex.cyclonedx.json", "application/json"),
             "sbom-cdx": (reports_mod.SBOM_COMBINED["cdx"][1], "application/json"),
             "sbom-spdx": (reports_mod.SBOM_COMBINED["spdx"][1], "application/json"),
             "sbom-summary": (reports_mod.SBOM_COMBINED["summary"][1],
                              "application/json")}

    with session_scope() as db:
        directory = reports_mod.output_dir(db)

    # The per repository SBOMs are a directory rather than a file, so they go
    # over as one archive.  Built on the way out and deleted once the response
    # has been written, because it is a copy of something already on disk and
    # keeping it would only mean two of everything.
    if which == "sbom-repos":
        from starlette.background import BackgroundTask

        folder = directory / reports_mod.SBOM_DIRECTORY
        if not folder.is_dir() or not any(folder.glob("*.json")):
            raise HTTPException(
                status_code=404,
                detail="No SBOMs have been kept yet. They are written by a "
                       "scan, so run one with SBOMs turned on.")
        archive = reports_mod.sbom_zip(directory)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return FileResponse(
            archive, media_type="application/zip",
            filename=f"sbom-by-repository-{stamp}.zip",
            background=BackgroundTask(archive.unlink, missing_ok=True))

    if which not in names:
        raise HTTPException(status_code=404, detail="No such file.")

    name, media = names[which]
    path = directory / name
    if not path.is_file():
        raise HTTPException(status_code=404,
                            detail="That file has not been written yet. Run a "
                                   "scan, or press Write them again.")
    return FileResponse(path, media_type=media, filename=name)


@router.get("/users")
def users(request: Request, msg: str = "", kind: str = "", tab: str = "",
          once: str = "", user: User = Depends(current_user)):
    rbac.require(user, "user.read")
    # A new or reset password arrives as a one time key rather than in msg,
    # so it never sits in a URL.
    if once:
        msg = _oneshot.take(once, user.id) or msg

    from app.core.models import ScanGroup

    with session_scope() as db:
        rows = db.query(User).order_by(User.username).all()
        for row in rows:
            # Load these while the session is open, or the template gets
            # nothing back.
            _ = [g.name for g in row.groups]
        groups = db.query(ScanGroup).order_by(ScanGroup.name).all()
        for group in groups:
            _ = len(group.members or [])
        # What each login actually reaches, so a developer seeing an empty
        # portal is a question somebody can answer from this page rather than
        # a mystery.  A login nobody has scanned yet resolves to nothing, and
        # saying so is the point.
        reach = {}
        for row in rows:
            if (row.github_login or "").strip():
                reach[row.id] = len(rbac.repositories_on_the_host(db, row))

        context = _shared(db, user)
        context.update(active_page="users", rows=rows,
                       reach=reach,
                       groups=groups,
                       tab=("groups" if tab == "groups" else "accounts"),
                       roles=[r.value for r in UserRole],
                       can_write=rbac.can(user, "user.write"),
                       can_impersonate=rbac.can(user, "user.impersonate"),
                       message=clean_notice(msg, limit=400),
                       message_kind="error" if kind == "error" else "ok")
        return page(request, "users.html", **context)


@router.get("/connections/{connection_id}/branches")
def connection_branches(connection_id: int, request: Request,
                        user: User = Depends(current_user)):
    """The branch names past scans found under one account.

    So the branch box is a choice rather than a memory test.  A name typed with
    the wrong case, or a branch that was renamed a year ago, matches nothing and
    says nothing about it, and a scan that covered no code is the one failure
    here nobody notices.
    """
    rbac.require(user, "settings.read")

    import json as json_module

    from app.core import connections as connection_store

    with session_scope() as db:
        row = connection_store.by_id(db, connection_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such connection.")
        answer = connection_store.discovered_branches(db, row)

    return Response(content=json_module.dumps(answer),
                    media_type="application/json",
                    headers={"Cache-Control": "no-store"})


@router.get("/connections")
def connections_page(request: Request, msg: str = "", kind: str = "",
                     q: str = "", user: User = Depends(current_user)):
    """The accounts this scans, one row per credential."""
    rbac.require(user, "settings.read")

    from app.core import connections as connection_store
    from app.core import connections as _connections
    from app.core import settings_store as connection_settings
    from app.core.models import Finding
    from sqlalchemy import func as sql_func

    with session_scope() as db:
        rows = connection_store.all_connections(db)
        counts = dict(db.query(Finding.connection, sql_func.count(Finding.id))
                      .group_by(Finding.connection).all())
        listed = [{
            "row": row,
            "configured": connection_store.configured(row),
            "findings": counts.get(row.name, 0),
        } for row in rows]

        # An estate with one credential per organization runs to dozens of
        # rows, which is more than anybody wants to read down.
        query = clean_text(q, "search", limit=200, required=False)
        total = len(listed)
        if query:
            needle = query.casefold()

            def matches(entry) -> bool:
                row = entry["row"]
                # Provider first, so "gitlab" finds every GitLab credential
                # without anybody having to name them consistently.  A row
                # written before the column existed reads as github, which is
                # what it is.
                haystack = " ".join(str(part or "") for part in (
                    row.name, row.organizations, row.repositories,
                    row.api_url, row.auth_method, row.last_status,
                    row.provider or "github",
                    row.application_name, row.application_owner,
                    row.technical_owner, row.sensitivity))
                return needle in haystack.casefold()

            listed = [entry for entry in listed if matches(entry)]
        context = _shared(db, user)
        context.update(
            active_page="connections",
            connections=listed,
            sensitivity_labels=connection_settings.sensitivity_labels(db),
            q=query,
            shown=len(listed),
            total=total,
            unassigned=counts.get("", 0) + counts.get(None, 0),
            # Names that appear in the data and in no connection.  A
            # connection can be removed while everything it brought in stays,
            # which is the right default, and the cost is a name that goes on
            # appearing in filters and reports with nothing behind it.
            leftovers=(_connections.leftovers(db)
                       if rbac.can(user, "settings.write") else []),
            can_write=rbac.can(user, "settings.write"),
            can_scope=rbac.can(user, "repo.scope"),
            message=clean_notice(msg, limit=1000),
            message_kind=kind if kind in ("error", "warn") else "ok",
        )
        return page(request, "connections.html", **context)


@router.get("/settings")
def settings_page(request: Request, msg: str = "", kind: str = "",
                  user: User = Depends(current_user)):
    """The setup form.

    Everything the scanner needs is here, and it all lives in the database.
    """
    rbac.require(user, "settings.read")
    from app.core import rule_mutes, settings_store as store
    from app.core.models import RuleMute
    from app.web.help_text import sections as help_sections

    with session_scope() as db:
        context = _shared(db, user)
        context.update(
            active_page="settings",
            # The links across the top and the ? beside each heading come from
            # the same list, so a section cannot end up in one and not the
            # other.
            help_sections=help_sections(),
            values=store.all_values(db),
            rulesets=store.RULESETS,
            muted_notes=store.MUTED_RULE_NOTES,
            mute_requests=rule_mutes.pending(db),
            mute_live={row.rule: row for row in db.query(RuleMute).filter(
                RuleMute.status.in_(["requested", "approved"])).all()},
            # In force because the tool ships them that way, with nobody here
            # having said anything either way.  The page has to show these as
            # set aside without putting a name to the decision.
            mute_shipped=rule_mutes.shipped_active(db),
            can_approve_mutes=rbac.can(user, "rule.mute.approve"),
            me=user.username,
            timezones=store.timezone_choices(),
            sensitivity_labels=store.sensitivity_labels(db),
            ruleset_names=store.RULESET_NAMES,
            describe=store.describe,
            configured=store.configured(db),
            readiness=store.readiness(db),
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok",
            can_write=rbac.can(user, "settings.write"),
        )
        return page(request, "settings.html", **context)


@router.get("/exclusions")
def exclusions_page(request: Request, msg: str = "", kind: str = "",
                    user: User = Depends(current_user)):
    """Findings somebody reviewed and accepted, and the reason each time."""
    rbac.require(user, "exclusion.read")
    from app.core import exclusions as exclusions_store

    params = request.query_params
    search = clean_text(params.get("q", ""), "Search", limit=200, required=False)
    of_kind = params.get("type", "")
    if of_kind not in exclusions_store.KINDS:
        of_kind = ""
    status = params.get("status", "")
    if status not in {"live", "expired"}:
        status = ""

    # Arriving from a finding by way of "exclude this value": the hash comes in
    # on the query string and the panel opens with it already filled in.  It is
    # checked rather than trusted, so a hand-made link cannot put arbitrary text
    # into the form.
    prefill = clean_text(params.get("exclude", ""), "Fingerprint", limit=128,
                         required=False).lower()
    if prefill and not exclusions_store.FINGERPRINT.match(prefill):
        prefill = ""
    prefill_kind = {"cred": "secret", "code": "code",
                    "dep": "vuln"}.get(prefill.split(":", 1)[0], "any")

    with session_scope() as db:
        rows = exclusions_store.visible(db, user, search=search, kind=of_kind,
                                        status=status)
        total = len(exclusions_store.visible(db, user))
        context = _shared(db, user)
        context.update(
            active_page="exclusions",
                       sensitivity_labels=_labels(db),
            exclusions=rows,
            kinds=exclusions_store.KINDS,
            live_count=sum(1 for row in rows if row.live()),
            expired_count=sum(1 for row in exclusions_store.visible(db, user)
                              if not row.live()),
            total=total,
            filters={"q": search, "type": of_kind, "status": status},
            prefill_fingerprint=prefill,
            prefill_kind=prefill_kind,
            **_expiry_window(180),
            can_write=rbac.can(user, "exclusion.write"),
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok",
        )
        return page(request, "exclusions.html", **context)


@router.get("/account/password")
def password_form(request: Request, error: str = "",
                  user: User = Depends(current_user)):
    """Change your own password.

    This is what must_change_password has always redirected to.  The page did
    not exist, so everybody an admin issued a password to landed on a 404 and
    nobody could change their own password at all.
    """
    from app.core.models import AuthSource

    return page(request, "password.html",
                active_page="account",
                user=user,
                local=(user.source == AuthSource.LOCAL),
                must_change=bool(user.must_change_password),
                error=clean_text(error, "error", limit=300, required=False))


@router.get("/severity")
def severity_page(request: Request, msg: str = "", kind: str = "",
                  rule: str = "", user: User = Depends(current_user)):
    """What findings are worth here, rather than what the engine guessed.

    A rule can arrive in the address, so the page that shows which rule is
    making the noise can hand this one over with the name already filled in.
    """
    rbac.require(user, "settings.read")
    from app.core import settings_store as severity_settings, severity_rules

    def severity_labels_for(db):
        return severity_settings.sensitivity_labels(db)

    with session_scope() as db:
        rules = severity_rules.all_rules(db)
        context = _shared(db, user)
        context.update(active_page="severity",
                       prefill_rule=clean_text(rule, "Rule", limit=200,
                                               required=False),
                       rules=rules,
                       # What each rule is, as a sentence, and how much of the
                       # estate it covers.  A rule is a decision about a set
                       # nobody can see from the page it is written on.
                       described={row.id: severity_rules.describe(row)
                                  for row in rules},
                       covers=severity_rules.counts_for(
                           db, rules, base=rbac.visible_findings(db, user)),
                       covers_query={row.id: severity_rules.findings_query(row)
                                     for row in rules},
                       fields=severity_rules.FIELDS,
                       combines=severity_rules.COMBINE,
                       severities=[s.value for s in Severity],
                       sensitivity_labels=severity_labels_for(db),
                       can_write=rbac.can(user, "settings.write"),
                       flash=clean_notice(msg, limit=300),
                       flash_kind=notice_class(kind))
        return page(request, "severity.html", **context)


@router.get("/tokens")
def tokens_page(request: Request, msg: str = "", kind: str = "",
                shown: str = "", user: User = Depends(current_user)):
    """Tokens for editors and pipelines.

    Anybody signed in can make their own, because the alternative is asking an
    administrator every time and that ends with one token shared by a team.
    """
    from app.core import api_tokens

    show_dead = request.query_params.get("dead") == "1"

    # The address a plugin has to be pointed at.  Worked out from the request
    # rather than stored, because whatever somebody reached this page on is
    # the address that works for them, and a value in a settings table is one
    # more thing to be wrong behind a proxy.
    base_url = str(request.base_url).rstrip("/") + (settings.base_path or "")

    with session_scope() as db:
        rows = api_tokens.listing(db, user, include_dead=show_dead)
        context = _shared(db, user)
        context.update(
            active_page="tokens",
            rows=rows,
            show_dead=show_dead,
            dead_count=api_tokens.dead_count(db, user),
            scopes=api_tokens.SCOPES,
            default_days=api_tokens.DEFAULT_DAYS,
            max_days=api_tokens.MAX_DAYS,
            sees_all=rbac.can(user, "user.write"),
            me=user.username,
            # Shown once, straight after it is made, and never again.  What
            # arrives in the address is a one time key, not the token.
            fresh=_oneshot.take(shown, user.id) if shown else "",
            api_url=f"{base_url}/api/v1",
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "tokens.html", **context)


@router.get("/tagging")
def tagging_page(request: Request, q: str = "", org: str = "",
                 show: str = "", user: User = Depends(current_user)):
    """What each repository is, who answers for it and what it holds."""
    rbac.require(user, "repo.read")
    from app.core import tagging
    from app.core.models import Repository

    search = clean_text(q, "Search", limit=200, required=False)
    organization = clean_text(org, "Organization", limit=255, required=False)

    with session_scope() as db:
        # Everything on this page starts from what this person may see: the
        # rows, the counts and the organization list alike.  It was the whole
        # estate's owners and data labels for anybody with repo.read.
        visible = rbac.visible_repositories(db, user)
        query = visible
        if organization:
            query = query.filter(Repository.organization == organization)
        if search:
            like = f"%{search}%"
            query = query.filter(Repository.full_name.ilike(like)
                                 | Repository.technical_owner.ilike(like)
                                 | Repository.application_name.ilike(like)
                                 | Repository.sensitivity.ilike(like))
        if show == "untagged":
            query = query.filter(
                (Repository.technical_owner == "")
                | (Repository.technical_owner.is_(None)))
        elif show == "tagged":
            query = query.filter(Repository.technical_owner != "",
                                 Repository.technical_owner.isnot(None))

        rows = query.order_by(Repository.organization, Repository.name).limit(500).all()
        resolved = tagging.effective_many(db, rows)
        total = visible.count()
        untagged = tagging.untagged(db, base=visible).count()

        orgs = [o[0] for o in visible.with_entities(Repository.organization)
                .distinct().order_by(Repository.organization).all() if o[0]]

        context = _shared(db, user)
        context.update(
            active_page="tagging",
            rows=rows, resolved=resolved, orgs=orgs,
            labels=tagging.labels(db),
            sensitivity_labels=tagging.labels(db),
            total=total, untagged=untagged, shown=len(rows),
            filters={"q": search, "org": organization, "show": show},
            can_write=rbac.can(user, "repo.write"),
            message=clean_notice(request.query_params.get("msg", ""), limit=300),
            message_kind="error" if request.query_params.get("kind") == "error" else "ok")
        return page(request, "tagging.html", **context)


@router.get("/blast-radius")
def blast_radius(request: Request, user: User = Depends(current_user)):
    """Who can reach what, by organization.

    An audit starts here: what each account holds, who answers for it, and how
    many people can reach it.
    """
    rbac.require(user, "repo.read")
    from app.core import access as access_store

    with session_scope() as db:
        # Only what this person may see.  The access map is the estate's list
        # of who can push where, which is a target list as much as an audit.
        rows = access_store.organizations(
            db, rbac.visible_repository_names(db, user))
        context = _shared(db, user)
        context.update(
            active_page="blast-radius",
            orgs=rows,
            totals={
                "organizations": len(rows),
                "repositories": sum(r["repositories"] for r in rows),
                "people": sum(r["people"] for r in rows),
                "admins": sum(r["admins"] for r in rows),
                "outside": sum(r["outside"] for r in rows),
                "unprotected": sum(r["unprotected"] for r in rows),
            })
        return page(request, "blast_radius.html", **context)


# Declared before /blast-radius/{organization} for the same reason as the
# software page below.
@router.get("/blast-radius/web-apps")
def blast_web_apps(request: Request, q: str = "", within: str = "",
                   user: User = Depends(current_user)):
    """Every web application, the repositories behind it, and when they moved.

    For deciding which sites may want another penetration test because the
    code behind them changed.  A commit is not a deployment, and the page says
    so: this reads the repository, not what is running.
    """
    rbac.require(user, "repo.read")
    from app.core import webapps

    search = clean_text(q, "Search", limit=200, required=False)
    try:
        window = int(within or 0)
    except ValueError:
        window = 0
    if window not in webapps.WINDOWS:
        window = 0

    with session_scope() as db:
        # Open findings per repository, so the site whose code moved and
        # already carries something open reads as the first one to look at.
        counts = {}
        for repo_name, severity, total in (
                rbac.visible_findings(db, user)
                .filter(Finding.state == FindingState.OPEN)
                .filter(Finding.out_of_scope.is_(False))
                .with_entities(Finding.repository, Finding.severity,
                               func.count(Finding.id))
                .group_by(Finding.repository, Finding.severity).all()):
            counts.setdefault(repo_name or "", {})[
                getattr(severity, "value", "")] = total
        everything = webapps.inventory(
            db, base=rbac.visible_repositories(db, user), counts=counts)
        shown = webapps.narrow(everything, search, window)
        context = _shared(db, user)
        context.update(active_page="blast-radius", blast_tab="web-apps",
                       apps=shown, totals=webapps.summary(shown),
                       marked=len(everything), q=search, within=window,
                       windows=webapps.WINDOWS)
        return page(request, "blast_web_apps.html", **context)


# Declared before /blast-radius/{organization}, or "software" would be read as
# the name of an organization and nobody would ever reach this page.
@router.get("/blast-radius/software")
def software(request: Request, q: str = "", ecosystem: str = "",
             organization: str = "", repository: str = "", branch: str = "",
             license: str = "", unlicensed: str = "", vulnerable: str = "",
             page_no: int = 1, user: User = Depends(current_user)):
    """Every package in the estate, and where each one sits.

    The list the findings pages cannot give you.  A finding exists because
    somebody published an advisory; this exists because the package is there.
    When a release is announced as compromised on a Tuesday morning it will
    not have an advisory for days, and the only useful question is whether
    that exact version is anywhere in the code.
    """
    rbac.require(user, "repo.read")
    from app.core import software as software_store

    filters = {
        "search": clean_text(q, "Search", limit=200, required=False),
        "ecosystem": clean_text(ecosystem, "Ecosystem", limit=64, required=False),
        "organization": clean_text(organization, "Organization", limit=255,
                                   required=False),
        "repository": clean_text(repository, "Repository", limit=320,
                                 required=False),
        "branch": clean_text(branch, "Branch", limit=255, required=False),
        "license_text": clean_text(license, "License", limit=120, required=False),
        "unlicensed": unlicensed in ("1", "true", "on", "yes"),
    }
    only_vulnerable = vulnerable in ("1", "true", "on", "yes")

    with session_scope() as db:
        found = software_store.inventory(db, user, page=page_no,
                                         vulnerable=only_vulnerable, **filters)
        context = _shared(db, user)
        context.update(
            active_page="blast-radius", blast_tab="software",
            rows=found["rows"], total=found["total"],
            page_no=found["page"], pages=found["pages"],
            totals=found["summary"],
            choices=software_store.choices(db, user),
            q=filters["search"], ecosystem=filters["ecosystem"],
            organization=filters["organization"],
            repository=filters["repository"], branch=filters["branch"],
            license=filters["license_text"],
            unlicensed=filters["unlicensed"], vulnerable=only_vulnerable,
            query_string=urlencode({k: v for k, v in {
                "q": filters["search"], "ecosystem": filters["ecosystem"],
                "organization": filters["organization"],
                "repository": filters["repository"], "branch": filters["branch"],
                "license": filters["license_text"],
                "unlicensed": "1" if filters["unlicensed"] else "",
                "vulnerable": "1" if only_vulnerable else "",
            }.items() if v}),
            can_export=rbac.can(user, "findings.export"))
        return page(request, "software.html", **context)


@router.get("/blast-radius/software/where")
def software_where(request: Request, name: str = "", version: str = "",
                   ecosystem: str = "", user: User = Depends(current_user)):
    """One package, everywhere it is.

    Version left blank on purpose when somebody arrives from a search: which
    versions are here is the question that comes before whether it matters.
    """
    rbac.require(user, "repo.read")
    from app.core import software as software_store

    name = clean_text(name, "Package", limit=512)
    version = clean_text(version, "Version", limit=128, required=False)
    ecosystem = clean_text(ecosystem, "Ecosystem", limit=64, required=False)

    with session_scope() as db:
        places = software_store.where(db, user, name, version, ecosystem)
        versions = {}
        for place in places:
            versions.setdefault(place["version"] or "unknown",
                                {"branches": 0, "repositories": set(),
                                 "vulnerable": False, "worst": ""})
            seen = versions[place["version"] or "unknown"]
            seen["branches"] += 1
            seen["repositories"].add(place["repository"])
            seen["vulnerable"] = seen["vulnerable"] or place["vulnerable"]
            if place["vulnerable"] and (
                    not seen["worst"]
                    or software_store.SEVERITY_RANK.get(place["worst"], 9)
                    < software_store.SEVERITY_RANK.get(seen["worst"], 9)):
                seen["worst"] = place["worst"]
        for seen in versions.values():
            seen["repositories"] = len(seen["repositories"])

        context = _shared(db, user)
        context.update(
            active_page="blast-radius", blast_tab="software",
            name=name, version=version, ecosystem=ecosystem,
            places=places, versions=dict(sorted(versions.items())),
            repositories=len({p["repository"] for p in places}),
            organizations=len({p["organization"] for p in places if p["organization"]}),
            can_export=rbac.can(user, "findings.export"))
        return page(request, "software_where.html", **context)


@router.get("/blast-radius/software/export")
def software_export(request: Request, format: str = "csv", q: str = "",
                    ecosystem: str = "", organization: str = "",
                    repository: str = "", branch: str = "", license: str = "",
                    unlicensed: str = "", vulnerable: str = "", name: str = "",
                    version: str = "", user: User = Depends(current_user)):
    """The inventory as a file, narrowed the same way the page was.

    Flat, one row per package per branch per repository, because whatever
    reads it wants to join it to its own list rather than read a count.

    CycloneDX is the same search again as a bill of materials, for the tools
    that will only read one.  It is a document rather than a table, so it
    carries the graph the other two formats have no room for.
    """
    rbac.require(user, "findings.export")
    from app.core import software as software_store

    # Arriving from the detail page: one package, every place it is, rather
    # than whatever the filter row on the list page happened to say.
    filters = {}
    one_name = clean_text(name, "Package", limit=512, required=False)
    one_version = clean_text(version, "Version", limit=128, required=False)
    one_ecosystem = clean_text(ecosystem, "Ecosystem", limit=64, required=False)
    if not name:
        filters = {
            "search": clean_text(q, "Search", limit=200, required=False),
            "ecosystem": clean_text(ecosystem, "Ecosystem", limit=64, required=False),
            "organization": clean_text(organization, "Organization", limit=255,
                                       required=False),
            "repository": clean_text(repository, "Repository", limit=320,
                                     required=False),
            "branch": clean_text(branch, "Branch", limit=255, required=False),
            "license_text": clean_text(license, "License", limit=120,
                                       required=False),
            "unlicensed": unlicensed in ("1", "true", "on", "yes"),
        }
    only_vulnerable = vulnerable in ("1", "true", "on", "yes")

    with session_scope() as db:
        if name:
            rows = [
                {"organization": place["organization"],
                 "repository": place["repository"], "branch": place["branch"],
                 "package": place["name"], "version": place["version"],
                 "ecosystem": place["ecosystem"], "license": place["licenses"],
                 "purl": place["purl"], "kind": place["kind"],
                 "connection": place["connection"],
                 "vulnerable": "true" if place["vulnerable"] else "false",
                 "worst_severity": place["worst"],
                 "advisories": " ".join(place["advisories"]),
                 "known_exploited": "true" if place["known_exploited"] else "false",
                 "malicious": "true" if place["malicious"] else "false",
                 "first_seen": place["first_seen"].isoformat() if place["first_seen"] else "",
                 "last_seen": place["last_seen"].isoformat() if place["last_seen"] else ""}
                for place in software_store.where(
                    db, user, one_name, one_version, one_ecosystem)]
        else:
            rows = software_store.rows_for_export(
                db, user, vulnerable=only_vulnerable, **filters)
        # Inside the session, because the document is written after it closes
        # and an advisory with no severity on it reads as one nobody graded.
        severities = (software_store.advisory_severities(db)
                      if format == "cdx" else {})

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    # The name goes in a Content-Disposition header, so it is cut down to what
    # a filename may hold rather than passed through from the query string.
    label = re.sub(r"[^A-Za-z0-9._@-]+", "-",
                   (name or q or ecosystem or organization or "all"))[:80] or "all"
    suffix = {"json": "json", "cdx": "cdx.json"}.get(format, "csv")
    filename = f"software-{label}-{stamp}.{suffix}"

    if format == "cdx":
        import json as json_module

        # What the search was, said in the document, from the cleaned values
        # rather than the query string: this goes into a file somebody keeps,
        # and a document that cannot say what it covers is one nobody can tell
        # apart from the next one six months later.
        document = software_store.cyclonedx(
            rows, scope=label, severities=severities,
            filters={"q": one_name or filters.get("search", ""),
                     "version": one_version if name else "",
                     "ecosystem": one_ecosystem if name
                                  else filters.get("ecosystem", ""),
                     "organization": filters.get("organization", ""),
                     "repository": filters.get("repository", ""),
                     "branch": filters.get("branch", ""),
                     "license": filters.get("license_text", ""),
                     "unlicensed": "1" if filters.get("unlicensed") else "",
                     "vulnerable": "1" if only_vulnerable else ""})
        # The media type CycloneDX registers, with the version on it.  Plenty
        # of the tools this file is for sniff that rather than open the
        # document, and the ones that do not are unharmed by it being right.
        return Response(
            content=json_module.dumps(document, indent=2) + "\n",
            media_type="application/vnd.cyclonedx+json; version=1.6",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    if format == "json":
        import json as json_module

        body = json_module.dumps(
            {"generated_at": datetime.now(timezone.utc).isoformat(),
             "scope": label, "rows": len(rows), "software": rows}, indent=2)
        return Response(content=body, media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{filename}"'})

    import csv as csv_module
    import io as io_module

    buffer = io_module.StringIO()
    writer = csv_module.DictWriter(buffer,
                                   fieldnames=software_store.EXPORT_COLUMNS,
                                   extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(spreadsheet_row(row) for row in rows)
    return Response(content=buffer.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition":
                             f'attachment; filename="{filename}"'})


@router.get("/blast-radius/{organization}")
def blast_radius_org(organization: str, request: Request, view: str = "people",
                     user: User = Depends(current_user)):
    """One organization, opened on whichever column somebody clicked."""
    rbac.require(user, "repo.read")
    from app.core import access as access_store
    from app.core.models import Repository

    organization = clean_text(organization, "Organization", limit=255)
    # "all" is every organization at once, which is what the estate wide
    # numbers at the top of the landing page open.
    everything = organization == "all"
    if view not in {"people", "admins", "outside", "repos", "unprotected", "machines"}:
        view = "people"

    with session_scope() as db:
        allowed = rbac.visible_repository_names(db, user)
        everybody = access_store.people(db, "" if everything else organization,
                                        allowed)

        if view == "admins":
            shown = [p for p in everybody if p["highest"] == "admin"]
        elif view == "outside":
            shown = [p for p in everybody if p["outside"]]
        elif view == "machines":
            shown = [p for p in everybody if p["machine"]]
        else:
            shown = everybody

        # By repository rather than by person, for the two views that ask it
        # that way round.
        by_repo = {}
        for person in everybody:
            for entry in person["repositories"]:
                by_repo.setdefault(entry["repository"], []).append(
                    {"login": person["login"], "permission": entry["permission"],
                     "outside": person["outside"], "machine": person["machine"]})
        for people_here in by_repo.values():
            people_here.sort(key=lambda p: (-access_store.RANK.get(p["permission"], 0),
                                            p["login"].lower()))

        protection = db.query(Repository).filter(
            Repository.default_branch_protected.is_(False))
        if not everything:
            protection = protection.filter(Repository.organization == organization)
        unprotected = {r.full_name for r in protection.all()
                       if allowed is None or r.full_name in allowed}
        if view == "unprotected":
            by_repo = {name: people_here for name, people_here in by_repo.items()
                       if name in unprotected
                       and any(access_store.RANK.get(p["permission"], 0)
                               >= access_store.RANK["write"] for p in people_here)}

        # What each repository is, for the panel that opens under its row.
        # Only for the view that shows them, and only for the ones on screen:
        # this is a per repository lookup and an estate wide people view has
        # no use for it.
        detail = {}
        if view in ("repos", "unprotected") and by_repo:
            from app.core import repo_context
            for name in list(by_repo)[:1000]:
                # Not the people: this page already has them, from the rollup
                # it built above, and asking again per row would be the
                # slowest thing on it.
                known = repo_context.for_repository(db, name, with_people=False)
                if known:
                    detail[name] = known

        context = _shared(db, user)
        context.update(
            active_page="blast-radius",
            detail=detail,
            can_describe=rbac.can(user, "repo.describe"),
            organization=("every organization" if everything else organization),
            export_scope=("all" if everything else organization),
            view=view,
            people=shown,
            everybody=everybody,
            by_repo=dict(sorted(by_repo.items())),
            unprotected=unprotected,
            # Who answers for an organization is about the organization, so
            # it is shown only to somebody who can see something in it.
            owner=(access_store.owner_context(db).get(organization, {})
                   if allowed is None
                   or any(name.split("/", 1)[0] == organization for name in allowed)
                   else {}),
            counts={
                "people": len(everybody),
                "admins": sum(1 for p in everybody if p["highest"] == "admin"),
                "outside": sum(1 for p in everybody if p["outside"]),
                "machines": sum(1 for p in everybody if p["machine"]),
                "repos": len(by_repo) if view != "unprotected" else None,
            })
        return page(request, "blast_radius_org.html", **context)


@router.get("/blast-radius/{organization}/export")
def blast_radius_export(organization: str, request: Request,
                        format: str = "csv",
                        user: User = Depends(current_user)):
    """One organization, or everything, as a file somebody can keep."""
    rbac.require(user, "findings.export")
    from app.core import access as access_store

    wanted = "" if organization == "all" else clean_text(
        organization, "Organization", limit=255)
    if format not in {"csv", "json"}:
        format = "csv"

    with session_scope() as db:
        rows = access_store.rows_for_export(
            db, wanted, rbac.visible_repository_names(db, user))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    name = f"blast-radius-{(wanted or 'all').replace('/', '-')}-{stamp}.{format}"

    if format == "json":
        import json as json_module

        from fastapi.responses import Response
        body = json_module.dumps(
            {"generated_at": datetime.now(timezone.utc).isoformat(),
             "scope": wanted or "all organizations",
             "rows": len(rows), "access": rows}, indent=2)
        return Response(content=body, media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{name}"'})

    import csv as csv_module
    import io as io_module

    from fastapi.responses import Response

    buffer = io_module.StringIO()
    if rows:
        writer = csv_module.DictWriter(buffer, fieldnames=list(rows[0]),
                                       lineterminator="\n")
        writer.writeheader()
        writer.writerows(spreadsheet_row(row) for row in rows)
    return Response(content=buffer.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition":
                             f'attachment; filename="{name}"'})


@router.get("/utilization")
def utilization_page(request: Request, user: User = Depends(current_user)):
    """CPU, memory, disk and network, for this server and for this app.

    The page is a shell.  utilization.js fills it from the two JSON routes
    below, so the gauges move without a reload.
    """
    rbac.require(user, "utilization.read")
    with session_scope() as db:
        context = _shared(db, user)
        context.update(active_page="utilization")
        return page(request, "utilization.html", **context)


def _whole_ms(value, low, high, fallback):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return fallback
    return max(low, min(high, number))


@router.get("/utilization/live")
def utilization_live(since: str = "0", user: User = Depends(current_user)):
    """The latest reading, for the gauges."""
    from app.core import utilization

    rbac.require(user, "utilization.read")
    return utilization.current(_whole_ms(since, 0, 2 ** 53, 0))


@router.get("/utilization/history")
def utilization_history(start: str = "", end: str = "",
                        user: User = Depends(current_user)):
    """The trend over a range, in epoch milliseconds, at most a year."""
    import time as _time

    from app.core import utilization

    rbac.require(user, "utilization.read")
    now = int(_time.time() * 1000)
    to = _whole_ms(end, 0, now + 60000, now)
    frm = _whole_ms(start, 0, now, to - 86400000)
    if not to > frm:
        raise HTTPException(status_code=400,
                            detail="The end of the range has to be after the start.")
    if to - frm > utilization.MAX_SPAN_SEC * 1000:
        raise HTTPException(status_code=400,
                            detail="That range is longer than the history kept, "
                                   "a year at most.")
    return utilization.history(frm, to)


@router.get("/backup")
def backup_page(request: Request, msg: str = "", kind: str = "",
                user: User = Depends(current_user)):
    """Take a copy of this installation, or put one back."""
    rbac.require(user, "settings.write")
    from app.core import backup as backup_store
    from app.core.models import Base

    with session_scope() as db:
        counts = {}
        for table in Base.metadata.sorted_tables:
            if table.name in backup_store.SKIP_TABLES:
                continue
            n = db.execute(table.count()).scalar() if hasattr(table, "count") else None
            if n is None:
                from sqlalchemy import func, select
                n = db.execute(select(func.count()).select_from(table)).scalar()
            if n:
                counts[table.name] = n

        context = _shared(db, user)
        context.update(
            active_page="backup",
            counts=counts,
            total_rows=sum(counts.values()),
            min_password=backup_store.MIN_PASSWORD,
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "backup.html", **context)


@router.get("/triage")
def triage_page(request: Request, msg: str = "", kind: str = "",
                sample: str = "", target: str = "",
                user: User = Depends(current_user)):
    """What the scanner treats as an example rather than a credential."""
    rbac.require(user, "settings.read")
    from app.core import settings_store as triage_settings, triage_rules

    # Trying a sample is the only way to see what a value rule does: the
    # cleartext it matches never leaves the scan, so there is nothing stored
    # here to run it against.
    sample = clean_text(sample, "Sample", limit=500, required=False)
    against = target if target in triage_rules.TARGETS else "value"

    with session_scope() as db:
        rules = triage_rules.listing(db)
        hits = []
        matched_paths = []
        if sample:
            live = [r["pattern"] for r in rules
                    if r["target"] == against and r["enabled"]]
            hits = triage_rules.matches(live, sample)
            # A path can be tried against what is already here.  A value
            # cannot: the database holds a hash, not the secret.
            if against == "path" and hits:
                matched_paths = (db.query(Finding)
                                 .filter(Finding.kind == FindingKind.CREDENTIAL)
                                 .filter(Finding.file_path == sample)
                                 .count())

        context = _shared(db, user)
        context.update(
            active_page="triage",
            rules=rules,
            targets=triage_rules.TARGETS,
            shipped_count=sum(1 for r in rules if r["source"] == "shipped"),
            custom_count=sum(1 for r in rules if r["source"] == "custom"),
            off_count=sum(1 for r in rules if not r["enabled"]),
            sample=sample,
            sample_target=against,
            sample_hits=hits,
            sample_findings=matched_paths,
            min_entropy=triage_settings.get(db, "secrets.min_entropy"),
            min_length=triage_settings.get(db, "secrets.min_length"),
            drop_below_entropy=bool(triage_settings.get(
                db, "secrets.drop_below_entropy")),
            can_write=rbac.can(user, "settings.write"),
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "triage.html", **context)


@router.get("/noise")
def noise_page(request: Request, msg: str = "", kind: str = "",
               only: str = "", user: User = Depends(current_user)):
    """Which rules are producing the work list.

    Tuning is a rule level job, and until this page existed the product only
    offered a finding level view of it. Ten decisions usually move half the
    list; this is the page that says which ten.
    """
    rbac.require(user, "findings.read")
    from app.core import noise, rule_mutes

    only = only if only in {k.value for k in FindingKind} else ""

    with session_scope() as db:
        rows = noise.ranked(db, user, kind=only)
        totals = noise.summary(db, user, rows)

        # What is already set aside, so a row does not offer to do it twice.
        muted = set(rule_mutes.effective(db))
        shipped = rule_mutes.shipped_active(db)
        waiting = {row.rule for row in rule_mutes.pending(db)}
        for row in rows:
            row["muted"] = row["rule"] in muted
            row["shipped"] = row["rule"] in shipped
            row["pending"] = row["rule"] in waiting

        context = _shared(db, user)
        context.update(
            active_page="noise",
            rows=rows,
            totals=totals,
            only=only,
            kinds=[k.value for k in FindingKind],
            can_mute=rbac.can(user, "rule.mute.request"),
            can_grade=rbac.can(user, "settings.write"),
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "noise.html", **context)


def _when(value):
    """A stored ISO time back as a datetime, or None."""
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


@router.get("/notifications")
def notifications_page(request: Request, msg: str = "", kind: str = "",
                       user: User = Depends(current_user)):
    """Telling somebody, without waiting for them to log in."""
    rbac.require(user, "settings.read")
    from app.core import settings_store as notify_settings

    keys = [name for name in notify_settings.DEFAULTS if name.startswith("notify.")]
    with session_scope() as db:
        values = {}
        for key in keys:
            # A stored secret is never sent back to the browser.  The form
            # shows whether there is one, which is all anybody needs to decide
            # whether to type a new one.
            if notify_settings.is_secret(key):
                values[key] = bool(notify_settings.get(db, key))
            else:
                values[key] = notify_settings.get(db, key)
        from app.core import org_coverage

        coverage = org_coverage.last(db)
        context = _shared(db, user)
        context.update(
            active_page="notifications",
            values=values,
            coverage=coverage,
            coverage_at=_when(coverage.get("checked_at")),
            can_write=rbac.can(user, "settings.write"),
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "notifications.html", **context)


@router.get("/ai")
def ai_page(request: Request, msg: str = "", kind: str = "", tab: str = "",
            days: int = 30, user: User = Depends(current_user)):
    """Which language model reads a finding when somebody asks it to."""
    rbac.require(user, "settings.read")
    from app.core import ai, ai_cost, settings_store as store

    keys = [name for name in store.DEFAULTS if name.startswith("ai.")]
    with session_scope() as db:
        values = {}
        for key in keys:
            # The same rule as everywhere else: a stored secret is never sent
            # back to the browser, only whether there is one.
            if store.is_secret(key):
                values[key] = bool(store.get(db, key))
            else:
                values[key] = store.get(db, key)
        cfg = ai.config(db)
        context = _shared(db, user)
        context.update(
            active_page="ai",
            values=values,
            efforts=ai.EFFORTS,
            custom_example=ai.CUSTOM_EXAMPLE,
            problem=ai.missing(cfg) if ai.enabled(cfg) else "",
            can_write=rbac.can(user, "settings.write"),
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok")
        # The cost tab belongs to the custom service, which is the one whose
        # prices nobody else publishes.
        has_cost = cfg.get("ai.provider") == "custom"
        tab = "cost" if tab == "cost" and has_cost else "settings"
        days = max(1, min(366, int(days or 30)))
        context.update(tab=tab, has_cost=has_cost, cost_days=days,
                       cost_windows=(7, 30, 90, 365))
        if tab == "cost":
            usage = ai_cost.summary(db, cfg, days)
            context.update(usage=usage,
                           usage_chart=ai_cost.chart(usage["daily"], usage["priced"]))
        return page(request, "ai.html", **context)


def _can_validate_ai(db, user) -> str:
    """Which bulk button belongs on the findings list for this person.

    "ai" when a model is set up, "rules" when it is not but rules have been
    learned, which still apply with AI off, and "" when neither.
    """
    from app.core import ai
    from app.core.models import LearnedRule
    if not rbac.can(user, "finding.validate"):
        return ""
    cfg = ai.config(db)
    if ai.enabled(cfg) and not ai.missing(cfg):
        return "ai"
    if db.query(LearnedRule).filter(LearnedRule.retired_at.is_(None)).first() is not None:
        return "rules"
    return ""


def _ai_grade_context(db, row) -> dict:
    """What AI validation and learned rules say about one finding, for its page."""
    from app.core import learned
    from app.core.models import AIGrade, GradeBasis, LearnedRule

    grade = db.query(AIGrade).filter(AIGrade.finding_id == row.id).one_or_none()
    rule = None
    if grade is not None and grade.rule_id:
        rule = db.get(LearnedRule, grade.rule_id)
    elif grade is None and not learned.protected(row):
        rule = learned.match(learned.load_rules(db), row)
    lifted = (db.query(GradeBasis)
              .filter(GradeBasis.finding_id == row.id, GradeBasis.lifted_at.isnot(None))
              .order_by(GradeBasis.lifted_at.desc()).all())
    return {"ai_grade": grade, "ai_rule": rule,
            "ai_rule_text": learned.describe(rule) if rule is not None else "",
            "ai_protected": learned.protected(row), "lifted_grades": lifted}


@router.get("/ai/learned")
def learned_page(request: Request, msg: str = "", kind: str = "", batch: int = 0,
                 show: str = "", per_page: int = 100, offset: int = 0, q: str = "",
                 user: User = Depends(current_user)):
    """What AI validation has taught the scanner, and how a bulk run is going."""
    rbac.require(user, "finding.validate")
    from app.core import analysis, learned
    from app.core.models import LearnedRule

    if per_page not in PAGE_SIZES:
        per_page = 100
    offset = max(0, offset)
    with session_scope() as db:
        query = db.query(LearnedRule)
        q = (q or "").strip()[:200]
        number = q.lstrip("#").strip()
        if number.isdigit():
            # A number is one rule, live or retired, since a finding's page
            # names the rule that graded it either way.
            query = query.filter(LearnedRule.id == int(number))
        else:
            if show != "retired":
                query = query.filter(LearnedRule.retired_at.is_(None))
            if q:
                query = query.filter(sa_or(*[column.contains(q, autoescape=True) for column in (
                    LearnedRule.repository, LearnedRule.rule, LearnedRule.package,
                    LearnedRule.path_glob, LearnedRule.reason)]))
        total = query.count()
        if offset >= total:
            offset = 0
        rules = (query.order_by(LearnedRule.created_at.desc(), LearnedRule.id.desc())
                 .offset(offset).limit(per_page).all())
        rows = [{"rule": r, "text": learned.describe(r), "local_only": learned.local_only(r),
                 "problems": learned.self_test(r) if r.retired_at is None else [],
                 "cases": learned.fixture_of(r)} for r in rules]
        status = analysis.batch_status(batch or None)
        context = _shared(db, user)
        context.update(
            active_page="ai", rows=rows, show=show, batch=status,
            total=total, offset=offset, per_page=per_page, page_sizes=PAGE_SIZES,
            q=q, page_query=urlencode([(k, v) for k, v in (("show", show), ("q", q))
                                       if v and (k != "show" or v == "retired")]),
            can_write=rbac.can(user, "settings.write"),
            message=clean_notice(msg, limit=300),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "learned.html", **context)


@router.get("/editors")
def editors_page(request: Request, user: User = Depends(current_user)):
    """The packages for the editors, and how to point each one at this server.

    A developer here cannot install this from a marketplace.  Most of these
    installations sit on a private network and a fair number on one with no
    way out at all, so the server hands out its own packages rather than
    sending somebody to Microsoft for them.

    Everybody signed in can have them.  A plugin reaches what its owner's token
    reaches, which is what their account already sees on these pages, so there
    is nothing here to keep from a reader.
    """
    from app.core import editor_plugins

    # The address they reached this on, which is the one that works for them.
    # A value in a settings table is one more thing to be wrong behind a proxy.
    base_url = str(request.base_url).rstrip("/") + (settings.base_path or "")

    packages = []
    problem = ""
    if editor_plugins.available():
        try:
            packages = [editor_plugins.describe(key)
                        for key in ("vsix", "lsp")]
        except OSError as exc:
            # Worth saying out loud rather than showing an empty page: the
            # usual cause is a read only data directory, and the fix is not
            # something a developer can guess at.
            log.warning("could not build the editor packages: %s", exc)
            problem = ("The packages could not be built on this server.  "
                       "Whoever runs it will find the reason in the log.")
    else:
        problem = ("This installation was built without the editor source, so "
                   "there is nothing to hand out.  The language server and the "
                   "extension both live in ide/ in the release.")

    with session_scope() as db:
        context = _shared(db, user)
        context.update(
            active_page="editors",
            packages={row["key"]: row for row in packages},
            problem=problem,
            api_url=f"{base_url}/api/v1",
            lsp_root=editor_plugins.LSP_ROOT,
            version=VERSION)
        return page(request, "editors.html", **context)


@router.get("/editors/download/{which}")
def download_editor_package(which: str, request: Request,
                            user: User = Depends(current_user)):
    """Hand over one of the packages.

    Built on the way out if it is not there, which keeps it in step with the
    version of the server serving it.  Nothing in either package is secret:
    it is the same JavaScript that ships in the image, and it is useless
    without a token the person has to make for themselves.
    """
    from fastapi.responses import FileResponse

    from app.core import editor_plugins

    if which not in editor_plugins.BUILDERS:
        raise HTTPException(status_code=404, detail="No such package.")
    if not editor_plugins.available():
        raise HTTPException(
            status_code=404,
            detail="This installation was built without the editor source.")

    name, _builder, media = editor_plugins.BUILDERS[which]
    try:
        path = editor_plugins.build(which)
    except OSError as exc:
        log.warning("could not build %s: %s", which, exc)
        raise HTTPException(status_code=500,
                            detail="The package could not be built here.")
    return FileResponse(path, media_type=media, filename=name)


@router.get("/docs/connections-{provider}")
def connection_docs(provider: str, request: Request,
                    user: User = Depends(current_user)):
    """How to set a credential up, per host.

    Linked from the connection form, because the resource owner trap and the
    GitLab token kinds are exactly the things somebody needs while filling it
    in rather than afterwards.
    """
    pages = {"github": "docs_github.html", "gitlab": "docs_gitlab.html",
             "bitbucket": "docs_bitbucket.html",
             # One page for the two of them: Forgejo is a fork of Gitea and
             # everything on it - the token, the address, the scopes - is the
             # same, so a second copy would be one more thing to keep in step.
             "gitea": "docs_gitea.html", "forgejo": "docs_gitea.html"}
    template = pages.get((provider or "").strip().lower())
    if template is None:
        raise HTTPException(status_code=404, detail="No guide for that one yet.")
    with session_scope() as db:
        context = _shared(db, user)
        context.update(active_page="connections")
        return page(request, template, **context)


@router.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Browsers ask for this by name whatever the page's icon link says.

    The mark is our own.  It used to be GitHub's Octocat, which is their
    trademark and not ours to ship.
    """
    from pathlib import Path

    from fastapi.responses import FileResponse

    icon = Path(__file__).resolve().parent / "static" / "icon.svg"
    if not icon.exists():
        raise HTTPException(status_code=404, detail="No icon.")
    return FileResponse(icon, media_type="image/svg+xml")


@router.get("/account")
def account(request: Request, user: User = Depends(current_user)):
    with session_scope() as db:
        context = _shared(db, user)
        context.update(active_page="account")
        return page(request, "account.html", **context)
