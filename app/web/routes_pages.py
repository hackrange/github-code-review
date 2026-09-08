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
from sqlalchemy import case, func, or_ as sa_or

from app.config import APP_NAME, VERSION, settings
from app.core import baseline as baseline_filter
from app.core import rbac, recommendation, repo_context, risk
from app.core.db import session_scope
from app.core.models import (
    AuditEvent, Finding, FindingKind, FindingState, Repository, ScanRun,
    Schedule, Severity, User, UserRole, Waiver, WaiverStatus,
)
from app.web.render import notice_class, page, render_partial
from app.web.security import clean_text, current_user

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


def _shared(db, user: User) -> dict:
    """The handful of things the shell needs on every page."""
    pending = 0
    if rbac.can(user, "waiver.approve"):
        pending = (db.query(func.count(Waiver.id))
                   .filter(Waiver.status == WaiverStatus.REQUESTED).scalar()) or 0

    last = (db.query(ScanRun)
            .filter(ScanRun.status == "finished")
            .order_by(ScanRun.finished_at.desc())
            .first())
    return {
        "user": user,
        "pending_waivers": pending,
        "last_scan": _ago(last.finished_at) if last and last.finished_at else "",
        # The shell decides whether to offer the link, so a role without the
        # permission is not shown a page it would be refused at.
        "can_see_trends": rbac.can(user, "trend.read"),
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
    "id":         Finding.vuln_id,
}


def _sort_order(sort: str, direction: str):
    """Order by whichever column was clicked, priority by default."""
    if sort not in SORTABLE or sort == "priority":
        return [_priority_order(), Finding.last_found_at.desc()]
    column = SORTABLE[sort]
    ordered = column.desc() if direction == "desc" else column.asc()
    # A stable second key, or rows with equal values shuffle between pages.
    return [ordered, Finding.id.asc()]


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
    severity_rank = case(
        (Finding.severity == Severity.CRITICAL, 5),
        (Finding.severity == Severity.HIGH, 4),
        (Finding.severity == Severity.MEDIUM, 3),
        (Finding.severity == Severity.LOW, 2),
        else_=1)

    # Unrated sits between medium and high rather than at the bottom: nothing
    # is known about it, which is not the same as knowing it is weak.
    confidence_weight = case(
        (Finding.confidence == "high", 100),
        (Finding.confidence == "medium", 70),
        (Finding.confidence == "low", 40),
        else_=85)

    # A credential somebody proved still works outranks everything, and a
    # vulnerability on the CISA exploited list is not theoretical.
    verified_bonus = case((Finding.verified.is_(True), 250), else_=0)
    exploited_bonus = case((Finding.known_exploited.is_(True), 150), else_=0)

    # A vulnerability in a package nothing imports is a real vulnerability in
    # nothing, and a critical one in a test framework should not sit above a
    # medium in code that ships.  This moves it down the list rather than out
    # of it: no verdict is worth the same as reachable, so a scan from before
    # there was one ranks exactly where it used to.
    reachability_weight = case(
        (Finding.reachability == "unlikely", -120),
        (Finding.reachability == "unknown", -30),
        else_=0)

    return (severity_rank * confidence_weight + verified_bonus
            + exploited_bonus + reachability_weight).desc()


def _filtered_findings(db, user, params):
    """The findings query behind the Findings page, filters and all.

    Shared with the export, so the number in the file is the number on the
    screen.  Two copies of this logic would drift within a week.
    """
    query = rbac.visible_findings(db, user)

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
        query = query.filter(Finding.severity == Severity(severity))
    if kind in {k.value for k in FindingKind}:
        query = query.filter(Finding.kind == FindingKind(kind))
    if state in {s.value for s in FindingState}:
        query = query.filter(Finding.state == FindingState(state))
    if connection:
        query = query.filter(Finding.connection == connection)
    if exception == "without":
        query = query.filter(Finding.excepted.is_(False))
    elif exception == "with":
        query = query.filter(Finding.excepted.is_(True))

    # These two were shown as badges on every row and could not be filtered on,
    # so the only way to see just them was to read the whole list.  They are
    # the two the dashboard puts a number against, and a number nobody can
    # click is a number nobody can act on.
    if str(params.get("malicious", "")) == "1":
        query = query.filter(Finding.malicious.is_(True))
    if str(params.get("exploited", "")) == "1":
        query = query.filter(Finding.known_exploited.is_(True))
    if str(params.get("verified", "")) == "1":
        query = query.filter(Finding.verified.is_(True))

    # The engine's own confidence.  A rule from an audit ruleset says "somebody
    # should look at this", not "this is a bug", and being able to set those
    # aside as a group is the difference between triage and an exception per
    # finding.  Anything scanned before this was recorded is unrated.
    if confidence == "unrated":
        query = query.filter(sa_or(Finding.confidence.is_(None),
                                   Finding.confidence == ""))
    elif confidence:
        query = query.filter(Finding.confidence == confidence)

    # Anything scanned before there was a fidelity pass has no verdict, and has
    # to stay in the work list rather than quietly leave it.
    if triage == "work":
        query = query.filter(sa_or(Finding.triage.is_(None),
                                   Finding.triage == "",
                                   Finding.triage == "review"))
    elif triage != "any":
        query = query.filter(Finding.triage == triage)

    # Whether the application can reach the vulnerable package.  Anything
    # scanned before there was a verdict is unrated and stays in the list: a
    # blank is not the same as unlikely, and treating it as one would quietly
    # hide the backlog.
    reach = (params.get("reach", "") or "").strip().lower()
    if reach == "unrated":
        query = query.filter(sa_or(Finding.reachability.is_(None),
                                   Finding.reachability == ""))
    elif reach in {"reachable", "unlikely", "unknown"}:
        query = query.filter(Finding.reachability == reach)
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
        query = query.filter(sa_or(Finding.reachability.is_(None),
                                   Finding.reachability != "unlikely"))

    # Which side of the baseline.  The work by default.  This does nothing at
    # all until somebody draws a line, because an organization without one has
    # every finding counted as new, so an install that never touches this sees
    # exactly what it saw before.
    since = (params.get("baseline", "new") or "new").strip().lower()
    if since not in baseline_filter.MODES:
        since = "new"
    query = baseline_filter.apply(db, query, since)

    if org:
        query = query.filter(Finding.organization == org)
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
        query = query.filter(Finding.repository == repo)
    branch = clean_text(params.get("branch", ""), "Branch", limit=255,
                        required=False)
    if branch:
        query = query.filter(Finding.branch == branch)
    # The two axes of the risk matrix, so a cell in it opens its own rows.
    # An allowlist rather than the value as it arrives, because these go
    # straight into a comparison and the list of legal answers is four words
    # long.
    impact = (params.get("impact", "") or "").strip().lower()
    if impact in ("low", "medium", "high"):
        query = query.filter(Finding.impact == impact)
    likelihood = (params.get("likelihood", "") or "").strip().lower()
    if likelihood in ("unlikely", "possible", "likely", "happening now"):
        query = query.filter(Finding.likelihood == likelihood)
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
        query = rbac.visible_findings(db, user).filter(
            Finding.state == FindingState.OPEN)

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
        from app.core import grouping

        counts, advisory_counts = grouping.counts_by_severity(query)

        by_kind = {}
        for kind, total in (query.with_entities(
                Finding.kind, func.count(Finding.id))
                .group_by(Finding.kind).all()):
            by_kind[getattr(kind, "value", str(kind))] = total

        exploited = query.filter(Finding.known_exploited.is_(True)).count()
        # A package that is itself the attack.  Counted separately from the
        # exploited list because nothing about upgrading it helps, which makes
        # it a different piece of work.
        malicious = query.filter(Finding.malicious.is_(True)).count()
        verified = query.filter(Finding.verified.is_(True)).count()

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

        worst = (query.order_by(_priority_order(), Finding.last_found_at.desc())
                 .limit(15).all())

        top_repos = (query.with_entities(Finding.repository,
                                         func.count(Finding.id).label("n"))
                     .group_by(Finding.repository)
                     .order_by(func.count(Finding.id).desc())
                     .limit(8).all())

        runs = (db.query(ScanRun).order_by(ScanRun.started_at.desc())
                .limit(5).all())

        context = _shared(db, user)
        context.update(active_page="dashboard", counts=counts, by_kind=by_kind,
                       exploited=exploited, verified=verified, worst=worst,
                       malicious=malicious,
                       top_repos=top_repos, runs=runs,
                       certified=certified,
                       advisory_counts=advisory_counts,
                       advisory_total=sum(advisory_counts.values()),
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
    if window not in (7, 30, 90, 365):
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
        grid = {"axis": axis, "rows": report_data.hotspots(
            report_data._scoped(rbac.visible_findings(db, user),
                                organization, repository, branch, connection),
            axis=axis)}
        matrix = report_data.risk_matrix(
            report_data._scoped(rbac.visible_findings(db, user),
                                organization, repository, branch, connection))
        options = trends.choices(db, base=base, connection=connection,
                                 organization=organization,
                                 repository=repository)

        # Where the recorded history starts.  Everything before it was worked
        # out from when findings were first seen and resolved, and its
        # severities are today's applied backwards, so the chart marks it
        # rather than drawing one line across two different things.
        first_snapshot = None
        for point in points:
            if point["source"] == trends.SNAPSHOT:
                first_snapshot = point["day"]
                break

        from app.core import charts

        context = _shared(db, user)
        context.update(
            active_page="trends", points=points, heat=grid,
            matrix=matrix,
            chart=charts.stacked_area(points),
            heat_rows=charts.heat_levels(grid["rows"]),
            basis=basis, window=window, options=options,
            first_snapshot=first_snapshot,
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
    if window not in (7, 30, 90, 365):
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
        if repository and branch:
            row = _cert.for_branch(db, repository, branch)
            if row is not None:
                state = _cert.status(db, row)
                if state["state"] == _cert.ACTIVE:
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
            "certified_note": report_text.certified_note(_cert.counts(db)),
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

    pdf = HTML(string=html, base_url=str(request.base_url)).write_pdf()

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
    state = params.get("state", "open")
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
    since = (params.get("baseline", "new") or "new").strip().lower()
    if since not in baseline_filter.MODES:
        since = "new"
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

        if grouped == "action":
            from app.core import grouping
            groups, total = grouping.page_of_groups(db, query, offset, limit)
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
            hidden_unreachable = max(
                0, _filtered_findings(db, user, wider).count() - query.count())

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
        def _choices(column, **fixed):
            picked = rbac.visible_findings(db, user)
            if fixed.get("connection"):
                picked = picked.filter(Finding.connection == fixed["connection"])
            if fixed.get("org"):
                picked = picked.filter(Finding.organization == fixed["org"])
            if fixed.get("repo"):
                picked = picked.filter(Finding.repository == fixed["repo"])
            return sorted({r[0] for r in
                           picked.with_entities(column).distinct().all() if r[0]})

        orgs = _choices(Finding.organization, connection=connection)
        repo_choices = _choices(Finding.repository, connection=connection, org=org)
        branch_choices = _choices(Finding.branch, connection=connection,
                                  org=org, repo=repo_filter)
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
                     "group": grouped},
            hidden_unreachable=hidden_unreachable,
            groups=groups, grouped=grouped, folded=folded,
            page_sizes=PAGE_SIZES,
            connections=[c[0] for c in
                         rbac.visible_findings(db, user)
                         .with_entities(Finding.connection).distinct().all()
                         if c[0]],
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
                                   ("connection", connection),
                                   ("triage", triage if triage != "work" else ""),
                                   ("baseline", since if since != "new" else ""),
                                   ("sort", sort if sort != "priority" else ""),
                                   ("dir", direction if sort != "priority" else ""))
                                  if value}),
            excepted_total=(rbac.visible_findings(db, user)
                            .filter(Finding.excepted.is_(True)).count()),
            # How much the fidelity pass set aside, so nothing feels concealed.
            #
            # Counted with the lane filter lifted and everything else kept: the
            # builder applies the lane too, so asking it for the work list and
            # then counting what is not in the work list always gave zero.
            set_aside=(_filtered_findings(
                db, user, dict(params, triage="any"))
                .filter(Finding.triage.in_(
                    ["third_party", "advisory", "not_applicable"])).count()
                if triage == "work" else 0),
            # What is behind the line, counted with every other filter still
            # on, so switching the filter over lands on this same number.
            backlog_total=(_filtered_findings(
                db, user, dict(params, baseline="backlog")).count()
                if since == "new" else 0),
            baseline_dates=baseline_filter.dates(db),
            can_set_baseline=rbac.can(user, "settings.write"),
            can_waive=rbac.can(user, "waiver.request"),
            can_delete=rbac.can(user, "findings.delete"),
            can_regrade=rbac.can(user, "finding.regrade"),
            # Not the filtered count.  The delete-everything dialog has to
            # say how many rows actually go, which is rarely the number on
            # screen.
            all_total=(rbac.visible_findings(db, user).count()
                       if rbac.can(user, "findings.delete") else 0),
            default_expiry=(datetime.now(timezone.utc)
                            + timedelta(days=90)).strftime("%Y-%m-%d"),
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

    from app.core.reports import CSV_COLUMNS, as_dict, as_row

    rbac.require(user, "findings.export")

    params = request.query_params
    wants = "json" if params.get("format", "csv").lower() == "json" else "csv"

    with session_scope() as db:
        query = _filtered_findings(db, user, params)
        rows = (query.order_by(_priority_order(), Finding.last_found_at.desc())
                .limit(MAX_EXPORT_ROWS + 1).all())
        trimmed = len(rows) > MAX_EXPORT_ROWS
        rows = rows[:MAX_EXPORT_ROWS]

        if wants == "json":
            body = json_module.dumps({
                "generator": {"name": APP_NAME, "version": VERSION},
                "generated_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "filters": {name: value for name, value in params.items()
                            if name not in {"format", "offset"}},
                "count": len(rows),
                "truncated": trimmed,
                "findings": [as_dict(row) for row in rows],
            }, indent=2) + "\n"
        else:
            buffer = io_module.StringIO()
            writer = csv_module.DictWriter(buffer, fieldnames=CSV_COLUMNS,
                                           extrasaction="ignore",
                                           lineterminator="\n")
            writer.writeheader()
            for row in rows:
                writer.writerow(as_row(row))
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
        if row is None:
            # Out of scope and does not exist look the same on purpose.
            raise HTTPException(status_code=404, detail="No such finding.")

        waiver = db.query(Waiver).filter(Waiver.finding_id == row.id).one_or_none()

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
                     "bitbucket": "Bitbucket"}.get(provider, "")

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

        about = repo_context.for_repository(db, row.repository)
        risk_context = {"sensitivity": about.get("sensitivity"),
                        "visibility": about.get("visibility"),
                        "people_total": about.get("people_total")} if about else {}

        context = _shared(db, user)
        context.update(active_page="findings", f=row, waiver=waiver,
                       host_name=host_name,
                       can_waive=rbac.can(user, "waiver.request"),
                       can_approve=rbac.can(user, "waiver.approve"),
                       can_exclude=rbac.can(user, "exclusion.write"),
                       can_regrade=rbac.can(user, "finding.regrade"),
                       can_describe=rbac.can(user, "repo.describe"),
                       repo_info=about,
                       can_scan=rbac.can(user, "scan.run"),
                       scanning_now=_scanning_now(),
                       on_branches=on_branches,
                       certification=certification,
                       exemption=exemption,
                       can_certify=rbac.can(user, "repo.certify"),
                       can_exempt=rbac.can(user, "repo.certify.exempt"),
                       # Both halves of what the grade is standing in for.
                       # Worked out here rather than read off the finding so
                       # that a repository tagged since the last scan reads
                       # correctly straight away, instead of on the next one.
                       assessment=risk.assess(row, risk_context),
                       recommendation=recommendation.for_finding(row,
                                                                 risk_context),
                       flash=clean_text(msg, "message", limit=300,
                                        required=False),
                       flash_kind=notice_class(kind),
                       default_expiry=(datetime.now(timezone.utc)
                                       + timedelta(days=90)).strftime("%Y-%m-%d"))
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
        visible_ids = [f.id for f in rbac.visible_findings(db, user).all()]
        base = (db.query(Waiver)
                .filter(Waiver.finding_id.in_(visible_ids) if visible_ids
                        else Waiver.id.is_(None)))

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
            matching = [f.id for f in db.query(Finding).filter(
                Finding.id.in_(visible_ids) if visible_ids else Finding.id.is_(None))
                .filter(sa_or(Finding.repository.ilike(needle),
                              Finding.file_path.ilike(needle),
                              Finding.package_name.ilike(needle))).all()]
            base = base.filter(sa_or(Waiver.reason.ilike(needle),
                                     Waiver.ticket.ilike(needle),
                                     Waiver.requested_by.ilike(needle),
                                     Waiver.finding_id.in_(matching or [0])))

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


@router.get("/repositories")
def repositories(request: Request, user: User = Depends(current_user)):
    from app.core import certification as _cert

    # The dashboard tile for certified branches linked here with a filter that
    # did not exist, so the number opened a list of everything.  A count that
    # cannot be opened is a count somebody has to take on trust.
    wanted = (request.query_params.get("certified", "") or "").strip().lower()
    if wanted not in {"", "active", "stale", "lapsed", "revoked",
                      "not_applicable"}:
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
        for row in _cert.all_certifications(db):
            if row.repository not in seen:
                continue
            state = _cert.status(db, row)
            badges.append({"repository": row.repository, "branch": row.branch,
                           "state": state["state"], "why": state.get("why", ""),
                           "by": row.certified_by, "at": row.certified_at,
                           "expires": row.expires_at, "note": row.note})
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
                           "note": row.reason})
        badges.sort(key=lambda b: (b["repository"], b["branch"]))
        if wanted:
            badges = [b for b in badges if b["state"] == wanted]

        counts = {}
        for repo_name, severity, total in (
                rbac.visible_findings(db, user)
                .filter(Finding.state == FindingState.OPEN)
                .with_entities(Finding.repository, Finding.severity,
                               func.count(Finding.id))
                .group_by(Finding.repository, Finding.severity).all()):
            key = repo_name or ""
            counts.setdefault(key, {})[getattr(severity, "value", "")] = total

        context = _shared(db, user)
        context.update(active_page="repositories", rows=rows, counts=counts,
                       can_scan=rbac.can(user, "scan.run"),
                       scanning_now=_scanning_now(),
                       certified=badges, certified_filter=wanted)
        return page(request, "repositories.html", **context)


@router.get("/scans")
def scans(request: Request, msg: str = "", kind: str = "",
          user: User = Depends(current_user)):
    from app.core import scanner

    with session_scope() as db:
        rows = (db.query(ScanRun).order_by(ScanRun.started_at.desc())
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
                       message=clean_text(msg, "message", limit=300,
                                          required=False),
                       message_kind="error" if kind == "error" else "ok")
        return page(request, "scans.html", **context)


@router.get("/schedules")
def schedules(request: Request, user: User = Depends(current_user)):
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
                       can_download=rbac.sees_everything(user))
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
        body = tagging.to_csv(db, organization)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    name = f"tagging-{organization or 'all'}-{stamp}.csv"
    return Response(
        content=body, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/exclusions/export")
def export_exclusions(request: Request, user: User = Depends(current_user)):
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
        rows = (db.query(ScanRun).order_by(ScanRun.started_at.desc())
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
            writer.writerow({
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
            })

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
    if not rbac.sees_everything(user):
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
          user: User = Depends(current_user)):
    rbac.require(user, "user.read")

    from app.core.models import ScanGroup

    with session_scope() as db:
        rows = db.query(User).order_by(User.username).all()
        for row in rows:
            # Load these while the session is open, or the template gets
            # nothing back.
            _ = [s.organization for s in row.scopes]
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
                       message=clean_text(msg, "message", limit=400,
                                          required=False),
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
            message=clean_text(msg, "message", limit=400, required=False),
            message_kind="error" if kind == "error" else "ok",
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
            message=clean_text(msg, "message", limit=300, required=False),
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
            default_expiry=(datetime.now(timezone.utc)
                            + timedelta(days=180)).strftime("%Y-%m-%d"),
            can_write=rbac.can(user, "exclusion.write"),
            message=clean_text(msg, "message", limit=300, required=False),
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
        context = _shared(db, user)
        context.update(active_page="severity",
                       prefill_rule=clean_text(rule, "Rule", limit=200,
                                               required=False),
                       rules=severity_rules.all_rules(db),
                       severities=[s.value for s in Severity],
                       sensitivity_labels=severity_labels_for(db),
                       can_write=rbac.can(user, "settings.write"),
                       flash=clean_text(msg, "message", limit=300, required=False),
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
            # Shown once, straight after it is made, and never again.
            fresh=clean_text(shown, "token", limit=120, required=False),
            api_url=f"{base_url}/api/v1",
            message=clean_text(msg, "message", limit=300, required=False),
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
        query = db.query(Repository)
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
        resolved = {row.id: tagging.effective(db, row) for row in rows}
        total = db.query(Repository).count()
        untagged = tagging.untagged(db).count()

        orgs = [o[0] for o in db.query(Repository.organization)
                .distinct().order_by(Repository.organization).all() if o[0]]

        context = _shared(db, user)
        context.update(
            active_page="tagging",
            rows=rows, resolved=resolved, orgs=orgs,
            labels=tagging.labels(db),
            total=total, untagged=untagged, shown=len(rows),
            filters={"q": search, "org": organization, "show": show},
            can_write=rbac.can(user, "repo.write"),
            message=clean_text(request.query_params.get("msg", ""), "message",
                               limit=300, required=False),
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
        rows = access_store.organizations(db)
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
    writer.writerows(rows)
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
        everybody = access_store.people(db, "" if everything else organization)

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
        unprotected = {r.full_name for r in protection.all()}
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
            owner=access_store.owner_context(db).get(organization, {}),
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
        rows = access_store.rows_for_export(db, wanted)

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
        writer.writerows(rows)
    return Response(content=buffer.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition":
                             f'attachment; filename="{name}"'})


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
            message=clean_text(msg, "message", limit=300, required=False),
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
            message=clean_text(msg, "message", limit=300, required=False),
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
            message=clean_text(msg, "message", limit=300, required=False),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "noise.html", **context)


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
        context = _shared(db, user)
        context.update(
            active_page="notifications",
            values=values,
            can_write=rbac.can(user, "settings.write"),
            message=clean_text(msg, "message", limit=300, required=False),
            message_kind="error" if kind == "error" else "ok")
        return page(request, "notifications.html", **context)


@router.get("/docs/connections-{provider}")
def connection_docs(provider: str, request: Request,
                    user: User = Depends(current_user)):
    """How to set a credential up, per host.

    Linked from the connection form, because the resource owner trap and the
    GitLab token kinds are exactly the things somebody needs while filling it
    in rather than afterwards.
    """
    pages = {"github": "docs_github.html", "gitlab": "docs_gitlab.html",
             "bitbucket": "docs_bitbucket.html"}
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
