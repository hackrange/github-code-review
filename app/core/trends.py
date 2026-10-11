"""What the estate looked like over time, at whatever scope somebody asks for.

Every number here is stored at one grain, a day and a branch of a repository,
and every view of it is a sum over that.  An organization is the sum of its
repositories.  Everything is the sum of the lot.  A branch is a single row.
That is what lets the filters be arbitrary: nothing has to be anticipated,
because nothing is pre-aggregated.

There are two ways a row gets here and the difference is kept on the row.

A snapshot is written after a scan and is what the database actually held that
day.  It is exact, severities included.

A reconstruction is worked out from when each finding was first seen and when
it was resolved.  It is the only way to have any history before this table
existed, and it is honest about counts: a finding first seen on the second and
resolved on the ninth was open on the fifth, and no judgement is involved in
saying so.  It is not honest about severity, because severity is stored as its
current value, so a finding regraded this morning appears in a reconstruction
as though it always carried that grade.  The chart marks the boundary rather
than drawing one continuous line across two things that do not mean the same.

Rebuilding a reconstruction is safe and rebuilding a snapshot is not, which is
why reconstruction never overwrites a snapshot.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from app.core.models import (Finding, FindingKind, FindingState, Severity,
                             TrendPoint)

log = logging.getLogger("gcr.trends")

SNAPSHOT = "snapshot"
RECONSTRUCTED = "reconstructed"

LEVELS = ("critical", "high", "medium", "low", "info", "unknown")


def _midnight(value: datetime) -> datetime:
    """The day a moment belongs to, in UTC, as a datetime at midnight.

    Stored as a datetime rather than a date because the two databases behind
    this disagree about what a date is when it comes back out, and one shape
    everywhere is worth more than the two bytes.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return datetime(value.year, value.month, value.day)


def today() -> datetime:
    return _midnight(datetime.now(timezone.utc))


# --- writing ----------------------------------------------------------------

def record(session, day: datetime = None) -> int:
    """Write today's snapshot, one row per branch of each repository.

    Called after a scan finishes.  Re-running it for the same day replaces
    that day rather than adding to it, so two scans in one day leave the state
    after the second, which is what the day ended looking like.
    """
    from app.core import grouping

    day = _midnight(day or datetime.now(timezone.utc))
    # Not counting what is only on branches that do not ship.  Those are off
    # every other number too, and a trend line that disagrees with the
    # dashboard is one nobody trusts.
    open_only = session.query(Finding).filter(
        Finding.state == FindingState.OPEN).filter(
        Finding.out_of_scope.is_(False))

    # Advisories per branch and severity, in one statement.
    rows = (open_only.with_entities(
                Finding.organization, Finding.repository, Finding.branch,
                Finding.connection, Finding.severity,
                func.count(Finding.id))
            .group_by(Finding.organization, Finding.repository,
                      Finding.branch, Finding.connection, Finding.severity)
            .all())

    # Keyed on the branch, not on the connection.
    #
    # A repository can be reachable through more than one connection, and
    # several here are: the same branch of the same repository arrives twice
    # with two connection names.  Keyed on both, that is two rows claiming to
    # describe one branch on one day, which is a duplicate by the definition
    # this table is built on.  The connection is kept as a label so the filter
    # box still works, and the first one seen wins, because a branch that two
    # connections can reach is one branch.
    buckets = {}
    labels = {}
    for org, repo, branch, conn, severity, total in rows:
        key = (org or "", repo or "", branch or "")
        labels.setdefault(key, conn or "")
        entry = buckets.setdefault(key, {level: 0 for level in LEVELS})
        name = getattr(severity, "value", str(severity))
        entry[name] = entry.get(name, 0) + total

    # Actions per branch and severity, counted the way the list counts them.
    head, alone = grouping._key_columns()
    rank = grouping._rank_column()
    keys = (Finding.organization, Finding.repository, Finding.branch,
            Finding.connection, head, Finding.package_version,
            Finding.fixed_in, Finding.image_ref, alone)
    grouped = (open_only.with_entities(
                   Finding.organization, Finding.repository, Finding.branch,
                   Finding.connection, func.max(rank).label("worst"))
               .group_by(*keys).subquery())
    action_rows = (session.query(grouped.c.organization, grouped.c.repository,
                                 grouped.c.branch, grouped.c.connection,
                                 grouped.c.worst, func.count())
                   .group_by(grouped.c.organization, grouped.c.repository,
                             grouped.c.branch, grouped.c.connection,
                             grouped.c.worst).all())

    actions = {}
    for org, repo, branch, conn, worst, total in action_rows:
        key = (org or "", repo or "", branch or "")
        labels.setdefault(key, conn or "")
        level = grouping.BY_RANK.get(int(worst or 0))
        if level is None:
            continue
        entry = actions.setdefault(key, {name: 0 for name in LEVELS})
        entry[level.value] = entry.get(level.value, 0) + total

    certified = _certification_by_branch(session)

    # Replace the day rather than add to it.
    #
    # Every row for the day goes, not just the snapshot ones.  A reconstruction
    # of today can exist: backfill writes one for any day that has no snapshot
    # yet, and on a fresh install that runs before the first scan of the day.
    # Leaving it there would put two rows on the same branch on the same day
    # and the chart adds them up, so the last point on the line reads as
    # roughly double and looks like an overnight disaster.  A real record of a
    # day beats a reconstruction of it, which is the rule backfill already
    # follows in the other direction.
    (session.query(TrendPoint)
     .filter(TrendPoint.day == day)
     .delete(synchronize_session=False))

    written = 0
    for key in set(buckets) | set(actions):
        org, repo, branch = key
        found = buckets.get(key, {level: 0 for level in LEVELS})
        acted = actions.get(key, {level: 0 for level in LEVELS})
        session.add(TrendPoint(
            day=day, organization=org, repository=repo, branch=branch,
            connection=labels.get(key, ""), source=SNAPSHOT,
            critical=found["critical"], high=found["high"],
            medium=found["medium"], low=found["low"],
            info=found["info"], unknown=found["unknown"],
            findings_total=sum(found.values()),
            actions_critical=acted["critical"], actions_high=acted["high"],
            actions_medium=acted["medium"], actions_low=acted["low"],
            actions_info=acted["info"], actions_unknown=acted["unknown"],
            actions_total=sum(acted.values()),
            certification=certified.get((repo, branch), "")))
        written += 1
    session.flush()
    log.info("trend snapshot for %s: %d branch row(s)", day.date(), written)
    return written


def _certification_by_branch(session) -> dict:
    """-> {(repository, branch): state}.  Empty where nobody has signed off."""
    from app.core import certification

    out = {}
    try:
        from app.core.models import Certification
        rows = session.query(Certification).all()
        for row, found in zip(rows, certification.statuses(session, rows)):
            state = found.get("state", "")
            if state:
                out[(row.repository, row.branch)] = state
    except Exception:            # a trend row is not worth failing a scan for
        log.warning("could not read certifications for the trend point",
                    exc_info=True)
    return out


def backfill(session, days: int = 90) -> int:
    """Work out the days before this table existed, from what findings say.

    A finding carries when it was first seen and when it was resolved, so
    whether it was open on a given day is a fact already in the database.  The
    counts that come out of this are right.

    Severity is not.  It is stored as its current value, so a regrade today
    reaches backwards through the whole reconstruction.  Rows are marked so
    the chart can say where this stops.

    Never overwrites a snapshot.  A real record of a day always beats a
    reconstruction of it, and this is safe to re-run.
    """
    from app.core import grouping

    end = today()
    earliest = session.query(func.min(Finding.first_found_at)).scalar()
    if earliest is None:
        return 0
    start = max(_midnight(earliest), end - timedelta(days=days))

    have = {row[0] for row in session.query(TrendPoint.day)
            .filter(TrendPoint.source == SNAPSHOT).distinct().all()}

    written = 0
    day = start
    while day <= end:
        if day in have:
            day += timedelta(days=1)
            continue

        # Open on that day: seen by then, and not resolved until after.
        edge = day + timedelta(days=1)
        was_open = session.query(Finding).filter(
            Finding.first_found_at < edge).filter(
            (Finding.resolved_at.is_(None)) | (Finding.resolved_at >= edge)).filter(
            Finding.out_of_scope.is_(False))

        rows = (was_open.with_entities(
                    Finding.organization, Finding.repository, Finding.branch,
                    Finding.connection, Finding.severity, func.count(Finding.id))
                .group_by(Finding.organization, Finding.repository,
                          Finding.branch, Finding.connection,
                          Finding.severity).all())
        if not rows:
            day += timedelta(days=1)
            continue

        buckets = {}
        labels = {}
        for org, repo, branch, conn, severity, total in rows:
            key = (org or "", repo or "", branch or "")
            labels.setdefault(key, conn or "")
            entry = buckets.setdefault(key, {level: 0 for level in LEVELS})
            name = getattr(severity, "value", str(severity))
            entry[name] = entry.get(name, 0) + total

        head, alone = grouping._key_columns()
        rank = grouping._rank_column()
        keys = (Finding.organization, Finding.repository, Finding.branch,
                Finding.connection, head, Finding.package_version,
                Finding.fixed_in, Finding.image_ref, alone)
        grouped = (was_open.with_entities(
                       Finding.organization, Finding.repository,
                       Finding.branch, Finding.connection,
                       func.max(rank).label("worst"))
                   .group_by(*keys).subquery())
        actions = {}
        for org, repo, branch, conn, worst, total in session.query(
                grouped.c.organization, grouped.c.repository, grouped.c.branch,
                grouped.c.connection, grouped.c.worst, func.count()).group_by(
                grouped.c.organization, grouped.c.repository, grouped.c.branch,
                grouped.c.connection, grouped.c.worst).all():
            key = (org or "", repo or "", branch or "")
            labels.setdefault(key, conn or "")
            level = grouping.BY_RANK.get(int(worst or 0))
            if level is not None:
                entry = actions.setdefault(key, {n: 0 for n in LEVELS})
                entry[level.value] = entry.get(level.value, 0) + total

        (session.query(TrendPoint)
         .filter(TrendPoint.day == day, TrendPoint.source == RECONSTRUCTED)
         .delete(synchronize_session=False))

        for key in set(buckets) | set(actions):
            org, repo, branch = key
            found = buckets.get(key, {n: 0 for n in LEVELS})
            acted = actions.get(key, {n: 0 for n in LEVELS})
            session.add(TrendPoint(
                day=day, organization=org, repository=repo, branch=branch,
                connection=labels.get(key, ""), source=RECONSTRUCTED,
                critical=found["critical"], high=found["high"],
                medium=found["medium"], low=found["low"],
                info=found["info"], unknown=found["unknown"],
                findings_total=sum(found.values()),
                actions_critical=acted["critical"], actions_high=acted["high"],
                actions_medium=acted["medium"], actions_low=acted["low"],
                actions_info=acted["info"], actions_unknown=acted["unknown"],
                actions_total=sum(acted.values())))
            written += 1
        day += timedelta(days=1)

    session.flush()
    log.info("reconstructed %d trend row(s) from finding history", written)
    return written


# --- reading ----------------------------------------------------------------

def _scoped(session, organization: str = "", repository: str = "",
            branch: str = "", connection: str = "", since: datetime = None,
            until: datetime = None, base=None):
    """The rows a filter selects.  Narrower filters win over wider ones.

    `base` is the query this starts from, and every caller that serves a page
    passes the one already narrowed to what the reader may see.  Defaulting to
    every row is for the writers and the tests; a route that forgets to pass
    it is the bug this note exists to make obvious.
    """
    query = base if base is not None else session.query(TrendPoint)
    if connection:
        query = query.filter(TrendPoint.connection == connection)
    if organization:
        query = query.filter(TrendPoint.organization == organization)
    if repository:
        query = query.filter(TrendPoint.repository == repository)
    if branch:
        query = query.filter(TrendPoint.branch == branch)
    if since is not None:
        query = query.filter(TrendPoint.day >= _midnight(since))
    if until is not None:
        query = query.filter(TrendPoint.day <= _midnight(until))
    return query


def series(session, basis: str = "actions", base=None, **scope) -> list:
    """-> [{day, critical, ..., total, source}], oldest first.

    basis is "actions" or "advisories".  Both are stored, so switching does
    not change what the numbers mean partway through the history.

    A day carrying any reconstructed row is marked reconstructed as a whole.
    Half a day of each would be a line nobody could read honestly.
    """
    columns = {
        "actions": ("actions_critical", "actions_high", "actions_medium",
                    "actions_low", "actions_info", "actions_unknown",
                    "actions_total"),
        "advisories": ("critical", "high", "medium", "low", "info",
                       "unknown", "findings_total"),
    }[basis if basis in ("actions", "advisories") else "actions"]

    rows = (_scoped(session, base=base, **scope)
            .with_entities(
                TrendPoint.day,
                *[func.sum(getattr(TrendPoint, name)) for name in columns],
                func.min(TrendPoint.source))
            .group_by(TrendPoint.day)
            .order_by(TrendPoint.day.asc()).all())

    out = []
    for row in rows:
        day = row[0]
        values = [int(v or 0) for v in row[1:8]]
        # min() over the two words puts "reconstructed" first alphabetically,
        # so a day with any reconstructed row reads as reconstructed.
        out.append({
            "day": day,
            "critical": values[0], "high": values[1], "medium": values[2],
            "low": values[3], "info": values[4], "unknown": values[5],
            "total": values[6],
            "source": row[8] or SNAPSHOT,
        })
    return out


def heatmap(session, basis: str = "actions", base=None, **scope) -> dict:
    """-> {"axis": what the rows are, "rows": [{name, critical, ..., total}]}.

    The rows follow the filter rather than being fixed, so the same widget
    works at every level and narrowing it is a drill down rather than a
    different chart: everything shows organizations, an organization shows its
    repositories, a repository shows its branches.
    """
    if scope.get("repository"):
        axis, column = "branch", TrendPoint.branch
    elif scope.get("organization"):
        axis, column = "repository", TrendPoint.repository
    else:
        axis, column = "organization", TrendPoint.organization

    prefix = "actions_" if basis != "advisories" else ""
    total_column = "actions_total" if basis != "advisories" else "findings_total"

    # The most recent day in scope, because a heatmap is about now.
    latest = _scoped(session, base=base, **scope).with_entities(
        func.max(TrendPoint.day)).scalar()
    if latest is None:
        return {"axis": axis, "rows": [], "day": None}

    scope_now = dict(scope)
    scope_now["since"] = latest
    scope_now["until"] = latest

    rows = (_scoped(session, base=base, **scope_now)
            .with_entities(
                column,
                *[func.sum(getattr(TrendPoint, prefix + name))
                  for name in ("critical", "high", "medium", "low", "info")],
                func.sum(getattr(TrendPoint, total_column)))
            .group_by(column)
            .order_by(func.sum(getattr(TrendPoint, total_column)).desc())
            .all())

    return {
        "axis": axis,
        "day": latest,
        "rows": [{"name": row[0] or "(none)",
                  "critical": int(row[1] or 0), "high": int(row[2] or 0),
                  "medium": int(row[3] or 0), "low": int(row[4] or 0),
                  "info": int(row[5] or 0), "total": int(row[6] or 0)}
                 for row in rows],
    }


def choices(session, base=None, connection: str = "", organization: str = "",
            repository: str = "", since: datetime = None,
            within: set = None) -> dict:
    """What the filter boxes can offer, given what is already chosen.

    Each box offers only what the boxes to its left leave possible.  Picking a
    connection and then being offered every branch in the estate, most of
    which return nothing, is a filter that makes somebody prove a negative one
    click at a time.

    The period is one of the things already chosen.  It was the one narrowing
    never applied here, so a branch last read a month ago was still offered
    under a period of Today, and picking it drew an empty chart.  That is the
    same "prove a negative one click at a time" this docstring already
    objected to, arriving through the one box nobody had wired up.

    `within` is the set of repositories the period actually read, and it has
    to be handed in because these rows cannot say.  record() snapshots every
    open finding in the estate each time any scan anywhere finishes, so a
    repository nobody has looked at in a month still gets a row today.  The
    day on a row says when the snapshot was taken, not when that code was
    read, and reading it as the second is what put every repository in the
    estate behind a period of Today.

    Every list is narrowed by what came before it, and never by what comes
    after: choosing a branch must not remove the connections, or the reader
    cannot get back out of a dead end they have just walked into.  The period
    does not narrow them either, for the same reason: it is a filter somebody
    has to be able to widen again.

    Scoped the same way everything else is, so the boxes never name a
    repository the reader cannot open.  A filter list is a disclosure too.
    """
    everything = base if base is not None else session.query(TrendPoint)
    source = everything
    if since is not None:
        source = source.filter(TrendPoint.day >= _midnight(since))
    if within is not None:
        source = source.filter(TrendPoint.repository.in_(sorted(within)))

    def distinct(column, **narrowing):
        query = narrowing.pop("source", None) or source
        if narrowing.get("connection"):
            query = query.filter(TrendPoint.connection == narrowing["connection"])
        if narrowing.get("organization"):
            query = query.filter(
                TrendPoint.organization == narrowing["organization"])
        if narrowing.get("repository"):
            query = query.filter(TrendPoint.repository == narrowing["repository"])
        return sorted({row[0] for row in
                       query.with_entities(column).distinct().all() if row[0]})

    return {
        # Never narrowed: this is the way back out.
        "connections": distinct(TrendPoint.connection, source=everything),
        "organizations": distinct(TrendPoint.organization,
                                  connection=connection),
        "repositories": distinct(TrendPoint.repository,
                                 connection=connection,
                                 organization=organization),
        "branches": distinct(TrendPoint.branch,
                             connection=connection,
                             organization=organization,
                             repository=repository),
    }
