"""Counts worked out ahead of time, so pages stop scanning every finding.

Three tables, all rebuilt from the findings table and never edited by hand.
finding_counts holds how many findings share each combination of what a
page filters on.  finding_groups holds the open findings' pieces of work,
and finding_branches holds every branch name the findings mention.

A number read from here is never allowed to be out of date.  Any write to
the findings table that commits marks the summaries stale, and until the
next rebuild finishes every page asks the findings table directly, exactly
as it did before these existed.  A rebuild runs a few seconds after the
last write, so a burst of changes costs one rebuild rather than many.

Stale is tracked in memory.  That is only sound because one process owns
every write, which is also what the rate limiter assumes.  The scanner is a
shell script that writes files, and ingest reads them in this process.  If
that ever changes, this needs a counter in the database instead.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time

from sqlalchemy import case, delete, event, func, insert, select

from app.core.models import (
    Finding, FindingBranch, FindingCount, FindingGroup, FindingState, Severity,
)

log = logging.getLogger("gcr.summary")

# A write to the findings table, in any spelling SQLAlchemy or a person uses.
_WRITE = re.compile(
    r"^\s*(?:INSERT(?:\s+IGNORE)?\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM"
    r"|TRUNCATE(?:\s+TABLE)?)\s+[`\"]?findings[`\"]?(?:\s|\(|$)",
    re.IGNORECASE)

DEBOUNCE_SEC = 3
MIN_GAP_SEC = 10

_lock = threading.Lock()
_build_lock = threading.Lock()
_generation = 1          # bumped by every committed write to findings
_built = 0               # the generation the tables were last built from
_built_at = 0.0
_branches_complete = False
_auto = False
_timer = None
_rerun = False
_last_start = 0.0


# ---- noticing a write --------------------------------------------------------

def watch(engine) -> None:
    """Hook the engine so a committed write to findings marks us stale.

    At the cursor, because that sees every write however it was issued: a
    session flush, a bulk update, a text statement.  Marked stale only once
    the commit is done, because marking it before would let a rebuild that
    started in between read the old rows and call itself current.
    """
    if getattr(engine, "_gcr_summary_watched", False):
        return
    engine._gcr_summary_watched = True

    @event.listens_for(engine, "after_cursor_execute")
    def _seen(conn, _cursor, statement, _params, _context, _many):
        if _WRITE.match(statement or ""):
            conn.info["gcr_findings_written"] = True

    @event.listens_for(engine, "commit")
    def _committing(conn):
        if conn.info.pop("gcr_findings_written", False):
            conn.info["gcr_findings_committed"] = True

    @event.listens_for(engine, "rollback")
    def _rolled_back(conn):
        conn.info.pop("gcr_findings_written", None)

    # Both run after the commit has finished: the next transaction starting
    # on that connection, or the connection going back to the pool.
    @event.listens_for(engine, "begin")
    def _next_begin(conn):
        if conn.info.pop("gcr_findings_committed", False):
            changed()

    @event.listens_for(engine.pool, "checkin")
    def _returned(_dbapi, record):
        if record is not None and record.info.pop("gcr_findings_committed", False):
            changed()


def changed() -> None:
    global _generation
    with _lock:
        _generation += 1
    _schedule()


def fresh() -> bool:
    """Whether the tables match the findings right now."""
    with _lock:
        return _built > 0 and _built == _generation


def branches_fresh() -> bool:
    return fresh() and _branches_complete


def status() -> dict:
    with _lock:
        return {"fresh": _built > 0 and _built == _generation,
                "generation": _generation, "built": _built,
                "built_at": _built_at}


# ---- rebuilding --------------------------------------------------------------

def enable(start: bool = True) -> None:
    """Rebuild on our own from now on.  Off in tests, which call rebuild()."""
    global _auto
    _auto = True
    if start:
        _schedule(delay=0)


def _schedule(delay: float = DEBOUNCE_SEC) -> None:
    global _timer, _rerun
    if not _auto:
        return
    with _lock:
        if _build_lock.locked():
            _rerun = True
            return
        if _timer is not None:
            _timer.cancel()
        wait = max(delay, _last_start + MIN_GAP_SEC - time.time())
        _timer = threading.Timer(max(0.0, wait), _run)
        _timer.daemon = True
        _timer.start()


def _run() -> None:
    global _rerun
    rebuild()
    with _lock:
        again, _rerun = _rerun, False
    if again or not fresh():
        _schedule()


def rebuild() -> bool:
    """Build all three tables from the findings.  True when it worked."""
    global _built, _built_at, _branches_complete, _last_start
    from app.core.db import engine

    with _build_lock:
        with _lock:
            # Read before the rows are, so a write that lands during the
            # build leaves the result marked stale rather than current.
            generation = _generation
        _last_start = time.time()
        eng = engine()
        started = time.perf_counter()
        try:
            with eng.connect() as conn:
                if eng.dialect.name != "sqlite":
                    # Reading committed rows without locking them, so a
                    # rebuild never holds up a scan writing its results.
                    conn = conn.execution_options(isolation_level="READ COMMITTED")
                with conn.begin():
                    conn.execute(delete(FindingCount.__table__))
                    conn.execute(delete(FindingGroup.__table__))
                    conn.execute(delete(FindingBranch.__table__))
                    _fill_counts(conn)
                    _fill_groups(conn)
                    complete = _fill_branches(conn)
        except Exception:
            log.warning("could not rebuild the finding summaries", exc_info=True)
            return False
        with _lock:
            _built = generation
            _built_at = time.time()
            _branches_complete = complete
        log.info("finding summaries rebuilt in %.2fs",
                 time.perf_counter() - started)
        return True


_COUNT_DIMS = ("organization", "repository", "connection", "branch", "kind",
               "severity", "state", "excepted", "out_of_scope", "triage",
               "reachability", "confidence", "known_exploited", "malicious",
               "verified", "impact", "likelihood")

_GROUP_DIMS = ("organization", "connection", "kind", "severity", "state",
               "excepted", "out_of_scope",
               "triage", "reachability", "confidence", "known_exploited",
               "malicious", "verified", "impact", "likelihood")


def _fill_counts(conn) -> None:
    dims = [getattr(Finding, name) for name in _COUNT_DIMS]
    source = select(*dims, func.count(Finding.id)).group_by(*dims)
    conn.execute(insert(FindingCount.__table__).from_select(
        list(_COUNT_DIMS) + ["findings"], source))


def _fill_groups(conn) -> None:
    from app.core import grouping

    head, alone = grouping._key_columns()
    keys = [Finding.repository, Finding.branch, head, Finding.package_version,
            Finding.fixed_in, Finding.image_ref, alone]
    dims = [getattr(Finding, name) for name in _GROUP_DIMS]
    # The group key is a dense rank over the seven key columns.  Ranked by the
    # database, so two names it would group together, jQuery and jquery on
    # MariaDB, share a key exactly as they share a group.
    source = (select(*keys, func.dense_rank().over(order_by=keys), *dims,
                     func.max(grouping._rank_column()),
                     func.max(Finding.risk_score), func.count(Finding.id),
                     func.group_concat(Finding.id))
              .where(Finding.state == FindingState.OPEN)
              .group_by(*keys, *dims))
    conn.execute(insert(FindingGroup.__table__).from_select(
        ["repository", "branch", "head", "package_version", "fixed_in",
         "image_ref", "alone", "group_key"] + list(_GROUP_DIMS)
        + ["worst", "score", "members", "member_ids"], source))


def _fill_branches(conn) -> bool:
    """-> False when a name is too long to store, so readers ask live."""
    found = {}
    complete = True
    rows = conn.execute(select(
        Finding.organization, Finding.repository, Finding.connection,
        Finding.state, Finding.branch, Finding.branches,
        Finding.last_found_at)).yield_per(2000)
    for org, repo, connection, state, primary, listed, seen in rows:
        names = set()
        if primary:
            names.add(str(primary))
        try:
            for name in (json.loads(listed or "[]") or []):
                if name:
                    names.add(str(name))
        except (TypeError, ValueError):
            pass
        for name in names:
            if len(name) > 255:
                complete = False
                continue
            key = (org, repo, connection, state, name)
            if key not in found or (seen is not None and
                                    (found[key] is None or seen > found[key])):
                found[key] = seen
    batch = []
    for (org, repo, connection, state, name), seen in found.items():
        batch.append({"organization": org, "repository": repo,
                      "connection": connection, "state": state,
                      "name": name, "last_found_at": seen})
        if len(batch) >= 2000:
            conn.execute(insert(FindingBranch.__table__), batch)
            batch = []
    if batch:
        conn.execute(insert(FindingBranch.__table__), batch)
    return complete


# ---- reading -----------------------------------------------------------------

def total(query) -> int:
    """The number of findings a finding_counts query covers."""
    return int(query.with_entities(
        func.coalesce(func.sum(FindingCount.findings), 0)).scalar() or 0)


def by_severity(query) -> dict:
    out = {level.value: 0 for level in Severity}
    for severity, n in (query.with_entities(
            FindingCount.severity, func.sum(FindingCount.findings))
            .group_by(FindingCount.severity).all()):
        out[getattr(severity, "value", str(severity))] = int(n or 0)
    return out


def actions_by_severity(query) -> dict:
    """The dashboard's actions figure, from finding_groups."""
    from app.core.grouping import BY_RANK

    out = {level.value: 0 for level in Severity}
    grouped = (query.with_entities(func.max(FindingGroup.worst).label("worst"))
               .group_by(FindingGroup.group_key).subquery())
    for worst, n in (query.session.query(grouped.c.worst, func.count())
                     .group_by(grouped.c.worst).all()):
        level = BY_RANK.get(int(worst or 0))
        if level is not None:
            out[level.value] = int(n)
    return out


def group_keys():
    return (FindingGroup.repository, FindingGroup.branch, FindingGroup.head,
            FindingGroup.package_version, FindingGroup.fixed_in,
            FindingGroup.image_ref, FindingGroup.alone)


def member_ids(rows) -> list | None:
    """The ids a set of finding_groups rows lists, or None when a list came
    back short, which a database cap on concatenation would cause."""
    ids = []
    for listed, members in rows:
        parts = [p for p in str(listed or "").split(",") if p.strip()]
        if len(parts) != int(members or 0):
            return None
        ids.extend(int(p) for p in parts)
    return ids


def priority(model):
    """The findings list's priority, for any table carrying its columns.

    Kept in step with routes_pages._priority_order, which calls this."""
    severity_rank = case(
        (model.severity == Severity.CRITICAL, 5),
        (model.severity == Severity.HIGH, 4),
        (model.severity == Severity.MEDIUM, 3),
        (model.severity == Severity.LOW, 2),
        else_=1)
    confidence_weight = case(
        (model.confidence == "high", 100),
        (model.confidence == "medium", 70),
        (model.confidence == "low", 40),
        else_=85)
    verified_bonus = case((model.verified.is_(True), 250), else_=0)
    exploited_bonus = case((model.known_exploited.is_(True), 150), else_=0)
    reachability_weight = case(
        (model.reachability == "unlikely", -120),
        (model.reachability == "unknown", -30),
        else_=0)
    return (severity_rank * confidence_weight + verified_bonus
            + exploited_bonus + reachability_weight)


def top_candidates(groups, want: int, cap: int = 5000) -> list | None:
    """Ids that must include the `want` highest priority findings.

    Everything at or above the priority where the running count first
    reaches `want`, so a tie at that line is fetched whole and the caller's
    own ordering settles it.  None when that is more than `cap` findings or a
    member list came back short, and the caller asks live.
    """
    from app.core.models import FindingGroup as G

    rank = priority(G)
    line, seen, step, offset = None, 0, 200, 0
    ordered = groups.with_entities(rank.label("p"), G.members).order_by(rank.desc())
    while seen < want:
        batch = ordered.offset(offset).limit(step).all()
        for value, members in batch:
            line = value
            seen += int(members or 0)
            if seen >= want:
                break
        if len(batch) < step:
            break
        offset += step
    if line is None:
        return []
    ids = member_ids(groups.filter(rank >= line)
                     .with_entities(G.member_ids, G.members).all())
    if ids is None or len(ids) > cap:
        return None
    return ids

