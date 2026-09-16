"""Cron, in process.

Two kinds of job.  A scan job runs the scanner.  A feeds job pulls the CISA and
EPSS lists again, which is cheap and worth doing more often, because a finding
you already have can turn urgent overnight without anybody touching the code.

Schedules live in the database so they survive a restart, and the scheduler
reads them back on boot.
"""

from __future__ import annotations

import json
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import timezone as _dt_timezone

from app.core.audit import record
from app.core.db import session_scope
from app.core.models import ScanRun, Schedule, utcnow

_UTC = _dt_timezone.utc

log = logging.getLogger("gcr.scheduler")

_scheduler = None

DEFAULTS = [
    # Nightly, at a time nobody picked for anything else.
    {"name": "Nightly scan", "kind": "scan", "cron": "17 2 * * *"},
    # Twice a day.  The lists change on their own schedule, not ours.
    {"name": "Refresh vulnerability feeds", "kind": "feeds", "cron": "0 */12 * * *"},
]


def _zone():
    """The zone a cron expression is read in.

    Somebody who types "0 2 * * *" means two in the morning where they are, not
    two in the morning in UTC.  Set on the Settings page; GMT keeps the old
    behavior, which is what an install that never touched it gets.
    """
    from zoneinfo import ZoneInfo

    try:
        from app.core import live
        return ZoneInfo(live.timezone_name())
    except Exception:
        return ZoneInfo("GMT")


def valid_cron(expression: str) -> bool:
    try:
        CronTrigger.from_crontab((expression or "").strip(), timezone=_zone())
        return True
    except (ValueError, TypeError):
        return False


def next_run_for(expression: str):
    """The next firing, as UTC, because that is how it is stored.

    The trigger works in the configured zone, so the answer already accounts
    for the offset and for daylight saving.
    """
    try:
        trigger = CronTrigger.from_crontab(expression.strip(), timezone=_zone())
        nxt = trigger.get_next_fire_time(None, utcnow())
        return nxt.astimezone(_UTC) if nxt is not None else None
    except (ValueError, TypeError):
        return None


def _run_job(schedule_id: int) -> None:
    """What actually fires.  Reads the row again so an edit takes effect."""
    from app.core import scanner

    with session_scope() as db:
        row = db.query(Schedule).filter(Schedule.id == schedule_id).one_or_none()
        if row is None or not row.enabled:
            return
        kind = row.kind
        name = row.name
        from app.core.scanner_config import widen

        # A schedule written as * means every organization, same as leaving it
        # empty.  Left as a literal it would send the scanner after an
        # organization by that name and quietly scan nothing.
        orgs = widen((row.scope_orgs or "").split(","))
        repos = widen((row.scope_repos or "").split(","))
        row.last_run_at = utcnow()
        row.last_status = "running"

    log.info("schedule firing: %s (%s)", name, kind)
    # Real work outranks catch up.  A catch up pass holds the same gate, so a
    # schedule that fired while one was running would be refused outright; it
    # is stopped instead, and what it had already walked is kept.
    if kind != "feeds":
        _yield_catchup()
    try:
        if kind == "feeds":
            result = scanner.refresh_feeds()
        elif orgs or repos:
            # Somebody named something, so scan exactly that.
            result = scanner.run_scan(triggered_by=f"schedule:{name}",
                                      trigger="schedule",
                                      orgs=orgs or None, repos=repos or None)
        else:
            # Nothing named means every account on the Connections page, one
            # run each.
            result = scanner.run_every_connection(
                triggered_by=f"schedule:{name}", trigger="schedule")
        # An account with nothing in it is not a failed schedule, and it is not
        # a clean one either: say so on the row rather than picking a side.
        if result.get("empty"):
            status = "empty"
        else:
            status = "ok" if result.get("ok", True) else "failed"
    except Exception as exc:
        log.exception("schedule %s blew up", name)
        status = "failed"
        with session_scope() as db:
            record(db, "schedule.failed", actor="scheduler", target=name,
                   detail=str(exc)[:200], outcome="error")

    with session_scope() as db:
        row = db.query(Schedule).filter(Schedule.id == schedule_id).one_or_none()
        if row is not None:
            row.last_status = status
            row.next_run_at = next_run_for(row.cron)


# How often to look for a history that is not finished.  Long enough that a
# quiet machine is not being asked constantly, short enough that an evening of
# idle time is several windows rather than one.
CATCHUP_MINUTES = 20
CATCHUP_JOB_ID = "gcr-catchup"


def _yield_catchup() -> None:
    """Stop a catch up pass so something that was actually asked for can run."""
    from app.core import scanner

    with scanner._process_lock:
        catching_up = [rid for rid, _ in scanner._running.items()]
    if not catching_up:
        return
    with session_scope() as db:
        rows = (db.query(ScanRun)
                .filter(ScanRun.id.in_(catching_up))
                .filter(ScanRun.trigger == "catchup").all())
        ids = [r.id for r in rows]
    for run_id in ids:
        log.info("stopping catch up run %s to make room for a schedule", run_id)
        scanner.stop_scan(run_id)


def _run_catchup() -> None:
    """The idle time job.  Refuses itself whenever anything else is scanning."""
    from app.core import scanner

    try:
        result = scanner.run_catchup()
    except Exception as exc:  # a background job must not take the scheduler down
        log.warning("catch up pass failed: %s", exc)
        return
    if not result.get("ok"):
        log.debug("catch up did nothing: %s", result.get("reason", ""))


def _seed_defaults() -> None:
    with session_scope() as db:
        if db.query(Schedule).count() > 0:
            return
        for entry in DEFAULTS:
            db.add(Schedule(name=entry["name"], kind=entry["kind"],
                            cron=entry["cron"], enabled=True,
                            created_by="system",
                            next_run_at=next_run_for(entry["cron"])))
        log.info("added the default schedules")


def reload_jobs() -> int:
    """Read the schedules back out of the database and arm them.

    Called on boot and after anybody edits one.  Clearing and re-adding is
    simpler than working out what changed, and there are never many of these.
    """
    if _scheduler is None:
        return 0

    for job in _scheduler.get_jobs():
        # Everything armed from a Schedule row goes, to be armed again below.
        # The catch up tick is not one of those and must survive: it is armed
        # once at start up, and anybody editing a schedule would otherwise
        # switch it off without knowing they had.
        if job.id.startswith("gcr-") and job.id != CATCHUP_JOB_ID:
            job.remove()

    armed = 0
    with session_scope() as db:
        for row in db.query(Schedule).filter(Schedule.enabled.is_(True)).all():
            if not valid_cron(row.cron):
                log.warning("schedule %s has a cron we cannot read: %s",
                            row.name, row.cron)
                continue
            _scheduler.add_job(
                _run_job,
                CronTrigger.from_crontab(row.cron.strip(), timezone=_zone()),
                args=[row.id], id=f"gcr-{row.id}", replace_existing=True,
                misfire_grace_time=3600, coalesce=True, max_instances=1)
            row.next_run_at = next_run_for(row.cron)
            armed += 1
    log.info("armed %d schedule(s)", armed)
    return armed


def start() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    # The scheduler itself stays on UTC; each trigger carries the configured
    # zone, so changing the setting re-reads every cron without a restart.
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.start()
    _seed_defaults()
    reload_jobs()

    # The catch up tick.  Not a Schedule row: it is not something anybody
    # arranges for a time, it is what the machine does when nothing else is
    # asking.  It refuses itself whenever a scan is running, so the interval is
    # only how often it looks.
    from apscheduler.triggers.interval import IntervalTrigger

    _scheduler.add_job(_run_catchup,
                       IntervalTrigger(minutes=CATCHUP_MINUTES),
                       id=CATCHUP_JOB_ID, replace_existing=True,
                       misfire_grace_time=300, coalesce=True, max_instances=1)
    log.info("catch up looks for unfinished history every %d minutes",
             CATCHUP_MINUTES)

    # The finding summaries.  Rebuilt a few seconds after any write to the
    # findings, and checked every ten minutes in case a rebuild failed.
    from app.core import summary

    summary.enable()
    _scheduler.add_job(lambda: summary.fresh() or summary.rebuild(),
                       IntervalTrigger(minutes=10), id="summary-check",
                       replace_existing=True, misfire_grace_time=120,
                       coalesce=True, max_instances=1)

    # CPU, memory, disk and network for the Utilization page.  The sample is
    # a few file reads, the breakdown asks the database how big it is, and
    # the rollup averages minutes into the wider tables.
    from datetime import datetime, timedelta

    from app.core import utilization

    now = datetime.now(_UTC)
    for job_id, func, trigger, first in (
            ("utilization-sample", utilization.sample,
             IntervalTrigger(seconds=utilization.PERIOD_SEC), now),
            ("utilization-breakdown", utilization.refresh_breakdown,
             IntervalTrigger(minutes=5), now),
            ("utilization-rollup", utilization.rollup,
             IntervalTrigger(minutes=10), now + timedelta(minutes=1))):
        _scheduler.add_job(func, trigger, id=job_id, replace_existing=True,
                           next_run_time=first, misfire_grace_time=30,
                           coalesce=True, max_instances=1)


def shutdown() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def known_organizations(session) -> list:
    """Organizations we could schedule.

    The connections are the real answer: one credential per organization is how
    an estate this shape is set up, and every one of them is scannable the
    moment it is added.  Repository rows only cover what has already been
    scanned, so on their own they hide every organization somebody has just
    configured and not run yet.  The old settings list is still read for an
    install that predates connections.
    """
    from app.core import settings_store as store
    from app.core.models import Connection, Repository

    names = {str(name).strip() for name in
             (store.get(session, "scan.organizations") or []) if str(name).strip()}

    for row in session.query(Connection).all():
        for part in str(row.organizations or "").replace("\n", ",").split(","):
            part = part.strip()
            if part and part != "*":
                names.add(part)

    for (organization,) in (session.query(Repository.organization)
                            .distinct().all()):
        if organization:
            names.add(organization)
    return sorted(names)


def split_by_organization(session, actor: str, cron_start: str = "0 2 * * *",
                          gap_minutes: int = 40) -> list:
    """One scan schedule per organization, spread out through the night.

    A single job over the whole estate runs for hours and holds the lock the
    whole time.  One per organization means each is smaller, a failure only
    costs that one, and the API budget is spread rather than spent at once.
    """
    from app.core.models import Schedule

    organizations = known_organizations(session)
    if not organizations:
        return []

    parts = cron_start.split()
    try:
        minute, hour = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        minute, hour = 0, 2

    made = []
    for index, organization in enumerate(organizations):
        total = minute + index * gap_minutes
        at_minute = total % 60
        at_hour = (hour + total // 60) % 24
        cron = f"{at_minute} {at_hour} * * *"
        name = f"nightly {organization}"

        row = (session.query(Schedule)
               .filter(Schedule.name == name).one_or_none())
        if row is None:
            row = Schedule(name=name, created_by=actor)
            session.add(row)
        row.kind = "scan"
        row.cron = cron
        row.enabled = True
        row.scope_orgs = organization
        row.next_run_at = next_run_for(cron)
        made.append((name, cron, organization))

    session.flush()
    return made
