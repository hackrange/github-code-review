"""Scheduled scans of external sites.

A schedule says when, in the time zone set in Settings: once at a date and
time, or every day, every week on a weekday, or every month on a day, at a
time.  The scheduler looks once a minute for schedules whose next run has
come, starts the scan the way the Scan button would, and works out the next
run.  Missed runs while the server was down are not made up one by one: the
schedule runs once and moves on to its next time.
"""

from __future__ import annotations

import calendar
import logging
import re
from datetime import datetime, timedelta, timezone

from app.core.db import session_scope
from app.core.models import ExternalAsset, ExternalScanSchedule, utcnow

log = logging.getLogger("gcr.external")

FREQUENCIES = {"once": "Once", "daily": "Every day", "weekly": "Every week",
               "monthly": "Every month"}
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MAX_PER_SITE = 10


def zone():
    from app.core.scheduler import _zone

    return _zone()


def _aware(value):
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def next_run(sched, after: datetime, tz=None) -> datetime | None:
    """The first run strictly after `after`, in UTC.  None when there is none."""
    tz = tz or zone()
    after = _aware(after)
    local = after.astimezone(tz)
    hour, minute = (int(x) for x in (sched.time_of_day or "00:00").split(":"))

    def at(day):
        return datetime(day.year, day.month, day.day, hour, minute, tzinfo=tz)

    if sched.frequency == "once":
        try:
            when = datetime.strptime(sched.run_on, "%Y-%m-%dT%H:%M").replace(tzinfo=tz)
        except (TypeError, ValueError):
            return None
        return when.astimezone(timezone.utc) if when > after else None
    if sched.frequency == "daily":
        candidate = at(local)
        if candidate <= after:
            candidate = at(local + timedelta(days=1))
        return candidate.astimezone(timezone.utc)
    if sched.frequency == "weekly":
        ahead = (int(sched.weekday or 0) - local.weekday()) % 7
        candidate = at(local + timedelta(days=ahead))
        if candidate <= after:
            candidate = at(local + timedelta(days=ahead + 7))
        return candidate.astimezone(timezone.utc)
    if sched.frequency == "monthly":
        year, month = local.year, local.month
        for _ in range(3):
            last = calendar.monthrange(year, month)[1]
            day = min(int(sched.day_of_month or 1), last)
            candidate = datetime(year, month, day, hour, minute, tzinfo=tz)
            if candidate > after:
                return candidate.astimezone(timezone.utc)
            month += 1
            if month > 12:
                month, year = 1, year + 1
    return None


def clean(data: dict, profiles, site_has_auth: bool) -> dict:
    """A schedule as a form or the API sends it, checked.  Raises ValueError."""
    frequency = str(data.get("frequency") or "").strip().lower()
    if frequency not in FREQUENCIES:
        raise ValueError("How often is once, daily, weekly or monthly.")
    time_of_day = str(data.get("time_of_day") or "").strip()
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", time_of_day):
        raise ValueError("Give the time as HH:MM, such as 02:30.")
    out = {"frequency": frequency, "time_of_day": time_of_day, "run_on": "",
           "weekday": 0, "day_of_month": 1}
    if frequency == "once":
        day = str(data.get("run_on") or "").strip()[:10]
        try:
            datetime.strptime(day, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Give the date to run on, as YYYY-MM-DD.")
        out["run_on"] = f"{day}T{time_of_day}"
    elif frequency == "weekly":
        try:
            weekday = int(data.get("weekday"))
        except (TypeError, ValueError):
            raise ValueError("Pick the day of the week.")
        if not 0 <= weekday <= 6:
            raise ValueError("Pick the day of the week.")
        out["weekday"] = weekday
    elif frequency == "monthly":
        try:
            day = int(data.get("day_of_month"))
        except (TypeError, ValueError):
            raise ValueError("Pick the day of the month.")
        if not 1 <= day <= 31:
            raise ValueError("The day of the month is 1 to 31.")
        out["day_of_month"] = day
    profile = str(data.get("profile") or "").strip().lower()
    if profile and profile not in profiles:
        raise ValueError("Pick a scan profile.")
    out["profile"] = profile
    for key in ("authenticated", "ai_triage"):
        value = data.get(key)
        if isinstance(value, str):
            value = value.lower() in ("1", "on", "true", "yes")
        out[key] = bool(value)
    if out["authenticated"] and not site_has_auth:
        raise ValueError("This site has no scan sign in to use.  Set one in Edit first.")
    return out


def describe(sched) -> str:
    """The schedule in words, for the page and the API."""
    if sched.frequency == "once":
        return f"Once, on {sched.run_on.replace('T', ' at ')}"
    if sched.frequency == "daily":
        return f"Every day at {sched.time_of_day}"
    if sched.frequency == "weekly":
        return f"Every {WEEKDAYS[int(sched.weekday or 0)]} at {sched.time_of_day}"
    day = int(sched.day_of_month or 1)
    suffix = "th" if 10 <= day % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    tail = ", or the last day of a shorter month" if day > 28 else ""
    return f"Every month on the {day}{suffix} at {sched.time_of_day}{tail}"


def as_dict(sched) -> dict:
    return {"id": sched.id, "asset_id": sched.asset_id, "frequency": sched.frequency,
            "when": describe(sched), "run_on": sched.run_on or None,
            "time_of_day": sched.time_of_day, "weekday": sched.weekday,
            "day_of_month": sched.day_of_month, "profile": sched.profile or "",
            "authenticated": bool(sched.authenticated), "ai_triage": bool(sched.ai_triage),
            "enabled": bool(sched.enabled),
            "next_run_at": _aware(sched.next_run_at).isoformat() if sched.next_run_at else None,
            "last_run_at": _aware(sched.last_run_at).isoformat() if sched.last_run_at else None,
            "last_result": sched.last_result or "", "last_scan_id": sched.last_scan_id,
            "created_by": sched.created_by or ""}


def create(db, asset: ExternalAsset, data: dict, actor: str) -> ExternalScanSchedule:
    from app.core import dast_engines

    if db.query(ExternalScanSchedule).filter_by(asset_id=asset.id).count() >= MAX_PER_SITE:
        raise ValueError(f"A site can have at most {MAX_PER_SITE} schedules.")
    fields = clean(data, dast_engines.PROFILES, bool(asset.auth_kind))
    sched = ExternalScanSchedule(asset_id=asset.id, created_by=(actor or "")[:120], **fields)
    sched.next_run_at = next_run(sched, utcnow())
    if sched.next_run_at is None:
        raise ValueError("That time has already passed.")
    db.add(sched)
    db.flush()
    return sched


def run_due(now: datetime = None) -> int:
    """Start every scan whose time has come.  The scheduler calls this each minute."""
    from app.core import external

    now = now or utcnow()
    with session_scope() as db:
        if not external.enabled(db):
            return 0
        due = [s.id for s in db.query(ExternalScanSchedule).filter(
            ExternalScanSchedule.enabled.is_(True),
            ExternalScanSchedule.next_run_at.isnot(None),
            ExternalScanSchedule.next_run_at <= now)]
    started = 0
    for sched_id in due:
        with session_scope() as db:
            sched = db.get(ExternalScanSchedule, sched_id)
            asset = db.get(ExternalAsset, sched.asset_id) if sched else None
            if sched is None or asset is None:
                continue
            args = dict(asset_id=asset.id,
                        profile=sched.profile or external.profile_for(asset),
                        actor=sched.created_by, ai=sched.ai_triage,
                        auth=sched.authenticated)
            obsolete = asset.status == "obsolete"
        if obsolete:
            scan_id, problem = None, "the site is obsolete"
        else:
            scan_id, problem = external.start_scan(args["asset_id"], args["profile"],
                                                   args["actor"], ai_triage=args["ai"],
                                                   authenticated=args["auth"])
        with session_scope() as db:
            sched = db.get(ExternalScanSchedule, sched_id)
            if sched is None:
                continue
            sched.last_run_at = now
            sched.last_scan_id = scan_id
            sched.last_result = (f"started a {args['profile']} scan" if scan_id
                                 else f"skipped: {problem}")[:300]
            sched.next_run_at = next_run(sched, now)
            if sched.frequency == "once":
                sched.enabled = False
        started += 1 if scan_id else 0
        log.info("scheduled scan %s of site %s: %s", sched_id, args["asset_id"],
                 "started" if scan_id else f"skipped, {problem}")
    return started


def refresh_all() -> None:
    """Work every next run out again, after the time zone changed."""
    with session_scope() as db:
        for sched in db.query(ExternalScanSchedule).filter(ExternalScanSchedule.enabled.is_(True)):
            sched.next_run_at = next_run(sched, utcnow())
