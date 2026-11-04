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
    ias_config = str(data.get("ias_config") or "").strip()
    if ias_config:
        from app.core import insightappsec

        if not insightappsec.is_uuid(ias_config):
            raise ValueError("Pick an InsightAppSec scan config.")
        # The scan config in Rapid7 decides the attack and the sign in.
        out.update(profile="", authenticated=False)
    out["ias_config"] = ias_config
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
            "runs_on": "insightappsec" if sched.ias_config else "here",
            "ias_config": sched.ias_config or "",
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


# Bulk monthly schedules: days 1 to 28 so every month has each one, and a
# slot every half hour inside the window, so a night holds a handful of
# scans instead of every site at once.
BULK_DAYS = 28
BULK_STEP = 30


def window_slots(start: str, end: str, step: int = BULK_STEP) -> list:
    """The HH:MM times from start up to, not including, end.  A window may
    cross midnight, as 22:00 to 04:00 does.  Raises ValueError."""
    def minutes(text, what):
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(text or "")):
            raise ValueError(f"Give the {what} time as HH:MM, such as 22:00.")
        hour, minute = (int(x) for x in text.split(":"))
        return hour * 60 + minute

    first, last = minutes(start, "start"), minutes(end, "end")
    length = (last - first) % (24 * 60)
    if length < step:
        raise ValueError(f"The window has to be at least {step} minutes long.")
    return [f"{((first + n) // 60) % 24:02d}:{(first + n) % 60:02d}"
            for n in range(0, length, step)]


def bulk_monthly(db, assets: list, profile: str, start: str, end: str,
                 actor: str) -> dict:
    """A monthly scan for each site, spread over the month and the window.

    Each site gets the least used slot: across the days first, then the
    times, counting the monthly schedules already there.  A site marked no
    scan, one a block rule covers, an obsolete one, or one that already has a
    monthly scan of its own is skipped and named.
    -> {"created": [(host, when)], "skipped": [(host, why)]}
    """
    from app.core import dast_engines, external

    if profile not in dast_engines.PROFILES:
        raise ValueError("Pick a scan profile.")
    times = window_slots(start, end)
    used = {}
    for day, time_of_day in db.query(ExternalScanSchedule.day_of_month,
                                     ExternalScanSchedule.time_of_day).filter(
            ExternalScanSchedule.frequency == "monthly",
            ExternalScanSchedule.enabled.is_(True)):
        used[(int(day or 1), time_of_day)] = used.get((int(day or 1), time_of_day), 0) + 1
    order = [(day, t) for t in times for day in range(1, BULK_DAYS + 1)]
    has_monthly = {a for a, ias in db.query(ExternalScanSchedule.asset_id,
                                            ExternalScanSchedule.ias_config).filter(
        ExternalScanSchedule.frequency == "monthly",
        ExternalScanSchedule.enabled.is_(True)) if not ias}
    created, skipped = [], []
    for asset in sorted(assets, key=lambda a: a.host):
        if asset.no_scan:
            skipped.append((asset.host, "marked no scan"))
            continue
        if (asset.status or "active") == "obsolete":
            skipped.append((asset.host, "obsolete"))
            continue
        why = external.blocked(db, asset)
        if why:
            skipped.append((asset.host, why))
            continue
        if asset.id in has_monthly:
            skipped.append((asset.host, "already has a monthly scan"))
            continue
        pick = min(range(len(order)), key=lambda i: (used.get(order[i], 0), i))
        day, time_of_day = order[pick]
        try:
            sched = create(db, asset, {"frequency": "monthly", "day_of_month": day,
                                       "time_of_day": time_of_day, "profile": profile},
                           actor)
        except ValueError as exc:
            skipped.append((asset.host, str(exc)))
            continue
        used[(day, time_of_day)] = used.get((day, time_of_day), 0) + 1
        has_monthly.add(asset.id)
        created.append((asset.host, describe(sched)))
    return {"created": created, "skipped": skipped}


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
            ias_config = sched.ias_config or ""
            args = dict(asset_id=asset.id,
                        profile="" if ias_config else (sched.profile or external.profile_for(asset)),
                        actor=sched.created_by, ai=sched.ai_triage,
                        auth=sched.authenticated)
            obsolete = asset.status == "obsolete"
        if obsolete:
            scan_id, problem = None, "the site is obsolete"
        else:
            extra = {"ias_config": ias_config} if ias_config else {}
            scan_id, problem = external.start_scan(args["asset_id"], args["profile"],
                                                   args["actor"], ai_triage=args["ai"],
                                                   authenticated=args["auth"], **extra)
        with session_scope() as db:
            sched = db.get(ExternalScanSchedule, sched_id)
            if sched is None:
                continue
            sched.last_run_at = now
            sched.last_scan_id = scan_id
            what = "an InsightAppSec" if ias_config else f"a {args['profile']}"
            sched.last_result = (f"started {what} scan" if scan_id
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
