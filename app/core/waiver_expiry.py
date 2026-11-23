"""Approved exceptions whose date has passed.

An exception ends on its expiry date, but nothing used to act on that.  The
waiver stayed "approved", the finding stayed waived, and only the places
that called Waiver.active() noticed.  A system reading the API saw a live
exception that was not one.

This closes them: the waiver becomes expired, and its finding comes back on
the list unless an exclusion still covers it.  Run on a timer, and before the
API answers anything about exceptions, so a reader never sees a stale one for
long.
"""

from __future__ import annotations

import logging
import threading
import time

from app.core.models import Finding, FindingState, Waiver, WaiverStatus, utcnow

log = logging.getLogger("gcr.waiver_expiry")

# How often a read may trigger a sweep.  The sweep is one indexed query when
# there is nothing to do, but a page of API calls should not each run it.
_READ_GAP_SECONDS = 60
_last_run = 0.0
_lock = threading.Lock()


def sweep(session, actor: str = "expiry") -> int:
    """Close every approved waiver past its date.  -> how many were closed."""
    from app.core import ingest
    from app.core.audit import record

    now = utcnow()
    # Compared naive, the way SQLite hands it back and MariaDB stores it.
    cutoff = now.replace(tzinfo=None)
    rows = (session.query(Waiver)
            .filter(Waiver.status == WaiverStatus.APPROVED,
                    Waiver.expires_at.isnot(None),
                    Waiver.expires_at <= cutoff)
            .all())
    if not rows:
        return 0

    reopened = []
    for waiver in rows:
        waiver.status = WaiverStatus.EXPIRED
        finding = session.get(Finding, waiver.finding_id)
        if finding is None:
            continue
        if finding.state == FindingState.WAIVED:
            finding.state = FindingState.OPEN
        if finding.excepted:
            finding.excepted = False
            finding.exception_reason = ""
            finding.exception_by = ""
            finding.exception_at = None
            finding.exception_expires_at = None
            reopened.append(finding)
        record(session, "waiver.expired", actor=actor,
               target=finding.fingerprint,
               detail=(f"exception {waiver.id} on {finding.repository} "
                       f"ran out on {waiver.expires_at:%Y-%m-%d}"))
    session.flush()
    # Anything an exclusion still covers goes straight back to excepted, with
    # that exclusion's reason.  The waiver's own mirrored exclusion carries
    # the same date, so it has run out too and does not match.
    if reopened:
        ingest.apply_exceptions(session, findings=reopened)
        session.flush()

    from app.core.reports import request_rewrite

    request_rewrite()
    log.info("closed %d expired exception(s)", len(rows))
    return len(rows)


def run() -> int:
    """The scheduled job.  Its own session, and never raises."""
    from app.core.db import session_scope

    global _last_run
    try:
        with session_scope() as db:
            done = sweep(db)
        _last_run = time.monotonic()
        return done
    except Exception:  # noqa: BLE001 - a timer job must not die
        log.warning("expired exception sweep failed", exc_info=True)
        return 0


def on_read() -> None:
    """Sweep before an API read, at most once a minute.  Never raises.

    In its own session, ahead of the reader's, so the answer that follows
    already sees the change.
    """
    global _last_run
    if time.monotonic() - _last_run < _READ_GAP_SECONDS:
        return
    if not _lock.acquire(blocking=False):
        return
    try:
        # Stamped first, so a sweep that keeps failing is tried once a
        # minute rather than on every call.
        _last_run = time.monotonic()
        run()
    finally:
        _lock.release()
