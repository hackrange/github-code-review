"""Who did what.

Append only.  Nothing in the app deletes from this table, and there is no
route that lets anyone try.
"""

from __future__ import annotations

import logging

from app.core.models import AuditEvent

log = logging.getLogger("gcr.audit")


def record(session, action: str, actor: str = "", target: str = "",
           detail: str = "", source_ip: str = "", outcome: str = "ok") -> None:
    """Write one line of history.

    Never raises.  An audit write failing should not take down the thing the
    person was actually doing, but it does get logged loudly.
    """
    try:
        session.add(AuditEvent(
            actor=(actor or "")[:120],
            action=(action or "")[:120],
            target=(target or "")[:512],
            detail=(detail or "")[:4000],
            source_ip=(source_ip or "")[:64],
            outcome=(outcome or "ok")[:32],
        ))
        session.flush()
    except Exception as exc:
        log.error("could not write audit event %s: %s", action, exc)
