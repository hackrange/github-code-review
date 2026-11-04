"""Mail before an External site's TLS certificate runs out.

Once a day, every site whose certificate ends within the number of days set
under Settings, External sites, is named in one message.  Each certificate is
named once: what was told is kept as the site and the certificate's end date,
so a renewed certificate starts over and an unchanged one is not repeated
every morning.

What the list knows about a certificate is as old as the site's telemetry,
which may be a week.  A certificate renewed since then would be a false
alarm, so each site about to be named has its certificate read again first,
with the same single handshake telemetry uses.  When that read fails the
stored date is used, and the message says where it came from.
"""

from __future__ import annotations

import datetime as dt
import logging

from app.core import settings_store as store

log = logging.getLogger("gcr.external_certs")


def _when(value) -> dt.datetime | None:
    try:
        got = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return got if got.tzinfo else got.replace(tzinfo=dt.timezone.utc)


def recipients(session) -> list:
    """The addresses set for these alerts, or the Notifications page's list."""
    from app.core import notify

    own = notify._split(store.get(session, "external.cert_alert_to"))
    return own or notify.recipients(session)


def stored_expiry(asset) -> dt.datetime | None:
    from app.core import external

    tls = external.telemetry_of(asset).get("tls") or {}
    return _when(tls.get("not_after"))


def live_expiry(host: str, allow_private: bool) -> dt.datetime | None:
    """The certificate the site serves now, or None when it cannot be read."""
    from app.core import external_probe

    ips = external_probe.resolve(host)
    if not ips or (not allow_private and not all(external_probe.is_public(i) for i in ips)):
        return None
    info = external_probe.analyze_tls(host, ips[0], legacy=False)
    return _when(info.get("not_after"))


def expiring(session, days: int, now: dt.datetime = None, reread: bool = True) -> list:
    """Sites whose certificate ends within `days`, soonest first.  Expired ones
    count: a site added after its certificate ran out is still worth saying."""
    from app.core import external
    from app.core.models import ExternalAsset

    now = now or dt.datetime.now(dt.timezone.utc)
    horizon = now + dt.timedelta(days=days)
    allow_private = bool(store.get(session, "external.allow_private"))
    out = []
    for asset in session.query(ExternalAsset).all():
        if (asset.status or "active") == "obsolete":
            continue
        ends = stored_expiry(asset)
        if ends is None or ends > horizon:
            continue
        source = "telemetry"
        if reread:
            try:
                fresh = live_expiry(asset.host, allow_private)
            except Exception:  # noqa: BLE001 - an unreadable site keeps the stored date
                fresh = None
            if fresh is not None:
                ends, source = fresh, "live"
                if ends > horizon:
                    continue  # renewed since telemetry was read
        tls = external.telemetry_of(asset).get("tls") or {}
        out.append({
            "id": asset.id, "host": asset.host,
            "application": asset.application or "",
            "environment": asset.environment or "",
            "not_after": ends,
            # Whole days on either side: a day and a half ago is one day ago.
            "days_left": (ends - now).days if ends >= now else -((now - ends).days),
            "issuer": tls.get("issuer") or "",
            "source": source,
            "read_at": asset.telemetry_at,
        })
    out.sort(key=lambda r: (r["not_after"], r["host"]))
    return out


def _line(site: dict) -> str:
    name = site["host"]
    extra = ", ".join(x for x in (site["application"], site["environment"]) if x)
    if extra:
        name += f" ({extra})"
    date = site["not_after"].strftime("%Y-%m-%d")
    left = site["days_left"]
    if left < 0:
        when = f"expired {date}, {-left} day{'s' if left != -1 else ''} ago"
    elif left == 0:
        when = f"expires {date}, today"
    else:
        when = f"expires {date}, in {left} day{'s' if left != 1 else ''}"
    text = f"{name}: certificate {when}"
    if site["source"] != "live":
        read = (f"telemetry read {site['read_at'].strftime('%Y-%m-%d')}" if site["read_at"]
                else "an earlier telemetry read")
        text += f".  The site did not answer just now, so this date is from {read}"
    return text + "."


def message(sites: list, days: int) -> tuple:
    """-> (title, lines)."""
    n = len(sites)
    title = (f"{n} site certificate{'s' if n != 1 else ''} "
             f"expire{'s' if n == 1 else ''} within {days} days")
    lines = [_line(s) for s in sites[:60]]
    if n > 60:
        lines.append(f"and {n - 60} more")
    lines.append("Each certificate is named once.  A renewed one is named again only "
                 "if it too comes within the warning window.")
    return title, lines


def daily() -> dict:
    """The scheduled check.  Quiet unless it is switched on and a certificate
    newly comes within the window.  -> what happened, for the audit log."""
    from app.core import external, notify
    from app.core.audit import record
    from app.core.db import session_scope

    with session_scope() as db:
        if not external.enabled(db) or not store.get(db, "external.cert_alert_enabled"):
            return {}
        days = int(store.get(db, "external.cert_alert_days") or 29)
        try:
            sites = expiring(db, days)
        except Exception as exc:  # noqa: BLE001 - a background job must not take the scheduler down
            log.warning("certificate check failed: %s", exc)
            return {}
        told = store.get(db, "external.cert_alert_last") or {}
        if not isinstance(told, dict):
            told = {}
        key = lambda s: s["not_after"].isoformat()  # noqa: E731
        new = [s for s in sites if told.get(str(s["id"])) != key(s)]
        if not new:
            # Forget sites that left the window, so the list never grows.
            store.set_value(db, "external.cert_alert_last",
                            {str(s["id"]): key(s) for s in sites}, "scheduler")
            return {"new": 0, "expiring": len(sites)}
        to = recipients(db)
        title, lines = message(new, days)
        root = notify.base_url(db)
        sent = notify._mail(db, title, lines, f"{root}/external" if root else "",
                            None, to) if to else {}
        ok = bool(sent) and all(sent.values())
        if ok:
            # Only once it went, so a mail server that was down tries again
            # tomorrow instead of the warning being lost.
            store.set_value(db, "external.cert_alert_last",
                            {str(s["id"]): key(s) for s in sites}, "scheduler")
        record(db, "notifications.cert_expiry", actor="scheduler",
               detail="%d newly expiring, %d in the window; %s" % (
                   len(new), len(sites),
                   ", ".join(f"{k}: {'ok' if v else 'failed'}" for k, v in sorted(sent.items()))
                   or "no recipients, nothing sent"),
               outcome="ok" if ok else "warn")
        return {"new": len(new), "expiring": len(sites), "sent": sent}
