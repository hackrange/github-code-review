"""Decisions on dynamic scan findings: false positive, a new severity, or an
exception until a date.

A decision belongs to the site and the finding, not to one scan, so the next
scan that finds the same thing again carries it too.  Each scan's counts, its
worst severity and the site's last scan are worked out again from the
findings with the decisions applied, whenever a decision is made or undone,
when a scan finishes, and nightly so an expired exception counts again.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from app.core.models import (ExternalAsset, ExternalDastScan, ExternalFindingDecision,
                             utcnow)

KINDS = {"false_positive": "False positive", "severity": "Severity changed",
         "exception": "Exception"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
MAX_EXCEPTION_DAYS = 365


def finding_key(f: dict) -> str:
    """The same finding in two scans gets the same key: its title and its
    address without the query, without case."""
    title = re.sub(r"\W+", " ", str(f.get("title") or "").lower()).strip()
    url = str(f.get("url") or "").split("?")[0].split("#")[0].rstrip("/").lower()
    return hashlib.sha256(f"{title}|{url}".encode()).hexdigest()[:32]


def _aware(value):
    return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)


def active(decision, now=None) -> bool:
    if decision.kind != "exception" or decision.expires_at is None:
        return True
    return _aware(decision.expires_at) > (now or utcnow())


def for_asset(db, asset_id: int) -> dict:
    """-> {finding key: {0: the site's decision, scan id: that scan's own}}"""
    out: dict = {}
    for d in db.query(ExternalFindingDecision).filter_by(asset_id=asset_id):
        out.setdefault(d.finding_key, {})[int(d.only_scan_id or 0)] = d
    return out


def effective(decisions: dict, key: str, scan_id: int = 0):
    """The decision that holds for this finding on this scan: the scan's own,
    or else the site's."""
    mine = decisions.get(key) or {}
    return mine.get(int(scan_id or 0)) if scan_id and int(scan_id) in mine else mine.get(0)


def apply(findings: list, decisions: dict, now=None, scan_id: int = 0) -> list:
    """The findings with decisions marked on them.  Each keeps what was found
    as severity_found; severity is what counts."""
    out = []
    for f in findings or []:
        f = dict(f)
        f["key"] = f.get("key") or finding_key(f)
        f["severity_found"] = f.get("severity_found") or f.get("severity")
        f["severity"] = f["severity_found"]
        f.pop("decision", None)
        d = effective(decisions, f["key"], scan_id)
        if d is not None and active(d, now):
            f["decision"] = {"id": d.id, "kind": d.kind, "kind_name": KINDS.get(d.kind, d.kind),
                             "severity": d.severity or "", "reason": d.reason or "",
                             "by": d.decided_by or "",
                             "at": _aware(d.decided_at).isoformat() if d.decided_at else None,
                             "persist": not d.only_scan_id,
                             "expires": _aware(d.expires_at).isoformat() if d.expires_at else None}
            if d.kind == "severity" and d.severity in SEVERITIES:
                f["severity"] = d.severity
        elif d is not None:
            f["decision_expired"] = True
        out.append(f)
    return out


def counted(f: dict) -> bool:
    return (f.get("decision") or {}).get("kind") not in ("false_positive", "exception")


def recount(db, asset_id: int, now=None) -> None:
    """Apply the site's decisions to every finished scan of it, and the
    newest one to the site."""
    from app.core import external, external_dast

    decisions = for_asset(db, asset_id)
    for scan in db.query(ExternalDastScan).filter_by(asset_id=asset_id, status="done"):
        if scan.summary_only:
            continue
        findings = apply(external.findings_of(scan), decisions, now, scan.id)
        roll = external_dast.rollup([f for f in findings if counted(f)])
        scan.findings = json.dumps(findings, default=str)
        scan.severity = roll["severity"]
        for sev in SEVERITIES:
            setattr(scan, sev, roll[sev])
    asset = db.get(ExternalAsset, asset_id)
    if asset is not None:
        external.copy_newest(db, asset)


def decide(db, asset, scan, key: str, kind: str, reason: str, actor: str,
           severity: str = "", expires: str = "", persist: bool = True) -> ExternalFindingDecision:
    """Record a decision on one finding.  Raises ValueError with a sentence."""
    from app.core import external

    if kind not in KINDS:
        raise ValueError("A decision is false positive, a new severity, or an exception.")
    reason = str(reason or "").strip()
    if len(reason) < 10:
        raise ValueError("Say why, in at least 10 characters.  The next person to see it will ask.")
    finding = next((f for f in apply(external.findings_of(scan), {})
                    if f["key"] == key), None)
    if finding is None:
        raise ValueError("That finding is not in this scan.")
    only = 0 if persist else scan.id
    if persist:
        # Kept for the whole site from this scan on: this scan's own decision,
        # if it had one, would hide it here, so it goes.
        db.query(ExternalFindingDecision).filter_by(
            asset_id=asset.id, finding_key=key, only_scan_id=scan.id).delete()
    row = (db.query(ExternalFindingDecision)
           .filter_by(asset_id=asset.id, finding_key=key, only_scan_id=only).one_or_none())
    if row is None:
        row = ExternalFindingDecision(asset_id=asset.id, finding_key=key, only_scan_id=only)
        db.add(row)
    row.kind, row.reason = kind, reason[:4000]
    row.title, row.url = str(finding.get("title") or "")[:300], str(finding.get("url") or "")[:1000]
    row.severity, row.expires_at = "", None
    if kind == "severity":
        severity = str(severity or "").lower()
        if severity not in SEVERITIES:
            raise ValueError("Pick the severity it should have.")
        if severity == finding.get("severity_found"):
            raise ValueError("That is the severity it already has.")
        row.severity = severity
    if kind == "exception":
        try:
            when = datetime.strptime(str(expires or "")[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError("An exception needs the date it ends, as YYYY-MM-DD.")
        if when <= utcnow():
            raise ValueError("An exception has to end in the future.")
        if when > utcnow() + timedelta(days=MAX_EXCEPTION_DAYS):
            raise ValueError(f"An exception can last at most {MAX_EXCEPTION_DAYS} days.")
        row.expires_at = when
    row.decided_by, row.decided_at, row.scan_id = (actor or "")[:120], utcnow(), scan.id
    db.flush()
    recount(db, asset.id)
    return row


def undo(db, asset, key: str, scan_id: int = 0) -> bool:
    """Take back the decision that holds on this scan: its own if it has
    one, which lets the site's decision show again, or else the site's."""
    row = effective(for_asset(db, asset.id), key, scan_id)
    if row is None:
        return False
    db.delete(row)
    db.flush()
    recount(db, asset.id)
    return True


def recount_expired() -> int:
    """Nightly: sites with an exception that has ended count it again."""
    from app.core.db import session_scope

    with session_scope() as db:
        ids = {d.asset_id for d in db.query(ExternalFindingDecision).filter(
            ExternalFindingDecision.kind == "exception",
            ExternalFindingDecision.expires_at <= utcnow())}
        for asset_id in ids:
            recount(db, asset_id)
    return len(ids)
