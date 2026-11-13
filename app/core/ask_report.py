"""A security findings report for the findings a question picked.  Read only.

The model decides the scope by writing a query that returns finding ids.
Everything after that is the same engine the Security Assessment PDF uses,
report_data and report_text, so the counts, the urgent items and the advice
read the same here as there and none of it is the model's opinion.

Everything is turned into plain values inside the read only session, because
that session is rolled back on the way out and an ORM row read afterwards
would be empty.
"""

from __future__ import annotations

import logging

log = logging.getLogger("gcr.ask.report")

MAX_FINDINGS = 5000
WORST = 25


def _sev(f) -> str:
    level = f.custom_severity or f.severity
    return getattr(level, "value", str(level or "unknown"))


def _finding(f) -> dict:
    row = {"finding_id": f.id, "id": f.vuln_id, "severity": _sev(f),
           "kind": getattr(f.kind, "value", str(f.kind)),
           "title": (f.title or "")[:240], "repository": f.repository,
           "branch": f.branch or "",
           "location": ("%s:%s" % (f.file_path, f.line) if f.line else (f.file_path or ""))[:300],
           "risk_score": f.risk_score or 0}
    if f.package_name:
        row["package"] = "%s %s" % (f.package_name, f.package_version or "")
        row["fixed_in"] = f.fixed_in or ""
    if f.vulnerability_id:
        row["advisory"] = f.vulnerability_id
    if f.cwe:
        row["cwe"] = f.cwe[:80]
    flags = []
    if f.verified:
        flags.append("confirmed working")
    if f.known_exploited:
        flags.append("known exploited")
    if f.malicious:
        flags.append("malicious package")
    if flags:
        row["flags"] = ", ".join(flags)
    return row


def build(finding_ids: list, scope_label: str) -> dict:
    """-> plain dict for the model, the chat panel and the PDF."""
    from app.core import report_data, report_text
    from app.core.db import read_only_session
    from app.core.models import Finding

    ids = [i for i in finding_ids if isinstance(i, int) and not isinstance(i, bool)]
    ids = list(dict.fromkeys(ids))[:MAX_FINDINGS]
    if not ids:
        return {}

    with read_only_session(seconds=30) as db:
        query = db.query(Finding).filter(Finding.id.in_(ids))
        data = report_data.assemble(db, query)
        worst = report_data.worst_findings(query, limit=WORST)
        out = {
            "scope": scope_label,
            "findings": data["coverage"]["findings"],
            "repositories": data["coverage"]["repositories"],
            "branches": data["coverage"]["branches"],
            "severity": data["severity"],
            "urgent": {key: value["count"] for key, value in data["urgent"].items()},
            "summary": report_text.assessment(data, scope_label),
            "recommendations": [{"priority": r["priority"], "title": r["title"],
                                 "detail": r["detail"]}
                                for r in report_text.what_matters(data)],
            "kinds": [{"name": k.get("name"), "total": k.get("total"),
                       "serious": k.get("serious"), "advice": k.get("advice")}
                      for k in data["kinds"]],
            "classes": [{"severity": section["severity"], "total": section["total"],
                         "groups": [{"name": c["name"], "count": c["count"],
                                     "what": c["what"], "todo": c["todo"],
                                     "repositories": c["repositories"][:8]}
                                    for c in section["classes"]]}
                        for section in data["detail"]],
            "actions": data["actions"],
            "themes": [{"title": t["title"], "count": t.get("count"),
                        "detail": t.get("detail", "")} for t in data["themes"]],
            "worst": [_finding(f) for f in worst],
            "capped": len(finding_ids) >= MAX_FINDINGS,
        }
    return out


def for_model(report: dict) -> dict:
    """The parts the model writes the answer from, kept small."""
    return {key: report.get(key) for key in (
        "scope", "findings", "repositories", "branches", "severity", "urgent",
        "summary", "recommendations", "classes", "actions", "capped")} | {
        "worst": report.get("worst", [])[:15]}
