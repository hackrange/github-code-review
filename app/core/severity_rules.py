"""Severity, as this organization means it.

A scanner grades a rule once, for everybody who will ever run it.  That grade
is a reasonable default and a poor answer: a plain HTTP link to an image on a
marketing page and a plain HTTP link carrying a session are the same rule and
very different risks, and only the people who own the system can say which one
they have.

So an override is a first class thing here, matched on the rule or on a CWE the
finding carries.  The engine's own grade is not thrown away: what changes is
what the number means to the people reading it.
"""

from __future__ import annotations

import logging

from app.core.models import Severity, SeverityRule

log = logging.getLogger("gcr.severity_rules")

MATCH_TYPES = ("rule", "cwe")


def all_rules(session) -> list:
    return (session.query(SeverityRule)
            .order_by(SeverityRule.match_type, SeverityRule.pattern).all())


def add(session, match_type: str, pattern: str, severity, actor: str = "",
        reason: str = "", unless_sensitivity: str = "") -> tuple:
    """-> (row, why not).  One override per pattern, so editing is replacing."""
    match_type = (match_type or "rule").strip().lower()
    if match_type not in MATCH_TYPES:
        return None, "Match on a rule name or a CWE."
    pattern = (pattern or "").strip()
    if not pattern:
        return None, "Give it something to match."
    try:
        severity = severity if isinstance(severity, Severity) else Severity(str(severity).lower())
    except ValueError:
        return None, "That is not a severity."

    row = (session.query(SeverityRule)
           .filter(SeverityRule.match_type == match_type,
                   SeverityRule.pattern == pattern).one_or_none())
    if row is None:
        row = SeverityRule(match_type=match_type, pattern=pattern)
        session.add(row)
    row.severity = severity
    row.reason = (reason or "")[:2000]
    row.unless_sensitivity = (unless_sensitivity or "")[:400]
    row.created_by = actor or ""
    session.flush()
    return row, ""


def remove(session, rule_id: int) -> bool:
    row = session.query(SeverityRule).filter(SeverityRule.id == rule_id).one_or_none()
    if row is None:
        return False
    session.delete(row)
    return True


def _tags(value) -> set:
    return {t.strip().lower() for t in str(value or "").split(",") if t.strip()}


def as_map(session) -> dict:
    """Loaded once per ingest rather than queried per finding."""
    out = {"rule": {}, "cwe": {}}
    for row in all_rules(session):
        out.setdefault(row.match_type, {})[row.pattern.strip().lower()] = (
            row.severity, _tags(row.unless_sensitivity))
    return out


def apply(overrides: dict, rule: str, cwe: str, sensitivity: str = ""):
    """The severity this organization gives it, or None to leave it alone.

    A rule name is the more specific statement, so it wins over a CWE.  A
    finding can carry several CWEs; the first one anybody wrote a rule for
    decides, and the order is the order they came in.

    An override stops applying where the system holds something it was not
    written for.  "A plain HTTP link is low" is a fair statement about a
    brochure site and a careless one about the system holding cardholder data,
    so the tags on the connection can take the exception away again.
    """
    if not overrides:
        return None
    carried = _tags(sensitivity)

    def usable(entry):
        severity, unless = entry
        if unless and (carried & unless):
            return None      # this system is one the exception was not meant for
        return severity

    by_rule = overrides.get("rule") or {}
    entry = by_rule.get((rule or "").strip().lower())
    if entry is not None:
        return usable(entry)

    by_cwe = overrides.get("cwe") or {}
    if by_cwe and cwe:
        for item in str(cwe).split(","):
            item = item.strip().lower()
            if not item:
                continue
            if item in by_cwe:
                return usable(by_cwe[item])
            # CWE-79 and 79 are the same thing to a person.
            bare = item.replace("cwe-", "")
            for key, value in by_cwe.items():
                if key.replace("cwe-", "") == bare:
                    return usable(value)
    return None
