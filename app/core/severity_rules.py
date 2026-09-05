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

# What this tool thinks some rules are worth, before anybody says otherwise.
#
# These are the tool's opinion rather than somebody's decision, which is why
# they live here as a constant instead of as rows: a row in the table names a
# person who made a call, and seeding one would have to invent that person.
# An install that disagrees writes a real row, and that row wins.
#
# The three below came out of putting this side by side with a commercial
# scanner on the same repository.  It graded all three low; this graded all
# three high, on infrastructure that was doing what it was designed to do.
# Being louder than the alternative is not the same as being better than it,
# and on these the other tool was right.
#
# Each carries the sensitivity labels that take the exception away again,
# because these are downgrades of exposure and encryption findings, and the
# argument for calling them minor stops holding on a system that holds
# regulated data.
SHIPPED = {
    "aws-0053": (
        "low",
        "A load balancer being reachable from the internet is what a public "
        "application is for. Graded high it fires on every public service in "
        "an estate and teaches people that this rule means nothing, which "
        "costs more than it finds. It stays reportable because an internal "
        "service that became internet facing by accident looks exactly the "
        "same in the file.",
        "PCI, HIPAA, CUI"),
    "aws-0132": (
        "low",
        "Storage encrypted with a provider managed key rather than a customer "
        "managed one. The data is encrypted either way: this is a statement "
        "about who holds the key, which is a compliance preference in most "
        "places and a requirement in a few.",
        "PCI, HIPAA, CUI"),
    "aws-0033": (
        "low",
        "The same question about a container registry rather than a bucket, "
        "and the same answer.",
        "PCI, HIPAA, CUI"),
    "aws-0031": (
        "medium",
        "A mutable image tag can be moved under you by anybody who can write "
        "to the registry, which is a real supply chain problem and not a high "
        "one: it needs push access to the registry first, and that is a much "
        "larger thing to have already lost.",
        ""),
}


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
    # The tool's own opinion first, so a decision somebody actually made
    # overwrites it below rather than the other way round.
    for pattern, (level, _why, unless) in SHIPPED.items():
        try:
            out["rule"][pattern] = (Severity(level), _tags(unless))
        except ValueError:          # a typo here must not take a scan down
            log.warning("shipped severity for %s is not a severity", pattern)
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
