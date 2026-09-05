"""The line between the backlog and the work.

The first scan of a repository with years in it comes back with thousands of
findings.  Nobody triages thousands.  The number never moves, it stops meaning
anything, and before long somebody turns the scan off.  A baseline is the way
out of that: what was already here is the backlog, what turns up afterwards is
the work, and the second number is one a small team can actually hold.

None of this deletes or hides anything.  It decides which of two lists a
finding lands in, and both lists are on the page.  An organization with no line
drawn has every finding counted as new, so an install that never sets one
behaves exactly as it did before this existed.

It is the finding's own first_found_at that decides, not the scan it last
turned up in, so rescanning never moves anything across the line.
"""

from __future__ import annotations

from sqlalchemy import and_, false, or_

from app.core.models import Baseline, Finding

MODES = ("new", "backlog", "any")


def dates(session) -> dict:
    """Organization to the date its line is drawn on."""
    return {row.organization: row.baseline_at
            for row in session.query(Baseline).all()}


def condition(session, mode: str):
    """A filter for one side of the line, or None to filter nothing.

    Returning None means "no restriction", which is right for new when no line
    exists anywhere.  Backlog with no line has to match nothing instead, or
    asking for the backlog would hand back the entire estate.
    """
    if mode not in {"new", "backlog"}:
        return None

    lines = dates(session)

    if mode == "backlog":
        if not lines:
            return false()
        return or_(*[and_(Finding.organization == org,
                          Finding.first_found_at < at)
                     for org, at in lines.items()])

    if not lines:
        return None
    parts = [and_(Finding.organization == org, Finding.first_found_at >= at)
             for org, at in lines.items()]
    # An organization nobody has drawn a line for is all work and no backlog.
    parts.append(Finding.organization.notin_(list(lines)))
    return or_(*parts)


def apply(session, query, mode: str):
    """Narrow a findings query to one side of the line."""
    clause = condition(session, mode)
    return query if clause is None else query.filter(clause)


def backlog_count(session, query) -> int:
    """How much is behind the line, for the number beside the filter.

    Takes the query the page already built so scope and every other filter
    still apply.  A count that ignored those would be a different number to
    the one the same person gets when they switch the filter over.
    """
    if not dates(session):
        return 0
    return apply(session, query, "backlog").count()
