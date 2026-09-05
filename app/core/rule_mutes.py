"""Asking for a rule to be set aside, and somebody else agreeing to it.

Muting is the highest leverage thing anybody does in this tool.  An exception
hides one finding; a mute hides every finding a rule will ever produce, in
every repository, for as long as nobody looks again.  That is worth a second
person, and the point is not distrust: it is that the person closest to the
noise is the worst placed to judge whether it matters.

Two asymmetries hold the design together:

  Muting needs approval and unmuting does not.  Showing more findings is never
  the dangerous direction, so nobody has to wait for permission to undo one.

  Nobody approves their own request.  That is the whole control, and it works
  even when everybody is an administrator, which in a small team they usually
  are.
"""

from __future__ import annotations

import logging

from app.core.models import RuleMute, utcnow

log = logging.getLogger("gcr.rule_mutes")

REQUESTED, APPROVED, REJECTED, REVOKED = (
    "requested", "approved", "rejected", "revoked")

# Rules this tool ships set aside, and why.
#
# These are not somebody's decision, they are the tool's opinion, and the
# difference matters enough to keep them out of the rule_mutes table.  A row
# in that table names a person who asked and a person who agreed; seeding one
# would have to invent both, and the only thing that table is good for is
# being a record of what humans actually decided.
#
# So they live here as a constant and get unioned in at the point of use.  An
# install that disagrees turns one back on, which writes a real row saying so,
# and that row then outranks this list for that rule.
SHIPPED = {
    "unlink-use": "Flags every call to unlink(). It cannot tell a temporary "
                  "file from a path an attacker controls, so on a real "
                  "repository 100% of what it reported was a false positive. "
                  "It ships inside Default, so turning packs off will not "
                  "remove it: setting the rule aside is the only lever.",
    # This one is not a false positive and the reason says so. Pinning an
    # action to a tag rather than a commit is a real supply chain risk. It is
    # also one decision per repository rather than one per finding, and on a
    # twenty repository corpus it was 271 of 1,291 code findings, 21% of
    # everything, which buried the rest of the list.
    "github-actions-mutable-action-tag":
        "Correct, and worth fixing: an action pinned to a tag can be changed "
        "under you by whoever owns it. It is set aside because it is one "
        "decision per repository and it produced a fifth of every code "
        "finding on a real estate, not because it does not matter. The "
        "findings are still here under Set aside, and turning this back on "
        "puts them at the top where they will drown everything else.",
    "avoid-html-safe":
        "Flags every use of html_safe, which is an ordinary Rails idiom for "
        "markup the application built itself. It cannot tell that from markup "
        "built out of user input, so it reports the pattern rather than a "
        "misuse of it: 65 findings on one corpus, every one medium and every "
        "one low confidence.",
    "plaintext-http-link":
        "Flags every http:// address, including ones in comments, examples "
        "and links to specifications that only exist over http. A plain link "
        "on a page that carries no session is not the same risk as one that "
        "does, and this rule cannot tell them apart.",
}


def _latest(session) -> dict:
    """The last word on each rule, whatever it was.

    Ordering by id rather than by date: two decisions in the same second are
    ordinary, and a clock is a worse tiebreak than the order they were written.
    """
    latest = {}
    for row in session.query(RuleMute).order_by(RuleMute.id).all():
        latest[row.rule] = row
    return latest


def effective(session) -> list:
    """The rules actually set aside right now.

    Two sources.  A rule somebody asked for and somebody else agreed to, and a
    rule this tool ships set aside.  A pending request is neither: until
    somebody agrees the findings keep arriving, which is the safe way round
    for a request to sit unread.

    For a shipped rule the local record wins when there is one.  Revoked or
    rejected means this install looked at it and said no, and that has to
    survive a restart or the tool would quietly overrule them on every boot.
    """
    latest = _latest(session)
    out = {rule for rule, row in latest.items() if row.status == APPROVED}
    for rule in SHIPPED:
        row = latest.get(rule)
        if row is None or row.status == APPROVED:
            out.add(rule)
    return sorted(out)


def shipped_active(session) -> set:
    """Shipped rules in force with nobody here having touched them.

    The settings page needs to tell these apart from an approved mute, so it
    can say "shipped default" rather than putting somebody's name against a
    decision they never made.
    """
    latest = _latest(session)
    return {rule for rule in SHIPPED if latest.get(rule) is None}


def pending(session) -> list:
    return (session.query(RuleMute)
            .filter(RuleMute.status == REQUESTED)
            .order_by(RuleMute.requested_at.desc()).all())


def current(session, rule: str):
    """The live record for a rule, whatever state it is in."""
    return (session.query(RuleMute)
            .filter(RuleMute.rule == rule,
                    RuleMute.status.in_([REQUESTED, APPROVED]))
            .order_by(RuleMute.id.desc()).first())


def request(session, rule: str, actor: str, reason: str = "") -> tuple:
    """Ask for a rule to be set aside.  -> (record, created)"""
    rule = (rule or "").strip()
    if not rule:
        return None, False
    existing = current(session, rule)
    if existing is not None:
        return existing, False
    row = RuleMute(rule=rule, reason=(reason or "")[:2000],
                   status=REQUESTED, requested_by=actor or "")
    session.add(row)
    session.flush()
    return row, True


def approve(session, mute_id: int, actor: str) -> tuple:
    """Agree to somebody else's request.  -> (ok, why not)"""
    row = session.query(RuleMute).filter(RuleMute.id == mute_id).one_or_none()
    if row is None:
        return False, "That request is gone."
    if row.status != REQUESTED:
        return False, f"That request is already {row.status}."
    if (row.requested_by or "").strip().lower() == (actor or "").strip().lower():
        # The entire point.  One person deciding alone is what this exists to
        # prevent, and an administrator is still one person.
        return False, ("You asked for this one, so somebody else has to agree "
                       "to it.")
    row.status = APPROVED
    row.decided_by = actor or ""
    row.decided_at = utcnow()
    return True, ""


def reject(session, mute_id: int, actor: str) -> tuple:
    row = session.query(RuleMute).filter(RuleMute.id == mute_id).one_or_none()
    if row is None:
        return False, "That request is gone."
    if row.status != REQUESTED:
        return False, f"That request is already {row.status}."
    row.status = REJECTED
    row.decided_by = actor or ""
    row.decided_at = utcnow()
    return True, ""


def revoke(session, rule: str, actor: str) -> bool:
    """Put a rule back in the work list.  No approval: it only shows more."""
    changed = False
    for row in (session.query(RuleMute)
                .filter(RuleMute.rule == rule,
                        RuleMute.status.in_([REQUESTED, APPROVED])).all()):
        row.status = REVOKED
        row.decided_by = actor or ""
        row.decided_at = utcnow()
        changed = True

    # A shipped default has no row to turn over, so turning it back on has to
    # leave one behind.  Without this the constant would win again on the next
    # boot and quietly undo them.
    if not changed and rule in SHIPPED:
        latest = _latest(session).get(rule)
        if latest is None or latest.status == APPROVED:
            session.add(RuleMute(
                rule=rule, status=REVOKED,
                reason="shipped set aside by default; turned back on here",
                requested_by="", decided_by=actor or "",
                decided_at=utcnow()))
            session.flush()
            changed = True
    return changed
