"""Whether somebody in security has signed off a branch, and whether that still
describes the code.

The badge is the easy part.  What makes this safe to show is the two ways it
stops being true, because a green mark that outlives what it was based on is
worse than no mark at all: it does not merely fail to help, it actively tells
somebody not to look.

  It expires.  A date is required when it is written, and past that date it
  reads as lapsed rather than quietly carrying on.

  It goes stale the moment anybody pushes.  The commit that was reviewed is
  recorded and compared against where the branch is now, so any new commit at
  all turns the badge amber, whether or not it produced a finding.  Waiting for
  a finding would be the wrong test: a reviewer read some code, and different
  code has not been read.  "Our engines found nothing in it" is not the claim a
  sign off makes.

Both of those are shown rather than enforced.  Nothing in this file removes a
finding, changes a grade, or keeps anything out of a report.  A certified
repository that starts producing criticals shows every one of them, beside a
badge saying the review no longer covers what is there.  The moment a
certification can hide a finding it stops being one person's opinion and
becomes everybody else's blind spot.
"""

from __future__ import annotations

import logging

from datetime import timezone

from app.core.models import Certification, Finding, FindingState, utcnow

log = logging.getLogger("gcr.certification")

# The states a badge can be in, worst last so a caller can sort on it.
ACTIVE = "active"        # reviewed, in date, and nothing has changed since
STALE = "stale"          # in date, but the code has moved on
LAPSED = "lapsed"        # the date has passed
REVOKED = "revoked"      # somebody took it back
NONE = "none"            # nobody has reviewed this


def _aware(value):
    """A timestamp that can be compared with utcnow().

    SQLite hands back naive datetimes whatever the column says, so a stored
    expiry compared straight against an aware now raises rather than
    answering.  On a single file install that meant the finding page did not
    render at all, which is a strange way to find out a badge had expired.
    """
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def for_branch(session, repository: str, branch: str):
    """The certification covering this branch, whatever state it is in."""
    if not repository:
        return None
    return (session.query(Certification)
            .filter(Certification.repository == repository)
            .filter(Certification.branch == (branch or ""))
            .one_or_none())


def head_of(session, repository: str, branch: str) -> str:
    """Where that branch was at the last scan, as a commit."""
    import json

    from app.core.models import Repository

    repo = (session.query(Repository)
            .filter(Repository.full_name == repository).one_or_none())
    if repo is None:
        return ""
    try:
        heads = json.loads(repo.branch_heads or "{}") or {}
    except (TypeError, ValueError):
        return ""
    if branch:
        return str(heads.get(branch, "") or "")
    return str(heads.get(repo.default_branch or "", "") or "")


def status(session, row, head_sha: str = "") -> dict:
    """-> {state, why, ...}.  What this badge should say today.

    Answers with a sentence rather than a color, because the interesting cases
    are the ones where it is no longer true and the reader needs to know which
    kind of no longer true it is.
    """
    if row is None:
        return {"state": NONE, "why": "", "certification": None}

    now = utcnow()
    if row.revoked_at is not None:
        return {"state": REVOKED, "certification": row,
                "why": ("withdrawn by %s%s" % (
                    row.revoked_by or "somebody",
                    ": " + row.revoked_reason if row.revoked_reason else ""))}

    expires = _aware(row.expires_at)
    if not expires or expires <= now:
        return {"state": LAPSED, "certification": row,
                "why": "the review has passed its expiry date and needs doing again"}

    # Has anybody pushed since the review.
    #
    # This is the first question and not the second, and the order is the
    # point.  Waiting for a finding to arrive would mean a badge stays green
    # across any amount of new code the scanner happened to have nothing to
    # say about, and "our engines found nothing in it" is not what a sign off
    # claims.  A reviewer read some code.  Different code has not been read.
    #
    # Only ever decided on two known commits.  A missing sha proves nothing,
    # and guessing towards still-fine is the one direction that would make
    # this badge a liability.
    if not head_sha:
        head_sha = head_of(session, row.repository, row.branch)
    if row.commit_sha and head_sha and head_sha != row.commit_sha:
        return {"state": STALE, "certification": row, "moved": True,
                "why": ("the branch has moved since the review, from %s to %s, "
                        "so somebody has pushed code nobody has looked at"
                        % (row.commit_sha[:12], head_sha[:12]))}

    # And whether anything has been found since, which catches the case the
    # commit check cannot: a repository certified before it was ever scanned,
    # or one whose head this install has not recorded yet.
    since = (session.query(Finding)
             .filter(Finding.repository == row.repository)
             .filter(Finding.state == FindingState.OPEN)
             .filter(Finding.excepted.is_(False))
             .filter(Finding.first_found_at > _aware(row.certified_at))
             .count())
    if since:
        return {"state": STALE, "certification": row, "new_findings": since,
                "why": ("%d finding%s has arrived since the review, so it no "
                        "longer covers what is there"
                        % (since, "" if since == 1 else "s"))}

    return {"state": ACTIVE, "certification": row,
            "why": "reviewed and nothing has changed since"}


def certify(session, repository: str, branch: str, note: str, expires_at,
            actor: str, commit_sha: str = "") -> tuple:
    """Record a review, or replace the one that is there.  -> (row, why not)."""
    repository = (repository or "").strip()
    if not repository:
        return None, "Which repository."
    if expires_at is None:
        return None, ("Give it an expiry date.  A review with no end date is a "
                      "claim that nothing will ever change.")
    if _aware(expires_at) <= utcnow():
        return None, "That date has already passed."
    note = (note or "").strip()
    if len(note) < 20:
        return None, ("Say what you reviewed and what you concluded.  Somebody "
                      "is going to rely on this without being able to ask you.")

    row = for_branch(session, repository, branch)
    if row is None:
        row = Certification(repository=repository, branch=(branch or ""))
        session.add(row)

    row.note = note[:4000]
    row.commit_sha = (commit_sha or "")[:64]
    row.certified_by = actor or ""
    row.certified_at = utcnow()
    row.expires_at = expires_at
    # Recertifying clears a previous withdrawal: this is a fresh review, and
    # the audit log keeps the fact that the old one was taken back.
    row.revoked_at = None
    row.revoked_by = ""
    row.revoked_reason = ""
    session.flush()
    log.info("%s certified %s on %s until %s", actor, repository,
             branch or "(default)", expires_at)
    return row, ""


def revoke(session, repository: str, branch: str, actor: str,
           reason: str = "") -> tuple:
    """Take one back.  Kept rather than deleted.  -> (row, why not)."""
    row = for_branch(session, repository, branch)
    if row is None:
        return None, "There is no certification on that branch."
    if row.revoked_at is not None:
        return None, "That one has already been withdrawn."
    row.revoked_at = utcnow()
    row.revoked_by = actor or ""
    row.revoked_reason = (reason or "")[:2000]
    session.flush()
    return row, ""
