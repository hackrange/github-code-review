"""Proposed changes to what a repository is.

Somebody who can see a finding but cannot change the repository can say what
it holds, what it is, who owns it, what it is for and where it is served.
They can also tick branches they think should not be scanned, with a reason.
Never the default branch, and never the whole repository.  None of it is saved onto the repository.  It waits here until an
administrator edits it, approves it, or turns it down.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import object_session

from app.core import scan_scope, tagging
from app.core.models import RepoProposal, utcnow

# What can be proposed.  The same answers the finding page's form and the
# repository's own page set, plus the description and where it is served.
FIELDS = ("sensitivity", "application_name", "application_owner",
          "technical_owner", "note", "web_app", "web_app_urls",
          "no_scan_branches", "no_scan_reason")

# Yes or no answers, kept as booleans rather than text.
FLAGS = ("web_app",)

# Kept here, not on the repository.  Approving writes them as branch scope
# overrides, so the scope page, its history and its undo all see them.
SCOPE_FIELDS = ("no_scan_branches", "no_scan_reason")

LABELS = {"sensitivity": "What it holds", "application_name": "Application",
          "application_owner": "Business owner",
          "technical_owner": "Technical owner", "note": "Description",
          "web_app": "Part of a web application",
          "web_app_urls": "Web addresses",
          "no_scan_branches": "Branches not to scan",
          "no_scan_reason": "Why not scan them"}

PENDING, APPROVED, REJECTED = "pending", "approved", "rejected"


def current(repo) -> dict:
    """What the repository says for itself now, in the shape a proposal has."""
    out = {field: (getattr(repo, field, "") or "").strip()
           for field in FIELDS if field not in FLAGS + SCOPE_FIELDS}
    for field in FLAGS:
        out[field] = bool(getattr(repo, field, False))
    out["no_scan_branches"] = skipped_now(repo)
    # The reason is only ever about a change, so there is none standing.
    out["no_scan_reason"] = ""
    return out


def skipped_now(repo) -> list:
    """The branches of this repository that are Do Not Scan now, sorted."""
    session = object_session(repo)
    if session is None:
        return []
    return scan_scope.rule_for(session, repo.full_name).skipped_branches()


def branch_choices(repo) -> list:
    """Branches somebody may tick: every one known except the default."""
    session = object_session(repo)
    if session is None:
        return []
    names = set(scan_scope.known_branches(session, repo.full_name))
    names.update(skipped_now(repo))
    names.discard(repo.default_branch or "")
    return sorted(n for n in names if n)


def changes(proposal) -> dict:
    try:
        value = json.loads(proposal.changes or "{}")
    except (TypeError, ValueError):
        return {}
    return {k: v for k, v in value.items() if k in FIELDS} \
        if isinstance(value, dict) else {}


def wanted(proposal) -> dict:
    """The whole record as it would be if this were approved now."""
    out = current(proposal.repo)
    out.update(changes(proposal))
    return out


def pending_count(session) -> int:
    return (session.query(RepoProposal)
            .filter(RepoProposal.status == PENDING).count())


def mine(session, repo_id: int, username: str):
    """This person's own pending proposal on a repository, if there is one."""
    return (session.query(RepoProposal)
            .filter(RepoProposal.repo_id == repo_id)
            .filter(RepoProposal.proposed_by == username)
            .filter(RepoProposal.status == PENDING).one_or_none())


def propose(session, repo, values: dict, username: str,
            finding_id: int = None):
    """Keep what somebody asked for.  -> the proposal, or None when it changes nothing.

    Only what differs from the repository is kept, so a reviewer sees what
    was asked rather than a whole form.  Asking again replaces their last
    pending one, and asking for exactly what is there withdraws it.
    """
    now = current(repo)
    diff = {k: v for k, v in values.items() if k in FIELDS and now.get(k) != v}
    # A reason on its own changes nothing.  It goes with the branches.
    if "no_scan_branches" not in diff:
        diff.pop("no_scan_reason", None)
    row = mine(session, repo.id, username)
    if not diff:
        if row is not None:
            session.delete(row)
            session.flush()
        return None
    if row is None:
        row = RepoProposal(repo_id=repo.id, proposed_by=username)
        session.add(row)
    row.changes = json.dumps(diff, sort_keys=True)
    row.finding_id = finding_id
    row.proposed_at = utcnow()
    session.flush()
    return row


def approve(session, proposal, values: dict, actor: str) -> list:
    """Write it onto the repository, as the reviewer left it.  -> the fields that moved.

    Raises ValueError when a branch change is refused, before anything moves.
    """
    repo = proposal.repo
    moved = []
    if "no_scan_branches" in values:
        moved += set_skipped(session, repo, values["no_scan_branches"],
                             values.get("no_scan_reason", ""), actor)
    moved += tagging.set_own(
        session, repo,
        {k: v for k, v in values.items()
         if k in FIELDS and k not in ("note",) + SCOPE_FIELDS},
        actor=actor)
    if "note" in values and values["note"] != (repo.note or "").strip():
        repo.note = values["note"]
        repo.note_by = actor
        repo.note_at = utcnow()
        moved.append("note")
    proposal.status = APPROVED
    proposal.decided_by = actor
    proposal.decided_at = utcnow()
    session.flush()
    return moved


def set_skipped(session, repo, branches, reason: str, actor: str) -> list:
    """Make exactly these branches Do Not Scan.  -> ["no_scan_branches"] if any moved.

    New ones become "none" overrides; ones no longer listed go back to
    following the repository.  Each goes through scan_scope.apply, so it is
    recorded and can be undone on the scope page.  Raises ValueError with
    the reason when one is refused, for instance the default branch.
    """
    want = sorted({str(b).strip() for b in (branches or []) if str(b).strip()})
    have = skipped_now(repo)
    if want == have:
        return []
    reason = (reason or "").strip()
    changes = ([(b, "none", "") for b in want if b not in have]
               + [(b, "inherit", "") for b in have if b not in want])
    _, problem = scan_scope.apply_batch(session, repo.full_name, changes,
                                        reason, None, actor)
    if problem:
        raise ValueError(problem)
    return ["no_scan_branches"]


def reject(session, proposal, actor: str) -> None:
    proposal.status = REJECTED
    proposal.decided_by = actor
    proposal.decided_at = utcnow()
    session.flush()
