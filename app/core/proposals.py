"""Proposed changes to what a repository is.

Somebody who can see a finding but cannot change the repository can say what
it holds, what it is, who owns it, what it is for and where it is served.
None of it is saved onto the repository.  It waits here until an
administrator edits it, approves it, or turns it down.
"""

from __future__ import annotations

import json

from app.core import tagging
from app.core.models import RepoProposal, utcnow

# What can be proposed.  The same answers the finding page's form and the
# repository's own page set, plus the description and where it is served.
FIELDS = ("sensitivity", "application_name", "application_owner",
          "technical_owner", "note", "web_app", "web_app_urls")

LABELS = {"sensitivity": "What it holds", "application_name": "Application",
          "application_owner": "Business owner",
          "technical_owner": "Technical owner", "note": "Description",
          "web_app": "Part of a web application",
          "web_app_urls": "Web addresses"}

PENDING, APPROVED, REJECTED = "pending", "approved", "rejected"


def current(repo) -> dict:
    """What the repository says for itself now, in the shape a proposal has."""
    out = {field: (getattr(repo, field, "") or "").strip()
           for field in FIELDS if field != "web_app"}
    out["web_app"] = bool(repo.web_app)
    return out


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
    """Write it onto the repository, as the reviewer left it.  -> the fields that moved."""
    repo = proposal.repo
    moved = tagging.set_own(
        session, repo,
        {k: v for k, v in values.items() if k in FIELDS and k != "note"},
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


def reject(session, proposal, actor: str) -> None:
    proposal.status = REJECTED
    proposal.decided_by = actor
    proposal.decided_at = utcnow()
    session.flush()
