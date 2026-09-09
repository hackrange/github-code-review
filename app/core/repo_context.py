"""What is known about a repository, gathered in one place.

Two screens ask the same question from different directions.  The blast radius
opens a repository to say what it is and who can reach it.  A finding wants the
same thing, because "a hardcoded password" means one thing in the payment
gateway and another in a brochure site, and the person reading the finding is
the one who has to tell them apart.

So it is answered once here rather than twice, slightly differently.
"""

from __future__ import annotations

import logging

log = logging.getLogger("gcr.repo_context")

# Enough people to show who can reach a repository without turning a finding
# page into a directory listing.  The blast radius page is where the whole list
# belongs.
MAX_PEOPLE = 25


def for_repository(session, full_name: str, *, with_people: bool = True) -> dict:
    """Everything worth knowing about one repository.  -> {} if it is unknown.

    Every tagged answer says where it came from.  "Nobody has said" and
    "somebody said, for the whole account" are different states, and a screen
    that shows them the same way is quietly asserting something nobody did.
    """
    from app.core import tagging
    from app.core.models import Repository

    if not full_name:
        return {}

    repo = (session.query(Repository)
            .filter(Repository.full_name == full_name).one_or_none())
    if repo is None:
        return {}

    applies = tagging.effective(session, repo)
    out = {
        "id": repo.id,
        "full_name": repo.full_name,
        "organization": repo.organization or "",
        "visibility": repo.visibility or "",
        "archived": bool(repo.archived),
        "default_branch": repo.default_branch or "",
        # Where it lives on the host.  Recorded by every scan and, until now,
        # never handed to a page: the repository was printed as text on screens
        # that had nothing else to offer as a way of getting to it.  That is
        # most obvious on a dependency finding, which has no file to open, so
        # the only link on the page led to an advisory on somebody else's site
        # and none led to the code the advisory is about.
        "html_url": repo.html_url or "",
        "protected": bool(repo.default_branch_protected),
        "last_scanned_at": repo.last_scanned_at,
        "connection": repo.connection or "",
        # Both halves of the same answer.  The name is what the row was
        # written with and what most screens print; the id is the one that
        # survives somebody renaming the account.
        "connection_id": repo.connection_id,
        "note": repo.note or "",
        "note_by": repo.note_by or "",
        "note_at": repo.note_at,
        "sensitivity": applies["sensitivity"],
        "application_name": applies["application_name"],
        "application_owner": applies["application_owner"],
        "technical_owner": applies["technical_owner"],
        "people": [],
        "people_total": 0,
        "admins": 0,
        "outside": 0,
    }

    if with_people:
        out.update(_people(session, full_name))
    return out


def _people(session, full_name: str) -> dict:
    """Who can reach it, worst permission first.

    Read straight from the access table rather than through the estate wide
    rollup: this is one repository, and building the whole picture to answer
    for one row would be the slowest thing on the page.
    """
    from app.core.access import RANK
    from app.core.models import RepoAccess

    try:
        rows = (session.query(RepoAccess)
                .filter(RepoAccess.repository == full_name).all())
    except Exception:            # noqa: BLE001 - a finding page must still open
        log.warning("could not read who can reach %s", full_name, exc_info=True)
        return {}

    people = [{
        "login": row.login,
        "permission": (row.permission or "read"),
        "outside": bool(row.outside_collaborator),
        "machine": (row.account_type or "User") != "User",
    } for row in rows]
    people.sort(key=lambda p: (-RANK.get(p["permission"], 0), p["login"].lower()))

    return {
        "people": people[:MAX_PEOPLE],
        "people_total": len(people),
        "admins": sum(1 for p in people if p["permission"] == "admin"),
        "outside": sum(1 for p in people if p["outside"]),
    }
