"""Credentials for things that are not browsers.

An editor plugin cannot hold a session cookie, do a second factor or follow a
redirect to a login page.  It needs a bearer token, and a bearer token on a
laptop is the credential most likely to end up somewhere it should not be.

So: only the hash is stored, they expire, they can be revoked, every use is
recorded, and the scopes are thin enough that losing one is a nuisance rather
than an incident.

The token is shown once, when it is made.  There is no way to read it back,
which is the same promise this tool makes about everything else it stores.
"""

from __future__ import annotations

import hashlib
import logging
import secrets as secrets_module
from datetime import timedelta

from app.core.models import ApiToken, utcnow

log = logging.getLogger("gcr.api_tokens")

SCOPES = {
    "review": "Editors: send code to be checked, nothing is saved",
    "rules": "Editors: read the triage rules and exclusions",
    # Your findings, SBOMs and trend lines, and asking for an exception.  Each
    # is cut down to what the owner can open on the screen.  The whole estate
    # report files sit behind this scope too, and stay with the people allowed
    # them.  Its own scope rather than a corner of another, so a token handed
    # to an editor cannot pull every finding by accident.
    "reports": ("Pipelines: read your findings, fix plan, SBOMs and trends, "
                "and ask for exceptions"),
    # A CI job's token.  It asks for a verdict on a pull request and reads
    # the answer back, and that is all.  Its own scope so a pipeline secret
    # that leaks cannot be used to pull every report, and an editor token
    # cannot be used to run gate checks.
    "gate": "Pull requests: run the gate check before a merge",
    # Signing off: approving and rejecting exceptions, and writing
    # exclusions.  These take findings out of the report files, so they are
    # their own scope rather than part of reports.  A pipeline token that
    # leaks still cannot hide anything, and only an administrator's token can
    # carry this one.  The permission is checked again on every call.
    "approve": ("Administrators: approve or reject exceptions and add "
                "exclusions"),
    # External sites and their dynamic scans.  Only an administrator's token
    # can use it, since the pages are theirs alone, and the check is made on
    # every call rather than when the token is made.
    "external": ("External sites: list sites, record and start dynamic scans "
                 "(administrators only)"),
}

PREFIX = "gcr_"
DEFAULT_DAYS = 90
MAX_DAYS = 365


def _hash(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


def allowed_scopes(owner, scopes) -> list:
    """The scopes asked for, checked against the person the token belongs to.

    Raises ValueError with a sentence to show.  Always the owner's role, never
    the role of whoever is editing: an administrator giving a developer's
    token the approve scope would hand that developer an administrator's power
    through the back door.
    """
    from app.core import rbac

    wanted = sorted({s.strip() for s in scopes if s.strip() in SCOPES})
    if "external" in wanted and not rbac.can(owner, "external.manage"):
        raise ValueError("Only an administrator's token can work with external sites.")
    if "approve" in wanted and not (rbac.can(owner, "waiver.approve")
                                    and rbac.can(owner, "exclusion.write")):
        raise ValueError("Only an administrator's token can approve exceptions.")
    if not wanted:
        raise ValueError("Pick at least one thing it may do.")
    return wanted


def set_scopes(session, token_id: int, scopes, actor):
    """Change what a live token may do.  -> (row, the scopes it had before).

    Administrators only, on anybody's token.  The token itself does not
    change, so nothing using it has to be updated: the next call is checked
    against the new list.  Raises LookupError for a token that is not there,
    or is revoked or expired, and ValueError for scopes its owner may not have.
    """
    from app.core.models import User

    if actor is None or not _sees_everything(actor):
        raise PermissionError("Only an administrator can change a token's scopes.")
    row = session.query(ApiToken).filter(ApiToken.id == token_id).one_or_none()
    if row is None or not row.live():
        raise LookupError("No such token, or it no longer works.")
    owner = session.query(User).filter(User.id == row.user_id).one_or_none()
    if owner is None:
        raise LookupError("No such token, or it no longer works.")
    wanted = allowed_scopes(owner, scopes)
    before = row.scopes or ""
    row.scopes = ",".join(wanted)
    session.flush()
    log.info("api token %s scopes %s -> %s by %s", row.name, before, row.scopes,
             actor.username)
    return row, before


def create(session, user, name: str, scopes, days: int = DEFAULT_DAYS):
    """-> (row, the token itself).  The only time anybody sees the token."""
    name = (name or "").strip()
    if not name:
        raise ValueError("Give it a name, so somebody can tell later what it was for.")

    wanted = allowed_scopes(user, scopes)

    try:
        days = int(days)
    except (TypeError, ValueError):
        days = DEFAULT_DAYS
    if days < 1 or days > MAX_DAYS:
        raise ValueError(f"An expiry is between 1 and {MAX_DAYS} days.")

    raw = PREFIX + secrets_module.token_urlsafe(48)
    row = ApiToken(
        name=name[:120],
        token_hash=_hash(raw),
        prefix=raw[:12],
        scopes=",".join(wanted),
        user_id=user.id,
        created_by=user.username,
        expires_at=utcnow() + timedelta(days=days),
    )
    session.add(row)
    session.flush()
    log.info("api token %s created by %s, %d day(s)", row.name, user.username, days)
    return row, raw


def verify(session, presented: str, scope: str = "", source_ip: str = ""):
    """-> (token, user), or (None, None).

    Looks the hash up rather than comparing anything, so there is no string
    comparison here to time.  A token that is expired, revoked or missing the
    scope is treated exactly like one that does not exist.
    """
    token = (presented or "").strip()
    if not token:
        return None, None

    from app.core.models import User

    row = (session.query(ApiToken)
           .filter(ApiToken.token_hash == _hash(token)).one_or_none())
    if row is None or not row.live():
        return None, None
    if scope and not row.may(scope):
        return None, None

    # A token is only as good as the account behind it.  Disable somebody and
    # every token they made stops working, without anybody having to remember
    # to revoke them one at a time.
    owner = session.query(User).filter(User.id == row.user_id).one_or_none()
    if owner is None or owner.disabled:
        return None, None

    # Worth knowing which of these is still in use when somebody asks whether
    # they can all be revoked.
    row.last_used_at = utcnow()
    row.last_used_ip = (source_ip or "")[:64]
    row.uses = (row.uses or 0) + 1
    return row, owner


def revoke(session, token_id: int, actor=None) -> bool:
    """Revoke one.  Pass the user to make it theirs only."""
    query = session.query(ApiToken).filter(ApiToken.id == token_id)
    if actor is not None and not _sees_everything(actor):
        query = query.filter(ApiToken.user_id == actor.id)
    row = query.one_or_none()
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = utcnow()
    session.flush()
    log.info("api token %s revoked", row.name)
    return True


def _sees_everything(user) -> bool:
    from app.core import rbac
    return rbac.can(user, "user.write")


def remove(session, token_id: int, actor=None) -> bool:
    """Delete the row.

    Revoking stops a token working and keeps the record.  Deleting takes the
    row away, which is what somebody clearing up ten dead tokens actually
    wants.  The audit log still says it existed and who removed it, so nothing
    that matters is lost with it.
    """
    query = session.query(ApiToken).filter(ApiToken.id == token_id)
    if actor is not None and not _sees_everything(actor):
        query = query.filter(ApiToken.user_id == actor.id)
    row = query.one_or_none()
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True


def listing(session, user=None, include_dead: bool = False) -> list:
    """Somebody's own tokens, or everybody's for an administrator.

    Dead ones are left out unless asked for.  A page full of revoked tokens
    buries the two that still work, and the two that still work are the ones
    somebody came to look at.
    """
    query = session.query(ApiToken)
    if user is not None and not _sees_everything(user):
        query = query.filter(ApiToken.user_id == user.id)
    rows = query.order_by(ApiToken.id.desc()).all()
    if include_dead:
        return sorted(rows, key=lambda r: (not r.live(), -r.id))
    return [row for row in rows if row.live()]


def dead_count(session, user=None) -> int:
    return len([r for r in listing(session, user, include_dead=True)
                if not r.live()])
