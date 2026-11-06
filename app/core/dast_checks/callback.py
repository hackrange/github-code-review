"""The out of band callback: proof that a site reached back to us.

Some weaknesses only show when the server is made to make a request of its
own.  Server side request forgery is the clearest case: feed the site a URL,
and if the site fetches it, that proves the flaw, and nothing on the site had
to change for the proof.

The engine mints a unique token per probe, puts a callback URL carrying that
token into what it sends the site, and later asks here whether the token was
hit.  The public endpoint records a hit when something fetches the URL.

A token is random and namespaced, so only a real probe's token ever matches,
and a stray request with a made up token is ignored.  Hits hold only what
proves contact: the token, how it arrived, the caller's address and a short
note.  They are short lived and cleaned up.
"""

from __future__ import annotations

import re
import secrets

from app.core.db import session_scope

TOKEN_PREFIX = "gcrcb"
_TOKEN = re.compile(r"^gcrcb[0-9a-f]{20}$")
# How long a hit is kept.  A scan reads it within minutes; nothing needs it
# after that, and the table should not grow without bound.
KEEP_HOURS = 24


def base_url(db) -> str:
    from app.core import settings_store

    return (settings_store.get(db, "dast.oob_url") or "").strip().rstrip("/")


def valid_token(token: str) -> bool:
    return bool(_TOKEN.match(token or ""))


def record(token: str, kind: str = "http", source_ip: str = "",
           detail: str = "") -> bool:
    """Write a hit for a real token.  -> whether it was ours and recorded.

    Ignores anything that is not a token we mint, so the public endpoint cannot
    be used to stuff the table with arbitrary rows.  One row per token: a site
    that fetches the URL many times still proves contact once.
    """
    if not valid_token(token):
        return False
    from app.core.models import DastOobHit

    with session_scope() as db:
        if db.query(DastOobHit).filter(DastOobHit.token == token).first():
            return True
        db.add(DastOobHit(token=token, kind=(kind or "http")[:8],
                          source_ip=(source_ip or "")[:64], detail=(detail or "")[:300]))
    return True


def cleanup() -> int:
    """Drop hits older than the keep window.  -> how many went."""
    from datetime import timedelta

    from app.core.models import DastOobHit, utcnow

    cutoff = utcnow() - timedelta(hours=KEEP_HOURS)
    with session_scope() as db:
        gone = db.query(DastOobHit).filter(DastOobHit.seen_at < cutoff).delete()
    return gone or 0


class Callback:
    """What a scan uses to mint tokens, build the URL and check for a hit."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def token(self) -> str:
        return TOKEN_PREFIX + secrets.token_hex(10)

    def url(self, token: str) -> str:
        """The callback URL a probe hands the site for this token."""
        return f"{self.base}/oob/{token}"

    def hit(self, token: str) -> bool:
        from app.core.models import DastOobHit

        with session_scope() as db:
            return db.query(DastOobHit).filter(
                DastOobHit.token == token).first() is not None


def for_scan(db) -> "Callback | None":
    """A callback for a scan, or None when no callback address is set."""
    base = base_url(db)
    return Callback(base) if base else None
