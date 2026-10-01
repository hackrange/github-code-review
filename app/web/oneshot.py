"""Something shown once, carried across a redirect without going in the URL.

A new password, a reset password and a new API token are each shown exactly
once, on the page a form redirects to.  They used to ride in that redirect's
query string, which put them in the access log, in any proxy's log and in the
browser's history: every place a URL is written down, for the life of those
files.  Now the secret stays here, in memory, under a random key, and only the
key goes in the URL.  The page takes it out once and it is gone.

In memory on purpose.  The app is one process, and a secret that never reaches
disk cannot be read back off it.  A restart between the redirect and the page
loses it, and the cost of that is somebody pressing the button again.
"""

from __future__ import annotations

import secrets
import threading
import time

# Long enough for a slow redirect, short enough that a key copied out of a log
# is worth nothing by the time anybody reads it.
TTL_SECONDS = 120
_MAX_HELD = 1000

_held = {}
_lock = threading.Lock()


def put(owner_id: int, value: str) -> str:
    """Hold a value for one user.  -> the key to put in the redirect."""
    key = secrets.token_urlsafe(24)
    now = time.monotonic()
    with _lock:
        for stale in [k for k, (_o, _v, at) in _held.items()
                      if now - at > TTL_SECONDS]:
            del _held[stale]
        if len(_held) >= _MAX_HELD:
            _held.pop(next(iter(_held)))
        _held[key] = (owner_id, value, now)
    return key


def take(key: str, owner_id: int) -> str:
    """The value, once, for the user it was held for.  -> "" otherwise.

    Taken out whether or not it matched, so a key cannot be tried twice.
    """
    if not key:
        return ""
    with _lock:
        held = _held.pop(key, None)
    if held is None:
        return ""
    owner, value, at = held
    if owner != owner_id or time.monotonic() - at > TTL_SECONDS:
        return ""
    return value
