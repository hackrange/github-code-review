"""Settings that used to live in the environment.

The .env file holds what the container needs before there is a database to ask:
where to listen, how to reach MariaDB, and the key.  Everything else belongs in
the database, where an admin can change it without editing a file and without a
restart, and where the client secret is encrypted rather than sitting in plain
text on the host.

Every reader here falls back to the environment, so a fresh install works
before anybody has been through the Settings page, and so does an install that
was set up with .env before any of this moved.

The values are cached for a few seconds.  These get read on every request, and
a database round trip per header is not worth it.
"""

from __future__ import annotations

import logging
import threading
import time

from app.config import AuthConfig, settings as env_settings

log = logging.getLogger("gcr.live")

# How long a cached copy is good for.  Short enough that a change shows up
# without a restart, long enough that a busy page does not hammer the database.
TTL_SECONDS = 15

_lock = threading.Lock()
_cache = {"at": 0.0, "values": None}


def invalidate() -> None:
    """Drop the cache.  Called after somebody saves the Settings page."""
    with _lock:
        _cache["at"] = 0.0
        _cache["values"] = None


def _values() -> dict:
    now = time.monotonic()
    with _lock:
        if _cache["values"] is not None and now - _cache["at"] < TTL_SECONDS:
            return _cache["values"]

    values = {}
    try:
        from app.core import settings_store as store
        from app.core.db import session_scope

        with session_scope() as db:
            for key in store.LIVE_KEYS:
                value = store.stored(db, key)
                # Only what somebody actually saved.  A default here would beat
                # whatever is in .env, which is not what anybody expects.
                if value is not store.MISSING:
                    values[key] = value
    except Exception as exc:
        # No database yet, or it is mid upgrade.  The environment still works.
        log.debug("falling back to the environment for live settings: %s", exc)
        values = {}

    with _lock:
        _cache["values"] = values
        _cache["at"] = time.monotonic()
    return values


def _get(key, fallback):
    value = _values().get(key)
    if value is None or value == "" or value == []:
        return fallback
    return value


def auth_config() -> AuthConfig:
    """How people sign in, as the app has always expected it."""
    env = env_settings.auth
    return AuthConfig(
        mode=str(_get("auth.mode", env.mode)).strip().lower(),
        oidc_issuer=str(_get("oidc.issuer", env.oidc_issuer)).strip(),
        oidc_client_id=str(_get("oidc.client_id", env.oidc_client_id)).strip(),
        oidc_client_secret=str(_get("oidc.client_secret", env.oidc_client_secret)),
        oidc_scopes=str(_get("oidc.scopes", env.oidc_scopes)),
        oidc_redirect_url=str(_get("oidc.redirect_url", env.oidc_redirect_url)).strip(),
        oidc_group_claim=str(_get("oidc.group_claim", env.oidc_group_claim)).strip(),
        oidc_admin_groups=list(_get("oidc.admin_groups", env.oidc_admin_groups) or []),
        oidc_developer_groups=list(_get("oidc.developer_groups",
                                        env.oidc_developer_groups) or []),
        oidc_reader_groups=list(_get("oidc.reader_groups", env.oidc_reader_groups) or []),
        oidc_default_role=str(_get("oidc.default_role",
                                   env.oidc_default_role)).strip().lower(),
    )


def session_hours() -> int:
    return int(_get("session.hours", env_settings.session_hours))


def idle_minutes() -> int:
    return int(_get("session.idle_minutes", env_settings.idle_minutes))


def login_attempt_limit() -> int:
    return int(_get("login.attempt_limit", env_settings.login_attempt_limit))


def login_lockout_minutes() -> int:
    return int(_get("login.lockout_minutes", env_settings.login_lockout_minutes))


def force_https() -> bool:
    value = _values().get("security.force_https")
    if value is None or value == "":
        return env_settings.force_https
    return bool(value)


def timezone_name() -> str:
    """The IANA zone every time on screen is shown in.

    Also the zone a schedule's cron is read in, so "0 2 * * *" means two in the
    morning where the person who typed it lives.  GMT keeps everything on UTC,
    which is what an install that has never been through the Settings page gets.
    """
    name = str(_get("ui.timezone", "GMT")).strip() or "GMT"
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(name)
    except Exception:
        # A zone the machine does not have must not take the whole app down.
        log.warning("unknown timezone %r in settings; falling back to GMT", name)
        return "GMT"
    return name


def trusted_proxies() -> list:
    return list(_get("security.trusted_proxies", env_settings.trusted_proxies) or [])
