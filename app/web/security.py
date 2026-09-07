"""The layer in front of every request.

Security headers, CSRF, rate limiting, and figuring out who is asking.  If you
are adding a route, the two things you need from here are current_user and
check_csrf.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth import service as auth_service
from app.config import settings
from app.core import live
from app.core.db import session_scope
from app.core.models import User

log = logging.getLogger("gcr.security")

SESSION_COOKIE = "gcr_session"
CSRF_COOKIE = "gcr_csrf"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"


# ---------------------------------------------------------------------------
# Who is asking
# ---------------------------------------------------------------------------
def client_ip(request: Request) -> str:
    """The caller's address.

    X-Forwarded-For is only believed when the request came from a proxy we
    were told about.  Otherwise anybody could set it and walk past the rate
    limiter.
    """
    peer = request.client.host if request.client else ""
    if not live.trusted_proxies():
        return peer

    try:
        peer_addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer

    trusted = False
    for entry in live.trusted_proxies():
        try:
            if peer_addr in ipaddress.ip_network(entry, strict=False):
                trusted = True
                break
        except ValueError:
            continue
    if not trusted:
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return peer


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------
class ImpersonationIsReadOnlyMiddleware(BaseHTTPMiddleware):
    """While an administrator is borrowing somebody's view, nothing writes.

    Enforced here rather than in each route on purpose.  A route that forgets
    the check is the whole hole, and there are well over a hundred of them.
    This sees every request whatever it is routed to, so there is one place to
    read and one place to get right.

    The reason it is read only at all: this product exists to say who decided
    what and why.  An administrator waiving a finding while wearing somebody
    else's face would put a name against a decision that person did not make,
    and that is the one record nobody can reconstruct afterwards.  Looking is
    useful, and looking is enough.

    Only writes pay for the lookup.  A GET never touches the database here.
    """

    SAFE = {"GET", "HEAD", "OPTIONS"}

    async def dispatch(self, request: Request, call_next):
        if request.method not in self.SAFE:
            path = request.url.path
            # The way out has to keep working, or somebody borrowing a view is
            # stuck in it.
            if not path.endswith("/impersonate/stop"):
                token = request.cookies.get(SESSION_COOKIE, "")
                if token and _session_is_borrowed(token, client_ip(request)):
                    log.warning("refused a %s to %s while impersonating",
                                request.method, path)
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "You are looking at this as somebody "
                                           "else.  Stop impersonating to make "
                                           "changes, so the record says who "
                                           "actually made them."})
        return await call_next(request)


def _session_is_borrowed(token: str, ip: str) -> bool:
    """Is this session currently looking at the product as somebody else."""
    try:
        with session_scope() as db:
            row = auth_service.current_session(db, token, ip)
            return bool(row is not None and row.impersonating_id)
    except Exception:            # noqa: BLE001 - never fail open on an error
        log.exception("could not tell whether this session is impersonating")
        return True


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Headers on every answer.

    The content security policy has no unsafe-inline for scripts.  Everything
    the page needs is in app.js, and the icons are inline SVG rather than
    fetched, so there is nothing to allow from anywhere else.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        headers = response.headers

        headers["Content-Security-Policy"] = "; ".join([
            "default-src 'self'",
            "script-src 'self'",
            # Inline style attributes are used for progress bar widths.
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
        ])
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "same-origin"
        headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()")
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        headers["Cross-Origin-Resource-Policy"] = "same-origin"

        if live.force_https():
            headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains")

        # Pages behind a login should never sit in a shared cache.
        if request.url.path.startswith(f"{settings.base_path}/static"):
            headers["Cache-Control"] = "public, max-age=3600"
        else:
            headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            headers["Pragma"] = "no-cache"

        return response


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    """A simple window per address, tighter on the sign in path.

    In memory on purpose.  One container, one process, and a limiter that
    needs its own database is a limiter that fails open when that database is
    having a bad day.
    """

    def __init__(self, app, general: int = 300, auth: int = 12,
                 window: int = 60):
        super().__init__(app)
        self.general = general
        self.auth = auth
        self.window = window
        self._hits = defaultdict(deque)

    def _allowed(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and bucket[0] < now - self.window:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.endswith(("/healthz", "/readyz")):
            return await call_next(request)

        ip = client_ip(request)
        is_auth_path = "/auth/" in path or path.endswith("/login")
        # A plugin calls the API on every save, so counting it against the
        # same budget as somebody clicking around the pages would lock the
        # pages out.  Its own bucket, and a wider one.
        is_api = "/api/v1/" in path
        if is_api:
            limit, kind = self.general * 4, "api"
        elif is_auth_path:
            limit, kind = self.auth, "auth"
        else:
            limit, kind = self.general, "gen"
        key = f"{kind}:{ip}"

        if not self._allowed(key, limit):
            log.warning("rate limited %s on %s", ip, path)
            # Returned, not raised.  The handler that turns an HTTPException
            # into a response lives inside the app, underneath this middleware,
            # so one raised here sails straight past it and reaches the caller
            # as a 500.  That is wrong twice over.  The client is told the
            # server broke rather than to slow down, so nothing backs off, and
            # every throttled request writes a full traceback to the log.  A
            # scanner walking a list of backup filenames turned that into
            # hundreds of tracebacks and buried everything else in them.
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(self.window)},
                content={"detail": "Slow down and try again in a minute."})
        return await call_next(request)


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def issue_csrf(response, token: str = None) -> str:
    """Put the token in a cookie the page can read back into its forms."""
    token = token or new_csrf_token()
    response.set_cookie(
        CSRF_COOKIE, token,
        max_age=live.session_hours() * 3600,
        httponly=False,     # the page has to read it to fill in the form
        secure=live.force_https(),
        samesite="strict",
        path=settings.base_path or "/",
    )
    return token


async def check_csrf(request: Request) -> None:
    """Compare what came with the form against the cookie.

    Another site can make your browser send its cookie, but it cannot read the
    cookie to fill in the matching field.  That difference is the whole trick.
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return

    cookie = request.cookies.get(CSRF_COOKIE, "")
    sent = request.headers.get(CSRF_HEADER, "")
    if not sent:
        try:
            form = await request.form()
            sent = str(form.get(CSRF_FIELD, ""))
        except Exception:
            sent = ""

    if not cookie or not sent or not secrets.compare_digest(cookie, sent):
        log.warning("csrf mismatch on %s from %s", request.url.path,
                    client_ip(request))
        raise HTTPException(status_code=403,
                            detail="That form expired. Load the page again.")


# ---------------------------------------------------------------------------
# Getting the signed in user
# ---------------------------------------------------------------------------
def _load_user(request: Request, allow_half: bool = False):
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return None, None

    with session_scope() as db:
        row = auth_service.current_session(db, token, client_ip(request))
        if row is None:
            return None, None
        if row.half_auth and not allow_half:
            return None, None

        user = db.query(User).filter(User.id == row.user_id).one_or_none()
        if user is None or user.disabled:
            return None, None

        # An administrator borrowing somebody's view.  What comes back is the
        # other person, so every page, every filter and every scope check
        # answers as it would for them, which is the entire point.  Who is
        # actually here is carried alongside, because the audit log and the
        # banner both need to say it, and because writing is refused while it
        # is set.
        borrowed = None
        if row.impersonating_id and not row.half_auth:
            borrowed = (db.query(User)
                        .filter(User.id == row.impersonating_id).one_or_none())
            if borrowed is not None and not borrowed.disabled:
                real_name = user.username
                user = borrowed
                _ = [x.organization for x in user.scopes]
                for group in user.groups:
                    _ = group.entries
                db.expunge(user)
                user.impersonated_by = real_name
                return user, row.half_auth

        # Pull the scopes and the groups in now, while the session is open.
        # Touching them after it closes gives a detached instance error, and
        # both are read on every page that lists findings.
        _ = [s.organization for s in user.scopes]
        for group in user.groups:
            _ = group.entries
        db.expunge(user)
        user.impersonated_by = ""
        return user, row.half_auth


def current_user(request: Request) -> User:
    """The signed in user, or a redirect to the login page.

    Use this on every page that is not the login page.
    """
    user, _half = _load_user(request)
    if user is None:
        raise HTTPException(
            status_code=307,
            headers={"Location": f"{settings.base_path}/login"},
            detail="Sign in first.",
        )

    # A password somebody else chose has to be changed before the rest of the
    # tool opens up.  The flag was read in exactly one place before this, the
    # redirect after sign in, and it pointed at a page that did not exist, so
    # it never actually stopped anybody: you got a 404 and carried on with the
    # password an administrator picked for you.
    if user.must_change_password:
        path = request.url.path
        base = settings.base_path or ""
        if path not in (f"{base}/account/password", f"{base}/logout"):
            raise HTTPException(
                status_code=307,
                headers={"Location": f"{base}/account/password"},
                detail="Change your password first.",
            )
    return user


def optional_user(request: Request):
    user, _half = _load_user(request)
    return user


def half_auth_user(request: Request):
    """The user partway through signing in, on the TOTP page only."""
    user, half = _load_user(request, allow_half=True)
    if user is None or not half:
        return None
    return user


def redirect(path: str, status_code: int = 303) -> RedirectResponse:
    return RedirectResponse(f"{settings.base_path}{path}",
                            status_code=status_code)


# ---------------------------------------------------------------------------
# Input checking
# ---------------------------------------------------------------------------
def clean_text(value, what: str = "value", limit: int = 500,
               required: bool = True) -> str:
    """Trim it, cap it, and refuse control characters."""
    text = (value or "").strip()
    if required and not text:
        raise HTTPException(status_code=400, detail=f"{what} is required.")
    if len(text) > limit:
        raise HTTPException(status_code=400,
                            detail=f"{what} is too long, keep it under {limit}.")
    if any(ord(c) < 32 and c not in "\n\t" for c in text):
        raise HTTPException(status_code=400,
                            detail=f"{what} has characters that do not belong.")
    return text


def clean_email(value, what: str = "Address", required: bool = False) -> str:
    """An owner has to be somebody you can actually reach.

    A name in an owner field ages badly: people move teams, and "Dana" is not
    something anybody can send a question to two years later.  An address is,
    and it is also the thing an audit needs when it asks who was told.

    Several are allowed, comma separated, because a rota is a real answer.
    """
    import re as _re

    text = (value or "").strip()
    if not text:
        if required:
            raise HTTPException(status_code=400, detail=f"{what} is required.")
        return ""
    if text == "-":
        return "-"          # the word that clears a field

    pattern = _re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[a-z]{2,}$", _re.I)
    cleaned = []
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not pattern.match(part):
            raise HTTPException(
                status_code=400,
                detail=f"{what} has to be an email address, so somebody can "
                       f"be asked about it later.  {part!r} is not one.")
        cleaned.append(part)
    if not cleaned:
        raise HTTPException(status_code=400,
                            detail=f"{what} has to be an email address.")
    if len(", ".join(cleaned)) > 400:
        raise HTTPException(status_code=400, detail=f"{what} is too long.")
    return ", ".join(cleaned)


def clean_remote_url(value, what: str = "Address", required: bool = False) -> str:
    """An address this server will fetch by itself.

    Anything the app requests on its own behalf is worth checking, because the
    request comes from inside the network and reaches whatever the container
    can reach.  Two rules:

    It has to be https.  Every provider this talks to publishes over TLS, and
    plain http here would be a downgrade nobody asked for.

    It cannot point at a link-local address.  That range is where cloud
    providers put the instance metadata service, and no identity provider or
    feed lives there.  Internal hosts are fine otherwise: a self hosted git
    server or an internal IdP on a private address is a normal way to run this.
    """
    from ipaddress import ip_address
    from urllib.parse import urlparse

    text = (value or "").strip()
    if not text:
        if required:
            raise HTTPException(status_code=400, detail=f"{what} is required.")
        return ""

    parsed = urlparse(text)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400,
                            detail=f"{what} has to start with https://")
    if not parsed.hostname:
        raise HTTPException(status_code=400,
                            detail=f"{what} needs a host name.")

    try:
        address = ip_address(parsed.hostname)
    except ValueError:
        return text          # a name, not a literal address

    if address.is_link_local:
        raise HTTPException(
            status_code=400,
            detail=f"{what} points at a link-local address, which is where "
                   "cloud metadata lives.  Use a real host.")
    return text


def clean_int(value, what: str = "value", low: int = None, high: int = None):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{what} must be a number.")
    if low is not None and number < low:
        raise HTTPException(status_code=400, detail=f"{what} is too small.")
    if high is not None and number > high:
        raise HTTPException(status_code=400, detail=f"{what} is too big.")
    return number
