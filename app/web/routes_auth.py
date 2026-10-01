"""Signing in and out.

Password, then the six digit code.  A password on its own gets you a session
that can reach exactly one page, and that page asks for the code.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from app.auth import service as auth_service
from app.config import settings
from app.core import live
from app.core.audit import record
from app.core.db import session_scope
from app.core.models import AuthSource, User
from app.web.render import page
from app.web.security import (
    SESSION_COOKIE, check_csrf, client_ip, half_auth_user, issue_csrf,
    new_csrf_token, redirect,
)

log = logging.getLogger("gcr.auth.routes")
router = APIRouter()


def _set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=live.session_hours() * 3600,
        httponly=True,
        secure=live.force_https(),
        samesite="lax",   # lax so a link from your mail client still works
        path=settings.base_path or "/",
    )


@router.get("/login")
def login_form(request: Request):
    """The sign in page, or straight to the provider when it is the only way.

    With the provider on its own there is nothing on this page to choose
    between, so showing a page with one button on it is a step that asks
    somebody to confirm what they already asked for.

    Two things still land here rather than bouncing.  Something went wrong and
    the reason has to be readable, and somebody has just signed out, where
    bouncing would hand them straight back to a provider that still has their
    session and sign them in again.  Both say so in the address, so the way
    back to this page is always to ask for it.
    """
    from app.web.security import optional_user
    if optional_user(request) is not None:
        return redirect("/")

    auth = live.auth_config()
    error = request.query_params.get("error", "")
    staying = request.query_params.get("stay", "") or error

    if auth.oidc_enabled and not auth.local_enabled and not staying:
        return redirect("/auth/oidc/start")

    return page(request, "login.html", stage="password",
                auth=auth, error=error)


@router.post("/auth/login")
async def login_submit(request: Request,
                       username: str = Form(""),
                       password: str = Form("")):
    await check_csrf(request)
    ip = client_ip(request)

    if not live.auth_config().local_enabled:
        return page(request, "login.html", stage="password", auth=live.auth_config(),
                    error="Local sign in is turned off here.")

    with session_scope() as db:
        result = auth_service.authenticate_local(db, username, password, ip)
        if not result.ok:
            return page(request, "login.html", stage="password",
                        auth=live.auth_config(), error=result.reason)

        # Half session.  It cannot reach anything except the code page.
        token = auth_service.create_session(
            db, result.user, ip, request.headers.get("user-agent", ""),
            half_auth=True)
        needs_setup = result.needs_totp_setup

    response = redirect("/auth/totp-setup" if needs_setup else "/auth/totp")
    _set_session_cookie(response, token)
    issue_csrf(response, new_csrf_token())
    return response


@router.get("/auth/totp")
def totp_form(request: Request):
    user = half_auth_user(request)
    if user is None:
        return redirect("/login")
    return page(request, "login.html", stage="totp", auth=live.auth_config(),
                username=user.username,
                error=request.query_params.get("error", ""))


@router.post("/auth/totp")
async def totp_submit(request: Request, code: str = Form("")):
    await check_csrf(request)
    user = half_auth_user(request)
    if user is None:
        return redirect("/login")

    token = request.cookies.get(SESSION_COOKIE, "")
    ip = client_ip(request)

    with session_scope() as db:
        row = db.query(User).filter(User.id == user.id).one_or_none()
        if row is None:
            return redirect("/login")

        # Locked by too many wrong codes, or by wrong passwords since this half
        # session began: the code step does not get to run past either.
        if auth_service.totp_locked(row):
            auth_service.revoke_session(db, token, "second step while locked")
            return redirect("/login")

        if not auth_service.check_totp(row, code):
            record(db, "login.totp_failed", actor=row.username, source_ip=ip,
                   outcome="denied")
            if auth_service.totp_failed(db, row, ip):
                # Out of tries.  The half session goes too, so the next guess
                # needs the password again and then waits out the lock.
                auth_service.revoke_session(db, token, "too many wrong codes")
                return redirect("/login")
            return page(request, "login.html", stage="totp", auth=live.auth_config(),
                        username=row.username,
                        error="That code did not work. Try the next one.")

        row.totp_failures = 0
        auth_service.promote_session(db, token)
        row.last_login_at = auth_service.utcnow()
        # Who signed in from what.  A sign in that records only the address is
        # the one event nobody can follow up: two people behind the same
        # gateway look identical, and the browser is the only other thing the
        # request tells us.  Truncated, because a user agent is somebody
        # else's string and this one is displayed.
        agent = (request.headers.get("user-agent") or "").strip()[:200]
        record(db, "login.success", actor=row.username, source_ip=ip,
               detail=(f"role {row.role.value}"
                       + (f"; {agent}" if agent else "")))
        must_change = bool(row.must_change_password)

    return redirect("/account/password" if must_change else "/")


@router.get("/auth/totp-setup")
def totp_setup_form(request: Request):
    """First run for a local account.  No code yet, so we make one."""
    user = half_auth_user(request)
    if user is None:
        return redirect("/login")
    # Enrollment is for an account that has no second factor yet.  Offering it
    # to one that does let anybody holding the password swap in their own
    # authenticator and walk past the code they did not have.
    if user.totp_confirmed:
        return redirect("/auth/totp")

    enrollment = auth_service.enroll_totp(user)
    response = page(request, "totp_setup.html",
                    username=user.username,
                    qr_svg=enrollment["qr_svg"],
                    secret=enrollment["secret"],
                    error=request.query_params.get("error", ""))
    # The secret rides in a short cookie until they prove they can read a code
    # off it.  Nothing is written to the account before that.
    response.set_cookie("gcr_totp_enroll", enrollment["secret"],
                        max_age=600, httponly=True,
                        secure=live.force_https(), samesite="strict",
                        path=settings.base_path or "/")
    return response


@router.post("/auth/totp-setup")
async def totp_setup_submit(request: Request, code: str = Form("")):
    await check_csrf(request)
    user = half_auth_user(request)
    if user is None:
        return redirect("/login")
    if user.totp_confirmed:
        return redirect("/auth/totp")

    secret = request.cookies.get("gcr_totp_enroll", "")
    if not secret:
        return redirect("/auth/totp-setup?error=That+took+too+long.+Here+is+a+new+code.")

    probe = User(username=user.username, totp_secret=secret)
    if not auth_service.check_totp(probe, code):
        return redirect("/auth/totp-setup?error=That+code+did+not+match.")

    plain, hashes = auth_service.make_recovery_codes()
    token = request.cookies.get(SESSION_COOKIE, "")

    with session_scope() as db:
        row = db.query(User).filter(User.id == user.id).one_or_none()
        if row is None:
            return redirect("/login")
        # Asked again on the row itself, inside the write, so two enrollments
        # racing each other cannot both land.
        if row.totp_confirmed:
            return redirect("/auth/totp")
        auth_service.save_totp(row, secret, hashes)
        auth_service.promote_session(db, token)
        row.last_login_at = auth_service.utcnow()
        record(db, "totp.enrolled", actor=row.username,
               source_ip=client_ip(request))
        # They are set up now, so the file with the starting password can go.
        if row.username == "admin":
            auth_service.clear_bootstrap_file()

    response = page(request, "recovery_codes.html", codes=plain,
                    username=user.username)
    response.delete_cookie("gcr_totp_enroll", path=settings.base_path or "/")
    return response


@router.get("/logout")
@router.post("/logout")
async def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        with session_scope() as db:
            row = auth_service.current_session(db, token)
            if row is not None:
                who = db.query(User).filter(User.id == row.user_id).one_or_none()
                record(db, "logout", actor=who.username if who else "",
                       source_ip=client_ip(request))
            auth_service.revoke_session(db, token)

    # Signed out lands on the page rather than the provider.  Going straight
    # back would meet a provider that still has a session and sign them in
    # again, which is not what anybody means by signing out.
    response = RedirectResponse(f"{settings.base_path}/login?stay=1",
                                status_code=303)
    response.delete_cookie(SESSION_COOKIE, path=settings.base_path or "/")
    return response


# ---------------------------------------------------------------------------
# Single sign on
# ---------------------------------------------------------------------------
@router.get("/auth/oidc/start")
async def oidc_start(request: Request):
    """Send the browser off to the identity provider."""
    from app.auth import oidc

    if not oidc.is_configured():
        return page(request, "login.html", stage="password", auth=live.auth_config(),
                    error="Single sign on is not set up here.")

    try:
        url = await oidc.begin_login(client_ip(request))
    except oidc.OIDCError as exc:
        log.warning("could not start an oidc login: %s", exc)
        return page(request, "login.html", stage="password", auth=live.auth_config(),
                    error=str(exc))

    return RedirectResponse(url, status_code=303)


@router.get("/auth/callback")
async def oidc_callback(request: Request):
    """Where the provider sends them back.

    An error here always lands on the login page with something readable.  A
    stack trace tells an attacker more than it tells the person signing in.
    """
    from app.auth import oidc

    params = request.query_params
    if params.get("error"):
        detail = params.get("error_description") or params.get("error")
        return page(request, "login.html", stage="password", auth=live.auth_config(),
                    error=f"Your provider refused the sign in: {detail[:200]}")

    code = params.get("code", "")
    state = params.get("state", "")
    if not code or not state:
        return page(request, "login.html", stage="password", auth=live.auth_config(),
                    error="That callback was missing something. Try again.")

    ip = client_ip(request)
    try:
        profile = await oidc.complete_login(code, state, ip)
    except oidc.OIDCError as exc:
        log.warning("oidc sign in failed from %s: %s", ip, exc)
        with session_scope() as db:
            record(db, "login.oidc_failed", source_ip=ip, detail=str(exc)[:200],
                   outcome="denied")
        return page(request, "login.html", stage="password", auth=live.auth_config(),
                    error=str(exc))

    try:
        with session_scope() as db:
            user = oidc.sync_user(db, profile)
            # The provider already did the second factor, so there is no half
            # session here.  Making them do TOTP again would just be theater.
            token = auth_service.create_session(
                db, user, ip, request.headers.get("user-agent", ""),
                half_auth=False)
            record(db, "login.success", actor=user.username, source_ip=ip,
                   detail=f"through the identity provider as {user.role.value}")
    except oidc.OIDCError as exc:
        with session_scope() as db:
            record(db, "login.oidc_denied", actor=profile.get("username", ""),
                   source_ip=ip, detail=str(exc)[:200], outcome="denied")
        return page(request, "login.html", stage="password", auth=live.auth_config(),
                    error=str(exc))

    response = redirect("/")
    _set_session_cookie(response, token)
    issue_csrf(response, new_csrf_token())
    return response
