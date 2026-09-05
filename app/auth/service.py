"""Local sign in, TOTP, and sessions.

Two stages.  The password gets you a half session that can reach exactly one
page, the one asking for your six digit code.  Only after the code checks out
does the session become real.

Nothing here trusts anything the browser sends about who you are.  The session
token is random, we store only its hash, and the cookie is the whole claim.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.config import settings
from app.core import live
from app.core.audit import record
from app.core.models import AuthSource, Session, User, UserRole, utcnow

log = logging.getLogger("gcr.auth")

# Sensible cost.  Enough to hurt an offline attacker, not enough that a login
# takes long enough for anyone to notice.
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

TOTP_ISSUER = "Git Code Review"
RECOVERY_CODE_COUNT = 10


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    if not stored_hash or not password:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, ValueError):
        return True


def password_problems(password: str) -> list:
    """What is wrong with this password.

    Length does most of the work.  The rest is about the handful of choices
    that show up in every breach list.
    """
    out = []
    if len(password or "") < 12:
        out.append("Use at least 12 characters.")
    if password and password.lower() in {
        "password", "password123", "letmein", "changeme", "admin",
        "administrator", "welcome", "qwerty", "123456789012",
    }:
        out.append("That one is on every list attackers try first.")
    if password and password.strip() != password:
        out.append("Leading or trailing spaces are more trouble than they are worth.")
    return out


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------
def enroll_totp(user: User) -> dict:
    """Make a secret and the QR to go with it.

    Nothing is saved yet.  The secret only sticks once they prove they can
    read a code off it, so a half finished setup cannot lock anyone out.
    """
    import segno

    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.username, issuer_name=TOTP_ISSUER)

    # Black on white, spelled out in hex.  segno only takes real colors, and a
    # QR wants proper contrast anyway: a transparent one that inherits a dark
    # page background is one no phone can read.
    # Black on white, spelled out in hex.  segno only takes real colors, and a
    # QR wants proper contrast anyway: a transparent one that inherits a dark
    # page background is one no phone can read.  It writes bytes, so the
    # buffer has to be one that takes bytes.
    buffer = io.BytesIO()
    segno.make(uri, error="m").save(buffer, kind="svg", scale=4, border=2,
                                    dark="#000000", light="#ffffff",
                                    xmldecl=False, svgversion=None)
    return {"secret": secret, "uri": uri,
            "qr_svg": buffer.getvalue().decode("utf-8")}


def check_totp(user: User, code: str) -> bool:
    """Check a six digit code, or one of the recovery codes."""
    code = (code or "").strip().replace(" ", "").replace("-", "")
    if not code:
        return False

    if user.totp_secret and len(code) == 6 and code.isdigit():
        # One step either side, so a slightly wrong clock still works.
        if pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
            return True

    return _consume_recovery_code(user, code)


def make_recovery_codes() -> tuple:
    """Ten one time codes, and the hashes we keep.

    The plain codes are shown once and never stored.
    """
    plain = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(5)
        plain.append(f"{raw[:5]}-{raw[5:]}")
    hashes = [hashlib.sha256(c.encode()).hexdigest() for c in plain]
    return plain, hashes


def _consume_recovery_code(user: User, code: str) -> bool:
    """Burn a recovery code if it matches.  Each one works exactly once."""
    try:
        stored = json.loads(user.recovery_hashes or "[]")
    except (ValueError, TypeError):
        return False
    if not stored:
        return False

    candidate = hashlib.sha256(code.encode()).hexdigest()
    for held in list(stored):
        if hmac.compare_digest(held, candidate):
            stored.remove(held)
            user.recovery_hashes = json.dumps(stored)
            return True
    return False


def save_totp(user: User, secret: str, recovery_hashes: list) -> None:
    user.totp_secret = secret
    user.totp_confirmed = True
    user.recovery_hashes = json.dumps(recovery_hashes)


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------
@dataclass
class AuthResult:
    ok: bool = False
    user: User = None
    reason: str = ""
    needs_totp: bool = False
    needs_totp_setup: bool = False
    must_change_password: bool = False


def _locked(user: User) -> bool:
    if not user.locked_until:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def authenticate_local(session, username: str, password: str,
                       source_ip: str = "") -> AuthResult:
    """Check a username and password.

    The answer to a bad username and a bad password is the same sentence on
    purpose.  Telling somebody which half they got right is telling them half
    the answer.
    """
    generic = "That username and password do not match."

    user = (session.query(User)
            .filter(User.username == (username or "").strip().lower())
            .one_or_none())

    if user is None:
        # Spend roughly the same time as a real check so the timing does not
        # answer the question either.
        _hasher.hash("timing" + secrets.token_hex(8))
        record(session, "login.failed", actor=username, source_ip=source_ip,
               detail="no such user", outcome="denied")
        return AuthResult(reason=generic)

    if user.disabled:
        record(session, "login.failed", actor=user.username, source_ip=source_ip,
               detail="account disabled", outcome="denied")
        return AuthResult(reason="That account is turned off.")

    if user.source != AuthSource.LOCAL:
        return AuthResult(reason="That account signs in through your identity provider.")

    if _locked(user):
        record(session, "login.failed", actor=user.username, source_ip=source_ip,
               detail="locked out", outcome="denied")
        return AuthResult(
            reason="Too many tries. Wait a few minutes and try again.")

    if not verify_password(user.password_hash, password):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= live.login_attempt_limit():
            user.locked_until = utcnow() + timedelta(
                minutes=live.login_lockout_minutes())
            user.failed_logins = 0
            record(session, "login.lockout", actor=user.username,
                   source_ip=source_ip, outcome="denied")
        else:
            record(session, "login.failed", actor=user.username,
                   source_ip=source_ip, detail="wrong password", outcome="denied")
        return AuthResult(reason=generic)

    user.failed_logins = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    return AuthResult(
        ok=True,
        user=user,
        needs_totp=bool(user.totp_confirmed),
        needs_totp_setup=not user.totp_confirmed,
        must_change_password=bool(user.must_change_password),
    )


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(session, user: User, source_ip: str = "",
                   user_agent: str = "", half_auth: bool = False) -> str:
    """Start a session and hand back the token.

    We keep the hash, never the token.  Somebody who reads the database still
    cannot sign in as anybody.
    """
    token = secrets.token_urlsafe(48)
    lifetime = timedelta(minutes=5) if half_auth else timedelta(
        hours=live.session_hours())

    session.add(Session(
        token_hash=_token_hash(token),
        user_id=user.id,
        half_auth=half_auth,
        source_ip=(source_ip or "")[:64],
        user_agent=(user_agent or "")[:255],
        expires_at=utcnow() + lifetime,
    ))
    session.flush()
    return token


def promote_session(session, token: str) -> bool:
    """Turn a half session into a real one, once TOTP checks out."""
    row = (session.query(Session)
           .filter(Session.token_hash == _token_hash(token))
           .one_or_none())
    if row is None or row.revoked_at:
        return False
    row.half_auth = False
    row.expires_at = utcnow() + timedelta(hours=live.session_hours())
    row.last_seen_at = utcnow()
    return True


def current_session(session, token: str, source_ip: str = ""):
    """Look up a session and keep it alive, or return None.

    Expired, revoked, or idle too long all give the same answer: nothing.
    """
    if not token:
        return None

    row = (session.query(Session)
           .filter(Session.token_hash == _token_hash(token))
           .one_or_none())
    if row is None or row.revoked_at:
        return None

    now = datetime.now(timezone.utc)
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= now:
        return None

    last_seen = row.last_seen_at or row.created_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    if live.idle_minutes() > 0:
        if last_seen + timedelta(minutes=live.idle_minutes()) <= now:
            row.revoked_at = utcnow()
            row.revoked_reason = "idle too long"
            return None

    row.last_seen_at = utcnow()
    return row


def revoke_session(session, token: str, reason: str = "signed out") -> None:
    row = (session.query(Session)
           .filter(Session.token_hash == _token_hash(token))
           .one_or_none())
    if row is not None and not row.revoked_at:
        row.revoked_at = utcnow()
        row.revoked_reason = reason[:255]


def revoke_all_for_user(session, user_id: int, reason: str) -> int:
    rows = (session.query(Session)
            .filter(Session.user_id == user_id, Session.revoked_at.is_(None))
            .all())
    for row in rows:
        row.revoked_at = utcnow()
        row.revoked_reason = reason[:255]
    return len(rows)


def cleanup_expired(session) -> int:
    """Drop sessions nobody can use any more.  Called from the scheduler."""
    cutoff = utcnow() - timedelta(days=7)
    rows = (session.query(Session)
            .filter(Session.expires_at < cutoff)
            .all())
    for row in rows:
        session.delete(row)
    return len(rows)


# ---------------------------------------------------------------------------
# The first admin
# ---------------------------------------------------------------------------
def ensure_bootstrap_admin(session) -> dict:
    """Make an admin on first boot, once.

    The password is printed to the log and never stored anywhere else.  They
    have to change it and set up TOTP before the app lets them do anything.
    """
    if not live.auth_config().local_enabled:
        return {}
    if session.query(User).filter(User.role == UserRole.ADMIN).count() > 0:
        return {}

    password = base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip("=")
    admin = User(
        username="admin",
        display_name="Administrator",
        role=UserRole.ADMIN,
        source=AuthSource.LOCAL,
        password_hash=hash_password(password),
        must_change_password=True,
    )
    session.add(admin)
    session.flush()
    record(session, "user.created", actor="system", target="admin",
           detail="first admin created at startup")

    # Drop it in a file too.  Grepping the log for it is fragile, and the
    # installer needs something it can rely on.  Mode 600, and the app deletes
    # it the moment that account changes its password.
    try:
        path = settings.data_dir / "first-admin.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "Git Code Review, first administrator\n"
            "\n"
            f"  username: admin\n"
            f"  password: {password}\n"
            "\n"
            "Change it at first sign in.  This file is removed automatically\n"
            "once that account has a new password.\n",
            encoding="utf-8")
        path.chmod(0o600)
    except OSError as exc:
        log.warning("could not write the first admin file: %s", exc)

    return {"username": "admin", "password": password}


def clear_bootstrap_file() -> None:
    """Remove the first admin file.  Called once that account is set up."""
    try:
        (settings.data_dir / "first-admin.txt").unlink()
    except OSError:
        pass
