"""Single sign on.

Standard OpenID Connect authorization code flow with PKCE.  Works with Okta,
Entra, Keycloak, Google, anything that publishes a discovery document.

Groups decide the role.  Somebody in none of the mapped groups gets no account
at all, which is the safe way round.  A provider that suddenly stops sending
groups should lock people out rather than quietly hand everybody admin.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient

from app.config import settings
from app.core import live
from app.core.models import AuthSource, User, UserRole, utcnow

log = logging.getLogger("gcr.oidc")

# Discovery documents barely ever change, and fetching one on every login adds
# a round trip to somebody else's server before anybody can get in.
_discovery_cache = {}
_DISCOVERY_TTL = 3600

# Logins in flight.  Holds the PKCE verifier and the state between sending
# somebody off to the provider and them coming back.
_pending = {}
_PENDING_TTL = 600


class OIDCError(Exception):
    pass


def is_configured() -> bool:
    auth = live.auth_config()
    return bool(auth.oidc_enabled and auth.oidc_issuer and auth.oidc_client_id)


def _redirect_uri() -> str:
    configured = live.auth_config().oidc_redirect_url
    if configured:
        return configured
    raise OIDCError("GCR_OIDC_REDIRECT_URL is not set, so we cannot start a login")


async def get_discovery() -> dict:
    """Fetch and cache the provider's discovery document."""
    issuer = live.auth_config().oidc_issuer.rstrip("/")
    cached = _discovery_cache.get(issuer)
    if cached and time.time() - cached["at"] < _DISCOVERY_TTL:
        return cached["doc"]

    url = f"{issuer}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        raise OIDCError(f"could not reach the provider at {url}: {exc}")

    if response.status_code >= 400:
        raise OIDCError(f"the provider returned {response.status_code} for {url}")

    try:
        doc = response.json()
    except json.JSONDecodeError:
        raise OIDCError("the discovery document was not valid JSON")

    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if required not in doc:
            raise OIDCError(f"the discovery document has no {required}")

    _discovery_cache[issuer] = {"doc": doc, "at": time.time()}
    return doc


def _cleanup_pending() -> None:
    now = time.time()
    for state in [s for s, v in _pending.items()
                  if now - v["created"] > _PENDING_TTL]:
        _pending.pop(state, None)


async def begin_login(source_ip: str = "") -> str:
    """Start a login and give back the URL to send the browser to.

    Two things get made here and both matter.

    state is random and gets checked when they come back.  Without it somebody
    can hand a victim a crafted callback URL and sign them into an account the
    attacker controls, which is login CSRF.

    PKCE is the verifier and its hash.  It stops a stolen authorization code
    being any use to somebody who does not also hold the verifier.
    """
    doc = await get_discovery()

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

    _cleanup_pending()
    _pending[state] = {"verifier": verifier, "created": time.time(),
                       "source_ip": source_ip}

    params = {
        "response_type": "code",
        "client_id": live.auth_config().oidc_client_id,
        "redirect_uri": _redirect_uri(),
        "scope": live.auth_config().oidc_scopes,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{doc['authorization_endpoint']}?{urlencode(params)}"


async def complete_login(code: str, state: str, source_ip: str = "") -> dict:
    """Finish the login.  Swap the code for tokens and check the id_token."""
    pending = _pending.pop(state, None)
    if not pending:
        raise OIDCError("that sign in is not one we started, or it took too "
                        "long. Try again.")
    if time.time() - pending["created"] > _PENDING_TTL:
        raise OIDCError("that sign in took too long, start again")

    doc = await get_discovery()

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _redirect_uri(),
        "client_id": live.auth_config().oidc_client_id,
        "code_verifier": pending["verifier"],
    }
    if live.auth_config().oidc_client_secret:
        data["client_secret"] = live.auth_config().oidc_client_secret

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                doc["token_endpoint"], data=data,
                headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise OIDCError(f"could not reach the token endpoint: {exc}")

    if response.status_code >= 400:
        raise OIDCError(f"the provider refused the code: {response.text[:300]}")

    tokens = response.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise OIDCError("the provider did not send back an id_token")

    claims = _verify_id_token(id_token, doc)

    # Groups are often left out of the id_token to keep it small.  Ask the
    # userinfo endpoint when that happens.
    claim_name = live.auth_config().oidc_group_claim
    groups = claims.get(claim_name) or []
    if not groups and doc.get("userinfo_endpoint") and tokens.get("access_token"):
        groups = await _fetch_groups(doc["userinfo_endpoint"],
                                     tokens["access_token"], claim_name)

    return {
        "subject": claims.get("sub"),
        "username": (claims.get("preferred_username") or claims.get("email")
                     or claims.get("sub")),
        "email": claims.get("email", ""),
        "full_name": claims.get("name", ""),
        "groups": list(groups or []),
    }


def _verify_id_token(id_token: str, doc: dict) -> dict:
    """Check the id_token properly.

    This is the part that must not be loosened.  An id_token is only worth
    anything if the signature is checked against the provider's published keys,
    and the issuer and audience are checked too.

    Decoding it without verifying is one line shorter and means anybody can
    hand us a token they wrote themselves saying they are an admin.
    """
    try:
        jwk_client = PyJWKClient(doc["jwks_uri"], cache_keys=True, lifespan=3600)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    except Exception as exc:
        raise OIDCError(f"could not get the signing key from the provider: {exc}")

    try:
        return jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
            audience=live.auth_config().oidc_client_id,
            issuer=doc["issuer"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["exp", "iat", "iss", "aud", "sub"],
            },
            leeway=30,
        )
    except jwt.ExpiredSignatureError:
        raise OIDCError("that token has expired, sign in again")
    except jwt.InvalidAudienceError:
        raise OIDCError("that token was issued for a different application")
    except jwt.InvalidIssuerError:
        raise OIDCError("that token came from an issuer we do not trust")
    except jwt.InvalidTokenError as exc:
        raise OIDCError(f"the token did not check out: {exc}")


async def _fetch_groups(userinfo_url: str, access_token: str,
                        claim_name: str) -> list:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"})
            if response.status_code >= 400:
                return []
            return response.json().get(claim_name) or []
    except (httpx.HTTPError, json.JSONDecodeError):
        return []


def role_for_groups(groups: list) -> UserRole:
    """Map provider groups onto a role.

    Most access wins, so somebody in both the admin group and the reader group
    gets admin.  Returns None when none of their groups is mapped.  The caller
    decides what that means: a refusal, or the configured default role.
    """
    auth = live.auth_config()
    lowered = {str(g).strip().lower() for g in (groups or [])}

    def matches(configured):
        return bool(lowered & {str(g).strip().lower() for g in (configured or [])})

    if matches(auth.oidc_admin_groups):
        return UserRole.ADMIN
    if matches(auth.oidc_developer_groups):
        return UserRole.DEVELOPER
    if matches(auth.oidc_reader_groups):
        return UserRole.READER
    return None


def _default_role():
    """The role for somebody in none of the mapped groups, or None to refuse.

    Refusing is the default and is what you want when the provider sends group
    names.  Some providers will not, either because nobody can configure the
    claim or because the groups live somewhere the token cannot reach.  Setting
    a role here moves the decision to who the provider lets near the
    application at all, so it is only safe when the application is restricted
    to the right people on the provider's side.

    An unrecognized value refuses rather than guessing, because a typo here
    should not quietly hand out a role nobody chose.
    """
    configured = (live.auth_config().oidc_default_role or "").strip().lower()
    if not configured:
        return None
    try:
        return UserRole(configured)
    except ValueError:
        log.warning("oidc.default_role is set to %r, which is not a role. "
                    "Refusing the sign in instead of guessing.", configured)
        return None


def sync_user(session, profile: dict) -> User:
    """Make or update the local record for somebody who signed in.

    The provider owns the role.  Every sign in re-reads their groups, so
    somebody moved out of the admin group loses admin the next time they sign
    in rather than whenever anybody remembers.

    Unless an administrator has pinned that account, which holds the role
    where it was put and skips the group check for that one person.  Signing
    in still goes through the provider, so this hands out a role and never a
    way in.
    """
    username = (profile.get("username") or "").strip().lower()
    if not username:
        raise OIDCError("the provider did not tell us who you are")

    user = session.query(User).filter(User.username == username).one_or_none()

    if user is not None and user.source != AuthSource.OIDC:
        # A local account already owns that name.  Refusing is safer than
        # quietly turning a password account into an SSO one.
        raise OIDCError(
            f"there is already a local account called {username}. "
            "An administrator needs to sort that out.")

    # Whose account this is has to be known before the role is decided, because
    # a pinned account keeps the role it was given and the groups do not come
    # into it.  That is the whole point of pinning one: it is the way back in
    # when the provider has stopped saying who is an administrator.
    pinned = user is not None and user.role_pinned
    if pinned:
        role = user.role
    else:
        role = role_for_groups(profile.get("groups"))
        if role is None:
            role = _default_role()
        if role is None:
            raise OIDCError(
                "your account is not in any group that has access here. "
                "Ask an administrator to add you to one.")

    if user is None:
        user = User(username=username, source=AuthSource.OIDC)
        session.add(user)

    user.email = (profile.get("email") or "")[:255]
    user.display_name = (profile.get("full_name") or "")[:255]
    user.role = role
    user.disabled = False
    user.last_login_at = utcnow()
    session.flush()
    return user
