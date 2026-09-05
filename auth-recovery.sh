#!/usr/bin/env bash
#
# The way back in when nobody can sign in any more.
#
# There are a few ways to get locked out of this thing.  Sign in can be set so
# local passwords are refused, and then the identity provider goes down, or its
# certificate expires, or somebody deletes the application registration.  Or
# the one admin who set it up loses the phone with the authenticator on it.  Or
# five bad passwords lock the only account there is.
#
# This is the door that does not depend on any of that.  It talks to the
# database through the running container, which means it needs a shell on the
# box.  That is the point: if you can get to a root shell here you are already
# trusted more than any login page could check.
#
#   ./auth-recovery.sh                     say how sign in is set and who can use it
#   ./auth-recovery.sh --allow-local       local accounts or the provider, both work
#   ./auth-recovery.sh --local-only        local accounts only, provider ignored
#   ./auth-recovery.sh --reset-password USER   new password, printed once
#   ./auth-recovery.sh --reset-totp USER   clear two step so they enroll again
#   ./auth-recovery.sh --unlock USER       clear a lockout and the failed count
#   ./auth-recovery.sh --insecure-cookies  stop marking cookies secure
#
# That last one is for a specific way of getting stuck.  Behind TLS is on by
# default, which marks session cookies secure, and a browser will not send a
# secure cookie over plain HTTP.  Turn it on while you are still reaching the
# app over HTTP and the login page keeps taking your password and sending you
# straight back to itself, with nothing in the log to explain why.
#
# Everything it does is written to the audit log.  A recovery script that
# leaves no trace is one nobody can tell apart from somebody changing the locks.
set -euo pipefail

CONTAINER="${GCR_CONTAINER:-github-code-review}"
PYTHON="/opt/gcr/venv/bin/python"

fail() { printf '\n  %s\n\n' "$*" >&2; exit 1; }

usage() {
    sed -n '3,33p' "$0" | sed 's/^#\s\?//'
    exit "${1:-0}"
}

MODE=""; ACTION=""; WHO=""
while [ $# -gt 0 ]; do
    case "$1" in
        --allow-local)    ACTION="mode"; MODE="both" ;;
        --local-only)     ACTION="mode"; MODE="local" ;;
        --reset-password) ACTION="password"; WHO="${2:-}"; shift ;;
        --reset-totp)     ACTION="totp";     WHO="${2:-}"; shift ;;
        --unlock)         ACTION="unlock";   WHO="${2:-}"; shift ;;
        --insecure-cookies) ACTION="cookies" ;;
        -h|--help)        usage 0 ;;
        *)                printf '\n  %s is not an option this script has.\n' "$1" >&2
                          usage 1 ;;
    esac
    shift
done

if [ -n "$ACTION" ] && [ "$ACTION" != "mode" ] && [ -z "$WHO" ]; then
    fail "which account?  For example: ./auth-recovery.sh $1 admin"
fi

command -v docker >/dev/null 2>&1 || fail "docker is not on the path, so this
  cannot reach the app.  If the container runs under a different name, set
  GCR_CONTAINER first."

if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    fail "the $CONTAINER container is not running, so there is nothing to talk
  to.  Start it with 'docker compose up -d' from the install directory and run
  this again.  If the container is the thing that will not start, this is not
  your problem: look at 'docker compose logs'."
fi

printf '\n'

# Everything below runs inside the container, because that is where the
# database, the settings and the encryption key all are.  Going through
# settings_store and the auth service rather than straight into the tables
# means values are written exactly the way the app writes them, which is the
# difference between a fix and a second bug.

if [ -z "$ACTION" ]; then
    docker exec -i "$CONTAINER" "$PYTHON" - <<'PY'
from app.core import live
from app.core.db import session_scope
from app.core.models import AuthSource, User, UserRole

mode = live.auth_config().mode
words = {
    "local": "local accounts only.  The provider is not offered.",
    "both":  "local accounts or the provider.  Both work.",
    "oidc":  "the provider only.  Local passwords are refused.",
}
print(f"  Sign in is set to: {mode}")
print(f"  Which means: {words.get(mode, 'something unrecognized, which reads as local')}")

with session_scope() as s:
    admins = s.query(User).filter(
        User.role == UserRole.ADMIN, User.disabled.is_(False),
        User.source == AuthSource.LOCAL).all()
    rows = [(u.username, bool(u.password_hash), u.totp_confirmed,
             u.locked_until is not None) for u in admins]

print()
if rows:
    print("  Admins with a local account:")
    for name, has_password, has_totp, locked in sorted(rows):
        bits = []
        bits.append("password set" if has_password else "NO PASSWORD")
        bits.append("two step set up" if has_totp else "two step NOT set up")
        if locked:
            bits.append("LOCKED")
        print(f"    {name}: {', '.join(bits)}")
else:
    print("  No enabled admin has a local account.  Turning local sign in back")
    print("  on will not help on its own, somebody has to be able to use it.")

if mode == "oidc":
    print()
    print("  To put local passwords back:  ./auth-recovery.sh --allow-local")
PY
    printf '\n'
    exit 0
fi

if [ "$ACTION" = "cookies" ]; then
    docker exec -i "$CONTAINER" "$PYTHON" - <<'PYEOF'
from app.core import live
from app.core.audit import record
from app.core.db import session_scope
from app.core import settings_store as store

with session_scope() as s:
    store.set_value(s, "security.force_https", False, "auth-recovery.sh")
    record(s, "settings.saved", actor="auth-recovery.sh", source_ip="console",
           detail="secure cookies turned off from the console")

live.invalidate()
print("  Cookies are no longer marked secure, so sign in works over plain HTTP.")
print("  It applies to the next sign in.  Nothing needs restarting.")
print()
print("  Put it back from Settings once TLS is in front of this, and check the")
print("  proxy sends X-Forwarded-Proto: https when you do.")
PYEOF
    printf '\n'
    exit 0
fi

if [ "$ACTION" = "mode" ]; then
    docker exec -i "$CONTAINER" "$PYTHON" - "$MODE" <<'PY'
import sys

from app.core import live
from app.core.audit import record
from app.core.db import session_scope
from app.core import settings_store as store
from app.core.models import AuthSource, User, UserRole

wanted = sys.argv[1]
before = live.auth_config().mode

if before == wanted:
    print(f"  Sign in is already set to {wanted}.  Nothing to change.")
    raise SystemExit(0)

with session_scope() as s:
    store.set_value(s, "auth.mode", wanted, "auth-recovery.sh")
    record(s, "settings.saved", actor="auth-recovery.sh", source_ip="console",
           detail=f"sign in changed from {before} to {wanted} from the console")
    names = sorted(u.username for u in s.query(User).filter(
        User.role == UserRole.ADMIN, User.disabled.is_(False),
        User.source == AuthSource.LOCAL).all())

live.invalidate()
print(f"  Sign in changed from {before} to {wanted}.")
print("  It applies to the next sign in.  Nothing needs restarting.")
print()
if names:
    print(f"  Sign in with one of these and a password: {', '.join(names)}")
    print("  A second factor is still required, as it always was.")
else:
    print("  Careful: no enabled admin has a local password, so the login page")
    print("  will take a username and still refuse everybody.  Fix an account")
    print("  with --reset-password before this helps.")
PY
    printf '\n  Put it back from Settings once the provider is answering again.\n\n'
    exit 0
fi

docker exec -i "$CONTAINER" "$PYTHON" - "$ACTION" "$WHO" <<'PY'
import secrets
import string
import sys

from app.auth.service import hash_password, revoke_all_for_user
from app.core.audit import record
from app.core.db import session_scope
from app.core.models import AuthSource, User

action, who = sys.argv[1], sys.argv[2]

# Long enough that it does not matter that it goes on a terminal, and made of
# characters somebody can read off a screen and type without a second attempt.
alphabet = string.ascii_letters + string.digits
new_password = "".join(secrets.choice(alphabet) for _ in range(20))

with session_scope() as s:
    user = s.query(User).filter(User.username == who).one_or_none()
    if user is None:
        print(f"  There is no account called {who}.")
        raise SystemExit(1)

    if action == "password":
        if user.source != AuthSource.LOCAL:
            print(f"  {who} signs in through the provider, so there is no local")
            print("  password to reset.  Fix it there instead.")
            raise SystemExit(1)
        user.password_hash = hash_password(new_password)
        user.must_change_password = True
        user.failed_logins = 0
        user.locked_until = None
        # Anything already signed in as them goes.  A password reset that
        # leaves old sessions alive is not a reset.
        revoke_all_for_user(s, user.id, "password reset from the console")
        record(s, "user.password_reset", actor="auth-recovery.sh", target=who,
               source_ip="console", detail="reset from the console")
        print(f"  New password for {who}:")
        print()
        print(f"      {new_password}")
        print()
        print("  They have to change it at the next sign in, and two step is")
        print("  still required.  This is the only time it is shown.")

    elif action == "totp":
        user.totp_secret = ""
        user.totp_confirmed = False
        user.recovery_hashes = ""
        user.failed_logins = 0
        user.locked_until = None
        revoke_all_for_user(s, user.id, "two step reset from the console")
        record(s, "user.totp_reset", actor="auth-recovery.sh", target=who,
               source_ip="console", detail="reset from the console")
        print(f"  Two step is cleared for {who}.")
        print("  The next sign in with their password walks them through")
        print("  enrolling again, and prints a new set of recovery codes.")

    elif action == "unlock":
        was_locked = user.locked_until is not None or user.failed_logins
        user.failed_logins = 0
        user.locked_until = None
        record(s, "user.unlocked", actor="auth-recovery.sh", target=who,
               source_ip="console")
        if was_locked:
            print(f"  {who} is unlocked and the failed count is back to zero.")
        else:
            print(f"  {who} was not locked.  Nothing to do.")
PY
printf '\n'
