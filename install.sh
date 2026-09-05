#!/usr/bin/env bash
# Git Code Review, installer.
#
# Asks a handful of questions, writes .env, builds the image and starts it.
# Safe to run again later.  It reads your existing .env and offers what is
# already there as the default.
#
# If you have not cloned the project yet, this does the whole thing:
#
#   curl -fsSL https://git.failoverlb.net/github-code-review/-/raw/master/get-gcr.sh | bash
#
# Author: Tim Rice <tim.j.rice@hackrange.com>
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

ENV_FILE="$HERE/.env"
REPORTS_DEFAULT="$HERE/out"
WORK_DEFAULT="$HERE/work"

c_head=$'\033[1;34m'; c_ok=$'\033[32m'; c_warn=$'\033[33m'
c_err=$'\033[31m';  c_dim=$'\033[2m';  c_off=$'\033[0m'
[[ -t 1 ]] || { c_head=; c_ok=; c_warn=; c_err=; c_dim=; c_off=; }

say()  { printf '%s==>%s %s\n' "$c_head" "$c_off" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%s  !!%s %s\n' "$c_warn" "$c_off" "$*" >&2; }
die()  { printf '%s  xx%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }
hint() { printf '%s     %s%s\n' "$c_dim" "$*" "$c_off"; }

# ask <variable> <question> <default>
# Asking, when stdin is not a person.
#
# Piped into bash, stdin holds the rest of this script.  A plain read gets EOF
# straight away, every answer comes back empty, and the install falls over on
# the first one that mattered with "cannot create directory ''".  That is
# exactly how the one line install failed.
#
# So questions go to the terminal, and if there is no terminal the defaults are
# taken and said out loud.  Set GCR_ASSUME_DEFAULTS=1 to take them anyway.
# Try to open it rather than test that it exists.  /dev/tty is there in every
# container and on every cron run, and opening it fails with "no such device"
# when nothing is attached, which is not something a test for the file catches.
TTY_IN=""
if { : > /dev/tty; } 2>/dev/null; then
  TTY_IN=/dev/tty
fi
[[ "${GCR_ASSUME_DEFAULTS:-0}" == "1" ]] && TTY_IN=""

ask() {
  local var="$1" question="$2" default="${3:-}" answer=""
  if [[ -z "$TTY_IN" ]]; then
    answer="$default"
    printf '     %s: %s%s\n' "$question" "${answer:-(none)}" \
           "$([[ -n "$default" ]] && echo ' (default)')"
    printf -v "$var" '%s' "$answer"
    return 0
  fi
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$question" "$default" > "$TTY_IN"
    read -r answer < "$TTY_IN" || true
    answer="${answer:-$default}"
  else
    printf '%s: ' "$question" > "$TTY_IN"
    read -r answer < "$TTY_IN" || true
  fi
  printf -v "$var" '%s' "$answer"
}

random_secret() {
  local length="${1:-32}"
  openssl rand -base64 48 2>/dev/null | tr -d '\n=+/' | cut -c "1-$length" \
    || head -c 64 /dev/urandom | base64 | tr -d '\n=+/' | cut -c "1-$length"
}

ask_secret() {
  local var="$1" question="$2" answer=""
  if [[ -z "$TTY_IN" ]]; then
    # Nothing to type into, so nothing is set and whatever depends on it
    # generates its own.  Silence beats a blank password.
    printf -v "$var" '%s' ""
    return 0
  fi
  printf '%s: ' "$question" > "$TTY_IN"
  read -r -s answer < "$TTY_IN" || true
  printf '\n' > "$TTY_IN"
  printf -v "$var" '%s' "$answer"
}

ask_yes() {
  local question="$1" default="${2:-y}" answer=""
  if [[ -z "$TTY_IN" ]]; then
    printf '     %s: %s (default)\n' "$question" "$default"
    [[ "${default,,}" == y* ]]
    return
  fi
  printf '%s [%s]: ' "$question" "$default" > "$TTY_IN"
  read -r answer < "$TTY_IN" || true
  answer="${answer:-$default}"
  [[ "${answer,,}" == y* ]]
}

# Pull a value out of the existing .env so re-running keeps your answers.
existing() {
  # Fails when it finds nothing, so `existing X || echo a-default` works.
  #
  # It used to return 0 with no output, which meant the || never fired and
  # every default was the empty string.  Nothing noticed until an answer that
  # had to be a path came out empty and mkdir was handed ''.
  local value=""
  [[ -f "$ENV_FILE" ]] && value=$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -1)
  [[ -n "$value" ]] || return 1
  printf '%s' "$value"
}

# ensure_container_dir <path>
# A directory the container writes to, owned by the user the container runs as.
#
# out/ and work/ are gitignored, so a fresh checkout has neither.  Whichever
# one this does not create first, docker creates as a bind mount source owned
# by root, and uid 10001 inside gets permission denied the moment it tries to
# write: reports that never appear, or every scan dying on
# /var/tmp/gcr-work/gcr-scan-XXXXXX.
ensure_container_dir() {
  local path="$1"
  mkdir -p "$path" || die "cannot create $path"
  # The container runs as uid 10001 and has to write here.
  chown -R 10001:10001 "$path" 2>/dev/null || \
    warn "could not chown $path to uid 10001, the container may not be able to write"
}

UPGRADE=0
while (( $# )); do
  case "$1" in
    --upgrade|-u) UPGRADE=1; shift ;;
    -h|--help)
      cat <<'__USAGE__'
install.sh - set Git Code Review up, or bring it up to date.

  install.sh              first time.  Asks where it listens, which database,
                          where the reports go, then builds and starts it.
  install.sh --upgrade    already installed.  Pulls the latest, rebuilds and
                          restarts.  Asks nothing and changes no settings.

Everything you answered the first time lives in .env and is left alone either
way, so an upgrade cannot quietly move your database or your reports.
__USAGE__
      exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

# -----------------------------------------------------------------------------
say "Checking what is already here"
command -v docker >/dev/null 2>&1 || die "docker is not installed"
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  die "docker compose is not available"
fi
docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon, are you in the docker group"
ok "docker and compose look fine"

echo
if (( UPGRADE )); then
  say "Git Code Review 1.0.1 upgrade"
  [[ -f "$ENV_FILE" ]] || die "no .env here, so there is nothing to upgrade.  Run install.sh without --upgrade"

  # The code first, and only if this is a checkout.  Somebody who unpacked a
  # tarball still gets the rebuild, which is the part that matters.
  if [[ -d "$HERE/.git" ]]; then
    say "Pulling the latest"
    branch=$(git -C "$HERE" rev-parse --abbrev-ref HEAD 2>/dev/null || echo master)
    if ! git -C "$HERE" diff --quiet 2>/dev/null; then
      warn "there are local changes here, so nothing is being pulled"
      hint "Commit or stash them, then run this again"
    else
      git -C "$HERE" fetch --quiet origin "$branch" || die "could not fetch"
      git -C "$HERE" pull --quiet --ff-only origin "$branch" \
        || die "could not fast forward.  Sort the checkout out, then run this again"
      ok "now at $(git -C "$HERE" log -1 --format='%h %s' | cut -c1-60)"
    fi
  else
    warn "not a git checkout, so only the rebuild is happening"
  fi

  # .env is never touched.  Anything new in .env.example is reported rather
  # than merged, because guessing at somebody's settings is how an upgrade
  # moves their database.
  if [[ -f "$HERE/.env.example" ]]; then
    missing=""
    while IFS= read -r key; do
      [[ -n "$key" ]] || continue
      grep -q "^${key}=" "$ENV_FILE" 2>/dev/null || missing="$missing $key"
    done < <(grep -oE '^[A-Z_]+=' "$HERE/.env.example" 2>/dev/null | tr -d '=')
    if [[ -n "$missing" ]]; then
      warn "new settings exist that your .env does not have:$missing"
      hint "They fall back to their defaults.  Add them to $ENV_FILE if you want to set them."
    fi
  fi

  BIND="$(existing GCR_BIND_ADDRESS || echo 127.0.0.1)"
  PORT="$(existing GCR_PORT || echo 8080)"
  REPORTS="$(existing GCR_OUT_PATH || echo "$REPORTS_DEFAULT")"
  WORK="$(existing GCR_WORK_PATH || echo "$WORK_DEFAULT")"
  DB_PROFILE="$(existing COMPOSE_PROFILES || echo bundled-db)"

  # Not a settings change.  An install from before these were made here has a
  # root owned work directory that docker created, and every scan on it fails.
  ensure_container_dir "$REPORTS"
  ensure_container_dir "$WORK"
  export COMPOSE_PROFILES="$DB_PROFILE"

  say "Rebuilding"
  "${COMPOSE[@]}" build || die "build failed"
  ok "image built"

  say "Restarting"
  # up -d recreates only what changed, so the database container is left
  # alone unless its own definition moved.
  "${COMPOSE[@]}" up -d || die "could not start the container"

  say "Waiting for it to come up"
  up=0
  for _ in $(seq 1 60); do
    curl -fsS "http://${BIND}:${PORT}/healthz" >/dev/null 2>&1 && { up=1; break; }
    sleep 2
  done
  if (( up )); then
    ok "it is up"
  else
    warn "it did not answer in two minutes.  Check: ${COMPOSE[*]} logs"
  fi

  echo
  ok "Upgraded.  Running at http://${BIND}:${PORT}"
  hint "New columns were added on boot, and any that had outgrown their size"
  hint "were widened.  There is nothing to run by hand."
  hint "Logs: ${COMPOSE[*]} logs -f"
  echo
  exit 0
fi

say "Git Code Review 1.0.1 setup"
hint "Press enter to take the default in brackets."
echo

# -----------------------------------------------------------------------------
say "Where it listens"
ask BIND "Bind address, loopback is safest behind a proxy" "$(existing GCR_BIND_ADDRESS || echo 127.0.0.1)"
ask PORT "Port" "$(existing GCR_PORT || echo 8080)"

echo
say "The database"
hint "Everything lives here: the settings, the findings, the users, the"
hint "exclusions.  The GitHub token is encrypted before it goes in."
if ask_yes "Run MariaDB in a container next to the app" "y"; then
  DB_PROFILE="bundled-db"
  DB_HOST="mariadb"
  DB_PORT="3306"
  DB_NAME="$(existing GCR_DB_NAME || echo gcr)"
  DB_USER="$(existing GCR_DB_USER || echo gcr)"
  DB_PASSWORD="$(existing GCR_DB_PASSWORD || true)"
  DB_ROOT_PASSWORD="$(existing GCR_DB_ROOT_PASSWORD || true)"
  [[ -n "$DB_PASSWORD" ]]      || DB_PASSWORD="$(random_secret 24)"
  [[ -n "$DB_ROOT_PASSWORD" ]] || DB_ROOT_PASSWORD="$(random_secret 24)"

  # Encrypted at rest.  The key of record is in .env, and the keyfile MariaDB
  # reads is written from it, so there is one place to back up.
  DB_ENC_KEY="$(existing GCR_DB_ENCRYPTION_KEY || true)"
  [[ -n "$DB_ENC_KEY" ]] || DB_ENC_KEY="$(openssl rand -hex 32)"
  mkdir -p "$HERE/secrets"
  chmod 700 "$HERE/secrets"
  printf '1;%s\n' "$DB_ENC_KEY" > "$HERE/secrets/mariadb-keyfile"
  chmod 640 "$HERE/secrets/mariadb-keyfile"
  # MariaDB in the official image runs as uid 999 and has to read it.
  chown 0:999 "$HERE/secrets/mariadb-keyfile" 2>/dev/null || \
    chmod 644 "$HERE/secrets/mariadb-keyfile"
  ok "MariaDB will run as gcr-mariadb, encrypted at rest, passwords generated"
else
  DB_PROFILE=""
  hint "Point it at a MariaDB you already have.  Create the database and a user"
  hint "with rights on it first:"
  hint "  CREATE DATABASE gcr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  hint "  GRANT ALL ON gcr.* TO 'gcr'@'%' IDENTIFIED BY '...';"
  ask DB_HOST "Database host" "$(existing GCR_DB_HOST || echo db.example.com)"
  ask DB_PORT "Port"          "$(existing GCR_DB_PORT || echo 3306)"
  ask DB_NAME "Database name" "$(existing GCR_DB_NAME || echo gcr)"
  ask DB_USER "Username"      "$(existing GCR_DB_USER || echo gcr)"
  ask_secret DB_PASSWORD "Password"
  [[ -n "$DB_PASSWORD" ]] || DB_PASSWORD="$(existing GCR_DB_PASSWORD || true)"
  DB_ROOT_PASSWORD=""
  DB_ENC_KEY=""
  [[ -n "$DB_PASSWORD" ]] || die "the database password is required"
  hint "Encryption at rest is up to that server.  See its documentation for"
  hint "file_key_management and innodb_encrypt_tables."
fi

echo
say "Where the reports go"
hint "vulnerabilities.json and vulnerabilities.csv land here.  Whatever ingests"
hint "them reads straight off the host, so this path is a contract."
ask REPORTS "Reports directory" "$(existing GCR_OUT_PATH || echo "$REPORTS_DEFAULT")"
ensure_container_dir "$REPORTS"
ok "reports directory ready at $REPORTS"

echo
say "Where the clones go while a scan runs"
hint "Repositories are cloned here and deleted again as the scan moves on, and"
hint "nothing is kept between runs.  It wants real disk rather than a RAM disk:"
hint "a full history scan of a large estate is tens of gigabytes in flight."
ask WORK "Working directory" "$(existing GCR_WORK_PATH || echo "$WORK_DEFAULT")"
ensure_container_dir "$WORK"
ok "working directory ready at $WORK"

echo
hint "Everything else is set on the Settings page once you sign in: how people"
hint "sign in, the identity provider, what to scan, the GitHub token, and the"
hint "exclusions.  None of it goes in a file."

# -----------------------------------------------------------------------------
echo
say "Writing .env"
SECRET_KEY="$(existing GCR_SECRET_KEY || true)"
[[ -n "$SECRET_KEY" ]] || SECRET_KEY="$(random_secret 48)"
ENCRYPTION_KEY="$(existing GCR_ENCRYPTION_KEY || true)"
[[ -n "$ENCRYPTION_KEY" ]] || ENCRYPTION_KEY="$(random_secret 48)"

umask 077
cat > "$ENV_FILE" <<ENVEOF
# Written by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# This file holds secrets.  It is gitignored, keep it that way.
#
# Only what the container needs before anybody can sign in is here.  The rest
# is on the Settings page and lives in the database.

GCR_VERSION=1.0.1
GCR_BIND_ADDRESS=$BIND
GCR_PORT=$PORT

# The database.  Take COMPOSE_PROFILES out to stop the bundled MariaDB and
# point GCR_DB_HOST at your own.
COMPOSE_PROFILES=$DB_PROFILE
GCR_DB_HOST=$DB_HOST
GCR_DB_PORT=$DB_PORT
GCR_DB_NAME=$DB_NAME
GCR_DB_USER=$DB_USER
GCR_DB_PASSWORD=$DB_PASSWORD
GCR_DB_ROOT_PASSWORD=$DB_ROOT_PASSWORD
GCR_DATABASE_URL=

# The database is encrypted at rest with this.  secrets/mariadb-keyfile is
# written from it.  Back it up: without it the data files are unreadable.
GCR_DB_ENCRYPTION_KEY=$DB_ENC_KEY
GCR_DB_KEYFILE=./secrets/mariadb-keyfile

# Signs sessions, and encrypts the GitHub token and the client secret in the
# database.  Keep it.  Losing it means pasting those back in.
GCR_SECRET_KEY=$SECRET_KEY

# Encrypts the GitHub token, the App private key and the OIDC client secret in
# the database.  Lose it and those have to be pasted in again.
GCR_ENCRYPTION_KEY=$ENCRYPTION_KEY

# Only used before the first sign in.  After that the Settings page owns them.
GCR_AUTH_MODE=local
GCR_TRUSTED_PROXIES=
GCR_FORCE_HTTPS=true

GCR_OUT_PATH=$REPORTS

# Where repositories are cloned while a scan runs.  Wants real disk.  Nothing
# is kept here between runs.
GCR_WORK_PATH=$WORK
TZ=$(cat /etc/timezone 2>/dev/null || echo UTC)
ENVEOF
chmod 600 "$ENV_FILE"
ok "wrote $ENV_FILE"

# -----------------------------------------------------------------------------
echo
say "Building the image, this pulls the scanners so give it a few minutes"
"${COMPOSE[@]}" build || die "build failed"
ok "image built"

say "Starting it"
"${COMPOSE[@]}" up -d || die "could not start the container"

# Wait for the health check rather than guessing.
say "Waiting for it to come up"
up=0
for _ in $(seq 1 60); do
  if curl -fsS "http://${BIND}:${PORT}/healthz" >/dev/null 2>&1; then
    up=1; break
  fi
  sleep 2
done
if (( up )); then
  ok "it is up"
else
  warn "it did not answer in two minutes.  Check: ${COMPOSE[*]} logs"
fi

# -----------------------------------------------------------------------------
# The starting password.
#
# The app writes it to a file inside the db volume on first boot, so we read it
# from there rather than grepping the log and hoping.
# -----------------------------------------------------------------------------
show_first_admin() {
  local raw=""
  for _ in $(seq 1 10); do
    raw=$("${COMPOSE[@]}" exec -T github-code-review \
            cat /data/first-admin.txt 2>/dev/null || true)
    [[ -n "$raw" ]] && break
    sleep 1
  done
  [[ -n "$raw" ]] || return 1

  local username password
  username=$(sed -n 's/^ *username: *//p' <<< "$raw" | head -1)
  password=$(sed -n 's/^ *password: *//p' <<< "$raw" | head -1)
  [[ -n "$username" && -n "$password" ]] || return 1

  echo
  printf '%s' "$c_head"
  cat <<'BOX'
  +--------------------------------------------------------------+
  |  SIGN IN WITH THIS                                           |
  +--------------------------------------------------------------+
BOX
  printf '%s' "$c_off"
  printf '     username:  %s%s%s\n' "$c_ok" "$username" "$c_off"
  printf '     password:  %s%s%s\n' "$c_ok" "$password" "$c_off"
  printf '%s  +--------------------------------------------------------------+%s\n' \
         "$c_head" "$c_off"
  echo
  hint "You have to change this and set up two step on the first sign in."
  hint "This is the only place it is written down, and the app deletes it"
  hint "once that account is set up."
  return 0
}

echo
say "First sign in"
if ! show_first_admin; then
  warn "could not read the starting password from the container"
  hint "Try: ${COMPOSE[*]} exec github-code-review cat /data/first-admin.txt"
  hint "Or:  ${COMPOSE[*]} logs | grep -A3 'FIRST ADMIN'"
fi

echo
ok "Git Code Review is running at http://${BIND}:${PORT}"
echo
hint "Reports:  $REPORTS/vulnerabilities.json"
hint "          $REPORTS/vulnerabilities.csv"
hint "Next:     sign in, then open Settings and add your GitHub token and"
hint "          the organizations to scan.  Nothing scans until you do."
hint "Docs:     $HERE/documentation/"
hint "Logs:     ${COMPOSE[*]} logs -f"
echo
if [[ "$BIND" != "127.0.0.1" && "$BIND" != "localhost" ]]; then
  warn "It is listening on $BIND in plain HTTP."
  hint "Put a reverse proxy with TLS in front of it before anybody else uses it."
else
  hint "It is on loopback only.  Put a reverse proxy with TLS in front of it to"
  hint "let anybody else reach it."
fi
echo
