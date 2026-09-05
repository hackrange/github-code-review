#!/usr/bin/env bash
# Git Code Review, one line install.
#
#   curl -fsSL https://git.failoverlb.net/github-code-review/-/raw/master/get-gcr.sh | bash
#
# Checks the machine, offers to fetch anything missing, clones the project and
# runs install.sh.  That is the whole thing.
#
#   GCR_INSTALL_DOCKER=yes   say yes to installing Docker ahead of time
#   GCR_DIR=/srv/gcr         where the checkout goes
#   GCR_REPO / GCR_BRANCH    install from a copy somewhere else
#
# Author: Tim Rice <tim.j.rice@hackrange.com>
set -euo pipefail

# Short on purpose.  The server puts the full path back together, so this
# reaches the project without spelling out the account that owns it.  Set
# GCR_REPO if you are installing from a copy somewhere else.
REPO="${GCR_REPO:-https://git.failoverlb.net/github-code-review.git}"
INSTALL_URL="https://git.failoverlb.net/github-code-review/-/raw/master/get-gcr.sh"
# The code goes here.  The reports and the database live in volumes, so this
# directory is only the checkout and you can move it whenever you like.
DEST="${GCR_DIR:-/data/docker/github-code-review}"
BRANCH="${GCR_BRANCH:-master}"

c_head=$'\033[1;34m'; c_ok=$'\033[32m'; c_warn=$'\033[33m'
c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[[ -t 1 ]] || { c_head=; c_ok=; c_warn=; c_err=; c_dim=; c_off=; }
say()  { printf '%s==>%s %s\n' "$c_head" "$c_off" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%s  !!%s %s\n' "$c_warn" "$c_off" "$*" >&2; }
die()  { printf '%s  xx%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }
hint() { printf '%s     %s%s\n' "$c_dim" "$*" "$c_off"; }

cat <<'BANNER'

  Git Code Review
  Finds secrets, code weaknesses and vulnerable packages across every
  repository and branch in a GitHub organization.

  Needs git, Docker Engine and the docker compose plugin.  Anything missing is
  offered, never installed quietly, and Docker comes from Docker's own
  repository rather than from this distribution.

BANNER

# ---- docker ------------------------------------------------------------------
# From Docker, not from the distribution.
#
# The package a distribution calls docker is either something else entirely, on
# Debian and Ubuntu it is an old system tray applet, or it is a Docker with no
# compose plugin.  Either way the next check fails and somebody spends an hour
# on it.  Docker's own repository is the only one that ships docker-ce together
# with the compose plugin this needs.
#
# Nothing here runs without being asked.  This is a security tool, and a script
# that pipes itself into root and then installs system packages unattended is
# the shape of the thing it exists to find.  Set GCR_INSTALL_DOCKER=yes to say
# yes ahead of time, which is what an unattended build wants.

SUDO=""
if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || die "not root, and no sudo here"
  SUDO="sudo"
fi

ask() {
  # curl | bash leaves stdin holding the script, so a plain read gets the rest
  # of this file rather than an answer.  The terminal is the only honest place
  # to ask.
  local reply=""
  case "${GCR_INSTALL_DOCKER:-}" in
    yes|YES|y|1) return 0 ;;
    no|NO|n|0)   return 1 ;;
  esac
  [[ -r /dev/tty ]] || {
    warn "nothing to ask on, so nothing is being installed"
    hint "Run it again with GCR_INSTALL_DOCKER=yes to allow it"
    return 1
  }
  printf '%s  ?? %s%s [y/N] ' "$c_warn" "$c_off" "$1" > /dev/tty
  read -r reply < /dev/tty || true
  [[ "$reply" =~ ^[Yy] ]]
}

docker_distro() {
  # Which of Docker's repositories applies.  Derivatives are told apart by
  # what they are built on rather than by name, so Mint gets Ubuntu's.
  . /etc/os-release 2>/dev/null || return 1
  case "${ID:-}" in
    ubuntu|debian) echo "$ID" ;;
    linuxmint|pop|elementary|zorin) echo "ubuntu" ;;
    raspbian) echo "debian" ;;
    rhel|centos|rocky|almalinux|ol) echo "centos" ;;
    fedora) echo "fedora" ;;
    *) case "${ID_LIKE:-}" in
         *ubuntu*) echo "ubuntu" ;;
         *debian*) echo "debian" ;;
         *fedora*|*rhel*|*centos*) echo "centos" ;;
         *) return 1 ;;
       esac ;;
  esac
}

install_docker_apt() {
  local distro="$1" codename
  . /etc/os-release
  # A derivative names its own codename, which Docker has never heard of.  The
  # UBUNTU_CODENAME line is what the derivatives set for exactly this.
  codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
  [[ -n "$codename" ]] || die "cannot tell which release this is"

  say "Installing Docker from download.docker.com"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq ca-certificates curl >/dev/null
  $SUDO install -m 0755 -d /etc/apt/keyrings
  $SUDO curl -fsSL "https://download.docker.com/linux/$distro/gpg" \
       -o /etc/apt/keyrings/docker.asc
  $SUDO chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$distro" "$codename" \
    | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
       docker-buildx-plugin docker-compose-plugin
}

install_docker_dnf() {
  local distro="$1" mgr=dnf
  command -v dnf >/dev/null 2>&1 || mgr=yum
  say "Installing Docker from download.docker.com"
  $SUDO $mgr -y install dnf-plugins-core >/dev/null 2>&1 || true
  $SUDO $mgr config-manager --add-repo \
       "https://download.docker.com/linux/$distro/docker-ce.repo" 2>/dev/null \
    || $SUDO $mgr config-manager addrepo --from-repofile \
       "https://download.docker.com/linux/$distro/docker-ce.repo"
  $SUDO $mgr -y install docker-ce docker-ce-cli containerd.io \
       docker-buildx-plugin docker-compose-plugin
}

install_docker() {
  local distro
  distro=$(docker_distro) || {
    warn "this is not a distribution Docker publishes packages for"
    hint "Install it yourself: https://docs.docker.com/engine/install/"
    return 1
  }
  case "$distro" in
    ubuntu|debian)        install_docker_apt "$distro" ;;
    centos|fedora)        install_docker_dnf "$distro" ;;
    *) return 1 ;;
  esac

  # A package that is installed and not running has helped nobody.
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl enable --now docker >/dev/null 2>&1 || true
  fi
}

# ---- what we need before we start -------------------------------------------
say "Checking this machine"

command -v git >/dev/null 2>&1 || {
  warn "git is missing"
  if command -v apt-get >/dev/null 2>&1; then
    ask "Install git?" && $SUDO apt-get update -qq && $SUDO apt-get install -y -qq git
  elif command -v dnf >/dev/null 2>&1; then
    ask "Install git?" && $SUDO dnf -y install git
  elif command -v yum >/dev/null 2>&1; then
    ask "Install git?" && $SUDO yum -y install git
  fi
  command -v git >/dev/null 2>&1 || die "git is needed to fetch the project"
}

if ! command -v docker >/dev/null 2>&1; then
  warn "docker is missing"
  hint "It will come from Docker's own repository, not from this distribution,"
  hint "because the distribution package either is not Docker or has no compose."
  ask "Install Docker Engine and the compose plugin?" \
    || die "install Docker yourself, then run this again: https://docs.docker.com/engine/install/"
  install_docker || die "could not install Docker"
  ok "Docker installed"
fi

# The compose plugin, not the old standalone script.  v1 reads this project's
# compose file differently enough to matter.
if ! docker compose version >/dev/null 2>&1; then
  warn "the docker compose plugin is missing"
  if command -v docker-compose >/dev/null 2>&1; then
    hint "docker-compose v1 is here, and this needs the v2 plugin instead."
  fi
  ask "Install the compose plugin from Docker's repository?" \
    || die "install docker-compose-plugin, then run this again"
  install_docker || die "could not install the compose plugin"
fi
docker compose version >/dev/null 2>&1 || die "docker compose still is not available"

if ! docker info >/dev/null 2>&1; then
  # Almost always the group, and almost always on the run right after
  # installing, because group membership only applies to a new login.
  if [[ -n "$SUDO" ]] && ! id -nG "$USER" 2>/dev/null | tr " " "\n" | grep -qx docker; then
    warn "this account is not in the docker group"
    if ask "Add $USER to the docker group?"; then
      $SUDO usermod -aG docker "$USER" || true
      hint "Log out and back in for that to apply, then run this again."
      hint "Or carry on now with: sudo $0"
      die "group added, but this shell does not have it yet"
    fi
  fi
  die "cannot talk to the docker daemon.  Try again with sudo, or start it: sudo systemctl start docker"
fi
ok "git, docker and compose are all here"

# ---- get the code -----------------------------------------------------------
# ---- somewhere to put it -----------------------------------------------------
# The default is under /opt, which nobody can write to as themselves.  Making
# the directory with sudo and then handing it over is the difference between
# this working and a permission error nobody can act on.
prepare_dest() {
  # Try it as yourself first, and only reach for sudo when that fails.  Asking
  # for root when the directory was going to work anyway is a habit worth not
  # teaching.
  if [[ -d "$DEST" ]]; then
    [[ -w "$DEST" ]] && return 0
  elif mkdir -p "$DEST" 2>/dev/null; then
    return 0
  fi

  [[ -n "$SUDO" ]] || return 1

  say "Making $DEST"
  $SUDO mkdir -p "$DEST" || return 1
  # Handed to whoever is installing, so git and every update after this work
  # without sudo.  A checkout only root can write to is one nobody can pull.
  $SUDO chown -R "$(id -un):$(id -gn)" "$DEST" || return 1
  return 0
}

if ! prepare_dest; then
  warn "cannot write to $DEST"
  hint "Either run this with sudo, or pick somewhere you own:"
  hint "  GCR_DIR=\$HOME/github-code-review curl -fsSL $INSTALL_URL | bash"
  die "nowhere to put it"
fi

if [[ -d "$DEST/.git" ]]; then
  say "Already cloned at $DEST, pulling the latest"
  git -C "$DEST" fetch --quiet origin "$BRANCH" || die "could not fetch"
  git -C "$DEST" checkout --quiet "$BRANCH"
  git -C "$DEST" pull --quiet --ff-only origin "$BRANCH" \
    || warn "could not fast forward, you have local changes"
  ok "up to date"
else
  if [[ -n "$(ls -A "$DEST" 2>/dev/null)" ]]; then
    die "$DEST already exists and is not empty.  Move it, or set GCR_DIR to somewhere else"
  fi
  say "Cloning into $DEST"
  # Into the directory that was just made, rather than letting git make it,
  # so the ownership set above is the ownership it keeps.
  git clone --quiet --branch "$BRANCH" "$REPO" "$DEST" \
    || die "could not clone $REPO"
  ok "cloned"
fi

cd "$DEST" || die "cannot enter $DEST"
chmod +x install.sh 2>/dev/null || true
[[ -x ./install.sh ]] || die "install.sh is missing from the clone"

# ---- hand over --------------------------------------------------------------
say "Handing over to install.sh"
echo
exec ./install.sh "$@"
