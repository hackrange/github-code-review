#!/usr/bin/env bash
# Installs everything ghscan needs. Safe to re-run.
# Works as root or as a normal user. Run with -h for the options.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${BIN_DIR:-}"
VENV_DIR="${VENV_DIR:-$HERE/.venv}"
ONLY=""
DRY=0
USER_MODE=0
SKIP_SYSTEM=0
SKIP_PYTHON=0

say()  { printf '\033[34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m  %s\n' "$*" >&2; }
err()  { printf '\033[31mxx\033[0m  %s\n' "$*" >&2; }
run()  { if (( DRY )); then printf '   + %s\n' "$*"; else "$@"; fi; }

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'MORE'

Scanners installed:
  gitleaks     secrets, across full git history
  trufflehog   secrets, plus live credential verification
  syft         SBOM with license data
  grype        vulnerabilities, matched against the SBOM
  osv-scanner  package vulnerabilities from OSV.dev
  trivy        Terraform, Kubernetes, Helm and Dockerfile misconfiguration
  zizmor       GitHub Actions workflows: injection, dangerous triggers
  semgrep      static analysis (installed into the venv)

Python packages come from requirements.txt.
MORE
}

while (( $# )); do
  case "$1" in
    --bin-dir)     BIN_DIR="$2"; shift 2 ;;
    --venv)        VENV_DIR="$2"; shift 2 ;;
    --only)        ONLY="$2"; shift 2 ;;
    --user)        USER_MODE=1; shift ;;
    --skip-system) SKIP_SYSTEM=1; shift ;;
    --skip-python) SKIP_PYTHON=1; shift ;;
    --dry-run)     DRY=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) err "unknown argument: $1"; usage >&2; exit 2 ;;
  esac
done

want() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

# Where things go
if [[ -z "$BIN_DIR" ]]; then
  if (( USER_MODE )) || [[ "$(id -u)" != "0" && ! -w /usr/local/bin ]]; then
    BIN_DIR="$HOME/.local/bin"
    USER_MODE=1
  else
    BIN_DIR="/usr/local/bin"
  fi
fi

# Root installs directly. Everyone else goes through sudo if it is there.
SUDO=""
CAN_INSTALL_PACKAGES=1
if [[ "$(id -u)" != "0" ]]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo"
  elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"          # will prompt for a password
  else
    CAN_INSTALL_PACKAGES=0
  fi
  if (( ! USER_MODE )) && [[ ! -w "$BIN_DIR" ]] && [[ -z "$SUDO" ]]; then
    warn "not root and no sudo, so installing under \$HOME instead"
    BIN_DIR="$HOME/.local/bin"; USER_MODE=1
  fi
fi

# pkg_install <packages...>
pkg_install() {
  if (( ! CAN_INSTALL_PACKAGES )); then
    warn "cannot install packages (not root, no sudo). Install by hand: $*"
    return 1
  fi
  case "$PKG_MGR" in
    apt-get) run $SUDO apt-get update -qq && run $SUDO apt-get install -y --no-install-recommends "$@" ;;
    dnf|yum) run $SUDO "$PKG_MGR" install -y "$@" ;;
    zypper)  run $SUDO zypper --non-interactive install "$@" ;;
    pacman)  run $SUDO pacman -Sy --noconfirm "$@" ;;
    apk)     run $SUDO apk add --no-cache "$@" ;;
    brew)    run brew install "$@" ;;
    *) warn "no supported package manager; install by hand: $*"; return 1 ;;
  esac
}

# The venv package is named differently everywhere, and on Debian it ships no
# binary, so you only find out it is missing when venv creation half-fails.
venv_package_name() {
  case "$PKG_MGR" in
    apt-get) printf 'python3-venv python3-pip' ;;
    dnf|yum) printf 'python3-pip' ;;
    zypper)  printf 'python3-pip python3-virtualenv' ;;
    pacman)  printf 'python-pip' ;;
    apk)     printf 'py3-pip' ;;
    brew)    printf 'python3' ;;
    *)       printf '' ;;
  esac
}

mkdir -p "$BIN_DIR"
if [[ ! -w "$BIN_DIR" ]]; then
  err "$BIN_DIR is not writable. Re-run with --user, or set BIN_DIR."
  exit 1
fi

PKG_MGR=""
for m in apt-get dnf yum zypper pacman apk brew; do
  command -v "$m" >/dev/null 2>&1 && { PKG_MGR="$m"; break; }
done

# Platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux|darwin) ;;
  *) err "unsupported OS: $OS (linux and darwin only)"; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  GO_ARCH=amd64; GL_ARCH=x64;   TV_ARCH=64bit; ZZ_ARCH=x86_64 ;;
  aarch64|arm64) GO_ARCH=arm64; GL_ARCH=arm64; TV_ARCH=ARM64; ZZ_ARCH=aarch64 ;;
  armv7l)        GO_ARCH=arm;   GL_ARCH=armv7; TV_ARCH=ARM;   ZZ_ARCH="" ;;
  *) err "unsupported architecture: $(uname -m)"; exit 1 ;;
esac

# System packages
install_system_packages() {
  local missing=()
  local c
  for c in git jq curl openssl tar; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  command -v python3 >/dev/null 2>&1 || missing+=("python3")

  if (( ${#missing[@]} == 0 )); then
    say "system packages already present"
    return 0
  fi

  say "installing system packages: ${missing[*]}"
  local base=(git jq curl openssl ca-certificates tar coreutils findutils util-linux)
  case "$PKG_MGR" in
    apt-get) pkg_install "${base[@]}" python3 python3-venv python3-pip ;;
    dnf|yum|zypper) pkg_install "${base[@]}" python3 python3-pip ;;
    pacman)  pkg_install git jq curl openssl ca-certificates tar coreutils findutils util-linux python python-pip ;;
    apk)     pkg_install bash git jq curl openssl ca-certificates tar coreutils findutils util-linux python3 py3-pip ;;
    brew)    pkg_install git jq curl openssl coreutils findutils python3 ;;
    *) err "no supported package manager. Install these yourself: ${missing[*]}"; return 1 ;;
  esac
}

# Scanners
fetch() { curl -fsSL --retry 3 --retry-delay 2 "$1"; }

pinned_tag() {
  # The version to install, fixed.  This used to ask GitHub for the latest
  # release and only fall back to the pinned tag when that call was rate
  # limited, which meant a normal run installed whatever the upstream had
  # tagged most recently rather than a version anybody here had chosen.  A
  # build should install the version it was tested against; bump the pins
  # deliberately.  The repository is kept as a first argument so the call
  # sites still read as "this tool, this version".
  local _repo="$1" pinned="$2"
  printf '%s' "$pinned"
}

install_gitleaks() {
  local ver url tmp
  ver=$(pinned_tag gitleaks/gitleaks v8.30.1); ver="${ver#v}"
  url="https://github.com/gitleaks/gitleaks/releases/download/v${ver}/gitleaks_${ver}_${OS}_${GL_ARCH}.tar.gz"
  say "gitleaks $ver"
  (( DRY )) && { printf '   + download %s\n' "$url"; return 0; }
  tmp=$(mktemp -d)
  fetch "$url" > "$tmp/gl.tgz"
  tar -xzf "$tmp/gl.tgz" -C "$tmp" gitleaks
  install -m 0755 "$tmp/gitleaks" "$BIN_DIR/gitleaks"
  rm -rf "$tmp"
}

install_via_vendor_script() {
  local name="$1" url="$2" tmp
  say "$name"
  (( DRY )) && { printf '   + sh <(%s) -b %s\n' "$url" "$BIN_DIR"; return 0; }
  tmp=$(mktemp)
  fetch "$url" > "$tmp"
  # Fetch first, then run, so the script can be pinned or reviewed if you want to.
  sh "$tmp" -b "$BIN_DIR" >/dev/null
  rm -f "$tmp"
}

install_osv_scanner() {
  local ver url tmp
  ver=$(pinned_tag google/osv-scanner v2.5.1)
  url="https://github.com/google/osv-scanner/releases/download/${ver}/osv-scanner_${OS}_${GO_ARCH}"
  say "osv-scanner $ver"
  (( DRY )) && { printf '   + download %s\n' "$url"; return 0; }
  tmp=$(mktemp)
  if fetch "$url" > "$tmp" 2>/dev/null; then
    install -m 0755 "$tmp" "$BIN_DIR/osv-scanner"
  else
    warn "could not download osv-scanner, skipping it"
  fi
  rm -f "$tmp"
}

install_trivy() {
  local ver url tmp os
  ver=$(pinned_tag aquasecurity/trivy v0.74.0); ver="${ver#v}"
  # Trivy names the platform with a capital, unlike everything else here.
  os=$(uname -s)
  url="https://github.com/aquasecurity/trivy/releases/download/v${ver}/trivy_${ver}_${os}-${TV_ARCH}.tar.gz"
  say "trivy $ver"
  (( DRY )) && { printf '   + download %s\n' "$url"; return 0; }
  tmp=$(mktemp -d)
  if fetch "$url" | tar -xz -C "$tmp" trivy 2>/dev/null; then
    install -m 0755 "$tmp/trivy" "$BIN_DIR/trivy"
  else
    warn "could not download trivy, skipping it"
  fi
  rm -rf "$tmp"
}

install_zizmor() {
  local ver url tmp
  if [[ -z "$ZZ_ARCH" ]]; then
    warn "zizmor publishes no build for this architecture, skipping it"
    return 0
  fi
  ver=$(pinned_tag zizmorcore/zizmor v1.29.0)
  url="https://github.com/zizmorcore/zizmor/releases/download/${ver}/zizmor-${ZZ_ARCH}-unknown-linux-gnu.tar.gz"
  say "zizmor $ver"
  (( DRY )) && { printf '   + download %s\n' "$url"; return 0; }
  tmp=$(mktemp -d)
  if fetch "$url" | tar -xz -C "$tmp" zizmor 2>/dev/null; then
    install -m 0755 "$tmp/zizmor" "$BIN_DIR/zizmor"
  else
    warn "could not download zizmor, skipping it"
  fi
  rm -rf "$tmp"
}

# Python
install_python_deps() {
  local req="$HERE/requirements.txt"
  [[ -f "$req" ]] || { warn "requirements.txt missing, skipping python setup"; return 0; }

  if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found and could not be installed; skipping python packages"
    return 1
  fi

  local pyver
  pyver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  say "python $pyver, venv at $VENV_DIR"
  (( DRY )) && { printf '   + python3 -m venv %s && pip install -r %s\n' "$VENV_DIR" "$req"; return 0; }

  if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    say "python is missing ensurepip, installing the venv package"
    local vp; vp=$(venv_package_name)
    # shellcheck disable=SC2086
    [[ -n "$vp" ]] && pkg_install $vp || true
  fi

  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    python3 -m venv "$VENV_DIR" 2>/dev/null || python3 -m venv --without-pip "$VENV_DIR" 2>/dev/null || true
  fi
  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    err "could not create a venv at $VENV_DIR"
    err "Debian/Ubuntu: apt-get install python3-venv    RHEL: dnf install python3"
    return 1
  fi

  # A venv built without the python3-venv package has no pip. Put one in.
  if ! "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1; then
    say "venv has no pip, bootstrapping one"
    # ensurepip, and only ensurepip.  Downloading get-pip.py from the network
    # and running it is fetching an unpinned script straight into the
    # interpreter; a missing pip is a packaging problem the operator fixes by
    # installing python3-venv, not something to paper over with a remote
    # bootstrap.
    "$VENV_DIR/bin/python" -m ensurepip --upgrade >/dev/null 2>&1 || true
  fi
  if ! "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1; then
    err "no pip in $VENV_DIR and bootstrapping failed"
    err "Debian/Ubuntu: apt-get install python3-venv python3-pip"
    return 1
  fi

  "$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip setuptools wheel
  "$VENV_DIR/bin/python" -m pip install --quiet -r "$req"

  # Make sure it really worked, rather than reporting success on an empty venv.
  local pkg missing=()
  while read -r pkg; do
    [[ -z "$pkg" ]] && continue
    "$VENV_DIR/bin/python" -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('$pkg') else 1)" \
      2>/dev/null || missing+=("$pkg")
  done < <(sed 's/#.*//' "$req" | sed 's/[<>=!].*//' | tr -d ' ' | tr '-' '_' | grep -v '^$')
  if (( ${#missing[@]} )); then
    err "these python packages did not install: ${missing[*]}"
    return 1
  fi

  # ghscan finds the venv on its own, but a shim keeps ad-hoc use simple.
  cat > "$BIN_DIR/ghscan-python" <<SHIM
#!/bin/sh
exec "$VENV_DIR/bin/python" "\$@"
SHIM
  chmod 0755 "$BIN_DIR/ghscan-python"
}

# Go
(( SKIP_SYSTEM )) || install_system_packages || warn "system package step had problems, continuing"

for c in curl jq tar; do
  command -v "$c" >/dev/null 2>&1 || { err "$c is required and is still missing"; exit 1; }
done

want gitleaks   && install_gitleaks
want trufflehog && install_via_vendor_script trufflehog \
  "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"
want syft       && install_via_vendor_script syft \
  "https://raw.githubusercontent.com/anchore/syft/main/install.sh"
want grype      && install_via_vendor_script grype \
  "https://raw.githubusercontent.com/anchore/grype/main/install.sh"
want osv-scanner && install_osv_scanner
want trivy      && install_trivy
want zizmor     && install_zizmor

(( SKIP_PYTHON )) || [[ -n "$ONLY" ]] || install_python_deps || warn "python setup had problems, continuing"

# What we ended up with
echo
say "installed"
for t in git jq curl openssl gitleaks trufflehog syft grype; do
  if command -v "$t" >/dev/null 2>&1; then
    printf '  %-12s %s\n' "$t" "$("$t" --version 2>/dev/null | head -1)"
  elif [[ -x "$BIN_DIR/$t" ]]; then
    printf '  %-12s %s\n' "$t" "$("$BIN_DIR/$t" --version 2>/dev/null | head -1)"
  else
    printf '  %-12s %s\n' "$t" "not installed"
  fi
done
if [[ -x "$VENV_DIR/bin/python" ]]; then
  printf '  %-12s %s\n' "python" "$("$VENV_DIR/bin/python" --version 2>&1)"
  "$VENV_DIR/bin/python" -m pip list --format=freeze 2>/dev/null \
    | grep -iE '^(detect-secrets|jsonschema)=' | sed 's/^/  /'
fi

echo
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH. Add: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
say "next: cp config/config.example.json config/config.json, edit it, then ./bin/ghscan check"
