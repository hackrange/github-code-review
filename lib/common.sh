#!/usr/bin/env bash
# Logging, temp files, redaction, small helpers.
# shellcheck shell=bash

set -o pipefail

: "${GHSCAN_LOG_LEVEL:=info}"
: "${GHSCAN_COLOR:=auto}"

_ghs_color_on() {
  case "$GHSCAN_COLOR" in
    always) return 0 ;;
    never)  return 1 ;;
    *)      [[ -t 2 ]] ;;
  esac
}

if _ghs_color_on; then
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'
  C_BLU=$'\033[34m'; C_DIM=$'\033[2m';  C_RST=$'\033[0m'
else
  C_RED=; C_YEL=; C_GRN=; C_BLU=; C_DIM=; C_RST=
fi

_ghs_level_num() {
  case "$1" in
    trace) echo 0 ;; debug) echo 1 ;; info) echo 2 ;;
    warn)  echo 3 ;; error) echo 4 ;; *) echo 2 ;;
  esac
}

_log() {
  local lvl="$1"; shift
  local want cur
  want=$(_ghs_level_num "$lvl")
  cur=$(_ghs_level_num "$GHSCAN_LOG_LEVEL")
  (( want < cur )) && return 0
  local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local col=""
  case "$lvl" in
    error) col="$C_RED" ;; warn) col="$C_YEL" ;;
    info)  col="$C_BLU" ;; debug|trace) col="$C_DIM" ;;
  esac
  printf '%s%s [%-5s] %s%s\n' "$col" "$ts" "$lvl" "$*" "$C_RST" >&2
}

log_trace() { _log trace "$@"; }
log_debug() { _log debug "$@"; }
log_info()  { _log info  "$@"; }
log_warn()  { _log warn  "$@"; }
log_error() { _log error "$@"; }
log_ok()    { _log info  "${C_GRN}$*${C_RST}"; }

die() { log_error "$@"; exit 1; }

# Temp files. All of it goes away on exit, including on Ctrl-C.
GHSCAN_TMPROOT=""

# The clone work tree, which is not under the temp root: it lives wherever
# clone.workdir points, so it needs saying separately.  Without this a run that
# is killed or crashes leaves every clone it was holding behind, and on a
# space capped work area that is the difference between the next run working
# and the next run failing to clone anything at all.
#
# Set only when the clones are meant to go.  keep_clones is a debugging aid and
# a trap that ignored it would be a trap that deletes the thing somebody asked
# to keep.
GHSCAN_WORKROOT=""

workroot_track() {
  GHSCAN_WORKROOT="$1"
}

_ghs_cleanup() {
  local rc=$?
  if [[ -n "$GHSCAN_TMPROOT" && -d "$GHSCAN_TMPROOT" ]]; then
    rm -rf -- "$GHSCAN_TMPROOT" 2>/dev/null || true
  fi
  if [[ -n "$GHSCAN_WORKROOT" && -d "$GHSCAN_WORKROOT" ]]; then
    rm -rf -- "$GHSCAN_WORKROOT" 2>/dev/null || true
  fi
  return $rc
}

# Where the temp root goes.  Cleartext credentials pass through these files on
# their way to becoming a mask and a fingerprint, so memory is the right place
# for them: nothing survives a power cut, and no disk keeps a copy in a block
# it has stopped pointing at.
#
# Disk is still the fallback, because a container ships with a 64MB /dev/shm
# and a scan of a large repository will not fit in that.  Running out of room
# halfway through is a worse failure than writing to disk, so the size is
# checked rather than assumed.  Set GHSCAN_TMPDIR to decide for yourself.
_tmp_base() {
  if [[ -n "${GHSCAN_TMPDIR:-}" ]]; then printf '%s' "$GHSCAN_TMPDIR"; return 0; fi
  local dir free
  for dir in /dev/shm "${XDG_RUNTIME_DIR:-}"; do
    [[ -n "$dir" && -d "$dir" && -w "$dir" ]] || continue
    free=$(df -Pk "$dir" 2>/dev/null | awk 'NR==2 {print $4}')
    [[ -n "$free" ]] && (( free >= 262144 )) && { printf '%s' "$dir"; return 0; }
  done
  printf '%s' "${TMPDIR:-/tmp}"
}

tmp_init() {
  [[ -n "$GHSCAN_TMPROOT" ]] && return 0
  local base; base=$(_tmp_base)
  GHSCAN_TMPROOT=$(mktemp -d "$base/ghscan.XXXXXXXX") || die "cannot create temp dir"
  chmod 700 "$GHSCAN_TMPROOT"
  case "$base" in
    /dev/shm|/run/*) log_debug "temp files are in memory at $base" ;;
    *) log_warn "temp files are going to $base, which is disk.  Credentials pass through them in the clear before they are masked.  Give this more shared memory to keep them out of it." ;;
  esac
  # A trap that only cleans up and returns is a trap that ignores the signal:
  # bash runs it and then carries straight on.  Ctrl-C and a stop from the web
  # app both have to actually stop this.
  trap _ghs_cleanup EXIT
  trap '_ghs_cleanup; exit 130' INT
  trap '_ghs_cleanup; exit 143' TERM
}

tmp_file() {
  tmp_init
  mktemp "$GHSCAN_TMPROOT/${1:-t}.XXXXXX"
}

# Get rid of a file that held credentials in the clear, now rather than at the
# end of the run.  The engine reports are the worst of them: they are whatever
# the engine found, in full, before anything has been masked.
#
# gitleaks cannot be asked to stream instead.  It wants a seekable file and
# writes nothing at all to a pipe or a fifo, which is why these exist rather
# than the output going straight into the normalizer.
#
# On tmpfs the pages go back to the kernel when the last link goes, so
# unlinking really is the end of it.  On a host that fell back to disk it is
# not, so overwrite first when there is a tool for it.
wipe_file() {
  local f="$1"
  [[ -n "$f" && -f "$f" ]] || return 0
  case "${GHSCAN_TMPROOT:-}" in
    /dev/shm/*|/run/*) rm -f -- "$f"; return 0 ;;
  esac
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$f" 2>/dev/null && return 0
  fi
  rm -f -- "$f"
}

# Where a host puts a file, a commit and a line of history in its own URLs.
#
# The real answer is in lib/provider.sh, which defines this again and replaces
# this one the moment it is loaded; bin/ghscan loads it four lines later, so a
# scan always gets the real thing.  This exists for the other case: something
# that sources one library on its own, a test or a hook, where a missing
# function makes the jq that builds a finding fail and the caller reads the
# empty result as a file with nothing wrong in it.  A link of the wrong shape
# is a poor answer.  No findings at all is the one answer this tool must never
# give by accident, so the fallback is GitHub's shape rather than nothing.
provider_link_parts() {
  jq -cn '{blob:"blob", blob_commit:"blob", commit:"commit",
           blame:"blame", blame_commit:"blame", history:"commits", line:"#L"}'
}

# Hand jq a big JSON value through a file instead of on the command line.
#
# argv has a size limit, and a repository with a thousand findings goes
# straight past it.  What you get is "Argument list too long" on stderr, an
# empty result, and a repository that quietly never appears in the report.
# Anything that could be more than a few kilobytes goes through here.
#
# json_file <value> [name] -> path to a file holding it
json_file() {
  local value="$1" name="${2:-val}" path
  path=$(tmp_file "$name")
  printf '%s' "${value:-null}" > "$path"
  printf '%s' "$path"
}

tmp_dir() {
  tmp_init
  mktemp -d "$GHSCAN_TMPROOT/${1:-d}.XXXXXX"
}

# Small helpers.
# jq 1.6 is the oldest build these programs are known to work on (it ships with
# Debian bookworm and RHEL 9). 1.5 lacks builtins used by the triage stage.
require_jq() {
  need_cmd jq
  local v; v=$(jq --version 2>/dev/null | sed 's/^jq-//')
  case "$v" in
    1.[0-4]*|1.5*) die "jq $v is too old; ghscan needs jq 1.6 or newer" ;;
  esac
  log_debug "jq version $v"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# json_str <text>  -> a properly escaped JSON string literal
json_str() { jq -Rn --arg v "$1" '$v'; }

# slugify org/repo -> org__repo (safe for filenames)
slugify() { printf '%s' "$1" | sed 's|/|__|g' | tr ':@ ' '___'; }

# urlencode a path segment
urlenc() {
  jq -rn --arg v "$1" '$v|@uri'
}

# redact "<secret>" [prefix] [suffix] [max_mask]
#   sk_deadbeefcafegsj -> sk_d*********gsj
# Reports never carry cleartext. The fingerprint below is how you correlate.
redact() {
  local s="$1" pre="${2:-4}" suf="${3:-3}" maxmask="${4:-12}"

  # Collapse newlines so a multi-line secret still previews on one line.
  s="${s//$'\n'/ }"; s="${s//$'\r'/ }"

  # Masking a PEM body gives you "----****---", which says nothing useful.
  # Name the key type instead. We skip the BEGIN line on purpose so this report
  # doesn't trip other people's secret scanners.
  if [[ "$s" == *"-----BEGIN "*"-----"* ]]; then
    local hdr="${s#*-----BEGIN }"; hdr="${hdr%%-----*}"
    printf '[%s] %s' "$hdr" '****************'
    return
  fi

  local n=${#s}
  # Too short to reveal anything safely: mask entirely.
  if (( n <= pre + suf + 2 )); then
    printf '%*s' "$(( n < 8 ? 8 : n ))" '' | tr ' ' '*'
    return
  fi
  local mid=$(( n - pre - suf ))
  (( mid > maxmask )) && mid=$maxmask
  local stars
  stars=$(printf '%*s' "$mid" '' | tr ' ' '*')
  printf '%s%s%s' "${s:0:pre}" "$stars" "${s: -suf}"
}

# fingerprint <secret> -> first 16 hex chars of sha256
fingerprint() {
  printf '%s' "$1" | sha256sum | cut -c1-16
}

# retry <attempts> <base_delay_sec> -- cmd...
retry() {
  local attempts="$1" delay="$2"; shift 2
  [[ "$1" == "--" ]] && shift
  local i=1
  while true; do
    if "$@"; then return 0; fi
    local rc=$?
    if (( i >= attempts )); then
      log_debug "retry: giving up after $i attempts (rc=$rc): $1"
      return $rc
    fi
    log_debug "retry: attempt $i/$attempts failed (rc=$rc), sleeping ${delay}s"
    sleep "$delay"
    delay=$(( delay * 2 ))
    i=$(( i + 1 ))
  done
}

# Portable timeout wrapper (no-op if coreutils timeout is absent)
with_timeout() {
  local secs="$1"; shift
  if (( secs > 0 )) && have_cmd timeout; then
    timeout --kill-after=30s "${secs}s" "$@"
  else
    "$@"
  fi
}

# engine_versions -> JSON object naming every scanner actually present, with
# its version. Recorded in the report so a finding set is reproducible.
# The venv the installer builds, or whatever python3 is on PATH.
ghscan_python() {
  if [[ -x "${GHSCAN_HOME:-}/.venv/bin/python" ]]; then
    printf '%s' "$GHSCAN_HOME/.venv/bin/python"
  elif have_cmd python3; then
    printf 'python3'
  fi
}

ghscan_venv_bin() {
  local name="$1"
  if [[ -x "${GHSCAN_HOME:-}/.venv/bin/$name" ]]; then
    printf '%s' "$GHSCAN_HOME/.venv/bin/$name"
  elif have_cmd "$name"; then
    printf '%s' "$name"
  fi
}

engine_versions() {
  local out='{}' t v
  for t in gitleaks trufflehog syft grype git jq curl; do
    if have_cmd "$t"; then
      v=$("$t" --version 2>/dev/null | head -1 | tr -d '\r' | sed 's/^[[:space:]]*//')
      [[ -z "$v" ]] && v="present"
    else
      v="not installed"
    fi
    out=$(printf '%s' "$out" | jq -c --arg k "$t" --arg v "$v" '.[$k] = $v')
  done
  printf '%s' "$out"
}
