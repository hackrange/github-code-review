#!/usr/bin/env bash
# Shared by the gcr-*.sh scripts.  Source it, do not run it.
#
# Settings come from the environment first, then from a .env file:
#
#   GCR_URL            API base, https, ending in /api/v1
#   GCR_TOKEN          a token with the "reports" scope (in CI, from a secret)
#   GCR_TOKEN_COMMAND  or a command that prints the token, for a token kept
#                      encrypted or in a keychain, such as
#                      gpg --quiet --decrypt ~/.config/gcr/token.gpg
#   GCR_TOKEN_FILE     or a file holding only the token, mode 600
#   GCR_CA_BUNDLE      optional: a CA file for a server with an internal cert
#   GCR_ALLOW_HTTP     set to 1 to allow plain http, for local testing only
#
# Needs curl and jq, which every GitHub-hosted Ubuntu runner already has.

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 3; }
done

# True when no other user can read the file.
_gcr_private() {
  local mode
  mode="$(stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null)" || return 0
  (( (8#$mode & 8#077) == 0 ))
}

# .env in the current folder, or in the kit folder above these scripts.
# Values already in the environment win, so a CI secret always beats a file.
for _gcr_file in "$PWD/.env" "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/.env"; do
  [[ -r "$_gcr_file" ]] || continue
  if grep -Eq '^[[:space:]]*(export[[:space:]]+)?GCR_TOKEN[[:space:]]*=[[:space:]]*[^[:space:]]' "$_gcr_file" \
     && ! _gcr_private "$_gcr_file"; then
    echo "$_gcr_file holds a token but other users can read it.  Run: chmod 600 $_gcr_file" >&2
    exit 3
  fi
  while IFS='=' read -r _k _v; do
    _k="${_k#export }"; _k="${_k//[[:space:]]/}"
    [[ "$_k" =~ ^GCR_[A-Z_]+$ ]] || continue
    _v="${_v%$'\r'}"; _v="${_v#"${_v%%[![:space:]]*}"}"; _v="${_v%"${_v##*[![:space:]]}"}"
    _v="${_v#\"}"; _v="${_v%\"}"; _v="${_v#\'}"; _v="${_v%\'}"
    [[ -z "${!_k:-}" && -n "$_v" ]] && export "$_k=$_v"
  done < "$_gcr_file"
  break
done
unset _gcr_file _k _v

GCR_URL="${GCR_URL:-}"; GCR_URL="${GCR_URL%/}"
if [[ -z "$GCR_URL" ]]; then
  echo "No server address.  Set GCR_URL, or copy .env.example to .env." >&2
  exit 3
fi
case "$GCR_URL" in
  https://*) ;;
  http://localhost*|http://127.0.0.1*|http://\[::1\]*) ;;
  *) if [[ "${GCR_ALLOW_HTTP:-}" != 1 ]]; then
       echo "GCR_URL must start with https://.  A token sent over plain http can be read by anybody on the network." >&2
       exit 3
     fi ;;
esac

# The token, from the first place that has one.  It is never echoed.
if [[ -z "${GCR_TOKEN:-}" && -n "${GCR_TOKEN_COMMAND:-}" ]]; then
  GCR_TOKEN="$(eval "$GCR_TOKEN_COMMAND" 2>/dev/null | head -n 1 | tr -d '[:space:]')" || true
  [[ -n "$GCR_TOKEN" ]] || { echo "GCR_TOKEN_COMMAND did not print a token." >&2; exit 3; }
fi
if [[ -z "${GCR_TOKEN:-}" && -n "${GCR_TOKEN_FILE:-}" ]]; then
  GCR_TOKEN_FILE="${GCR_TOKEN_FILE/#\~/$HOME}"
  [[ -r "$GCR_TOKEN_FILE" ]] || { echo "GCR_TOKEN_FILE $GCR_TOKEN_FILE does not exist." >&2; exit 3; }
  _gcr_private "$GCR_TOKEN_FILE" || {
    echo "$GCR_TOKEN_FILE can be read by other users.  Run: chmod 600 $GCR_TOKEN_FILE" >&2; exit 3; }
  GCR_TOKEN="$(tr -d '[:space:]' < "$GCR_TOKEN_FILE")"
fi
if [[ -z "${GCR_TOKEN:-}" ]]; then
  echo "No token.  Set GCR_TOKEN, GCR_TOKEN_COMMAND or GCR_TOKEN_FILE." >&2
  exit 3
fi

# Options every call shares.  The token goes to curl through a config on a
# here-document, never as an argument, so it never shows up in the process
# list where other users of the machine could read it.
_gcr_curl() {
  local tls=()
  [[ -n "${GCR_CA_BUNDLE:-}" ]] && tls=(--cacert "${GCR_CA_BUNDLE/#\~/$HOME}")
  curl -sS -m 60 --proto '=https,http' "${tls[@]}" -K - "$@" <<CFG
header = "Authorization: Bearer ${GCR_TOKEN}"
header = "Accept: application/json"
CFG
}

# The repository and branch, from GitHub Actions when not given.  On a pull
# request GITHUB_REF_NAME is "123/merge", which is never scanned, so the
# branch being merged into is used instead.
gcr_default_repo()   { printf '%s' "${1:-${GITHUB_REPOSITORY:-}}"; }
gcr_default_branch() {
  if [[ -n "${1:-}" ]]; then printf '%s' "$1"
  elif [[ "${GITHUB_EVENT_NAME:-}" == pull_request* ]]; then printf '%s' "${GITHUB_BASE_REF:-}"
  else printf '%s' "${GITHUB_REF_NAME:-}"; fi
}

# gcr_get PATH [name=value ...]
# Prints the body.  Returns 3 and says why when the call fails.  Retried
# twice when the server is busy or restarting.
gcr_get() {
  local path="$1"; shift
  local args=() pair body status
  for pair in "$@"; do [[ -n "${pair#*=}" ]] && args+=(--data-urlencode "$pair"); done
  body="$(_gcr_curl -G --retry 2 --retry-delay 5 -w $'\n%{http_code}' \
            "${args[@]}" "$GCR_URL$path")" || { echo "Could not reach $GCR_URL" >&2; return 3; }
  status="${body##*$'\n'}"; body="${body%$'\n'*}"
  if [[ "$status" != 2* ]]; then gcr_explain "$status" "$body"; return 3; fi
  printf '%s' "$body"
}

# gcr_post PATH JSON.  Never retried, so a request is never sent twice.
gcr_post() { gcr_send POST "$1" "$2"; }

# gcr_patch PATH JSON.  Changes part of something, such as your exception.
gcr_patch() { gcr_send PATCH "$1" "$2"; }

# gcr_send METHOD PATH JSON.  Never retried.
gcr_send() {
  local body status data="${3:-}"
  [[ -n "$data" ]] || data='{}'
  body="$(_gcr_curl -X "$1" -H "Content-Type: application/json" \
            --data-binary "$data" -w $'\n%{http_code}' "$GCR_URL$2")" \
    || { echo "Could not reach $GCR_URL" >&2; return 3; }
  status="${body##*$'\n'}"; body="${body%$'\n'*}"
  if [[ "$status" != 2* ]]; then gcr_explain "$status" "$body"; return 3; fi
  printf '%s' "$body"
}

gcr_explain() {
  local status="$1" body="$2" detail
  detail="$(jq -r '.detail // empty' 2>/dev/null <<<"$body")"
  # Some errors come back as plain text, which is the reason itself.
  if [[ -z "$detail" && -n "$body" ]] && ! grep -qi '<html' <<<"$body"; then
    detail="$(printf '%s' "${body:0:500}" | tr -s '\r\n' '  ')"
    detail="${detail% }"
  fi
  if [[ -z "$detail" ]]; then
    # The load balancer swaps some answers for its own web page.
    case "$status" in
      401) detail="the token was refused: wrong, expired, revoked, or missing a scope" ;;
      403) detail="refused before the API: the runner's IP is probably not allowed through the load balancer" ;;
      404) detail="not found, or not visible to the token's owner" ;;
      429) detail="too many calls, wait a minute" ;;
      *)   detail="unexpected answer" ;;
    esac
  fi
  echo "Git Code Review API: HTTP $status: $detail" >&2
  [[ "${GITHUB_ACTIONS:-}" == true ]] && echo "::error title=Git Code Review API::HTTP $status $detail"
  return 0
}

# Add markdown to the GitHub Actions job summary, when there is one.
gcr_summary() { [[ -n "${GITHUB_STEP_SUMMARY:-}" ]] && printf '%s\n\n' "$1" >> "$GITHUB_STEP_SUMMARY"; return 0; }
