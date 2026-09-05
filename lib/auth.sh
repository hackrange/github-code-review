#!/usr/bin/env bash
# GitHub auth. Okta FastPass needs a browser and a device, so a scheduled scan
# can't do it. Use a GitHub App: installation tokens skip the SAML SSO check
# entirely. PATs work too, but each one has to be SSO-authorized per org.
# shellcheck shell=bash

# Keep whatever the parent exported. Workers re-source this file, and a plain
# assignment here would wipe the token path they just inherited.
GHSCAN_TOKEN_FILE="${GHSCAN_TOKEN_FILE:-}"
GHSCAN_TOKEN_META="${GHSCAN_TOKEN_META:-}"
GHSCAN_AUTH_METHOD="${GHSCAN_AUTH_METHOD:-}"
GHSCAN_AUTH_KIND="${GHSCAN_AUTH_KIND:-}"

_b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# Build a signed RS256 JWT for the GitHub App (valid 9 minutes; GitHub caps at 10).
_app_jwt() {
  local app_id="$1" key="$2"
  local now iat exp header payload signing_input sig
  now=$(date +%s)
  iat=$(( now - 60 ))     # tolerate modest clock skew
  exp=$(( now + 540 ))

  header=$(printf '{"alg":"RS256","typ":"JWT"}' | _b64url)
  payload=$(jq -cn --argjson iat "$iat" --argjson exp "$exp" --arg iss "$app_id" \
    '{iat:$iat, exp:$exp, iss:$iss}' | _b64url)
  signing_input="${header}.${payload}"

  sig=$(printf '%s' "$signing_input" \
        | openssl dgst -sha256 -sign "$key" 2>/dev/null \
        | _b64url) || die "failed to sign App JWT with $key"
  [[ -n "$sig" ]] || die "empty JWT signature - is $key a valid PKCS#1/PKCS#8 RSA private key?"

  printf '%s.%s' "$signing_input" "$sig"
}

# Resolve the installation id for the App, preferring the configured value and
# otherwise discovering the installation that matches the first configured org.
_app_installation_id() {
  local jwt="$1" api="$2"
  local id; id=$(cfg '.github.auth.app.installation_id')
  if [[ -n "$id" && "$id" != "null" ]]; then printf '%s' "$id"; return 0; fi

  local org; org=$(cfg_arr '.github.scope.orgs' | head -1)
  local body hdr
  hdr=$(tmp_file hdr); body=$(tmp_file body)
  jwt_curl "$jwt" -sS -D "$hdr" -o "$body" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$api/app/installations?per_page=100" || die "cannot list App installations"

  local code; code=$(awk 'toupper($1) ~ /^HTTP/ {c=$2} END{print c}' "$hdr")
  if [[ "$code" != "200" ]]; then
    log_error "GET /app/installations returned HTTP $code"
    jq -r '.message // empty' "$body" >&2 2>/dev/null || true
    die "App authentication failed - check app_id and private key"
  fi

  id=$(jq -r --arg org "$org" '.[] | select((.account.login // "") | ascii_downcase == ($org|ascii_downcase)) | .id' "$body" | head -1)
  if [[ -z "$id" ]]; then
    log_error "GitHub App is not installed on org '$org'. Installations found:"
    jq -r '.[] | "  - \(.account.login) (id \(.id), \(.target_type))"' "$body" >&2
    die "install the App on '$org' or set github.auth.app.installation_id"
  fi
  log_debug "discovered App installation id $id for org $org"
  printf '%s' "$id"
}

_mint_installation_token() {
  local api; api=$(cfg '.github.api_url' 'https://api.github.com')
  local app_id key jwt inst body hdr
  app_id=$(cfg '.github.auth.app.app_id')
  key=$(cfg '.github.auth.app.private_key_path')

  jwt=$(_app_jwt "$app_id" "$key")
  inst=$(_app_installation_id "$jwt" "$api")

  hdr=$(tmp_file hdr); body=$(tmp_file body)
  jwt_curl "$jwt" -sS -X POST -D "$hdr" -o "$body" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$api/app/installations/${inst}/access_tokens" \
    || die "failed to request installation token"

  local code; code=$(awk 'toupper($1) ~ /^HTTP/ {c=$2} END{print c}' "$hdr")
  if [[ "$code" != "201" ]]; then
    log_error "installation token request returned HTTP $code"
    jq -r '.message // empty' "$body" >&2 2>/dev/null || true
    die "could not mint an installation token"
  fi

  local tok exp
  tok=$(jq -r '.token' "$body")
  exp=$(jq -r '.expires_at' "$body")
  [[ -n "$tok" && "$tok" != "null" ]] || die "installation token response had no token"

  local exp_epoch
  exp_epoch=$(date -u -d "$exp" +%s 2>/dev/null || echo $(( $(date +%s) + 3000 )))

  umask 077
  printf '%s' "$tok" > "$GHSCAN_TOKEN_FILE"
  jq -cn --argjson exp "$exp_epoch" --arg inst "$inst" \
     '{expires_at:$exp, installation_id:$inst, kind:"app"}' > "$GHSCAN_TOKEN_META"
  log_debug "minted installation token for installation $inst (expires $exp)"
}

auth_init() {
  tmp_init
  GHSCAN_TOKEN_FILE="$GHSCAN_TMPROOT/token"
  GHSCAN_TOKEN_META="$GHSCAN_TMPROOT/token.meta.json"
  export GHSCAN_TOKEN_FILE GHSCAN_TOKEN_META
  GHSCAN_AUTH_METHOD=$(cfg '.github.auth.method' 'pat')
  export GHSCAN_AUTH_METHOD
  umask 077

  case "$GHSCAN_AUTH_METHOD" in
    app)
      need_cmd openssl
      GHSCAN_AUTH_KIND="token"
      _mint_installation_token
      ;;
    pat)
      local env_name file tok
      env_name=$(cfg '.github.auth.pat.token_env' 'GITHUB_TOKEN')
      file=$(cfg '.github.auth.pat.token_file')
      tok="${!env_name:-}"
      if [[ -z "$tok" && -r "${file:-/nonexistent}" ]]; then
        tok=$(tr -d '\r\n' < "$file")
      fi
      [[ -n "$tok" ]] || die "no PAT found (env \$$env_name / file '$file')"
      GHSCAN_AUTH_KIND="token"
      printf '%s' "$tok" > "$GHSCAN_TOKEN_FILE"
      printf '{"expires_at":0,"kind":"pat"}' > "$GHSCAN_TOKEN_META"
      ;;
    gh_cli)
      local tok; tok=$(gh auth token 2>/dev/null) || die "gh auth token failed - run 'gh auth login' first"
      GHSCAN_AUTH_KIND="token"
      printf '%s' "$tok" > "$GHSCAN_TOKEN_FILE"
      printf '{"expires_at":0,"kind":"gh_cli"}' > "$GHSCAN_TOKEN_META"
      ;;
  esac
  export GHSCAN_AUTH_KIND
  chmod 600 "$GHSCAN_TOKEN_FILE"
}

# Current token, refreshed automatically when an App token is close to expiry.
# Safe to call from parallel workers: the refresh is serialized with flock.
auth_token() {
  local meta exp now
  if [[ "$GHSCAN_AUTH_METHOD" == "app" ]]; then
    exp=$(jq -r '.expires_at // 0' "$GHSCAN_TOKEN_META" 2>/dev/null || echo 0)
    now=$(date +%s)
    if (( now > exp - 300 )); then
      if have_cmd flock; then
        ( flock -w 60 9
          exp=$(jq -r '.expires_at // 0' "$GHSCAN_TOKEN_META" 2>/dev/null || echo 0)
          (( $(date +%s) > exp - 300 )) && _mint_installation_token
        ) 9>"${GHSCAN_TOKEN_FILE}.lock"
      else
        _mint_installation_token
      fi
    fi
  fi
  cat "$GHSCAN_TOKEN_FILE"
}

auth_header() {
  # Kept for callers that want the header as a plain string.  The provider
  # decides its shape: GitHub takes "Authorization: token", GitLab takes
  # PRIVATE-TOKEN.
  local line; line=$(provider_call auth_header_line "$(auth_token)")
  # The provider hands back a curl config line; strip it back to the header.
  printf '%s' "${line#header = \"}" | sed 's/"$//'
}

# curl with the credential attached, without putting it in the process list.
#
# -H "Authorization: token ..." means the token sits in argv, and argv is
# readable by anybody who can run ps in this container.  A config on stdin
# keeps it in a pipe, so the command line only ever shows switches.
auth_curl() {
  # The credential goes through a curl config on stdin rather than argv, so it
  # never appears in the process list.  Which header it is depends on the host.
  printf '%s\n' "$(provider_call auth_header_line "$(auth_token)")" \
    | curl -K - "$@"
}

# The same trick for the App JWT, which is a credential for ten minutes.
jwt_curl() {
  local jwt="$1"; shift
  printf 'header = "Authorization: Bearer %s"\n' "$jwt" | curl -K - "$@"
}

# Clone URL with no credential in it.
auth_git_url() {
  provider_call git_url "$1"
}

# Feed git the token through a helper instead of the URL. Putting it in the URL
# leaks it to anyone running `ps`, and into .git/config.
auth_git_credential_args() {
  [[ -n "${GHSCAN_TOKEN_FILE:-}" ]] || return 0
  # Refresh first, so the file the helper reads is current for the whole clone.
  auth_token >/dev/null
  # The username half of basic auth is a per host convention: GitHub wants
  # x-access-token, GitLab wants oauth2.  The password is the token either way,
  # and it is read from a file by the helper so it never reaches argv.
  local git_user; git_user=$(provider_call git_username)
  printf '%s\0' \
    "-c" "credential.helper=" \
    "-c" "credential.helper=!f(){ test \"\$1\" = get && { echo username=${git_user}; echo \"password=\$(cat \"\$GHSCAN_TOKEN_FILE\")\"; }; }; f" \
    "-c" "credential.useHttpPath=false"
}

# Inspect an X-GitHub-SSO header and explain what the operator must do.
auth_explain_sso() {
  local sso_header="$1" org="${2:-}"
  [[ -z "$sso_header" ]] && return 1
  log_error "GitHub returned a SAML SSO challenge: $sso_header"
  case "$sso_header" in
    *required*)
      local url; url=$(printf '%s' "$sso_header" | sed -n 's/.*url=\([^,;[:space:]]*\).*/\1/p')
      log_error "This token has not been authorized for the SAML-protected org${org:+ ($org)}."
      if [[ -n "$url" ]]; then
        log_error "Authorize it here (you will be sent through Okta / FastPass): $url"
      else
        log_error "Open https://github.com/settings/tokens, click 'Configure SSO' on the token, and authorize the org."
      fi
      log_error "Better long-term fix: switch github.auth.method to 'app'. GitHub App installation tokens are exempt from SAML SSO authorization."
      ;;
    *partial-results*)
      local orgs; orgs=$(printf '%s' "$sso_header" | sed -n 's/.*organizations=\([0-9,]*\).*/\1/p')
      log_error "Results were TRUNCATED: the token is not SSO-authorized for org id(s) ${orgs:-unknown}."
      log_error "Repos in those orgs were silently omitted. Authorize the token or use method=app."
      ;;
  esac
  return 0
}

# Verify the credential works and report what it can see.
auth_whoami() {
  local api; api=$(cfg '.github.api_url' 'https://api.github.com')
  local body hdr code
  hdr=$(tmp_file hdr); body=$(tmp_file body)

  if [[ "$GHSCAN_AUTH_METHOD" == "app" ]]; then
    auth_curl -sS -D "$hdr" -o "$body" \
      -H "Accept: application/vnd.github+json" "$api/installation/repositories?per_page=1"
    code=$(awk 'toupper($1) ~ /^HTTP/ {c=$2} END{print c}' "$hdr")
    [[ "$code" == "200" ]] || { jq -r '.message // empty' "$body" >&2; die "installation token rejected (HTTP $code)"; }
    local n; n=$(jq -r '.total_count // 0' "$body")
    log_ok "authenticated as GitHub App installation; $n repositories visible"
    printf '%s' "$n"
    return 0
  fi

  auth_curl -sS -D "$hdr" -o "$body" "$api/$(provider_call whoami_path)"
  code=$(awk 'toupper($1) ~ /^HTTP/ {c=$2} END{print c}' "$hdr")
  local sso; sso=$(grep -i '^x-github-sso:' "$hdr" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true)
  [[ -n "$sso" ]] && auth_explain_sso "$sso"
  if [[ "$code" != "200" ]]; then
    jq -r '.message // empty' "$body" >&2
    die "token rejected (HTTP $code)"
  fi
  local login; login=$(jq -r "$(provider_call whoami_field)" "$body")
  local scopes; scopes=$(grep -i '^x-oauth-scopes:' "$hdr" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true)
  log_ok "authenticated as $login${scopes:+ (scopes: $scopes)}"
  if [[ -n "$scopes" && "$scopes" != *repo* ]]; then
    log_warn "token scopes do not include 'repo' - private repositories will be invisible"
  fi
  printf '%s' "$login"
}
