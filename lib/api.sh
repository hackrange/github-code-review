#!/usr/bin/env bash
# GitHub REST client. Handles pagination, rate limits, and SSO errors.
# Everything here is a GET. The only write in the whole codebase is the
# installation-token POST in auth.sh.
# shellcheck shell=bash

GHSCAN_API_LAST_CODE=0
GHSCAN_API_LAST_SSO=""
GHSCAN_SSO_TRUNCATED="${GHSCAN_SSO_TRUNCATED:-0}"

_api_url() {
  local p="$1" api
  api=$(cfg '.github.api_url' 'https://api.github.com')
  case "$p" in
    http://*|https://*) printf '%s' "$p" ;;
    /*) printf '%s%s' "${api%/}" "$p" ;;
    *)  printf '%s/%s' "${api%/}" "$p" ;;
  esac
}

# Rate limiting.
#
# GitHub gives a PAT 5000 requests an hour, reset on the hour. Three things
# matter for a long scan: parallel workers share one budget so they have to
# coordinate through a file, the wait for a reset can be a full hour so a
# 15 minute cap is useless, and it is better to slow down early than to stall
# at zero. State lives in one flock-protected file that every worker updates.

_rl_state() { printf '%s' "${GHSCAN_RL_STATE:-${GHSCAN_TMPROOT:-/tmp}/ratelimit.json}"; }

_rl_lock_do() {
  local f; f="$(_rl_state).lock"
  if have_cmd flock; then
    ( flock -w 30 9 || true; "$@" ) 9>"$f"
  else
    "$@"
  fi
}

_rl_write() {
  local limit="$1" remaining="$2" reset="$3"
  jq -cn --argjson l "$limit" --argjson r "$remaining" --argjson x "$reset" \
     --argjson now "$(date +%s)" \
     '{limit:$l, remaining:$r, reset:$x, updated_at:$now}' > "$(_rl_state).tmp" 2>/dev/null \
    && mv -f "$(_rl_state).tmp" "$(_rl_state)" 2>/dev/null || true
}

# Record what a response told us about the budget.
_rl_record() {
  local hdr="$1"
  local limit remaining reset
  limit=$(grep -i '^x-ratelimit-limit:'     "$hdr" | head -1 | tr -dc '0-9' || true)
  remaining=$(grep -i '^x-ratelimit-remaining:' "$hdr" | head -1 | tr -dc '0-9' || true)
  reset=$(grep -i '^x-ratelimit-reset:'     "$hdr" | head -1 | tr -dc '0-9' || true)
  [[ -z "$remaining" || -z "$reset" ]] && return 0
  [[ -z "$limit" ]] && limit=5000
  _rl_lock_do _rl_write "$limit" "$remaining" "$reset"
}

_rl_jitter() {
  local max; max=$(cfg_num '.rate_limit.jitter_sec' 3)
  (( max <= 0 )) && { echo 0; return; }
  echo $(( RANDOM % (max + 1) ))
}

# Called before every request. Sleeps when the budget is tight so we glide into
# the reset instead of slamming into it.
_rl_pace() {
  local st; st=$(_rl_state)
  [[ -s "$st" ]] || return 0

  local limit remaining reset now
  limit=$(jq -r '.limit // 5000'    "$st" 2>/dev/null || echo 5000)
  remaining=$(jq -r '.remaining // 5000' "$st" 2>/dev/null || echo 5000)
  reset=$(jq -r '.reset // 0'       "$st" 2>/dev/null || echo 0)
  now=$(date +%s)

  local minrem maxwait
  minrem=$(cfg_num '.rate_limit.min_remaining' 100)
  maxwait=$(cfg_num '.rate_limit.max_sleep_sec' 3900)

  # Out of budget: wait for the actual reset, however long that is.
  if (( remaining <= minrem )); then
    cfg_bool '.rate_limit.sleep_on_exhaustion' true || return 0
    local wait=$(( reset - now + 5 + $(_rl_jitter) ))
    (( wait < 0 )) && wait=0
    (( wait > maxwait )) && wait=$maxwait
    if (( wait > 0 )); then
      log_warn "rate limit budget spent (remaining=$remaining). Sleeping $(( wait / 60 ))m $(( wait % 60 ))s until reset."
      sleep "$wait"
    fi
    return 0
  fi

  cfg_bool '.rate_limit.adaptive_pacing' true || return 0

  # Below the comfort line, spread what is left across the time remaining.
  local frac_num frac_den
  frac_num=$(cfg '.rate_limit.pace_below_fraction' '0.25')
  frac_den=$(awk -v l="$limit" -v f="$frac_num" 'BEGIN{printf "%d", l*f}')
  (( remaining >= frac_den )) && return 0

  local secs_left=$(( reset - now ))
  (( secs_left <= 0 )) && return 0
  local interval; interval=$(awk -v s="$secs_left" -v r="$remaining" 'BEGIN{printf "%.2f", (r>0? s/r : 0)}')
  awk -v i="$interval" 'BEGIN{exit !(i > 0.2)}' || return 0

  local cap; cap=$(cfg_num '.rate_limit.max_pace_sleep_sec' 30)
  interval=$(awk -v i="$interval" -v c="$cap" 'BEGIN{printf "%.2f", (i>c? c : i)}')
  log_trace "pacing: remaining=$remaining, ${secs_left}s to reset, sleeping ${interval}s"
  sleep "$interval"
}

# Secondary limits are separate from the hourly budget. GitHub asks for a
# specific backoff, and ignoring it gets you blocked harder.
_api_handle_secondary() {
  local hdr="$1" body="$2" attempt="$3"
  local retry_after maxwait
  maxwait=$(cfg_num '.rate_limit.max_sleep_sec' 3900)
  retry_after=$(grep -i '^retry-after:' "$hdr" | head -1 | tr -dc '0-9' || true)

  if [[ -n "$retry_after" ]] && (( retry_after > 0 )); then
    (( retry_after > maxwait )) && retry_after=$maxwait
    log_warn "secondary rate limit; GitHub asked for ${retry_after}s, waiting"
    sleep $(( retry_after + $(_rl_jitter) ))
    return 0
  fi

  # No Retry-After but the body says secondary limit: back off exponentially.
  if grep -qiE 'secondary rate limit|abuse detection' "$body" 2>/dev/null; then
    local base; base=$(cfg_num '.rate_limit.secondary_backoff_sec' 60)
    local wait=$(( base * attempt + $(_rl_jitter) ))
    (( wait > maxwait )) && wait=$maxwait
    log_warn "secondary rate limit (attempt $attempt); backing off ${wait}s"
    sleep "$wait"
    return 0
  fi
  return 1
}

# Primary budget exhausted, signalled by a 403/429 with remaining=0.
_api_handle_primary() {
  local hdr="$1"
  local remaining reset now wait maxwait
  remaining=$(grep -i '^x-ratelimit-remaining:' "$hdr" | head -1 | tr -dc '0-9' || true)
  reset=$(grep -i '^x-ratelimit-reset:' "$hdr" | head -1 | tr -dc '0-9' || true)
  [[ -z "$remaining" || -z "$reset" ]] && return 1
  (( remaining > 0 )) && return 1

  cfg_bool '.rate_limit.sleep_on_exhaustion' true || {
    log_warn "rate limit exhausted and sleeping is disabled"
    return 1
  }
  maxwait=$(cfg_num '.rate_limit.max_sleep_sec' 3900)
  now=$(date +%s)
  wait=$(( reset - now + 5 + $(_rl_jitter) ))
  (( wait < 0 )) && wait=0
  (( wait > maxwait )) && wait=$maxwait
  log_warn "rate limit exhausted. Sleeping $(( wait / 60 ))m $(( wait % 60 ))s until reset at $(date -u -d "@$reset" +%H:%M:%SZ 2>/dev/null || echo "$reset")."
  sleep "$wait"
  return 0
}

# What is left, for logging and the preflight estimate.
rate_limit_snapshot() {
  local st; st=$(_rl_state)
  if [[ -s "$st" ]]; then cat "$st"; else echo '{}'; fi
}

# api_get <path-or-url> [extra curl args...]
# Body -> stdout. Status in GHSCAN_API_LAST_CODE. Returns non-zero on failure.
api_get() {
  local path="$1"; shift
  local url; url=$(_api_url "$path")
  local hdr body attempts delay i
  hdr=$(tmp_file hdr); body=$(tmp_file body)
  attempts=$(cfg_num '.rate_limit.retries' 4)
  delay=$(cfg_num '.rate_limit.retry_base_delay_sec' 2)

  for (( i=1; i<=attempts; i++ )); do
    : > "$hdr"; : > "$body"
    _rl_pace
    # Whatever this host wants on every request.  Built as an array rather
    # than a string: a header has spaces in it, and word splitting would tear
    # it into separate arguments.
    local -a api_headers=()
    local api_header
    while IFS= read -r api_header; do
      [[ -n "$api_header" ]] && api_headers+=(-H "$api_header")
    done < <(provider_call api_headers)

    auth_curl -sS --fail-with-body --location --max-time 120 \
      -D "$hdr" -o "$body" \
      "${api_headers[@]}" \
      -H "User-Agent: ghscan" \
      "$@" "$url" >/dev/null 2>&1
    local curl_rc=$?
    GHSCAN_API_LAST_CODE=$(awk 'toupper($1) ~ /^HTTP/ {c=$2} END{print c+0}' "$hdr")
    _rl_record "$hdr"

    GHSCAN_API_LAST_SSO=$(grep -i '^x-github-sso:' "$hdr" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true)
    if [[ -n "$GHSCAN_API_LAST_SSO" ]]; then
      GHSCAN_SSO_TRUNCATED=1
      auth_explain_sso "$GHSCAN_API_LAST_SSO" || true
    fi

    case "$GHSCAN_API_LAST_CODE" in
      200|201|204)
        cat "$body"
        cp "$hdr" "$GHSCAN_TMPROOT/last_headers" 2>/dev/null || true
        return 0
        ;;
      401)
        log_error "HTTP 401 for $url - credential invalid or expired"
        jq -r '.message // empty' "$body" >&2 2>/dev/null || true
        return 1
        ;;
      403|429)
        if _api_handle_secondary "$hdr" "$body" "$i"; then continue; fi
        if _api_handle_primary "$hdr"; then continue; fi
        log_debug "HTTP $GHSCAN_API_LAST_CODE for $url: $(jq -r '.message // empty' "$body" 2>/dev/null)"
        return 1
        ;;
      404)
        log_debug "HTTP 404 for $url"
        return 1
        ;;
      5*)
        log_debug "HTTP $GHSCAN_API_LAST_CODE for $url (attempt $i/$attempts)"
        sleep "$delay"; delay=$(( delay * 2 ))
        continue
        ;;
      0)
        log_debug "curl transport error rc=$curl_rc for $url (attempt $i/$attempts)"
        sleep "$delay"; delay=$(( delay * 2 ))
        continue
        ;;
      *)
        log_debug "HTTP $GHSCAN_API_LAST_CODE for $url"
        return 1
        ;;
    esac
  done
  log_warn "giving up on $url after $attempts attempts"
  return 1
}

# api_paginate <path> [per_page]  -> single JSON array of all items
# Handles both bare-array responses and {items:[...]} search-style responses.
api_paginate() {
  local path="$1" per="${2:-100}"
  local url sep out page_body next acc
  case "$path" in *\?*) sep='&' ;; *) sep='?' ;; esac
  url=$(_api_url "${path}${sep}per_page=${per}")
  acc=$(tmp_file acc)
  echo '[]' > "$acc"
  # Reused for every page rather than one temp file per page: a thousand-page
  # walk would otherwise leave a thousand files behind.
  local chunk_f; chunk_f=$(tmp_file chunk)

  local guard=0
  while [[ -n "$url" ]]; do
    (( guard++ > 1000 )) && { log_warn "pagination guard tripped for $path"; break; }
    page_body=$(api_get "$url") || return 1

    local chunk
    chunk=$(printf '%s' "$page_body" | jq -c 'if type=="array" then . elif has("items") then .items elif has("repositories") then .repositories elif has("sboms") then .sboms else [.] end' 2>/dev/null) || chunk='[]'
    # A page of a hundred repositories is far past what a single argument
    # holds.  On the command line this failed with an empty result and a zero
    # exit, so the org came back as "0 repositories in scope" and the report
    # left them out without ever saying why.  File, and shout if it still fails
    # rather than quietly reporting a short list.
    printf '%s' "${chunk:-[]}" > "$chunk_f"
    if ! jq -c --slurpfile c "$chunk_f" '. + $c[0]' "$acc" > "${acc}.new"; then
      log_error "could not accumulate a page of $path; refusing to report a partial list"
      return 1
    fi
    mv "${acc}.new" "$acc"

    next=""
    if [[ -f "$GHSCAN_TMPROOT/last_headers" ]]; then
      # The last page has no Link header, so a failure here is normal.
      next=$(grep -i '^link:' "$GHSCAN_TMPROOT/last_headers" 2>/dev/null | tr ',' '\n' \
             | grep 'rel="next"' | sed -n 's/.*<\([^>]*\)>.*/\1/p' | head -1 || true)
    fi
    url="$next"
  done
  cat "$acc"
}

# api_get_quiet <path> -> body on success, empty on any failure (no noise).
api_get_quiet() {
  api_get "$1" 2>/dev/null || printf ''
}

api_rate_limit_status() {
  api_get_quiet '/rate_limit' | jq -c '{
    core: (.resources.core // {}),
    graphql: (.resources.graphql // {}),
    code_search: (.resources.code_search // {})
  }' 2>/dev/null || echo '{}'
}

# Rough request cost per repo, from what the enabled stages actually call.
rate_limit_preflight() {
  local n_repos="$1" n_orgs="${2:-1}"
  cfg_bool '.rate_limit.preflight_estimate' true || return 0

  local per=0
  cfg_bool '.scan.secrets.enabled' true && per=$(( per + 3 ))          # alerts, locations, commit lookups
  cfg_bool '.scan.sbom.enabled' true   && per=$(( per + 2 ))           # license, dependency graph
  cfg_bool '.scan.access.enabled' true && per=$(( per + 6 ))           # collaborators x2, teams, branches, keys, invitations
  cfg_bool '.scan.pull_history.enabled' true && per=$(( per + 3 ))     # pulls pages, clone traffic
  cfg_bool '.scan.vulnerabilities.enabled' true && per=$(( per + 2 ))  # dependabot, code scanning
  per=$(( per + 1 ))                                                   # repo metadata

  local est=$(( n_repos * per + n_orgs * 4 + 5 ))

  local snap limit remaining
  snap=$(api_rate_limit_status)
  limit=$(printf '%s' "$snap" | jq -r '.core.limit // empty')
  remaining=$(printf '%s' "$snap" | jq -r '.core.remaining // empty')

  # Not every host publishes a budget.  GitLab has no /rate_limit endpoint at
  # all, and a self managed instance often has limiting switched off entirely,
  # so these come back empty.  A missing budget used to divide by zero and take
  # the whole scan down before it had cloned anything.
  if [[ ! "$limit" =~ ^[0-9]+$ ]] || (( limit <= 0 )); then
    log_debug "$(provider_name) does not publish a request budget; skipping the preflight estimate"
    log_debug "git clone traffic is not counted against any API rate limit"
    return 0
  fi
  [[ "$remaining" =~ ^[0-9]+$ ]] || remaining="$limit"

  log_info "preflight: about $est API requests for $n_repos repositories (~$per each); $remaining of $limit left this hour"

  if (( est > remaining )); then
    local hours=$(( (est + limit - 1) / limit ))
    log_warn "this scan needs more requests than one hourly window allows."
    log_warn "it will pause and resume across roughly ${hours} reset window(s). Leave it running; nothing is lost."
  fi
  # Cloning is git, not the REST API, so it never touches this budget.
  log_debug "git clone traffic is not counted against the API rate limit"
  return 0
}
