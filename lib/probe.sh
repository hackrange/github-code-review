#!/usr/bin/env bash
# `ghscan check --probe` calls each endpoint the scanner uses and reports what
# the token can actually reach, plus the permission name to fix a gap.
# shellcheck shell=bash

# endpoint | permission needed | what it gives ghscan
_PROBE_REPO_ENDPOINTS=(
  "|Metadata: read|repository metadata"
  "/branches|Contents: read|branch list"
  "/license|Metadata: read|repository license"
  "/commits/HEAD|Contents: read|commit author lookup"
  "/collaborators?per_page=1|Metadata: read|who has access"
  "/teams|Administration: read|team access"
  "/keys|Administration: read|deploy keys"
  "/invitations|Administration: read|pending invitations"
  "/pulls?state=all&per_page=1|Pull requests: read|pull history"
  "/dependabot/alerts?per_page=1|Dependabot alerts: read|dependency vulnerabilities"
  "/secret-scanning/alerts?per_page=1|Secret scanning alerts: read|GHAS secret findings"
  "/code-scanning/alerts?per_page=1|Code scanning alerts: read|CodeQL findings"
  "/dependency-graph/sbom|Contents: read|SBOM fallback"
  "/traffic/clones|Administration: read|clone traffic"
)

_PROBE_ORG_ENDPOINTS=(
  "|Metadata: read|organization metadata"
  "/repos?per_page=1|Metadata: read|repository listing"
  "/members?per_page=1|Members: read|org members"
  "/outside_collaborators?per_page=1|Members: read|outside collaborators"
)

_probe_one() {
  local url="$1" perm="$2" what="$3" label="$4"
  local hdr body code sso msg verdict color
  hdr=$(tmp_file phdr); body=$(tmp_file pbody)
  auth_curl -sS -D "$hdr" -o "$body" --max-time 30 \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" "$url" >/dev/null 2>&1 || true
  code=$(awk 'toupper($1) ~ /^HTTP/ {c=$2} END{print c+0}' "$hdr" 2>/dev/null || echo 0)
  sso=$(grep -ci '^x-github-sso:' "$hdr" 2>/dev/null || true)
  msg=$(jq -r '.message // empty' "$body" 2>/dev/null | head -c 40)

  # A 404 on /license just means the repo has no LICENSE file.
  if [[ "$code" == "404" && "$url" == */license ]]; then
    printf '  %s%-14s%s %-38s %-28s %s\n' "$C_DIM" "no license" "$C_RST" "$label" "$perm" "$what"
    return 0
  fi

  # GitHub says so in the body when a feature is switched off, which is a very
  # different problem from a missing permission.
  if [[ "$code" == "403" || "$code" == "404" ]] \
     && grep -qiE 'are disabled|is disabled|must be enabled|not enabled' "$body" 2>/dev/null; then
    printf '  %s%-14s%s %-38s %-28s %s\n' "$C_YEL" "feature off" "$C_RST" "$label" "$perm" "$what"
    return 0
  fi

  case "$code" in
    200|201|204)
      if [[ "$sso" != "0" ]]; then
        verdict="SSO-TRUNCATED"; color="$C_RED"
      else
        verdict="ok"; color="$C_GRN"
      fi ;;
    403) verdict="forbidden"; color="$C_YEL" ;;
    404) verdict="no access"; color="$C_YEL" ;;
    401) verdict="bad token"; color="$C_RED" ;;
    5*)  verdict="transient"; color="$C_DIM" ;;
    *)   verdict="HTTP $code"; color="$C_YEL" ;;
  esac

  printf '  %s%-14s%s %-38s %-28s %s\n' \
    "$color" "$verdict" "$C_RST" "$label" "$perm" "$what"
  [[ "$verdict" == "ok" ]]
}

probe_run() {
  local repo="$1" org="$2"
  local api; api=$(cfg '.github.api_url' 'https://api.github.com')

  printf '\n  %-14s %-38s %-28s %s\n' "RESULT" "ENDPOINT" "PERMISSION NEEDED" "GIVES GHSCAN"
  printf '  %-14s %-38s %-28s %s\n' "------" "--------" "-----------------" "------------"

  if [[ -n "$org" ]]; then
    printf '\n  organization: %s\n' "$org"
    local e path perm what
    for e in "${_PROBE_ORG_ENDPOINTS[@]}"; do
      IFS='|' read -r path perm what <<< "$e"
      _probe_one "${api}/orgs/${org}${path}" "$perm" "$what" "/orgs/{org}${path%%\?*}" || true
    done
  fi

  if [[ -n "$repo" ]]; then
    printf '\n  repository: %s\n' "$repo"
    local e path perm what
    for e in "${_PROBE_REPO_ENDPOINTS[@]}"; do
      IFS='|' read -r path perm what <<< "$e"
      _probe_one "${api}/repos/${repo}${path}" "$perm" "$what" "/repos/{repo}${path%%\?*}" || true
    done
  fi

  printf '\n  %-14s %s\n' "ok" "works today"
  printf '  %-14s %s\n' "no license" "repository has no LICENSE file, nothing to fix"
  printf '  %-14s %s\n' "transient" "GitHub 5xx, retry before treating it as a problem"
  printf '  %-14s %s\n' "no access"  "grant the permission, or the token cannot see this repo at all"
  printf '  %-14s %s\n' "forbidden"  "the token lacks this permission"
  printf '  %-14s %s\n' "feature off" "permission is fine, the feature is switched off on the repository"
  printf '  %-14s %s\n' "SSO-TRUNCATED" "results silently incomplete, authorize the token for SAML SSO"
  echo
}
