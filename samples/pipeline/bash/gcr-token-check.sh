#!/usr/bin/env bash
# Check the token works and warn before it expires.
#
#   gcr-token-check.sh [-w 14]
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"
warn=14
[[ "${1:-}" == "-w" ]] && warn="$2"

answer="$(gcr_get /ping)" || exit 3
jq -e '.scopes | index("reports")' >/dev/null <<<"$answer" \
  || { echo "This token does not have the reports scope." >&2; exit 1; }
expires="$(jq -r '.expires_at // empty' <<<"$answer")"
if [[ -z "$expires" ]]; then echo "Token works and does not expire."; exit 0; fi
# The server keeps it in UTC and sometimes leaves the zone off.
# GNU date on Linux, BSD date on macOS.
stamp="${expires%Z}"; stamp="${stamp%%.*}"; stamp="${stamp%+00:00}"
then_s="$(date -u -d "${stamp}Z" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%S' "$stamp" +%s)"
left=$(( ( then_s - $(date -u +%s) ) / 86400 ))
echo "Token works.  It expires on ${expires:0:10}, in $left day(s)."
if (( left <= warn )); then
  echo "Warning: make a new token soon, on the IDE tokens page, and update wherever this one is kept." >&2
  if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    echo "::warning title=GCR token expiring::The Git Code Review token expires in $left day(s).  Make a new one and update the GCR_TOKEN secret."
  fi
fi
exit 0
