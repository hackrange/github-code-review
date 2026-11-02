#!/usr/bin/env bash
# Fail when a severity has gone up over a window.  Good for a weekly job.
#
#   gcr-trend-guard.sh [-r org/name] [-o org] [-d 7|30|90|365] [-s critical]
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

repo="" org="" days=30 level="critical"
while (( $# )); do
  case "$1" in
    -r|--repo) repo="$2"; shift 2 ;;
    -o|--org) org="$2"; shift 2 ;;
    -d|--days) days="$2"; shift 2 ;;
    -s|--severity) level="$2"; shift 2 ;;
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done
[[ -z "$org" ]] && repo="$(gcr_default_repo "$repo")"

answer="$(gcr_get /trends "days=$days" "repo=$repo" "org=$org")" || exit 3
if (( $(jq '.series | length' <<<"$answer") == 0 )); then
  echo "No trend data for that filter yet."; exit 0
fi
first="$(jq -r --arg s "$level" '.series[0][$s]' <<<"$answer")"
last="$(jq -r --arg s "$level" '.series[-1][$s]' <<<"$answer")"
echo "$level over $days day(s): $first -> $last"
jq -r '.series[] | "  \(.day)  critical \(.critical)  high \(.high)  medium \(.medium)  total \(.total)"' <<<"$answer" | tail -10

gcr_summary "### $level findings, last $days day(s)

$first on $(jq -r '.series[0].day' <<<"$answer"), $last on $(jq -r '.series[-1].day' <<<"$answer")."

if (( last > first )); then
  [[ "${GITHUB_ACTIONS:-}" == true ]] && echo "::error title=Findings are rising::$level went from $first to $last"
  exit 1
fi
