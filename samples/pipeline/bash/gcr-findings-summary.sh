#!/usr/bin/env bash
# Count open findings for a repository by severity, and optionally fail
# when there are too many of one severity.
#
#   gcr-findings-summary.sh [-r org/name] [-b branch] [--max-critical N] [--max-high N] [--csv FILE]
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

repo="" branch="" max_critical="" max_high="" csv=""
while (( $# )); do
  case "$1" in
    -r|--repo) repo="$2"; shift 2 ;;
    -b|--branch) branch="$2"; shift 2 ;;
    --max-critical) max_critical="$2"; shift 2 ;;
    --max-high) max_high="$2"; shift 2 ;;
    --csv) csv="$2"; shift 2 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done
repo="$(gcr_default_repo "$repo")"
[[ -n "$repo" ]] || { echo "Give -r org/name, or run inside GitHub Actions." >&2; exit 3; }

# Page through every finding, 1000 at a time.
all='[]' offset=0
while :; do
  page="$(gcr_get /findings "repo=$repo" "branch=$branch" "limit=1000" "offset=$offset")" || exit 3
  all="$(jq -s '.[0] + .[1].findings' <(printf '%s' "$all") <(printf '%s' "$page"))"
  offset="$(jq length <<<"$all")"
  (( offset >= $(jq .total <<<"$page") )) && break
  (( $(jq '.count' <<<"$page") == 0 )) && break
done

counts="$(jq 'reduce .[] as $f ({critical:0,high:0,medium:0,low:0,info:0,unknown:0}; .[$f.severity] += 1)' <<<"$all")"
echo "$repo${branch:+ @ $branch}: $(jq length <<<"$all") open finding(s)"
jq -r 'to_entries[] | "  \(.key): \(.value)"' <<<"$counts"

if [[ -n "$csv" ]]; then
  jq -r '(["id","vuln_id","severity","kind","branch","file","title","package","version","fixed_in"] | @csv),
         (.[] | [.id, .vuln_id, .severity, .kind, .branch, (if .file == "" then (.package.declared_in // "" | ltrimstr("/")) else .file end), .title,
                 (.package.name // ""), (.package.version // ""), (.package.fixed_in // "")] | @csv)' \
     <<<"$all" > "$csv"
  echo "Wrote $csv"
fi

gcr_summary "$(jq -r --arg r "$repo" '"### Open findings in `\($r)`\n\n| critical | high | medium | low | info |\n|---|---|---|---|---|\n| \(.critical) | \(.high) | \(.medium) | \(.low) | \(.info) |"' <<<"$counts")"

rc=0
if [[ -n "$max_critical" ]] && (( $(jq .critical <<<"$counts") > max_critical )); then
  echo "More than $max_critical critical finding(s)." >&2; rc=1; fi
if [[ -n "$max_high" ]] && (( $(jq .high <<<"$counts") > max_high )); then
  echo "More than $max_high high finding(s)." >&2; rc=1; fi
exit $rc
