#!/usr/bin/env bash
# Stop a deploy when the last scan found something to fix.
#
#   gcr-deploy-check.sh [-r org/name] [-b branch] [-f high] [-i package,image,build]
#                       [--allow-unknown] [--warn-only]
#
# Exit 0 pass, 1 fail, 2 the branch was never scanned, 3 the call failed.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

repo="" branch="" fail_on="high" include="" allow_unknown=0 warn_only=0
while (( $# )); do
  case "$1" in
    -r|--repo) repo="$2"; shift 2 ;;
    -b|--branch) branch="$2"; shift 2 ;;
    -f|--fail-on) fail_on="$2"; shift 2 ;;
    -i|--include) include="$2"; shift 2 ;;
    --allow-unknown) allow_unknown=1; shift ;;
    --warn-only) warn_only=1; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done
repo="$(gcr_default_repo "$repo")"; branch="$(gcr_default_branch "$branch")"
[[ -n "$repo" ]] || { echo "Give -r org/name, or run inside GitHub Actions." >&2; exit 3; }

answer="$(gcr_get /check "repo=$repo" "branch=$branch" "fail_on=$fail_on" "include=$include")" || exit 3
verdict="$(jq -r .verdict <<<"$answer")"

echo "$(tr '[:lower:]' '[:upper:]' <<<"$verdict"): $(jq -r .message <<<"$answer")"
jq -r '"  \(.repository) @ \(.branch), last scanned \(.last_scanned_at // "never")"' <<<"$answer"
jq -r '.blocking[] | "  [\(.severity)] \(.area): \(.title)  \(.file)\n      \(.fix // .why)\n      \(.link)"' <<<"$answer"

if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  # One annotation per blocking finding, on the file when there is one.
  jq -r '.blocking[] |
    def p: gsub("%";"%25") | gsub("\r";"%0D") | gsub("\n";"%0A") | gsub(":";"%3A") | gsub(",";"%2C");
    def d: gsub("%";"%25") | gsub("\r";"%0D") | gsub("\n";"%0A");
    (.file | ltrimstr("/")) as $f |
    "::error " + (if $f != "" then "file=\($f | p)," + (if .line > 0 then "line=\(.line)," else "" end) else "" end)
    + "title=\("\(.severity) \(.area): \(.title)" | p)::\("\(.fix // .why)  \(.link)" | d)"' <<<"$answer"
  gcr_summary "$(jq -r '
    "### Git Code Review deploy check: \(.verdict | ascii_upcase)\n\n\(.message)\n\n" +
    "`\(.repository)` on `\(.branch)`, last scanned \(.last_scanned_at // "never").\n\n" +
    (if (.blocking | length) > 0 then
      "| Severity | Area | Finding | File | Fix |\n|---|---|---|---|---|\n" +
      ([.blocking[] | "| \(.severity) | \(.area) | [\(.title)](\(.link)) | `\(.file)` | \(.fix // .why) |"] | join("\n"))
     else "" end)' <<<"$answer")"
fi

case "$verdict" in
  pass) exit 0 ;;
  unknown) (( allow_unknown )) && exit 0 || exit 2 ;;
  *) (( warn_only )) && exit 0 || exit 1 ;;
esac
