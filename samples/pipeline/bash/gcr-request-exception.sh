#!/usr/bin/env bash
# Ask for an exception on one finding.  It waits for an administrator to
# approve it in the web app, so this never takes anything out of a report
# on its own.
#
#   gcr-request-exception.sh -i FINDING_ID -e YYYY-MM-DD -m "reason, 20+ characters" [-t TICKET] [--not-deployed]
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

id="" expires="" reason="" ticket="" category=""
while (( $# )); do
  case "$1" in
    -i|--id) id="$2"; shift 2 ;;
    -e|--expires) expires="$2"; shift 2 ;;
    -m|--reason) reason="$2"; shift 2 ;;
    -t|--ticket) ticket="$2"; shift 2 ;;
    --not-deployed) category="not_deployed"; shift ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done
[[ "$id" =~ ^[0-9]+$ && -n "$expires" && -n "$reason" ]] \
  || { echo "Give -i FINDING_ID, -e YYYY-MM-DD and -m REASON." >&2; exit 3; }

body="$(jq -n --arg r "$reason" --arg e "$expires" --arg t "$ticket" --arg c "$category" \
          '{reason:$r, expires:$e, ticket:$t, category:$c}')"
answer="$(gcr_post "/findings/$id/exceptions" "$body")" || exit 3
jq -r '"Exception \(.id) on finding \(.finding) is \(.status).  An administrator approves it in the web app."' <<<"$answer"
