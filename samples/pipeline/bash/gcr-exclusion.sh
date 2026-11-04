#!/usr/bin/env bash
# Exclusions, for administrators: list them, exclude a fingerprint, and take
# one back.
#
#   gcr-exclusion.sh list   [-p FINGERPRINT] [-f FINDING_ID] [-s live|expired|revoked]
#   gcr-exclusion.sh add    -p FINGERPRINT -m "reason, 20+ characters" [-e YYYY-MM-DD] [-t TICKET]
#   gcr-exclusion.sh add    -f FINDING_ID  -m "reason" [--by-value]
#   gcr-exclusion.sh revoke -p FINGERPRINT        every rule on that value
#   gcr-exclusion.sh revoke -i EXCLUSION_ID
#
# list and revoke work with a reports token.  add needs a token with the
# approve scope.  A revoked rule is kept on the record, marked revoked, and
# what it covered comes back into the reports.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

action="${1:-}"; shift || true
id="" fingerprint="" finding="" status="" reason="" expires="" ticket="" by_value=false
while (( $# )); do
  case "$1" in
    -i|--id) id="$2"; shift 2 ;;
    -p|--fingerprint) fingerprint="$2"; shift 2 ;;
    -f|--finding) finding="$2"; shift 2 ;;
    -s|--status) status="$2"; shift 2 ;;
    -m|--reason) reason="$2"; shift 2 ;;
    -e|--expires) expires="$2"; shift 2 ;;
    -t|--ticket) ticket="$2"; shift 2 ;;
    --by-value) by_value=true; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done

table() {
  jq -r '.[] | [.id, .type, .fingerprint, "\(.organization)/\(.repository):\(.path)",
                (if .revoked then "revoked" elif .in_force then "in force" else "expired" end)] | @tsv'
}

case "$action" in
  list)
    gcr_get "/exclusions" "fingerprint=$fingerprint" "finding=$finding" \
            "status=$status" "limit=1000" | jq '.exclusions' | table ;;
  add)
    [[ -n "$reason" ]] || { echo "Give -m REASON." >&2; exit 3; }
    if [[ -n "$finding" ]]; then
      [[ "$finding" =~ ^[0-9]+$ ]] || { echo "-f is a finding number." >&2; exit 3; }
      body="$(jq -n --argjson f "$finding" --argjson v "$by_value" --arg r "$reason" \
                --arg e "$expires" --arg t "$ticket" \
                '{finding:$f, by_value:$v, reason:$r, expires:$e, ticket:$t}')"
    elif [[ -n "$fingerprint" ]]; then
      body="$(jq -n --arg p "$fingerprint" --arg r "$reason" --arg e "$expires" \
                --arg t "$ticket" '{fingerprint:$p, reason:$r, expires:$e, ticket:$t}')"
    else
      echo "Give -p FINGERPRINT or -f FINDING_ID." >&2; exit 3
    fi
    gcr_post "/exclusions" "$body" \
      | jq -r '"Exclusion \(.id) added.  \(.findings_excluded) finding(s) left the reports."' \
      || exit 3 ;;
  revoke)
    if [[ "$id" =~ ^[0-9]+$ ]]; then
      gcr_post "/exclusions/$id/revoke" '{}' | jq '[.]' | table || exit 3
    elif [[ -n "$fingerprint" ]]; then
      gcr_post "/exclusions/revoke" "$(jq -n --arg p "$fingerprint" '{fingerprint:$p}')" \
        | jq '.revoked' | table || exit 3
    else
      echo "Give -i EXCLUSION_ID or -p FINGERPRINT." >&2; exit 3
    fi
    echo "What they covered is back in the reports, unless an approved exception still holds it." ;;
  *) sed -n '2,13p' "$0"; exit 3 ;;
esac
