#!/usr/bin/env bash
# Look after one exception: show it, change it, withdraw it, and for
# administrators revoke, approve or reject it.
#
#   gcr-exception.sh show     -i ID
#   gcr-exception.sh list     [-s requested|approved|rejected|revoked|expired] [-f FINDING_ID]
#   gcr-exception.sh edit     -i ID [-m "reason, 20+ characters"] [-e YYYY-MM-DD] [-t TICKET]
#   gcr-exception.sh withdraw -i ID      your own, waiting or approved
#   gcr-exception.sh revoke   -i ID      administrators, an approved one
#   gcr-exception.sh approve  -i ID [-n NOTE]   administrators, needs the approve scope
#   gcr-exception.sh reject   -i ID [-n NOTE]   administrators, needs the approve scope
#
# You can only see, change or withdraw your own.  Changing an approved one
# sends it back to waiting, and its finding returns to the reports until an
# administrator agrees again.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

action="${1:-}"; shift || true
id="" reason="" expires="" ticket="" note="" status="" finding=""
while (( $# )); do
  case "$1" in
    -i|--id) id="$2"; shift 2 ;;
    -m|--reason) reason="$2"; shift 2 ;;
    -e|--expires) expires="$2"; shift 2 ;;
    -t|--ticket) ticket="$2"; shift 2 ;;
    -n|--note) note="$2"; shift 2 ;;
    -s|--status) status="$2"; shift 2 ;;
    -f|--finding) finding="$2"; shift 2 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done

need_id() { [[ "$id" =~ ^[0-9]+$ ]] || { echo "Give -i EXCEPTION_ID." >&2; exit 3; }; }
said() { jq -r --arg w "$1" '"Exception \(.id) on finding \(.finding) \($w), now \(.status)."'; }

case "$action" in
  show)
    need_id; gcr_get "/exceptions/$id" | jq . ;;
  list)
    gcr_get "/exceptions" "status=$status" "finding=$finding" "limit=1000" \
      | jq -r '.exceptions[] | [.id, .finding, .status, (.expires_at // "")[:10], .repository, .reason[:50]] | @tsv' ;;
  edit)
    need_id
    body="$(jq -n --arg r "$reason" --arg e "$expires" --arg t "$ticket" \
              '{} + (if $r != "" then {reason:$r} else {} end)
                  + (if $e != "" then {expires:$e} else {} end)
                  + (if $t != "" then {ticket:$t} else {} end)')"
    [[ "$body" != "{}" ]] || { echo "Give -m, -e or -t to change." >&2; exit 3; }
    gcr_patch "/exceptions/$id" "$body" | said "changed" || exit 3 ;;
  withdraw)
    need_id; gcr_post "/exceptions/$id/withdraw" '{}' | said "withdrawn" || exit 3 ;;
  revoke)
    need_id; gcr_post "/exceptions/$id/revoke" '{}' | said "revoked" || exit 3 ;;
  approve|reject)
    need_id
    gcr_post "/exceptions/$id/$action" "$(jq -n --arg n "$note" '{note:$n}')" \
      | said "${action%e}ed" || exit 3 ;;
  *) sed -n '2,16p' "$0"; exit 3 ;;
esac
