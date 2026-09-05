#!/usr/bin/env bash
# One name per detector, whichever engine found it.
#
# See config/detector-aliases.json for why.  Everything that turns an engine's
# output into a finding runs the same function over the name, so the database
# gets one spelling and a rule level decision written once actually covers it.
# shellcheck shell=bash

# detector_alias_map -> the alias object, or {} if the file is unreadable.
#
# A missing or broken file must not stop a scan.  Without it every name comes
# out kebab cased, which is where this was before the table existed.
detector_alias_map() {
  local path="${GHSCAN_HOME:-.}/config/detector-aliases.json"
  [[ -r "$path" ]] || { printf '{}'; return 0; }
  jq -c '.aliases // {}' "$path" 2>/dev/null || printf '{}'
}

# The jq side, shared so the engines cannot drift apart.
#
#   PrivateKey  -> private-key      the camel case split
#   private-key -> private-key      already there
#   JWT         -> jwt              an acronym on its own
#   SlackWebhook-> slack-webhook-url the table, because the words differ
read -r -d '' JQ_CANON_DETECTOR <<'JQ' || true
def canon_detector($aliases):
  (. // "" | tostring) as $raw
  | if ($raw | length) == 0 then "unknown"
    else
      ($raw | ascii_downcase | gsub("[^a-z0-9]"; "")) as $key
      | if ($aliases | has($key)) then $aliases[$key]
        else ($raw
              | gsub("(?<a>[A-Z]+)(?<b>[A-Z][a-z])"; "\(.a)-\(.b)")
              | gsub("(?<a>[a-z0-9])(?<b>[A-Z])"; "\(.a)-\(.b)")
              | ascii_downcase
              | gsub("[^a-z0-9]+"; "-")
              | sub("^-+"; "") | sub("-+$"; ""))
        end
    end;
JQ
