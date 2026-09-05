#!/usr/bin/env bash
# Free, open vulnerability data used to rank findings.
#
#   CISA KEV   CVEs confirmed exploited in the wild. A plain CSV.
#   EPSS       daily probability that a CVE gets exploited. Also a CSV.
#
# A CVSS score says how bad it would be. These say how likely it is. A medium
# that is on the KEV list matters more than a critical that nobody exploits.
# shellcheck shell=bash

_ti_dir() { printf '%s' "${GHSCAN_TI_CACHE:-${HOME:-/tmp}/.cache/ghscan/intel}"; }

_ti_fresh() {
  local f="$1" max_age_h="$2"
  [[ -s "$f" ]] || return 1
  local age; age=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) ) / 3600 ))
  (( age < max_age_h ))
}

# Pull both feeds, cache them, and turn them into lookup JSON.
threat_intel_refresh() {
  cfg_bool '.scan.threat_intel.enabled' true || return 0
  local dir; dir=$(_ti_dir); mkdir -p "$dir" || return 1
  local max_age; max_age=$(cfg_num '.scan.threat_intel.max_age_hours' 24)

  local kev_csv="$dir/kev.csv" kev_json="$dir/kev.json"
  if ! _ti_fresh "$kev_json" "$max_age"; then
    log_info "refreshing CISA Known Exploited Vulnerabilities catalog"
    if curl -sSfL --max-time 120 "$(cfg '.scan.threat_intel.kev_url' 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv')" -o "$kev_csv" 2>/dev/null; then
      # cveID is column 1, ransomware use is column 9, due date column 8.
      awk -F',' 'NR>1 && $1 ~ /^CVE-/ {print $1"\t"$5"\t"$8"\t"$9}' "$kev_csv" \
        | jq -R -s -c 'split("\n") | map(select(length>0) | split("\t"))
                       | map({key: .[0], value: {kev: true, added: .[1], due: .[2],
                                                 ransomware: (.[3] == "Known")}}) | from_entries' \
        > "$kev_json" 2>/dev/null || echo '{}' > "$kev_json"
      log_ok "KEV catalog: $(jq 'length' "$kev_json") exploited CVEs"
    else
      log_warn "could not fetch the KEV catalog, continuing without it"
      [[ -s "$kev_json" ]] || echo '{}' > "$kev_json"
    fi
  fi

  local epss_gz="$dir/epss.csv.gz" epss_json="$dir/epss.json"
  if ! _ti_fresh "$epss_json" "$max_age"; then
    log_info "refreshing EPSS exploit prediction scores"
    if curl -sSfL --max-time 180 "$(cfg '.scan.threat_intel.epss_url' 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz')" -o "$epss_gz" 2>/dev/null; then
      # Only keep scores worth acting on; the full file is ~365k rows.
      local floor; floor=$(cfg '.scan.threat_intel.epss_min_score' '0.01')
      gunzip -c "$epss_gz" 2>/dev/null \
        | awk -F',' -v f="$floor" 'NR>2 && $1 ~ /^CVE-/ && $2+0 >= f {print $1"\t"$2"\t"$3}' \
        | jq -R -s -c 'split("\n") | map(select(length>0) | split("\t"))
                       | map({key: .[0], value: {epss: (.[1]|tonumber), percentile: (.[2]|tonumber)}})
                       | from_entries' > "$epss_json" 2>/dev/null || echo '{}' > "$epss_json"
      log_ok "EPSS scores: $(jq 'length' "$epss_json") CVEs above the score floor"
    else
      log_warn "could not fetch EPSS scores, continuing without them"
      [[ -s "$epss_json" ]] || echo '{}' > "$epss_json"
    fi
  fi
  export GHSCAN_KEV_JSON="$kev_json" GHSCAN_EPSS_JSON="$epss_json"
}

# Tag each vulnerability with exploitation data and a priority that reflects it.
threat_intel_enrich() {
  local vulns="$1"
  local kev="${GHSCAN_KEV_JSON:-}" epss="${GHSCAN_EPSS_JSON:-}"
  [[ -s "$kev"  ]] || kev=/dev/null
  [[ -s "$epss" ]] || epss=/dev/null

  printf '%s' "$vulns" | jq -c \
    --slurpfile K "$kev" --slurpfile E "$epss" '
    ($K[0] // {}) as $kev | ($E[0] // {}) as $epss
    | map(
        . as $v
        | ([ $v.id, ($v.aliases // [])[] ] | map(select(type == "string" and startswith("CVE-")))) as $cves
        | ([ $cves[] | $kev[.] // empty ] | first) as $k
        | ([ $cves[] | $epss[.] // empty ] | max_by(.epss)) as $e
        | $v + {
            known_exploited: ($k != null),
            kev_added: ($k.added // null),
            kev_due_date: ($k.due // null),
            kev_ransomware: ($k.ransomware // false),
            epss_score: ($e.epss // null),
            epss_percentile: ($e.percentile // null),
            priority: (
              if $k != null then "act-now"
              elif ($e.epss // 0) >= 0.1 then "urgent"
              elif ($v.severity // "") == "critical" then "high"
              elif ($e.epss // 0) >= 0.01 then "elevated"
              else "routine" end),
            priority_reason: (
              if $k != null then ("on the CISA exploited list since " + ($k.added // "?")
                                  + (if ($k.ransomware // false) then ", used in ransomware" else "" end))
              elif ($e.epss // 0) >= 0.1 then ("EPSS " + (($e.epss * 100 | round | tostring)) + "% chance of exploitation")
              elif ($v.severity // "") == "critical" then "critical severity, no exploitation signal"
              else "no exploitation signal" end)
          })
    | sort_by([ (if .priority == "act-now" then 0 elif .priority == "urgent" then 1
                 elif .priority == "high" then 2 elif .priority == "elevated" then 3 else 4 end),
                -(.epss_score // 0) ])' 2>/dev/null || printf '%s' "$vulns"
}
