#!/usr/bin/env bash
# Vulnerabilities from three places: grype against our SBOM, plus GitHub's
# Dependabot and code scanning alerts. Merged and deduped.
# shellcheck shell=bash

_sev_rank() {
  case "$(printf '%s' "${1:-unknown}" | tr '[:upper:]' '[:lower:]')" in
    critical) echo 5 ;; high) echo 4 ;; medium|moderate) echo 3 ;;
    low) echo 2 ;; negligible|note|info|informational) echo 1 ;; *) echo 0 ;;
  esac
}

# vulns_grype <sbom_cdx> <full_name> -> JSON array of normalized findings
vulns_grype() {
  local sbom="$1" full_name="$2"
  have_cmd grype || { log_debug "grype not installed, skipping"; echo '[]'; return; }
  [[ -s "$sbom" ]] || { echo '[]'; return; }

  local out; out=$(tmp_file grype)
  local args=(-o json -q)
  cfg_bool '.scan.vulnerabilities.grype.only_fixed' false && args+=(--only-fixed)
  cfg_bool '.scan.vulnerabilities.grype.db_auto_update' true || export GRYPE_DB_AUTO_UPDATE=false

  if ! GRYPE_CHECK_FOR_APP_UPDATE=false grype "sbom:$sbom" "${args[@]}" > "$out" 2>"$GHSCAN_TMPROOT/grype.log"; then
    log_warn "$full_name: grype failed: $(tail -2 "$GHSCAN_TMPROOT/grype.log" | tr '\n' ' ')"
    echo '[]'; return
  fi

  jq -c '[ (.matches // [])[] | {
      source: "grype",
      id: (.vulnerability.id // "UNKNOWN"),
      aliases: ([ (.relatedVulnerabilities // [])[].id ] | unique),
      severity: ((.vulnerability.severity // "unknown") | ascii_downcase),
      cvss_score: ( [ ((.vulnerability.cvss // [])[] | .metrics.baseScore), ((.relatedVulnerabilities // [])[].cvss[]? | .metrics.baseScore) ] | map(select(. != null)) | max ),
      title: (.vulnerability.description // ((.relatedVulnerabilities // [])[0].description) // null),
      package: {
        name: (.artifact.name // null),
        version: (.artifact.version // null),
        type: (.artifact.type // null),
        purl: (.artifact.purl // null),
        locations: ([ (.artifact.locations // [])[].path ] | unique)
      },
      fixed_in: ((.vulnerability.fix.versions // []) | join(", ") | select(. != "")),
      fix_state: (.vulnerability.fix.state // "unknown"),
      cvss_vector: ( [ ((.vulnerability.cvss // [])[] | .vector), ((.relatedVulnerabilities // [])[].cvss[]? | .vector) ] | map(select(. != null)) | first ),
      cwe: ( [ (.vulnerability.cwe // empty), ((.relatedVulnerabilities // [])[].cwe? // empty) ] | flatten | unique ),
      urls: (.vulnerability.urls // []),
      reference: (.vulnerability.dataSource // null),
      state: "open"
    } ]' "$out" 2>/dev/null || echo '[]'
}

# vulns_dependabot <full_name> -> JSON array
vulns_dependabot() {
  local full_name="$1"
  # Dependabot is a GitHub feature.  Calling it elsewhere returns a 404 that
  # would be read as an empty alert list, which looks like good news.
  if ! provider_supports dependabot_alerts; then
    log_debug "$(provider_name) has no dependency alerts of its own, so it is not asked for"
    echo '[]'; return 0
  fi
  local body
  body=$(api_paginate "/repos/${full_name}/dependabot/alerts?state=open" 100) || {
    log_debug "$full_name: dependabot alerts unavailable (disabled or no permission)"
    echo '[]'; return
  }
  printf '%s' "$body" | jq -c --argjson skip "$(cfg_json '.scan.vulnerabilities.ignore_states // []')" '
    [ .[]? | . as $a | (($a.state // "open")) as $st
      | select( ($skip | index($st)) == null ) | {
      source: "github_dependabot",
      id: (.security_advisory.cve_id // .security_advisory.ghsa_id // "UNKNOWN"),
      aliases: ([ (.security_advisory.identifiers // [])[].value ] | unique),
      severity: ((.security_advisory.severity // "unknown") | ascii_downcase),
      cvss_score: (.security_advisory.cvss.score // null),
      title: (.security_advisory.summary // null),
      package: {
        name: (.dependency.package.name // null),
        version: null,
        type: (.dependency.package.ecosystem // null),
        purl: null,
        locations: ([ .dependency.manifest_path // empty ])
      },
      vulnerable_range: (.security_vulnerability.vulnerable_version_range // null),
      fixed_in: (.security_vulnerability.first_patched_version.identifier // null),
      fix_state: (if .security_vulnerability.first_patched_version then "fixed" else "unknown" end),
      scope: (.dependency.scope // null),
      cvss_vector: (.security_advisory.cvss.vector_string // null),
      cwe: [ (.security_advisory.cwes // [])[].cwe_id ],
      published_at: (.security_advisory.published_at // null),
      updated_at: (.security_advisory.updated_at // null),
      reference: (.html_url // null),
      alert_number: .number,
      state: (.state // "open"),
      created_at: .created_at
    } ]' 2>/dev/null || echo '[]'
}

# vulns_code_scanning <full_name> -> JSON array (SAST findings, incl. hardcoded creds)
vulns_code_scanning() {
  local full_name="$1" web="$2"
  # Same again: an empty result here would read as "nothing wrong".
  if ! provider_supports code_scanning; then
    log_debug "$(provider_name) has no code scanning alerts, so it is not asked for"
    echo '[]'; return 0
  fi
  local body
  body=$(api_paginate "/repos/${full_name}/code-scanning/alerts?state=open" 100) || {
    log_debug "$full_name: code scanning alerts unavailable"
    echo '[]'; return
  }
  printf '%s' "$body" | jq -c '
    [ .[]? | {
      source: "github_code_scanning",
      id: (.rule.id // "UNKNOWN"),
      aliases: [],
      severity: ((.rule.security_severity_level // .rule.severity // "unknown") | ascii_downcase),
      cvss_score: null,
      title: (.rule.description // .rule.name // null),
      package: {name: null, version: null, type: "source", purl: null,
                locations: ([ .most_recent_instance.location.path // empty ])},
      file: (.most_recent_instance.location.path // null),
      start_line: (.most_recent_instance.location.start_line // null),
      branch: ((.most_recent_instance.ref // "") | sub("^refs/heads/"; "")),
      tool: (.tool.name // null),
      reference: (.html_url // null),
      alert_number: .number,
      state: (.state // "open"),
      created_at: .created_at,
      fix_state: "unknown"
    } ]' 2>/dev/null || echo '[]'
}

# vulns_merge <arr1> <arr2> ... -> deduped, severity-filtered, sorted array
# vulns_stamp <repo> <default_branch> - adds organization/repository/branch
vulns_stamp() {
  local repo="$1" branch="$2"
  jq -c --arg repo "$repo" --arg br "$branch" '
    map(. + {
      organization: ($repo | split("/")[0]),
      repository: $repo,
      branch: (.branch // $br)
    })'
}

vulns_merge() {
  # "all" (the default) keeps every severity, including unknown and negligible.
  local minsev; minsev=$(cfg '.scan.vulnerabilities.min_severity' 'all')
  local minrank
  case "$minsev" in
    all|any|none|"") minrank=0 ;;
    *) minrank=$(_sev_rank "$minsev") ;;
  esac
  jq -s -c --argjson minrank "$minrank" '
    def rank: (. // "unknown") | ascii_downcase
      | if . == "critical" then 5 elif . == "high" then 4
        elif . == "medium" or . == "moderate" then 3
        elif . == "low" then 2
        elif . == "negligible" or . == "note" or . == "info" then 1
        else 0 end;
    add
    | map(select((.severity | rank) >= $minrank or (.severity | rank) == 0))
    | group_by([ (.id // "?"), (.package.name // "?"), (.package.version // "?") ])
    | map( (.[0]) + {
        sources: (map(.source) | unique),
        references: (map(.reference) | map(select(. != null)) | unique),
        severity: (max_by(.severity | rank) | .severity)
      } )
    | sort_by([ -( .severity | rank ), (.package.name // "") ])
  ' "$@" 2>/dev/null || echo '[]'
}

# osv-scanner queries OSV.dev, which resolves npm, pypi and maven manifests
# that grype sometimes misses. Second opinion on the same tree.
vulns_osv() {
  local dir="$1" full_name="$2"
  have_cmd osv-scanner || { log_debug "osv-scanner not installed, skipping"; echo '[]'; return; }
  local out; out=$(tmp_file osv)
  ( cd "$dir" && with_timeout 600 osv-scanner scan source --format json . ) > "$out" 2>/dev/null || true
  [[ -s "$out" ]] || { echo '[]'; return; }

  jq -c '[ (.results // [])[] | .source.path as $manifest | (.packages // [])[]
           | .package as $pkg | (.vulnerabilities // [])[]
           | . as $v | {
      source: "osv",
      id: (.id // "UNKNOWN"),
      aliases: ((.aliases // []) | unique),
      severity: (
        ([ (.severity // [])[] | select(.type == "CVSS_V3") | .score ] | first) as $cv |
        ((.database_specific.severity // "") | ascii_downcase) as $ds |
        if   $ds != "" then $ds
        elif ($cv // "" | test("/C:H/I:H/A:H")) then "critical"
        else "unknown" end),
      cvss_vector: ([ (.severity // [])[] | select(.type == "CVSS_V3") | .score ] | first),
      cvss_score: null,
      title: (.summary // null),
      package: {
        name: ($pkg.name // null),
        version: ($pkg.version // null),
        type: ($pkg.ecosystem // null),
        purl: ($pkg.purl // null),
        locations: [ $manifest ]
      },
      fixed_in: ([ (.affected // [])[] | (.ranges // [])[] | (.events // [])[] | .fixed // empty ] | unique | join(", ")),
      fix_state: (if ([ (.affected // [])[] | (.ranges // [])[] | (.events // [])[] | .fixed // empty ] | length) > 0
                  then "fixed" else "unknown" end),
      cwe: ((.database_specific.cwe_ids // []) | unique),
      published_at: (.published // null),
      updated_at: (.modified // null),
      reference: ("https://osv.dev/vulnerability/" + (.id // "")),
      state: "open"
    }
    # OpenSSF publishes its malicious package database into OSV as MAL
    # advisories, so a package somebody has already reported comes back with
    # everything else and only has to be recognised.  This is not a
    # vulnerability in a package: the package is the attack, and nothing about
    # upgrading it helps.
    | if ((.id // "") | startswith("MAL-")) then
        . + {severity: "critical",
             malicious: {signal: "advisory", confidence: "confirmed",
                         reason: "reported to the OpenSSF malicious packages database",
                         evidence: (.id // ""), manifest: (.package.locations[0] // "")},
             # Whether the application imports it is the wrong question.  This
             # kind runs at install time, so "nothing calls it" is not a
             # mitigation and must not read like one.
             reachability: {verdict: "unknown",
                            reason: "a malicious package runs when it is installed, so whether the code imports it is not the question",
                            ecosystem: ((.package.type // "unknown") | tostring),
                            direct: "unknown", scope: "runtime"}}
      else . end ]' "$out" 2>/dev/null || echo '[]'
}

# vulns_malicious <dir> <full_name> -> JSON array in the vulnerability shape
#
# The half of this that can only be answered while the clone is on disk: an
# install hook that fetches and runs something, a dependency that does not come
# from a registry, a specifier that floats, and a name one edit from a popular
# one.  None of it is certain, and none of it is graded as though it were.
vulns_malicious() {
  local dir="$1" full_name="$2"
  [[ -d "$dir" ]] || { echo '[]'; return 0; }
  local py; py=$(ghscan_python)
  [[ -n "$py" ]] || { echo '[]'; return 0; }

  local raw
  raw=$("$py" "$GHSCAN_HOME/lib/malicious.py" "$dir" 2>/dev/null) || { echo '[]'; return 0; }
  [[ -n "$raw" && "$raw" != "[]" ]] || { echo '[]'; return 0; }

  printf '%s' "$raw" | jq -c '[ .[] | {
      source: "supply-chain",
      # Not a CVE and deliberately not shaped like one.  An id that looked like
      # an advisory would be looked up and not found.
      id: ("SUPPLY-" + (.signal | ascii_upcase)),
      aliases: [],
      severity: (if .confidence == "confirmed" then "critical" else "high" end),
      cvss_score: null,
      title: .reason,
      package: {name: .package, version: .version, type: .ecosystem,
                purl: null, locations: [ .manifest ]},
      fixed_in: "",
      fix_state: "unknown",
      cwe: ["CWE-1357"],
      urls: [],
      reference: null,
      state: "open",
      malicious: {signal: .signal, confidence: .confidence, reason: .reason,
                  evidence: .evidence, manifest: .manifest},
      # A supply chain signal is about how the package arrives, not about
      # whether the application calls it, so reachability has nothing to say.
      reachability: {verdict: "unknown",
                     reason: "a supply chain signal is about how the package gets here, not about whether the code calls it",
                     ecosystem: (.ecosystem // "unknown"), direct: "direct", scope: "unknown"}
    } ]' 2>/dev/null || echo '[]'
}

# vulns_reachability <findings_json> <repo_dir> -> findings with a verdict on each
#
# Most of a vulnerability count sits in packages the application never calls.
# This says which, from facts about the tree rather than a call graph: whether
# the package is asked for directly, whether it is a development dependency,
# and whether anything imports it.  Nothing is removed.  A tree it cannot read
# gives every finding `unknown`, which leaves the list exactly as it was.
vulns_reachability() {
  local findings="$1" dir="$2"
  [[ -n "$findings" && "$findings" != "[]" ]] || { printf '%s' "$findings"; return 0; }
  [[ -d "$dir" ]] || { printf '%s' "$findings"; return 0; }

  local py; py=$(ghscan_python)
  if [[ -z "$py" ]]; then
    log_debug "reachability needs python3; leaving the findings as they are"
    printf '%s' "$findings"; return 0
  fi

  local f_in; f_in=$(json_file "$findings" reach_in)
  local f_err; f_err=$(tmp_file reach_err)
  local out
  if out=$("$py" "$GHSCAN_HOME/lib/reachability.py" "$f_in" "$dir" 2>"$f_err"); then
    printf '%s' "$out"
    return 0
  fi
  # Ranking failing is not a reason to lose the findings.
  log_warn "could not work out reachability, so the findings are unranked: $(tail -1 "$f_err")"
  printf '%s' "$findings"
}
