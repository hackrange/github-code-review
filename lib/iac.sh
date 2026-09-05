#!/usr/bin/env bash
# The configuration, read as code: Terraform, CloudFormation, Kubernetes, Helm,
# Ansible and Dockerfiles.
#
# Everything else in a scan reads what the application does.  None of it opens
# the files that decide where the application runs, so a bucket open to the
# world, a security group with 0.0.0.0/0 on it and a container running as root
# all went past without a word.  For a team with no security function that is
# likelier to end badly than any injection finding.
#
# trivy does the reading.  It is one binary, the same shape as gitleaks, syft
# and grype, and it scans a checkout that is already on disk.
# shellcheck shell=bash

# run_trivy_config <dir> <full_name> <out_json>
run_trivy_config() {
  local dir="$1" full_name="$2" out="$3"
  have_cmd trivy || {
    log_warn "trivy is not on the path, so nothing looked at the infrastructure files"
    echo '{}' > "$out"; return 0; }

  local args=(config "$dir" --format json --quiet)
  # Trivy phones home for a policy bundle on first use.  On an isolated builder
  # that is a long wait for a timeout, so the offline switch is a setting
  # rather than something to find out about.
  cfg_bool '.scan.iac.offline' false && args+=(--skip-policy-update --skip-check-update)

  local skips; skips=$(cfg_arr '.scan.iac.skip_dirs' | paste -sd, -)
  [[ -n "$skips" ]] && args+=(--skip-dirs "$skips")

  local timeout_s; timeout_s=$(cfg_num '.scan.iac.timeout_sec' 600)
  log_debug "$full_name: trivy ${args[*]}"
  with_timeout "$timeout_s" trivy "${args[@]}" > "$out" 2>"$GHSCAN_TMPROOT/trivy.log" || true
  jq -e . "$out" >/dev/null 2>&1 || {
    log_warn "$full_name: trivy produced nothing usable: $(tail -1 "$GHSCAN_TMPROOT/trivy.log" 2>/dev/null)"
    echo '{}' > "$out"; }
}

# normalize_trivy_config <in> <repo> <branch> <web> -> json array of findings
#
# The shape matches a code finding on purpose.  Everything downstream, the
# report writers, the CSV, the SARIF, the web app, already knows how to carry
# one of those, and a second shape would mean teaching all of them twice.
#
# What is deliberately dropped: trivy returns the offending source lines in
# CauseMetadata.Code, and a Terraform file is a place people put passwords.
# Nothing in here has ever put a line of somebody's source in a report and this
# is not the feature to start with.  The line number says where to look.
normalize_trivy_config() {
  local in="$1" repo="$2" branch="$3" web="$4"
  jq -c --arg repo "$repo" --arg br "$branch" --arg web "$web" '
    def aslist: if . == null then [] elif type == "array" then . else [.] end;

    # A path that is an example, a fixture or a vendored module is still a real
    # finding, it is just nobody`s to fix.  Same reasoning as the code triage:
    # nothing is dropped, everything is graded, and the reason travels with it.
    def verdict($p):
      if   ($p | test("(^|/)(examples?|_examples?)/"))        then ["third_party", "an example, not a deployed configuration"]
      elif ($p | test("(^|/)(tests?|fixtures?|testdata)/"))   then ["third_party", "test material"]
      elif ($p | test("(^|/)\\.terraform/"))                  then ["third_party", "a downloaded module"]
      elif ($p | test("(^|/)(vendor|charts|node_modules)/"))  then ["third_party", "a vendored dependency"]
      else ["review", ""] end;

    [ (.Results // [])[]
      | (.Target // "") as $target
      | (.Type // "") as $kind
      | (.Misconfigurations // [])[]
      # PASS and SKIP are the checks that were fine.  Only a FAIL is a finding.
      | select((.Status // "FAIL") == "FAIL")
      | . as $m
      | ($m.CauseMetadata // {}) as $c
      # trivy names the directory as a target as well as the files in it.  A
      # directory has no line to point at, so the file is the better anchor.
      | (if ($target == "." or $target == "") then ($c.Resource // "") else $target end) as $file
      | (verdict($file)) as $v
      | {
          organization: ($repo | split("/")[0]),
          repository: $repo,
          repository_name: ($repo | split("/")[1]),
          branch: $br,
          source: "trivy",
          category: "misconfiguration",
          finding_type: "infrastructure_as_code",
          configuration_kind: $kind,
          rule_id: ($m.ID // "unknown"),
          rule_name: ($m.ID // "unknown"),
          title: ($m.Title // ""),
          message: ($m.Message // $m.Description // ""),
          description: ($m.Description // ""),
          resolution: ($m.Resolution // ""),
          resource: ($c.Resource // ""),
          provider: ($c.Provider // ""),
          service: ($c.Service // ""),
          file: $file,
          start_line: ($c.StartLine // 0),
          end_line: ($c.EndLine // 0),
          start_column: 0,
          end_column: 0,
          severity: (($m.Severity // "UNKNOWN") | ascii_downcase
                     | if . == "critical" or . == "high" or . == "medium"
                          or . == "low" then . else "unknown" end),
          engine_severity: ($m.Severity // null),
          confidence: "high",
          references: ($m.References | aslist),
          url: (if $file == "" then $web + "/" + $repo
                else $web + "/" + $repo + "/blob/" + $br + "/" + $file
                     + (if ($c.StartLine // 0) > 0 then "#L" + (($c.StartLine // 0) | tostring) else "" end) end),
          help_url: ($m.PrimaryURL // ""),
          triage: $v[0],
          triage_reason: $v[1],
          state: "open"
        } ]
    | sort_by([ (if .severity == "critical" then 0 elif .severity == "high" then 1
                 elif .severity == "medium" then 2 else 3 end), .file, .start_line ])' \
    "$in" 2>/dev/null || echo '[]'
}
