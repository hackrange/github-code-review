#!/usr/bin/env bash
# Rolls the per-repo result files up into the final report.
# shellcheck shell=bash

report_build() {
  local results_dir="$1" meta_json="$2"
  local files=("$results_dir"/*.json)
  [[ -e "${files[0]}" ]] || { log_warn "no per-repo results to aggregate"; files=(); }

  local list; list=$(tmp_file repolist)
  if (( ${#files[@]} > 0 )); then
    jq -s -c '.' "${files[@]}" > "$list" 2>/dev/null || echo '[]' > "$list"
  else
    echo '[]' > "$list"
  fi

  # The meta now carries every organization profile and every member across the
  # whole estate, which is far too big for an argument.
  local f_meta; f_meta=$(json_file "$meta_json" meta)
  jq -c --slurpfile meta_in "$f_meta" '
    def rank: (. // "unknown") | ascii_downcase
      | if . == "critical" then 5 elif . == "high" then 4
        elif . == "medium" or . == "moderate" then 3
        elif . == "low" then 2 elif . == "negligible" or . == "note" or . == "info" then 1
        else 0 end;
    # A key has to be a string.  A finding with no detector, or a project on a
    # host that does not report a language, produces null here, and jq refuses
    # null as an object key by dying in the middle of aggregation - after every
    # repository has already been scanned.  Unknown is a fact; a dead report is
    # not.
    def tally(f): [ .[] | (f // "unknown") | tostring ]
                  | group_by(.) | map({key: .[0], value: length}) | from_entries;
    def prank: if . == "admin" then 5 elif . == "maintain" then 4
               elif . == "write" or . == "push" then 3 elif . == "triage" then 2
               elif . == "read" or . == "pull" then 1 else 0 end;

    ($meta_in[0]) as $meta
    | . as $repos
    | [ $repos[] | .secrets.reported[]? ]        as $secrets
    | [ $repos[] | .secrets.filtered[]? ]        as $filtered
    | [ $repos[] | .secrets.suppressed[]? ]      as $suppressed
    | [ $repos[] | .vulnerabilities[]? ]         as $vulns
    | [ $repos[] | .code_findings[]? ]           as $code
    | [ $repos[] | .misconfigurations[]? ]      as $iac
    | [ $repos[] | select(.status == "ok") ]     as $ok
    | [ $repos[] | select(.status != "ok") ]     as $bad

    | {
        schema_version: "1.0.0",
        tool: $meta.tool,
        organizations: ($meta.organizations // []),
        scan: ($meta.scan + {
          sso_results_truncated: (($meta.scan.sso_results_truncated // false)
                                  or any($repos[]; .sso_results_truncated == true))
        }),
        target: $meta.target,

        summary: {
          repositories: {
            in_scope:  ($repos | length),
            scanned:   ($ok | length),
            failed:    ([ $bad[] | select(.status == "failed") ] | length),
            skipped:   ([ $bad[] | select(.status == "skipped") ] | length),
            # Stopped part way, and what it had found was kept.  Counted on its
            # own because it is neither of the other two: some of this
            # repository was examined and some of it was not, and a reader who
            # is told only "scanned" or "failed" cannot tell which parts.
            incomplete: ([ $bad[] | select(.status == "partial") ] | length),
            with_secrets: ([ $repos[] | select((.secrets.reported | length) > 0) | .repository.full_name ] | unique | length),
            with_vulnerabilities: ([ $repos[] | select((.vulnerabilities | length) > 0) | .repository.full_name ] | unique | length)
          },
          branches: {
            scanned: ([ $repos[] | .branch_count // 0 ] | add // 0),
            with_secrets: ([ $secrets[] | .branches[]? ] | length)
          },
          secrets: {
            reported:                ($secrets | length),
            confirmed_live:          ([ $secrets[] | select(.verified == true) ] | length),
            unverified_probable:     ([ $secrets[] | select(.verified != true) ] | length),
            still_in_branch_heads:   ([ $secrets[] | select(.still_live_in_working_tree == true) ] | length),
            history_only:            ([ $secrets[] | select(.still_live_in_working_tree != true) ] | length),
            placeholders_filtered:   ($filtered | length),
            allowlist_suppressed:    ($suppressed | length),
            by_severity:             ($secrets | tally(.severity)),
            by_confidence:           ($secrets | tally(.confidence)),
            by_detector:             ($secrets | tally(.detector)),
            by_engine:               ([ $secrets[] | .engines[]? | (. // "unknown") | tostring ] | group_by(.) | map({key: .[0], value: length}) | from_entries),
            top_repositories:        ([ $secrets[] | .repository ] | group_by(.) | map({repository: .[0], count: length}) | sort_by(-.count) | .[0:10])
          },
          sbom: {
            repositories_with_sbom: ([ $repos[] | select(.sbom != null) ] | length),
            components_total:       ([ $repos[] | .sbom.component_count // 0 ] | add // 0),
            unique_licenses:        ([ $repos[] | .sbom.licenses[]?.license ] | unique | length),
            license_distribution:   ([ $repos[] | .sbom.licenses[]? ] | group_by(.license)
                                       | map({license: .[0].license, count: (map(.count) | add)})
                                       | sort_by(-.count)),
            unlicensed_components:  ([ $repos[] | .sbom.unlicensed_components[]? ] | length),
            ecosystems:             ([ $repos[] | .sbom.ecosystems[]? ] | group_by(.ecosystem)
                                       | map({ecosystem: .[0].ecosystem, count: (map(.count) | add)})
                                       | sort_by(-.count)),
            license_policy: {
              status:        (if ([ $repos[] | select(.license_policy.status == "fail") ] | length) > 0 then "fail"
                              elif ([ $repos[] | select(.license_policy.status == "warn") ] | length) > 0 then "warn"
                              else "pass" end),
              denied_total:  ([ $repos[] | .license_policy.denied_count // 0 ] | add // 0),
              flagged_total: ([ $repos[] | .license_policy.flagged_count // 0 ] | add // 0),
              failing_repositories: ([ $repos[] | select(.license_policy.status == "fail") | .repository.full_name ])
            }
          },
          access: (
            [ $repos[] | select(.access != null) | .access ] as $A
            | [ $A[].users[]? ] as $AU
            | {
                repositories_inventoried: ($A | length),
                repositories_unreadable:  ([ $A[] | select(.error != null) ] | length),
                unique_users:      ([ $AU[].login | ascii_downcase ] | unique | length),
                unique_admins:     ([ $AU[] | select(.permission == "admin") | .login | ascii_downcase ] | unique | length),
                unique_writers:    ([ $AU[] | select(.permission | prank >= 3) | .login | ascii_downcase ] | unique | length),
                outside_collaborators: ([ $AU[] | select(.outside_collaborator) | .login | ascii_downcase ] | unique | length),
                bots:              ([ $AU[] | select(.type == "Bot") | .login | ascii_downcase ] | unique | length),
                unique_teams:      ([ $A[].teams[]?.slug ] | unique | length),
                pending_invitations: ([ $A[].pending_invitations[]? ] | length),
                deploy_keys:         ([ $A[].deploy_keys[]? ] | length),
                write_deploy_keys:   ([ $A[].deploy_keys[]? | select(.read_only == false) ] | length),
                by_permission:       ($AU | tally(.permission))
              }
          ),
          pull_history: (
            [ $repos[] | .pull_history[]? ] as $P
            | {
                pull_requests: ([ $P[].count ] | add // 0),
                merged:        ([ $P[].merged_count ] | add // 0),
                unique_users:  ([ $P[].username ] | unique | length),
                unique_branches_targeted: ([ $P[] | .repository + "#" + .branch ] | unique | length),
                repositories_with_activity: ([ $P[].repository ] | unique | length),
                most_recent: ([ $P[].last_pull_at ] | sort | last),
                top_users: ([ $P[] | {username, count} ] | group_by(.username)
                            | map({username: .[0].username, count: (map(.count) | add)})
                            | sort_by(-.count) | .[0:10])
              }
          ),
          code_findings: {
            total:        ($code | length),
            by_severity:  ($code | tally(.severity)),
            by_cwe:       ([ $code[] | .cwe_ids[]? | (. // "unknown") | tostring ] | group_by(.) | map({key: .[0], value: length}) | from_entries),
            by_rule:      ([ $code[] | .rule_name ] | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count) | .[0:10]),
            repositories_affected: ([ $code[] | .repository ] | unique | length),
            critical_and_high: ([ $code[] | select((.severity | rank) >= 4) ] | length)
          },
          misconfigurations: {
            total:        ($iac | length),
            needs_review: ([ $iac[] | select(.triage == "review") ] | length),
            by_severity:  ($iac | tally(.severity)),
            by_kind:      ($iac | tally(.configuration_kind)),
            by_source:    ($iac | tally(.source)),
            by_rule:      ([ $iac[] | .rule_id ] | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count) | .[0:10]),
            repositories_affected: ([ $iac[] | .repository ] | unique | length),
            critical_and_high: ([ $iac[] | select((.severity | rank) >= 4) ] | length)
          },
          vulnerabilities: {
            total:       ($vulns | length),
            by_severity: ($vulns | tally(.severity)),
            by_source:   ([ $vulns[] | .sources[]? // .source ] | group_by(.) | map({key: .[0], value: length}) | from_entries),
            critical_and_high: ([ $vulns[] | select((.severity | rank) >= 4) ] | length),
            top_packages: ([ $vulns[] | .package.name // "unknown" ] | group_by(.) | map({package: .[0], count: length}) | sort_by(-.count) | .[0:10]),
            known_exploited: ([ $vulns[] | select(.known_exploited == true) ] | length),
            by_priority: ($vulns | tally(.priority)),
            act_now: ([ $vulns[] | select(.priority == "act-now")
                        | {id, package: .package.name, repository, kev_added, epss_score, kev_ransomware} ])
          }
        },

        # Flat, ready-to-triage list: repository -> branch(es) -> URL.
        secrets: ( $secrets
          | sort_by([ -( .severity | rank ), (if .verified then 0 else 1 end), .repository, .file ]) ),

        vulnerabilities: ( $vulns | sort_by([ -( .severity | rank ), (.package.name // "") ]) ),

        code_findings: ( $code | sort_by([ -( .severity | rank ), .repository, .file ]) ),

        # Repositories this run left out because they are archived.
        #
        # Carried at the top level because it is a statement about the scan
        # rather than about any repository in it: these are precisely the ones
        # that are not in the list below, and without this the reader cannot
        # tell them apart from a repository that was simply never reached.
        archived_repositories: (($meta.scan.archived_repositories // []) | unique),

        # Repositories whose code pass was cut short. Nothing missing
        # from these may be counted as fixed: it was never looked at.
        partial_code_repositories:
          [ $repos[] | select(.code_complete == false)
            | {repository: .repository.full_name, reason: (.code_incomplete_reason // "the code pass did not complete")} ],

        # Repositories whose CodeQL alerts could not be read from GitHub.  Only
        # findings CodeQL reported are held open for these.
        codeql_unread_repositories:
          [ $repos[] | select((.codeql_unread_reason // "") != "")
            | {repository: .repository.full_name, reason: .codeql_unread_reason} ],


        misconfigurations: ( $iac | sort_by([ -( .severity | rank ), .repository, .file ]) ),

        # PR activity, rolled up across every repo.
        pull_history: {
          by_user_branch: (
            [ $repos[] | .pull_history[]? ]
            | sort_by([-.count, .username, .repository, .branch])
          ),
          by_user: (
            [ $repos[] | .pull_history[]? ]
            | group_by(.username)
            | map({
                username: .[0].username,
                user_type: .[0].user_type,
                organizations: (map(.organization) | unique),
                repository_count: (map(.repository) | unique | length),
                branch_count: (map(.branch) | unique | length),
                count: (map(.count) | add),
                merged_count: (map(.merged_count) | add),
                open_count: (map(.open_count) | add),
                first_pull_at: (map(.first_pull_at) | sort | first),
                last_pull_at:  (map(.last_pull_at)  | sort | last)
              })
            | sort_by(-.count)
          ),
          clone_traffic: [ $repos[] | select(.clone_traffic != null)
                           | {repository: .repository.full_name} + .clone_traffic ]
        },

        placeholders_filtered: $filtered,
        allowlist_suppressed:  $suppressed,

        # Every user who can reach anything in scope, and how.
        access: {
          organizations: ($meta.organizations // []),
          users: (
            [ $repos[] | select(.access != null) | .access.users[]? ]
            | group_by(.login | ascii_downcase)
            | map({
                login: .[0].login,
                id: .[0].id,
                type: .[0].type,
                site_admin: .[0].site_admin,
                html_url: .[0].html_url,
                outside_collaborator: (any(.[]; .outside_collaborator)),
                repository_count: length,
                highest_permission: (max_by(.permission | prank) | .permission),
                admin_of: [ .[] | select(.permission == "admin") | .repository ],
                repositories: [ .[] | {repository, permission, affiliation, outside_collaborator} ]
              })
            | sort_by([-(.highest_permission | prank), -.repository_count, .login])
          ),
          teams: (
            [ $repos[] | select(.access != null) | .access.teams[]? ]
            | group_by(.slug)
            | map({
                slug: .[0].slug, name: .[0].name, privacy: .[0].privacy,
                repository_count: length,
                highest_permission: (max_by(.permission | prank) | .permission),
                repositories: [ .[] | {repository, permission} ]
              })
            | sort_by(-.repository_count)
          ),
          pending_invitations: [ $repos[] | select(.access != null) | .access.pending_invitations[]? ],
          deploy_keys:         [ $repos[] | select(.access != null) | .access.deploy_keys[]? ],
          unreadable_repositories: [ $repos[] | select(.access != null and .access.error != null)
                                     | {repository: .repository.full_name, error: .access.error} ]
        },

        repositories: [ $repos[] | {
          repository: .repository,
          status, error,
          passes_complete: (.passes_complete // []),
          history: (.history // null),
          # Which engine in the credential pass died, if one did.  Carried
          # rather than dropped because the reader acts on it: a history whose
          # engine was killed must not keep a marker saying it has been read
          # end to end.  Computed and discarded here, that decision would be
          # made on the wrong evidence.
          secrets_incomplete_reason: (.secrets_incomplete_reason // null),
          # Why the CodeQL alerts were not read, for the same reader: it is
          # the whole reason those findings were held open rather than closed.
          codeql_unread_reason: (.codeql_unread_reason // null),
          branches_scanned: .branches_scanned,
          # And every branch that is there, walked or not.  The walked list is
          # narrowed by the quiet branch filter and the per repository cap, so
          # a name missing from it does not mean the branch has gone.  A sign
          # off may only be taken away on the evidence of this one.
          branches_present: (.branches_present // null),
          branch_count,
          # Where each branch actually was, and whether a dynamic pass could
          # run here.  Both are worked out per repository and both were being
          # dropped at this point: the worker wrote them, this selection did
          # not name them, and nothing downstream ever saw them.  A field that
          # is computed and then discarded is worse than one nobody wrote,
          # because the code that produced it looks like it works.
          branch_heads: (.branch_heads // {}),
          # The semgrep rules the run had for this repository.  Ingest holds open a
          # finding whose rule is missing, so a rule withdrawn upstream is not
          # read as everything it found being fixed.
          code_rules_loaded: (.code_rules_loaded // []),
          dast: (.dast // null),
          secret_counts: {
            reported:   (.secrets.reported | length),
            confirmed:  ([ .secrets.reported[] | select(.verified == true) ] | length),
            filtered:   (.secrets.filtered | length),
            suppressed: (.secrets.suppressed | length)
          },
          license: .license,
          license_policy: .license_policy,
          access: (if .access == null then null
                   else {error: .access.error, counts: .access.counts, branches: (.access.branches // [])} end),
          sbom: (if .sbom == null then null else (.sbom | del(.components)) end),
          sbom_by_branch: [ (.sbom_by_branch // [])[] | {branch, component_count: .sbom.component_count, license_policy_status: .license_policy.status} ],
          code_finding_counts: {
            total: ((.code_findings // []) | length),
            by_severity: ((.code_findings // []) | tally(.severity))
          },
          misconfiguration_counts: {
            total: ((.misconfigurations // []) | length),
            needs_review: ([ (.misconfigurations // [])[] | select(.triage == "review") ] | length),
            by_severity: ((.misconfigurations // []) | tally(.severity))
          },
          pull_history: (.pull_history // []),
          clone_traffic: .clone_traffic,
          vulnerability_counts: {
            total: (.vulnerabilities | length),
            by_severity: (.vulnerabilities | tally(.severity))
          },
          timing: .timing
        } ],

        errors: [ $bad[] | {repository: .repository.full_name, status, error} ]
      }
  ' "$list"
}

# The full SBOM component lists are big; they go to their own file.
report_sbom_bundle() {
  local results_dir="$1"
  local files=("$results_dir"/*.json)
  [[ -e "${files[0]}" ]] || { echo '{"repositories":[]}'; return; }
  jq -s -c '{
    schema_version: "1.0.0",
    generated_at: (env.GHSCAN_NOW // ""),
    repositories: [ .[] | select(.sbom != null) | {
      repository: .repository.full_name,
      default_branch: .repository.default_branch,
      repository_license: .license,
      sbom: .sbom,
      license_policy: .license_policy,
      sbom_by_branch: (.sbom_by_branch // [])
    } ]
  }' "${files[@]}" 2>/dev/null || echo '{"repositories":[]}'
}

report_write() {
  local doc="$1" path="$2"
  local dir; dir=$(dirname "$path")
  mkdir -p "$dir"
  if cfg_bool '.output.pretty' true; then
    printf '%s' "$doc" | jq '.' > "$path"
  else
    printf '%s' "$doc" | jq -c '.' > "$path"
  fi
  if cfg_bool '.output.gzip' false; then
    gzip -f "$path" && path="${path}.gz"
  fi
  printf '%s' "$path"
}

# Human-readable console recap.
report_console_summary() {
  local doc="$1"
  printf '%s' "$doc" | jq -r '
    "",
    "  Repositories scanned .......... \(.summary.repositories.scanned)/\(.summary.repositories.in_scope)   (failed: \(.summary.repositories.failed), skipped: \(.summary.repositories.skipped))",
    "  Branches scanned .............. \(.summary.branches.scanned)",
    "",
    "  SECRETS",
    "    Reported .................... \(.summary.secrets.reported)",
    "    Confirmed live (verified) ... \(.summary.secrets.confirmed_live)",
    "    Still in a branch head ...... \(.summary.secrets.still_in_branch_heads)",
    "    In git history only ......... \(.summary.secrets.history_only)",
    "    Placeholders filtered out ... \(.summary.secrets.placeholders_filtered)",
    "    Allowlist suppressed ........ \(.summary.secrets.allowlist_suppressed)",
    "    By severity ................. \(.summary.secrets.by_severity | to_entries | map("\(.key)=\(.value)") | join("  "))",
    "",
    "  SBOM / LICENSING",
    "    Components .................. \(.summary.sbom.components_total) across \(.summary.sbom.repositories_with_sbom) repos",
    "    Distinct licenses ........... \(.summary.sbom.unique_licenses)",
    "    Components w/o license ...... \(.summary.sbom.unlicensed_components)",
    "    License policy .............. \(.summary.sbom.license_policy.status | ascii_upcase) (denied: \(.summary.sbom.license_policy.denied_total), flagged: \(.summary.sbom.license_policy.flagged_total))",
    "",
    "  ACCESS",
    "    Repositories inventoried .... \(.summary.access.repositories_inventoried)   (unreadable: \(.summary.access.repositories_unreadable))",
    "    Unique users ................ \(.summary.access.unique_users)",
    "    Admins ...................... \(.summary.access.unique_admins)",
    "    Users with write or above ... \(.summary.access.unique_writers)",
    "    Outside collaborators ....... \(.summary.access.outside_collaborators)",
    "    Teams ....................... \(.summary.access.unique_teams)",
    "    Pending invitations ......... \(.summary.access.pending_invitations)",
    "    Deploy keys ................. \(.summary.access.deploy_keys)   (writable: \(.summary.access.write_deploy_keys))",
    "",
    "  CODE VULNERABILITIES (static analysis)",
    "    Findings .................... \(.summary.code_findings.total)",
    "    Critical + High ............. \(.summary.code_findings.critical_and_high)",
    "    Repositories affected ....... \(.summary.code_findings.repositories_affected)",
    "    By severity ................. \(.summary.code_findings.by_severity | to_entries | map("\(.key)=\(.value)") | join("  "))",
    "    Top CWEs .................... \(.summary.code_findings.by_cwe | to_entries | sort_by(-.value) | .[0:5] | map("\(.key)=\(.value)") | join("  "))",
    "",
    "  INFRASTRUCTURE AS CODE",
    "    Findings .................... \(.summary.misconfigurations.total)",
    "    Worth a look ................ \(.summary.misconfigurations.needs_review)",
    "    Critical + High ............. \(.summary.misconfigurations.critical_and_high)",
    "    By severity ................. \(.summary.misconfigurations.by_severity | to_entries | map("\(.key)=\(.value)") | join("  "))",
    "    By kind ..................... \(.summary.misconfigurations.by_kind | to_entries | map("\(.key)=\(.value)") | join("  "))",
    "",
    "  VULNERABILITIES",
    "    Total ....................... \(.summary.vulnerabilities.total)",
    "    Critical + High ............. \(.summary.vulnerabilities.critical_and_high)",
    "    By severity ................. \(.summary.vulnerabilities.by_severity | to_entries | map("\(.key)=\(.value)") | join("  "))",
    "    Known exploited (CISA KEV) .. \(.summary.vulnerabilities.known_exploited)",
    "    By priority ................. \(.summary.vulnerabilities.by_priority | to_entries | map("\(.key)=\(.value)") | join("  "))",
    ""
  ' 2>/dev/null
}
