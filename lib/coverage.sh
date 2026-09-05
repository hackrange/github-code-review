#!/usr/bin/env bash
# `ghscan coverage`: how much there is to scan. Orgs, repos, branches.
# API only, no cloning, so it is quick even across a large estate.
# shellcheck shell=bash

# coverage_branches <full_name> -> {name, protected, commit} array
coverage_branches() {
  provider_call list_branches "$1"
}

# coverage_build <orgs_json> <repos_json> -> the report
coverage_build() {
  local orgs_json="$1" repos_json="$2"
  local acc; acc=$(tmp_file cov); echo '[]' > "$acc"

  local total; total=$(printf '%s' "$repos_json" | jq 'length')
  local i=0 full_name branches n
  # Reused across the loop rather than a file per repository.
  local bf; bf=$(tmp_file covbr)
  while IFS= read -r full_name; do
    [[ -z "$full_name" ]] && continue
    i=$(( i + 1 ))
    branches=$(coverage_branches "$full_name")
    n=$(printf '%s' "$branches" | jq 'length')
    log_info "[$i/$total] $full_name: $n branch(es)"
    printf '%s' "${branches:-[]}" > "$bf"
    jq -c --slurpfile b_in "$bf" --arg r "$full_name" \
       --argjson meta "$(printf '%s' "$repos_json" | jq -c --arg r "$full_name" '.[] | select(.full_name == $r)')" \
       '($b_in[0]) as $b
        | . + [{repository: $r,
              organization: ($r | split("/")[0]),
              visibility: ($meta.visibility // "unknown"),
              archived: ($meta.archived // false),
              fork: ($meta.fork // false),
              size_kb: ($meta.size_kb // 0),
              default_branch: ($meta.default_branch // "unknown"),
              branch_count: ($b | length),
              protected_branches: ([ $b[] | select(.protected) ] | length),
              branches: [ $b[].name ]}]' "$acc" > "${acc}.n" && mv "${acc}.n" "$acc"
  done < <(printf '%s' "$repos_json" | jq -r '.[].full_name')

  jq -cn --argjson orgs "$orgs_json" --slurpfile repos "$acc" \
         --arg generated "$(now_iso)" '
    ($repos[0] | map(.branches[]?)) as $all_branches
    | {
        generated_at: $generated,
        totals: {
          organizations:            ($orgs | length),
          organizations_readable:   ([ $orgs[] | select(.accessible) ] | length),
          organizations_no_access:  ([ $orgs[] | select(.accessible | not) ] | length),
          repositories:             ($repos[0] | length),
          branches:                 ($all_branches | length),
          unique_branch_names:      ($all_branches | unique | length),
          protected_branches:       ([ $repos[0][].protected_branches ] | add // 0),
          total_size_mb:            ((([ $repos[0][].size_kb ] | add // 0) / 1024) | floor)
        },
        repositories_by_visibility: ($repos[0] | group_by(.visibility)
                                     | map({visibility: .[0].visibility, count: length})
                                     | sort_by(-.count)),
        repositories_by_organization: ($repos[0] | group_by(.organization)
                                     | map({organization: .[0].organization,
                                            repositories: length,
                                            branches: ([ .[].branch_count ] | add // 0)})
                                     | sort_by(-.repositories)),
        branch_name_frequency: ($all_branches | group_by(.)
                                     | map({branch: .[0], repositories: length})
                                     | sort_by(-.repositories) | .[0:25]),
        default_branch_names: ([ $repos[0][].default_branch ] | group_by(.)
                                     | map({branch: .[0], count: length}) | sort_by(-.count)),
        branches_per_repository: {
          max:    ([ $repos[0][].branch_count ] | max // 0),
          min:    ([ $repos[0][].branch_count ] | min // 0),
          mean:   ((([ $repos[0][].branch_count ] | add // 0) * 100 / ([$repos[0] | length, 1] | max)) | round / 100),
          busiest: ($repos[0] | sort_by(-.branch_count) | .[0:10]
                    | map({repository, branch_count, protected_branches}))
        },
        organizations: ($orgs | sort_by([(.accessible | not), .organization])),
        repositories: ($repos[0] | sort_by(.repository))
      }'
}

coverage_console() {
  printf '%s' "$1" | jq -r '
    "",
    "  ORGANIZATIONS",
    "    Total seen .................. \(.totals.organizations)",
    "    Readable .................... \(.totals.organizations_readable)",
    "    No access ................... \(.totals.organizations_no_access)",
    "",
    "  REPOSITORIES",
    "    Total ....................... \(.totals.repositories)",
    "    By visibility ............... \(.repositories_by_visibility | map("\(.visibility)=\(.count)") | join("  "))",
    "    Total size .................. \(.totals.total_size_mb) MB",
    "",
    "  BRANCHES",
    "    Total across all repos ...... \(.totals.branches)",
    "    Unique branch names ......... \(.totals.unique_branch_names)",
    "    Protected ................... \(.totals.protected_branches)",
    "    Per repo (min/mean/max) ..... \(.branches_per_repository.min) / \(.branches_per_repository.mean) / \(.branches_per_repository.max)",
    "    Default branch names ........ \(.default_branch_names | map("\(.branch)=\(.count)") | join("  "))",
    ""' 2>/dev/null
}
