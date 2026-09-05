#!/usr/bin/env bash
# Finds the orgs, repos and branches to scan.
# shellcheck shell=bash

# When SSO truncates a listing, GitHub names the org IDs it withheld. That is
# often the only way to learn which orgs exist, so we mine it.
orgs_from_sso_header() {
  local api; api=$(cfg '.github.api_url' 'https://api.github.com')
  local hdr; hdr=$(tmp_file ssohdr)
  auth_curl -sSI --max-time 30 -H "Accept: application/vnd.github+json" \
    "$api/user/repos?per_page=1" > "$hdr" 2>/dev/null || true
  local ids
  ids=$(grep -i '^x-github-sso:' "$hdr" 2>/dev/null | tr -d '\r' \
        | sed -n 's/.*organizations=\([0-9,]*\).*/\1/p' | tr ',' ' ' || true)
  [[ -z "$ids" ]] && { echo '[]'; return 0; }
  local out='[]' id name
  for id in $ids; do
    name=$(api_get_quiet "/organizations/$id" | jq -r '.login // empty' 2>/dev/null)
    [[ -n "$name" ]] && out=$(printf '%s' "$out" | jq -c --arg n "$name" '. + [$n]')
  done
  printf '%s' "$out"
}

# Can we actually read repositories in this org, or only its public face?
org_access_status() {
  local org="$1"
  local body; body=$(api_get_quiet "/orgs/${org}/repos?per_page=100")
  local n; n=$(printf '%s' "$body" | jq 'if type=="array" then length else 0 end' 2>/dev/null || echo 0)
  jq -cn --arg org "$org" --argjson n "${n:-0}" \
    '{organization:$org, repositories_visible:$n, accessible:($n > 0)}'
}

# Leave scope.orgs empty and we scan every org the token can see.
# Two gotchas we warn about: no read:org scope gives you an empty list rather
# than an error, and SAML orgs the token isn't authorized for just vanish.
# shuffle_json_array <json array> -> the same array in a random order
#
# Why a scan should not always start in the same place.
#
# Every list here is sorted, which is right for reading and wrong for
# scanning.  A run that is cut short, by its time limit or by the API budget
# or by a failure part way, stops wherever it had got to, so a stable order
# means the tail of the alphabet is never reached.  Not scanned then reads
# exactly like nothing found, which is the failure this whole tool is built to
# avoid, and it lands on the same repositories every night.
#
# max_repos makes it worse rather than better.  Capped at fifty, a sorted list
# scans the same fifty forever and the rest of the estate is never looked at
# once.  Shuffled, the cap becomes a sample that moves, and a month of nightly
# runs covers most of it.
#
# The order that was used is logged, so a run can still be reproduced when
# somebody needs to know what happened in what sequence.
shuffle_json_array() {
  local json="$1"
  [[ -n "$json" && "$json" != "[]" ]] || { printf '%s' "${json:-[]}"; return 0; }
  cfg_bool '.scan.randomize_order' true || { printf '%s' "$json"; return 0; }
  have_cmd shuf || { printf '%s' "$json"; return 0; }
  printf '%s' "$json" | jq -c '.[]' 2>/dev/null | shuf | jq -sc '.' 2>/dev/null \
    || printf '%s' "$json"
}

inventory_orgs() {
  local configured; configured=$(cfg_json '.github.scope.orgs // []')

  if [[ "$configured" != "[]" ]]; then
    shuffle_json_array "$configured"
    return 0
  fi

  if ! cfg_bool '.github.scope.auto_discover_orgs' true; then
    echo '[]'
    return 0
  fi

  log_info "no $(provider_group_noun)s configured - discovering every one this credential can see"
  local orgs; orgs=$(provider_call list_groups) || orgs='[]'
  [[ -n "$orgs" ]] || orgs='[]'

  if [[ "$orgs" == "[]" ]]; then
    provider_call no_groups_warning
  else
    log_ok "discovered $(printf '%s' "$orgs" | jq 'length') $(provider_group_noun)(s): $(printf '%s' "$orgs" | jq -r 'join(", ")')"
  fi
  shuffle_json_array "$orgs"
}

# inventory_repos -> JSON array of normalized repo objects on stdout
#
# The provider finds the work and hands back normalized objects; the filtering
# below is the same whoever the host is.
inventory_repos() {
  local normalized; normalized=$(tmp_file normalized)
  provider_call list_repos > "$normalized" || return 1

  local inc_arch inc_fork inc_tmpl excl_re max_repos excl_list
  inc_arch=$(cfg_bool '.github.scope.include_archived' false && echo true || echo false)
  inc_fork=$(cfg_bool '.github.scope.include_forks' false && echo true || echo false)
  inc_tmpl=$(cfg_bool '.github.scope.include_templates' true && echo true || echo false)
  excl_re=$(cfg '.github.scope.exclude_repo_regex' '')
  max_repos=$(cfg_num '.github.scope.max_repos' 0)
  excl_list=$(cfg_json '.github.scope.exclude_repos // []')

  local picked
  picked=$(jq -c \
    --argjson inc_arch "$inc_arch" \
    --argjson inc_fork "$inc_fork" \
    --argjson inc_tmpl "$inc_tmpl" \
    --arg excl_re "$excl_re" \
    --argjson excl "$excl_list" '
    ( $excl | map(ascii_downcase) ) as $ex
    | unique_by(.full_name)
    | map(select(.full_name != null))
    | map(select($inc_arch or (.archived // false) == false))
    | map(select($inc_fork or (.fork // false) == false))
    | map(select($inc_tmpl or (.is_template // false) == false))
    | map(select((.full_name | ascii_downcase) as $n | ($ex | index($n)) == null))
    | map(select($excl_re == "" or ((.full_name | test($excl_re)) | not)))
    | sort_by(.full_name)
  ' "$normalized")

  # Shuffled first, then capped, and that order is the whole point.  Capping a
  # sorted list takes the same prefix of the alphabet every night and never
  # reaches the rest; capping a shuffled one takes a sample that moves, so a
  # month of runs covers the estate rather than the first fifty of it.
  picked=$(shuffle_json_array "$picked")
  if (( max_repos > 0 )); then
    picked=$(printf '%s' "$picked" | jq -c --argjson max "$max_repos" '.[0:$max]')
    log_info "scanning $(printf '%s' "$picked" | jq 'length') of them, capped by max_repos"
  fi
  printf '%s' "$picked"
}

# branch_filter_args -> prints the include/exclude globs for use by callers
# branch_allowed <branch> -> exit 0 if the branch should be scanned
branch_allowed() {
  local br="$1"
  local mode; mode=$(cfg '.github.branches.mode' 'all')

  if [[ "$mode" == "default" ]]; then
    [[ "$br" == "${GHSCAN_DEFAULT_BRANCH:-}" ]] && return 0 || return 1
  fi

  local pat matched=1
  if [[ "$mode" == "list" ]]; then
    matched=1
    while IFS= read -r pat; do
      [[ -z "$pat" ]] && continue
      # shellcheck disable=SC2053
      [[ "$br" == $pat ]] && { matched=0; break; }
    done < <(cfg_arr '.github.branches.include')
    (( matched == 0 )) || return 1
  else
    local has_inc; has_inc=$(cfg_json '.github.branches.include // []')
    if [[ "$has_inc" != "[]" ]]; then
      matched=1
      while IFS= read -r pat; do
        [[ -z "$pat" ]] && continue
        # shellcheck disable=SC2053
        [[ "$br" == $pat ]] && { matched=0; break; }
      done < <(cfg_arr '.github.branches.include')
      (( matched == 0 )) || return 1
    fi
  fi

  while IFS= read -r pat; do
    [[ -z "$pat" ]] && continue
    # shellcheck disable=SC2053
    [[ "$br" == $pat ]] && return 1
  done < <(cfg_arr '.github.branches.exclude')

  return 0
}

# repo_branches <clone_dir> -> newline-separated branch names, filtered.
# Read from the local mirror so no extra API calls are needed and every ref,
# including ones the branches endpoint paginates awkwardly, is covered.
repo_branches() {
  local dir="$1"
  local stale_days max_per
  stale_days=$(cfg_num '.github.branches.stale_days' 0)
  max_per=$(cfg_num '.github.branches.max_per_repo' 0)

  local cutoff=0
  if (( stale_days > 0 )); then
    cutoff=$(( $(date +%s) - stale_days * 86400 ))
  fi

  local out=()
  local line br ts
  while IFS=$'\t' read -r br ts; do
    [[ -z "$br" ]] && continue
    branch_allowed "$br" || { log_trace "branch filtered out: $br"; continue; }
    if (( cutoff > 0 )) && [[ -n "$ts" ]] && (( ts < cutoff )); then
      log_trace "branch stale, skipping: $br"
      continue
    fi
    out+=("$br")
  done < <(git -C "$dir" for-each-ref --format='%(refname:strip=2)%09%(committerdate:unix)' \
             --sort=-committerdate refs/heads/ 2>/dev/null)

  if (( max_per > 0 )) && (( ${#out[@]} > max_per )); then
    log_debug "limiting to $max_per of ${#out[@]} branches"
    out=("${out[@]:0:$max_per}")
  fi

  (( ${#out[@]} > 0 )) && printf '%s\n' "${out[@]}"
}

# branches_containing <clone_dir> <sha> -> comma-free newline list of branches
# whose history contains that commit. This is how a finding at a commit is
# attributed back to every branch it is reachable from.
branches_containing() {
  local dir="$1" sha="$2"
  git -C "$dir" for-each-ref --contains "$sha" --format='%(refname:strip=2)' refs/heads/ 2>/dev/null
}
