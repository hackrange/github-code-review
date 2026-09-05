#!/usr/bin/env bash
# Pull request history per user, per repo, per target branch.
#
# Note on wording: GitHub's API cannot tell you who ran `git pull`. Fetches and
# clones only show up in the Enterprise Cloud audit log. What we can count is
# pull requests, which is what this does, plus repo-level clone traffic totals
# that have no username attached.
# shellcheck shell=bash

# pulls_fetch <full_name> - PRs, newest first, stopped at the cutoff.
pulls_fetch() {
  local full_name="$1"
  # GitLab has merge requests and Bitbucket has pull requests, but neither is
  # wired up yet, so nothing is claimed.
  if ! provider_supports pull_history; then
    log_debug "$(provider_name) has no pull or merge request history reachable yet, so it is not asked for"
    echo '[]'; return 0
  fi
  local state; state=$(cfg '.scan.pull_history.state' 'all')
  local since_days; since_days=$(cfg_num '.scan.pull_history.since_days' 365)
  local max; max=$(cfg_num '.scan.pull_history.max_per_repo' 2000)

  local cutoff=""
  if (( since_days > 0 )); then
    cutoff=$(date -u -d "-${since_days} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
  fi

  local acc; acc=$(tmp_file pulls); echo '[]' > "$acc"
  local page=1 got=0

  while (( page <= 100 )); do
    local body
    body=$(api_get "/repos/${full_name}/pulls?state=${state}&sort=updated&direction=desc&per_page=100&page=${page}") || break
    local n; n=$(printf '%s' "$body" | jq 'length' 2>/dev/null || echo 0)
    (( n == 0 )) && break

    jq -c --slurpfile acc "$acc" '$acc[0] + .' <<<"$body" > "${acc}.n" && mv "${acc}.n" "$acc"
    got=$(( got + n ))

    # Sorted by updated desc, so once a page ends before the cutoff we are done.
    if [[ -n "$cutoff" ]]; then
      local oldest; oldest=$(printf '%s' "$body" | jq -r '[.[].updated_at] | min // ""')
      [[ -n "$oldest" && "$oldest" < "$cutoff" ]] && break
    fi
    (( max > 0 && got >= max )) && break
    (( n < 100 )) && break
    page=$(( page + 1 ))
  done

  jq -c --arg cutoff "$cutoff" '
    if $cutoff == "" then . else map(select(.created_at >= $cutoff)) end' "$acc"
}

# pulls_by_user <full_name> <prs_json> - one row per user per target branch.
pulls_by_user() {
  local full_name="$1" prs="$2"
  printf '%s' "$prs" | jq -c --arg repo "$full_name" '
    [ .[]? | {
        username: (.user.login // "unknown"),
        user_type: (.user.type // "User"),
        organization: ($repo | split("/")[0]),
        repository: $repo,
        branch: (.base.ref // "unknown"),
        head_branch: (.head.ref // null),
        number: .number,
        state: (.state // "open"),
        merged: ((.merged_at // null) != null),
        draft: (.draft // false),
        created_at: .created_at,
        updated_at: .updated_at,
        merged_at: (.merged_at // null),
        closed_at: (.closed_at // null)
      } ]
    | group_by([.username, .branch])
    | map({
        username: .[0].username,
        user_type: .[0].user_type,
        organization: .[0].organization,
        repository: .[0].repository,
        branch: .[0].branch,
        count: length,
        merged_count: ([ .[] | select(.merged) ] | length),
        open_count:   ([ .[] | select(.state == "open") ] | length),
        closed_count: ([ .[] | select(.state == "closed" and (.merged | not)) ] | length),
        draft_count:  ([ .[] | select(.draft) ] | length),
        first_pull_at: ([ .[].created_at ] | sort | first),
        last_pull_at:  ([ .[] | (.merged_at // .closed_at // .updated_at // .created_at) ] | sort | last),
        last_pull_number: (max_by(.created_at) | .number)
      })
    | sort_by([-.count, .username])'
}

# Repo-level clone and fetch totals. No usernames, GitHub does not expose them.
pulls_clone_traffic() {
  local full_name="$1"
  cfg_bool '.scan.pull_history.include_clone_traffic' true || { echo 'null'; return; }
  local body; body=$(api_get_quiet "/repos/${full_name}/traffic/clones")
  [[ -z "$body" ]] && { echo 'null'; return; }
  printf '%s' "$body" | jq -c '{
    period_days: 14,
    total_clones: (.count // 0),
    unique_cloners: (.uniques // 0),
    daily: [ (.clones // [])[] | {date: .timestamp, clones: .count, uniques: .uniques} ]
  }' 2>/dev/null || echo 'null'
}
