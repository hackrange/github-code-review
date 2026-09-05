#!/usr/bin/env bash
# Who can reach each repo: users, teams, invites, deploy keys.
# Listing collaborators needs push access, so a read-only token gets a 403 and
# we record that instead of pretending the repo has nobody on it.
# shellcheck shell=bash

_perm_rank() {
  case "${1:-none}" in
    admin) echo 5 ;; maintain) echo 4 ;; write|push) echo 3 ;;
    triage) echo 2 ;; read|pull) echo 1 ;; *) echo 0 ;;
  esac
}

# access_collaborators <full_name> <direct_json> <outside_logins_json> -> array
access_collaborators() {
  local full_name="$1" direct="$2" outside="$3"
  local all
  all=$(api_paginate "/repos/${full_name}/collaborators?affiliation=all" 100) || return 1

  local f_direct f_outside
  f_direct=$(json_file "$direct" direct)
  f_outside=$(json_file "$outside" outside)
  printf '%s' "$all" | jq -c \
    --slurpfile direct_in "$f_direct" \
    --slurpfile outside_in "$f_outside" \
    --arg repo "$full_name" '
    ($direct_in[0]) as $direct
    | ($outside_in[0]) as $outside
    | ([ $direct[]?.login ]  | map(ascii_downcase)) as $D
    | ($outside              | map(ascii_downcase)) as $O
    | [ .[]?
        | . as $c
        | ($c.login | ascii_downcase) as $l
        | {
        repository: $repo,
        login: .login,
        id: .id,
        type: (.type // "User"),
        site_admin: (.site_admin // false),
        permission: (
          .role_name
          // (if   (.permissions.admin    // false) then "admin"
              elif (.permissions.maintain // false) then "maintain"
              elif (.permissions.push     // false) then "write"
              elif (.permissions.triage   // false) then "triage"
              elif (.permissions.pull     // false) then "read"
              else "unknown" end)
        ),
        permissions: (.permissions // {}),
        affiliation: (if ($D | index($l)) != null then "direct" else "inherited" end),
        outside_collaborator: (($O | index($l)) != null),
        html_url: (.html_url // null)
      } ]'
}

access_direct_collaborators() {
  api_paginate "/repos/${1}/collaborators?affiliation=direct" 100 || echo '[]'
}

# Teams with access, and the permission each one grants.
access_teams() {
  local full_name="$1"
  local body; body=$(api_paginate "/repos/${full_name}/teams" 100) || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c --arg repo "$full_name" '
    [ .[]? | {
        repository: $repo,
        slug: .slug,
        name: .name,
        id: .id,
        privacy: (.privacy // null),
        permission: (
          .permission
          // (if   (.permissions.admin    // false) then "admin"
              elif (.permissions.maintain // false) then "maintain"
              elif (.permissions.push     // false) then "write"
              elif (.permissions.triage   // false) then "triage"
              else "read" end)
        ),
        html_url: (.html_url // null)
      } ]' 2>/dev/null || echo '[]'
}

# Pending invitations are access that has been granted but not yet accepted.
access_invitations() {
  local full_name="$1"
  local body; body=$(api_paginate "/repos/${full_name}/invitations" 100) || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c --arg repo "$full_name" '
    [ .[]? | {
        repository: $repo,
        invitee: (.invitee.login // null),
        inviter: (.inviter.login // null),
        permission: (.permissions // null),
        created_at: .created_at,
        expired: (.expired // false)
      } ]' 2>/dev/null || echo '[]'
}

# Deploy keys are unattended access with no user behind them.
access_deploy_keys() {
  local full_name="$1"
  local body; body=$(api_paginate "/repos/${full_name}/keys" 100) || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c --arg repo "$full_name" '
    [ .[]? | {
        repository: $repo,
        id: .id,
        title: .title,
        read_only: (if .read_only == null then true else .read_only end),
        created_at: .created_at,
        last_used: (.last_used // null),
        verified: (.verified // null)
      } ]' 2>/dev/null || echo '[]'
}

# Branches and which of them are protected. One call, and it tells you where
# write access actually means something.
access_branches() {
  provider_call list_branches "$1"
}

# Who is allowed to push to a protected branch, when the rule names people.
access_branch_restrictions() {
  local full_name="$1" branch="$2"
  local enc; enc=$(urlenc "$branch")
  local body; body=$(api_get_quiet "/repos/${full_name}/branches/${enc}/protection")
  [[ -z "$body" ]] && { echo 'null'; return 0; }
  printf '%s' "$body" | jq -c '{
    enforce_admins: (.enforce_admins.enabled // null),
    required_reviews: (.required_pull_request_reviews.required_approving_review_count // null),
    restricted: ((.restrictions != null)),
    push_users: [ (.restrictions.users // [])[].login ],
    push_teams: [ (.restrictions.teams // [])[].slug ],
    push_apps:  [ (.restrictions.apps  // [])[].slug ]
  }' 2>/dev/null || echo 'null'
}

# Org-level stuff, fetched once and reused across that org's repos.
access_org_outside_collaborators() {
  local org="$1"
  local body; body=$(api_paginate "/orgs/${org}/outside_collaborators" 100) || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c '[ .[]?.login ]' 2>/dev/null || echo '[]'
}

access_org_members() {
  local org="$1"
  local members admins
  members=$(api_paginate "/orgs/${org}/members" 100) || { echo '[]'; return 0; }
  admins=$(api_paginate "/orgs/${org}/members?role=admin" 100) || admins='[]'
  # A large organization has thousands of members.  On the command line this
  # failed and the `|| echo []` below then threw every member away in silence.
  local f_admins; f_admins=$(json_file "$admins" admins)
  printf '%s' "$members" | jq -c --slurpfile admins_in "$f_admins" --arg org "$org" '
    ($admins_in[0]) as $admins
    | ([ $admins[]?.login ] | map(ascii_downcase)) as $A
    | [ .[]?
        | . as $m
        | ($m.login | ascii_downcase) as $l
        | {
        organization: $org,
        login: .login,
        id: .id,
        type: (.type // "User"),
        site_admin: (.site_admin // false),
        org_role: (if ($A | index($l)) != null then "admin" else "member" end),
        html_url: (.html_url // null)
      } ]' 2>/dev/null || echo '[]'
}

# Members whose 2FA is off. Requires org owner rights; absent otherwise.
access_org_2fa_disabled() {
  local org="$1"
  # Reporting nobody without 2FA because the endpoint does not exist would be
  # a comforting lie.
  if ! provider_supports two_factor_status; then
    log_debug "$(provider_name) has no way to report who has two step off, so it is not asked for"
    echo 'null'; return 0
  fi
  local body; body=$(api_paginate "/orgs/${org}/members?filter=2fa_disabled" 100) || { echo 'null'; return 0; }
  printf '%s' "$body" | jq -c '[ .[]?.login ]' 2>/dev/null || echo 'null'
}

access_org_profile() {
  local org="$1"
  local body; body=$(api_get_quiet "/orgs/${org}")
  [[ -z "$body" ]] && { echo 'null'; return 0; }
  printf '%s' "$body" | jq -c '{
    login, id,
    name: (.name // null),
    two_factor_requirement_enabled: (.two_factor_requirement_enabled // null),
    default_repository_permission: (.default_repository_permission // null),
    members_can_create_repositories: (.members_can_create_repositories // null),
    public_repos, total_private_repos: (.total_private_repos // null),
    html_url
  }' 2>/dev/null || echo 'null'
}

# Per-repository roll-up
# access_for_repo <full_name> <outside_logins_json> -> one access object
access_for_repo() {
  local full_name="$1" outside="${2:-[]}"
  local sources; sources=$(cfg_json '.scan.access.sources // []')
  local users='[]' teams='[]' invites='[]' keys='[]' err='null' branches='[]'

  if printf '%s' "$sources" | jq -e 'index("collaborators")' >/dev/null; then
    local direct; direct=$(access_direct_collaborators "$full_name")
    if ! users=$(access_collaborators "$full_name" "$direct" "$outside"); then
      users='[]'
      err='"collaborator listing denied - the token needs push access to this repository (HTTP 403/404)"'
      log_debug "$full_name: cannot list collaborators"
    fi
  fi
  printf '%s' "$sources" | jq -e 'index("teams")'       >/dev/null && teams=$(access_teams "$full_name")
  if printf '%s' "$sources" | jq -e 'index("branches")' >/dev/null; then
    branches=$(access_branches "$full_name")
    if cfg_bool '.scan.access.branch_protection_detail' false; then
      local acc; acc=$(tmp_file brprot); echo '[]' > "$acc"
      local bn prot
      while IFS= read -r bn; do
        [[ -z "$bn" ]] && continue
        prot=$(access_branch_restrictions "$full_name" "$bn")
        jq -c --arg n "$bn" --argjson p "$prot" '. + [{name: $n, protection: $p}]' "$acc" > "${acc}.n" && mv "${acc}.n" "$acc"
      done < <(printf '%s' "$branches" | jq -r '.[] | select(.protected) | .name')
      local f_br; f_br=$(json_file "$branches" branches)
      branches=$(jq -cn --slurpfile b_in "$f_br" --slurpfile d "$acc" '
        ($b_in[0]) as $b
        | [ $b[] | . as $x | $x + {protection: (($d[0][] | select(.name == $x.name) | .protection) // null)} ]')
    fi
  fi
  printf '%s' "$sources" | jq -e 'index("invitations")' >/dev/null && invites=$(access_invitations "$full_name")
  printf '%s' "$sources" | jq -e 'index("deploy_keys")' >/dev/null && keys=$(access_deploy_keys "$full_name")

  local include_bots; include_bots=$(cfg_bool '.scan.access.include_bots' true && echo true || echo false)

  local f_users f_teams f_invites f_keys f_branches2
  f_users=$(json_file "$users" users)
  f_teams=$(json_file "$teams" teams)
  f_invites=$(json_file "$invites" invites)
  f_keys=$(json_file "$keys" keys)
  f_branches2=$(json_file "$branches" branches)
  jq -cn \
    --slurpfile users_in "$f_users" --slurpfile teams_in "$f_teams" \
    --slurpfile invites_in "$f_invites" --slurpfile keys_in "$f_keys" \
    --argjson err "$err" --argjson include_bots "$include_bots" \
    --slurpfile branches_in "$f_branches2" '
    def rank: if . == "admin" then 5 elif . == "maintain" then 4
              elif . == "write" or . == "push" then 3 elif . == "triage" then 2
              elif . == "read" or . == "pull" then 1 else 0 end;
    ($users_in[0]) as $users
    | ($teams_in[0]) as $teams
    | ($invites_in[0]) as $invites
    | ($keys_in[0]) as $keys
    | ($branches_in[0]) as $branches
    | ($users | if $include_bots then . else map(select(.type != "Bot")) end) as $u
    | {
        error: $err,
        branches: $branches,
        users: ($u | sort_by([-(.permission | rank), .login])),
        teams: $teams,
        pending_invitations: $invites,
        deploy_keys: $keys,
        counts: {
          users:         ($u | length),
          admins:        ([ $u[] | select(.permission == "admin") ]        | length),
          writers:       ([ $u[] | select(.permission | rank >= 3) ]       | length),
          read_only:     ([ $u[] | select(.permission | rank == 1) ]       | length),
          direct:        ([ $u[] | select(.affiliation == "direct") ]      | length),
          inherited:     ([ $u[] | select(.affiliation == "inherited") ]   | length),
          outside:       ([ $u[] | select(.outside_collaborator) ]         | length),
          bots:          ([ $u[] | select(.type == "Bot") ]                | length),
          branches:            ($branches | length),
          protected_branches:  ([ $branches[] | select(.protected) ] | length),
          teams:         ($teams   | length),
          invitations:   ($invites | length),
          deploy_keys:   ($keys    | length),
          write_deploy_keys: ([ $keys[] | select(.read_only == false) ]    | length)
        }
      }'
}
