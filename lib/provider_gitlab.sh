#!/usr/bin/env bash
# GitLab.
#
# Two things shape this.  A GitLab token is not scoped to one group the way a
# fine grained GitHub token is scoped to one resource owner, so a single
# connection usually reaches the whole instance and there is no per group
# authorization step to trip over.  And a great many instances are the free
# tier or self managed, where the security features simply are not there.  So
# nothing here assumes an endpoint exists: what is missing is reported as
# missing rather than read as nothing found.
# shellcheck shell=bash

provider_gitlab_api_default() { printf 'https://gitlab.com/api/v4'; }
provider_gitlab_web_default() { printf 'https://gitlab.com'; }

# GitLab takes PRIVATE-TOKEN for a personal access token.  A bearer token works
# too but only for OAuth tokens, and sending both confuses it, so this sends
# the one that works for the credential people actually paste in.
provider_gitlab_auth_header_line() {
  printf 'header = "PRIVATE-TOKEN: %s"' "$1"
}

provider_gitlab_api_headers() {
  printf '%s\n' "Accept: application/json"
}

# group/subgroup/project -> https://gitlab.com/group/subgroup/project.git
# Subgroups nest, so the path can have more than two parts.  Nothing here has
# to care, because the path arrives already joined.
provider_gitlab_git_url() {
  local path="$1" web
  web=$(cfg '.github.web_url' "$(provider_gitlab_web_default)")
  printf '%s/%s.git' "${web%/}" "$path"
}

# GitLab puts /-/ in front of blob, which GitHub does not.
provider_gitlab_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web
  web=$(cfg '.github.web_url' "$(provider_gitlab_web_default)")
  printf '%s/%s/-/blob/%s/%s' "${web%/}" "$repo" "$ref" "$file"
  (( line > 0 )) && printf '#L%s' "$line"
  printf '\n'
}

# GitLab wants a namespace path URL encoded, so grp/sub becomes grp%2Fsub.
_gl_encode() {
  printf '%s' "$1" | jq -sRr '@uri' | sed 's/%0A$//'
}

# Every group the credential can see.
#
# min_access_level=10 is Guest, the lowest level that can actually read a
# project.  Without it this returns only groups the account owns.
provider_gitlab_list_groups() {
  local body
  body=$(api_paginate '/groups?min_access_level=10&order_by=path&sort=asc' 100) || body='[]'
  printf '%s' "$body" | jq -c '[ .[].full_path ] | unique'
}

provider_gitlab_no_groups_warning() {
  # A project access token is a member of one project and of no group at all,
  # so it sees zero groups and that is correct rather than broken.  Tested
  # against a real instance: the token came back as a project bot, /groups was
  # empty, and every project it could reach arrived through the membership
  # listing below.  Saying "none" without saying why sends somebody looking for
  # a permissions problem that is not there.
  log_warn "no groups came back. A project access token belongs to a project rather than a group, so this is expected for one of those; every project it is a member of is still found. For a group or personal token it means either no read_api scope or no group membership."
}

# Every project this credential can reach, normalized.
#
# Subgroups nest, which organizations do not, so include_subgroups=true is what
# stops a group with its work one level down from looking empty.
provider_gitlab_list_repos() {
  local raw; raw=$(tmp_file glrepos)
  echo '[]' > "$raw"
  local merge_f; merge_f=$(tmp_file glmerge)

  _gl_merge() {
    printf '%s' "${1:-[]}" > "$merge_f"
    if ! jq -c --slurpfile c "$merge_f" '. + $c[0]' "$raw" > "${raw}.n"; then
      log_error "could not merge a project list; refusing to report a partial inventory"
      return 1
    fi
    mv "${raw}.n" "$raw"
  }

  local groups_json="${GHSCAN_ORGS:-}"
  [[ -z "$groups_json" ]] && groups_json=$(inventory_orgs)

  local group
  while IFS= read -r group; do
    [[ -z "$group" ]] && continue
    log_info "enumerating projects for group: $group"
    local enc; enc=$(_gl_encode "$group")
    local body
    body=$(api_paginate "/groups/${enc}/projects?include_subgroups=true&archived=false&statistics=true&order_by=path&sort=asc" 100) || {
      log_warn "could not list projects for group '$group' (see errors above)"
      continue
    }
    _gl_merge "$(printf '%s' "$body" | jq -c '.')"
  done < <(printf '%s' "$groups_json" | jq -r '.[]?')

  # Projects the credential is a member of, which no group listing returns.
  #
  # This is not a nicety.  A project access token is a member of exactly one
  # project and of no group, so the group walk above finds nothing and this is
  # the only thing that finds anything at all.  Turning it off with such a
  # token gives an empty scan that reports success.
  if cfg_bool '.github.scope.include_collaborator_repos' true; then
    log_info "enumerating projects this credential is a member of"
    local body
    body=$(api_paginate '/projects?membership=true&statistics=true&order_by=path&sort=asc' 100) || body='[]'
    _gl_merge "$(printf '%s' "$body" | jq -c '.')"
  fi

  local explicit
  while IFS= read -r explicit; do
    [[ -z "$explicit" ]] && continue
    local enc; enc=$(_gl_encode "$explicit")
    local body; body=$(api_get "/projects/${enc}") || { log_warn "cannot access project '$explicit'"; continue; }
    _gl_merge "$(printf '%s' "$body" | jq -c '[.]')"
  done < <(cfg_arr '.github.scope.include_repos')

  provider_gitlab_normalize "$raw"
}

# GitLab's project object into the shape everything downstream expects.
# repository_size only comes back with statistics=true and the rights to ask,
# so a missing one is zero rather than a failure.
provider_gitlab_normalize() {
  jq -c '
    map({
      full_name:      .path_with_namespace,
      name:           (.name // .path),
      owner:          (.namespace.full_path // (.path_with_namespace | split("/")[0])),
      owner_type:     (if (.namespace.kind // "group") == "user" then "User" else "Organization" end),
      permissions:    null,
      role_name:      null,
      id:             .id,
      node_id:        null,
      private:        ((.visibility // "private") != "public"),
      visibility:     (.visibility // "private"),
      archived:       (.archived // false),
      fork:           (.forked_from_project != null),
      is_template:    false,
      default_branch: (.default_branch // "main"),
      size_kb:        (((.statistics.repository_size // 0) / 1024) | floor),
      language:       null,
      html_url:       .web_url,
      clone_url:      .http_url_to_repo,
      pushed_at:      .last_activity_at,
      license_api:    (if .license then {spdx_id: .license.key, name: .license.name, key: .license.key} else null end)
    })
    | map(select(.full_name != null))' "$1"
}

# GitLab wants oauth2 as the username when the password is a token.  Anything
# else is rejected, which reads as a wrong password rather than a wrong user.
provider_gitlab_git_username() { printf 'oauth2'; }

# GitLab keys the project by its encoded path and spells protection out on the
# branch itself, so one call answers the same question.
provider_gitlab_list_branches() {
  local full_name="$1"
  local enc; enc=$(_gl_encode "$full_name")
  local body
  body=$(api_paginate "/projects/${enc}/repository/branches" 100) || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c '[ .[]? | {name: .name, protected: (.protected // false)} ]' 2>/dev/null || echo '[]'
}

# GitLab calls it username, not login.  Reading .login gave "authenticated as
# null", which looks like a broken credential and is not.
provider_gitlab_whoami_path()  { printf 'user'; }
provider_gitlab_whoami_field() { printf '.username'; }
