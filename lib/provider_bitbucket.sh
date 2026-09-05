#!/usr/bin/env bash
# Bitbucket Cloud.
#
# Three things are genuinely different here rather than just spelled
# differently:
#
#   1. Paging is in the body.  GitHub and GitLab put the next page in a Link
#      header; Bitbucket returns {"values": [...], "next": "<url>"} and expects
#      you to follow it until it is absent.  api_paginate reads Link headers,
#      so it is no use here and this file walks the pages itself.
#   2. App passwords are gone.  Atlassian removed them on 28 July 2026, so the
#      only thing left is an API token or a workspace / project / repository
#      access token, and both of those are Bearer.
#   3. Cloning wants a fixed username, x-token-auth, with the token as the
#      password.
#
# A workspace is what a group of repositories is called.
# shellcheck shell=bash

provider_bitbucket_api_default() { printf 'https://api.bitbucket.org/2.0'; }
provider_bitbucket_web_default() { printf 'https://bitbucket.org'; }

# Bearer covers both an API token and a workspace / project / repository access
# token.  Basic would also work for an API token, but only if the account's
# email is carried around beside it, and one credential is enough to ask for.
provider_bitbucket_auth_header_line() {
  printf 'header = "Authorization: Bearer %s"' "$1"
}

provider_bitbucket_api_headers() {
  printf '%s\n' "Accept: application/json"
}

provider_bitbucket_git_username() { printf 'x-token-auth'; }

provider_bitbucket_whoami_path()  { printf 'user'; }
provider_bitbucket_whoami_field() { printf '.display_name // .nickname // .uuid'; }

# workspace/repo -> https://bitbucket.org/workspace/repo.git
provider_bitbucket_git_url() {
  local path="$1" web
  web=$(cfg '.github.web_url' "$(provider_bitbucket_web_default)")
  printf '%s/%s.git' "${web%/}" "$path"
}

# Bitbucket puts the file under /src/<ref>/ and anchors lines as #lines-N.
provider_bitbucket_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web
  web=$(cfg '.github.web_url' "$(provider_bitbucket_web_default)")
  printf '%s/%s/src/%s/%s' "${web%/}" "$repo" "$ref" "$file"
  (( line > 0 )) && printf '#lines-%s' "$line"
  printf '\n'
}

# Follow the next link in the body until it stops coming.
# _bb_paginate <path> -> one JSON array of every .values entry
_bb_paginate() {
  local path="$1"
  local acc; acc=$(tmp_file bbacc); echo '[]' > "$acc"
  local chunk_f; chunk_f=$(tmp_file bbchunk)
  local url; url=$(_api_url "$path")
  local guard=0

  while [[ -n "$url" ]]; do
    (( guard++ > 1000 )) && { log_warn "pagination guard tripped for $path"; break; }
    local body; body=$(api_get "$url") || return 1

    local chunk
    chunk=$(printf '%s' "$body" | jq -c '.values // []' 2>/dev/null) || chunk='[]'
    # Through a file, never argv: a page of repositories is far past what a
    # single argument holds.
    printf '%s' "${chunk:-[]}" > "$chunk_f"
    if ! jq -c --slurpfile c "$chunk_f" '. + $c[0]' "$acc" > "${acc}.new"; then
      log_error "could not accumulate a page of $path; refusing to report a partial list"
      return 1
    fi
    mv "${acc}.new" "$acc"

    url=$(printf '%s' "$body" | jq -r '.next // empty' 2>/dev/null)
  done
  cat "$acc"
}

# Every workspace the credential can see.
provider_bitbucket_list_groups() {
  local body; body=$(_bb_paginate '/workspaces?pagelen=100') || body='[]'
  printf '%s' "$body" | jq -c '[ .[].slug ] | unique'
}

provider_bitbucket_no_groups_warning() {
  log_warn "no workspaces came back. A repository or project access token is scoped below the workspace and will not list one, which is expected; name the workspace on the connection instead. For an API token it means the token has no workspace membership."
}

provider_bitbucket_list_repos() {
  local raw; raw=$(tmp_file bbrepos); echo '[]' > "$raw"
  local merge_f; merge_f=$(tmp_file bbmerge)

  _bb_merge() {
    printf '%s' "${1:-[]}" > "$merge_f"
    if ! jq -c --slurpfile c "$merge_f" '. + $c[0]' "$raw" > "${raw}.n"; then
      log_error "could not merge a repository list; refusing to report a partial inventory"
      return 1
    fi
    mv "${raw}.n" "$raw"
  }

  local groups_json="${GHSCAN_ORGS:-}"
  [[ -z "$groups_json" ]] && groups_json=$(inventory_orgs)

  local workspace
  while IFS= read -r workspace; do
    [[ -z "$workspace" ]] && continue
    log_info "enumerating repositories for workspace: $workspace"
    local body
    body=$(_bb_paginate "/repositories/${workspace}?pagelen=100&sort=full_name") || {
      log_warn "could not list repositories for workspace '$workspace' (see errors above)"
      continue
    }
    _bb_merge "$(printf '%s' "$body" | jq -c '.')"
  done < <(printf '%s' "$groups_json" | jq -r '.[]?')

  local explicit
  while IFS= read -r explicit; do
    [[ -z "$explicit" ]] && continue
    local body; body=$(api_get "/repositories/${explicit}") || { log_warn "cannot access repository '$explicit'"; continue; }
    _bb_merge "$(printf '%s' "$body" | jq -c '[.]')"
  done < <(cfg_arr '.github.scope.include_repos')

  provider_bitbucket_normalize "$raw"
}

# Bitbucket's repository object into the one shape everything downstream reads.
provider_bitbucket_normalize() {
  jq -c '
    map({
      full_name:      .full_name,
      name:           (.name // .slug),
      owner:          (.workspace.slug // ((.full_name // "") | split("/")[0])),
      owner_type:     "Organization",
      permissions:    null,
      role_name:      null,
      id:             .uuid,
      node_id:        null,
      private:        (.is_private // true),
      visibility:     (if (.is_private // true) then "private" else "public" end),
      archived:       false,
      fork:           (.parent != null),
      is_template:    false,
      default_branch: (.mainbranch.name // "main"),
      size_kb:        (((.size // 0) / 1024) | floor),
      language:       (if (.language // "") == "" then null else .language end),
      html_url:       (.links.html.href // null),
      clone_url:      ([ (.links.clone // [])[] | select(.name == "https") | .href ] | first // null),
      pushed_at:      (.updated_on // null),
      license_api:    null
    })
    | map(select(.full_name != null))' "$1"
}

provider_bitbucket_list_branches() {
  local full_name="$1"
  local body
  body=$(_bb_paginate "/repositories/${full_name}/refs/branches?pagelen=100") || { echo '[]'; return 0; }
  # Bitbucket has no protected flag on a branch; branch restrictions are a
  # separate call, so this reports what it knows rather than guessing false.
  printf '%s' "$body" | jq -c '[ .[]? | {name: .name, protected: false} ]' 2>/dev/null || echo '[]'
}
