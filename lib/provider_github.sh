#!/usr/bin/env bash
# GitHub.  This is the behavior everything had before there was a choice, so
# these are deliberately thin: they are the reference the others are read
# against.
# shellcheck shell=bash

provider_github_api_default()  { printf 'https://api.github.com'; }
provider_github_web_default()  { printf 'https://github.com'; }

# GitHub accepts "Authorization: token X" for a PAT and for an installation
# token alike.
provider_github_auth_header_line() {
  printf 'header = "Authorization: token %s"' "$1"
}

provider_github_api_headers() {
  printf '%s\n' \
    "Accept: application/vnd.github+json" \
    "X-GitHub-Api-Version: 2022-11-28"
}

# owner/repo -> https://github.com/owner/repo.git
provider_github_git_url() {
  local path="$1" web
  web=$(cfg '.github.web_url' "$(provider_github_web_default)")
  printf '%s/%s.git' "${web%/}" "$path"
}

# A link to a line of a file at a commit.
provider_github_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web
  web=$(cfg '.github.web_url' "$(provider_github_web_default)")
  printf '%s/%s/blob/%s/%s' "${web%/}" "$repo" "$ref" "$file"
  (( line > 0 )) && printf '#L%s' "$line"
  printf '\n'
}

# Every repository this credential can reach, normalized.
#
# This is the enumeration that used to live in inventory_repos.  It is GitHub
# shaped from top to bottom: organizations are flat, an App installation can be
# asked what it was installed on, and /user/repos catches what is shared with
# the account directly.
provider_github_list_repos() {
  local raw; raw=$(tmp_file repos)
  echo '[]' > "$raw"
  # One reused file rather than one per merge.
  local merge_f; merge_f=$(tmp_file merge)

  # A page of repositories is hundreds of kilobytes and does not fit in an
  # argument.  On the command line this came back empty with a zero exit, so an
  # org with fifty repositories reported "0 repositories in scope" and the
  # report simply left it out.  A partial inventory is worse than no inventory,
  # so a failure here stops the scan instead of shortening the list.
  _merge() {
    printf '%s' "${1:-[]}" > "$merge_f"
    if ! jq -c --slurpfile c "$merge_f" '. + $c[0]' "$raw" > "${raw}.n"; then
      log_error "could not merge a repository list; refusing to report a partial inventory"
      return 1
    fi
    mv "${raw}.n" "$raw"
  }

  local method; method=$(cfg '.github.auth.method' 'pat')

  # A GitHub App can enumerate exactly what it was installed on - one call, no
  # org listing permission needed, and it never trips SAML SSO.
  if [[ "$method" == "app" ]]; then
    log_info "enumerating repositories visible to the App installation"
    local body; body=$(api_paginate '/installation/repositories' 100) || body='[]'
    _merge "$(printf '%s' "$body" | jq -c '.')"
  fi

  # Resolve the org list once (configured, or discovered) and reuse it. The
  # caller can pre-seed GHSCAN_ORGS to avoid a second discovery round trip.
  local orgs_json="${GHSCAN_ORGS:-}"
  [[ -z "$orgs_json" ]] && orgs_json=$(inventory_orgs)
  GHSCAN_ORGS="$orgs_json"; export GHSCAN_ORGS

  local org
  while IFS= read -r org; do
    [[ -z "$org" ]] && continue
    if [[ "$method" == "app" ]]; then
      log_debug "org '$org' covered by the installation listing"
      continue
    fi
    log_info "enumerating repositories for org: $org"
    local vis; vis=$(cfg '.github.scope.visibility' 'all')
    local body
    body=$(api_paginate "/orgs/${org}/repos?type=${vis}&sort=full_name" 100) || {
      log_warn "could not list repos for org '$org' (see errors above)"
      continue
    }
    _merge "$(printf '%s' "$body" | jq -c '.')"
  done < <(printf '%s' "$orgs_json" | jq -r '.[]?')

  # /orgs/{org}/repos misses personal repos and ones shared with the user
  # directly. /user/repos catches those. Duplicates get deduped below.
  if [[ "$method" != "app" ]] && cfg_bool '.github.scope.include_collaborator_repos' true; then
    local aff; aff=$(cfg '.github.scope.affiliation' 'owner,collaborator,organization_member')
    log_info "enumerating repositories reachable by the token (affiliation: $aff)"
    local body
    body=$(api_paginate "/user/repos?affiliation=${aff}&sort=full_name" 100) || body='[]'
    local n; n=$(printf '%s' "$body" | jq 'length')
    log_debug "/user/repos returned $n repositor$([[ "$n" == "1" ]] && echo y || echo ies)"
    _merge "$(printf '%s' "$body" | jq -c '.')"
  fi

  local user
  while IFS= read -r user; do
    [[ -z "$user" ]] && continue
    log_info "enumerating repositories for user: $user"
    local body; body=$(api_paginate "/users/${user}/repos?type=owner&sort=full_name" 100) || continue
    _merge "$(printf '%s' "$body" | jq -c '.')"
  done < <(cfg_arr '.github.scope.users')

  local explicit
  while IFS= read -r explicit; do
    [[ -z "$explicit" ]] && continue
    log_debug "fetching explicitly included repo: $explicit"
    local body; body=$(api_get "/repos/${explicit}") || { log_warn "cannot access repo '$explicit'"; continue; }
    _merge "$(printf '%s' "$body" | jq -c '[.]')"
  done < <(cfg_arr '.github.scope.include_repos')

  provider_github_normalize "$raw"
}

# Raw API objects in a file -> the shape everything downstream expects.
# is_template is carried through because the scope filter still has to see it.
provider_github_normalize() {
  jq -c '
    map({
      full_name, name,
      owner:          (.owner.login // (.full_name | split("/")[0])),
      owner_type:     (.owner.type // "Organization"),
      permissions:    (.permissions // null),
      role_name:      (.role_name // null),
      id, node_id,
      private:        (.private // false),
      visibility:     (.visibility // (if .private then "private" else "public" end)),
      archived:       (.archived // false),
      fork:           (.fork // false),
      is_template:    (.is_template // false),
      default_branch: (.default_branch // "main"),
      size_kb:        (.size // 0),
      language:       .language,
      html_url:       .html_url,
      clone_url:      .clone_url,
      pushed_at:      .pushed_at,
      license_api:    (if .license then {spdx_id: .license.spdx_id, name: .license.name, key: .license.key} else null end)
    })' "$1"
}

# Every organization this credential can see.
provider_github_list_groups() {
  local method; method=$(cfg '.github.auth.method' 'pat')
  if [[ "$method" == "app" ]]; then
    # An App sees its installations, not a user's org memberships.
    local body; body=$(api_paginate '/installation/repositories' 100) || body='[]'
    printf '%s' "$body" | jq -c '[ .[].owner.login ] | unique'
    return 0
  fi
  local body; body=$(api_paginate '/user/orgs' 100) || body='[]'
  printf '%s' "$body" | jq -c '[ .[].login ] | unique'
}

provider_github_no_groups_warning() {
  log_warn "/user/orgs returned nothing. Either the token has no 'read:org' scope, or the account belongs to no organizations. Personal repositories are still covered via /user/repos."
}

# GitHub takes any non empty username with a token as the password; this is the
# one its own documentation uses.
provider_github_git_username() { printf 'x-access-token'; }

# Branches and which of them are protected.
provider_github_list_branches() {
  local full_name="$1"
  local body; body=$(api_paginate "/repos/${full_name}/branches" 100) || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c '[ .[]? | {name: .name, protected: (.protected // false)} ]' 2>/dev/null || echo '[]'
}

provider_github_whoami_path()  { printf 'user'; }
provider_github_whoami_field() { printf '.login'; }
