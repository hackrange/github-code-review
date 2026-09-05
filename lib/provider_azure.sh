#!/usr/bin/env bash
# Azure Repos, in Azure DevOps Services.
#
# Four things differ from the others rather than being spelled differently:
#
#   1. The organization is in the base address, not in a path.  Every call is
#      https://dev.azure.com/<org>/_apis/..., so the connection carries the
#      organization and there is no listing above it.
#   2. A project sits between the organization and the repository, and it is
#      what a group of repositories means here.
#   3. Auth is Basic with an empty username and the personal access token as
#      the password, which is Microsoft's own documented shape.
#   4. Every call wants an api-version, and leaving it off returns a page of
#      HTML rather than an error anybody can read.
#
# full_name is project/repository.  The organization is the connection.
# shellcheck shell=bash

# The version to ask for.  Pinned rather than latest: an unpinned call is a
# call whose shape can change under a scan that has been running for a year.
AZURE_API_VERSION="${AZURE_API_VERSION:-7.1}"

provider_azure_api_default() { printf 'https://dev.azure.com'; }
provider_azure_web_default() { printf 'https://dev.azure.com'; }

# Basic, with nothing before the colon.  Microsoft documents the empty
# username, and a token in the password field is what the git remote wants too.
provider_azure_auth_header_line() {
  printf 'header = "Authorization: Basic %s"' "$(printf ':%s' "$1" | base64 -w0)"
}

provider_azure_api_headers() {
  printf '%s\n' "Accept: application/json"
}

# Any username works as long as the token is the password.  This one is only
# to make a log line legible.
provider_azure_git_username() { printf 'azure'; }

# The organization the connection points at.  Azure has no call that lists
# organizations from a plain PAT, so this is configuration rather than
# discovery.
_azure_org() {
  local org; org=$(cfg '.github.organization' '')
  [[ -n "$org" ]] && { printf '%s' "$org"; return 0; }
  # Fall back to the first configured scope, which is where the web interface
  # puts it.
  cfg_json '.github.scope.orgs // []' | jq -r '.[0] // empty'
}

_azure_base() {
  local api; api=$(cfg '.github.api_url' "$(provider_azure_api_default)")
  printf '%s/%s/_apis' "${api%/}" "$(_azure_org)"
}

_azure_get() {
  local url="$1"
  local sep='?'; [[ "$url" == *"?"* ]] && sep='&'
  api_get "${url}${sep}api-version=${AZURE_API_VERSION}"
}

provider_azure_whoami_path()  { printf 'projects'; }
provider_azure_whoami_field() { printf '"organization " + (.count | tostring) + " project(s)"'; }

# project/repo -> https://dev.azure.com/<org>/<project>/_git/<repo>
provider_azure_git_url() {
  local path="$1" web org
  web=$(cfg '.github.web_url' "$(provider_azure_web_default)")
  org=$(_azure_org)
  local project="${path%%/*}" repo="${path#*/}"
  printf '%s/%s/%s/_git/%s' "${web%/}" "$org" "$project" "$repo"
}

# Azure puts the file in a query string and the branch in a GB prefixed
# version, which is its own spelling of "git branch".
provider_azure_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web org
  web=$(cfg '.github.web_url' "$(provider_azure_web_default)")
  org=$(_azure_org)
  local project="${repo%%/*}" name="${repo#*/}"
  printf '%s/%s/%s/_git/%s?path=%s&version=GB%s' \
    "${web%/}" "$org" "$project" "$name" \
    "$(urlencode "/$file")" "$(urlencode "$ref")"
  (( line > 0 )) && printf '&line=%s&lineEnd=%s&lineStartColumn=1&lineEndColumn=1' "$line" "$line"
  printf '\n'
}

# The projects in the organization.  This is the group listing: there is
# nothing above the organization a plain token can enumerate.
provider_azure_list_groups() {
  local body; body=$(_azure_get "$(_azure_base)/projects?\$top=1000") || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c '[ (.value // [])[].name ] | unique' 2>/dev/null || echo '[]'
}

provider_azure_no_groups_warning() {
  log_warn "no projects came back. Azure has no call that lists organizations from a personal access token, so the organization has to be named on the connection; check it is set and that the token has Code (read) on it."
}

# Every repository in the organization, across every project, in one call.
provider_azure_list_repos() {
  local raw; raw=$(tmp_file azrepos)
  local body
  if ! body=$(_azure_get "$(_azure_base)/git/repositories"); then
    log_error "could not list Azure repositories; refusing to report an empty estate"
    echo '[]'; return 1
  fi
  printf '%s' "$body" | jq -c '.value // []' > "$raw" 2>/dev/null || echo '[]' > "$raw"
  provider_azure_normalize "$raw"
}

provider_azure_normalize() {
  jq -c '
    map(select(.isDisabled != true))
    | map({
        full_name:      ((.project.name // "unknown") + "/" + (.name // "")),
        name:           (.name // ""),
        owner:          (.project.name // "unknown"),
        owner_type:     "Organization",
        permissions:    null,
        role_name:      null,
        id:             (.id // null),
        node_id:        null,
        # Azure Repos is private unless the whole project is public.
        private:        ((.project.visibility // "private") != "public"),
        visibility:     (.project.visibility // "private"),
        archived:       false,
        fork:           (.isFork // false),
        is_template:    false,
        default_branch: ((.defaultBranch // "refs/heads/main") | sub("^refs/heads/"; "")),
        size_kb:        (((.size // 0) / 1024) | floor),
        language:       null,
        html_url:       (.webUrl // null),
        clone_url:      (.remoteUrl // null),
        pushed_at:      null,
        license_api:    null
      })
    | map(select(.name != ""))' "$1"
}

provider_azure_list_branches() {
  local full_name="$1"
  local project="${full_name%%/*}" repo="${full_name#*/}"
  local body
  body=$(_azure_get "$(_azure_base)/git/repositories/$(urlencode "$repo")/refs?filter=heads/&\$top=1000") \
    || { echo '[]'; return 0; }
  # Azure carries no protected flag on a ref.  Branch policies are a separate
  # call per branch, so this says what it knows rather than guessing false is
  # a fact.
  printf '%s' "$body" | jq -c '
    [ (.value // [])[]
      | {name: ((.name // "") | sub("^refs/heads/"; "")), protected: false}
      | select(.name != "") ]' 2>/dev/null || echo '[]'
}
