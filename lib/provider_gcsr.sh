#!/usr/bin/env bash
# Google Cloud Source Repositories.
#
# The API is plain REST and would take a bearer token happily, but getting one
# means signing a JWT with a service account key and exchanging it, which is
# again a security control this would be writing for the second time.  The
# gcloud CLI already does it, and an operator running this against Google
# Cloud has it, so this asks gcloud for the token and makes the calls itself.
#
# Cloning uses the same token as a password with a fixed username, which is
# what Google documents for HTTPS access.
#
# Worth knowing: Google closed Cloud Source Repositories to new customers in
# mid 2024.  This is for projects that already have repositories in it.
#
# A project is the grouping.
# shellcheck shell=bash

provider_gcsr_api_default() { printf 'https://sourcerepo.googleapis.com/v1'; }
provider_gcsr_web_default() { printf 'https://source.cloud.google.com'; }

_gcsr_token() {
  gcloud auth print-access-token 2>/dev/null
}

# The token is fetched rather than configured, so the header line is built at
# the moment it is needed.
provider_gcsr_auth_header_line() {
  local token; token=$(_gcsr_token)
  [[ -n "$token" ]] || return 1
  printf 'header = "Authorization: Bearer %s"' "$token"
}

provider_gcsr_api_headers() {
  printf '%s\n' "Accept: application/json"
}

provider_gcsr_git_username() { printf 'oauth2accesstoken'; }

_gcsr_project() {
  local p; p=$(cfg '.github.organization' '')
  [[ -n "$p" ]] && { printf '%s' "$p"; return 0; }
  gcloud config get-value project 2>/dev/null | grep -v '^(unset)$'
}

provider_gcsr_whoami_path()  { printf ''; }
provider_gcsr_whoami_field() { printf ''; }

provider_gcsr_whoami() {
  provider_check_tool || return 1
  gcloud config get-value account 2>/dev/null | grep -v '^(unset)$'
}

provider_gcsr_git_url() {
  local path="$1" project
  project=$(_gcsr_project)
  printf 'https://source.developers.google.com/p/%s/r/%s' "$project" "${path#*/}"
}

provider_gcsr_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web project
  web=$(cfg '.github.web_url' "$(provider_gcsr_web_default)")
  project=$(_gcsr_project)
  printf '%s/%s/%s/+/%s:%s' "${web%/}" "$project" "${repo#*/}" "$(urlencode "$ref")" "$file"
  printf '\n'
}

provider_gcsr_list_groups() {
  local project; project=$(_gcsr_project)
  [[ -n "$project" ]] && printf '["%s"]' "$project" || printf '[]'
}

provider_gcsr_no_groups_warning() {
  log_warn "no project is set. Cloud Source Repositories is scoped to a project, so name it on the connection or set it with gcloud config set project."
}

provider_gcsr_list_repos() {
  provider_check_tool || { echo '[]'; return 1; }
  local project; project=$(_gcsr_project)
  if [[ -z "$project" ]]; then
    provider_gcsr_no_groups_warning
    echo '[]'; return 1
  fi

  local api; api=$(cfg '.github.api_url' "$(provider_gcsr_api_default)")
  local raw; raw=$(tmp_file gcrepos); echo '[]' > "$raw"
  local chunk_f; chunk_f=$(tmp_file gcchunk)
  local page="" guard=0

  while (( guard++ < 200 )); do
    local url="${api%/}/projects/${project}/repos?pageSize=500"
    [[ -n "$page" ]] && url="${url}&pageToken=${page}"
    local body
    if ! body=$(api_get "$url"); then
      log_error "could not list Cloud Source Repositories; refusing to report an empty estate"
      echo '[]'; return 1
    fi
    printf '%s' "$body" | jq -c '.repos // []' > "$chunk_f" 2>/dev/null || echo '[]' > "$chunk_f"
    jq -c --slurpfile c "$chunk_f" '. + $c[0]' "$raw" > "${raw}.n" && mv "${raw}.n" "$raw"
    page=$(printf '%s' "$body" | jq -r '.nextPageToken // empty' 2>/dev/null)
    [[ -n "$page" ]] || break
  done

  provider_gcsr_normalize "$raw"
}

provider_gcsr_normalize() {
  local project; project=$(_gcsr_project)
  jq -c --arg project "$project" '
    map({
      # The name comes back as projects/<p>/repos/<name>, and the name itself
      # can contain slashes, which is why this takes everything after the
      # marker rather than the last segment.
      _short: ((.name // "") | sub("^projects/[^/]+/repos/"; "")),
      raw: .
    })
    | map({
        full_name:      ($project + "/" + ._short),
        name:           ._short,
        owner:          $project,
        owner_type:     "Organization",
        permissions:    null,
        role_name:      null,
        id:             (.raw.name // null),
        node_id:        null,
        private:        true,
        visibility:     "private",
        archived:       false,
        fork:           false,
        is_template:    false,
        default_branch: "master",
        size_kb:        (((.raw.size // 0 | tonumber? // 0) / 1024) | floor),
        language:       null,
        html_url:       (.raw.url // null),
        clone_url:      (.raw.url // null),
        pushed_at:      null,
        license_api:    null
      })
    | map(select(.name != ""))' "$1"
}

provider_gcsr_list_branches() {
  # There is no branch listing on this API.  The clone carries every branch,
  # and the scanner reads them from it, so this says nothing rather than
  # claiming a repository has none.
  log_debug "cloud source repositories has no branch listing; branches come from the clone"
  echo '[]'
}
