#!/usr/bin/env bash
# Beanstalk.
#
# One account is one address: https://<account>.beanstalkapp.com, and the API
# hangs off /api.  Auth is Basic with the username and an access token rather
# than a password.  There is nothing above the account to enumerate, so the
# account is the group and the connection names it.
#
# Beanstalk hosts Subversion repositories as well as git ones.  Those are
# reported and skipped rather than half scanned: the clone step is git, and a
# Subversion repository cloned by git is not a thing that happens.
# shellcheck shell=bash

provider_beanstalk_api_default() { printf ''; }
provider_beanstalk_web_default() { printf ''; }

provider_beanstalk_auth_header_line() {
  # The username rides in the config beside the token; Beanstalk wants both.
  local user; user=$(cfg '.github.username' '')
  printf 'header = "Authorization: Basic %s"' \
    "$(printf '%s:%s' "$user" "$1" | base64 -w0)"
}

provider_beanstalk_api_headers() {
  printf '%s\n' "Accept: application/json"
  printf '%s\n' "Content-Type: application/json"
}

provider_beanstalk_git_username() { cfg '.github.username' 'git'; }

provider_beanstalk_whoami_path()  { printf 'users/current.json'; }
provider_beanstalk_whoami_field() { printf '.user.name // .user.login // .user.email'; }

provider_beanstalk_git_url() {
  local path="$1" web
  web=$(cfg '.github.web_url' '')
  printf '%s/%s.git' "${web%/}" "${path#*/}"
}

provider_beanstalk_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web
  web=$(cfg '.github.web_url' '')
  printf '%s/%s/browse/git/%s?branch=%s' "${web%/}" "${repo#*/}" "$file" "$(urlencode "$ref")"
  (( line > 0 )) && printf '#L%s' "$line"
  printf '\n'
}

# The account is the only grouping, and it is configuration rather than
# something to discover.
provider_beanstalk_list_groups() {
  local account; account=$(cfg '.github.organization' '')
  [[ -n "$account" ]] && printf '["%s"]' "$account" || printf '[]'
}

provider_beanstalk_no_groups_warning() {
  log_warn "no account is set on the connection. Beanstalk has one address per account and nothing above it to list, so the account name has to be given."
}

provider_beanstalk_list_repos() {
  local raw; raw=$(tmp_file bsrepos); echo '[]' > "$raw"
  local page=1 chunk_f; chunk_f=$(tmp_file bschunk)

  while (( page <= 200 )); do
    local body
    if ! body=$(api_get "$(_api_url "repositories.json?page=${page}&per_page=50")"); then
      log_error "could not list Beanstalk repositories; refusing to report an empty estate"
      return 1
    fi
    local n; n=$(printf '%s' "$body" | jq 'length' 2>/dev/null || echo 0)
    (( n == 0 )) && break
    printf '%s' "$body" > "$chunk_f"
    jq -c --slurpfile c "$chunk_f" '. + $c[0]' "$raw" > "${raw}.n" && mv "${raw}.n" "$raw"
    (( n < 50 )) && break
    (( page++ ))
  done

  local svn; svn=$(jq '[ .[] | select((.repository.vcs // "git") != "git") ] | length' "$raw" 2>/dev/null || echo 0)
  (( svn > 0 )) && log_warn "$svn Beanstalk repository(ies) are Subversion and are skipped here; point a subversion connection at them instead."

  provider_beanstalk_normalize "$raw"
}

provider_beanstalk_normalize() {
  local account; account=$(cfg '.github.organization' 'beanstalk')
  jq -c --arg account "$account" '
    map(.repository // .)
    | map(select((.vcs // "git") == "git"))
    | map({
        full_name:      ($account + "/" + (.name // .title // "")),
        name:           (.name // .title // ""),
        owner:          $account,
        owner_type:     "Organization",
        permissions:    null,
        role_name:      null,
        id:             (.id // null),
        node_id:        null,
        private:        true,
        visibility:     "private",
        archived:       false,
        fork:           false,
        is_template:    false,
        default_branch: (.default_branch // "master"),
        size_kb:        (((.storage_used // 0) / 1024) | floor),
        language:       null,
        html_url:       null,
        clone_url:      (.repository_url // null),
        pushed_at:      (.last_commit_at // .updated_at // null),
        license_api:    null
      })
    | map(select(.name != ""))' "$1"
}

provider_beanstalk_list_branches() {
  local full_name="$1" name="${full_name#*/}"
  local body
  body=$(api_get "$(_api_url "repositories/$(urlencode "$name")/branches.json")") \
    || { echo '[]'; return 0; }
  # Beanstalk answers with a bare list of names.
  printf '%s' "$body" | jq -c '
    [ .[]? | (if type == "string" then . else (.name // empty) end)
      | select(. != null and . != "") | {name: ., protected: false} ]' \
    2>/dev/null || echo '[]'
}
