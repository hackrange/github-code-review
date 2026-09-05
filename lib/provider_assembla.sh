#!/usr/bin/env bash
# Assembla.
#
# A space is what a group of repositories is called, and a repository is a
# "space tool" inside one, which is why listing them is two calls rather than
# one: the spaces, then the git tools in each.
#
# Auth is two headers rather than one, an API key and its secret, so the
# secret travels as the token and the key rides beside it in the config.
# shellcheck shell=bash

provider_assembla_api_default() { printf 'https://api.assembla.com/v1'; }
provider_assembla_web_default() { printf 'https://app.assembla.com'; }

# Assembla wants X-Api-Key and X-Api-Secret rather than an Authorization
# header.  The key is not a secret on its own, so it sits in the config; the
# secret is the credential and comes in as the token.
provider_assembla_auth_header_line() {
  local key; key=$(cfg '.github.username' '')
  printf 'header = "X-Api-Key: %s"\nheader = "X-Api-Secret: %s"' "$key" "$1"
}

provider_assembla_api_headers() {
  printf '%s\n' "Accept: application/json"
}

provider_assembla_git_username() { cfg '.github.username' 'git'; }

provider_assembla_whoami_path()  { printf 'user.json'; }
provider_assembla_whoami_field() { printf '.name // .login // .email'; }

provider_assembla_git_url() {
  local path="$1" web
  web=$(cfg '.github.web_url' "$(provider_assembla_web_default)")
  printf '%s/%s.git' "${web%/}" "$path"
}

provider_assembla_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web
  web=$(cfg '.github.web_url' "$(provider_assembla_web_default)")
  printf '%s/spaces/%s/git/source/%s/%s' "${web%/}" "${repo%%/*}" "$(urlencode "$ref")" "$file"
  (( line > 0 )) && printf '#L%s' "$line"
  printf '\n'
}

provider_assembla_list_groups() {
  local body; body=$(api_get "$(_api_url 'spaces.json?per_page=100')") || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c '[ .[]? | (.wiki_name // .name // empty) ] | unique' \
    2>/dev/null || echo '[]'
}

provider_assembla_no_groups_warning() {
  log_warn "no spaces came back. Check the API key and secret are both set, and that the key belongs to an account with a space on it."
}

provider_assembla_list_repos() {
  local spaces; spaces=$(provider_assembla_list_groups)
  local raw; raw=$(tmp_file asrepos); echo '[]' > "$raw"
  local chunk_f; chunk_f=$(tmp_file aschunk)
  local any=0

  local space
  while IFS= read -r space; do
    [[ -n "$space" ]] || continue
    local body
    if ! body=$(api_get "$(_api_url "spaces/$(urlencode "$space")/space_tools.json")"); then
      log_warn "could not read the tools in space $space; it is left out rather than reported empty"
      continue
    fi
    any=1
    # Only the git repositories.  A space also holds wikis, ticket trackers and
    # Subversion tools, and none of those is something to clone.
    printf '%s' "$body" | jq -c --arg space "$space" '
      [ .[]? | select((.type // .tool_id // "") | test("git"; "i"))
        | . + {_space: $space} ]' > "$chunk_f" 2>/dev/null || echo '[]' > "$chunk_f"
    jq -c --slurpfile c "$chunk_f" '. + $c[0]' "$raw" > "${raw}.n" && mv "${raw}.n" "$raw"
  done < <(printf '%s' "$spaces" | jq -r '.[]?')

  if (( any == 0 )); then
    log_error "no Assembla space could be read; refusing to report an empty estate"
    return 1
  fi
  provider_assembla_normalize "$raw"
}

provider_assembla_normalize() {
  jq -c '
    map({
      full_name:      ((._space // "unknown") + "/" + (.name // .url // "")),
      name:           (.name // .url // ""),
      owner:          (._space // "unknown"),
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
      size_kb:        0,
      language:       null,
      html_url:       (.url // null),
      clone_url:      (.repository_url // .url // null),
      pushed_at:      null,
      license_api:    null
    })
    | map(select(.name != ""))' "$1"
}

provider_assembla_list_branches() {
  # Assembla has no branch listing on the space tools API.  Saying so once is
  # better than an empty list that reads as "this repository has no branches".
  log_debug "assembla has no branch listing; the default branch is used"
  echo '[]'
}
