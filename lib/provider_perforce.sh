#!/usr/bin/env bash
# Perforce Helix Core.
#
# Further from git than Subversion is, and the same honesty applies twice over.
#
# Perforce has no clone.  A client workspace is a mapping from depot paths to
# a directory, and `p4 sync` fills that directory with one revision of the
# files.  So what this scanner gets is a checkout: semgrep, syft, grype,
# osv-scanner, triage, exclusions and the report writers all work over it
# unchanged, and the credential engines see the files as they are now.
#
# What is missing is the same thing Subversion is missing, and for the same
# reason: gitleaks and trufflehog walk git history, and there is none here.  A
# credential that was submitted and later deleted is invisible.  `p4 filelog`
# could in principle find them, but that is a different engine rather than a
# provider, and pretending otherwise would put a number on a report that does
# not mean what a reader would take it to mean.
#
# A depot is the grouping, and a stream or a depot path stands in for a branch.
# shellcheck shell=bash

provider_perforce_api_default() { printf ''; }
provider_perforce_web_default() { printf ''; }

provider_perforce_auth_header_line() { printf ''; }
provider_perforce_api_headers() { printf ''; }
provider_perforce_git_username() { cfg '.github.username' ''; }

provider_perforce_whoami_path()  { printf ''; }
provider_perforce_whoami_field() { printf ''; }

_p4_env() {
  local port user
  port=$(cfg '.github.api_url' '')
  [[ -n "$port" ]] || port=$(cfg '.github.web_url' '')
  user=$(cfg '.github.username' '')
  printf 'P4PORT=%s\n' "${port#*://}"
  [[ -n "$user" ]] && printf 'P4USER=%s\n' "$user"
  [[ -n "${GHSCAN_TOKEN:-}" ]] && printf 'P4PASSWD=%s\n' "$GHSCAN_TOKEN"
}

# Run p4 with the connection's settings, and never write a ticket file into a
# home directory this container shares.
_p4() {
  local -a env_args=()
  local line
  while IFS= read -r line; do [[ -n "$line" ]] && env_args+=("$line"); done < <(_p4_env)
  env "${env_args[@]}" P4CONFIG=/dev/null p4 -z tag "$@" 2>/dev/null
}

provider_perforce_whoami() {
  provider_check_tool || return 1
  local who; who=$(_p4 info) || return 1
  printf '%s' "$who" | awk '/^\.\.\. userName /{print $3}' | head -1
}

provider_perforce_git_url() {
  # There is no URL to clone.  The depot path is what identifies the work, and
  # the scan step syncs it rather than cloning it.
  local path="$1"
  printf '//%s/...' "${path#*/}"
}

provider_perforce_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}"
  printf '//%s/%s\n' "${repo#*/}" "$file"
}

provider_perforce_list_groups() {
  provider_check_tool || { echo '[]'; return 1; }
  local out; out=$(_p4 depots) || { echo '[]'; return 1; }
  printf '%s' "$out" | awk '/^\.\.\. name /{print $3}' \
    | jq -R -s -c 'split("\n") | map(select(length > 0)) | unique' 2>/dev/null || echo '[]'
}

provider_perforce_no_groups_warning() {
  log_warn "no depots came back. Check P4PORT on the connection and that the account can run p4 depots."
}

# A depot is the closest thing to a repository here, so each depot is reported
# as one.  Splitting further would need somebody's stream layout, and guessing
# at that produces repositories nobody recognizes.
provider_perforce_list_repos() {
  provider_check_tool || { echo '[]'; return 1; }

  log_warn "perforce is scanned at its current revision only. History is not walked, so credentials that were submitted and later deleted are not found."

  local out; out=$(_p4 depots)
  if [[ -z "$out" ]]; then
    log_error "could not list depots; refusing to report an empty estate"
    echo '[]'; return 1
  fi

  local server; server=$(cfg '.github.organization' 'perforce')
  printf '%s' "$out" | awk '/^\.\.\. name /{print $3}' \
    | jq -R -s -c --arg server "$server" '
      split("\n") | map(select(length > 0))
      | map({
          full_name:      ($server + "/" + .),
          name:           .,
          owner:          $server,
          owner_type:     "Organization",
          permissions:    null, role_name: null, id: null, node_id: null,
          private:        true, visibility: "private",
          archived:       false, fork: false, is_template: false,
          default_branch: "main",
          size_kb:        0, language: null, html_url: null,
          clone_url:      null, pushed_at: null, license_api: null
        })' 2>/dev/null || echo '[]'
}

provider_perforce_normalize() { cat "$1"; }

provider_perforce_list_branches() {
  # Streams are the nearest equivalent and only exist on a stream depot.  Where
  # there are none this reports one, rather than reporting zero and having the
  # scan read that as a repository with nothing in it.
  provider_check_tool || { echo '[]'; return 0; }
  local full_name="$1" depot="${full_name#*/}"
  local out; out=$(_p4 streams "//${depot}/..." 2>/dev/null)
  local names
  names=$(printf '%s' "$out" | awk '/^\.\.\. Stream /{print $3}' \
          | jq -R -s -c 'split("\n") | map(select(length > 0))' 2>/dev/null)
  if [[ -z "$names" || "$names" == "[]" ]]; then
    echo '[{"name":"main","protected":false}]'
    return 0
  fi
  printf '%s' "$names" | jq -c '[ .[] | {name: ., protected: false} ]'
}
