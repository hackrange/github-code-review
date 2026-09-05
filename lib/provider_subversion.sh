#!/usr/bin/env bash
# Subversion.
#
# Read the roadmap entry before changing anything here.  The short version:
# most of this scanner reads files, and files are files, so semgrep, syft,
# grype, osv-scanner, the triage pass, the exclusions and both report writers
# all work unchanged over a Subversion checkout.
#
# What does not carry across is history, and history is the valuable half.
# gitleaks and trufflehog find credentials that were committed and later
# deleted by walking git history.  A Subversion checkout is one revision, so
# what comes back is the credentials still in the tree, which is the half
# somebody already knows about.
#
# This is the checkout only mode the roadmap describes as an honest first
# step.  It scans, and it says plainly what it did not look at.  The mirror
# approach, git svn clone into a kept volume, gets the history back and is a
# larger piece of work with an ongoing cost; it is not this.
#
# A branch in Subversion is a directory convention rather than a thing to
# enumerate, so what gets scanned is trunk unless the connection says
# otherwise.
# shellcheck shell=bash

provider_subversion_api_default() { printf ''; }
provider_subversion_web_default() { printf ''; }

# No API, so no headers and no bearer anything.  The credential is a username
# and password handed to svn on the command line.
provider_subversion_auth_header_line() { printf ''; }
provider_subversion_api_headers() { printf ''; }
provider_subversion_git_username() { cfg '.github.username' ''; }

provider_subversion_whoami_path()  { printf ''; }
provider_subversion_whoami_field() { printf ''; }

provider_subversion_whoami() {
  provider_check_tool || return 1
  local user; user=$(cfg '.github.username' '')
  printf '%s' "${user:-an anonymous subversion client}"
}

_svn_root() {
  local web; web=$(cfg '.github.web_url' '')
  [[ -n "$web" ]] || web=$(cfg '.github.api_url' '')
  printf '%s' "${web%/}"
}

# svn wants the credential as arguments.  --no-auth-cache keeps it out of the
# home directory it would otherwise write to.
_svn_args() {
  local user pass
  user=$(cfg '.github.username' '')
  pass="${GHSCAN_TOKEN:-}"
  printf '%s\n' --non-interactive --trust-server-cert-failures=unknown-ca --no-auth-cache
  [[ -n "$user" ]] && printf '%s\n%s\n' --username "$user"
  [[ -n "$pass" ]] && printf '%s\n%s\n' --password "$pass"
}

provider_subversion_git_url() {
  local path="$1"
  printf '%s/%s' "$(_svn_root)" "${path#*/}"
}

provider_subversion_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}"
  # No web interface is guaranteed, so this points at the repository path the
  # file came from, which is the one thing that is always true.
  printf '%s/%s/%s\n' "$(_svn_root)" "${repo#*/}" "$file"
}

provider_subversion_list_groups() {
  local root; root=$(_svn_root)
  [[ -n "$root" ]] && printf '["%s"]' "$(basename "$root")" || printf '[]'
}

provider_subversion_no_groups_warning() {
  log_warn "no subversion address is set on the connection."
}

# What lives under the root.  A Subversion server usually holds several
# repositories side by side; listing the root shows them.
provider_subversion_list_repos() {
  provider_check_tool || { echo '[]'; return 1; }
  local root; root=$(_svn_root)
  if [[ -z "$root" ]]; then
    provider_subversion_no_groups_warning
    echo '[]'; return 1
  fi

  log_warn "subversion is scanned at its current revision only. History is not walked, so credentials that were committed and later removed are not found. See the report for what this covers."

  local -a args; mapfile -t args < <(_svn_args)
  local listing
  if ! listing=$(svn list "${args[@]}" "$root" 2>/dev/null); then
    log_error "could not list $root; refusing to report an empty estate"
    echo '[]'; return 1
  fi

  local group; group=$(basename "$root")
  # Directory entries only.  A file at the root of a server is not a
  # repository, and svn marks directories with a trailing slash.
  printf '%s' "$listing" | jq -R -s -c --arg group "$group" '
    split("\n") | map(select(endswith("/"))) | map(rtrimstr("/"))
    | map(select(length > 0))
    | map({
        full_name:      ($group + "/" + .),
        name:           .,
        owner:          $group,
        owner_type:     "Organization",
        permissions:    null, role_name: null, id: null, node_id: null,
        private:        true, visibility: "private",
        archived:       false, fork: false, is_template: false,
        # trunk is the convention.  It is a convention and not a rule, which
        # is exactly why branches cannot be enumerated here.
        default_branch: "trunk",
        size_kb:        0, language: null, html_url: null,
        clone_url:      null, pushed_at: null, license_api: null
      })' 2>/dev/null || echo '[]'
}

provider_subversion_normalize() { cat "$1"; }

provider_subversion_list_branches() {
  # A branch is a directory under branches/, by convention, on servers that
  # follow it.  Reporting trunk alone is honest; guessing at a layout and
  # scanning whatever is there would report paths as branches that nobody
  # calls branches.
  log_debug "subversion has no branch list; scanning the configured path only"
  echo '[{"name":"trunk","protected":false}]'
}
