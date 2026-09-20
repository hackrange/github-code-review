#!/usr/bin/env bash
# Gitea, and Forgejo, which is a fork of it and still speaks the same API.
#
# One file for the two of them.  Forgejo was forked from Gitea in 2022 and its
# API is still /api/v1 with the same objects in it, so a second copy of this
# would be two things to keep in step and one of them would drift.  The names
# stay apart everywhere a person reads one - the picker, the connection, the
# reports - because somebody running Forgejo should not be told they are
# running Gitea.  They are joined in provider_impl_name and nowhere else.
#
# What is genuinely different from GitHub rather than just spelled differently:
#
#   1. Paging is page and limit, not per_page, and the instance caps the limit
#      at 50 by default.  Link headers are set on most list endpoints and not
#      on all of them, so this counts its own pages rather than trusting them.
#      A walk that trusts a Link header that is not there stops after one page
#      and reports a fraction of the estate as the whole of it.
#   2. File links are /src/branch/<name>/ or /src/commit/<sha>/, not /blob/.
#      There is no /blob/ route at all, so a GitHub shaped link is a 404.
#   3. Listing who can reach a repository gives people and not what they are
#      allowed to do, so the permission is asked for per person.
#
# What it does not have: Dependabot, code scanning, GHAS secret alerts, a
# dependency graph.  Those are asked for through provider_supports, which says
# no for both of these, so nothing calls a GitHub path and reads the failure as
# an estate with nothing wrong in it.
# shellcheck shell=bash

# Nearly every one of these is somebody's own server, so the address on the
# connection is the real answer and these are only what is left when there is
# none.  Gitea has a hosted instance of its own; Codeberg is the Forgejo one.
provider_gitea_web_default() {
  case "$(provider_name)" in
    forgejo) printf 'https://codeberg.org' ;;
    *)       printf 'https://gitea.com' ;;
  esac
}

provider_gitea_api_default() { printf '%s/api/v1' "$(provider_gitea_web_default)"; }

# Gitea takes the same "Authorization: token X" GitHub does.  Bearer works too
# on a current version and did not on an older one, so this sends the one that
# has always worked.
provider_gitea_auth_header_line() {
  printf 'header = "Authorization: token %s"' "$1"
}

provider_gitea_api_headers() {
  printf '%s\n' "Accept: application/json"
}

# owner/repo -> https://git.example.com/owner/repo.git
provider_gitea_git_url() {
  local path="$1" web
  web=$(cfg '.github.web_url' "$(provider_gitea_web_default)")
  printf '%s/%s.git' "${web%/}" "$path"
}

# Gitea says which kind of ref it is being handed rather than working it out,
# so a branch and a commit are different paths.  Told apart by shape: a commit
# is hex and at least seven characters, and no branch name looks like that.
provider_gitea_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" web kind='branch'
  web=$(cfg '.github.web_url' "$(provider_gitea_web_default)")
  [[ "$ref" =~ ^[0-9a-fA-F]{7,64}$ ]] && kind='commit'
  printf '%s/%s/src/%s/%s/%s' "${web%/}" "$repo" "$kind" "$ref" "$file"
  (( line > 0 )) && printf '#L%s' "$line"
  printf '\n'
}

# Page and limit, counted here rather than followed out of a header.
#
# _gitea_paginate <path> [limit] -> one JSON array of everything on every page
_gitea_paginate() {
  local path="$1" limit="${2:-50}"
  local sep; case "$path" in *\?*) sep='&' ;; *) sep='?' ;; esac
  local acc; acc=$(tmp_file gtacc); echo '[]' > "$acc"
  # One reused file rather than one per page: a page of repositories is far
  # past what a single argument holds, and a thousand page walk would otherwise
  # leave a thousand files behind.
  local chunk_f; chunk_f=$(tmp_file gtchunk)
  local page=1 guard=0

  while (( page <= 1000 )); do
    (( guard++ > 1000 )) && { log_warn "pagination guard tripped for $path"; break; }
    local body; body=$(api_get "${path}${sep}page=${page}&limit=${limit}") || return 1

    # A list endpoint answers with an array; a search endpoint wraps it in
    # {ok, data}.  Both shapes turn up in the calls below.
    local chunk
    chunk=$(printf '%s' "$body" | jq -c '
      if type == "array" then . elif has("data") then .data else [.] end' 2>/dev/null) \
      || chunk='[]'
    local n; n=$(printf '%s' "$chunk" | jq 'length' 2>/dev/null || echo 0)
    (( n == 0 )) && break

    printf '%s' "${chunk:-[]}" > "$chunk_f"
    if ! jq -c --slurpfile c "$chunk_f" '. + $c[0]' "$acc" > "${acc}.n"; then
      log_error "could not accumulate a page of $path; refusing to report a partial list"
      return 1
    fi
    mv "${acc}.n" "$acc"

    # A short page is the last page.  Asking for one more and getting nothing
    # would do the same job and costs a request per list.
    (( n < limit )) && break
    page=$(( page + 1 ))
  done
  cat "$acc"
}

# Every organization the credential can see.
provider_gitea_list_groups() {
  local body; body=$(_gitea_paginate '/user/orgs') || body='[]'
  # Older versions call it username, newer ones also carry name.  Reading only
  # one of them gave a list of nulls on the other, which reads as an account
  # with no organizations rather than as a field that moved.
  printf '%s' "$body" | jq -c '[ .[] | (.username // .name // .login) | select(. != null) ] | unique'
}

provider_gitea_no_groups_warning() {
  log_warn "/user/orgs returned nothing. Either the token has no read:organization scope, or the account belongs to no organization. Repositories owned by the account itself, and any it is a collaborator on, are still found."
}

# Every repository this credential can reach, normalized.
provider_gitea_list_repos() {
  # Named repositories, and nothing else.
  #
  # include_repos adds to whatever discovery finds, which is right for the
  # setting it comes from: somebody names a repository outside the
  # organizations they scan and wants it as well.  It is wrong for a scan of
  # one repository.  Asking for one, in an account whose scope is an
  # organization, enumerated the organization and then added the one back,
  # which is every repository in it and exactly what naming one was meant to
  # avoid.
  #
  # So this is a separate key and it returns early.  No organizations, no
  # users, no membership sweep: the named repositories are the inventory.
  local _only; _only=$(cfg_json '.github.scope.only_repos // []' | jq 'length')
  if (( _only > 0 )); then
    local _raw; _raw=$(tmp_file onlyrepos)
    echo '[]' > "$_raw"
    local _want _one _tmp; _tmp=$(tmp_file onlymerge)
    while IFS= read -r _want; do
      [[ -z "$_want" ]] && continue
      # warn, not info: the product runs this scanner with -q, which is the
      # warn level, so an info line here is one nobody can read.  A scan that
      # has been narrowed to one repository is the case where a reader most
      # needs the run to say what it covered, because the whole worry is that
      # it covered more.
      log_warn "scanning only: $_want"
      _one=$(api_get "/repos/${_want}") || {
        log_warn "cannot access repo '$_want'"; continue; }
      printf '%s' "$_one" | jq -c '[.]' > "$_tmp"
      jq -c --slurpfile c "$_tmp" '. + $c[0]' "$_raw" > "${_raw}.n" && mv -f "${_raw}.n" "$_raw"
    done < <(cfg_arr '.github.scope.only_repos')
    provider_gitea_normalize "$_raw"
    return 0
  fi

  local raw; raw=$(tmp_file gtrepos); echo '[]' > "$raw"
  local merge_f; merge_f=$(tmp_file gtmerge)

  _gt_merge() {
    printf '%s' "${1:-[]}" > "$merge_f"
    if ! jq -c --slurpfile c "$merge_f" '. + $c[0]' "$raw" > "${raw}.n"; then
      log_error "could not merge a repository list; refusing to report a partial inventory"
      return 1
    fi
    mv "${raw}.n" "$raw"
  }

  local orgs_json="${GHSCAN_ORGS:-}"
  [[ -z "$orgs_json" ]] && orgs_json=$(inventory_orgs)
  GHSCAN_ORGS="$orgs_json"; export GHSCAN_ORGS

  local org
  while IFS= read -r org; do
    [[ -z "$org" ]] && continue
    log_info "enumerating repositories for organization: $org"
    local body
    body=$(_gitea_paginate "/orgs/${org}/repos") || {
      log_warn "could not list repositories for organization '$org' (see errors above)"
      continue
    }
    _gt_merge "$(printf '%s' "$body" | jq -c '.')"
  done < <(printf '%s' "$orgs_json" | jq -r '.[]?')

  # /orgs/{org}/repos misses the account's own repositories and anything it was
  # added to as a collaborator.  /user/repos catches both.  Duplicates are
  # deduped downstream.
  if cfg_bool '.github.scope.include_collaborator_repos' true; then
    log_info "enumerating repositories the credential can reach"
    local body; body=$(_gitea_paginate '/user/repos') || body='[]'
    _gt_merge "$(printf '%s' "$body" | jq -c '.')"
  fi

  local user
  while IFS= read -r user; do
    [[ -z "$user" ]] && continue
    log_info "enumerating repositories for user: $user"
    local body; body=$(_gitea_paginate "/users/${user}/repos") || continue
    _gt_merge "$(printf '%s' "$body" | jq -c '.')"
  done < <(cfg_arr '.github.scope.users')

  local explicit
  while IFS= read -r explicit; do
    [[ -z "$explicit" ]] && continue
    log_debug "fetching explicitly included repo: $explicit"
    local body; body=$(api_get "/repos/${explicit}") || { log_warn "cannot access repo '$explicit'"; continue; }
    _gt_merge "$(printf '%s' "$body" | jq -c '[.]')"
  done < <(cfg_arr '.github.scope.include_repos')

  provider_gitea_normalize "$raw"
}

# Gitea's repository object into the one shape everything downstream reads.
#
# owner_type is the one thing the API does not say: a repository carries its
# owner, and the owner carries no field that tells a person from an
# organization.  Organization is the honest guess for an estate being scanned
# for an employer, and nothing downstream decides anything unsafe from it.
provider_gitea_normalize() {
  jq -c '
    map({
      full_name:      .full_name,
      name:           (.name // ((.full_name // "") | split("/")[1])),
      owner:          (.owner.login // .owner.username
                       // ((.full_name // "") | split("/")[0])),
      owner_type:     "Organization",
      permissions:    (.permissions // null),
      role_name:      null,
      id:             .id,
      node_id:        null,
      private:        (.private // false),
      visibility:     (if (.private // false) then "private"
                       elif (.internal // false) then "internal"
                       else "public" end),
      archived:       (.archived // false),
      fork:           (.fork // false),
      is_template:    (.template // false),
      default_branch: (.default_branch // "main"),
      size_kb:        (.size // 0),
      language:       (if (.language // "") == "" then null else .language end),
      html_url:       .html_url,
      clone_url:      .clone_url,
      pushed_at:      (.pushed_at // .updated_at // null),
      license_api:    null
    })
    | map(select(.full_name != null))' "$1"
}

# Gitea reads the token out of the password and pays no attention to the
# username, so this is a fixed one rather than something that would have to
# know whose account the token belongs to.
provider_gitea_git_username() { printf 'x-access-token'; }

provider_gitea_list_branches() {
  local full_name="$1"
  local body; body=$(_gitea_paginate "/repos/${full_name}/branches") || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c '[ .[]? | {name: .name, protected: (.protected // false)} ]' 2>/dev/null || echo '[]'
}

# How many collaborators one repository is worth asking about individually.
# Past this the rest keep the permission they arrived with, which is unknown,
# because a repository with hundreds of people on it is a request each and the
# answer changes nothing anybody would act on.
GITEA_PERMISSION_LOOKUPS="${GITEA_PERMISSION_LOOKUPS:-50}"

# Fill in what each collaborator is actually allowed to do.
#
# Gitea answers the collaborator listing with people and nothing else: no
# permissions object, no role.  Left alone every row reads "unknown", and a
# repository with three admins on it reports none, which is the kind of quiet
# zero somebody makes an access decision on.  So the permission is asked for
# one person at a time.  A token that is not an administrator of the repository
# is refused, and then unknown is the truth and stays.
# The list arrives as a file rather than as an argument: a repository with a
# few hundred people on it is past what a single argument holds, and this is
# the sort of failure that turns into a wrong answer rather than an error.
provider_gitea_collaborator_permissions() {
  local full_name="$1" file="${2:-}"
  [[ -s "$file" ]] || { printf '[]'; return 0; }
  local n; n=$(jq 'length' "$file" 2>/dev/null || echo 0)
  (( n == 0 )) && { cat "$file"; return 0; }

  local map_f; map_f=$(tmp_file gtperm); echo '{}' > "$map_f"
  local asked=0 login perm
  while IFS= read -r login; do
    [[ -z "$login" ]] && continue
    if (( asked >= GITEA_PERMISSION_LOOKUPS )); then
      log_debug "$full_name: past $GITEA_PERMISSION_LOOKUPS collaborators, the rest keep an unknown permission"
      break
    fi
    asked=$(( asked + 1 ))
    perm=$(api_get_quiet "/repos/${full_name}/collaborators/${login}/permission" \
           | jq -r '.permission // .role_name // empty' 2>/dev/null)
    [[ -z "$perm" ]] && continue
    # Gitea calls the owner's own level owner, and nothing downstream ranks
    # that.  It is admin and more, so it is recorded as admin.
    [[ "$perm" == "owner" ]] && perm="admin"
    jq -c --arg l "$login" --arg p "$perm" '.[$l] = $p' "$map_f" > "${map_f}.n" \
      && mv -f "${map_f}.n" "$map_f"
  done < <(jq -r '.[]? | (.login // .username // empty)' "$file")

  jq -c --slurpfile perms "$map_f" '
    ($perms[0]) as $p
    | map(. + (($p[(.login // .username // "")] // null)
               | if . == null then {} else {role_name: .} end))' "$file"
}

provider_gitea_whoami_path()  { printf 'user'; }
provider_gitea_whoami_field() { printf '.login // .username'; }
