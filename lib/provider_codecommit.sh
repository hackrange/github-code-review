#!/usr/bin/env bash
# AWS CodeCommit.
#
# The odd one out, and worth saying why before the code.
#
# There is no bearer token.  Every call is signed with SigV4, which is a
# request signing algorithm rather than a header, and reimplementing it in
# bash with curl would be a security control written twice.  So this shells
# out to the AWS CLI, which already does it correctly and is the tool an
# operator has anyway.  Without the CLI this refuses to run rather than
# reporting an empty estate.
#
# Cloning uses the git credential helper the CLI installs, so the token this
# scanner carries for other providers is not used here at all: AWS credentials
# come from the environment, an instance role, or a named profile.
#
# Worth knowing: AWS stopped onboarding new CodeCommit customers in mid 2024.
# This is for accounts that already have repositories in it.
#
# A region is the grouping, because that is how CodeCommit is partitioned.
# shellcheck shell=bash

provider_codecommit_api_default() { printf ''; }
provider_codecommit_web_default() { printf 'https://console.aws.amazon.com/codesuite/codecommit'; }

# Nothing to send.  The CLI signs its own calls.
provider_codecommit_auth_header_line() { printf ''; }
provider_codecommit_api_headers() { printf ''; }
provider_codecommit_git_username() { printf ''; }

_cc_region() {
  local r; r=$(cfg '.github.organization' '')
  [[ -n "$r" ]] && { printf '%s' "$r"; return 0; }
  printf '%s' "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
}

_cc_aws() {
  local region; region=$(_cc_region)
  local -a args=(codecommit)
  [[ -n "$region" ]] && args+=(--region "$region")
  aws "${args[@]}" "$@" --output json 2>/dev/null
}

provider_codecommit_whoami_path()  { printf ''; }
provider_codecommit_whoami_field() { printf ''; }

# Asked instead of a whoami call: the CLI can say who the credentials belong to.
provider_codecommit_whoami() {
  provider_check_tool || return 1
  local who; who=$(aws sts get-caller-identity --output json 2>/dev/null) || return 1
  printf '%s' "$who" | jq -r '.Arn // .UserId // "an AWS identity"'
}

provider_codecommit_git_url() {
  local path="$1" region; region=$(_cc_region)
  printf 'https://git-codecommit.%s.amazonaws.com/v1/repos/%s' "$region" "${path#*/}"
}

provider_codecommit_permalink() {
  local repo="$1" ref="$2" file="$3" line="${4:-0}" region
  region=$(_cc_region)
  printf 'https://%s.console.aws.amazon.com/codesuite/codecommit/repositories/%s/browse/refs/heads/%s/--/%s' \
    "$region" "${repo#*/}" "$(urlencode "$ref")" "$file"
  printf '\n'
}

provider_codecommit_list_groups() {
  local region; region=$(_cc_region)
  [[ -n "$region" ]] && printf '["%s"]' "$region" || printf '[]'
}

provider_codecommit_no_groups_warning() {
  log_warn "no region is set. CodeCommit is partitioned by region and there is nothing above it to list, so the region has to be given on the connection or in AWS_REGION."
}

provider_codecommit_list_repos() {
  provider_check_tool || { echo '[]'; return 1; }
  local region; region=$(_cc_region)
  if [[ -z "$region" ]]; then
    provider_codecommit_no_groups_warning
    echo '[]'; return 1
  fi

  local names
  if ! names=$(_cc_aws list-repositories); then
    log_error "could not list CodeCommit repositories; refusing to report an empty estate"
    echo '[]'; return 1
  fi

  local raw; raw=$(tmp_file ccrepos); echo '[]' > "$raw"
  local one_f; one_f=$(tmp_file ccone)
  local name
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    # The listing carries only names, so each repository is asked about once.
    local meta
    meta=$(_cc_aws get-repository --repository-name "$name") || continue
    printf '%s' "$meta" | jq -c '[ .repositoryMetadata ]' > "$one_f" 2>/dev/null || continue
    jq -c --slurpfile c "$one_f" '. + $c[0]' "$raw" > "${raw}.n" && mv "${raw}.n" "$raw"
  done < <(printf '%s' "$names" | jq -r '.repositories[]?.repositoryName')

  provider_codecommit_normalize "$raw"
}

provider_codecommit_normalize() {
  local region; region=$(_cc_region)
  jq -c --arg region "$region" '
    map({
      full_name:      ($region + "/" + (.repositoryName // "")),
      name:           (.repositoryName // ""),
      owner:          $region,
      owner_type:     "Organization",
      permissions:    null,
      role_name:      null,
      id:             (.repositoryId // null),
      node_id:        null,
      private:        true,
      visibility:     "private",
      archived:       false,
      fork:           false,
      is_template:    false,
      default_branch: (.defaultBranch // "main"),
      size_kb:        0,
      language:       null,
      html_url:       null,
      clone_url:      (.cloneUrlHttp // null),
      pushed_at:      (.lastModifiedDate // null),
      license_api:    null
    })
    | map(select(.name != ""))' "$1"
}

provider_codecommit_list_branches() {
  provider_check_tool || { echo '[]'; return 0; }
  local full_name="$1" name="${full_name#*/}"
  local body
  body=$(_cc_aws list-branches --repository-name "$name") || { echo '[]'; return 0; }
  printf '%s' "$body" | jq -c '[ .branches[]? | {name: ., protected: false} ]' \
    2>/dev/null || echo '[]'
}
