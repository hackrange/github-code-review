#!/usr/bin/env bash
# Loads the JSON config, expands ${ENV_VARS}, validates it.
# shellcheck shell=bash

GHSCAN_CFG_JSON="${GHSCAN_CFG_JSON:-}"
GHSCAN_CFG_PATH="${GHSCAN_CFG_PATH:-}"

# Expand ${VAR} references inside every string value of the config.
# Unset variables expand to "" and are reported. Keys beginning with $comment
# are documentation and are left exactly as written.
_cfg_expand_env() {
  local raw="$1"

  local missing
  missing=$(printf '%s' "$raw" | jq -r '
    [ paths(strings) as $p
      | select(($p | map(tostring) | any(startswith("$comment"))) | not)
      | getpath($p)
      | scan("\\$\\{([A-Za-z_][A-Za-z0-9_]*)\\}")
    ] | flatten | unique | map(select(env[.] == null)) | .[]' 2>/dev/null)
  if [[ -n "$missing" ]]; then
    log_warn "config references unset environment variables (they expand to \"\"): $(printf '%s' "$missing" | tr '\n' ' ')"
  fi

  printf '%s' "$raw" | jq -c '
    def expand:
      if   type == "object" then
        with_entries(if (.key | startswith("$comment")) then . else .value |= expand end)
      elif type == "array"  then map(expand)
      elif type == "string" then gsub("\\$\\{(?<n>[A-Za-z_][A-Za-z0-9_]*)\\}"; env[.n] // "")
      else . end;
    expand'
}

config_load() {
  local path="$1"
  [[ -n "$path" ]] || die "no config file given - pass -c PATH or set GHSCAN_CONFIG"
  [[ -r "$path" ]] || die "config file not found or not readable: $path"

  # Read once. A process substitution is a pipe, so -c <(jq ...) would come
  # back empty on a second read.
  local raw expanded
  raw=$(cat -- "$path") || die "cannot read config: $path"
  [[ -n "$raw" ]] || die "config file is empty: $path"
  printf '%s' "$raw" | jq -e . >/dev/null 2>&1 || die "config file is not valid JSON: $path"
  expanded=$(_cfg_expand_env "$raw") || die "failed to expand config"

  GHSCAN_CFG_JSON="$expanded"
  GHSCAN_CFG_PATH="$path"
  _cfg_resolve_paths
  log_debug "config loaded from $path"
  config_validate
}

# Relative file paths in the config are interpreted relative to the config file
# itself, so a run from any working directory behaves identically.
_cfg_resolve_paths() {
  local base
  base=$(cd -- "$(dirname -- "$GHSCAN_CFG_PATH")" 2>/dev/null && pwd) || base="${GHSCAN_HOME:-.}"
  [[ -d "$base" ]] || base="${GHSCAN_HOME:-.}"
  local key val abs
  for key in '.scan.secrets.gitleaks.config_path' '.scan.secrets.triage.allowlist_file' \
             '.scan.exclusions.file'; do
    val=$(cfg "$key" '')
    [[ -z "$val" || "$val" == /* ]] && continue
    abs="$base/$val"
    # Relative to the config file first, then to the installation root, so both
    # "gitleaks-extra.toml" and "config/gitleaks-extra.toml" resolve.
    [[ -e "$abs" ]] || abs="${GHSCAN_HOME:-$base}/$val"
    [[ -e "$abs" ]] || abs="${GHSCAN_HOME:-$base}/config/$val"
    if [[ -e "$abs" ]]; then
      GHSCAN_CFG_JSON=$(printf '%s' "$GHSCAN_CFG_JSON" | jq -c --arg k "$key" --arg v "$abs" \
        'setpath(($k | ltrimstr(".") | split(".")); $v)')
      log_debug "resolved $key -> $abs"
    else
      log_warn "config $key points at a missing file: $val - it will be ignored (looked in $base and ${GHSCAN_HOME:-$base})"
    fi
  done
}

# cfg <jq-filter> [default]   -> raw string value
cfg() {
  local filter="$1" def="${2-}"
  local v
  v=$(printf '%s' "$GHSCAN_CFG_JSON" | jq -r "($filter) // empty" 2>/dev/null)
  if [[ -z "$v" ]]; then printf '%s' "$def"; else printf '%s' "$v"; fi
}

# cfg_json <jq-filter>  -> compact JSON value (arrays/objects)
cfg_json() {
  printf '%s' "$GHSCAN_CFG_JSON" | jq -c "$1" 2>/dev/null
}

# cfg_arr <jq-filter>   -> newline-separated array elements
cfg_arr() {
  printf '%s' "$GHSCAN_CFG_JSON" | jq -r "($1) // [] | .[]" 2>/dev/null
}

# cfg_bool <jq-filter> [default:false] -> exit 0 when true
cfg_bool() {
  local v
  v=$(printf '%s' "$GHSCAN_CFG_JSON" | jq -r "($1)" 2>/dev/null)
  case "$v" in
    true) return 0 ;;
    false) return 1 ;;
    *) [[ "${2:-false}" == "true" ]] ;;
  esac
}

# cfg_num <jq-filter> <default>
cfg_num() {
  local v
  v=$(printf '%s' "$GHSCAN_CFG_JSON" | jq -r "($1) // empty" 2>/dev/null)
  [[ "$v" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] || v="$2"
  printf '%s' "$v"
}

config_validate() {
  local errs=()

  local orgs users
  orgs=$(cfg_json '.github.scope.orgs // []')
  users=$(cfg_json '.github.scope.users // []')
  local inc; inc=$(cfg_json '.github.scope.include_repos // []')
  # Naming nothing is a real answer: with auto_discover_orgs on it means every
  # organization the credential can reach, which is what most people want for
  # the first run.  Only complain when discovery is off as well, because then
  # there genuinely is nothing to scan.
  local discover collab
  discover=$(cfg_bool '.github.scope.auto_discover_orgs' true && echo true || echo false)
  collab=$(cfg_bool '.github.scope.include_collaborator_repos' true && echo true || echo false)
  if [[ "$orgs" == "[]" && "$users" == "[]" && "$inc" == "[]" \
        && "$discover" != "true" && "$collab" != "true" ]]; then
    errs+=("github.scope: set at least one of orgs, users, or include_repos, \
or turn auto_discover_orgs on to scan everything the credential can reach")
  fi

  local prov; prov=$(cfg '.provider' 'github')
  provider_supported "$prov" || \
    errs+=("provider must be one of: ${GHSCAN_PROVIDERS//$'\n'/ } (got '$prov')")

  local method; method=$(cfg '.github.auth.method' 'pat')
  # A GitHub App is a GitHub thing.  Asking for one anywhere else would fail
  # later, in the middle of a scan, with something unhelpful about a JWT.
  if [[ "$prov" != "github" && "$method" == "app" ]]; then
    errs+=("auth method 'app' is GitHub only; $prov takes a token")
  fi

  case "$method" in
    app)
      [[ -n "$(cfg '.github.auth.app.app_id')" ]] || errs+=("github.auth.app.app_id is required when method=app")
      local pk; pk=$(cfg '.github.auth.app.private_key_path')
      if [[ -z "$pk" ]]; then
        errs+=("github.auth.app.private_key_path is required when method=app")
      elif [[ ! -r "$pk" ]]; then
        errs+=("github.auth.app.private_key_path not readable: $pk")
      else
        local perms; perms=$(stat -c '%a' "$pk" 2>/dev/null || echo "")
        [[ -n "$perms" && "${perms: -2}" != "00" ]] && \
          log_warn "GitHub App private key $pk is group/world readable (mode $perms); chmod 600 it"
      fi
      ;;
    pat)
      local env_name file
      env_name=$(cfg '.github.auth.pat.token_env' 'GITHUB_TOKEN')
      file=$(cfg '.github.auth.pat.token_file')
      if [[ -z "${!env_name:-}" && ! -r "${file:-/nonexistent}" ]]; then
        errs+=("method=pat but neither \$$env_name is set nor token_file is readable")
      fi
      ;;
    gh_cli)
      have_cmd gh || errs+=("method=gh_cli but the 'gh' CLI is not installed")
      ;;
    *)
      errs+=("github.auth.method must be one of: app, pat, gh_cli (got '$method')")
      ;;
  esac

  local bmode; bmode=$(cfg '.github.branches.mode' 'all')
  case "$bmode" in all|default|list) ;; *) errs+=("github.branches.mode must be all|default|list") ;; esac

  local wd; wd=$(cfg '.clone.workdir' '/var/tmp/ghscan-work')
  [[ -n "$wd" ]] || errs+=("clone.workdir must be set")

  local par; par=$(cfg_num '.scan.parallel_repos' 4)
  [[ "$par" =~ ^[0-9]+$ ]] && (( par >= 1 )) || errs+=("scan.parallel_repos must be a positive integer")

  if (( ${#errs[@]} > 0 )); then
    log_error "configuration is invalid:"
    printf '  - %s\n' "${errs[@]}" >&2
    exit 2
  fi
  log_debug "config validated (auth method: $method, branch mode: $bmode)"
}

# Print the effective config with anything secret-shaped stripped.
config_dump_safe() {
  printf '%s' "$GHSCAN_CFG_JSON" | jq '
    def scrub:
      walk(
        if type == "object" then
          with_entries(
            if (.key | test("token|secret|password|private_key|key_path"; "i")) and (.value | type == "string") and (.value | length > 0)
            then .value = "***redacted***" else . end
          )
        else . end
      );
    scrub'
}
