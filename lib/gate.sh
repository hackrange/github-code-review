#!/usr/bin/env bash
# gate: what one change adds, and nothing it inherited.
#
# A pull request gate that blocks on old findings gets turned off the first
# week, because nobody can merge a one line fix to a repository that already
# had forty problems.  So this reviews the files a change touched twice, once
# as they were at the merge base and once as they are at the head, and keeps
# only what the head has that the base did not.
#
# The comparison is the hard part and lives in lib/gate_diff.py.  Fingerprints
# for code and IaC findings include the line number, so adding one line above
# an old finding gives it a new fingerprint.  Matching on fingerprints alone
# would block on code that only moved.  The diff says where every old line
# went, and that is what the match uses.
#
# Secrets get one more pass, over the commits themselves.  A key added in one
# commit and deleted in the next is not in either tree, but it was pushed, and
# a pushed key has to be rotated whether or not the PR merges.
# shellcheck shell=bash

# gate_fetch <owner/name> <mirror> -> the mirror, brought up to date
#
# The server keeps one bare mirror per repository and fetches into it, rather
# than cloning for every pull request.  The first run pays for the clone and
# every run after that pays for the commits since.  A mirror takes every ref
# the host offers, which on GitHub includes refs/pull/*, so a PR from a fork
# resolves here even though its branch lives somewhere else.
#
# Read only, like every other call this tool makes.  The credential reaches
# git through the same helper a scan uses, never through the URL.
gate_fetch() {
  local full_name="$1" mirror="$2"
  local url; url=$(auth_git_url "$full_name")
  local -a cred=()
  while IFS= read -r -d '' a; do cred+=("$a"); done < <(auth_git_credential_args)
  mkdir -p -- "$(dirname "$mirror")"
  local err="$GHSCAN_TMPROOT/gate-fetch.err"
  (
    # Two gate runs on one repository share the mirror.  Only one of them
    # fetches at a time; reading while the other fetches is safe in git.
    have_cmd flock && flock -w 600 9
    if [[ -d "$mirror/objects" ]]; then
      GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true \
        git "${cred[@]}" -C "$mirror" fetch --quiet --prune origin '+refs/*:refs/*' 2>"$err"
    else
      rm -rf -- "$mirror.new"
      GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true \
        git "${cred[@]}" clone --quiet --mirror "$url" "$mirror.new" 2>"$err" \
        && mv -- "$mirror.new" "$mirror"
    fi
  ) 9>"$mirror.lock" || {
    log_error "$full_name: could not fetch: $(tail -3 "$err" | tr '\n' ' ' | sed -E 's#(://[^@/[:space:]]+):[^@/[:space:]]+@#\1:***@#g')"
    return 1; }
}

# gate_stage_commit <repo> <sha> <list> <dest> -> the listed files, as they were
#
# Straight out of the object store, so the checkout the caller has is never
# touched.  A CI job and the server both have a working tree they did not ask
# us to rearrange.
gate_stage_commit() {
  local repo="$1" sha="$2" list="$3" dest="$4" f type
  while IFS= read -r -d '' f; do
    [[ -n "$f" ]] || continue
    # A submodule is a commit id, not a file, and a symlink is a path.  Neither
    # has anything in it to review.
    type=$(git -C "$repo" cat-file -t "$sha:$f" 2>/dev/null) || continue
    [[ "$type" == "blob" ]] || continue
    mkdir -p "$dest/$(dirname "$f")"
    git -C "$repo" cat-file blob "$sha:$f" > "$dest/$f" 2>/dev/null || rm -f -- "$dest/$f"
  done < "$list"
}

# gate_history_secrets <repo> <from> <to> <name> -> json array of credentials
#
# Every credential added in from..to, whether or not it is still there at the
# end.  Same normalize, derive and triage steps a review uses, so a finding
# here and the same finding in the head tree carry the same fingerprint and
# lib/gate_diff.py can tell them apart.
gate_history_secrets() {
  local repo="$1" from="$2" to="$3" name="$4"
  local gl th merged
  gl=$(tmp_file ggl); th=$(tmp_file gth); merged=$(tmp_file gmerge)

  # A server config may say not to walk history, which is about the nightly
  # scan's budget.  Here the history is a handful of commits and is the whole
  # point, so it is walked whatever that says.
  # A local copy, not an environment prefix on the call: a config can run
  # past what the kernel lets one environment variable hold, and every engine
  # started from in here would then fail to start at all.
  local GHSCAN_CFG_JSON="${GHSCAN_CFG_JSON:-{\}}"
  GHSCAN_CFG_JSON=$(printf '%s' "$GHSCAN_CFG_JSON" \
    | jq -c '.github.branches.scan_full_history = true')

  GHSCAN_LOG_OPTS="$from..$to" run_gitleaks "$repo" "$name" "$gl"
  # trufflehog has no range, only a commit to start from.  Given the branch as
  # well, it walks from the head back to there, which is the same commits.
  GHSCAN_TH_SINCE_COMMIT="$from" GHSCAN_TH_BRANCH="$to" \
    run_trufflehog "$repo" "$name" "$th"

  : > "$merged"
  normalize_gitleaks "$gl" "$name" | derive_secret_facts "$repo" \
    >> "$merged" 2>/dev/null || true
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    printf '%s' "$line" | normalize_trufflehog /dev/stdin "$name" \
      | derive_secret_facts "$repo" >> "$merged" 2>/dev/null || true
  done < "$th"
  wipe_file "$gl"; wipe_file "$th"

  [[ -s "$merged" ]] || { wipe_file "$merged"; echo '[]'; return 0; }
  local repo_json; repo_json=$(jq -cn --arg n "$name" '{full_name: $n, default_branch: "HEAD"}')
  triage_findings "$repo" "$merged" "$repo_json" 2>/dev/null \
    | jq -s -c '[ .[] | select(.suppressed != true)
                  | select(.triage.verdict != "placeholder") ]' \
    || echo '[]'
  wipe_file "$merged"
}

# gate_deps <dir> <name> -> json array of dependency findings
#
# The same sources a scan uses, pointed at the files a change touched.  A
# manifest nobody touched is the same at the base and the head, so leaving it
# out changes nothing about what is new and saves the time of resolving it
# twice.  Each finding keeps the shape a scan gives it, with kind, file and
# rule added, so the SARIF writer and the policy read it the same way.
gate_deps() {
  local dir="$1" name="$2"
  cfg_bool '.scan.vulnerabilities.enabled' true || { echo '[]'; return 0; }
  local -a parts=()
  local f cdx
  cdx=$(tmp_file gcdx)
  if sbom_syft "$dir" "$name" "$cdx" "" 2>/dev/null; then
    f=$(tmp_file gvg); vulns_grype "$cdx" "$name" > "$f"; parts+=("$f")
  fi
  f=$(tmp_file gvo); vulns_osv "$dir" "$name" > "$f"; parts+=("$f")
  if cfg_bool '.scan.vulnerabilities.malicious' true; then
    f=$(tmp_file gvm); vulns_malicious "$dir" "$name" > "$f"; parts+=("$f")
  fi
  local found; found=$(vulns_merge "${parts[@]}" | vulns_stamp "$name" "HEAD")
  [[ -n "$found" ]] || found='[]'
  cfg_bool '.scan.threat_intel.enabled' true && found=$(threat_intel_enrich "$found")
  printf '%s' "$found" | jq -c --arg root "${dir%/}/" '
    [ .[] | . + {
        kind: "dependency",
        file: ((.package.locations // [])[0] // "" | ltrimstr($root) | ltrimstr("/")),
        line: 0,
        rule: (.id // "UNKNOWN")
      } ]'
}

# gate_reachability <doc> <repo> <head> -> the doc, new dependencies ranked
#
# Reachability reads the code that calls a package, and the staged copy only
# holds the files that changed, so asking it there would call nearly every
# package unused.  It gets the whole head tree instead, and only when there is
# something new to ask about, because extracting a large repository is the
# slowest thing the gate can do.
gate_reachability() {
  local doc="$1" repo="$2" head="$3"
  cfg_bool '.scan.vulnerabilities.reachability' true || { printf '%s' "$doc"; return 0; }
  local f_doc; f_doc=$(json_file "$doc" grdoc)
  local wanted
  wanted=$(jq -c '[ .findings | to_entries[]
                    | select(.value.kind == "dependency" and .value.new == true
                             and (.value.malicious == null))
                    | .key ]' "$f_doc")
  [[ "$wanted" != "[]" ]] || { printf '%s' "$doc"; return 0; }
  local tree; tree=$(tmp_dir gtree)
  git -C "$repo" archive --format=tar "$head" | tar -x -C "$tree" 2>/dev/null || {
    log_warn "could not extract the head tree, so new dependencies stay unranked"
    rm -rf -- "$tree"; printf '%s' "$doc"; return 0; }
  local picked ranked
  picked=$(jq -c --argjson w "$wanted" '[ .findings as $f | $w[] | $f[.] ]' "$f_doc")
  ranked=$(vulns_reachability "$picked" "$tree")
  rm -rf -- "$tree"
  local f_ranked; f_ranked=$(json_file "${ranked:-[]}" grrank)
  jq --argjson w "$wanted" --slurpfile r "$f_ranked" '
    reduce range(0; $w | length) as $i (.;
      .findings[$w[$i]].reachability = ($r[0][$i].reachability // .findings[$w[$i]].reachability))
  ' "$f_doc"
}

# gate_run <repo> <base> <head> <only> [<name>] -> one json document
#
# base is whatever the CI system calls the target branch.  The comparison is
# made against the merge base instead, because the target branch may have
# moved since the PR was opened, and what it gained since then is not this
# change's work.
gate_run() {
  local repo="$1" base="$2" head="$3" only="${4:-secrets,code,iac,workflows,deps}" name="${5:-}"
  [[ -n "$name" ]] || name="$(basename "$(cd "$repo" && pwd)")"
  # The same word a scan's --only takes for this.
  only="${only//vulnerabilities/deps}"; only="${only//vulns/deps}"
  tmp_init

  git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || {
    log_error "not a git repository: $repo"; return 2; }
  local base_sha head_sha merge_base
  base_sha=$(git -C "$repo" rev-parse --verify --quiet "${base}^{commit}") || {
    log_error "the base is not a commit in this repository: $base"; return 2; }
  head_sha=$(git -C "$repo" rev-parse --verify --quiet "${head}^{commit}") || {
    log_error "the head is not a commit in this repository: $head"; return 2; }
  # A shallow clone has no merge base to find.  Saying so beats reviewing
  # against the wrong commit, which would call the whole branch new.
  merge_base=$(git -C "$repo" merge-base "$base_sha" "$head_sha" 2>/dev/null) || {
    log_error "no merge base between $base and $head.  A shallow clone cannot" \
              "answer this: fetch the full history (fetch-depth: 0)."
    return 2; }

  # What changed, with renames, so a moved file is compared with where it was.
  local status; status=$(tmp_file gstatus)
  git -C "$repo" diff --no-color --no-ext-diff --name-status -z -M \
    "$merge_base" "$head_sha" -- > "$status"
  local head_list base_list renames
  head_list=$(tmp_file ghead); base_list=$(tmp_file gbase); renames=$(tmp_file grename)
  : > "$head_list"; : > "$base_list"; echo '{}' > "$renames"
  local code path old new
  while IFS= read -r -d '' code; do
    case "$code" in
      R*|C*)
        IFS= read -r -d '' old; IFS= read -r -d '' new
        printf '%s\0' "$new" >> "$head_list"
        # A copy leaves the original where it was, so only a rename has a
        # base side to compare against.
        if [[ "$code" == R* ]]; then
          printf '%s\0' "$old" >> "$base_list"
          jq -c --arg n "$new" --arg o "$old" '.[$n] = $o' "$renames" > "$renames.n" \
            && mv "$renames.n" "$renames"
        fi
        ;;
      A*) IFS= read -r -d '' path; printf '%s\0' "$path" >> "$head_list" ;;
      D*) IFS= read -r -d '' path ;;
      *)  IFS= read -r -d '' path
          printf '%s\0' "$path" >> "$head_list"; printf '%s\0' "$path" >> "$base_list" ;;
    esac
  done < "$status"

  local head_dir base_dir
  head_dir=$(tmp_dir ghd); base_dir=$(tmp_dir gbd)
  gate_stage_commit "$repo" "$head_sha" "$head_list" "$head_dir"
  gate_stage_commit "$repo" "$merge_base" "$base_list" "$base_dir"

  # The engines see two plain directories.  review_run is the same code an
  # editor and a hook call, so the gate cannot give a thinner answer than
  # either of them.
  local head_doc base_doc history='[]'
  head_doc=$(tmp_file gheaddoc); base_doc=$(tmp_file gbasedoc)
  review_run "$head_dir" "" "$only" "$name" > "$head_doc"
  if [[ -s "$base_list" ]]; then
    review_run "$base_dir" "" "$only" "$name" > "$base_doc"
  else
    review_document '[]' '[]' '[]' "$base_dir" "" > "$base_doc"
  fi
  if [[ ",$only," == *",secrets,"* ]]; then
    local found
    found=$(gate_history_secrets "$repo" "$merge_base" "$head_sha" "$name")
    history=$(review_document "${found:-[]}" '[]' '[]' "$repo" "")
  else
    history=$(review_document '[]' '[]' '[]' "$repo" "")
  fi
  local history_doc; history_doc=$(json_file "$history" ghist)

  local head_deps base_deps
  head_deps=$(tmp_file ghdeps); base_deps=$(tmp_file gbdeps)
  echo '[]' > "$head_deps"; echo '[]' > "$base_deps"
  if [[ ",$only," == *",deps,"* ]]; then
    # threat_intel_refresh is what a scan calls once at the start.  It keeps
    # a cache, so a gate run after the first one a day reads it off disk.
    cfg_bool '.scan.threat_intel.enabled' true && { threat_intel_refresh \
      || log_warn "threat intel unavailable, so nothing new is marked as exploited"; }
    gate_deps "$head_dir" "$name" > "$head_deps"
    [[ -s "$base_list" ]] && gate_deps "$base_dir" "$name" > "$base_deps"
  fi

  local diff; diff=$(tmp_file gdiff)
  git -C "$repo" diff --no-color --no-ext-diff -U0 -M \
    "$merge_base" "$head_sha" -- > "$diff"

  local python; python=$(ghscan_python)
  [[ -n "$python" ]] || { log_error "the gate needs python, and there is none on the path"; return 1; }
  "$python" "$GHSCAN_HOME/lib/gate_diff.py" \
    --head "$head_doc" --base "$base_doc" --history "$history_doc" \
    --diff "$diff" --renames "$renames" \
    --head-deps "$head_deps" --base-deps "$base_deps" \
    --head-root "$head_dir" --base-root "$base_dir" --repo-root "$repo" \
    --base-ref "$base_sha" --head-ref "$head_sha" --merge-base "$merge_base" \
    > "$head_doc.out"
  local rc=$?
  if (( rc == 0 )); then
    gate_reachability "$(cat "$head_doc.out")" "$repo" "$head_sha"
  fi
  rm -f -- "$head_doc.out"
  wipe_file "$head_doc"; wipe_file "$base_doc"; wipe_file "$history_doc"
  rm -rf -- "$head_dir" "$base_dir"
  return "$rc"
}
