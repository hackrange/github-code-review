#!/usr/bin/env bash
# The per-repo pipeline: clone, branches, secrets, triage, SBOM, access, vulns.
# shellcheck shell=bash

# A window edge as an instant rather than a date.
#
# The markers are written as YYYY-MM-DD, and git's date parser fills the parts
# it was not given from the current clock.  So a bare date means "that day, at
# the time it is now", which quietly moves all day and excludes everything
# committed before this moment.  start is the first instant of the day and end
# the last, so an edge can only ever widen the walk, never narrow it: a repeat
# of a commit already read costs nothing and a commit never read is the whole
# failure this pass exists to prevent.  A marker that already carries a time is
# left exactly as it is.
_walk_instant() {
  local marker="$1" edge="${2:-start}"
  [[ -z "$marker" ]] && return 0
  case "$marker" in
    *T*|*:*) printf '%s' "$marker"; return 0 ;;
  esac
  if [[ "$edge" == "end" ]]; then printf '%sT23:59:59Z' "$marker"
  else printf '%sT00:00:00Z' "$marker"; fi
}

# Whether a branch gets every pass, or only the credential one.
#
# The app sends a rule only for repositories somebody scoped, so no rule means
# every branch, every pass, which is how it always was.  A branch override
# wins, then the repository's mode.  The globs match the way the app's
# fnmatch does: a star crosses slashes, so release/* takes release/1.2.
scope_full_scan() {
  local repo="$1" branch="$2" rule mode over p
  rule=$(printf '%s' "$GHSCAN_CFG_JSON" \
           | jq -c --arg r "$repo" '.scan.branch_scope[$r] // null' 2>/dev/null)
  [[ -z "$rule" || "$rule" == "null" ]] && return 0
  over=$(jq -r --arg b "$branch" '.branches[$b] // ""' <<<"$rule" 2>/dev/null)
  case "$over" in
    full) return 0 ;;
    credentials) return 1 ;;
  esac
  mode=$(jq -r '.mode // "all"' <<<"$rule" 2>/dev/null)
  case "$mode" in
    credentials) return 1 ;;
    chosen)
      while IFS= read -r p; do
        # shellcheck disable=SC2053
        [[ -n "$p" && "$branch" == $p ]] && return 0
      done < <(jq -r '.full[]?' <<<"$rule" 2>/dev/null)
      return 1 ;;
  esac
  return 0
}

# Per-repository worker
scan_one_repo() {
  local repo_json="$1" results_dir="$2" work_root="$3"
  local full_name default_branch size_kb slug started
  full_name=$(printf '%s' "$repo_json" | jq -r '.full_name')
  default_branch=$(printf '%s' "$repo_json" | jq -r '.default_branch')
  size_kb=$(printf '%s' "$repo_json" | jq -r '.size_kb // 0')
  slug=$(slugify "$full_name")
  started=$(date +%s)

  BRANCHES_JSON='[]'; SECRETS_JSON='{"reported":[],"filtered":[],"suppressed":[]}'
  SBOM_JSON='null'; LICENSE_JSON='null'; POLICY_JSON='null'; VULNS_JSON='[]'
  SBOM_BY_BRANCH_JSON='[]'; ACCESS_JSON='null'
  PULLS_JSON='[]'; CLONE_TRAFFIC_JSON='null'; CODE_FINDINGS_JSON='[]'; CODEQL_UNREAD=''; CODE_RULES_LOADED_JSON='[]'
  MISCONFIG_JSON='[]'; WORKFLOW_JSON='[]'
  # Whether a dynamic pass could ever run here.  null until the question is
  # asked, so a report from before this existed and a repository nobody asked
  # about are not made to look like a refusal.
  DAST_JSON='null'
  # Which commit each branch is on, so a review of this code can be told
  # apart from a review of what it used to be.
  BRANCH_HEADS_JSON='{}'
  # Every branch that is there, as opposed to the ones this run walked.  A
  # branch skipped for being quiet is still a branch, and a sign off on one is
  # not a sign off on code that has gone.
  BRANCHES_PRESENT_JSON='[]'
  GHSCAN_SBOM_CDX=""

  local result_file="$results_dir/${slug}.json"
  local clone_dir="$work_root/$slug"

  HISTORY_FROM=""; HISTORY_COMPLETE="false"

  # Which passes have finished, in the order they finished.
  #
  # A repository used to be all or nothing: a worker stopped at its time limit
  # wrote no result at all, so six hours of credential scanning went in the bin
  # and the repository came back from the scan as if nothing had been looked at.
  # The passes are checkpointed instead, so what finished is kept and the report
  # can say plainly which parts of this repository nobody has looked at.
  PASSES_DONE=""

  _emit() {
    local status="$1" err="$2"; shift 2

    # Every one of these can be large.  One repository came back with a
    # thousand credential findings and jq refused the command line, which is
    # how a whole repository went missing from a scan that reported success.
    local f_repo f_branches f_secrets f_sbom f_license f_policy f_vulns
    local f_sbom_branches f_access f_pulls f_traffic f_code f_iac
    f_repo=$(json_file "$repo_json" repo)
    f_branches=$(json_file "$BRANCHES_JSON" branches)
    f_secrets=$(json_file "$SECRETS_JSON" secrets)
    f_sbom=$(json_file "$SBOM_JSON" sbom)
    f_license=$(json_file "$LICENSE_JSON" license)
    f_policy=$(json_file "$POLICY_JSON" policy)
    f_vulns=$(json_file "$VULNS_JSON" vulns)
    f_sbom_branches=$(json_file "$SBOM_BY_BRANCH_JSON" sbombranch)
    f_access=$(json_file "$ACCESS_JSON" access)
    f_pulls=$(json_file "$PULLS_JSON" pulls)
    f_traffic=$(json_file "$CLONE_TRAFFIC_JSON" traffic)
    f_code=$(json_file "$CODE_FINDINGS_JSON" code)
    f_iac=$(json_file "$MISCONFIG_JSON" iac)

    jq -cn \
      --slurpfile repo "$f_repo" \
      --arg status "$status" \
      --arg err "$err" \
      --slurpfile branches "$f_branches" \
      --slurpfile secrets "$f_secrets" \
      --slurpfile sbom "$f_sbom" \
      --slurpfile license "$f_license" \
      --slurpfile policy "$f_policy" \
      --slurpfile vulns "$f_vulns" \
      --slurpfile sbom_branches "$f_sbom_branches" \
      --slurpfile access "$f_access" \
      --slurpfile pulls "$f_pulls" \
      --slurpfile clone_traffic "$f_traffic" \
      --slurpfile code_findings "$f_code" \
      --slurpfile misconfigurations "$f_iac" \
      --argjson dur "$(( $(date +%s) - started ))" \
      --argjson code_ok "${CODE_PASS_COMPLETE:-true}" \
      --arg code_why "${CODE_PASS_INCOMPLETE:-}" \
      --arg codeql_why "${CODEQL_UNREAD:-}" \
      --arg secrets_why "${SECRETS_PASS_INCOMPLETE:-}" \
      --arg hist_mb "${HISTORY_VOLUME_MB:-}" \
      --argjson sso "${GHSCAN_SSO_TRUNCATED:-0}" \
      --arg passes "$PASSES_DONE" \
      --arg hist_from "${HISTORY_FROM:-}" \
      --argjson hist_done "${HISTORY_COMPLETE:-false}" \
      --argjson dast "${DAST_JSON:-null}" \
      --argjson branch_heads "${BRANCH_HEADS_JSON:-{\}}" \
      --argjson branches_present "${BRANCHES_PRESENT_JSON:-[]}" \
      --argjson code_rules "${CODE_RULES_LOADED_JSON:-[]}" '
      {
        repository: $repo[0],
        status: $status,
        error: (if $err == "" then null else $err end),
        branches_scanned: $branches[0],
        # Every branch that exists, walked or not.  The walked list above is
        # narrowed by the quiet branch filter and the per repository cap, so a
        # name missing from it does not mean the branch has gone, and taking a
        # sign off away on that evidence throws away a review somebody did.
        branches_present: $branches_present,
        # branch name to the commit it was on when this ran.
        branch_heads: $branch_heads,
        branch_count: ($branches[0] | length),
        # The semgrep rules this run had, so a finding whose rule was not among
        # them is held open rather than read as fixed.
        code_rules_loaded: $code_rules,
        secrets: $secrets[0],
        sbom: $sbom[0],
        sbom_by_branch: $sbom_branches[0],
        license: $license[0],
        license_policy: $policy[0],
        access: $access[0],
        code_findings: $code_findings[0],
        # False means the pass was cut short, so what it did not
        # report is missing rather than fixed.
        code_complete: $code_ok,
        code_incomplete_reason: (if $code_why == "" then null else $code_why end),
        # The CodeQL alerts on GitHub could not be read.  Only those findings are
        # held open: semgrep still read the code, so its answer still stands.
        codeql_unread_reason: (if $codeql_why == "" then null else $codeql_why end),
        # Which engine died, for whoever has to work out afterwards why a
        # repository went quiet.  This file is the only record that survives
        # the run, and it is what the diagnosis was missing.
        secrets_incomplete_reason:
          (if $secrets_why == "" then null else $secrets_why end),
        misconfigurations: $misconfigurations[0],
        pull_history: $pulls[0],
        clone_traffic: $clone_traffic[0],
        vulnerabilities: $vulns[0],
        sso_results_truncated: ($sso == 1),
        # What was actually looked at.  A reader of a partial repository needs
        # to know which half they are reading.
        passes_complete: ($passes | split(" ") | map(select(. != ""))),
        # How far back the credential engines have walked here, so the next run
        # continues instead of starting at the newest commit again.
        history: {walked_from: $hist_from, complete: $hist_done,
                  # Roughly how much diff a full walk of this repository would
                  # hand an engine.  Sampled, not exact.  Recorded so the
                  # ceiling above it can be chosen from what the estate really
                  # holds rather than from a number somebody picked.
                  volume_mb: (if $hist_mb == "" then null
                              else ($hist_mb | tonumber? // null) end)},
        # Could a dynamic pass run against this repository at all.  Reading
        # only: nothing is built and nothing is started.  Three answers, and
        # they are three different things, so a declined and an unknown are
        # never counted together.
        dast: $dast,
        timing: {duration_sec: $dur}
      }' > "${result_file}.part"
    # Into place in one step.  A checkpoint is written while the worker may be
    # killed at any moment, and half a JSON file is worse than none: the parent
    # would read it, fail to parse it, and lose the passes that did finish.
    mv -f "${result_file}.part" "$result_file" 2>/dev/null || true
  }

  # Keep what has finished so far.  Called after each pass that costs real time,
  # so a repository stopped later still reports the work already done.
  _checkpoint() {
    PASSES_DONE="${PASSES_DONE:+$PASSES_DONE }$1"
    _emit "partial" "still running; finished so far: $PASSES_DONE"
  }

  local need_clone=0
  cfg_bool '.scan.secrets.enabled' true && need_clone=1
  cfg_bool '.scan.sbom.enabled' true && need_clone=1
  cfg_bool '.scan.code_analysis.enabled' true && need_clone=1
  cfg_bool '.scan.iac.enabled' true && need_clone=1
  cfg_bool '.scan.workflows.enabled' true && need_clone=1

  if (( need_clone )); then
    log_info "[$full_name] cloning"
    local rc=0
    repo_clone "$full_name" "$clone_dir" "$default_branch" "$size_kb" || rc=$?
    if (( rc == 3 || rc != 0 )); then
      # The access inventory is API-only, so collect it even when the clone
      # failed - a repo we cannot read is still a repo someone can reach.
      if cfg_bool '.scan.access.enabled' true; then
        local owner_f; owner_f=$(printf '%s' "$repo_json" | jq -r '.owner')
        local outside_f="[]"
        [[ -n "${GHSCAN_OUTSIDE_COLLABORATORS:-}" ]] && \
          outside_f=$(printf '%s' "$GHSCAN_OUTSIDE_COLLABORATORS" | jq -c --arg o "$owner_f" '.[$o] // []')
        ACCESS_JSON=$(access_for_repo "$full_name" "$outside_f")
      fi
      if (( rc == 3 )); then _emit "skipped" "repository exceeds clone.max_repo_size_mb"
      else                   _emit "failed"  "clone failed"; fi
      return 0
    fi
  fi

  # --- branches -------------------------------------------------------------
  local -a branches=()
  if (( need_clone )); then
    export GHSCAN_DEFAULT_BRANCH="$default_branch"
    local b
    while IFS= read -r b; do [[ -n "$b" ]] && branches+=("$b"); done < <(repo_branches "$clone_dir")
    if (( ${#branches[@]} == 0 )); then branches=("$default_branch"); fi
    BRANCHES_JSON=$(printf '%s\n' "${branches[@]}" | jq -R . | jq -sc '.')
    export GHSCAN_BRANCH_SET="$BRANCHES_JSON"

    # Where each branch actually is, as a commit.
    #
    # The names alone cannot answer whether anything changed since somebody
    # last looked at this code, and that is the question a security sign off
    # depends on: a commit that introduced no finding is still a commit
    # nobody reviewed.  Recorded here because this is the one moment the
    # clone is on disk and the answer is free.
    local heads_json="{}" bh sha
    for bh in "${branches[@]}"; do
      sha=$(git -C "$clone_dir" rev-parse --verify --quiet "$bh" 2>/dev/null || echo "")
      [[ -n "$sha" ]] || continue
      heads_json=$(printf '%s' "$heads_json" \
        | jq -c --arg b "$bh" --arg s "$sha" '. + {($b): $s}')
    done
    BRANCH_HEADS_JSON="$heads_json"

    # And the full list, before the quiet branch filter and the per repository
    # cap.  Recorded so that a branch missing from it means deleted, which is
    # the only thing a sign off may be taken away on.
    local -a present=()
    local pb
    while IFS= read -r pb; do
      [[ -n "$pb" ]] && present+=("$pb")
    done < <(repo_branches_present "$clone_dir")
    if (( ${#present[@]} > 0 )); then
      BRANCHES_PRESENT_JSON=$(printf '%s\n' "${present[@]}" | jq -R . | jq -sc '.')
    else
      BRANCHES_PRESENT_JSON="$BRANCHES_JSON"
    fi
    # What is said about a credential comes from these, not from the walked
    # list.  The history walk reads every ref whatever the quiet branch filter
    # did, so a key on a branch that was skipped is still found, and labeling
    # it from the walked list stamped it onto the default branch, where it is
    # not.  Skipping a branch is meant to save a checkout, not to change what
    # is reported about the code on it.
    export GHSCAN_BRANCH_SET_PRESENT="$BRANCHES_PRESENT_JSON"
    # Every branch head, for whether a credential is still in the code.  The
    # ones the exclude patterns leave in come first, so a cap on how many are
    # searched drops excluded branches before it drops anything else.
    export GHSCAN_BRANCH_SET_HEADS
    GHSCAN_BRANCH_SET_HEADS=$(
      { printf '%s\n' "${present[@]}"
        git -C "$clone_dir" for-each-ref --format='%(refname:strip=2)' \
            --sort=-committerdate refs/heads/ 2>/dev/null; } \
        | awk 'NF && !seen[$0]++' | jq -R . | jq -sc '.')

    log_info "[$full_name] ${#branches[@]} branch(es) in scope"
  fi

  # How far back the credential walk reached, and where it stopped.
  #
  # Declared out here rather than inside the pass that fills them in, because
  # the history bookkeeping further down reads them whether or not that pass
  # ran.  With secrets switched off there is no walk at all, and a window of
  # zero is the honest answer to how far it got: the bookkeeping then skips,
  # which is what it did before this was reachable.
  #
  # They were local to the secrets block until a scan with
  # scan.secrets.enabled = false walked into `window_days: unbound variable`
  # and took the whole repository down with it.  The scanner runs under set -u,
  # so this is a crash rather than an empty value.
  local window_days=0 from_marker="" head_marker=""
  local history_done="false" since_arg="" until_arg=""

  # --- secrets --------------------------------------------------------------
  if cfg_bool '.scan.secrets.enabled' true; then
    local raw; raw=$(tmp_file raw_findings)
    : > "$raw"
    # Paths the exclude list kept out of this pass.  Only paths, never values,
    # so unlike the raw findings beside it this one is not sensitive.  It is
    # collected so the repository can be told what was not looked at.
    SECRETS_DROPPED=$(tmp_file secrets_dropped)
    : > "$SECRETS_DROPPED"
    # Any engine in this pass that did not finish.  Cleared per repository,
    # because a failure on the last one must not follow the next one around.
    SECRETS_PASS_INCOMPLETE=""
    HISTORY_TOO_BIG=0
    local engines; engines=$(cfg_json '.scan.secrets.engines // []')

    local want_gl want_th
    printf '%s' "$engines" | jq -e 'index("gitleaks")'   >/dev/null && want_gl=1 || want_gl=0
    printf '%s' "$engines" | jq -e 'index("trufflehog")' >/dev/null && want_th=1 || want_th=0
    local verify_note=""
    cfg_bool '.scan.secrets.trufflehog.verify' true && verify_note=" (live verification on)"

    # How far back to walk this run, and where the last run stopped.
    #
    # A window of zero is one pass over the whole history, which is what this
    # always did.  With a window, the walk is bounded and where it reached is
    # recorded, so a repository too large to finish in one run is continued by
    # the next one instead of restarting at the newest commit forever.
    window_days=$(cfg_num '.scan.secrets.history_window_days' 0)
    # Each range this run walks, as git log options.  More than one, because
    # working backwards through old history must not mean ignoring what has
    # been pushed at the front of it since the last run.
    local -a walk_ranges=()
    if (( window_days > 0 )) && (( need_clone )); then
      local resume_file; resume_file=$(cfg '.scan.secrets.resume_file' '')
      if [[ -n "$resume_file" && -r "$resume_file" ]]; then
        from_marker=$(jq -r --arg r "$full_name" '.[$r].from // ""' "$resume_file" 2>/dev/null)
        head_marker=$(jq -r --arg r "$full_name" '.[$r].head // ""' "$resume_file" 2>/dev/null)
        [[ "$(jq -r --arg r "$full_name" '.[$r].complete // false' "$resume_file" 2>/dev/null)" == "true" ]] \
          && history_done="true"
      fi
      if [[ "$history_done" == "true" ]]; then
        # The far end has been reached before.  Only what is new since then
        # needs walking, which is the cheap case.
        since_arg="${from_marker}"
        log_info "[$full_name] history already walked to its first commit; only new commits this run"
      else
        # Continue older.  The window ends where the last run began, or now.
        until_arg="${from_marker}"
        if [[ -n "$until_arg" ]]; then
          since_arg=$(date -u -d "$until_arg - ${window_days} days" +%Y-%m-%d 2>/dev/null || echo "")
        else
          since_arg=$(date -u -d "${window_days} days ago" +%Y-%m-%d 2>/dev/null || echo "")
        fi
        log_info "[$full_name] walking history from ${since_arg:-the beginning} to ${until_arg:-now}"
      fi
    fi

    # The git log options that bound this run's walk.
    #
    # The edges are said as instants, never as bare dates.  git fills the time
    # it was not given from the clock rather than from midnight, so at ten at
    # night "--since=2026-09-20" means "since ten o'clock this morning" and
    # every commit made earlier that day is walked straight past.  That is the
    # worst possible thing for this pass to get wrong: somebody commits a
    # credential, scans, and is told there is nothing there.  Measured on a
    # repository whose three commits were all made that afternoon: the bare
    # date matched none of them, the instant matched all three.
    local range_opts="--all --full-history"
    [[ -n "$since_arg" ]] && range_opts="$range_opts --since=$(_walk_instant "$since_arg" start)"
    [[ -n "$until_arg" ]] && range_opts="$range_opts --until=$(_walk_instant "$until_arg" end)"
    walk_ranges=("$range_opts")

    # Everything new since the last run, when this repository is part way
    # through its history.  Without this the front of the repository goes
    # unexamined for as many runs as the walk to the far end takes.
    if [[ "$history_done" != "true" && -n "$head_marker" && -n "$until_arg" ]]; then
      walk_ranges+=("--all --full-history --since=$(_walk_instant "$head_marker" start)")
      log_info "[$full_name] and everything pushed since $head_marker"
    fi
    export GHSCAN_LOG_OPTS="$range_opts"

    # trufflehog takes a commit rather than a date, so the window's older edge
    # is translated into the newest commit at or before it.  Empty leaves it
    # walking everything, which is the unwindowed case.
    GHSCAN_TH_SINCE_COMMIT=""
    if [[ -n "$since_arg" ]] && (( need_clone )); then
      GHSCAN_TH_SINCE_COMMIT=$(git -C "$clone_dir" rev-list --all \
                                 --before="$(_walk_instant "$since_arg" start)" \
                                 --max-count=1 2>/dev/null || true)
    fi
    export GHSCAN_TH_SINCE_COMMIT

    # Too much history to hand an engine, decided before one is started.
    #
    # Not a skip.  Falling through here puts the credential pass on the branch
    # head path instead: the current state of every branch in scope is still
    # read, which is where a live credential actually is, and only the walk
    # back through old commits is given up.  That is the half worth keeping
    # when the other half cannot be done at all.
    #
    # And the history is never marked complete afterwards, so nothing later
    # mistakes "we did not read it" for "there is nothing there".
    # Measured once, used twice: to decide, and to report.  Nothing used to
    # record what any repository actually measured, so the ceiling could only
    # ever be set by guessing at it.  The number goes in the result, where
    # somebody choosing the limit can see what the estate really looks like.
    HISTORY_VOLUME_MB=""
    if (( need_clone )); then
      HISTORY_VOLUME_MB=$(history_volume_mb "$clone_dir")
      if history_is_too_big "$clone_dir" "$full_name" "$HISTORY_VOLUME_MB"; then
        HISTORY_TOO_BIG=1
      fi
    fi

    if (( ${HISTORY_TOO_BIG:-0} == 0 )) && cfg_bool '.github.branches.scan_full_history' true; then
      # One pass over `git log --all`: every commit on every ref.
      if (( want_gl )); then
        local gl range
        # One walk per range.  Unwindowed that is a single pass over
        # everything, exactly as before; windowed it is the older window and
        # then whatever has arrived since the last run.
        for range in "${walk_ranges[@]:-"--all --full-history"}"; do
          gl=$(tmp_file gitleaks_out)
          export GHSCAN_LOG_OPTS="$range"
          log_info "[$full_name] gitleaks ($range)"
          run_gitleaks "$clone_dir" "$full_name" "$gl"
          normalize_gitleaks "$gl" "$full_name" \
            | secrets_drop_excluded "$SECRETS_DROPPED" \
            | derive_secret_facts "$clone_dir" >> "$raw"
          # The engine report is every credential it found, in full and
          # unmasked.  It has been read, so it goes now rather than sitting
          # there until the run ends.
          wipe_file "$gl"
        done
      fi
      if (( want_th )); then
        local th; th=$(tmp_file trufflehog_out)
        log_info "[$full_name] trufflehog (full history, all refs)$verify_note"
        run_trufflehog "$clone_dir" "$full_name" "$th"
        normalize_trufflehog "$th" "$full_name" \
          | secrets_drop_excluded "$SECRETS_DROPPED" \
          | derive_secret_facts "$clone_dir" >> "$raw"
        wipe_file "$th"
      fi
    else
      # Branch heads only: check out each branch and scan the files as they are.
      local b
      for b in "${branches[@]}"; do
        log_info "[$full_name] branch-head scan: $b"
        if ! git -C "$clone_dir" checkout --quiet --force "$b" 2>/dev/null; then
          log_warn "[$full_name] cannot check out '$b', skipping"
          continue
        fi
        if (( want_gl )); then
          local glb; glb=$(tmp_file gitleaks_wt)
          run_gitleaks_worktree "$clone_dir" "$full_name" "$glb"
          normalize_gitleaks "$glb" "$full_name" \
            | secrets_drop_excluded "$SECRETS_DROPPED" \
            | derive_secret_facts "$clone_dir" | tag_branch "$b" "$clone_dir" >> "$raw"
          wipe_file "$glb"
        fi
        if (( want_th )); then
          local thb; thb=$(tmp_file trufflehog_wt)
          run_trufflehog_worktree "$clone_dir" "$full_name" "$thb"
          normalize_trufflehog "$thb" "$full_name" \
            | secrets_drop_excluded "$SECRETS_DROPPED" \
            | derive_secret_facts "$clone_dir" | tag_branch "$b" "$clone_dir" >> "$raw"
          wipe_file "$thb"
        fi
      done
      git -C "$clone_dir" checkout --quiet --force "$default_branch" 2>/dev/null || true
    fi

    if printf '%s' "$engines" | jq -e 'index("github_secret_scanning")' >/dev/null; then
      local gh; gh=$(tmp_file gh_alerts)
      run_github_secret_scanning "$full_name" "$gh"
      local ghnd; ghnd=$(tmp_file gh_nd)
      normalize_github_alerts "$gh" "$full_name" \
        | secrets_drop_excluded "$SECRETS_DROPPED" \
        | derive_secret_facts "" > "$ghnd"
      wipe_file "$gh"
      if [[ -s "$ghnd" ]]; then
        enrich_github_alert_locations "$full_name" "$ghnd"
        cat "$ghnd" >> "$raw"
      fi
    fi

    if printf '%s' "$engines" | jq -e 'index("detect_secrets")' >/dev/null; then
      local ds; ds=$(tmp_file detect_secrets)
      log_info "[$full_name] detect-secrets (second opinion on the working tree)"
      run_detect_secrets "$clone_dir" "$ds"
      local corr; corr=$(tmp_file corroborated)
      while IFS= read -r ln; do
        [[ -n "$ln" ]] && printf '%s' "$ln" | corroborate "$ds" >> "$corr"
      done < "$raw"
      [[ -s "$corr" ]] && mv "$corr" "$raw"
    fi

    local n_raw; n_raw=$(wc -l < "$raw" | tr -d ' ')
    log_debug "[$full_name] $n_raw raw candidate(s) before triage"

    local triaged; triaged=$(tmp_file triaged)
    triage_findings "$clone_dir" "$raw" "$repo_json" > "$triaged"
    local keep_low; keep_low=$(cfg_bool '.scan.secrets.triage.path_rule_downgrades_only' true && echo true || echo false)
    SECRETS_JSON=$(triage_partition "$triaged" "$keep_low")
    shred -u "$raw" 2>/dev/null || rm -f "$raw"

    local n_rep n_conf
    n_rep=$(printf '%s' "$SECRETS_JSON" | jq '.reported | length')
    n_conf=$(printf '%s' "$SECRETS_JSON" | jq '[.reported[] | select(.verified)] | length')
    if (( n_rep > 0 )); then
      log_warn "[$full_name] $n_rep secret finding(s), $n_conf verified live"
    else
      log_info "[$full_name] no secrets reported"
    fi
  fi

  # Which branches this default-branch pass actually speaks for.
  #
  # The secrets pass checks every branch out and walks the history, so a secret
  # carries the real list of branches it sits on.  Code, dependencies and
  # infrastructure are looked at once, on the default branch checkout, and were
  # then stamped with the default branch as though that were where they lived.
  #
  # A reader takes that at face value, and on a repository whose release branch
  # is the same commit as its default branch they conclude the release branch
  # was checked and came back clean.  It was never looked at.  Saying nothing
  # would be better than that; saying which branches hold the identical tree is
  # better still, and git already knows.
  local -a same_branches=("$default_branch")
  if (( need_clone )); then
    local base_tree b_tree b2
    base_tree=$(git -C "$clone_dir" rev-parse "${default_branch}^{tree}" 2>/dev/null || echo "")
    if [[ -n "$base_tree" ]]; then
      for b2 in "${branches[@]}"; do
        [[ "$b2" == "$default_branch" ]] && continue
        b_tree=$(git -C "$clone_dir" rev-parse "${b2}^{tree}" 2>/dev/null || echo "")
        [[ -n "$b_tree" && "$b_tree" == "$base_tree" ]] && same_branches+=("$b2")
      done
    fi
  fi
  local SAME_BRANCHES_JSON
  SAME_BRANCHES_JSON=$(printf '%s\n' "${same_branches[@]}" | jq -R . | jq -sc '.')
  if (( ${#same_branches[@]} > 1 )); then
    log_info "[$full_name] the default branch tree is also on: ${same_branches[*]:1}"
  fi

  # Whether the branch these passes read ships.  When it does not, the code,
  # configuration and dependency passes are skipped and, just as important,
  # never named as finished.  The app closes a finding only when the pass
  # that makes its kind says it finished, so what they found before is held
  # open rather than read as fixed.  Credentials are read regardless.
  local full_passes=1
  if ! scope_full_scan "$full_name" "$default_branch"; then
    full_passes=0
    log_info "[$full_name] $default_branch is credentials only by scan scope, so the code, configuration and dependency passes are skipped"
  fi

  # Where the walk reached, for the next run to carry on from.
  HISTORY_FROM=""; HISTORY_COMPLETE="false"
  # A full walk, and only when one actually happened.
  #
  # No window means this run read every commit on every ref, which is the
  # strongest evidence a history can be complete, and it was the one case that
  # recorded nothing: the marker logic below only ran for windowed runs, so an
  # estate scanned end to end came out of it with every repository still saying
  # nobody had walked anything.  Turn a window on afterwards and the catch up
  # pass starts from nothing and spends its nights walking backwards through
  # history that had already been read.
  #
  # Three conditions and not one, because claiming a history is complete is a
  # claim that stops anything ever looking again.  The clone has to have
  # happened, the credential pass has to be the thing that reads history and
  # has to be switched on, and the run has to have been walking history rather
  # than checking out branch heads.  Any of those false and this stays silent,
  # which leaves the repository looking unwalked: the safe direction, since the
  # worst that costs is a pass that had nothing to do.
  if (( window_days == 0 )) && (( need_clone )) \
     && (( ${HISTORY_TOO_BIG:-0} == 0 )) \
     && cfg_bool '.scan.secrets.enabled' true \
     && cfg_bool '.github.branches.scan_full_history' true; then
    HISTORY_COMPLETE="true"
    HISTORY_FROM=$(date -u +%Y-%m-%d)
  elif (( window_days > 0 )) && (( need_clone )); then
    if [[ "$history_done" == "true" ]]; then
      # Already at the far end; keep it that way and move the marker forward so
      # the next run only looks at what is newer still.
      HISTORY_COMPLETE="true"
      HISTORY_FROM=$(date -u +%Y-%m-%d)
    else
      HISTORY_FROM="${since_arg:-}"
      # Nothing older than this window means the beginning has been reached.
      local older
      # The same instant the walk used, so this answer and that walk agree
      # about where the window began.  A bare date here drifts with the clock
      # in the other direction: commits made earlier today would count as
      # older than the window and the history would be called complete when
      # it is not.
      older=$(git -C "$clone_dir" rev-list --all \
                --before="$(_walk_instant "${since_arg:-1970-01-01}" start)" \
                --max-count=1 2>/dev/null || true)
      [[ -z "$older" ]] && HISTORY_COMPLETE="true"
      if [[ "$HISTORY_COMPLETE" == "true" ]]; then
        log_info "[$full_name] history walked back to its first commit"
      fi
    fi
  fi

  # A pass is complete when the engines that make it up finished, not when the
  # code reached the end of the block.  An engine that was killed writes an
  # empty report and the pass carries on, which is right, but declaring the
  # pass complete on the strength of it tells the reader that everything that
  # engine used to find has been remediated.
  #
  # Two things are withheld, and they are withheld together.  The pass, so
  # credential findings here are held open rather than closed for silence.
  # And the history marker, because a walk whose engine died is not a history
  # that has been read, and a marker saying otherwise stops anything ever
  # looking again.
  if [[ -n "${SECRETS_PASS_INCOMPLETE:-}" ]]; then
    HISTORY_COMPLETE="false"
    HISTORY_FROM=""
    _emit "partial" "still running; finished so far: ${PASSES_DONE:-none}"
  else
    _checkpoint secrets
  fi

  # --- static analysis of the code ------------------------------------------
  if (( full_passes )) && cfg_bool '.scan.code_analysis.enabled' true; then
    log_info "[$full_name] static code analysis"
    local sg; sg=$(tmp_file semgrep)
    GHSCAN_CODE_COMPLETE=true; GHSCAN_CODE_INCOMPLETE=""
    run_semgrep "$clone_dir" "$full_name" "$sg"
    # A key semgrep matched is a credential, not a line of code.
    cfg_bool '.scan.secrets.enabled' true && \
      semgrep_secrets_route "$clone_dir" "$full_name" "$sg" "$repo_json"
    CODE_RULES_LOADED_JSON=$(cat "$sg.rules" 2>/dev/null || echo '[]')
    CODE_PASS_COMPLETE="$GHSCAN_CODE_COMPLETE"
    CODE_PASS_INCOMPLETE="$GHSCAN_CODE_INCOMPLETE"
    CODE_FINDINGS_JSON=$(normalize_semgrep "$sg" "$full_name" "$default_branch" "$(cfg '.github.web_url' 'https://github.com')")

    # A second engine where semgrep only reads one file at a time.  Only the
    # languages that are actually in the tree, which is the same decision syft
    # already makes from what is in the checkout.
    if cfg_bool '.scan.code_analysis.second_engine' true; then
      local web_url; web_url=$(cfg '.github.web_url' 'https://github.com')
      local langs; langs=$(code_languages "$clone_dir")
      local -a extras=()
      [[ "$langs" == *go* ]] && extras+=("$(run_gosec "$clone_dir" "$full_name" "$default_branch" "$web_url")")
      [[ "$langs" == *python* ]] && extras+=("$(run_bandit "$clone_dir" "$full_name" "$default_branch" "$web_url")")
      [[ "$langs" == *javascript* ]] && extras+=("$(run_njsscan "$clone_dir" "$full_name" "$default_branch" "$web_url")")
      if (( ${#extras[@]} > 0 )); then
        CODE_FINDINGS_JSON=$(code_merge "$CODE_FINDINGS_JSON" "${extras[@]}")
        local agreed; agreed=$(printf '%s' "$CODE_FINDINGS_JSON" | jq '[.[]|select(.corroborated)]|length')
        (( agreed > 0 )) && log_info "[$full_name] $agreed finding(s) seen by more than one engine"
      fi
    fi
    # GitHub's CodeQL alerts.  Under the vulnerability sources setting, because
    # that is where an install already said whether it wants them.
    if cfg_json '.scan.vulnerabilities.sources // []' | jq -e 'index("github_code_scanning")' >/dev/null; then
      local cq_in cq_out
      cq_in=$(json_file "$CODE_FINDINGS_JSON" code_before_codeql)
      cq_out=$(tmp_file code_with_codeql)
      codeql_alerts "$clone_dir" "$full_name" "$default_branch" \
        "$(cfg '.github.web_url' 'https://github.com')" "$cq_in" "$cq_out"
      CODE_FINDINGS_JSON=$(cat "$cq_out")
    fi
    local nc; nc=$(printf '%s' "$CODE_FINDINGS_JSON" | jq 'length')
    if (( nc > 0 )); then
      log_warn "[$full_name] $nc code vulnerability finding(s), $(printf '%s' "$CODE_FINDINGS_JSON" | jq '[.[]|select(.severity=="critical")]|length') critical, semgrep used ${GHSCAN_SEMGREP_RULESETS:-an unknown number of} rulesets"
    else
      log_info "[$full_name] no code vulnerabilities found"
    fi
  fi

  # --- infrastructure as code -----------------------------------------------
  if (( full_passes )) && cfg_bool '.scan.iac.enabled' true; then
    log_info "[$full_name] reading the infrastructure files"
    local tv; tv=$(tmp_file trivy)
    run_trivy_config "$clone_dir" "$full_name" "$tv"
    MISCONFIG_JSON=$(normalize_trivy_config "$tv" "$full_name" "$default_branch" "$(cfg '.github.web_url' 'https://github.com')")
    # The container user check reads the supervisor config trivy never opens.
    # A failure here keeps the rows as trivy graded them.
    local mc_py; mc_py=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
    if [[ -n "$mc_py" && "$MISCONFIG_JSON" != "[]" ]]; then
      local mc_in; mc_in=$(json_file "$MISCONFIG_JSON" misconfig)
      local mc_out; mc_out=$("$mc_py" "$GHSCAN_HOME/lib/code_triage.py" --misconfig "$mc_in" "$clone_dir" 2>/dev/null) \
        && [[ -n "$mc_out" ]] && MISCONFIG_JSON="$mc_out"
    fi
    local ni; ni=$(printf '%s' "$MISCONFIG_JSON" | jq '[.[]|select(.triage=="review")]|length')
    local nit; nit=$(printf '%s' "$MISCONFIG_JSON" | jq 'length')
    if (( ni > 0 )); then
      log_warn "[$full_name] $ni misconfiguration(s) worth a look, of $nit found"
    else
      log_info "[$full_name] no misconfigurations found"
    fi
  fi

  # --- the build pipeline ---------------------------------------------------
  if (( full_passes )) && cfg_bool '.scan.workflows.enabled' true; then
    log_info "[$full_name] reading the workflows"
    local zz; zz=$(tmp_file zizmor)
    run_zizmor "$clone_dir" "$full_name" "$zz"
    WORKFLOW_JSON=$(normalize_zizmor "$zz" "$full_name" "$default_branch" "$(cfg '.github.web_url' 'https://github.com')")
    # The same job without a permissions block, once from CodeQL and once from
    # zizmor.  zizmor's row is kept; see fold_workflow_duplicates.  A failure
    # here leaves both, which is the old behavior.
    if [[ "${CODE_FINDINGS_JSON:-[]}" != "[]" && "$WORKFLOW_JSON" != "[]" ]]; then
      local fold_py; fold_py=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
      if [[ -n "$fold_py" ]]; then
        local fold_code fold_wf fold_out
        fold_code=$(json_file "$CODE_FINDINGS_JSON" fold_code)
        fold_wf=$(json_file "$WORKFLOW_JSON" fold_wf)
        fold_out=$("$fold_py" "$GHSCAN_HOME/lib/code_triage.py" --workflow-dupes \
                     "$fold_code" "$fold_wf" "$clone_dir" 2>/dev/null) \
          && [[ -n "$fold_out" ]] && CODE_FINDINGS_JSON="$fold_out"
      fi
    fi
    local nw; nw=$(printf '%s' "$WORKFLOW_JSON" | jq 'length')
    if (( nw > 0 )); then
      log_warn "[$full_name] $nw workflow finding(s), $(printf '%s' "$WORKFLOW_JSON" | jq '[.[]|select(.severity=="high")]|length') high"
    else
      log_info "[$full_name] no workflow findings"
    fi
  fi

  # --- could a dynamic pass run here ----------------------------------------
  #
  # Reading only.  Nothing is built and nothing is started: this answers
  # whether it could be, which is the question worth asking on every scan
  # because it costs a file read and it is the only way to know what fraction
  # of an estate a dynamic pass could ever cover.
  #
  # Silently skipping would be worse than declining.  A missing answer and an
  # answer of no look the same on a dashboard and only one of them is true.
  if cfg_bool '.scan.dast.qualify' true; then
    DAST_JSON=$(dast_qualify "$clone_dir" "$full_name")
    case "$(printf '%s' "$DAST_JSON" | jq -r '.verdict')" in
      qualified) log_info "[$full_name] a dynamic pass could run here: $(printf '%s' "$DAST_JSON" | jq -r '.reason')" ;;
      declined)  log_debug "[$full_name] no dynamic pass: $(printf '%s' "$DAST_JSON" | jq -r '.reason')" ;;
      *)         log_debug "[$full_name] dynamic pass qualification unknown" ;;
    esac
  fi

  if (( full_passes )); then _checkpoint code; fi

  # --- SBOM + licensing -----------------------------------------------------
  if (( full_passes )) && cfg_bool '.scan.sbom.enabled' true; then
    log_info "[$full_name] building SBOM"
    local cdx spdx; cdx=$(tmp_file cdx); spdx=$(tmp_file spdx)
    local sources; sources=$(cfg_json '.scan.sbom.sources // []')

    if printf '%s' "$sources" | jq -e 'index("syft")' >/dev/null && sbom_syft "$clone_dir" "$full_name" "$cdx" "$spdx"; then
      # Say which repository, which branch and which commit each component
      # came from, so the merged SBOM is still useful once it is flattened.
      local head_rev; head_rev=$(git -C "$clone_dir" rev-parse --short HEAD 2>/dev/null || echo "")
      sbom_stamp_repo cdx  "$cdx"  "$full_name" "$default_branch" "$head_rev"
      sbom_stamp_repo spdx "$spdx" "$full_name" "$default_branch" "$head_rev"
      # A library somebody copied in has no manifest entry, so the SBOM does
      # not have it and nothing downstream ever asks an advisory database
      # about it.  Adding it here means it goes through the same grype pass
      # as everything else rather than needing a report of its own.
      vendored_into_sbom "$clone_dir" "$full_name" "$cdx"
      # After the vendored pass, not before it: the graph has to cover what
      # that added as well, or the libraries somebody copied in are in the
      # document and in nothing that reads it.
      sbom_graph_cyclonedx "$cdx"
      SBOM_JSON=$(sbom_summarize_cyclonedx "$cdx")
    fi
    # The dependency graph, whether or not syft found anything.
    #
    # It used to be asked for only when syft came back empty, which meant a
    # repository where syft found the three libraries a pom names never had the
    # forty it actually resolves to.  Those transitive ones are most of what a
    # Java or .NET project ships and most of what turns out to be vulnerable,
    # and the host has already worked the tree out.  So it is a supplement now,
    # and only still a fallback when there is nothing to supplement.
    if printf '%s' "$sources" | jq -e 'index("github_dependency_graph")' >/dev/null; then
      local ghsbom; ghsbom=$(tmp_file ghsbom)
      if sbom_github "$full_name" "$ghsbom"; then
        if [[ "$SBOM_JSON" == "null" ]]; then
          log_debug "[$full_name] using GitHub dependency-graph SBOM"
          SBOM_JSON=$(sbom_summarize_spdx "$ghsbom")
        else
          sbom_merge_graph "$ghsbom" "$cdx" "$full_name"
          SBOM_JSON=$(sbom_summarize_cyclonedx "$cdx")
        fi
      fi
    fi
    sbom_write_per_repo "$full_name" "$cdx" "$spdx" "$(cfg '.output.dir' './out')"
    LICENSE_JSON=$(repo_license "$full_name")
    [[ "$SBOM_JSON" != "null" ]] && POLICY_JSON=$(sbom_license_policy "$SBOM_JSON")
    GHSCAN_SBOM_CDX="$cdx"

    # scan_branches=all: one SBOM per branch. Release branches routinely pin
    # different dependency versions than the default branch does.
    if [[ "$(cfg '.scan.sbom.scan_branches' 'default')" == "all" ]] && (( ${#branches[@]} > 1 )); then
      local acc; acc=$(tmp_file sbom_branches); echo '[]' > "$acc"
      local b bcdx bsum bpol
      for b in "${branches[@]}"; do
        [[ "$b" == "$default_branch" ]] && continue
        scope_full_scan "$full_name" "$b" || continue
        git -C "$clone_dir" checkout --quiet --force "$b" 2>/dev/null || continue
        bcdx=$(tmp_file cdx_branch)
        sbom_syft "$clone_dir" "$full_name" "$bcdx" "" || continue
        sbom_stamp_repo cdx "$bcdx" "$full_name" "$b" \
          "$(git -C "$clone_dir" rev-parse --short HEAD 2>/dev/null || echo "")"
        sbom_graph_cyclonedx "$bcdx"
        bsum=$(sbom_summarize_cyclonedx "$bcdx")
        [[ "$bsum" == "null" ]] && continue
        bpol=$(sbom_license_policy "$bsum")
        jq -c --arg b "$b" --argjson s "$bsum" --argjson p "$bpol" \
          '. + [{branch: $b, sbom: $s, license_policy: $p}]' "$acc" > "${acc}.n" && mv "${acc}.n" "$acc"
      done
      git -C "$clone_dir" checkout --quiet --force "$default_branch" 2>/dev/null || true
      SBOM_BY_BRANCH_JSON=$(cat "$acc")
      log_info "[$full_name] built $(jq length <<<"$SBOM_BY_BRANCH_JSON") additional per-branch SBOM(s)"
    fi
  fi

  # --- repository access ----------------------------------------------------
  if cfg_bool '.scan.access.enabled' true; then
    log_info "[$full_name] access inventory"
    local owner; owner=$(printf '%s' "$repo_json" | jq -r '.owner')
    local outside="[]"
    if [[ -n "${GHSCAN_OUTSIDE_COLLABORATORS:-}" ]]; then
      outside=$(printf '%s' "$GHSCAN_OUTSIDE_COLLABORATORS" | jq -c --arg o "$owner" '.[$o] // []')
    fi
    ACCESS_JSON=$(access_for_repo "$full_name" "$outside")
    local nu; nu=$(printf '%s' "$ACCESS_JSON" | jq '.counts.users')
    log_info "[$full_name] $nu user(s) with access, $(printf '%s' "$ACCESS_JSON" | jq '.counts.admins') admin(s)"
  fi

  # Who could have stopped it.  The access inventory is only in hand now, and a
  # workflow an outsider can trigger reads very differently next to the names of
  # the people who own the repository.  Then both sets of misconfigurations
  # become one list, because that is what they are.
  WORKFLOW_JSON=$(workflows_add_admins "$WORKFLOW_JSON" "$ACCESS_JSON")

  # What the credential pass was told not to read.  A skip list that reports
  # nothing is a scanner quietly getting smaller, so the repository gets one
  # row per file type rather than silence.
  local SKIPPED_JSON='[]'
  if [[ -n "${SECRETS_DROPPED:-}" && -s "${SECRETS_DROPPED:-/dev/null}" ]]; then
    SKIPPED_JSON=$(secrets_skipped_findings "$SECRETS_DROPPED" "$full_name" \
                     "$default_branch" "$(cfg '.github.web_url' 'https://github.com')")
    # warn, not info.  The product runs this scanner with -q, which is the
    # warn level, so an info line here is one nobody will ever read.  That
    # matters more for this than for most: the whole argument for a skip list
    # is that what it skipped gets said out loud, and the counts beside it,
    # "N secret finding(s), 0 verified live", are warn lines for the same
    # reason.  It only fires when something was actually dropped.
    log_warn "[$full_name] credential pass skipped $(wc -l < "$SECRETS_DROPPED") path(s) on the skip list"
  fi

  MISCONFIG_JSON=$(printf '%s\n%s\n%s' "$MISCONFIG_JSON" "$WORKFLOW_JSON" "$SKIPPED_JSON" \
                   | jq -c -s 'add // []')

  # The misconfiguration list is only whole here, once the workflow findings
  # have been folded into it, so this is the earliest honest place to say the
  # pass finished.  It matters beyond the checkpoint: the app closes a finding
  # only when the pass that produces its kind is named here, and a kind that
  # never names itself would have every finding of that kind closed by the
  # first run that reported none.
  if (( full_passes )); then _checkpoint misconfigurations; fi

  # Everything the default-branch passes produced now says which branches it
  # speaks for.  Done here, in one place, because the workflow findings are
  # merged into the misconfigurations just above and stamping earlier would
  # have missed them.
  local _stamp
  for _stamp in CODE_FINDINGS_JSON MISCONFIG_JSON VULNS_JSON; do
    printf -v "$_stamp" '%s' "$(printf '%s' "${!_stamp}" \
      | jq -c --argjson b "$SAME_BRANCHES_JSON" '[ .[]? | . + {branches: $b} ]' \
      || printf '%s' "${!_stamp}")"
  done

  # --- pull request history -------------------------------------------------
  if cfg_bool '.scan.pull_history.enabled' true; then
    log_info "[$full_name] pull request history"
    local prs; prs=$(pulls_fetch "$full_name")
    PULLS_JSON=$(pulls_by_user "$full_name" "$prs")
    CLONE_TRAFFIC_JSON=$(pulls_clone_traffic "$full_name")
    log_info "[$full_name] $(printf '%s' "$prs" | jq 'length') pull request(s) from $(printf '%s' "$PULLS_JSON" | jq '[.[].username] | unique | length') user(s)"
  fi

  if (( full_passes )); then _checkpoint sbom; fi

  # --- vulnerabilities ------------------------------------------------------
  if (( full_passes )) && cfg_bool '.scan.vulnerabilities.enabled' true; then
    log_info "[$full_name] vulnerability scan"
    local vsources; vsources=$(cfg_json '.scan.vulnerabilities.sources // []')
    local -a parts=()
    local f

    if printf '%s' "$vsources" | jq -e 'index("grype")' >/dev/null && [[ -n "${GHSCAN_SBOM_CDX:-}" && -s "${GHSCAN_SBOM_CDX:-/nonexistent}" ]]; then
      f=$(tmp_file v_grype); vulns_grype "$GHSCAN_SBOM_CDX" "$full_name" > "$f"; parts+=("$f")
    fi
    if printf '%s' "$vsources" | jq -e 'index("osv")' >/dev/null; then
      f=$(tmp_file v_osv); vulns_osv "$clone_dir" "$full_name" > "$f"; parts+=("$f")
    fi
    if printf '%s' "$vsources" | jq -e 'index("github_dependabot")' >/dev/null; then
      f=$(tmp_file v_dep); vulns_dependabot "$full_name" > "$f"; parts+=("$f")
    fi
    # github_code_scanning is still read from this list, so an install keeps
    # whatever it had chosen, but the alerts are code findings and are read in
    # the code pass above.
    # The layer underneath the application.  Off unless somebody turns it on:
    # this pulls base images from a registry, which is bandwidth and disk that
    # an install scanning two hundred repositories should opt into knowingly.
    # Packages that are malicious rather than vulnerable.  Answered from the
    # clone, which is the only moment these questions can be asked.
    if cfg_bool '.scan.vulnerabilities.malicious' true; then
      f=$(tmp_file v_mal); vulns_malicious "$clone_dir" "$full_name" > "$f"; parts+=("$f")
    fi
    if cfg_bool '.scan.images.enabled' false; then
      f=$(tmp_file v_img); images_scan "$clone_dir" "$full_name" > "$f"; parts+=("$f")
    fi
    if (( ${#parts[@]} > 0 )); then
      VULNS_JSON=$(vulns_merge "${parts[@]}" | vulns_stamp "$full_name" "$default_branch")
      cfg_bool '.scan.threat_intel.enabled' true && VULNS_JSON=$(threat_intel_enrich "$VULNS_JSON")
      # Which of these the application can actually reach.  After the merge so
      # it is worked out once per finding rather than once per source, and
      # before the count is logged so the number means something.
      cfg_bool '.scan.vulnerabilities.reachability' true &&
        VULNS_JSON=$(vulns_reachability "$VULNS_JSON" "$clone_dir")
      # When the file that asks for each package last changed.  Here for the
      # same reason reachability is: the clone is still on disk, and this is the
      # last moment either question can be asked.  A package has no line to
      # blame, so this is the only date the kind can carry, and without it a
      # critical that has been sitting in a repository since 2021 arrives
      # looking like one somebody introduced last night.
      (( need_clone )) && VULNS_JSON=$(vulns_dated "$VULNS_JSON" "$clone_dir")
      local nv; nv=$(printf '%s' "$VULNS_JSON" | jq 'length')
      log_info "[$full_name] $nv vulnerability finding(s)"
    fi
  fi

  cfg_bool '.clone.keep_clones' false || rm -rf -- "$clone_dir"
  if (( full_passes )); then
    PASSES_DONE="${PASSES_DONE:+$PASSES_DONE }vulnerabilities"
  fi
  _emit "ok" ""
  log_ok "[$full_name] done in $(( $(date +%s) - started ))s"
}

