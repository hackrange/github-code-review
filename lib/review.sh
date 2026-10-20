#!/usr/bin/env bash
# review: one directory, no GitHub.
#
# Everything else in here starts by asking an API which repositories exist and
# then cloning them.  This does not.  It takes a path that is already on the
# machine and looks at it, which is what a pre-commit hook, a CI job and an
# editor all need.
#
# The difference matters more than it sounds.  A scan reports credentials that
# have been in the history for months and now have to be rotated.  This runs
# before the commit exists, which is the only point where a leak can still be
# prevented rather than cleaned up after.
#
# Both engines run: credentials and code.  A review that only looked for
# secrets would miss the thing the author is more likely to be introducing.
# shellcheck shell=bash

# review_paths <dir> [<base>] -> the files to look at, one per line
#
# With a base, only what changed against that ref, so an editor and a hook see
# the author's own work rather than the repository's backlog.  Somebody opening
# a file should not be shown two thousand findings they did not write.
#
# Files git has never seen count as changed.  They are entirely this person's
# work, and git diff does not list them, so leaving them out would hide every
# finding in a file somebody just wrote.  The editor plugin learned the same
# thing in ide/core/changed.js.
review_paths() {
  local dir="$1" base="${2:-}"
  if [[ -z "$base" ]]; then
    printf '%s\n' "$dir"
    return 0
  fi
  git -C "$dir" rev-parse --git-dir >/dev/null 2>&1 || {
    log_warn "not a git checkout, so everything is being looked at"
    printf '%s\n' "$dir"; return 0; }
  git -C "$dir" rev-parse --verify --quiet "${base}^{commit}" >/dev/null || {
    log_warn "$base is not a commit here, so everything is being looked at"
    printf '%s\n' "$dir"; return 0; }
  { git -C "$dir" diff --name-only -z --diff-filter=ACMRT "$base" -- 2>/dev/null
    git -C "$dir" ls-files -z --others --exclude-standard 2>/dev/null; } \
    | while IFS= read -r -d '' f; do [[ -f "$dir/$f" ]] && printf '%s\n' "$f"; done \
    | sort -u
}

# review_stage <dir> <list> <dest> -> copies the listed files under dest
#
# The engines all take a directory, so a diff is reviewed by copying the files
# it names into one of its own.  Paths are kept, because a rule that keys on
# a path (tests/, a Dockerfile, a workflow) has to see the real one.
review_stage() {
  local dir="$1" list="$2" dest="$3" f
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    mkdir -p "$dest/$(dirname "$f")"
    cp -p -- "$dir/$f" "$dest/$f" 2>/dev/null || true
  done < "$list"
}

# review_secrets <dir> <name> -> ndjson of credential findings
review_secrets() {
  local dir="$1" name="$2"
  local gl th merged
  gl=$(tmp_file rgl); th=$(tmp_file rth); merged=$(tmp_file rmerge)

  run_gitleaks_worktree "$dir" "$name" "$gl"
  run_trufflehog_worktree "$dir" "$name" "$th"

  : > "$merged"
  # Same derive step a scan uses.  It turns the value into a fingerprint, a
  # mask and the facts the triage reads, and then drops it, so a review never
  # writes a credential down either.  A record that skipped this would have no
  # merge key and would be dropped by the triage without a word.
  normalize_gitleaks "$gl" "$name" | derive_secret_facts "$dir" \
    >> "$merged" 2>/dev/null || true
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    printf '%s' "$line" | normalize_trufflehog /dev/stdin "$name" \
      | derive_secret_facts "$dir" >> "$merged" 2>/dev/null || true
  done < "$th"
  wipe_file "$gl"; wipe_file "$th"
  printf '%s' "$(cat "$merged")"
}

# review_code <dir> <name> -> json array of code findings
review_code() {
  local dir="$1" name="$2"
  cfg_bool '.scan.code_analysis.enabled' true || { echo '[]'; return 0; }
  local raw; raw=$(tmp_file rsem)
  # run_semgrep triages what it finds before it returns, so the same verdicts
  # apply here as in a scan.  Calling code_triage again from here ran it twice
  # and said so twice in the log.
  run_semgrep "$dir" "$name" "$raw" || true
  # Four arguments, not three.  ghscan runs with set -u, so a missing one is
  # an unbound variable that takes the whole function down, and the || below
  # then turns a crash into a quiet "no findings".
  local findings
  findings=$(normalize_semgrep "$raw" "$name" "" "" 2>/dev/null || echo '[]')

  # The same second engine a scan gets.  An editor and a pipeline asking the
  # same question should not get a thinner answer than the nightly run does,
  # and this is exactly where somebody is about to commit the thing.
  if cfg_bool '.scan.code_analysis.second_engine' true; then
    local langs; langs=$(code_languages "$dir")
    local -a extras=()
    [[ "$langs" == *go* ]] && extras+=("$(run_gosec "$dir" "$name" "" "")")
    [[ "$langs" == *python* ]] && extras+=("$(run_bandit "$dir" "$name" "" "")")
    [[ "$langs" == *javascript* ]] && extras+=("$(run_njsscan "$dir" "$name" "" "")")
    (( ${#extras[@]} > 0 )) && findings=$(code_merge "$findings" "${extras[@]}")
  fi
  if [[ "$(code_languages "$dir")" == *mule* ]]; then
    local mule; mule=$(run_mule_check "$dir" "$name" "" "")
    [[ "$mule" != "[]" ]] && findings=$(code_merge "$findings" "$mule")
  fi
  printf '%s' "$findings"
}

# review_iac <dir> <name> -> json array of misconfiguration findings
review_iac() {
  local dir="$1" name="$2"
  cfg_bool '.scan.iac.enabled' true || { echo '[]'; return 0; }
  have_cmd trivy || { echo '[]'; return 0; }
  local raw; raw=$(tmp_file rtrivy)
  run_trivy_config "$dir" "$name" "$raw" || true
  normalize_trivy_config "$raw" "$name" "HEAD" "" 2>/dev/null || echo '[]'
}

# review_workflows <dir> <name> -> json array of workflow findings
review_workflows() {
  local dir="$1" name="$2"
  cfg_bool '.scan.workflows.enabled' true || { echo '[]'; return 0; }
  have_cmd zizmor || { echo '[]'; return 0; }
  local raw; raw=$(tmp_file rziz)
  run_zizmor "$dir" "$name" "$raw" || true
  normalize_zizmor "$raw" "$name" "HEAD" "" 2>/dev/null || echo '[]'
}

# review_run <dir> <base> <only> -> the whole thing as one json document
review_run() {
  local dir="$1" base="${2:-}" only="${3:-secrets,code}" name="${4:-}"
  [[ -n "$name" ]] || name="$(basename "$(cd "$dir" && pwd)")"

  # Once, here, in this shell.  Everything below runs in a command
  # substitution, and a subshell that makes its own temp root leaves the parent
  # still holding an empty one, so every path becomes /gitleaks.log and nothing
  # can be written.
  tmp_init

  # A review has no config file, because the whole point is that it runs on a
  # laptop or in a hook where there is nothing to point at.  So it brings its
  # own: the rules this project ships, and semgrep's default packs.  Anything
  # already loaded with -c wins, so a pipeline that does have a config keeps
  # using it.
  # The triage defaults ship as a file so a review gets the same filtering a
  # scan gets.  This used to hand triage empty lists, which meant a pipeline saw
  # every placeholder and stand-in the scheduled scan quietly set aside: the
  # wrong way round, because the pipeline is the one a developer reads.
  local tri_defaults='{"placeholder_patterns":[],"placeholder_paths":[]}'
  if [[ -r "$GHSCAN_HOME/config/triage-defaults.json" ]]; then
    tri_defaults=$(jq -c '{placeholder_patterns, placeholder_paths}' \
                     "$GHSCAN_HOME/config/triage-defaults.json" 2>/dev/null \
                   || printf '%s' "$tri_defaults")
  else
    log_debug "no triage defaults file, so a review filters nothing"
  fi

  if [[ -z "${GHSCAN_CFG_JSON:-}" || "$GHSCAN_CFG_JSON" == "{}" ]]; then
    GHSCAN_CFG_JSON=$(jq -cn --arg rules "$GHSCAN_HOME/config/gitleaks-extra.toml" \
                            --argjson tri "$tri_defaults" '{
      scan: {
        secrets: {
          enabled: true,
          gitleaks: {config_path: $rules, max_target_megabytes: 25},
          trufflehog: {verify: false, concurrency: 4},
          triage: {
            min_entropy: 3.0, min_length: 12,
            drop_unverified_below_entropy: true,
            placeholder_patterns: $tri.placeholder_patterns,
            placeholder_paths: $tri.placeholder_paths,
            path_rule_downgrades_only: true,
            allowlist_file: ""
          }
        },
        iac: {
          enabled: true, offline: false, skip_dirs: [], timeout_sec: 300
        },
        workflows: {
          enabled: true, persona: "regular", offline: true, timeout_sec: 300
        },
        code_analysis: {
          enabled: true, triage: true, jobs: 2, timeout_sec: 300,
          rulesets: ["p/default", "p/secrets", "p/owasp-top-ten",
                     "p/command-injection", "p/sql-injection", "p/xss"],
          muted_rules: []
        }
      },
      redaction: {prefix_chars: 4, suffix_chars: 3, max_mask_chars: 12}
    }')
  fi
  # --verify and --no-verify, which a review used to accept and then ignore.
  # The gate turns it on, because "live" is the one word in its policy that
  # only the issuing provider can say.
  if [[ -n "${GHSCAN_ARG_VERIFY:-}" ]]; then
    GHSCAN_CFG_JSON=$(printf '%s' "$GHSCAN_CFG_JSON" \
      | jq -c --argjson v "$GHSCAN_ARG_VERIFY" '.scan.secrets.trufflehog.verify = $v')
  fi

  # With a base, the engines look at a copy holding only what changed.  This
  # used to record the base and then look at everything, so --diff answered
  # with the whole repository's backlog while saying it had not.
  local reviewed="$dir" stage=""
  if [[ -n "$base" ]]; then
    local list; list=$(tmp_file rpaths)
    review_paths "$dir" "$base" > "$list"
    if [[ "$(head -n 1 "$list")" != "$dir" ]]; then
      stage=$(tmp_dir rstage)
      review_stage "$dir" "$list" "$stage"
      dir="$stage"
    fi
  fi

  local secrets='[]' code='[]' iac='[]'
  if [[ ",$only," == *",secrets,"* ]]; then
    local raw; raw=$(review_secrets "$dir" "$name")
    if [[ -n "$raw" ]]; then
      local repo_json
      repo_json=$(jq -cn --arg n "$name" '{full_name: $n, default_branch: "HEAD"}')
      local triaged; triaged=$(tmp_file rtri)
      printf '%s' "$raw" > "$triaged"
      secrets=$(triage_findings "$dir" "$triaged" "$repo_json" 2>/dev/null \
                | jq -s -c '[ .[] | select(.suppressed != true)
                              | select(.triage.verdict != "placeholder") ]' \
                || echo '[]')
    fi
  fi
  [[ ",$only," == *",code,"* ]] && code=$(review_code "$dir" "$name")
  [[ ",$only," == *",iac,"* ]] && iac=$(review_iac "$dir" "$name")
  if [[ ",$only," == *",workflows,"* ]]; then
    local wf; wf=$(review_workflows "$dir" "$name")
    iac=$(printf '%s\n%s' "${iac:-[]}" "${wf:-[]}" | jq -c -s 'add // []')
  fi

  if [[ -n "$stage" ]]; then
    # Paths come back under the copy.  Report them as the caller knows them,
    # or every link and every editor underline points at a directory that is
    # already gone.
    review_document "${secrets:-[]}" "${code:-[]}" "${iac:-[]}" "$reviewed" "$base" \
      | jq --arg stage "$stage/" --arg dir "${reviewed%/}/" '
          .findings |= map(.file |= (if startswith($stage)
                                     then $dir + ltrimstr($stage) else . end))'
    rm -rf -- "$stage"
  else
    review_document "${secrets:-[]}" "${code:-[]}" "${iac:-[]}" "$dir" "$base"
  fi
}

# review_document <secrets> <code> <iac> <dir> <base> -> the review document
#
# Its own function so the gate can build the same shape for the secrets it
# finds in commit history, rather than a second copy of the field list that
# drifts from this one.
review_document() {
  local secrets="$1" code="$2" iac="$3" dir="$4" base="${5:-}"
  # Both of these go to jq through a file.  A review of a large repository with
  # no --diff produces thousands of findings, and argv runs out long before jq
  # does.  Everywhere else in here already learned that the hard way.
  local f_secrets f_code f_iac
  f_secrets=$(json_file "${secrets:-[]}" rvsec)
  f_code=$(json_file "${code:-[]}" rvcode)
  f_iac=$(json_file "${iac:-[]}" rviac)

  jq -n --slurpfile secrets_in "$f_secrets" --slurpfile code_in "$f_code" \
        --slurpfile iac_in "$f_iac" \
        --arg dir "$dir" --arg base "$base" --arg version "$GHSCAN_VERSION" '
    ($secrets_in[0]) as $secrets
    | ($code_in[0]) as $code
    | ($iac_in[0]) as $iac
    | {
      generator: ("ghscan " + $version),
      reviewed: $dir,
      against: (if $base == "" then null else $base end),
      findings: (
        [ $secrets[] | {
            kind: "credential",
            file: .file, line: (.start_line // 0),
            start_column: (.start_column // 0), end_column: (.end_column // 0),
            rule: (.detector // .rule_id // "secret"),
            severity: (.severity // "critical"),
            title: (.description // "credential"),
            message: ((.classification // "") + " " + (.severity_reason // "") | ltrimstr(" ")),
            confidence: (.confidence // "medium"),
            # Whether the issuing provider said it still works.  Only
            # TruffleHog can ask, and only when verification is on.
            verified: (.verified == true),
            commit: (.commit // null),
            preview: (.secret_redacted // null),
            fingerprint: (.secret_fingerprint // null)
          } ]
        + [ $code[] | {
            kind: "code",
            file: .file, line: (.start_line // 0),
            start_column: (.start_column // 0), end_column: (.end_column // 0),
            rule: (.rule_name // .rule_id // "code"),
            severity: (.severity // "medium"),
            title: (.title // ""),
            message: (.message // ""),
            confidence: (.confidence // ""),
            triage: (.triage // null),
            triage_reason: (.triage_reason // null),
            # What the rule matched.  The web app keys a code finding on it
            # rather than the line, so this is how a review finds the waiver
            # on the same finding.
            matched: (.matched // null),
            # Which engines saw it.  An editor showing "two engines agree" is
            # showing the strongest signal either of them produces.
            engines: (.engines // [ (.source // "semgrep") ]),
            corroborated: (.corroborated // false)
          } ]
        + [ $iac[] | {
            kind: "misconfiguration",
            file: .file, line: (.start_line // 0),
            start_column: 0, end_column: 0,
            rule: (.rule_id // "iac"),
            severity: (.severity // "medium"),
            title: (.title // ""),
            message: (.message // ""),
            confidence: (.confidence // "high"),
            configuration_kind: (.configuration_kind // ""),
            finding_type: (.finding_type // ""),
            resource: (.resource // ""),
            provider: (.provider // ""),
            resolution: (.resolution // ""),
            help_url: (.help_url // ""),
            triage: (.triage // null),
            triage_reason: (.triage_reason // null)
          } ]
      )
    }
    | .counts = {
        total: (.findings | length),
        credential: ([ .findings[] | select(.kind == "credential") ] | length),
        code: ([ .findings[] | select(.kind == "code") ] | length),
        misconfiguration: ([ .findings[] | select(.kind == "misconfiguration") ] | length)
      }'
}
