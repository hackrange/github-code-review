#!/usr/bin/env bash
# Clone, run the secret engines, normalize what they spit out.
# Cleartext only ever lives in the 0700 temp dir and gets shredded after triage.
# shellcheck shell=bash

# Clone with full history for every branch, plus a working tree for the SBOM.
repo_clone() {
  local full_name="$1" dest="$2" default_branch="$3" size_kb="${4:-0}"

  local max_mb; max_mb=$(cfg_num '.clone.max_repo_size_mb' 0)
  if (( max_mb > 0 )) && (( size_kb > max_mb * 1024 )); then
    log_warn "$full_name: $(( size_kb / 1024 )) MB exceeds clone.max_repo_size_mb=${max_mb}, skipping"
    return 3
  fi

  local depth; depth=$(cfg_num '.clone.depth' 0)
  local url; url=$(auth_git_url "$full_name")

  rm -rf -- "$dest"
  mkdir -p -- "$dest"

  # --mirror into .git then flip to a work tree. Cheapest way to get every
  # branch under refs/heads plus a checkout.
  local -a cred=()
  while IFS= read -r -d '' a; do cred+=("$a"); done < <(auth_git_credential_args)

  local git_args=(clone --quiet --mirror)
  (( depth > 0 )) && git_args+=(--depth "$depth")

  if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true \
       git "${cred[@]}" -c advice.detachedHead=false \
       "${git_args[@]}" "$url" "$dest/.git" 2>"$GHSCAN_TMPROOT/clone.err"; then
    log_error "$full_name: clone failed: $(tail -3 "$GHSCAN_TMPROOT/clone.err" | tr '\n' ' ' | sed -E 's#(://[^@/[:space:]]+):[^@/[:space:]]+@#\1:***@#g')"
    return 1
  fi

  git -C "$dest" config --bool core.bare false
  git -C "$dest" config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'

  if ! git -C "$dest" checkout --quiet --force "$default_branch" 2>/dev/null; then
    git -C "$dest" checkout --quiet --force HEAD 2>/dev/null || \
      log_debug "$full_name: no working tree checkout (empty repo?)"
  fi
  return 0
}

# Everything a credential is, without keeping the credential.
#
# This is the one point in a run where the value is in hand, so this is where
# every fact derived from it gets worked out: what it hashes to, what it looks
# like masked, how long it is, how random it is, and whether it reads as
# something a person typed as a stand-in.  Then the value is dropped and only
# the facts travel on.  Before this it went the whole length of the pipeline
# and landed in whatever each stage wrote down.
#
# The fingerprint is sha256 of the value exactly as the engine handed it over,
# untouched.  It is the identity that every waiver and every triage decision in
# the database hangs off, so it cannot be normalized, tidied or recomputed from
# anything else without detaching all of them.
#
# The merge key is sha256 of the same value with the whitespace removed, which
# is a separate thing on purpose: gitleaks and trufflehog report the same
# private key with a different trailing newline, and those two hits are one
# finding.  That is the comparison the merge used to do on the raw value.
derive_secret_facts() {
  local dir="${1:-}"
  local pre suf maxmask pp
  pre=$(cfg_num '.redaction.prefix_chars' 4)
  suf=$(cfg_num '.redaction.suffix_chars' 3)
  maxmask=$(cfg_num '.redaction.max_mask_chars' 12)
  pp=$(cfg_json '.scan.secrets.triage.placeholder_patterns // []')

  local line secret fp merge redacted slen
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    secret=$(printf '%s' "$line" | jq -r '._secret // ""')
    [[ -z "$secret" ]] && continue

    fp=$(fingerprint "$secret")
    merge=$(fingerprint "$(printf '%s' "$secret" | tr -d '[:space:]')")
    redacted=$(redact "$secret" "$pre" "$suf" "$maxmask")
    slen=${#secret}

    # Whether the value is still sitting at the head of a branch, as opposed to
    # only being back in the history, is the one other thing that needs the
    # value itself: it is answered by searching the tree for it.  So it is
    # answered here, while the value is in hand, over every branch in scope.
    # The finding's own branches are narrower than that, and the intersection
    # is taken later where they are known.
    local live='[]'
    if [[ -n "$dir" ]]; then
      local -a allbr=()
      while IFS= read -r _b; do [[ -n "$_b" ]] && allbr+=("$_b"); done \
        < <(printf '%s' "${GHSCAN_BRANCH_SET:-[]}" | jq -r '.[]?' 2>/dev/null)
      (( ${#allbr[@]} > 0 )) && live=$(_live_at_head "$dir" "$secret" "${allbr[@]}")
    fi

    printf '%s' "$line" | jq -c \
      --arg fp "$fp" --arg merge "$merge" --arg redacted "$redacted" \
      --argjson slen "$slen" --argjson pp "$pp" --argjson live "$live" '
      def shannon:
        (explode) as $c
        | ($c | length) as $n
        | if $n == 0 then 0
          else ($c | group_by(.) | map(length / $n) | map(-(. * log2)) | add)
          end;
      (._secret // "") as $s
      | . + {
          secret_fingerprint: $fp,
          _merge: $merge,
          secret_redacted: $redacted,
          secret_length: $slen,
          _live_heads: $live,
          # Kept beside the engine entropy rather than replacing it.  gitleaks
          # reports its own and trufflehog does not, and the merge still wants
          # the highest any engine saw.
          _shannon: ($s | shannon),
          # A value in key armour is a key.  Its body is base64, base64 spells
          # anything given enough of it, and matching placeholder words against
          # that is how a real private key got dropped as a stand-in.
          placeholder_pattern_match:
            (if ($s | test("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")) then false
             else any($pp[]?; . as $re | $s | test($re)) end),
          low_character_diversity:
            (($s | explode | unique | length) <= 4 and ($s | length) >= 8)
        }
      | del(._secret)'
  done
}

# Engine: gitleaks
_gitleaks_subcommand() {
  # gitleaks >= 8.19 prefers `git`; older releases only have `detect`.
  if gitleaks git --help >/dev/null 2>&1; then echo "git"; else echo "detect"; fi
}

run_gitleaks() {
  local dir="$1" full_name="$2" out="$3"
  have_cmd gitleaks || { log_debug "gitleaks not installed, skipping"; echo '[]' > "$out"; return 0; }

  local sub; sub=$(_gitleaks_subcommand)
  local args=("$sub" "$dir" --report-format json --report-path "$out" --exit-code 0 --no-banner)

  if cfg_bool '.github.branches.scan_full_history' true; then
    # The caller decides how much of the history this run covers.  Without a
    # window that is all of it, which is what this always passed.
    args+=(--log-opts "${GHSCAN_LOG_OPTS:---all --full-history}")
  else
    args+=(--no-git)
  fi

  local gl_cfg; gl_cfg=$(cfg '.scan.secrets.gitleaks.config_path' '')
  [[ -n "$gl_cfg" && -r "$gl_cfg" ]] && args+=(--config "$gl_cfg")

  local maxmb; maxmb=$(cfg_num '.scan.secrets.gitleaks.max_target_megabytes' 0)
  (( maxmb > 0 )) && args+=(--max-target-megabytes "$maxmb")

  log_debug "$full_name: gitleaks ${args[*]}"
  gitleaks "${args[@]}" >"$GHSCAN_TMPROOT/gitleaks.log" 2>&1 || {
    log_warn "$full_name: gitleaks exited non-zero: $(tail -2 "$GHSCAN_TMPROOT/gitleaks.log" | tr '\n' ' ')"
  }
  [[ -s "$out" ]] || echo '[]' > "$out"
  jq -e . "$out" >/dev/null 2>&1 || echo '[]' > "$out"
}

# Engine: trufflehog (the only engine that can PROVE a credential is live)
run_trufflehog() {
  local dir="$1" full_name="$2" out="$3"
  have_cmd trufflehog || { log_debug "trufflehog not installed, skipping"; : > "$out"; return 0; }

  local args=(git "file://$dir" --json --no-update)
  # trufflehog cannot walk backwards through history the way gitleaks can: it
  # only takes a commit to start from and a depth.  So when the history is being
  # covered a window at a time, this engine takes the newest window and
  # gitleaks takes the rest.  Deep history is therefore detected but not
  # verified live, which the finding itself says.
  if [[ -n "${GHSCAN_TH_SINCE_COMMIT:-}" ]]; then
    args+=(--since-commit "$GHSCAN_TH_SINCE_COMMIT")
  fi
  if cfg_bool '.scan.secrets.trufflehog.verify' true; then
    local res; res=$(cfg '.scan.secrets.trufflehog.results' 'verified,unverified,unknown')
    args+=(--results "$res")
  else
    # Without verification every result is "unverified"; asking for anything
    # narrower would silently return nothing.
    args+=(--no-verification)
  fi

  local conc; conc=$(cfg_num '.scan.secrets.trufflehog.concurrency' 8)
  args+=(--concurrency "$conc")

  local d
  while IFS= read -r d; do [[ -n "$d" ]] && args+=(--include-detectors "$d"); done \
    < <(cfg_arr '.scan.secrets.trufflehog.include_detectors')
  while IFS= read -r d; do [[ -n "$d" ]] && args+=(--exclude-detectors "$d"); done \
    < <(cfg_arr '.scan.secrets.trufflehog.exclude_detectors')

  log_debug "$full_name: trufflehog ${args[*]}"
  trufflehog "${args[@]}" 2>"$GHSCAN_TMPROOT/trufflehog.log" \
    | grep -E '^\{' > "$out" || true
  [[ -f "$out" ]] || : > "$out"
}

# Used when scan_full_history is off. Caller checks out each branch, these scan
# the files as they are. Faster, but blind to anything already deleted.
run_gitleaks_worktree() {
  local dir="$1" full_name="$2" out="$3"
  have_cmd gitleaks || { echo '[]' > "$out"; return 0; }
  local sub; sub=$(_gitleaks_subcommand)
  [[ "$sub" == "git" ]] && sub="dir"
  local args=("$sub" "$dir" --report-format json --report-path "$out" --exit-code 0 --no-banner)
  [[ "$sub" == "detect" ]] && args+=(--no-git)

  local gl_cfg; gl_cfg=$(cfg '.scan.secrets.gitleaks.config_path' '')
  [[ -n "$gl_cfg" && -r "$gl_cfg" ]] && args+=(--config "$gl_cfg")

  gitleaks "${args[@]}" >"$GHSCAN_TMPROOT/gitleaks.log" 2>&1 || true
  [[ -s "$out" ]] || echo '[]' > "$out"
  jq -e . "$out" >/dev/null 2>&1 || echo '[]' > "$out"
}

run_trufflehog_worktree() {
  local dir="$1" full_name="$2" out="$3"
  have_cmd trufflehog || { : > "$out"; return 0; }
  local args=(filesystem "$dir" --json --no-update)
  if cfg_bool '.scan.secrets.trufflehog.verify' true; then
    args+=(--results "$(cfg '.scan.secrets.trufflehog.results' 'verified,unverified,unknown')")
  else
    args+=(--no-verification)
  fi
  args+=(--concurrency "$(cfg_num '.scan.secrets.trufflehog.concurrency' 8)")
  trufflehog "${args[@]}" 2>"$GHSCAN_TMPROOT/trufflehog.log" | grep -E '^\{' > "$out" || true
  [[ -f "$out" ]] || : > "$out"
}

# Stamp a branch onto findings that have no commit to attribute them by, and
# strip the clone directory prefix from absolute paths.
tag_branch() {
  local branch="$1" root="$2"
  jq -c --arg b "$branch" --arg root "$root" '
    . + {
      branch_hint: $b,
      file: ((.file // "") | ltrimstr($root) | ltrimstr("/"))
    }'
}

# Engine: GitHub Advanced Security secret scanning alerts (server-side, free)
run_github_secret_scanning() {
  local full_name="$1" out="$2"
  # GHAS is GitHub only.  The clone is still scanned by gitleaks and
  # trufflehog, which is where most of these come from anyway.
  if ! provider_supports secret_scanning_alerts; then
    log_debug "$(provider_name) has no GHAS secret alerts, so it is not asked for"
    echo '[]' > "$out"; return 0
  fi
  local alerts
  alerts=$(api_paginate "/repos/${full_name}/secret-scanning/alerts?state=open" 100) || {
    log_debug "$full_name: secret scanning alerts unavailable (GHAS off or no permission)"
    echo '[]' > "$out"; return 0
  }
  printf '%s' "$alerts" | jq -c '.' > "$out" 2>/dev/null || echo '[]' > "$out"
}

# Each engine's JSON into one common shape. `_secret` holds the cleartext for
# the enrichment step only, triage strips it before anything is written out.
normalize_gitleaks() {
  local in="$1" full_name="$2"
  jq -c --arg repo "$full_name" --argjson alias "$(detector_alias_map)" "$JQ_CANON_DETECTOR"'
    .[]? | {
      engine: "gitleaks",
      repository: $repo,
      # One spelling, whichever engine found it.  rule_id below keeps what the
      # engine actually said, so nothing is lost.
      detector: ((.RuleID // "unknown") | canon_detector($alias)),
      rule_id: (.RuleID // "unknown"),
      description: (.Description // ""),
      file: (.File // ""),
      start_line: (.StartLine // 0),
      end_line: (.EndLine // .StartLine // 0),
      start_column: (.StartColumn // 0),
      end_column: (.EndColumn // 0),
      commit: (.Commit // ""),
      author_name: (.Author // ""),
      author_email: (.Email // ""),
      committed_at: (.Date // ""),
      commit_message: null,
      entropy: (.Entropy // null),
      verified: false,
      verification_error: null,
      engine_fingerprint: (.Fingerprint // ""),
      tags: (.Tags // []),
      _secret: (.Secret // .Match // "")
    }' "$in" 2>/dev/null
}

normalize_trufflehog() {
  local in="$1" full_name="$2"
  jq -c --arg repo "$full_name" --argjson alias "$(detector_alias_map)" "$JQ_CANON_DETECTOR"'
    select(.DetectorName != null) |
    (.SourceMetadata.Data.Git // {}) as $g |
    {
      engine: "trufflehog",
      repository: $repo,
      detector: ((.DetectorName // "unknown") | canon_detector($alias)),
      rule_id: ((.DetectorName // "unknown") + (if .DecoderName and .DecoderName != "PLAIN" then "/" + .DecoderName else "" end)),
      description: ((.DetectorName // "secret") + " credential detected by TruffleHog"),
      file: ($g.file // ""),
      start_line: ($g.line // 0),
      end_line: ($g.line // 0),
      start_column: 0,
      end_column: 0,
      commit: ($g.commit // ""),
      author_name: "",
      author_email: ($g.email // ""),
      committed_at: ($g.timestamp // ""),
      commit_message: null,
      entropy: null,
      verified: (.Verified // false),
      verification_error: (.VerificationError // null),
      engine_fingerprint: "",
      tags: ([ .DecoderName // empty, (if .Verified then "verified" else "unverified" end) ]),
      _secret: (.Raw // .RawV2 // "")
    }' "$in" 2>/dev/null
}

normalize_github_alerts() {
  local in="$1" full_name="$2"
  jq -c --arg repo "$full_name" --argjson alias "$(detector_alias_map)" "$JQ_CANON_DETECTOR"'
    .[]? | {
      engine: "github_secret_scanning",
      repository: $repo,
      detector: ((.secret_type_display_name // .secret_type // "unknown") | canon_detector($alias)),
      rule_id: (.secret_type // "unknown"),
      description: ("GitHub secret scanning alert #" + ((.number // 0) | tostring) + " (" + (.state // "open") + ")"),
      file: "",
      start_line: 0,
      end_line: 0,
      start_column: 0,
      end_column: 0,
      commit: "",
      author_name: "",
      author_email: "",
      committed_at: (.created_at // ""),
      commit_message: null,
      entropy: null,
      verified: ((.validity // "") == "active"),
      verification_error: null,
      engine_fingerprint: ("gh-alert-" + ((.number // 0) | tostring)),
      tags: (["github_advanced_security", (.validity // "unknown")]),
      alert_number: .number,
      alert_url: .html_url,
      push_protection_bypassed: (.push_protection_bypassed // false),
      _secret: (.secret // "")
    }' "$in" 2>/dev/null
}

# GHAS alerts carry their locations on a separate endpoint; fetch them so the
# report can name the file and blob URL like the other engines do.
enrich_github_alert_locations() {
  local full_name="$1" ndjson="$2"
  local out; out=$(tmp_file ghloc)
  : > "$out"
  local line num locs
  while IFS= read -r line; do
    num=$(printf '%s' "$line" | jq -r '.alert_number // empty')
    if [[ -z "$num" ]]; then printf '%s\n' "$line" >> "$out"; continue; fi
    locs=$(api_get_quiet "/repos/${full_name}/secret-scanning/alerts/${num}/locations?per_page=30")
    if [[ -z "$locs" ]]; then printf '%s\n' "$line" >> "$out"; continue; fi
    printf '%s' "$line" | jq -c --argjson L "${locs:-[]}" '
      ( [ $L[]? | select(.type == "commit") | .details ] | first ) as $d
      | if $d == null then .
        else . + {
          file: ($d.path // .file),
          start_line: ($d.start_line // .start_line),
          end_line: ($d.end_line // .end_line),
          commit: ($d.blob_sha // $d.commit_sha // .commit)
        } end' >> "$out"
  done < "$ndjson"
  mv "$out" "$ndjson"
}

# detect-secrets works off file contents, not git history, and it hashes the
# secret rather than handing it over. So we use it as a second opinion: any
# finding it agrees with at the same file and line gets marked corroborated.
run_detect_secrets() {
  local dir="$1" out="$2"
  local ds; ds=$(ghscan_venv_bin detect-secrets)
  [[ -z "$ds" ]] && { echo '[]' > "$out"; return 0; }

  ( cd "$dir" && "$ds" scan --all-files 2>/dev/null ) \
    | jq -c '[ (.results // {}) | to_entries[] | .key as $f | .value[]
               | {file: $f, line: (.line_number // 0), type: .type} ]' \
    > "$out" 2>/dev/null || echo '[]' > "$out"
  [[ -s "$out" ]] || echo '[]' > "$out"
}

# Mark findings that detect-secrets also flagged.
corroborate() {
  local hits="$1"
  jq -c --slurpfile h "$hits" '
    ($h[0] // []) as $ds
    | . as $f
    | [ $ds[] | select(.file == ($f.file // "") and ((.line // 0) == ($f.start_line // -1))) ] as $m
    | $f + {
        corroborated_by: (if ($m | length) > 0 then ["detect-secrets"] else [] end),
        corroborating_detectors: [ $m[].type ]
      }'
}
