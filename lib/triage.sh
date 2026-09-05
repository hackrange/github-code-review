#!/usr/bin/env bash
# Turns raw engine hits into deduped, branch-attributed, redacted findings.
# Order: allowlist, then proven-live (never dropped), then placeholder rules.
# shellcheck shell=bash

# Cache: commit sha -> JSON array of branches containing it.
declare -gA _BRANCH_CACHE=()
# Cache: commit sha -> {author_login, committer_login}
declare -gA _LOGIN_CACHE=()

# Git records a name and an email, neither of which has to be real. The commits
# API tells you which GitHub account actually pushed it.
_github_login_for_commit() {
  local full_name="$1" sha="$2"
  [[ -z "$sha" ]] && { echo '{}'; return; }
  if [[ -n "${_LOGIN_CACHE[$sha]:-}" ]]; then printf '%s' "${_LOGIN_CACHE[$sha]}"; return; fi
  local body out='{}'
  body=$(api_get_quiet "/repos/${full_name}/commits/${sha}")
  if [[ -n "$body" ]]; then
    out=$(printf '%s' "$body" | jq -c '{
      author_login:    (.author.login // null),
      author_html_url: (.author.html_url // null),
      committer_login: (.committer.login // null),
      commit_verified: (.commit.verification.verified // null)
    }' 2>/dev/null) || out='{}'
  fi
  [[ -z "$out" ]] && out='{}'
  _LOGIN_CACHE[$sha]="$out"
  printf '%s' "$out"
}

_branches_for_commit() {
  local dir="$1" sha="$2"
  [[ -z "$sha" ]] && { echo '[]'; return; }
  if [[ -n "${_BRANCH_CACHE[$sha]:-}" ]]; then printf '%s' "${_BRANCH_CACHE[$sha]}"; return; fi
  local arr
  arr=$(branches_containing "$dir" "$sha" | jq -R . | jq -sc '.' 2>/dev/null) || arr='[]'
  [[ -z "$arr" ]] && arr='[]'
  _BRANCH_CACHE[$sha]="$arr"
  printf '%s' "$arr"
}

# Which branch HEADs still contain this exact secret? Distinguishes "rotate and
# rewrite history" from "rotate only - it is already out of the working tree".
_live_at_head() {
  local dir="$1" secret="$2"; shift 2
  local branches=("$@")
  (( ${#branches[@]} == 0 )) && { echo '[]'; return; }
  (( ${#branches[@]} > 200 )) && branches=("${branches[@]:0:200}")
  local hits
  hits=$(git -C "$dir" grep -l -F -e "$secret" "${branches[@]}" -- 2>/dev/null \
         | awk -F: '{print $1}' | sort -u | jq -R . | jq -sc '.') || hits='[]'
  [[ -z "$hits" ]] && hits='[]'
  printf '%s' "$hits"
}

# triage_findings <clone_dir> <raw_ndjson> <repo_json> -> enriched NDJSON
triage_findings() {
  local dir="$1" raw="$2" repo_json="$3"
  local full_name default_branch web
  full_name=$(printf '%s' "$repo_json" | jq -r '.full_name')
  default_branch=$(printf '%s' "$repo_json" | jq -r '.default_branch')
  web=$(cfg '.github.web_url' 'https://github.com')
  web="${web%/}"

  local pre suf maxmask
  pre=$(cfg_num '.redaction.prefix_chars' 4)
  suf=$(cfg_num '.redaction.suffix_chars' 3)
  maxmask=$(cfg_num '.redaction.max_mask_chars' 12)

  export GHSCAN_REPO_FULL_NAME="$full_name"

  # The merge, the git enrichment and the triage are one pipeline rather than
  # three steps with a file between each.  Those two files held the credential
  # in the clear, because the value has to survive as far as the triage that
  # turns it into a mask and a fingerprint.  In a pipe it lives in memory for
  # as long as the next stage takes to read it, and there is nothing to leave
  # behind if the run dies halfway.

  # --- classification, placeholder filtering, allowlist, redaction ----------
  local allow_file allow_json
  allow_file=$(cfg '.scan.secrets.triage.allowlist_file' '')
  if [[ -n "$allow_file" && -r "$allow_file" ]]; then
    allow_json=$(jq -c '.' "$allow_file" 2>/dev/null || echo '{}')
  else
    allow_json='{}'
  fi

  # A record that never went through derive_secret_facts has no merge key, and
  # the merge below groups on that key, so it would be dropped without a word.
  # That happened three times while this was being written: reviews, one set of
  # test findings, then another.  Every time the symptom was findings quietly
  # going missing, never an error, which is the worst way for a tool like this
  # to be wrong.  So it stops here and says so instead.  Streamed and stopped
  # at the first offender, because on a large estate this file is long.
  local orphan
  orphan=$(jq -c 'select(has("_merge") | not)' "$raw" 2>/dev/null | head -1)
  if [[ -n "$orphan" ]]; then
    log_error "a finding reached the triage without a merge key, so it never went through derive_secret_facts.  Refusing to report a set that would silently be short: $(printf '%s' "$orphan" | jq -r '"\(.engine // "?") \(.detector // "?") \(.file // "?")"' 2>/dev/null)"
    return 1
  fi

  # --- merge duplicate hits across engines -----------------------------------
  # Same secret + same file + adjacent line = one finding, with the union of the
  # engines that saw it. A verified verdict from any engine wins.
  jq -s -c '
    map(select((._merge // "") != ""))
    | map(. + {_key: ((.repository // "") + "|" + (.file // "")
                       + "|" + (._merge // "") )})
    | group_by(._key)
    | map(
        (map(select(.verified == true)) | first) as $v
        | (.[0]) as $f
        | $f + {
            engines:    (map(.engine) | unique),
            detectors:  (map(.detector) | unique),
            rule_ids:   (map(.rule_id) | unique),
            verified:   (any(.[]; .verified == true)),
            verification_error: ($v.verification_error // (map(.verification_error) | map(select(. != null)) | first)),
            occurrences: length,
            commits:    (map(.commit) | map(select(. != "")) | unique),
            first_committed_at: (map(.committed_at) | map(select(. != null and . != "")) | sort | first),
            last_committed_at:  (map(.committed_at) | map(select(. != null and . != "")) | sort | last),
            start_line: (map(.start_line) | map(select(. > 0)) | min // 0),
            entropy:    (map(.entropy) | map(select(. != null)) | max),
            alert_url:  (map(.alert_url // empty) | first),
            branch_hint: (map(.branch_hint // empty) | first),
            tags:       (map(.tags[]?) | unique)
          }
        | del(._key)
      )
    | .[]
  ' "$raw" 2>/dev/null \
  | {

  # --- per-finding git enrichment (branches, liveness, commit metadata) -------
  local line sha branches_json live_json meta
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sha=$(printf '%s' "$line" | jq -r '.commit // ""')

    branches_json=$(_branches_for_commit "$dir" "$sha")

    # Keep only branches that survived the branch filter for this repo.
    branches_json=$(printf '%s' "$branches_json" | jq -c --argjson keep "${GHSCAN_BRANCH_SET:-[]}" '
      if ($keep | length) == 0 then . else map(select(. as $b | $keep | index($b))) end')

    local -a barr=()
    while IFS= read -r b; do [[ -n "$b" ]] && barr+=("$b"); done \
      < <(printf '%s' "$branches_json" | jq -r '.[]?')

    if (( ${#barr[@]} == 0 )); then
      # No commit to attribute by (a branch-head scan, or a GHAS alert). Use the
      # branch the finding was stamped with, else the default branch.
      local hint; hint=$(printf '%s' "$line" | jq -r '.branch_hint // ""')
      [[ -z "$hint" ]] && hint="$default_branch"
      branches_json=$(jq -cn --arg d "$hint" '[$d]')
      barr=("$hint")
    fi

    # Which branch heads still carry it was worked out where the value was
    # read.  Narrow that to the branches this particular hit belongs to.
    live_json=$(printf '%s' "$line" | jq -c --argjson branches "$branches_json" \
                  '[(._live_heads // [])[] | select(. as $h | $branches | index($h))]')

    meta='{}'
    if [[ -n "$sha" ]]; then
      meta=$(git -C "$dir" show -s --format='%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%s' "$sha" 2>/dev/null \
             | head -1 \
             | jq -Rc 'split("\u001f") | {
                 author_name:    .[0], author_email: .[1], authored_at: .[2],
                 committer_name: .[3], committer_email: .[4], committed_at: .[5],
                 commit_message: .[6]
               }') || meta='{}'
      [[ -z "$meta" ]] && meta='{}'
      # Git only records a name and email. Ask GitHub who that actually is.
      if cfg_bool '.scan.secrets.resolve_commit_authors' true; then
        local login_json; login_json=$(_github_login_for_commit "$full_name" "$sha")
        meta=$(jq -cn --argjson m "$meta" --argjson l "$login_json" '$m + $l')
      fi
    fi

    printf '%s' "$line" | jq -c \
      --argjson branches "$branches_json" \
      --argjson live "$live_json" \
      --argjson meta "$meta" \
      --arg web "$web" \
      --arg repo "$full_name" \
      --arg defbr "$default_branch" '
      . as $f
      | ($meta | with_entries(select(.value != null and .value != ""))) as $m
      | ($branches | if length == 0 then [$defbr] else . end) as $brs
      | ($brs[0]) as $primary
      | (if ($f.file // "") == "" then null
         elif ($f.commit // "") != "" then
           $web + "/" + $repo + "/blob/" + $f.commit + "/" + $f.file + (if ($f.start_line // 0) > 0 then "#L" + ($f.start_line|tostring) else "" end)
         else
           $web + "/" + $repo + "/blob/" + $primary + "/" + $f.file + (if ($f.start_line // 0) > 0 then "#L" + ($f.start_line|tostring) else "" end)
         end) as $permalink
      | $f + $m + {
          organization: ($repo | split("/")[0]),
          repository_name: ($repo | split("/")[1]),
          branches: $brs,
          primary_branch: $primary,
          branch_count: ($brs | length),
          live_in_branch_heads: $live,
          still_live_in_working_tree: (($live | length) > 0),
          exposure: (if ($live | length) > 0 then "current_and_history" else "git_history_only" end),
          url: ($permalink // $f.alert_url // ($web + "/" + $repo)),
          permalink: $permalink,
          commit_url: (if ($f.commit // "") != "" then $web + "/" + $repo + "/commit/" + $f.commit else null end),
          repository_url: ($web + "/" + $repo),
          branch_urls: [ $brs[] | { branch: ., url: ($web + "/" + $repo + "/blob/" + . + "/" + ($f.file // "") + (if ($f.start_line // 0) > 0 then "#L" + ($f.start_line|tostring) else "" end)) } ],
          blame_url: (if ($f.file // "") == "" then null
                      else $web + "/" + $repo + "/blame/" + (if ($f.commit // "") != "" then $f.commit else $primary end)
                           + "/" + $f.file + (if ($f.start_line // 0) > 0 then "#L" + ($f.start_line|tostring) else "" end) end),
          file_history_url: (if ($f.file // "") == "" then null
                             else $web + "/" + $repo + "/commits/" + $primary + "/" + $f.file end)
        }
      | del(._key)
      '
  done
  } \
  | jq -c -s \
    --argjson tri "$(cfg_json '.scan.secrets.triage')" \
    --argjson sev "$(cfg_json '.scan.secrets.severity // {}')" \
    --argjson allow "$allow_json" \
    --arg today "$(date -u +%Y-%m-%d)" '
    def shannon:
      (explode) as $c
      | ($c | length) as $n
      | if $n == 0 then 0
        else ($c | group_by(.) | map(length / $n) | map(-(. * log2)) | add)
        end;

    ($tri.placeholder_patterns // []) as $pp
    | ($tri.placeholder_paths // []) as $ppath
    | ($tri.min_entropy // 3.0) as $minent
    | ($tri.min_length // 12) as $minlen
    | (($allow.fingerprints // []) | map(ascii_downcase)) as $afp
    | ($allow.rules // []) as $arules
    | (($allow.paths // [])) as $apaths
    | (($allow.detectors // []) | map(ascii_downcase)) as $adet

    | map(
        . as $f
        | ($f.file // "") as $path
        # The value is gone by now.  Everything below is what was worked out
        # from it at the point it was read, which is the only place it existed.
        | ($f.entropy // $f._shannon // 0) as $ent

        # -- allowlist ------------------------------------------------------
        | ( ($afp | index($f.secret_fingerprint | ascii_downcase)) != null
            or ($adet | index(($f.detector // "") | ascii_downcase)) != null
            or (any($apaths[]?; . as $re | $path | test($re)))
            or (any($arules[]?;
                  . as $r
                  | (($r.expires // "9999-12-31") >= $today)
                  and (($r.repo // $f.repository) == $f.repository)
                  and (($r.path_regex // ".") as $re | $path | test($re))
                  and (($r.detector // "") == "" or (($r.detector | ascii_downcase) == (($f.detector // "") | ascii_downcase))))) 
          ) as $allowed

        # -- placeholder heuristics ------------------------------------------
        #
        # Entropy and length are the only evidence there is about a value that
        # was found because it looked like a secret.  They are the wrong
        # evidence entirely about one found because the variable holding it is
        # called password: there the name is the finding, and the value being
        # short and guessable is what a real password written by a person looks
        # like.
        #
        # Measured on this estate: "Passw0rd!" scores 2.95 and is nine
        # characters, so both filters drop it, while the placeholder
        # "your_password_here" scores 3.46 over eighteen characters and passes
        # both.  Applied here the two heuristics are not merely weak, they are
        # backwards.  Named findings are judged on the placeholder word list and
        # the path instead, which is evidence about meaning rather than shape.
        | (($f.rule // "") | test("hardcoded-password|hardcoded-secret"; "i")) as $named
        | ($f.placeholder_pattern_match // false) as $pat_hit
        | ((($f.secret_length // 0) < $minlen) and ($named | not)) as $too_short
        | (($ent < $minent) and ($named | not)) as $low_entropy
        | ($f.low_character_diversity // false) as $too_uniform
        | (any($ppath[]?; . as $re | $path | test($re))) as $noisy_path

        | (if $f.verified then "confirmed"
           elif $pat_hit or $too_uniform then "placeholder"
           elif $too_short or ($low_entropy and ($tri.drop_unverified_below_entropy // true)) then "placeholder"
           elif $noisy_path then "low"
           else "probable" end) as $verdict

        | $f + {
            entropy: (($ent * 1000 | round) / 1000),
            classification: (
              if $f.verified then "verified_live_credential"
              elif $verdict == "placeholder" then "placeholder_or_test_value"
              elif $verdict == "low" then "probable_test_fixture"
              else "unverified_probable_secret" end),
            confidence: (
              if $f.verified then "confirmed"
              elif $verdict == "low" then "low"
              elif $ent >= 4.5 then "high"
              else "medium" end),
            category: "credential",
            finding_type: "exposed_credential",
            severity: (
              if $verdict == "low" then ($sev.test_fixture // "high")
              else ($sev.credential // "critical") end),
            severity_reason: (
              if $f.verified then "credential verified live against the issuing provider"
              elif $verdict == "low" then "real-shaped credential under a test or fixture path"
              else "credential survived placeholder triage" end),
            suppressed: $allowed,
            suppression_reason: (if $allowed then "matched allowlist" else null end),
            triage: {
              verdict: $verdict,
              placeholder_pattern_match: $pat_hit,
              below_min_length: $too_short,
              below_min_entropy: $low_entropy,
              low_character_diversity: $too_uniform,
              non_production_path: $noisy_path
            }
          }
        | del(._secret)
        | del(._merge)
        | del(._shannon)
        | del(._live_heads)
        | del(.branch_hint)
      )
    | .[]
  ' 2>/dev/null || true
}

# Split a triaged NDJSON stream into the reportable set and the filtered set.
triage_partition() {
  local ndjson="$1" keep_low="$2"
  jq -c -s --argjson keep_low "$keep_low" '
    {
      reported: [ .[] | select(.suppressed == false)
                      | select(.triage.verdict != "placeholder")
                      | select($keep_low or .triage.verdict != "low") ],
      filtered: [ .[] | select(.suppressed == false)
                      | select(.triage.verdict == "placeholder" or ((($keep_low|not)) and .triage.verdict == "low"))
                      | {repository, file, detector, secret_fingerprint, secret_redacted, entropy, triage, classification} ],
      suppressed: [ .[] | select(.suppressed == true)
                      | {repository, file, detector, secret_fingerprint, suppression_reason} ]
    }' "$ndjson" 2>/dev/null || echo '{"reported":[],"filtered":[],"suppressed":[]}'
}
