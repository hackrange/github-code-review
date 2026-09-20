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

# Answers primed by _prime_live_heads, keyed on the secret itself.
declare -gA _LIVE_CACHE=()
_LIVE_PRIMED=0

# The most expensive question in the scan, asked once for everything.
#
# git grep against a tree has to inflate every blob out of the pack before it
# can match, so asking it one secret at a time inflates the same blobs once per
# secret.  On a repository with 482 candidates and 200 branches that is the
# difference between minutes and hours, and it is all repeated work: the trees
# do not change between one secret and the next.
#
# git grep takes a file of patterns, so ask for all of them in one pass and
# keep the answers.  The mapping back from a matched line to which secret was
# on it is a substring test, and it only runs over lines that already matched.
_prime_live_heads() {
  local dir="$1" secrets_file="$2"; shift 2
  local branches=("$@")
  _LIVE_PRIMED=1
  (( ${#branches[@]} == 0 )) && return 0
  [[ -s "$secrets_file" ]] || return 0
  (( ${#branches[@]} > 200 )) && branches=("${branches[@]:0:200}")

  local hits
  hits=$(tmp_file livehits)
  git -C "$dir" grep -n -F -f "$secrets_file" "${branches[@]}" -- \
      >"$hits" 2>/dev/null || true
  [[ -s "$hits" ]] || return 0

  # tree:file:line:content.  A secret is live on a tree when it appears in a
  # line found on that tree.  Long lines are cut: a minified bundle on one line
  # is not worth megabytes of substring tests, and the secret is near the match.
  local mapped
  mapped=$(tmp_file livemap)
  awk -F: -v pf="$secrets_file" '
    BEGIN { while ((getline p < pf) > 0) if (length(p)) pat[++n] = p }
    {
      tree = $1
      line = substr($0, 1, 4000)
      for (i = 1; i <= n; i++)
        if (index(line, pat[i])) seen[pat[i] SUBSEP tree] = 1
    }
    END { for (k in seen) { split(k, a, SUBSEP); print a[1] "\t" a[2] } }
  ' "$hits" >"$mapped" 2>/dev/null || true
  rm -f "$hits"

  # Both of these hold the value in the clear, so they are opened and then
  # unlinked before a byte is read.  The descriptor stays valid, the name is
  # gone, and a run that dies here leaves nothing behind holding a credential.
  local secret tree
  exec {mfd}< "$mapped"; rm -f "$mapped"
  while IFS=$'\t' read -r secret tree; do
    [[ -z "$secret" ]] && continue
    _LIVE_CACHE["$secret"]+="$tree"$'\n'
  done <&${mfd}
  exec {mfd}<&-
}

# Which branch HEADs still contain this exact secret? Distinguishes "rotate and
# rewrite history" from "rotate only - it is already out of the working tree".
_live_at_head() {
  local dir="$1" secret="$2"; shift 2
  local branches=("$@")
  (( ${#branches[@]} == 0 )) && { echo '[]'; return; }

  # Primed means the batched pass already asked about every secret it was
  # given, so a miss here is a real "no branch has it" rather than "not looked
  # at yet".  Without that distinction an empty cache would send every secret
  # back down the slow path and buy nothing.
  # A multi line value was never put in the patterns file, so the cache has
  # nothing to say about it.  Ask the old way rather than answer "no branch".
  if (( _LIVE_PRIMED )) && [[ "$secret" != *$'\n'* ]]; then
    local rows="${_LIVE_CACHE[$secret]:-}"
    [[ -z "$rows" ]] && { echo '[]'; return; }
    # Built here rather than by piping through sed, sort and two jq processes.
    # This is the hit path, so those four ran for every cached secret in the
    # repository, and on a repository with tens of thousands of candidates
    # four processes each is most of the run.  Branch names cannot contain a
    # quote, a backslash or a control character, so the only escaping a name
    # could need is escaping git would have refused in the first place.
    local -A seen=()
    local -a uniq=()
    local r
    while IFS= read -r r; do
      [[ -z "$r" ]] && continue
      [[ -n "${seen[$r]:-}" ]] && continue
      seen[$r]=1
      uniq+=("$r")
    done <<< "$rows"
    (( ${#uniq[@]} == 0 )) && { echo '[]'; return; }
    # Sorted, because the pipeline this replaces ended in sort -u and the
    # report is compared against itself between runs.  An insertion sort is
    # the right shape here: the list is one entry per branch holding the
    # value, it is capped at two hundred, and the alternative is the process
    # this change exists to remove.
    # [[ > ]] and not (( > )): the second is arithmetic, and on branch names
    # it does not compare them, it tries to evaluate them.  Both this and
    # sort read LC_COLLATE, so the order is the same one the pipeline gave.
    local i j key
    for (( i = 1; i < ${#uniq[@]}; i++ )); do
      key="${uniq[i]}"
      j=$(( i - 1 ))
      while (( j >= 0 )) && [[ "${uniq[j]}" > "$key" ]]; do
        uniq[j+1]="${uniq[j]}"
        j=$(( j - 1 ))
      done
      uniq[j+1]="$key"
    done
    local out="" n
    for n in "${uniq[@]}"; do out+=",\"$n\""; done
    printf '[%s]' "${out:1}"
    return
  fi

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
  # How this host spells a link to a file, a commit and a blame.  Once, rather
  # than once per finding: it is the same answer every time round the loop.
  local link; link=$(provider_link_parts)
  local line sha branches_json live_json meta
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sha=$(printf '%s' "$line" | jq -r '.commit // ""')

    branches_json=$(_branches_for_commit "$dir" "$sha")

    # The branches it is really on, less any an exclude pattern names.
    #
    # Against the branches that are there, not the ones this run walked: a
    # branch skipped for being quiet still holds the key, and the history walk
    # found it there.  And when every branch it is on is excluded, those are
    # still where it is.  Stamping it onto the default branch instead told a
    # developer to look for a key in code that never had it.
    branches_json=$(printf '%s' "$branches_json" | jq -c \
      --argjson keep "${GHSCAN_BRANCH_SET_PRESENT:-${GHSCAN_BRANCH_SET:-[]}}" '
      . as $all
      | if ($keep | length) == 0 then $all
        else (map(select(. as $b | $keep | index($b))) as $kept
              | if ($kept | length) > 0 then $kept else $all end)
        end')

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
      --argjson link "$link" \
      --arg repo "$full_name" \
      --arg defbr "$default_branch" '
      . as $f
      | ($meta | with_entries(select(.value != null and .value != ""))) as $m
      | ($branches | if length == 0 then [$defbr] else . end) as $brs
      | ($brs[0]) as $primary
      | (if ($f.start_line // 0) > 0 then $link.line + ($f.start_line|tostring) else "" end) as $anchor
      | (if ($f.file // "") == "" then null
         elif ($f.commit // "") != "" then
           $web + "/" + $repo + "/" + $link.blob_commit + "/" + $f.commit + "/" + $f.file + $anchor
         else
           $web + "/" + $repo + "/" + $link.blob + "/" + $primary + "/" + $f.file + $anchor
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
          commit_url: (if ($f.commit // "") != "" then $web + "/" + $repo + "/" + $link.commit + "/" + $f.commit else null end),
          repository_url: ($web + "/" + $repo),
          branch_urls: [ $brs[] | { branch: ., url: ($web + "/" + $repo + "/" + $link.blob + "/" + . + "/" + ($f.file // "") + $anchor) } ],
          blame_url: (if ($f.file // "") == "" or ($link.blame // "") == "" then null
                      elif ($f.commit // "") != "" then
                        $web + "/" + $repo + "/" + $link.blame_commit + "/" + $f.commit + "/" + $f.file + $anchor
                      else
                        $web + "/" + $repo + "/" + $link.blame + "/" + $primary + "/" + $f.file + $anchor end),
          file_history_url: (if ($f.file // "") == "" or ($link.history // "") == "" then null
                             else $web + "/" + $repo + "/" + $link.history + "/" + $primary + "/" + $f.file end)
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
    # How many of one hash shape make a file a data file.  Eight, because a
    # generated report has hundreds and nothing that holds credentials has
    # eight of one hash length in it.
    | (($tri.digest_siblings_min // 8)) as $mindig
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
        # A token whose signature is the wrong length for its own algorithm,
        # or is not base64url at all, cannot be verified by anybody.  It reads
        # as a critical credential on entropy alone, which is what put stubs
        # from fixtures and documentation at the top of the queue.
        | ($f.jwt_signature_stub // false) as $jwt_stub

        # A hash of content, in a file full of hashes of content.
        #
        # The detectors that produce most of this are the ones whose whole rule
        # is a length and a nearby keyword: thirty two alphanumeric characters
        # with the word box somewhere in the file is a Box credential as far as
        # the engine is concerned, and an Allure test id, an ETag, a lock file
        # integrity line and a coverage report id all fit it exactly.
        #
        # Two things have to hold together, and neither is enough alone.  The
        # value is bare hex at exactly one hash length, which a real secret of
        # the mixed alphanumeric shape these detectors describe essentially
        # never is: sixteen of sixty two characters, thirty two times over.  And
        # it is one of many of that same shape in the same file, which is what
        # separates a generated artifact from a configuration file holding one
        # hex API key that must still be reported.
        | (($f.digest_shaped // false)
           and (($f.digest_siblings // 0) >= $mindig)) as $digest

        | (if $f.verified then "confirmed"
           elif $pat_hit or $too_uniform or $jwt_stub or $digest then "placeholder"
           elif $too_short or ($low_entropy and ($tri.drop_unverified_below_entropy // true)) then "placeholder"
           elif $noisy_path then "low"
           else "probable" end) as $verdict

        | $f + {
            entropy: (($ent * 1000 | round) / 1000),
            classification: (
              if $f.verified then "verified_live_credential"
              elif $digest then "content_digest"
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
              elif $digest then "a content hash, one of \($f.digest_siblings) of its own shape in the same file"
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
              jwt_signature_stub: $jwt_stub,
              content_digest: $digest,
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
