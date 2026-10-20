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
    # Said out loud rather than at debug.  Without a checkout there is no index
    # file, and trufflehog refuses to read the repository at all: "failed to
    # read index file".  That reads as an engine fault and is not one, and the
    # pass it fails is then held open for ever while the catch up queue tries
    # the same repository again every twenty minutes.  One line here would have
    # named the cause in a minute rather than an hour.
    git -C "$dest" checkout --quiet --force HEAD 2>/dev/null || \
      log_warn "$full_name: no working tree could be checked out, so there is no index and the credential engines cannot read it.  An empty repository, or a default branch ($default_branch) that is not there."
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
# Claim names that make a token a disclosure on its own, whether or not
# anybody can still use it.  An expired token carrying an employee's address
# is a dead credential and a live privacy problem, and those are two different
# findings that the same value produces.
JWT_IDENTITY_CLAIMS='["email","emails","mail","upn","unique_name",
  "preferred_username","username","name","given_name","family_name",
  "middle_name","nickname","phone","phone_number","address","birthdate",
  "gender","ssn","employee_id","employeeid","employeenumber","oid","puid",
  "national_id","dob"]'

# Claim names that say what the holder could do.  These raise what a token is
# worth to somebody who finds it: "read one report" and "administer the fleet"
# are the same leak with very different consequences.
JWT_PRIVILEGE_CLAIMS='["roles","role","scope","scp","scopes","permissions",
  "perms","groups","grp","authorities","entitlements","admin","is_admin",
  "isadmin","tenant","tid","act","azp","client_id","appid"]'

# How much diff a full history walk would hand the engines, roughly.
#
# The clone size limit above asks how big a repository is on disk.  That is the
# wrong question for the pass that reads history, and one repository showed
# exactly how wrong: two hundred and fourteen megabytes of git, six hundred and
# ninety commits, and sixteen and a half gigabytes of diff on the way into the
# engine, because every commit rewrote generated test artifacts wholesale.  It
# passed the size check comfortably and then took nine hours and twenty eight
# gigabytes of memory without finishing.
#
# Measured by sampling rather than by reading it all, since reading it all is
# the thing being avoided.  A handful of commits gives the average diff, and
# the commit count turns that into a projection.  It is an estimate and is
# treated as one: the limit is a ceiling for the obviously impossible, not a
# fine judgement about the merely large.
history_volume_mb() {
  local dir="$1" sample="${2:-40}"
  local commits; commits=$(git -C "$dir" rev-list --all --count 2>/dev/null || echo 0)
  [[ "$commits" =~ ^[0-9]+$ ]] || commits=0
  (( commits == 0 )) && { printf '0'; return 0; }

  # Spread across the whole history, not the newest end of it.
  #
  # This used to take the newest forty commits and scale their mean up.  That
  # reads a repository backwards.  The commits that make a history expensive
  # are almost always old: somebody imported a pile of generated artifacts
  # years ago, or a build wrote its output into the tree for a while and then
  # stopped.  The recent commits are ordinary work, so the mean came out near
  # nothing and the estimate with it.
  #
  # Measured on a repository built to that shape: two hundred commits, ten of
  # them early ones rewriting a five megabyte artifact whole, the rest one line
  # each.  A hundred and twenty four megabytes of real diff, and the estimate
  # said zero.  The same blind spot let a four hundred and sixty megabyte
  # repository through the ceiling and cost seventeen hundred credentials when
  # the engine was killed part way and its silence read as a clean sweep.
  #
  # So take every stride'th commit instead.  Same number of samples, same cost,
  # and the old artifacts are now in the sample rather than behind it.
  # Counted from zero, not from one.  A repository with fewer commits than the
  # sample size has a stride of one, and `NR % 1 == 1` is never true, so every
  # small repository would measure zero and pass any ceiling.
  local stride=$(( (commits + sample - 1) / sample ))
  (( stride < 1 )) && stride=1

  # Two bounds, because measuring must never become the expensive thing it is
  # there to avoid.  One commit is read up to PER, and the walk stops once
  # TOTAL has been read: by then the answer is already "far too big", and
  # reading more of it only confirms that more slowly.
  local PER=$(( 64 * 1048576 )) TOTAL=$(( 1024 * 1048576 ))
  local bytes=0 seen=0 sha n
  while IFS= read -r sha; do
    [[ -n "$sha" ]] || continue
    n=$(git -C "$dir" show -U0 --format= "$sha" 2>/dev/null \
        | head -c "$PER" | wc -c 2>/dev/null || echo 0)
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    bytes=$(( bytes + n ))
    seen=$(( seen + 1 ))
    (( bytes >= TOTAL )) && break
  done < <(git -C "$dir" rev-list --all 2>/dev/null \
           | awk -v s="$stride" '(NR - 1) % s == 0')

  (( seen == 0 )) && { printf '0'; return 0; }
  printf '%s' $(( bytes / seen * commits / 1048576 ))
}

# Is this repository's history too big to hand an engine.  -> 0 when it is fine.
history_is_too_big() {
  local dir="$1" full_name="$2" measured="${3:-}"
  local cap; cap=$(cfg_num '.scan.secrets.max_history_mb' 0)
  (( cap <= 0 )) && return 1
  # The caller may already have measured it, and measuring is the expensive
  # part.  Doing it twice to answer one question would be its own small
  # version of the problem this exists to prevent.
  local mb
  if [[ "$measured" =~ ^[0-9]+$ ]]; then mb="$measured"
  else mb=$(history_volume_mb "$dir"); fi
  if (( mb > cap )); then
    # warn, not info: the product runs the scanner at the warn level, and a
    # repository whose history went unread is the kind of thing that must not
    # be discovered from a graph that quietly flattened.
    log_warn "$full_name: history is about ${mb} MB of diff, over secrets.max_history_mb=${cap}; the credential pass will not read it"
    return 0
  fi
  log_debug "$full_name: history is about ${mb} MB of diff, under the ${cap} MB limit"
  return 1
}

# glob -> anchored regex for one path segment.
#
# The code pass hands its list to semgrep and lets semgrep decide what a glob
# means.  There is no engine to hand this one to: the filtering happens after
# both engines have reported, because that is where the cost is.  So the
# meaning is defined here, and it is deliberately the plain reading somebody
# writing the box would expect: a pattern matches if any single segment of the
# path matches it whole.
#
#   result*/   matches  a/result1/b.txt      (the directory, and all under it)
#   *.har      matches  traffic/session.har  (the file)
#   Blueprint/ matches  Blueprint/x/y.json
#
# A trailing slash is stripped rather than honoured, so "coverage" and
# "coverage/" are the same thing.  Somebody writing one and meaning the other
# is not a distinction worth failing on.
_glob_to_regex() {
  local g="${1%/}" out="" i c
  for (( i=0; i<${#g}; i++ )); do
    c="${g:i:1}"
    case "$c" in
      '*') out+='[^/]*' ;;
      '?') out+='[^/]' ;;
      '.'|'+'|'('|')'|'['|']'|'^'|'$'|'{'|'}'|'|'|'\\') out+="\\$c" ;;
      *)   out+="$c" ;;
    esac
  done
  printf '^%s$' "$out"
}

# The configured globs as a JSON array of segment regexes.
_secrets_exclude_regexes() {
  local g out=()
  while IFS= read -r g; do
    [[ -z "$g" ]] && continue
    out+=("$(_glob_to_regex "$g")")
  done < <(cfg_arr '.scan.secrets.exclude_paths')
  printf '%s\n' "${out[@]+"${out[@]}"}" | jq -R . | jq -sc '[ .[] | select(. != "") ]'
}

# Drop findings under an excluded path, before anything expensive touches them.
#
# This sits between normalization and derive_secret_facts on purpose.  Every
# candidate that gets past here is fingerprinted twice, entropy scored, JWT
# decoded and checked against the branch heads, and on a repository of recorded
# test traffic that is tens of thousands of candidates that were never going to
# be a credential.  Dropping them at the engine would have been tidier and is
# not possible: the two engines take different flags and one of them takes
# none, so the honest place is here, where the report is one shape.
#
# What was dropped is written out rather than forgotten, so the scan can say so
# and so the repository gets one finding about it.  A filter nobody can see is
# how a scanner starts quietly missing things.
secrets_drop_excluded() {
  local dropped_out="${1:-/dev/null}"
  # Appended to, never truncated here.  This runs once per engine and per
  # branch pass, five times over for a repository scanned across its history,
  # and truncating at the top meant each pass wiped what the one before it had
  # recorded.  The file then held only whatever the last pass happened to drop,
  # which for a repository whose generated output is all on one earlier pass is
  # nothing at all, and the finding that reports what was skipped said nothing
  # while the filter was busy removing thirty thousand candidates.
  #
  # The one truncation that should happen is per repository, and the caller
  # does it when it makes the file.
  local res; res=$(_secrets_exclude_regexes)
  if [[ -z "$res" || "$res" == "[]" ]]; then cat; return 0; fi

  # One pass, no temporary file.  The obvious shape is to buffer, ask which
  # rows are dropped, then ask which are kept, and that would put every secret
  # in the repository on disk in cleartext for the length of two jq runs.  So
  # the decision is tagged onto each row as it goes past and split downstream,
  # and the values stay in the pipe.  tojson keeps a row on one line whatever
  # is in it, which is what makes the split safe.
  jq -r --argjson res "$res" '
    ((.file // "") | split("/")) as $segs
    | if any($res[]?; . as $re | any($segs[]?; test($re)))
      then "D\t" + (.file // "")
      else "K\t" + tojson
      end' 2>/dev/null \
  | awk -v drop="$dropped_out" -F'\t' '
      $1 == "D" { print substr($0, 3) >> drop; next }
      $1 == "K" { print substr($0, 3) }'
}

# One finding per repository per file type the credential pass skipped.
#
# Not one per file.  A repository of recorded test traffic holds hundreds of
# them, and a finding per file would rebuild the flood this exclusion exists to
# stop, one category down.  A single row saying "forty seven session recordings
# are committed here", with the paths on it, is the actionable version of what
# those thousands of candidates were trying to say.
#
# Medium, and the reason is the interesting part.  Not high, because the pass
# deliberately did not open these files, and claiming a severity about contents
# nobody inspected would be asserting evidence this scan declined to collect.
# Not low, because a session recording holds Authorization headers and cookies
# as they were sent, and low is the band that gets filtered out of every report
# by default, which would leave the reader worse off than the noise did.
secrets_skipped_findings() {
  local dropped="$1" full_name="$2" branch="$3" web="${4:-https://github.com}"
  [[ -s "$dropped" ]] || { echo '[]'; return 0; }

  # Grouped by extension, falling back to the top directory for paths with no
  # extension, because "what kind of thing was skipped" is the question a
  # reader has and a list of four hundred paths is not an answer to it.
  sort -u "$dropped" \
  | jq -R -s -c \
      --arg repo "$full_name" --arg br "$branch" --arg web "$web" \
      --argjson link "$(provider_link_parts)" \
      --arg org "${full_name%%/*}" '
    def kind:
      if test("\\.[A-Za-z0-9]+$") then (capture("\\.(?<e>[A-Za-z0-9]+)$").e | ascii_downcase)
      else (split("/") | .[0]) end;
    # How to name the group in a sentence.  An extension reads as ".har file";
    # a directory does not, and ".Blueprint file" is the sort of wording that
    # makes a reader distrust the rest of the report.
    def phrase: if test("\\.[A-Za-z0-9]+$") then "." + kind + " file(s)" else "file(s) under " + kind + "/" end;
    split("\n") | map(select(length > 0))
    | group_by(kind)
    | map({
        organization: $org,
        repository: $repo,
        branch: $br,
        file: (.[0]),
        start_line: 0,
        category: "misconfiguration",
        finding_type: "skipped_by_credential_scan",
        rule_id: ("GCR-SECRETS-SKIPPED-" + (.[0] | kind | ascii_upcase)),
        rule_name: ("committed " + (.[0] | phrase)),
        severity: "medium",
        severity_reason:
          ("a file type that routinely carries credentials is committed here, "
           + "and the credential pass is configured to skip it, so nothing "
           + "has read what is inside"),
        title: ((length | tostring) + " " + (.[0] | phrase)
                + " committed, not read by the credential pass"),
        description:
          ("The credential pass skipped " + (length | tostring) + " "
           + (.[0] | phrase) + " in this repository because the skip "
           + "list covers them.  Recorded traffic and archives are excluded "
           + "by default: a single one can hold tens of thousands of "
           + "candidate values, none of which a person can act on, and "
           + "reading them is what stops a scan finishing.  That is a "
           + "reasonable trade and it is not free, so it is reported rather "
           + "than done quietly.  If these files should not be in version "
           + "control, remove them.  If they should, and you want them read, "
           + "take the pattern out of Skip these paths under Credentials."),
        remediation:
          ("Remove the files from version control, or narrow the skip list "
           + "under Settings, Credentials, Skip these paths."),
        paths: (.[0:50]),
        occurrences: length,
        triage: "review",
        url: ($web + "/" + $repo + "/" + $link.blob + "/" + $br + "/" + .[0])
      })
  ' || {
    log_warn "$full_name: could not build the skipped-file finding, so this run does not say what the credential pass left out"
    echo '[]'
  }
}

# The lengths a hash comes out at, in hex characters: MD5, SHA1, SHA224,
# SHA256, SHA384, SHA512.  Nothing else is treated as a digest length, because
# the whole argument below rests on the value being exactly one hash long.
_DIGEST_LENGTHS=" 32 40 56 64 96 128 "

# How much of a file is read looking for the other hashes in it.  A generated
# report is one enormous line and the answer is in the first few hundred
# kilobytes of it; reading the whole of a 40MB artifact to count past eight
# would be work spent confirming something already known.
_DIGEST_SCAN_BYTES=4000000

# _digest_siblings <dir> <file> <length> [commit] -> how many distinct hex
# strings of exactly that length are in that file.
#
# This is the question that makes the check safe.  A Datadog API key is 32 hex
# characters and a Git Code Review scan must keep reporting one; an Allure test
# id is also 32 hex characters and there are four hundred of them in one
# generated file.  One value of a shape is a credential.  Four hundred of the
# same shape in one file is content addressing.
#
# Word boundaries on purpose: without them every 64 character hash counts twice
# as a pair of 32s, and the count stops meaning what it says.
# The file is read out of the history when it is not in the working tree, which
# is the common case rather than the edge one: most of what a credential pass
# finds is back in the history, and a generated report is replaced by the next
# run, so the version that carried the value is often the only version that ever
# had it.  Without this the check would miss exactly the findings it was written
# for.
_digest_siblings() {
  local dir="$1" file="$2" len="$3" commit="${4:-}"
  [[ -n "$dir" && -n "$file" ]] || { printf '0'; return 0; }

  local body=""
  if [[ -f "$dir/$file" ]]; then
    body=$(head -c "$_DIGEST_SCAN_BYTES" -- "$dir/$file" 2>/dev/null)
  elif [[ -n "$commit" ]]; then
    body=$(git -C "$dir" show "$commit:$file" 2>/dev/null \
           | head -c "$_DIGEST_SCAN_BYTES")
  fi
  # No opinion where the file cannot be read at all.  Zero siblings leaves the
  # candidate where it was, which is reported.
  [[ -n "$body" ]] || { printf '0'; return 0; }

  printf '%s' "$body" \
    | grep -oE "\b[0-9a-fA-F]{$len}\b" 2>/dev/null \
    | sort -u | wc -l | tr -d ' '
}

# Whether the "value" is really the next JSON object key.
#
# gitleaks' generic-api-key takes a comma as an assignment, which is right for
# put("X-API-KEY", "abc...").  It is wrong for a JSON map whose previous value
# happens to end in a keyword.  An Allure report holds
#
#     "...Equipment Alerts vs API","xanR2Klhtr6ujyX7NL0ir":"Create Geofence"
#
# and the rule read API = xanR2Klhtr6ujyX7NL0ir, a test id, as a critical
# credential.  Two things have to hold.  The match is keyword, quote, comma,
# quote, value, quote.  And every place that exact match sits on its line, a
# colon comes next, so the value is a name in an object and not something
# assigned.  put("API_KEY", "abc") never has a colon after it, so it is still
# reported.  A line nobody can read decides nothing.
_object_key_neighbor() {
  local dir="$1" file="$2" commit="$3" lineno="$4" match="$5"
  [[ -n "$dir" && -n "$file" && -n "$match" && "$lineno" =~ ^[1-9][0-9]*$ ]] \
    || { printf 'false'; return 0; }

  local text=""
  if [[ -n "$commit" ]]; then
    text=$(git -C "$dir" show "$commit:$file" 2>/dev/null \
           | sed -n "${lineno}{p;q}" | head -c "$_DIGEST_SCAN_BYTES")
  elif [[ -f "$dir/$file" ]]; then
    text=$(sed -n "${lineno}{p;q}" -- "$dir/$file" 2>/dev/null \
           | head -c "$_DIGEST_SCAN_BYTES")
  fi
  [[ -n "$text" && "$text" == *"$match"* ]] || { printf 'false'; return 0; }

  local rest="$text" after
  while [[ "$rest" == *"$match"* ]]; do
    rest="${rest#*"$match"}"
    after="${rest#"${rest%%[![:space:]]*}"}"
    [[ "$after" == :* ]] || { printf 'false'; return 0; }
  done
  printf 'true'
}

# Where a Mule secure properties key is written down in the repository, if
# anywhere.
#
# A Mule value written ![base64] is ciphertext.  The app decrypts it at start
# up with a key it is handed at run time, usually -Dmule.key.  Without that key
# the value opens nothing, which is why triage can grade it info.  With it, the
# value is as good as plain text.  So before a ciphertext is lowered, look for
# the key in the places Mule projects tend to commit it:
#
#   mule.key=..., secure.key: ..., <mule.key>...</mule.key>, -Dmule.key=...
#   <secure-properties:config ... key="...">  (the key itself, not ${...})
#
# The name is the project's own choice.  One real project reads its key from
# ${decryption.key}, so the names in key="${...}" are read out of the config
# and looked for as well as the usual ones.
#
# A reference to a variable is not a key, so values starting with $, %, {, <,
# # or * do not count.  The branch heads are read, and the history of the usual
# config file types, because a key that was committed and then taken out still
# opens every value encrypted with it.
#
# Prints "checked<TAB>where".  where is empty when nothing was found.  Prints
# nothing at all when there is no clone to read, which is not the same answer.
_MULE_KEY_NAMES="(mule|secure|encrypt|encryption|decrypt|decryption|secure[._-]properties)[._-]?key"
_MULE_KEY_VALUE="[\"']?[[:space:]]*(=|:|>)[[:space:]]*[\"']?[^\"'\$%{<#*[:space:]]{4,}"
_MULE_KEY_ATTR_RE="[[:space:]]key[[:space:]]*=[[:space:]]*\"[^\"\$#{%][^\"]{3,}\""
# YAML nests its names, so decryption: then key: on the next line never reads
# as decryption.key to a line search.  This prints each scalar as its dotted
# path, name=value, which the key pattern can then read.  Lists and block
# scalars are skipped; a key is never written as either.
_yaml_dotted() {
  awk '
    /^[[:space:]]*(#|$)/ { next }
    {
      match($0, /^ */); ind = RLENGTH; line = substr($0, ind + 1)
      if (line !~ /^[A-Za-z0-9_.-]+[[:space:]]*:/) next
      k = line; sub(/[[:space:]]*:.*/, "", k)
      v = line; sub(/^[^:]*:[[:space:]]*/, "", v)
      while (n > 0 && ind <= at[n]) n--
      n++; at[n] = ind; name[n] = k
      if (v == "" || v ~ /^[|>]/) next
      path = name[1]; for (i = 2; i <= n; i++) path = path "." name[i]
      print path "=" v
    }'
}

_mule_key_location() {
  local dir="$1"; shift
  [[ -n "$dir" ]] && git -C "$dir" rev-parse --git-dir >/dev/null 2>&1 \
    || return 0
  local -a refs=("$@")
  (( ${#refs[@]} == 0 )) && refs=(HEAD)
  (( ${#refs[@]} > 200 )) && refs=("${refs[@]:0:200}")

  # The names this project's configs read the key from, as regex text.
  local names re
  names=$(git -C "$dir" grep -h -o -i -E 'key[[:space:]]*=[[:space:]]*"\$\{[A-Za-z0-9._-]+\}"' \
            "${refs[@]}" -- '*.xml' 2>/dev/null \
          | sed -E 's/.*\$\{([^}]+)\}.*/\1/' | sort -u | head -20 \
          | sed 's/[.]/[.]/g' | paste -sd'|' -) || true
  re="(${_MULE_KEY_NAMES}${names:+|$names})${_MULE_KEY_VALUE}"

  local hit ref
  # git grep -l prints ref:path.  The ref is cut off by name rather than at
  # the first colon, since a branch name can hold one.
  hit=$(git -C "$dir" grep -l -I -i -E -e "$re" "${refs[@]}" -- \
          2>/dev/null | head -1) || true
  if [[ -n "$hit" ]]; then
    for ref in "${refs[@]}"; do
      [[ "$hit" == "$ref:"* ]] && { hit="${hit#"$ref:"}"; break; }
    done
    printf 'checked\t%s' "$hit"; return 0
  fi

  # The config element spans lines more often than not, so it is read whole.
  local f block
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    block=$(git -C "$dir" show "$f" 2>/dev/null | head -c "$_DIGEST_SCAN_BYTES" \
            | tr '\n' ' ' | grep -oiE '<secure-properties:config[^>]*>') || true
    if [[ -n "$block" ]] && grep -qE -e "$_MULE_KEY_ATTR_RE" <<<"$block"; then
      for ref in "${refs[@]}"; do
        [[ "$f" == "$ref:"* ]] && { f="${f#"$ref:"}"; break; }
      done
      printf 'checked\t%s' "$f"; return 0
    fi
  done < <(git -C "$dir" grep -l -i -F -e 'secure-properties:config' \
             "${refs[@]}" -- '*.xml' 2>/dev/null | head -50)

  # Nested YAML, at the heads.  Only files with a key: line are read.
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if git -C "$dir" show "$f" 2>/dev/null | head -c "$_DIGEST_SCAN_BYTES" \
         | _yaml_dotted | grep -qiE -e "$re"; then
      for ref in "${refs[@]}"; do
        [[ "$f" == "$ref:"* ]] && { f="${f#"$ref:"}"; break; }
      done
      printf 'checked\t%s' "$f"; return 0
    fi
  done < <(git -C "$dir" grep -l -i -E -e '^[[:space:]]*key[[:space:]]*:' \
             "${refs[@]}" -- '*.yaml' '*.yml' 2>/dev/null | head -200)

  # Nested YAML in the history: every version of a file whose diff touched a
  # key: line, newest first, read whole.
  local sha path
  while IFS=$'\t' read -r sha path; do
    [[ -n "$sha" && -n "$path" ]] || continue
    if git -C "$dir" show "$sha:$path" 2>/dev/null | head -c "$_DIGEST_SCAN_BYTES" \
         | _yaml_dotted | grep -qiE -e "$re"; then
      printf 'checked\t%s in commit %s' "$path" "$sha"; return 0
    fi
  done < <(git -C "$dir" log --all -i -E -G '^[[:space:]]*key[[:space:]]*:' \
             --format='C %h' --name-only -- '*.yaml' '*.yml' 2>/dev/null \
           | awk '/^C / { sha = $2; next } NF { print sha "\t" $0 }' | head -300)

  # Taken out since is still committed.  -G reads added and removed lines.
  hit=$(git -C "$dir" log --all -i -E -G "$re" --format='%h' \
          --name-only -1 -- '*.properties' '*.yaml' '*.yml' '*.xml' '*.json' \
          '*.sh' '*.cmd' '*.bat' '*.env' '*.conf' '*.cfg' '*.launch' \
          '*Jenkinsfile*' '*Dockerfile*' '*.groovy' 2>/dev/null \
        | awk 'NF { if (!sha) sha = $0; else if (!path) path = $0 }
               END { if (path) print path " in commit " sha }') || true
  printf 'checked\t%s' "$hit"
}

# Whether the value is a Mule identifier rather than a credential.
#
# trufflehog's Anypoint detector takes any UUID near the words anypoint and org
# as a client id and org id.  Mule projects are full of UUIDs that are neither:
#
#   doc_id         Studio writes doc:id="<uuid>" on every element of a flow.
#                  One restart flow came up as 18 critical credentials.
#   anypoint_path  .../organizations/<uuid>/environments/<uuid> in an Anypoint
#                  URL.  Those name an org and an environment, and they are in
#                  every Anypoint address anybody copies.
#
# The rule is strict: every place the value sits in the file, it is wholly one
# of these.  The same UUID anywhere else, as a client_id say, keeps it
# reported.  Prints the kind, or nothing.  A file nobody can read decides
# nothing.
_mule_identifier() {
  local dir="$1" file="$2" commit="$3" secret="$4"
  [[ -n "$dir" && -n "$file" && -n "$secret" ]] || return 0

  local body=""
  if [[ -n "$commit" ]]; then
    body=$(git -C "$dir" show "$commit:$file" 2>/dev/null | head -c "$_DIGEST_SCAN_BYTES")
  elif [[ -f "$dir/$file" ]]; then
    body=$(head -c "$_DIGEST_SCAN_BYTES" -- "$dir/$file" 2>/dev/null)
  fi
  [[ -n "$body" && "$body" == *"$secret"* ]] || return 0

  _count(){ grep -oF -e "$1" <<<"$body" | wc -l | tr -d ' '; }
  local all docs paths
  all=$(_count "$secret")
  docs=$(( $(_count "doc:id=\"$secret\"") + $(_count "doc:id='$secret'") ))
  paths=$(( $(_count "/organizations/$secret") + $(_count "/environments/$secret") ))
  (( all > 0 && docs + paths == all )) || return 0
  if (( docs >= paths )); then printf 'doc_id'; else printf 'anypoint_path'; fi
}

derive_secret_facts() {
  local dir="${1:-}"
  local pre suf maxmask pp
  pre=$(cfg_num '.redaction.prefix_chars' 4)
  suf=$(cfg_num '.redaction.suffix_chars' 3)
  maxmask=$(cfg_num '.redaction.max_mask_chars' 12)
  pp=$(cfg_json '.scan.secrets.triage.placeholder_patterns // []')

  # The branch set is the same for every finding in this repository, so build
  # it once.  It used to be rebuilt with two jq calls inside the loop, which on
  # a repository with hundreds of candidates is hundreds of processes spent
  # parsing a value that never changed.
  local -a allbr=()
  while IFS= read -r _b; do [[ -n "$_b" ]] && allbr+=("$_b"); done \
    < <(printf '%s' "${GHSCAN_BRANCH_SET_HEADS:-${GHSCAN_BRANCH_SET:-[]}}" \
        | jq -r '.[]?' 2>/dev/null)

  # Buffered so the live-at-head question can be asked once for every secret
  # rather than once per secret.  In this directory, which is shared memory and
  # goes with the run: the value is already here in raw_findings, so nothing
  # reaches a disk that was not there before.
  local buffered
  buffered=$(tmp_file secretsin)
  cat > "$buffered"

  if [[ -n "$dir" ]] && (( ${#allbr[@]} > 0 )); then
    local patterns
    patterns=$(tmp_file secretpat)
    # Single line values only.  A PEM body is one secret spanning many lines,
    # and a patterns file is line oriented: writing one in would turn it into a
    # dozen separate patterns that match fragments of a key.  Multi line values
    # keep the per secret path below, which is what they had before.
    jq -r 'select(._secret != null and (._secret | contains("\n") | not))
           | ._secret' "$buffered" 2>/dev/null | sort -u > "$patterns"
    _prime_live_heads "$dir" "$patterns" "${allbr[@]}"
    rm -f "$patterns"
  fi

  # Asked once per repository, and only when there is a Mule ciphertext to ask
  # it for.  Unchecked and checked-but-empty are kept apart: only the second
  # one is a reason to lower anything.
  local mule_checked=false mule_key=""
  if jq -e -s 'any(.[]; (._secret // "") | startswith("![") )' "$buffered" \
       >/dev/null 2>&1; then
    local mule_answer
    mule_answer=$(_mule_key_location "$dir" "${allbr[@]+"${allbr[@]}"}")
    if [[ "$mule_answer" == checked$'\t'* ]]; then
      mule_checked=true
      mule_key="${mule_answer#checked$'\t'}"
    fi
  fi

  # Opened and unlinked, same as the rest: the loop reads a descriptor and the
  # name is already gone, so there is no window where this sits in the temp
  # root holding every secret in the repository.
  local bfd
  exec {bfd}< "$buffered"; rm -f "$buffered"

  # Asked once.  This is the run's clock, not the finding's, and it was being
  # forked per finding to answer the same question every time.
  local now_epoch; now_epoch=$(date -u +%s)

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
    if [[ -n "$dir" ]] && (( ${#allbr[@]} > 0 )); then
      live=$(_live_at_head "$dir" "$secret" "${allbr[@]}")
    fi

    # Whether this is a hash of something rather than a credential.
    #
    # A detector that matches "thirty two alphanumeric characters near the word
    # box" matches an MD5 too, and a generated test report is full of them: one
    # Cypress run published into a repository produced a critical credential
    # finding on an Allure test id, because the word box appears in a test name
    # in the same file.  Nothing about the value's length or entropy can tell
    # those apart, and entropy is the only evidence the rest of this pass has.
    #
    # Two facts are recorded and neither is a judgment, which triage makes: the
    # value is exactly one hash long and bare hex, and this is how many other
    # strings of that exact shape sit in the same file.  A real credential that
    # happens to be hex is one of one.
    local digest_shaped=false digest_siblings=0
    if [[ "$secret" =~ ^[0-9a-fA-F]+$ && "$_DIGEST_LENGTHS" == *" $slen "* ]]; then
      digest_shaped=true
      digest_siblings=$(_digest_siblings "$dir" \
        "$(printf '%s' "$line" | jq -r '.file // ""')" "$slen" \
        "$(printf '%s' "$line" | jq -r '.commit // ""')")
    fi

    # Only a comma shaped match is worth reading the file for.  Quotes may be
    # plain or single, and the value has to be the last thing matched.
    local object_key=false match
    match=$(printf '%s' "$line" | jq -r '._match // ""')
    if [[ -n "$match" ]] \
       && printf '%s' "$line" | jq -e --arg m "$match" --arg s "$secret" '
            ([39] | implode) as $sq
            | ($m | endswith($s + "\"") or endswith($s + $sq))
              and ($m | rtrimstr($s + "\"") | rtrimstr($s + $sq)
                      | test("[\"\u0027]\\s*,\\s*[\"\u0027]$"))' >/dev/null 2>&1; then
      object_key=$(_object_key_neighbor "$dir" \
        "$(printf '%s' "$line" | jq -r '.file // ""')" \
        "$(printf '%s' "$line" | jq -r '.commit // ""')" \
        "$(printf '%s' "$line" | jq -r '.start_line // 0')" "$match")
    fi

    local mule_id
    mule_id=$(_mule_identifier "$dir" \
      "$(printf '%s' "$line" | jq -r '.file // ""')" \
      "$(printf '%s' "$line" | jq -r '.commit // ""')" "$secret")

    printf '%s' "$line" | jq -c \
      --arg fp "$fp" --arg merge "$merge" --arg redacted "$redacted" \
      --argjson slen "$slen" --argjson pp "$pp" --argjson live "$live" \
      --argjson dshape "$digest_shaped" --argjson dsibs "${digest_siblings:-0}" \
      --argjson objkey "$object_key" --arg muleid "$mule_id" \
      --argjson mulechecked "$mule_checked" --arg mulekey "$mule_key" \
      --argjson now "$now_epoch" --argjson idc "$JWT_IDENTITY_CLAIMS" \
      --argjson prc "$JWT_PRIVILEGE_CLAIMS" '
      # A JSON web token is not opaque.  Two of its three parts are base64 of
      # plain JSON and anybody holding the token can read them without the
      # key, which is the whole reason a leaked one matters more than a
      # random high entropy string: the value says who it is for, what it
      # lets its holder do, and when it stopped working.
      #
      # Reading it is the difference between "a long string that looks like a
      # credential" and a fact.  A value the detector called a token that does
      # not decode is not a token, and an expiry in the past is the rare piece
      # of positive evidence that a finding is less dangerous than it looks
      # rather than merely unproven.
      #
      # Only the parts that are not themselves identifying come out of here.
      # The issuer, the audience, the algorithm and the two timestamps get
      # kept because they say which system this belongs to; the claim values
      # do not, because a token carrying one
      # of those must not be answered by writing that value into a second
      # system.  The
      # names of the claims are enough to say what was in it.
      def b64pad: . + ("=" * ((4 - (length % 4)) % 4));
      def unurl: gsub("-"; "+") | gsub("_"; "/");
      def jpart($i):
        (split(".")) as $p
        | if ($p | length) < 3 then null
          else (try ($p[$i] | unurl | b64pad | @base64d | fromjson) catch null)
          end;
      def isoish($t):
        if ($t | type) == "number" then ($t | todate) else null end;
      # How long a signature is, in base64url characters, for the algorithms
      # that fix its length.  RSA at 256 bits of hash signs with the whole
      # modulus, so RS256 is 256 bytes and 342 characters; HS256 is a 32 byte
      # MAC and 43.  Nothing else is a signature those algorithms produced.
      def sig_chars($alg):
        {"HS256": 43, "HS384": 64, "HS512": 86,
         "RS256": 342, "RS384": 512, "RS512": 683,
         "PS256": 342, "PS384": 512, "PS512": 683,
         "ES256": 86, "ES384": 128, "ES512": 176}
        | .[$alg | ascii_upcase];
      def jwt_facts:
        . as $s
        | ($s | jpart(0)) as $h
        | ($s | jpart(1)) as $b
        | if ($h | type) != "object" or ($b | type) != "object"
             or ($h | has("alg") | not)
          then {jwt: false}
          else
            ($b | keys) as $names
            | ($s | split(".")) as $parts
            | (($parts[2] // "") | sub("=+$"; "")) as $sig
            | (($h.alg // "") | tostring) as $alg
            | (if ($parts | length) == 3 then sig_chars($alg) else null end) as $want
            | {
                jwt: true,
                jwt_alg: ($h.alg // "" | tostring),
                jwt_issuer: ($b.iss // "" | tostring),
                jwt_audience:
                  (if ($b.aud | type) == "array" then ($b.aud | map(tostring) | join(", "))
                   else ($b.aud // "" | tostring) end),
                jwt_issued_at: isoish($b.iat),
                jwt_expires_at: isoish($b.exp),
                # Null rather than false where there is no expiry, because a
                # token that never expires is not the same as one that has not
                # expired yet, and it is the more alarming of the two.
                jwt_expired:
                  (if ($b.exp | type) == "number" then ($b.exp < $now) else null end),
                jwt_claims: $names,
                # Whether anybody could present this.  A signature that is
                # empty, that is not base64url, or that is the wrong length for
                # the algorithm the header itself names was not produced by
                # signing anything, so the value is the shape of a token
                # rather than a token.  A stub written into a fixture or a
                # README reads exactly like this and a real one never does.
                #
                # Said as a fact here and judged in triage, the same as every
                # other placeholder signal, so it lands in the filtered list
                # with a reason rather than disappearing.
                jwt_signature_stub:
                  (($alg | ascii_downcase) == "none"
                   or ($sig | length) == 0
                   or ($sig | test("[^A-Za-z0-9_-]"))
                   or (if $want == null then false
                       else ($sig | length) != $want end)),
                # A claim is identifying either because of what it is called or
                # because its value is plainly an address, whatever it is
                # called.  Both happen.
                jwt_identity_claims:
                  ([ $names[]
                     | select((. | ascii_downcase) as $n
                              | any($idc[]?; . == $n)
                                or (($b[$n] | tostring) | test("[^@[:space:]]+@[^@[:space:]]+\\.")))
                   ] | unique),
                jwt_privilege_claims:
                  ([ $names[]
                     | select((. | ascii_downcase) as $n | any($prc[]?; . == $n))
                   ] | unique)
              }
          end;
      # A public key is long, base64 and random, which is everything a generic
      # secret rule looks for, and it is meant to be handed out.  A trust store
      # of npm registry signing keys was coming up critical for exactly that.
      #
      # Every key of a given type and size starts with the same header bytes and
      # comes out the same length, so the header and the length together say
      # what it is.  The private forms start with a version number instead and
      # never share these headers.  Armor around it is allowed, a private one
      # is not.
      def spki_types:
        [["P-256", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE", 124],
         ["P-384", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE", 160],
         ["P-521", "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ", 212],
         ["secp256k1", "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE", 120],
         ["Ed25519", "MCowBQYDK2VwAyEA", 60],
         ["Ed448", "MEMwBQYDK2VxAzoA", 92],
         ["X25519", "MCowBQYDK2VuAyEA", 60],
         ["X448", "MEIwBQYDK2VvAzkA", 92],
         ["RSA 1024", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ", 216],
         ["RSA 2048", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 392],
         ["RSA 3072", "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA", 564],
         ["RSA 4096", "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA", 736]];
      def public_key_type:
        if test("PRIVATE") then ""
        else
          (gsub("-----(BEGIN|END) PUBLIC KEY-----"; "") | gsub("[[:space:]]"; "")) as $b
          | if ($b | test("^[A-Za-z0-9+/]+={0,2}$") | not) then ""
            else (first(spki_types[]
                        | select(. as $t | ($b | startswith($t[1]))
                                           and ($b | length) == $t[2])
                        | .[0]) // "")
            end
        end;
      # A login written into an address for the reader to fill in.  A comment
      # saying the token goes in user:token@host as the password came up critical,
      # because the URI detector reports the whole address and nothing in it
      # reads as a placeholder until it is taken apart.  So the password and
      # the host are judged on their own: a stand-in word, a variable, or a
      # host that is a word rather than a machine.  localhost is left out on
      # purpose, since a real password to a local database is still one.
      def url_stand_in($pp):
        # Collected into an array on purpose.  capture with no match yields
        # nothing at all, and nothing here would drop the whole finding.
        (try ([capture("^[A-Za-z][A-Za-z0-9+.-]*://(?<u>[^:/@\\s]*):(?<p>[^@\\s]*)@(?<h>[^/:?#\\s]+)")][0])
         catch null) as $u
        | if $u == null then false
          else ($u.p) as $p | ($u.h | ascii_downcase) as $h
            | $p == ""
              or ($p | test("^(password|passwd|pass|pwd|secret|token|apikey|api_key|key|changeme|change_me|placeholder|example|sample|dummy|test|admin|root|user|username|hunter2|letmein|_+token_+)$"; "i"))
              or ($p | test("^[$%<{\\[]|\\$\\{|\\{\\{"))
              or ($p | test("^(x+|\\*+|\\.+|0+)$"; "i"))
              or any($pp[]?; . as $re | $p | test($re))
              or ($h | test("^(host|hostname|your[-_]?host|my[-_]?host|server|domain|example)$|(^|\\.)example\\.(com|org|net)$|\\.(example|invalid|test)$"))
          end;
      # A Mule secure properties value: ![base64 ciphertext].  Blowfish and AES
      # both work in 8 byte blocks (AES in two of them), so the body decodes to
      # a whole number of blocks.  A 32 character client secret comes out at
      # 40 bytes and a 40 character AWS secret key at 48, which is the padding
      # doing its job.  Ciphertext also decodes to bytes nobody can read, while
      # a secret that was only base64 encoded decodes to plain text and must
      # stay a credential.  Collected into an array so no match is false, not
      # nothing.
      def mule_ciphertext:
        ([capture("^!\\[(?<b>[A-Za-z0-9+/]+={0,2})\\]$")][0].b) as $b
        | if $b == null or (($b | length) % 4) != 0 then false
          else (($b | length) / 4 * 3 - ($b | sub("^[^=]*"; "") | length)) as $n
            | $n >= 8 and ($n % 8) == 0
              and ((try ($b | @base64d | explode | any(. < 32 or . > 126))
                    catch false))
          end;
      def shannon:
        (explode) as $c
        | ($c | length) as $n
        | if $n == 0 then 0
          else ($c | group_by(.) | map(length / $n) | map(-(. * log2)) | add)
          end;
      (._secret // "") as $s
      | ($s | mule_ciphertext) as $mule
      | ($s | public_key_type) as $pk
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
            (($s | explode | unique | length) <= 4 and ($s | length) >= 8),
          # Bare hex, exactly one hash long, and how many others of that shape
          # share the file.  Facts, not a verdict: triage decides what a value
          # surrounded by four hundred of its own shape is.
          digest_shaped: $dshape,
          digest_siblings: $dsibs,
          # Which kind of public key, or empty.  Said here, judged in triage.
          public_key: ($pk != ""),
          public_key_type: $pk,
          url_stand_in: ($s | url_stand_in($pp)),
          # The value is the next key in a JSON object.  See _object_key_neighbor.
          object_key: $objkey,
          # A Mule element id or Anypoint path id.  See _mule_identifier.
          mule_identifier: $muleid,
          # Ciphertext, and whether the key that opens it was looked for and
          # where it turned up.  Said here, graded in ingest.
          mule_ciphertext: $mule,
          mule_key_checked: ($mule and $mulechecked),
          mule_key_location: (if $mule then $mulekey else "" end)
        }
      + ($s | jwt_facts)
      | del(._secret)
      | del(._match)'
  done <&${bfd}
  exec {bfd}<&-
}

# Engine: gitleaks
_gitleaks_subcommand() {
  # gitleaks >= 8.19 prefers `git`; older releases only have `detect`.
  if gitleaks git --help >/dev/null 2>&1; then echo "git"; else echo "detect"; fi
}

# An engine that died is not an engine that found nothing.
#
# Every one of these writes an empty report when it fails, because the pass has
# to carry on and report what the other engines did find.  That is right.  What
# was missing is any record that it happened, so an empty report from a killed
# engine reached the reader as "this repository is clean now" and every finding
# that engine used to report was closed as fixed.  One repository lost one
# thousand seven hundred and forty three credentials that way, in one pass, on
# a history nobody had actually read.
#
# So a death is written down here, the pass is not declared complete, and the
# reader holds those findings open instead.  Absence of evidence, again.
secrets_engine_died() {
  local engine="$1" rc="$2" full_name="$3" logf="${4:-}"
  local why
  if (( rc > 128 )); then
    why="$engine was stopped by signal $(( rc - 128 ))"
  else
    why="$engine exited $rc"
  fi
  if [[ -n "$logf" && -s "$logf" ]]; then
    # Six hundred rather than two hundred.  These engines report in JSON, and
    # two hundred characters cut the one that mattered off mid sentence: the
    # log said "failed to read index file: open /var/tmp/gcr-w" and stopped,
    # which named the problem and hid which file and why.
    why="$why: $(tail -2 "$logf" | tr '\n' ' ' | cut -c1-600)"
  fi
  SECRETS_PASS_INCOMPLETE="${SECRETS_PASS_INCOMPLETE:+$SECRETS_PASS_INCOMPLETE; }$why"
  log_warn "[$full_name] $why, so the credential pass is not complete"
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
  # --exit-code 0 above means a leak found is not a failure, so anything
  # non-zero here is the engine going wrong rather than the repository being
  # dirty.  A signal shows up as 128 plus the number.
  local rc=0
  gitleaks "${args[@]}" >"$GHSCAN_TMPROOT/gitleaks.log" 2>&1 || rc=$?
  (( rc == 0 )) || secrets_engine_died gitleaks "$rc" "$full_name" \
    "$GHSCAN_TMPROOT/gitleaks.log"
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
  # The gate wants one branch's commits, not every branch the clone has.
  [[ -n "${GHSCAN_TH_BRANCH:-}" ]] && args+=(--branch "$GHSCAN_TH_BRANCH")
  if cfg_bool '.scan.secrets.trufflehog.verify' true; then
    local res; res=$(cfg '.scan.secrets.trufflehog.results' 'verified,unverified,unknown')
    args+=(--results "$res")
  else
    # Without verification every result is "unverified"; asking for anything
    # narrower would silently return nothing.
    args+=(--no-verification)
  fi

  # The size ceiling, on the one thing this engine lets us bound.
  #
  # gitleaks takes a per file limit and this does not, but the files that hurt
  # are archives: a recorded traffic capture is a zip, and a zip is
  # decompressed before it is read.  Seventy four megabytes on disk became
  # gigabytes in memory and took a worker to ninety three gigabytes before the
  # kernel killed it, on a repository of twenty four commits whose whole
  # history measures thirty six megabytes.  History size was never the signal.
  local arch; arch=$(cfg_num '.scan.secrets.trufflehog.archive_max_mb' 0)
  (( arch > 0 )) && args+=(--archive-max-size "${arch}MB")
  local conc; conc=$(cfg_num '.scan.secrets.trufflehog.concurrency' 8)
  args+=(--concurrency "$conc")

  local d
  while IFS= read -r d; do [[ -n "$d" ]] && args+=(--include-detectors "$d"); done \
    < <(cfg_arr '.scan.secrets.trufflehog.include_detectors')
  while IFS= read -r d; do [[ -n "$d" ]] && args+=(--exclude-detectors "$d"); done \
    < <(cfg_arr '.scan.secrets.trufflehog.exclude_detectors')

  log_debug "$full_name: trufflehog ${args[*]}"
  # The status that matters is the engine's, not grep's, and grep matching
  # nothing is an ordinary quiet repository.  A pipeline reports the wrong one
  # and `|| true` throws away even that, so the engine writes its own.
  # In the root itself, not through tmp_file: that calls tmp_init, and in a
  # command substitution tmp_init runs in a subshell, so the root it creates
  # belongs to a shell that exits at once and the trap that would remove it
  # never runs.  A directory of cleartext credentials stays behind per call.
  local rcfile="$GHSCAN_TMPROOT/trufflehog.rc"; : > "$rcfile"
  { trufflehog "${args[@]}" 2>"$GHSCAN_TMPROOT/trufflehog.log" \
      || printf '%s' "$?" > "$rcfile"; } | grep -E '^\{' > "$out" || true
  [[ -f "$out" ]] || : > "$out"
  if [[ -s "$rcfile" ]]; then
    secrets_engine_died trufflehog "$(cat "$rcfile")" "$full_name" \
      "$GHSCAN_TMPROOT/trufflehog.log"
  fi
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

  local rc=0
  gitleaks "${args[@]}" >"$GHSCAN_TMPROOT/gitleaks.log" 2>&1 || rc=$?
  (( rc == 0 )) || secrets_engine_died gitleaks "$rc" "$full_name" \
    "$GHSCAN_TMPROOT/gitleaks.log"
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
  # The size ceiling, on the one thing this engine lets us bound.
  #
  # gitleaks takes a per file limit and this does not, but the files that hurt
  # are archives: a recorded traffic capture is a zip, and a zip is
  # decompressed before it is read.  Seventy four megabytes on disk became
  # gigabytes in memory and took a worker to ninety three gigabytes before the
  # kernel killed it, on a repository of twenty four commits whose whole
  # history measures thirty six megabytes.  History size was never the signal.
  local arch; arch=$(cfg_num '.scan.secrets.trufflehog.archive_max_mb' 0)
  (( arch > 0 )) && args+=(--archive-max-size "${arch}MB")
  args+=(--concurrency "$(cfg_num '.scan.secrets.trufflehog.concurrency' 8)")
  local rcfile="$GHSCAN_TMPROOT/trufflehog.rc"; : > "$rcfile"
  { trufflehog "${args[@]}" 2>"$GHSCAN_TMPROOT/trufflehog.log" \
      || printf '%s' "$?" > "$rcfile"; } | grep -E '^\{' > "$out" || true
  [[ -f "$out" ]] || : > "$out"
  if [[ -s "$rcfile" ]]; then
    secrets_engine_died trufflehog "$(cat "$rcfile")" "$full_name" \
      "$GHSCAN_TMPROOT/trufflehog.log"
  fi
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
      _secret: (.Secret // .Match // ""),
      # What the rule actually matched around the value.  It holds the value
      # too, so it goes the same way _secret does, in derive_secret_facts.
      _match: (.Match // "")
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

# semgrep_secrets_route <dir> <full_name> <semgrep_json> <repo_json>
#
# semgrep's secret detectors, moved to the credential pass.  See
# semgrep_secrets.py for why.  The value goes from the file into
# derive_secret_facts through a pipe and nowhere else.
#
# Everything here fails toward leaving the report as it was: if any step does
# not finish, semgrep's matches stay code findings, which is how they were
# always filed.  Only matches that became credentials are taken out of the
# code report, so nothing is moved into silence.
semgrep_secrets_route() {
  local dir="$1" full_name="$2" sg="$3" repo_json="$4"
  local py; py=$(ghscan_python)
  [[ -n "$py" && -s "$sg" ]] || return 0
  jq -e '[.results[]? | select(.check_id | startswith("generic.secrets."))] | length > 0' "$sg" >/dev/null 2>&1 \
    || return 0

  local cand; cand=$(tmp_file semgrep_creds)
  # One spelling across engines, the same canon the code pass uses, so a
  # detector override and the old code row's rule both line up.
  "$py" "$GHSCAN_HOME/lib/semgrep_secrets.py" --extract "$sg" "$dir" 2>/dev/null \
    | jq -c --arg repo "$full_name" --argjson alias "$(detector_alias_map)" "$JQ_CANON_DETECTOR"'
        # The repository too.  Ingest skips a row that names none, without a
        # word, and the first version of this left it out: every credential
        # only semgrep saw vanished, and the code rows it replaced were closed
        # as fixed.
        . + {repository: $repo,
             organization: ($repo | split("/")[0]),
             detector: (.detector | canon_detector($alias)),
             code_rule: (.code_rule | canon_detector($alias))}' \
    | secrets_drop_excluded /dev/null \
    | derive_secret_facts "$dir" > "$cand"
  if [[ ! -s "$cand" ]]; then rm -f "$cand"; return 0; fi

  local triaged; triaged=$(tmp_file semgrep_creds_triaged)
  if ! triage_findings "$dir" "$cand" "$repo_json" > "$triaged" || [[ ! -s "$triaged" ]]; then
    log_warn "[$full_name] semgrep's secret matches could not be triaged as credentials, so they stay code findings"
    rm -f "$cand" "$triaged"; return 0
  fi
  local keep_low; keep_low=$(cfg_bool '.scan.secrets.triage.path_rule_downgrades_only' true && echo true || echo false)
  local part; part=$(tmp_file semgrep_creds_part)
  triage_partition "$triaged" "$keep_low" > "$part"

  local base; base=$(json_file "${SECRETS_JSON:-}" secrets_before_semgrep)
  local merged
  # The same value in the same file is one credential, whichever engine said
  # so first: it gains semgrep as an engine and the lines semgrep saw.
  merged=$(jq -c --slurpfile add "$part" '
    def fp: ((.secret_fingerprint // "") + "|" + (.file // ""));
    def rows($o): (($o.reported // []) + ($o.filtered // []) + ($o.suppressed // []));
    def joined($same):
      if $same == null then .
      else .engines = (((.engines // [.engine // empty]) + ["semgrep"]) | unique)
         | .code_lines = (((.code_lines // []) + ($same.code_lines // [])) | unique)
         | .code_rule = (.code_rule // $same.code_rule)
      end;
    ($add[0]) as $new
    | (if type == "object" then . else {} end) as $base
    | (rows($base) | map(fp)) as $have
    | (rows($new) | map({key: fp, value: .}) | from_entries) as $by
    | reduce ("reported", "filtered", "suppressed") as $k ($base;
        .[$k] = (
          ((.[$k] // []) | map(joined($by[fp])))
          + (($new[$k] // []) | map(select(fp as $f | ($have | any(.[]; . == $f)) | not)))
        ))
  ' "$base" 2>/dev/null)
  if [[ -z "$merged" ]]; then
    log_warn "[$full_name] semgrep's secret matches could not be merged into the credentials, so they stay code findings"
    rm -f "$cand" "$triaged" "$part"; return 0
  fi

  local code_only; code_only=$(tmp_file semgrep_code_only)
  if "$py" "$GHSCAN_HOME/lib/semgrep_secrets.py" --drop "$sg" "$cand" > "$code_only" 2>/dev/null \
      && [[ -s "$code_only" ]]; then
    SECRETS_JSON="$merged"
    mv "$code_only" "$sg"
    log_info "[$full_name] $(jq -s 'length' "$cand") semgrep secret match(es) moved to the credential pass"
  fi
  rm -f "$cand" "$triaged" "$part" "$code_only"
}
