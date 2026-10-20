#!/usr/bin/env bash
# Static analysis of the code itself: command injection, SQL injection, XSS,
# weak crypto, unsafe function calls. Runs semgrep with its free OSS rules.
# This is the part GitHub charges for under Code Security.
# shellcheck shell=bash

_semgrep_bin() { ghscan_venv_bin semgrep; }

# One bad ruleset makes semgrep abort the whole run, so drop anything the
# registry does not serve rather than lose the scan.
semgrep_valid_configs() {
  local valid=() c code
  while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    if [[ "$c" == /* || -e "$c" ]]; then valid+=("$c"); continue; fi
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "https://semgrep.dev/c/${c}" 2>/dev/null || echo 000)
    if [[ "$code" == "200" ]]; then valid+=("$c")
    else log_warn "semgrep ruleset '$c' unavailable (HTTP $code), skipping it"; fi
  done < <(cfg_arr '.scan.code_analysis.rulesets')
  (( ${#valid[@]} )) && printf '%s\n' "${valid[@]}"
}

# _semgrep_html_blocks <dir> <full_name> <out_json> <extra_rules>
#
# Merges into the semgrep output that is already there, so everything
# downstream - normalising, triage, blame - treats these exactly like any other
# code finding, which is what they are.
_semgrep_html_blocks() {
  local dir="$1" full_name="$2" out="$3" extra="$4"
  local helper="${GHSCAN_HOME:-}/lib/html_scripts.py"
  [[ -r "$helper" ]] || return 0
  local python; python=$(command -v python3 || true)
  [[ -n "$python" ]] || return 0

  local blocks; blocks=$(tmp_dir htmlblocks)
  local count; count=$("$python" "$helper" extract "$dir" "$blocks" 2>/dev/null || echo 0)
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  (( count > 0 )) || return 0
  log_info "$full_name: $count script block(s) inside HTML pages, read as JavaScript"

  local bin; bin=$(command -v semgrep || true)
  [[ -n "$bin" ]] || return 0
  local hargs=(scan --metrics=off --json --no-git-ignore --quiet)
  [[ -n "$extra" && -r "$extra" ]] && hargs+=(--config "$extra")
  local c
  while IFS= read -r c; do
    # Only the JavaScript packs: a Java or Python pack has nothing to say about
    # a script block and only costs time.
    case "$c" in *javascript*|*typescript*|*xss*|*nodejs*|*react*) hargs+=(--config "$c");; esac
  done < <(semgrep_valid_configs)

  local raw; raw=$(tmp_file html_semgrep)
  ( cd "$blocks" && "$bin" "${hargs[@]}" . ) > "$raw" 2>/dev/null || true

  local mapped; mapped=$(tmp_file html_mapped)
  local n; n=$("$python" "$helper" remap "$raw" "$blocks" "$mapped" 2>/dev/null || echo 0)
  [[ "$n" =~ ^[0-9]+$ ]] || n=0
  if (( n > 0 )); then
    log_info "$full_name: $n finding(s) in HTML script blocks"
    local merged; merged=$(tmp_file html_merged)
    jq -s '.[0] as $a | .[1] as $b
           | $a + {results: (($a.results // []) + ($b.results // []))}' \
      "$out" "$mapped" > "$merged" 2>/dev/null && mv -f "$merged" "$out"
  fi
}

# run_semgrep <dir> <full_name> <out_json>
# _semgrep_loaded_rules <bin> <out> <semgrep args...>
#
# Which rules semgrep actually had this time, as the names findings carry.
#
# The packs are fetched from semgrep's registry on every scan, so a rule can
# be withdrawn between one scan and the next with nothing changed here.  On
# 2026-10-04 the JWT rule went from p/secrets between a morning and an evening
# scan, and every finding it had made started closing as fixed: tokens still
# sitting in the code, retired because a remote list changed.  Ingest holds a
# finding open when its rule was not loaded, and this is what it reads.
#
# Asked separately, against an empty directory with --time, because --time on
# the real pass adds timings for every file and rule.  Kept for an hour per set
# of packs, since every repository in a run asks the same question.  Empty
# output means unknown, which ingest treats as "do not hold".
_semgrep_loaded_rules() {
  local bin="$1" out="$2"; shift 2
  local -a cfgs=()
  while (( $# )); do
    [[ "$1" == "--config" && $# -ge 2 ]] && { cfgs+=(--config "$2"); shift 2; continue; }
    shift
  done
  (( ${#cfgs[@]} > 0 )) || { echo '[]' > "$out"; return 0; }
  local key; key=$(printf '%s\n' "${cfgs[@]}" "$(date -u +%Y%m%d%H)" | sha256sum | cut -c1-16)
  local cache="${TMPDIR:-/tmp}/gcr-semgrep-rules-$key.json"
  if [[ ! -s "$cache" ]]; then
    local empty; empty=$(mktemp -d)
    ( cd "$empty" && with_timeout 300 "$bin" scan --metrics=off --json --quiet --time "${cfgs[@]}" . ) 2>/dev/null \
      | jq -c --argjson alias "$(detector_alias_map)" "$JQ_CANON_DETECTOR"'
          [ (.time.rules // [])[] | (if type == "object" then (.id // "") else . end)
            | select(. != "") | split(".") | last | canon_detector($alias) ] | unique' \
        > "$cache.tmp" 2>/dev/null && [[ -s "$cache.tmp" ]] && mv "$cache.tmp" "$cache"
    rm -rf "$empty" "$cache.tmp"
  fi
  if [[ -s "$cache" ]]; then cp "$cache" "$out"; else echo '[]' > "$out"; fi
}

run_semgrep() {
  local dir="$1" full_name="$2" out="$3"
  local bin; bin=$(_semgrep_bin)
  [[ -z "$bin" ]] && {
    log_warn "semgrep is not on the path, so code analysis found nothing. It is at \$GCR_SCANNER_VENV/bin in the container."
    echo '{}' > "$out"; return 0; }

  local args=(scan --metrics=off --json --no-git-ignore --quiet)

  # Generated output is not source, and reading it is how a low confidence rule
  # comes back twenty two thousand times from one repository.  semgrep's own
  # defaults already cover node_modules and vendor; these are the directories
  # a test runner or a build writes, which no default can know the names of.
  local ex ex_count=0
  while IFS= read -r ex; do
    [[ -z "$ex" ]] && continue
    # semgrep matches these against the path, so a trailing slash would never
    # hit.  The name on its own excludes the directory and everything in it.
    args+=(--exclude "${ex%/}")
    ex_count=$((ex_count+1))
  done < <(cfg_arr '.scan.code_analysis.exclude_paths')
  if (( ex_count > 0 )); then
    log_info "$full_name: code analysis skips $ex_count generated path(s): $(cfg_json '.scan.code_analysis.exclude_paths // []' | jq -r 'join(", ")')"
  fi
  GHSCAN_CODE_EXCLUDED="$ex_count"
  export GHSCAN_CODE_EXCLUDED

  local c loaded=0
  while IFS= read -r c; do
    [[ -n "$c" ]] && { args+=(--config "$c"); loaded=$((loaded+1)); }
  done < <(semgrep_valid_configs)

  # Rules this product ships itself, for what the public packs do not cover.
  # Local, so it does not depend on the registry answering, and always on: it
  # exists because these weaknesses were being missed, not as an option.
  local extra; extra=$(cfg '.scan.code_analysis.extra_rules_path' '')
  if [[ -n "$extra" && -r "$extra" ]]; then
    args+=(--config "$extra"); loaded=$((loaded+1))
    log_debug "$full_name: plus the rules shipped with this product"
  fi

  # Say how many of them made it, every time, not only when one does not.
  #
  # A ruleset the registry will not answer for is dropped with a warning and
  # the scan carries on, which is the right call.  What was missing is a line
  # on a good run to compare a bad one against: without it, a scan that used
  # eight rulesets of twenty one looks exactly like a scan that used all of
  # them, and the only clue is a finding count nobody was watching.
  local wanted; wanted=$(cfg_arr '.scan.code_analysis.rulesets' | grep -c . || echo 0)
  if (( loaded < wanted )); then
    log_warn "$full_name: semgrep is using $loaded of $wanted rulesets, so this pass is thinner than it should be"
  fi
  # Carried out to the summary line the scan already prints, because that one
  # is a warning and survives a quiet run.  A count that only appears when
  # something is wrong leaves nothing to compare a wrong run against: the good
  # run and the check never running look identical from the outside.
  GHSCAN_SEMGREP_RULESETS="$loaded of $wanted"
  export GHSCAN_SEMGREP_RULESETS

  # No usable rulesets means nothing to do.
  printf '%s\n' "${args[@]}" | grep -q -- '--config' || { echo '{}' > "$out"; return 0; }

  local jobs; jobs=$(cfg_num '.scan.code_analysis.jobs' 2)
  args+=(--jobs "$jobs")
  local timeout_s; timeout_s=$(cfg_num '.scan.code_analysis.timeout_sec' 900)

  log_debug "$full_name: semgrep ${args[*]}"
  # A pass that did not finish is not a pass that found nothing.  This used to
  # swallow the exit status and replace unreadable output with an empty object,
  # so a semgrep that was killed on the way through came back as a clean
  # repository, and everything it had reported last time was marked fixed.  The
  # findings returned on the next scan, which is what gave it away.
  local rc=0
  ( cd "$dir" && with_timeout "$timeout_s" "$bin" "${args[@]}" . ) > "$out" 2>"$GHSCAN_TMPROOT/semgrep.log" || rc=$?

  # And again over the JavaScript inside HTML pages, which the pass above
  # cannot see: semgrep parses HTML and it parses JavaScript, but not one
  # inside the other, so a cross site scripting bug written in a page rather
  # than a module goes unreported.  The blocks are pulled out, analysed as
  # JavaScript, and the findings put back on the line of the page they came
  # from.
  _semgrep_html_blocks "$dir" "$full_name" "$out" "$extra"
  GHSCAN_CODE_COMPLETE=true
  GHSCAN_CODE_INCOMPLETE=""
  if (( rc != 0 )); then
    GHSCAN_CODE_COMPLETE=false
    if (( rc == 124 || rc == 137 )); then
      GHSCAN_CODE_INCOMPLETE="semgrep ran past ${timeout_s}s and was stopped"
    else
      GHSCAN_CODE_INCOMPLETE="semgrep exited $rc"
    fi
  fi
  if ! jq -e . "$out" >/dev/null 2>&1; then
    GHSCAN_CODE_COMPLETE=false
    GHSCAN_CODE_INCOMPLETE="${GHSCAN_CODE_INCOMPLETE:+$GHSCAN_CODE_INCOMPLETE, }semgrep output was unreadable"
    echo '{}' > "$out"
  fi
  # semgrep keeps going when a single file defeats it, and says so in the
  # report rather than in its exit status.  Those files were not analysed, so
  # anything in them is missing rather than gone.
  local gave_up
  gave_up=$(jq '[ (.errors[]? | select((((.type? // "") | tostring) + " " + ((.message? // "") | tostring)) | test("timeout|out of memory|too big|killed"; "i"))),
                 (.paths.skipped[]? | select(((.reason? // "") | tostring) | test("timeout|too_big|exceeded|error"; "i"))) ] | length' \
           "$out" 2>/dev/null || echo 0)
  if [[ "$gave_up" =~ ^[0-9]+$ ]] && (( gave_up > 0 )); then
    GHSCAN_CODE_COMPLETE=false
    GHSCAN_CODE_INCOMPLETE="${GHSCAN_CODE_INCOMPLETE:+$GHSCAN_CODE_INCOMPLETE, }semgrep gave up on $gave_up file(s)"
  fi
  export GHSCAN_CODE_COMPLETE GHSCAN_CODE_INCOMPLETE
  _semgrep_loaded_rules "$bin" "$out.rules" "${args[@]}"
  if [[ "$GHSCAN_CODE_COMPLETE" != "true" ]]; then
    log_warn "$full_name: the code pass did not complete ($GHSCAN_CODE_INCOMPLETE), so nothing it did not report will be counted as fixed"
  fi

  code_triage "$dir" "$out"
  code_blame "$dir" "$out"
}

# Decide which of those findings is worth somebody's attention.
#
# semgrep matches a pattern on a line.  It cannot see that the line is in a
# JSON endpoint, or in a theme somebody bought, or that the value was cast to
# an integer three characters earlier.  This runs while the clone is still on
# disk, which is the only moment those questions can be answered, and writes a
# verdict onto every finding.  Nothing is removed.
code_triage() {
  local dir="$1" out="$2"
  cfg_bool '.scan.code_analysis.triage' true || {
    log_debug "code triage is switched off"; return 0; }

  local engine="$GHSCAN_HOME/lib/code_triage.py"
  [[ -r "$engine" ]] || { log_warn "the triage engine is missing, so findings are unfiltered"; return 0; }

  local python; python=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
  [[ -n "$python" ]] || { log_warn "no python for the triage engine, so findings are unfiltered"; return 0; }

  local muted; muted=$(cfg_arr '.scan.code_analysis.muted_rules' | paste -sd, -)
  local triaged="${out}.triaged"

  if "$python" "$engine" "$out" "$dir" "$muted" > "$triaged" 2>"$GHSCAN_TMPROOT/triage.log"; then
    mv "$triaged" "$out"
    local kept; kept=$(jq '[ .results[]? | select(.triage.verdict == "review") ] | length' "$out" 2>/dev/null || echo 0)
    local total; total=$(jq '[ .results[]? ] | length' "$out" 2>/dev/null || echo 0)
    log_info "code triage: $kept of $total finding(s) need a person"
  else
    # An unfiltered report is a worse day for somebody reading it, but a
    # missing one is a worse day for everybody.
    log_warn "triage did not run, so code findings are unfiltered: $(tail -1 "$GHSCAN_TMPROOT/triage.log" 2>/dev/null)"
    rm -f "$triaged"
  fi
}

# Who last touched the line, for the findings that have one.
#
# The secrets pass has always carried an author because it walks commits to do
# its job.  Code findings never have, and a report that says a repository has
# eight hundred problems and nothing about who to ask is a report nobody acts
# on.  One blame per file while the clone is still here answers it.
code_blame() {
  local dir="$1" out="$2"

  local engine="$GHSCAN_HOME/lib/code_blame.py"
  [[ -r "$engine" ]] || { log_debug "no blame engine, so code findings carry no author"; return 0; }

  local python; python=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
  [[ -n "$python" ]] || { log_debug "no python for blame, so code findings carry no author"; return 0; }

  local blamed="${out}.blamed"
  if "$python" "$engine" "$out" "$dir" > "$blamed" 2>"$GHSCAN_TMPROOT/blame.log"; then
    mv "$blamed" "$out"
  else
    # An author is a convenience.  Losing the findings is not.
    log_warn "blame did not run, so code findings carry no author: $(tail -1 "$GHSCAN_TMPROOT/blame.log" 2>/dev/null)"
    rm -f "$blamed"
  fi
}

# semgrep severity is ERROR/WARNING/INFO; map it onto ours using the rule's
# own impact and likelihood so a high-impact finding is not filed as medium.
normalize_semgrep() {
  local in="$1" repo="$2" branch="$3" web="$4"
  jq -c --arg repo "$repo" --arg br "$branch" --arg web "$web" \
        --argjson link "$(provider_link_parts)" \
        --argjson alias "$(detector_alias_map)" "$JQ_CANON_DETECTOR"'
    # semgrep gives these as a string when there is one and an array when there
    # are several.  Anything that iterates them falls over on the string.
    def aslist: if . == null then [] elif type == "array" then . else [.] end;

    [ (.results // [])[] | . as $r | ($r.extra.metadata // {}) as $m |
      {
        organization: ($repo | split("/")[0]),
        repository: $repo,
        repository_name: ($repo | split("/")[1]),
        branch: $br,
        source: "semgrep",
        category: "code_vulnerability",
        finding_type: "static_analysis",
        rule_id: ($r.check_id // "unknown"),
        # One spelling across the engines: detected-jwt-token from semgrep and
        # jwt from gitleaks are the same thing, and a severity override written
        # once should cover both.  check_id above keeps the name semgrep used.
        rule_name: (($r.check_id // "unknown") | split(".") | last | canon_detector($alias)),
        title: ($r.extra.message // "" | split("\n")[0]),
        message: ($r.triage.promote.message // $r.extra.message // ""),
        # The line that matched, with anything credential shaped masked out
        # first.  Several semgrep rules here are secret detectors, so the line
        # they match on is the secret itself, and a report that carries it is
        # worse than one that carries nothing.  A run of twenty or more token
        # characters is masked keeping four at the front and three at the back,
        # the same shape redact() uses.  Slashes and at signs are not token
        # characters, so "actions/checkout@v4" survives and a JWT does not.
        snippet: (($r.extra.lines // "")
                  | gsub("[\r\n]+"; " ")
                  | gsub("(?<t>[A-Za-z0-9_+=-]{20,})";
                         (.t[0:4] + "************" + .t[-3:]))
                  | .[0:400]),
        file: (($r.path // "") | sub("^\\./"; "")),
        start_line: ($r.start.line // 0),
        end_line: ($r.end.line // 0),
        # An editor underlines a range, not a line.  semgrep has said where
        # the match starts and ends all along and we threw it away, so every
        # finding would have underlined the whole line and looked broken next
        # to any other linter.
        start_column: ($r.start.col // 0),
        end_column: ($r.end.col // 0),
        # Confidence was collected on the line below this one and never used,
        # so a rule that says "high impact, and I am not sure" came out
        # critical.  On one real repository every single critical finding was a
        # low confidence one, and every single one of them was wrong.
        #
        # Critical is the grade that makes somebody stop what they are doing.
        # A rule that is unsure has not earned it, and spending it on a guess
        # is how the word stops meaning anything.
        #
        # The same sentence applies one grade down, and for a long time this
        # code did not apply it.  An ERROR the engine is unsure about was still
        # high, which on a twenty repository corpus was 196 of the 314 findings
        # at the top of the list: 62% of the work list sitting there on a rule
        # that said, in the same breath, that it was guessing.  Those are now
        # medium.  Nothing is hidden and nothing is deleted; they stop
        # competing with the 101 findings the engine is actually sure about.
        # The triage pass can say a finding is not what the rule called it.
        # It only ever raises, and only on a fact about the file, so a rule
        # reporting "hash detected" on a credential the product ships with
        # comes out as the default credential it is.
        severity: (
          if (($r.triage.promote.severity // "") != "")
          then $r.triage.promote.severity
          else (
            ($r.extra.severity // "INFO") as $s |
            ($m.impact // "") as $i |
            (($m.confidence // "") | ascii_upcase) as $c |
            if   $i == "HIGH" and $s == "ERROR" and $c != "LOW" then "critical"
            elif $s == "ERROR" and $c == "LOW" then "medium"
            elif $s == "ERROR"  then "high"
            elif $s == "WARNING" then "medium"
            else "low" end)
          end
          # And the fidelity pass can lower it, on the same terms: only on a
          # fact about the file.  A promotion outranks a demotion, because the
          # promotion is the one that says somebody can log in.
          | (if (($r.triage.promote.severity // "") == "")
                and (($r.triage.demote.severity // "") != "")
             then $r.triage.demote.severity else . end)),
        engine_severity: ($r.extra.severity // null),
        confidence: (($m.confidence // "UNKNOWN") | ascii_downcase),
        impact: (($m.impact // "unknown") | ascii_downcase),
        likelihood: (($m.likelihood // "unknown") | ascii_downcase),
        cwe: (if (($r.triage.promote.cwe // "") != "")
              then ([$r.triage.promote.cwe] + ($m.cwe | aslist)) | unique
              else ($m.cwe | aslist) end),
        cwe_ids: [ ((if (($r.triage.promote.cwe // "") != "")
                     then ([$r.triage.promote.cwe] + ($m.cwe | aslist)) | unique
                     else ($m.cwe | aslist) end))[] | tostring | split(":")[0] ],
        owasp: ($m.owasp | aslist),
        technology: ($m.technology | aslist),
        references: ($m.references | aslist),
        fix: ($r.extra.fix // null),
        commit: (($r.blame.commit // "")),
        commit_url: (if ($r.blame.commit // "") == "" then ""
                     else $web + "/" + $repo + "/" + $link.commit + "/" + $r.blame.commit end),
        author_name: (($r.blame.author_name // "")),
        author_email: (($r.blame.author_email // "")),
        committed_at: (($r.blame.committed_at // "")),
        triage: (($r.triage.verdict // "review")),
        triage_reason: (($r.triage.reason // "")),
        triage_rule: ($r.triage.promote.rule // $r.triage.rule // ""),
        # The expression the rule actually matched, which is what makes this
        # finding this finding.
        #
        # Identity used to include the line number, so inserting a function
        # anywhere above a finding retired it and created a new one, and every
        # decision recorded on it stayed with the row that had just been
        # resolved.  Somebody graded the same three lines twice in one evening
        # because of it.
        #
        # The matched text moves with the code.  The triage pass already reads
        # it out of the source using the column offsets, so this is carrying
        # something already computed rather than computing anything.
        matched: (($r.triage.matched // "")),
        url: ($web + "/" + $repo + "/" + $link.blob + "/" + $br + "/" + (($r.path // "") | sub("^\\./"; "")) + $link.line + (($r.start.line // 0) | tostring)),
        state: "open"
      } ]
    | sort_by([ (if .severity == "critical" then 0 elif .severity == "high" then 1
                 elif .severity == "medium" then 2 else 3 end), .file ])' "$in" 2>/dev/null || echo '[]'
}

# --- a second engine, where semgrep reads one file at a time -----------------
#
# semgrep reads a file at a time.  A tainted value that crosses a function
# boundary into another file is invisible to it, and no ruleset fixes that:
# cross file dataflow is the half Semgrep sells and the free rules stop at the
# boundary on purpose.  CodeQL is not the answer either, because its license
# does not cover a private codebase without buying Advanced Security.
#
# So: a second engine per language, chosen because it costs nothing, and
# honest about which of them add depth and which only corroborate.
#
#   gosec     real analysis of Go, across the package rather than the file.
#   bandit    python.  AST rules, so corroboration rather than depth.
#   njsscan   javascript.  The same, and sold as the same.
#
# Two rules.  Only what the tree needs, the same decision syft already makes
# from what is in the checkout.  And agreement is kept rather than blended: a
# finding two engines produce is worth more than one, and a finding only the
# second engine saw is the class semgrep was never going to reach.

# code_languages <dir> -> space separated list of what is in there
code_languages() {
  local dir="$1" langs=""
  # -s exits at the first hit, so this costs one directory walk per language
  # rather than a full inventory nobody reads.
  find "$dir" -type d \( -name .git -o -name node_modules -o -name vendor \) -prune -o \
       -type f -name '*.go' -print -quit 2>/dev/null | grep -q . && langs+=" go"
  find "$dir" -type d \( -name .git -o -name node_modules -o -name vendor \) -prune -o \
       -type f -name '*.py' -print -quit 2>/dev/null | grep -q . && langs+=" python"
  find "$dir" -type d \( -name .git -o -name node_modules -o -name vendor \) -prune -o \
       -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' \) \
       -print -quit 2>/dev/null | grep -q . && langs+=" javascript"
  # Mule apps keep their flows under src/main/mule.  No other engine here
  # reads them.
  find "$dir" -type d \( -name .git -o -name node_modules -o -name target \) -prune -o \
       -type f -path '*/src/main/mule/*.xml' -print -quit 2>/dev/null | grep -q . && langs+=" mule"
  printf '%s' "${langs# }"
}

# run_mule_check <dir> <full_name> <branch> <web> -> findings JSON
#
# Not a second engine: semgrep and CodeQL do not read Mule flows at all, so
# this is the only thing that looks at them.  See lib/mule_check.py.
run_mule_check() {
  local dir="$1" repo="$2" branch="$3" web="$4"
  cfg_bool '.scan.code_analysis.mule_check' true || { echo '[]'; return 0; }
  local python; python=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
  [[ -n "$python" ]] || { log_debug "no python, so Mule flows are not read"; echo '[]'; return 0; }
  local out; out=$(tmp_file mulecheck)
  with_timeout 300 "$python" -I "$GHSCAN_HOME/lib/mule_check.py" "$dir" "$repo" "$branch" \
    "$web" "$(provider_link_parts)" > "$out" 2>"$GHSCAN_TMPROOT/mulecheck.log" || true
  if jq -e 'type == "array"' "$out" >/dev/null 2>&1; then
    cat "$out"
  else
    log_warn "[$repo] the Mule check did not run: $(tail -1 "$GHSCAN_TMPROOT/mulecheck.log" 2>/dev/null)"
    echo '[]'
  fi
}

# run_gosec <dir> <full_name> -> findings JSON
run_gosec() {
  local dir="$1" repo="$2" branch="$3" web="$4"
  have_cmd gosec || { log_debug "gosec not installed, skipping"; echo '[]'; return 0; }
  # gosec resolves types through go/packages, which shells out to `go list`.
  # Without a toolchain it exits zero having analysed nothing, which reads as
  # a clean Go codebase and is the most dangerous way for an engine to fail.
  # Say so instead.
  have_cmd go || {
    log_warn "gosec needs the go toolchain to resolve types; skipping it rather than reporting a clean result it did not earn"
    echo '[]'; return 0
  }
  local out; out=$(tmp_file gosec)
  # -quiet keeps the summary off stdout, which would not be JSON.
  #
  # GOPROXY=off matters more than it looks.  Resolving types would otherwise
  # reach out and download whatever the module graph names, which is a scanner
  # fetching arbitrary code from the internet in the middle of a run.  Tested
  # against gosec's own tree: the same nine findings either way, because what
  # it needs is the local package graph rather than the dependencies.
  #
  # The caches go under the work directory so nothing is written to a home
  # directory that may not be writable.
  ( cd "$dir" && GOPROXY=off GOFLAGS=-mod=mod       GOPATH="${GHSCAN_TMPROOT:-/tmp}/go" GOCACHE="${GHSCAN_TMPROOT:-/tmp}/gocache"       with_timeout 600 gosec -quiet -fmt json -no-fail ./... ) > "$out" 2>/dev/null || true
  [[ -s "$out" ]] || { echo '[]'; return 0; }

  jq -c --arg repo "$repo" --arg br "$branch" --arg web "$web" --arg root "$dir" \
        --argjson link "$(provider_link_parts)" '
    [ (.Issues // [])[] | {
        organization: ($repo | split("/")[0]),
        repository: $repo,
        repository_name: ($repo | split("/")[1]),
        branch: $br,
        source: "gosec",
        category: "code_vulnerability",
        finding_type: "static_analysis",
        rule_id: ("gosec." + (.rule_id // "unknown")),
        rule_name: (.rule_id // "unknown"),
        title: (.details // ""),
        message: (.details // ""),
        file: ((.file // "") | sub("^" + $root + "/?"; "") | sub("^\\./"; "")),
        start_line: ((.line // "0") | tostring | split("-")[0] | tonumber? // 0),
        end_line: ((.line // "0") | tostring | split("-") | last | tonumber? // 0),
        start_column: ((.column // "0") | tostring | tonumber? // 0),
        end_column: 0,
        severity: ((.severity // "MEDIUM") | ascii_downcase
                   | if . == "high" then "high" elif . == "medium" then "medium" else "low" end),
        engine_severity: (.severity // null),
        confidence: ((.confidence // "UNKNOWN") | ascii_downcase),
        impact: "unknown",
        likelihood: "unknown",
        cwe: (if (.cwe.id // "") != "" then [ "CWE-" + (.cwe.id | tostring) ] else [] end),
        cwe_ids: (if (.cwe.id // "") != "" then [ (.cwe.id | tostring) ] else [] end),
        owasp: [], technology: ["go"], references: [],
        fix: null, commit: "", commit_url: "",
        author_name: "", author_email: "", committed_at: "",
        triage: "review", triage_reason: "", triage_rule: "",
        url: ($web + "/" + $repo + "/" + $link.blob + "/" + $br + "/"
              + ((.file // "") | sub("^" + $root + "/?"; "") | sub("^\\./"; ""))
              + $link.line + ((.line // "0") | tostring | split("-")[0])),
        state: "open"
      } ]' "$out" 2>/dev/null || echo '[]'
}

# run_bandit <dir> <full_name> -> findings JSON
run_bandit() {
  local dir="$1" repo="$2" branch="$3" web="$4"
  local bin; bin=$(ghscan_venv_bin bandit)
  [[ -n "$bin" ]] || { log_debug "bandit not installed, skipping"; echo '[]'; return 0; }
  local out; out=$(tmp_file bandit)
  # bandit exits 1 when it finds anything, which is not a failure.
  ( cd "$dir" && with_timeout 600 "$bin" -r . -f json -q \
      -x './node_modules,./vendor,./.venv,./venv,./.git' ) > "$out" 2>/dev/null || true
  [[ -s "$out" ]] || { echo '[]'; return 0; }

  jq -c --arg repo "$repo" --arg br "$branch" --arg web "$web" \
        --argjson link "$(provider_link_parts)" '
    [ (.results // [])[] | {
        organization: ($repo | split("/")[0]),
        repository: $repo,
        repository_name: ($repo | split("/")[1]),
        branch: $br,
        source: "bandit",
        category: "code_vulnerability",
        finding_type: "static_analysis",
        rule_id: ("bandit." + (.test_id // "unknown")),
        rule_name: (.test_name // .test_id // "unknown"),
        title: (.issue_text // ""),
        message: (.issue_text // ""),
        file: ((.filename // "") | sub("^\\./"; "")),
        start_line: (.line_number // 0),
        end_line: (.line_number // 0),
        start_column: (.col_offset // 0),
        end_column: 0,
        severity: ((.issue_severity // "LOW") | ascii_downcase),
        engine_severity: (.issue_severity // null),
        confidence: ((.issue_confidence // "UNKNOWN") | ascii_downcase),
        impact: "unknown", likelihood: "unknown",
        cwe: (if (.issue_cwe.id // "") != "" then [ "CWE-" + (.issue_cwe.id | tostring) ] else [] end),
        cwe_ids: (if (.issue_cwe.id // "") != "" then [ (.issue_cwe.id | tostring) ] else [] end),
        owasp: [], technology: ["python"], references: [],
        fix: null, commit: "", commit_url: "",
        author_name: "", author_email: "", committed_at: "",
        triage: "review", triage_reason: "", triage_rule: "",
        url: ($web + "/" + $repo + "/" + $link.blob + "/" + $br + "/"
              + ((.filename // "") | sub("^\\./"; "")) + $link.line + ((.line_number // 0) | tostring)),
        state: "open"
      } ]' "$out" 2>/dev/null || echo '[]'
}

# run_njsscan <dir> <full_name> -> findings JSON
run_njsscan() {
  local dir="$1" repo="$2" branch="$3" web="$4"
  local bin; bin=$(ghscan_venv_bin njsscan)
  [[ -n "$bin" ]] || { log_debug "njsscan not installed, skipping"; echo '[]'; return 0; }
  local out; out=$(tmp_file njsscan)
  ( cd "$dir" && with_timeout 600 "$bin" --json -o /dev/stdout . ) > "$out" 2>/dev/null || true
  [[ -s "$out" ]] || { echo '[]'; return 0; }

  jq -c --arg repo "$repo" --arg br "$branch" --arg web "$web" \
        --argjson link "$(provider_link_parts)" '
    [ (.nodejs // {}) as $n | ($n | to_entries[]) | .key as $rule | .value as $v
      | ($v.files // [])[] | {
        organization: ($repo | split("/")[0]),
        repository: $repo,
        repository_name: ($repo | split("/")[1]),
        branch: $br,
        source: "njsscan",
        category: "code_vulnerability",
        finding_type: "static_analysis",
        rule_id: ("njsscan." + $rule),
        rule_name: $rule,
        title: ($v.metadata.description // $rule),
        message: ($v.metadata.description // ""),
        file: ((.file_path // "") | sub("^\\./"; "")),
        start_line: ((.match_lines // [0])[0] // 0),
        end_line: ((.match_lines // [0]) | last // 0),
        start_column: ((.match_position // [0])[0] // 0),
        end_column: ((.match_position // [0]) | last // 0),
        severity: (($v.metadata.severity // "INFO") | ascii_downcase
                   | if . == "error" then "high" elif . == "warning" then "medium" else "low" end),
        engine_severity: ($v.metadata.severity // null),
        confidence: "unknown", impact: "unknown", likelihood: "unknown",
        cwe: (if ($v.metadata.cwe // "") != "" then [ $v.metadata.cwe ] else [] end),
        cwe_ids: [ (($v.metadata.cwe // "") | tostring | capture("(?<n>[0-9]+)").n // empty) ],
        owasp: (if ($v.metadata.owasp // "") != "" then [ $v.metadata.owasp ] else [] end),
        technology: ["javascript"], references: [],
        fix: null, commit: "", commit_url: "",
        author_name: "", author_email: "", committed_at: "",
        triage: "review", triage_reason: "", triage_rule: "",
        url: ($web + "/" + $repo + "/" + $link.blob + "/" + $br + "/"
              + ((.file_path // "") | sub("^\\./"; "")) + $link.line + (((.match_lines // [0])[0] // 0) | tostring)),
        state: "open"
      } ]' "$out" 2>/dev/null || echo '[]'
}

# --- CodeQL, read from GitHub rather than run here ---------------------------
#
# codeql_alerts <dir> <repo> <branch> <web> <primary_json_file> <out_file>
#
# Writes the primary findings with the CodeQL alerts added, as code findings.
# Called in this shell, not in $( ), so CODEQL_UNREAD survives: it is set when
# GitHub could not be read, which is not the same as having nothing to say.
# A 404 means code scanning is not set up here, and is an honest empty.
# Anything else means the alerts that were open last time were not looked at,
# and ingest holds them open rather than calling them fixed.
codeql_alerts() {
  local dir="$1" repo="$2" branch="$3" web="$4" primary="$5" out="$6"
  CODEQL_UNREAD=""
  cp "$primary" "$out"
  provider_supports code_scanning || return 0

  local first; first=$(tmp_file cq_first)
  if ! api_get "/repos/${repo}/code-scanning/alerts?state=open&per_page=1" > "$first"; then
    if [[ "${GHSCAN_API_LAST_CODE:-0}" == "404" ]]; then
      log_debug "[$repo] no code scanning here"
      return 0
    fi
    CODEQL_UNREAD="GitHub answered ${GHSCAN_API_LAST_CODE:-nothing} for the code scanning alerts"
    log_warn "[$repo] $CODEQL_UNREAD, so CodeQL findings are held as they were"
    return 0
  fi
  [[ "$(jq 'length' "$first" 2>/dev/null || echo 0)" == "0" ]] && return 0

  local alerts; alerts=$(tmp_file cq_alerts)
  if ! api_paginate "/repos/${repo}/code-scanning/alerts?state=open" 100 > "$alerts"; then
    CODEQL_UNREAD="the code scanning alerts could not be read in full"
    log_warn "[$repo] $CODEQL_UNREAD, so CodeQL findings are held as they were"
    return 0
  fi

  # The SARIF for the newest analysis of each category the alerts came from.
  # It carries CodeQL's precision for each rule and where each data flow
  # starts.  Missing it costs those two facts and nothing else.
  local sarif_dir; sarif_dir="$GHSCAN_TMPROOT/cq_sarif.$$"
  rm -rf "$sarif_dir"; mkdir -p "$sarif_dir"
  local analyses; analyses=$(tmp_file cq_analyses)
  if api_get "/repos/${repo}/code-scanning/analyses?per_page=50" > "$analyses"; then
    local id
    while IFS= read -r id; do
      [[ -n "$id" ]] || continue
      GHSCAN_API_ACCEPT="application/sarif+json" \
        api_get "/repos/${repo}/code-scanning/analyses/${id}" > "$sarif_dir/$id.sarif" \
        || rm -f "$sarif_dir/$id.sarif"
    done < <(jq -r --slurpfile a "$alerts" '
        ([$a[0][]? | .most_recent_instance.category] | unique) as $want
        | [ .[]? | select(.category as $c | $want | index($c)) ]
        | group_by(.category) | map(max_by(.created_at) | .id) | .[]' "$analyses" 2>/dev/null)
  fi

  local python; python=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
  [[ -n "$python" ]] || { log_warn "[$repo] no python, so CodeQL alerts are not read"
                          CODEQL_UNREAD="no python to read the CodeQL alerts"; return 0; }
  local muted; muted=$(cfg_arr '.scan.code_analysis.muted_rules' | paste -sd, -)
  if ! "$python" "$GHSCAN_HOME/lib/codeql.py" "$alerts" "$sarif_dir" "$dir" "$repo" \
         "$branch" "$web" "$muted" "$(provider_link_parts)" "$primary" \
         > "${out}.new" 2>"$GHSCAN_TMPROOT/codeql.log"; then
    CODEQL_UNREAD="the CodeQL alerts could not be converted: $(tail -1 "$GHSCAN_TMPROOT/codeql.log" 2>/dev/null)"
    log_warn "[$repo] $CODEQL_UNREAD"
    rm -f "${out}.new"
    return 0
  fi
  mv "${out}.new" "$out"
  rm -rf "$sarif_dir"
  local n; n=$(jq '[.[] | select(.source == "codeql")] | length' "$out" 2>/dev/null || echo 0)
  local kept; kept=$(jq '[.[] | select(.source == "codeql" and .triage == "review")] | length' "$out" 2>/dev/null || echo 0)
  log_info "[$repo] $n CodeQL alert(s), $kept need a person"
}

# code_merge <primary_json> <extra_json...> -> one list, with agreement recorded
#
# Two engines pointing at the same line is the strongest signal either of them
# produces, and blending them into a single number throws it away.  So the
# finding says which engines saw it, and agreement raises confidence rather
# than adding a second row somebody has to dismiss.
code_merge() {
  local primary="$1"; shift
  local files=() f
  f=$(json_file "$primary" code_primary); files+=("$f")
  local extra
  for extra in "$@"; do
    [[ -n "$extra" && "$extra" != "[]" ]] || continue
    f=$(json_file "$extra" code_extra); files+=("$f")
  done
  (( ${#files[@]} > 1 )) || { printf '%s' "$primary"; return 0; }

  jq -s -c '
    add
    # Same file and within two lines of each other is the same thing seen
    # twice.  Exact line equality misses it: engines disagree about whether a
    # multi line call site starts at the call or the assignment.
    | group_by([ .file, ((.start_line // 0) / 3 | floor) ])
    | map(
        (map(.source) | unique) as $engines
        | (sort_by(if .source == "semgrep" then 0 else 1 end) | .[0]) as $best
        | $best + {
            engines: $engines,
            corroborated: (($engines | length) > 1),
            confidence: (if ($engines | length) > 1 then "high" else ($best.confidence // "unknown") end),
            engine_note: (if ($engines | length) > 1
                          then ("seen by " + ($engines | join(" and ")))
                          else ("seen only by " + ($engines[0] // "one engine")) end)
          }
      )
    | sort_by([ (if .severity == "critical" then 0 elif .severity == "high" then 1
                 elif .severity == "medium" then 2 else 3 end), .file ])' "${files[@]}" \
    2>/dev/null || printf '%s' "$primary"
}
