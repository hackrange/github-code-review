#!/usr/bin/env bash
# Exclusions: findings you have reviewed and accepted.
#
# One CSV covers credentials, code findings and package vulnerabilities. Nothing
# is deleted; excluded findings move to an `excluded` list with the reason and
# who signed it off, so the report still shows what was set aside and why.
# shellcheck shell=bash

# exclusions_load <csv> -> JSON array of rules
exclusions_load() {
  local csv="$1"
  [[ -n "$csv" && -r "$csv" ]] || { echo '[]'; return 0; }
  local py; py=$(ghscan_python)
  if [[ -z "$py" ]]; then
    log_warn "exclusions file needs python3 to parse; ignoring $csv"
    echo '[]'; return 0
  fi
  local out
  out=$("$py" "$GHSCAN_HOME/lib/csv_to_json.py" "$csv" 2>/dev/null) || {
    log_warn "could not parse exclusions CSV: $csv"
    echo '[]'; return 0
  }
  printf '%s' "$out" | jq -c '
    map({
      type:         ((.type // "any") | ascii_downcase),
      organization: (.organization // "*"),
      repository:   (.repository // "*"),
      path:         (.path // "*"),
      rule:         (.rule // "*"),
      fingerprint:  (.fingerprint // ""),
      reason:       (.reason // ""),
      reviewed_by:  (.reviewed_by // ""),
      reviewed_date:(.reviewed_date // ""),
      expires:      (.expires // ""),
      ticket:       (.ticket // "")
    })' 2>/dev/null || echo '[]'
}

# The matcher, shared by every finding type.
#   organization / repository  exact, or *
#   path / rule                glob
#   fingerprint                exact, secrets only, cred: prefix optional
#   expires                    a past date stops the rule working
# exclusions_partition <findings_json> <rules_json> -> {kept, excluded}
exclusions_partition() {
  local findings="$1" rules="$2"

  # Both of these go through files.  A repository with a thousand findings is
  # megabytes of JSON, and anything that reaches jq through argv hits the
  # command line limit and takes the whole scan down with it.
  local f_rules; f_rules=$(json_file "$rules" rules)
  local f_err;   f_err=$(tmp_file exclerr)
  local out

  if out=$(printf '%s' "$findings" | jq -c \
    --slurpfile rules_in "$f_rules" \
    --arg today "$(date -u +%Y-%m-%d)" '
    # Glob to regex. gsub hands the replacement a capture object, so the
    # metacharacter has to come through a named capture.
    def globmatch($pat; $s):
      if $pat == "" or $pat == "*" then true
      else ($s // "") | test("^" + ($pat
            | gsub("(?<c>[.+^$(){}\\[\\]|\\\\])"; "\\\(.c)")
            | gsub("\\*"; ".*")
            | gsub("\\?"; ".")) + "$"; "i")
      end;
    def repo_match($pat; $repo):
      if $pat == "" or $pat == "*" then true
      else (globmatch($pat; $repo) or globmatch($pat; ($repo | split("/") | last))) end;

    def kind:
      (.category // .finding_type // "") as $c
      | if ($c | test("credential")) then "secret"
        elif ($c | test("misconfiguration")) then "misconfig"
        elif ($c | test("code")) then "code"
        else "vuln" end;

    ($rules_in[0] // []) as $rules
    | . as $findings
    | [ $findings[]
        | . as $f
        | ($f.file // "") as $path
        | ([ $f.rule_name, $f.detector, $f.rule_id, $f.id ] | map(select(. != null and . != ""))) as $ids
        | ($f | kind) as $k
        | ($f.organization // (($f.repository // "") | split("/")[0])) as $org
        | ( [ $rules[]
              | . as $r
              | select($r.expires == "" or $r.expires >= $today)
              | select($r.type == "any" or $r.type == $k)
              | select(globmatch($r.organization; $org))
              | select(repo_match($r.repository; ($f.repository // "")))
              | select(globmatch($r.path; $path))
              # A rule may carry the fingerprint in either form: the CSV is
              # written with the bare hash, but one hand-written or moved from
              # an older installation keeps the cred: the findings are keyed by.
              | select($r.fingerprint == ""
                       or ($r.fingerprint | ascii_downcase | sub("^cred:"; ""))
                          == (($f.secret_fingerprint // "") | ascii_downcase))
              | select($r.rule == "" or $r.rule == "*" or any($ids[]; . as $i | globmatch($r.rule; $i)))
            ] | first ) as $hit
        | $f + {_excl: $hit}
      ]
    | {
        kept:     [ .[] | select(._excl == null) | del(._excl) ],
        excluded: [ .[] | select(._excl != null)
                    | {repository, file, organization,
                       rule: (.rule_name // .detector // .rule_id // .id),
                       severity, line: (.start_line // null),
                       secret_fingerprint: (.secret_fingerprint // null),
                       excluded_by: {reason: ._excl.reason, reviewed_by: ._excl.reviewed_by,
                                     reviewed_date: ._excl.reviewed_date, expires: ._excl.expires,
                                     ticket: ._excl.ticket, matched_path: ._excl.path,
                                     matched_rule: ._excl.rule}} ]
      }' 2>"$f_err"); then
    printf '%s' "$out"
    return 0
  fi

  # Falling back means nothing gets excluded, which is the safe direction: a
  # finding somebody accepted shows up again rather than a real one going
  # missing.  Say why, though.  This used to hide the reason and then fall over
  # trying to hand the same findings to jq on the command line.
  log_warn "could not apply exclusions, reporting everything: $(tail -2 "$f_err" | tr '\n' ' ')"
  local f_findings; f_findings=$(json_file "$findings" findings)
  jq -cn --slurpfile f "$f_findings" '{kept: $f[0], excluded: []}'
}

# Warn about rules that have lapsed, so exceptions do not quietly become permanent.
exclusions_report_expired() {
  local rules="$1"
  local today; today=$(date -u +%Y-%m-%d)
  local n; n=$(printf '%s' "$rules" | jq --arg t "$today" '[ .[] | select(.expires != "" and .expires < $t) ] | length')
  (( n > 0 )) && log_warn "$n exclusion rule(s) have expired and are no longer suppressing anything"
  printf '%s' "$rules" | jq -c --arg t "$today" '[ .[] | select(.expires != "" and .expires < $t)
    | {repository, path, rule, expires, reviewed_by, ticket} ]'
}
