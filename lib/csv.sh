#!/usr/bin/env bash
# CSV views of the report, for spreadsheets and ticket imports.
# jq's @csv handles the quoting.
# shellcheck shell=bash

# Everything goes through this so a custom delimiter works the same everywhere.
_csv_rows() {
  local delim; delim=$(cfg '.output.csv.delimiter' ',')
  if [[ "$delim" == "," ]]; then
    cat
  else
    # @csv already quoted anything containing a comma, so swap bare ones only.
    awk -v d="$delim" '{ q=0; out="";
      for (i=1; i<=length($0); i++) { c=substr($0,i,1);
        if (c=="\"") q=!q;
        if (c=="," && !q) c=d;
        out=out c }
      print out }'
  fi
}

# One row per vulnerability. Severity, org, repo, branch, plus what you need
# to actually go fix it.
csv_vulnerabilities() {
  printf '%s' "$1" | jq -r '
    def s(f): (f as $v | if $v == null then "" else $v end) | tostring;
    ["severity","organization","repository","branch","vulnerability_id","aliases",
     "package","version","ecosystem","purl","fixed_in","fix_state","cvss_score",
     "cvss_vector","cwe","priority","known_exploited","kev_ransomware","kev_due_date",
     "epss_score","epss_percentile","reachability","reachability_reason",
     "dependency_direct","dependency_scope",
     "sources","state","title","reference","manifest"],
    ( .vulnerabilities[]? | [
        s(.severity), s(.organization), s(.repository), s(.branch),
        s(.id), ((.aliases // []) | join(" ")),
        s(.package.name), s(.package.version), s(.package.type), s(.package.purl),
        s(.fixed_in), s(.fix_state), s(.cvss_score), s(.cvss_vector),
        ((.cwe // []) | join(" ")),
        s(.priority), s(.known_exploited), s(.kev_ransomware), s(.kev_due_date),
        s(.epss_score), s(.epss_percentile),
        s(.reachability.verdict), s(.reachability.reason),
        s(.reachability.direct), s(.reachability.scope),
        ((.sources // [.source]) | map(select(. != null)) | join(" ")),
        s(.state), s(.title), s(.reference),
        ((.package.locations // []) | join(" "))
      ] )
    | @csv' | _csv_rows
}

# One row per secret. These are credentials, so they come out critical.
csv_secrets() {
  printf '%s' "$1" | jq -r '
    def s(f): (f as $v | if $v == null then "" else $v end) | tostring;
    ["severity","category","organization","repository","branch","all_branches","file","line",
     "detector","engines","confidence","classification","verified","exposure",
     "secret_redacted","secret_fingerprint","entropy","author_name","author_email",
     "author_login","committed_at","first_committed_at","commit","url","commit_url","blame_url"],
    ( .secrets[]? | . as $f | (.branches // [""])[] | . as $br | [
        s($f.severity), s($f.category), ($f.repository | split("/")[0]), s($f.repository),
        s($br), (($f.branches // []) | join(" ")),
        s($f.file), s($f.start_line), s($f.detector),
        (($f.engines // []) | join(" ")), s($f.confidence), s($f.classification),
        s($f.verified), s($f.exposure), s($f.secret_redacted), s($f.secret_fingerprint),
        s($f.entropy), s($f.author_name), s($f.author_email), s($f.author_login),
        s($f.committed_at), s($f.first_committed_at), s($f.commit), s($f.url),
        s($f.commit_url), s($f.blame_url)
      ] )
    | @csv' | _csv_rows
}

# Who can reach what. One row per user per repo, or per branch when
# output.csv.expand_branches is on.
csv_access() {
  local doc="$1" expand
  expand=$(cfg_bool '.output.csv.expand_branches' true && echo true || echo false)
  printf '%s' "$doc" | jq -r --argjson expand "$expand" '
    def s(f): (f as $v | if $v == null then "" else $v end) | tostring;
    ( [ .repositories[]? | {key: .repository.full_name, value: .} ] | from_entries ) as $repo_meta
    | ( [ .organizations[]? | {key: .login, value: .} ] | from_entries ) as $orgs
    | ["organization","repository","visibility","branch","branch_protected","login","user_type",
       "permission","affiliation","outside_collaborator","org_role","site_admin","two_factor",
       "repository_count","highest_permission","profile_url"],
      ( .access.users[]? | . as $u | $u.repositories[]? | . as $r
        | ($r.repository | split("/")[0]) as $org
        | ($repo_meta[$r.repository] // {}) as $meta
        | ($orgs[$org] // {}) as $o
        | (if ($o.members_without_2fa // null) == null then "unknown"
           elif ($o.members_without_2fa | map(ascii_downcase) | index($u.login | ascii_downcase)) != null then "disabled"
           else "enabled" end) as $tfa
        | ( [ $o.members[]? | select((.login | ascii_downcase) == ($u.login | ascii_downcase)) | .org_role ] | first // "" ) as $role
        | ( if $expand and (($meta.access.branches // []) | length) > 0
            then ($meta.access.branches[])
            else {name: "", protected: null} end ) as $b
        | [ $org, s($r.repository), s($meta.repository.visibility), s($b.name), s($b.protected),
            s($u.login), s($u.type), s($r.permission), s($r.affiliation),
            s($r.outside_collaborator), $role, s($u.site_admin), $tfa,
            s($u.repository_count), s($u.highest_permission), s($u.html_url) ]
      )
    | @csv' | _csv_rows
}

# Teams, invitations and deploy keys are access too, just not user accounts.
csv_access_nonuser() {
  printf '%s' "$1" | jq -r '
    def s(f): (f as $v | if $v == null then "" else $v end) | tostring;
    ["principal_type","organization","repository","principal","permission","detail"],
    ( .access.teams[]?      | . as $t | $t.repositories[]?
      | ["team", (.repository | split("/")[0]), s(.repository), s($t.slug), s(.permission),
         ("privacy=" + s($t.privacy))] ),
    ( .access.pending_invitations[]?
      | ["invitation", (.repository | split("/")[0]), s(.repository), s(.invitee),
         s(.permission), ("invited_by=" + s(.inviter) + " on " + s(.created_at))] ),
    ( .access.deploy_keys[]?
      | ["deploy_key", (.repository | split("/")[0]), s(.repository), s(.title),
         (if .read_only then "read" else "write" end),
         ("last_used=" + s(.last_used))] )
    | @csv' | _csv_rows
}

csv_write() {
  local content="$1" path="$2"
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
  printf '%s' "$path"
}

# One row per user per repo per target branch.
csv_pulls() {
  printf '%s' "$1" | jq -r '
    def s(f): (f as $v | if $v == null then "" else $v end) | tostring;
    ["username","user_type","organization","repository","branch","count",
     "merged_count","open_count","closed_count","first_pull_at","last_pull_at"],
    ( .pull_history.by_user_branch[]? | [
        s(.username), s(.user_type), s(.organization), s(.repository), s(.branch),
        s(.count), s(.merged_count), s(.open_count), s(.closed_count),
        s(.first_pull_at), s(.last_pull_at)
      ] )
    | @csv' | _csv_rows
}

# Code vulnerabilities from static analysis, one row each.
csv_misconfigurations() {
  printf '%s' "$1" | jq -r '
    def s(f): (f as $v | if $v == null then "" else $v end) | tostring;
    ["severity","organization","repository","branch","file","line","rule",
     "source","kind","provider","service","resource","triage","admins",
     "title","resolution","url"],
    ( .misconfigurations[]? | [
        s(.severity), s(.organization), s(.repository), s(.branch),
        s(.file), s(.start_line), s(.rule_id),
        s(.source), s(.configuration_kind), s(.provider), s(.service),
        s(.resource), s(.triage),
        ((.repository_admins // []) | join(" ")),
        s(.title), s(.resolution), s(.url)
      ] )
    | @csv' | _csv_rows
}

csv_code_findings() {
  printf '%s' "$1" | jq -r '
    def s(f): (f as $v | if $v == null then "" else $v end) | tostring;
    ["severity","organization","repository","branch","file","line","rule","cwe","owasp",
     "confidence","impact","likelihood","title","url"],
    ( .code_findings[]? | [
        s(.severity), s(.organization), s(.repository), s(.branch),
        s(.file), s(.start_line), s(.rule_name),
        ([ (.cwe_ids // []) | if type == "array" then .[] else . end | tostring ] | join(" ")),
        ([ (.owasp // []) | if type == "array" then .[] else . end | tostring ] | join("; ")),
        s(.confidence), s(.impact), s(.likelihood), s(.title), s(.url)
      ] )
    | @csv' | _csv_rows
}
