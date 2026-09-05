#!/usr/bin/env bash
# The build pipeline, read as code.
#
# .github/workflows was text in a clone and nothing more.  It is also the most
# attacked part of a modern repository: a pull_request_target that checks out an
# untrusted head, an issue title interpolated straight into a run block, a third
# party action pinned to a tag somebody else can move, secrets handed to a
# workflow a fork can trigger.  Those take the whole organization rather than
# one service, which is what makes them worth their own pass.
#
# zizmor does the reading.  There is an advantage here no hosted competitor has:
# this clones every branch, so it sees the workflow on the branch somebody is
# still writing rather than only the one on main.
# shellcheck shell=bash

# run_zizmor <dir> <full_name> <out_json>
run_zizmor() {
  local dir="$1" full_name="$2" out="$3"
  have_cmd zizmor || {
    log_warn "zizmor is not on the path, so nothing looked at the workflows"
    echo '[]' > "$out"; return 0; }

  # Nothing to do is the common case, and zizmor treats a directory with no
  # workflows as an error rather than as a quiet day.
  if [[ ! -d "$dir/.github/workflows" ]]; then
    log_debug "$full_name: no .github/workflows, so nothing to audit"
    echo '[]' > "$out"; return 0
  fi

  local args=(. --format json --no-progress)
  local persona; persona=$(cfg '.scan.workflows.persona' 'regular')
  args+=(--persona "$persona")

  # Offline by default.  Some audits ask GitHub about an action, which needs a
  # token, and handing this tool's credential to another binary is a decision
  # somebody should make on purpose rather than inherit.
  local token_env=()
  if cfg_bool '.scan.workflows.offline' true; then
    args+=(--offline)
  elif [[ -n "${GHSCAN_TOKEN:-}" ]]; then
    # Through the environment, never on argv, so it stays out of ps output.
    token_env=(env "GH_TOKEN=$GHSCAN_TOKEN")
  fi

  local timeout_s; timeout_s=$(cfg_num '.scan.workflows.timeout_sec' 300)
  log_debug "$full_name: zizmor ${args[*]}"
  # zizmor exits non-zero to say how bad the worst finding was, so a failure
  # here is not a failure.  What matters is whether the output parses.
  ( cd "$dir" && with_timeout "$timeout_s" "${token_env[@]}" zizmor "${args[@]}" ) \
    > "$out" 2>"$GHSCAN_TMPROOT/zizmor.log" || true
  jq -e 'type == "array"' "$out" >/dev/null 2>&1 || {
    log_warn "$full_name: zizmor produced nothing usable: $(tail -1 "$GHSCAN_TMPROOT/zizmor.log" 2>/dev/null)"
    echo '[]' > "$out"; }
}

# normalize_zizmor <in> <repo> <branch> <web> -> json array of findings
#
# The same shape the infrastructure pass writes, because a workflow problem is a
# misconfiguration too and one new finding kind is enough.
#
# Dropped on purpose: every location carries `concrete.feature`, which is the
# offending lines of the workflow itself.  A workflow is a place people put
# credentials, and this is the same call the infrastructure pass makes.  The
# line number says where to look.
normalize_zizmor() {
  local in="$1" repo="$2" branch="$3" web="$4"
  jq -c --arg repo "$repo" --arg br "$branch" --arg web "$web" '
    def clean($p): ($p // "") | sub("^\\./"; "");

    [ .[]?
      | select(.ignored != true)
      | . as $f
      # A finding can point at several places.  The primary one is where the
      # problem is; the rest are what led to it.
      | ((.locations // []) | map(select(.symbolic.kind == "Primary")) | first
         // ((.locations // []) | first) // {}) as $loc
      | (clean($loc.symbolic.key.Local.verbatim_path)) as $file
      # zizmor counts rows from zero, and every other engine here counts lines
      # from one.  Getting this wrong puts each finding one line above itself.
      | (($loc.concrete.location.start_point.row // 0) + 1) as $line
      | (($loc.concrete.location.end_point.row // 0) + 1) as $end
      | {
          organization: ($repo | split("/")[0]),
          repository: $repo,
          repository_name: ($repo | split("/")[1]),
          branch: $br,
          source: "zizmor",
          category: "misconfiguration",
          finding_type: "workflow",
          configuration_kind: "github_actions",
          rule_id: ($f.ident // "unknown"),
          rule_name: ($f.ident // "unknown"),
          title: ($f.desc // ""),
          message: ([ ($f.desc // ""), ($loc.symbolic.annotation // "") ]
                    | map(select(. != "")) | join(": ")),
          description: ($f.desc // ""),
          resolution: (((.fixes // []) | first | .title) // ""),
          resource: ($loc.symbolic.annotation // ""),
          provider: "GitHub Actions",
          service: "workflow",
          file: $file,
          start_line: $line,
          end_line: (if $end >= $line then $end else $line end),
          start_column: 0,
          end_column: 0,
          severity: (($f.determinations.severity // "Unknown") | ascii_downcase
                     | if . == "high" then "high"
                       elif . == "medium" then "medium"
                       elif . == "low" then "low"
                       elif . == "informational" then "info"
                       else "unknown" end),
          engine_severity: ($f.determinations.severity // null),
          confidence: (($f.determinations.confidence // "unknown") | ascii_downcase),
          references: [],
          url: (if $file == "" then $web + "/" + $repo
                else $web + "/" + $repo + "/blob/" + $br + "/" + $file
                     + "#L" + ($line | tostring) end),
          help_url: ($f.url // ""),
          # A workflow is not a place with examples and fixtures in it the way a
          # terraform tree is, so there is nothing here to grade aside.  Saying
          # "review" plainly is better than inventing a rule to look busy.
          triage: "review",
          triage_reason: "",
          state: "open"
        } ]
    | sort_by([ (if .severity == "critical" then 0 elif .severity == "high" then 1
                 elif .severity == "medium" then 2 else 3 end), .file, .start_line ])' \
    "$in" 2>/dev/null || echo '[]'
}

# workflows_add_admins <findings_json> <access_json> -> findings with owners
#
# The point of the whole pass.  "An outsider can trigger this workflow" is a
# fact; "and here are the four people who could have stopped it" is something
# somebody can act on this afternoon.  Both halves are already in the same scan
# and nothing was putting them next to each other.
workflows_add_admins() {
  local findings="$1" access="$2"
  [[ -z "$findings" || "$findings" == "[]" ]] && { printf '[]'; return 0; }
  [[ -z "$access" || "$access" == "null" ]] && { printf '%s' "$findings"; return 0; }

  local f_find f_acc
  f_find=$(json_file "$findings" wfind)
  f_acc=$(json_file "$access" wacc)
  jq -c --slurpfile acc "$f_acc" '
    ([ ($acc[0].users // [])[] | select(.permission == "admin") | .login ]
     | unique) as $admins
    | [ .[] | . + {repository_admins: $admins} ]' "$f_find" 2>/dev/null \
    || printf '%s' "$findings"
}
