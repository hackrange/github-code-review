#!/usr/bin/env bash
# The findings again, in the format everything else already reads.
#
# The reasoning is in lib/sarif.py.  This is the part that decides where python
# is and what to do when the answer is nowhere.
# shellcheck shell=bash

_sarif_engine() { printf '%s' "$GHSCAN_HOME/lib/sarif.py"; }

# sarif_available -> 0 if a SARIF file can be produced at all
sarif_available() {
  local engine; engine=$(_sarif_engine)
  [[ -r "$engine" ]] || return 1
  local python; python=$(ghscan_python)
  [[ -n "$python" ]] || return 1
  return 0
}

# sarif_convert <input.json> <flags...> -> the document on stdout
#
# Nothing here catches a failure.  The two callers below both have somewhere
# sensible to put one, and they do different things about it.
sarif_convert() {
  local input="$1"; shift
  local python; python=$(ghscan_python)
  "$python" "$(_sarif_engine)" "$input" "$@"
}

# sarif_write <report_doc> <path> -> the path it wrote, on stdout
#
# The document arrives as a string and goes to python through a file.  Reports
# from a real estate run to tens of megabytes, and handing one of those over on
# argv is how a scan dies at the last step with every repository already done.
sarif_write() {
  local doc="$1" path="$2"
  local dir; dir=$(dirname "$path")
  mkdir -p "$dir"

  local src; src=$(json_file "$doc" sarifin)
  local args=("$src")
  cfg_bool '.output.pretty' true && args+=(--pretty)

  if ! sarif_convert "${args[@]}" > "$path" 2>"$GHSCAN_TMPROOT/sarif.log"; then
    # A report that exists is worth more than a SARIF file that does not, so
    # this never takes the scan down with it.
    log_warn "SARIF was not written: $(tail -1 "$GHSCAN_TMPROOT/sarif.log" 2>/dev/null)"
    rm -f "$path"
    return 1
  fi

  if cfg_bool '.output.gzip' false; then
    gzip -f "$path" && path="${path}.gz"
  fi
  printf '%s' "$path"
}

# sarif_review <review_doc> [<owner/name>] -> the document on stdout
#
# The review path prints to stdout rather than writing a file, because that is
# what a pipeline redirects and what the documentation already tells people to
# expect.  A repository name is optional and worth passing: without it the code
# findings still get stable fingerprints, they are just not the same ones a
# scan of that repository would produce.
sarif_review() {
  local doc="$1" repo="${2:-}"
  local src; src=$(json_file "$doc" sarifrev)
  local args=("$src" --review --pretty)
  [[ -n "$repo" ]] && args+=(--repository "$repo")
  sarif_convert "${args[@]}"
}
