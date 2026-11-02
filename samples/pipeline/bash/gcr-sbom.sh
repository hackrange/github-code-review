#!/usr/bin/env bash
# Download a repository's SBOM, to attach to a build or a release.
#
#   gcr-sbom.sh [-r org/name] [-f cdx|spdx] [-o file]
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

repo="" fmt="cdx" out=""
while (( $# )); do
  case "$1" in
    -r|--repo) repo="$2"; shift 2 ;;
    -f|--format) fmt="$2"; shift 2 ;;
    -o|--out) out="$2"; shift 2 ;;
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done
repo="$(gcr_default_repo "$repo")"
[[ -n "$repo" ]] || { echo "Give -r org/name, or run inside GitHub Actions." >&2; exit 3; }
out="${out:-${repo//\//__}.$fmt.json}"

# The slash in the repository name stays a slash in the path.
gcr_get "/sbom/$repo" "format=$fmt" > "$out" || { rm -f "$out"; exit 3; }
components="$(jq '(.components // .packages // []) | length' "$out")"
echo "Wrote $out, $(wc -c < "$out") bytes, $components component(s)."
