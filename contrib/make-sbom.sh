#!/usr/bin/env bash
# Build the SBOM for a release, in both formats.
#
# CycloneDX and SPDX say the same thing in different shapes.  Which one you
# need depends on who is asking, so we publish both rather than argue about it.
#
#   contrib/make-sbom.sh [source-dir] [out-dir]
#
# syft comes from the app image, so there is nothing to install first.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# What ships is what the SBOM has to describe, and `shipping/repo` is that
# tree exactly: rebuilt from what git would publish before every release.
#
# The repository root is not the same thing and must not be the default.  It
# holds the virtualenv, the scan output and a second copy of the source, and
# syft cannot tell any of that apart from the product.  Run this at the root
# once and you get two hundred components, most of them pip's own vendored
# binaries, in a document that says the product depends on them.  Somebody
# then sends that to a customer.
SRC="${1:-}"
if [[ -z "$SRC" ]]; then
  if [[ -d "$ROOT/shipping/repo" ]]; then
    SRC="$ROOT/shipping/repo"
  else
    echo "no shipping/repo to describe.  Stage it first, or name a source" >&2
    echo "directory: contrib/make-sbom.sh <source-dir>" >&2
    exit 1
  fi
fi

OUT="${2:-$ROOT/shipping/sbom}"
NAME="github-code-review"
VERSION="$(grep -oE '^VERSION = "[^"]+"' "$ROOT/app/config.py" | cut -d'"' -f2)"
IMAGE="${GCR_IMAGE:-github-code-review:$VERSION}"
AUTHOR="Tim Rice <tim.j.rice@hackrange.com>"

# On the machine, but not in the product.  These matter when somebody points
# this at a working tree by hand, which the default no longer does.
# Dot directories are swept as a class rather than one at a time.  None of
# them is ever a source of what the product depends on, and listing them by
# name means this file has to be edited every time somebody adds a tool.
EXCLUDE=(--exclude './.*/**'
         --exclude './venv/**' --exclude './node_modules/**'
         --exclude './shipping/**' --exclude './out/**' --exclude './work/**'
         --exclude './db/**' --exclude './reports/**')

command -v docker >/dev/null || { echo "docker is needed for syft" >&2; exit 1; }
mkdir -p "$OUT"

# Built somewhere else and moved into place at the end, so a run that turns
# out to be wrong leaves the last good SBOM where it was.  The alternative is
# what it sounds like: one bad run and the only correct document you had is
# gone, with nothing to compare the next one against.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

run_syft() {
  docker run --rm --entrypoint syft -v "$(cd "$SRC" && pwd):/src:ro" "$IMAGE" \
    dir:/src --source-name "$NAME" --source-version "$VERSION" \
    "${EXCLUDE[@]}" -o "$1=/dev/stdout" -q 2>/dev/null
}

# syft does not know who wrote this, so the author goes on afterward.  Both
# formats have a place for it and procurement asks for it every time.
run_syft cyclonedx-json \
  | jq --arg a "$AUTHOR" '.metadata.authors = [{name: $a}]
                          | .metadata.supplier = {name: $a}' \
  > "$STAGE/$NAME-$VERSION.cdx.json"

run_syft spdx-json \
  | jq --arg a "Person: $AUTHOR" \
       '.creationInfo.creators = ((.creationInfo.creators // []) + [$a] | unique)' \
  > "$STAGE/$NAME-$VERSION.spdx.json"

for f in "$STAGE/$NAME-$VERSION.cdx.json" "$STAGE/$NAME-$VERSION.spdx.json"; do
  jq -e . "$f" >/dev/null || { echo "not valid JSON: $f" >&2; exit 1; }
done

# Say so rather than write it.  A component found somewhere that is not the
# product means an exclude did not hold, and an SBOM of this machine handed to
# somebody as an SBOM of the product is worse than having none at all.
# grep exits 1 when it finds nothing, which is the case we want, so the
# status is thrown away and the emptiness of the output is what is read.
strays=$(grep -oE '/(venv|shipping|node_modules|site-packages|dist-info)/' \
           "$STAGE/$NAME-$VERSION.cdx.json" | sort -u | head -5 || true)
if [[ -n "$strays" ]]; then
  echo "this SBOM describes more than the product.  Found paths under:" >&2
  echo "$strays" | sed 's/^/  /' >&2
  echo "source was: $SRC" >&2
  echo "nothing was written; the SBOM already in $OUT is untouched" >&2
  exit 1
fi

mv "$STAGE/$NAME-$VERSION.cdx.json" "$STAGE/$NAME-$VERSION.spdx.json" "$OUT/"

echo "  source: ${SRC#$ROOT/}"
for f in "$OUT/$NAME-$VERSION.cdx.json" "$OUT/$NAME-$VERSION.spdx.json"; do
  printf '  %s  %s bytes  %s component(s)\n' "${f#$ROOT/}" "$(wc -c < "$f")" \
    "$(jq '[.components[]? // .packages[]?] | length' "$f")"
done

( cd "$OUT" && sha256sum "$NAME-$VERSION".*.json > "$NAME-$VERSION.sha256" )
echo "  checksums written"
