#!/usr/bin/env bash
# Container images: the layer underneath the application.
#
# syft and grype are pointed at a source checkout everywhere else, so the
# operating system packages, the base image and everything the build installs
# go unexamined.  On most applications that is where the critical count
# actually lives, and a four year old base image is the commonest way an estate
# carries hundreds of criticals nobody has ever seen.
#
# Two ways in, and they are the same feature.  From the Dockerfiles in the
# checkout, which needs nothing from anybody, and from a reference handed in by
# a pipeline that has just built something.
#
# Nothing is built.  A Dockerfile is read for the base image it names and that
# image is pulled and read.  Building a checkout is a different feature with a
# different risk, and it is not this one.
# shellcheck shell=bash

# How many distinct images one repository is worth pulling.  A monorepo with
# forty Dockerfiles is usually forty tags of the same two bases, and the cap
# stops one repository spending the whole scan window on downloads.
IMAGES_MAX_PER_REPO="${IMAGES_MAX_PER_REPO:-6}"

# images_from_dockerfiles <dir> -> JSON array of {ref, dockerfile}
#
# Reads FROM lines.  A stage alias is not an image, `scratch` is not an image,
# and a reference still carrying an unresolved variable is not one either: a
# guess at what ${BASE} was meant to be would be scanned and reported as though
# somebody had written it.
images_from_dockerfiles() {
  local dir="$1"
  [[ -d "$dir" ]] || { echo '[]'; return 0; }

  local py; py=$(ghscan_python)
  [[ -n "$py" ]] || { echo '[]'; return 0; }

  "$py" - "$dir" "$IMAGES_MAX_PER_REPO" <<'PY' 2>/dev/null || echo '[]'
import json, os, re, sys

root, cap = sys.argv[1], int(sys.argv[2])
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "site-packages",
             "third_party", "dist", "build", ".terraform"}
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+[Aa][Ss]\s+(\S+))?",
                  re.M)
ARG = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)", re.M)
VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")

out, seen = [], set()
for base, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
    for name in files:
        low = name.lower()
        if low != "dockerfile" and not low.startswith("dockerfile."):
            continue
        path = os.path.join(base, name)
        try:
            if os.path.getsize(path) > 512 * 1024:
                continue
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue

        args = dict(ARG.findall(text))
        # A stage has to be declared before it can be used as a FROM, so one
        # pass in file order is enough to tell "FROM builder" (an earlier stage
        # in this same file) from "FROM builder:latest" (an image).
        stages = set()
        for match in FROM.finditer(text):
            ref = match.group(1)
            alias = (match.group(2) or "").lower()
            resolved = VAR.sub(lambda m: args.get(m.group(1), m.group(0)), ref)
            low = resolved.lower()
            is_stage = low in stages
            if alias:
                stages.add(alias)
            if low == "scratch" or is_stage or "$" in resolved:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            out.append({"ref": resolved,
                        "dockerfile": os.path.relpath(path, root)})
            if len(out) >= cap:
                print(json.dumps(out)); raise SystemExit(0)
print(json.dumps(out))
PY
}

# images_vulns <ref> <full_name> <dockerfile> -> JSON array in the vulnerability shape
#
# grype reads a registry directly, so there is no daemon here and nothing is
# built.  A pull that fails is a warning and an empty list: a base image behind
# a private registry nobody gave us a credential for is not a scan failure.
images_vulns() {
  local ref="$1" full_name="$2" dockerfile="${3:-}"
  have_cmd grype || { log_debug "grype not installed, skipping images"; echo '[]'; return 0; }

  local out; out=$(tmp_file image_grype)
  local timeout_sec; timeout_sec=$(cfg_num '.scan.images.timeout_sec' 600)

  if ! GRYPE_CHECK_FOR_APP_UPDATE=false timeout "$timeout_sec" \
        grype "registry:$ref" -o json -q > "$out" 2>"$GHSCAN_TMPROOT/image.log"; then
    log_warn "$full_name: could not read image $ref: $(tail -1 "$GHSCAN_TMPROOT/image.log" | tr -d '\n')"
    echo '[]'; return 0
  fi

  # The same shape vulns_grype produces, so everything downstream, the merge,
  # the threat intel and the report, treats these as what they are: dependency
  # findings that happen to live in a layer rather than a manifest.
  jq -c --arg image "$ref" --arg dockerfile "$dockerfile" '
    [ (.matches // [])[] | {
      source: "grype-image",
      id: (.vulnerability.id // "UNKNOWN"),
      aliases: ([ (.relatedVulnerabilities // [])[].id ] | unique),
      severity: ((.vulnerability.severity // "unknown") | ascii_downcase),
      cvss_score: ( [ ((.vulnerability.cvss // [])[] | .metrics.baseScore) ] | map(select(. != null)) | max ),
      title: (.vulnerability.description // null),
      package: {
        name: (.artifact.name // null),
        version: (.artifact.version // null),
        type: (.artifact.type // null),
        purl: (.artifact.purl // null),
        locations: [ $image ]
      },
      image: $image,
      dockerfile: $dockerfile,
      fixed_in: ((.vulnerability.fix.versions // []) | join(", ") | select(. != "")),
      fix_state: (.vulnerability.fix.state // "unknown"),
      cwe: ( [ (.vulnerability.cwe // empty) ] | flatten | unique ),
      urls: (.vulnerability.urls // []),
      reference: (.vulnerability.dataSource // null),
      state: "open",
      # A package in a base image is not reached by reading the application
      # source, and saying "unlikely" on that basis would be wrong: it is in
      # the running container whether or not this repository imports it.
      reachability: {
        verdict: "unknown",
        reason: ("shipped in the image " + $image + ", which the application source says nothing about"),
        ecosystem: ((.artifact.type // "unknown") | tostring),
        direct: "unknown",
        scope: "runtime"
      }
    } ]' "$out" 2>/dev/null || echo '[]'
}

# images_scan <dir> <full_name> -> JSON array of vulnerabilities across every
# base image the checkout names.
images_scan() {
  local dir="$1" full_name="$2"
  local found; found=$(images_from_dockerfiles "$dir")
  local count; count=$(printf '%s' "$found" | jq 'length')
  (( count > 0 )) || { echo '[]'; return 0; }

  log_info "[$full_name] $count base image(s) named in Dockerfiles"

  local acc; acc=$(tmp_file image_acc); echo '[]' > "$acc"
  local ref dockerfile part
  while IFS=$'\t' read -r ref dockerfile; do
    [[ -n "$ref" ]] || continue
    log_debug "[$full_name] reading image $ref"
    part=$(tmp_file image_part)
    images_vulns "$ref" "$full_name" "$dockerfile" > "$part"
    jq -s -c 'add' "$acc" "$part" > "$acc.new" 2>/dev/null && mv "$acc.new" "$acc"
  done < <(printf '%s' "$found" | jq -r '.[] | [.ref, .dockerfile] | @tsv')

  cat "$acc"
}
