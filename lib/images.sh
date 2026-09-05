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

# images_from_dockerfiles <dir> -> JSON array of {ref, dockerfile, upgraded}
#
# Reads FROM lines.  A stage alias is not an image, `scratch` is not an image,
# and a reference still carrying an unresolved variable is not one either: a
# guess at what ${BASE} was meant to be would be scanned and reported as though
# somebody had written it.
#
# `upgraded` says whether the build patches this base after pulling it, and it
# is worked out per stage rather than per file, which is the whole difficulty.
#
# A base image is scanned as the registry publishes it, because that is all
# there is to scan: nothing here builds anything.  So a Dockerfile that runs
# apt-get upgrade three lines below its FROM produces a report describing
# packages that the image being reported on does not contain.  That is how
# eighty six advisories against this project's own base survived a build that
# had already fixed them.
#
# Answering it with a grep over the file would be worse than not answering it.
# A multi stage build upgrades in the builder and ships from somewhere else
# entirely, and the packages that ship are the ones in the last stage.  So the
# question asked here is narrow: does the stage that actually ships patch
# itself, or inherit from a stage that did.  Everything else reports false.
#
# And it is only ever a likelihood, never a suppression.  An upgrade moves
# packages to whatever the archive held on the day the image was built, which
# for an image built in March is March, and says nothing at all about an
# advisory published since.  The finding stays.
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

# The package managers, and the words each uses for "bring everything current".
# apt update alone is not one of them: it refreshes the list and installs
# nothing, and treating it as a patch would clear findings on a build that
# never applied one.
UPGRADE = re.compile(
    r"\b(?:"
    r"apt-get\s+(?:[-\w=]+\s+)*(?:upgrade|dist-upgrade)"
    r"|apt\s+(?:[-\w=]+\s+)*(?:upgrade|full-upgrade|dist-upgrade)"
    r"|(?:dnf|yum|microdnf)\s+(?:[-\w=]+\s+)*(?:update|upgrade)"
    r"|zypper\s+(?:[-\w=]+\s+)*(?:update|up|dup|dist-upgrade)"
    r"|apk\s+(?:[-\w=]+\s+)*upgrade"
    r"|pacman\s+[-\w]*Syu"
    r")\b", re.I)


def joined(text):
    """Line continuations folded, so a chained RUN reads as one line.

    Nearly every upgrade in a real Dockerfile is the second half of
    `RUN apt-get update \\` and a pattern that reads line by line misses all
    of them.
    """
    return re.sub(r"\\\s*\n", " ", text)


def stages_of(text, args):
    """Every FROM, with the body that belongs to it.

    The body of a stage runs from its FROM to the next one, which is what
    decides whether that particular stage patched itself.
    """
    found = list(FROM.finditer(text))
    out = []
    for i, match in enumerate(found):
        end = found[i + 1].start() if i + 1 < len(found) else len(text)
        ref = VAR.sub(lambda m: args.get(m.group(1), m.group(0)), match.group(1))
        out.append({"ref": ref,
                    "alias": (match.group(2) or "").lower(),
                    "body": text[match.end():end]})
    return out


def ships_from(stages):
    """-> (index of the stage whose base is what ships, upgraded)

    The last stage is what a build produces.  Its base may be another stage,
    so the chain is followed to the image it ultimately rests on, and an
    upgrade anywhere along that chain counts: a builder that patched itself
    and is then FROMed carries the patched packages forward.
    """
    if not stages:
        return None, False
    by_alias = {s["alias"]: i for i, s in enumerate(stages) if s["alias"]}
    index = len(stages) - 1
    upgraded = False
    seen = set()
    while True:
        if index in seen:                 # a cycle cannot happen in a valid
            break                         # Dockerfile, but never loop forever
        seen.add(index)
        stage = stages[index]
        if UPGRADE.search(joined(stage["body"])):
            upgraded = True
        parent = by_alias.get(stage["ref"].lower())
        if parent is None or parent == index:
            return index, upgraded
        index = parent
    return index, upgraded


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
        stages = stages_of(text, args)
        ship_index, ship_upgraded = ships_from(stages)

        declared = set()
        for i, stage in enumerate(stages):
            resolved = stage["ref"]
            low = resolved.lower()
            is_stage = low in declared
            if stage["alias"]:
                declared.add(stage["alias"])
            if low == "scratch" or is_stage or "$" in resolved:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            # Only the base the shipped artifact actually rests on gets to
            # carry the upgrade.  A builder that patches itself says nothing
            # about a runtime stage that does not.
            #
            # Matched on the reference rather than the stage index, because a
            # two stage build routinely names the same base twice and the
            # first occurrence is the builder.  Keyed by index, the entry that
            # survives deduplication is the builder's, and a runtime stage that
            # patches itself is reported as though it had not.
            ship_ref = stages[ship_index]["ref"].lower() if ship_index is not None else ""
            upgraded = bool(ship_upgraded and low == ship_ref)
            out.append({"ref": resolved,
                        "dockerfile": os.path.relpath(path, root),
                        "upgraded": upgraded})
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
  local ref="$1" full_name="$2" dockerfile="${3:-}" upgraded="${4:-false}"
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
  jq -c --arg image "$ref" --arg dockerfile "$dockerfile" \
        --argjson upgraded "${upgraded:-false}" '
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
        # The package this one was built from.
        #
        # A distribution ships one source package as many binary ones, and a
        # vulnerability in the source is reported against every binary that
        # came out of it.  One flaw in util-linux arrives as eight findings
        # against bsdutils, libblkid1, libmount1, libsmartcols1, libuuid1,
        # login, mount and util-linux, and one apt upgrade answers all eight.
        # Without this the interface has no way to know they are the same job.
        #
        # Two spellings because two shapes are in the wild: upstreams is what
        # a current grype writes, and the metadata the dpkg cataloger
        # records is what older output has.  Neither exists for something that is not a
        # distribution package, and null is the right answer there.
        source: (.artifact.upstreams[0].name // .artifact.metadata.source // null),
        locations: [ $image ]
      },
      image: $image,
      dockerfile: $dockerfile,
      # Whether the build patches this base after pulling it.  Not a fix and
      # not a suppression: the finding is true of the image in the registry,
      # and this says the image that ships is probably not that one.  What it
      # buys is a place in the queue, further down, with the reason attached.
      base_upgraded: $upgraded,
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
  while IFS=$'\t' read -r ref dockerfile upgraded; do
    [[ -n "$ref" ]] || continue
    log_debug "[$full_name] reading image $ref"
    part=$(tmp_file image_part)
    images_vulns "$ref" "$full_name" "$dockerfile" "$upgraded" > "$part"
    jq -s -c 'add' "$acc" "$part" > "$acc.new" 2>/dev/null && mv "$acc.new" "$acc"
  done < <(printf '%s' "$found" | jq -r '.[] | [.ref, .dockerfile, (.upgraded // false)] | @tsv')

  cat "$acc"
}
