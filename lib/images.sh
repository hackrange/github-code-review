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
#
# The words between the tool and its verb can be anything that stays inside
# one command, such as -o Dpkg::Options::=--force-confold, so they are read
# up to the next ; & | or line end rather than as a list of known option
# shapes.  The verb must stand on its own: --only-upgrade foo patches one
# package, and update-motd is a package name, so neither counts.
UPGRADE = re.compile(
    r"\b(?:apt-get|apt)\b[^;&|\n]*?\s(?:dist-|full-)?upgrade(?=[\s;&|]|$)"
    r"|\b(?:dnf|yum|microdnf)\b[^;&|\n]*?\s(?:update|upgrade|distro-sync)(?=[\s;&|]|$)"
    r"|\bzypper\b[^;&|\n]*?\s(?:update|up|dup|dist-upgrade)(?=[\s;&|]|$)"
    r"|\bapk\b[^;&|\n]*?\supgrade(?=[\s;&|]|$)"
    r"|\bpacman\s+[-\w]*Syu", re.I)


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

# --- the image the repository publishes ------------------------------------
#
# Everything above reads the base image a Dockerfile starts from.  This reads
# the image the repository itself builds and publishes, which is what a server
# runs, and which differs from the checkout in ways reading the checkout never
# shows: a sudoers rule a layer adds, a backup somebody left in the build
# context, a credential written in one layer and deleted in the next, source
# files copied in from outside the repository.
#
# Which images: only ones the repository names literally, as a compose service
# that builds from it and tags an image, or a workflow step that pushes a named
# tag.  See lib/image_check.py shipped_refs.  The pull is lib/image_fetch.py:
# HTTPS only, public addresses only unless the settings allow private ones,
# every connection pinned to the address that was checked, and the layers read
# as streams into the scan root, which is memory.
#
# IMAGE_CONTENT_DIRS holds "ref<TAB>dir" for each image that was read whole.
# IMAGE_UNREAD says why one was not, and the app holds that repository's image
# findings open rather than closing them for silence.

IMAGE_CONTENT_DIRS=()
IMAGE_UNREAD=""

# image_contents_prepare <clone_dir> <full_name>
# Called in this shell, not in $( ), so the two variables survive.
image_contents_prepare() {
  local dir="$1" full_name="$2"
  IMAGE_CONTENT_DIRS=(); IMAGE_UNREAD=""
  cfg_bool '.scan.images.contents' false || return 0
  [[ -d "$dir" ]] || return 0
  local py; py=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
  if [[ -z "$py" ]]; then
    IMAGE_UNREAD="no python to read the published image"
    return 0
  fi
  local cap; cap=$(cfg_num '.scan.images.contents_max_images' 3)
  local refs
  refs=$("$py" -I "$GHSCAN_HOME/lib/image_check.py" refs "$dir" "$cap" 2>"$GHSCAN_TMPROOT/imagerefs.log") || refs='[]'
  [[ "$refs" == \[* ]] || refs='[]'
  local n; n=$(printf '%s' "$refs" | jq 'length')
  (( n > 0 )) || return 0

  local max_mb; max_mb=$(cfg_num '.scan.images.contents_max_mb' 512)
  local timeout_sec; timeout_sec=$(cfg_num '.scan.images.timeout_sec' 600)
  local -a flags=("--max-mb=$max_mb")
  cfg_bool '.scan.images.allow_private_registries' false && flags+=("--allow-private")

  local ref source out err
  while IFS=$'\t' read -r ref source; do
    [[ -n "$ref" ]] || continue
    out=$(tmp_dir image_contents)
    err="$GHSCAN_TMPROOT/imagefetch.log"
    log_info "[$full_name] reading the published image $ref (named in $source)"
    if timeout "$timeout_sec" "$py" -I "$GHSCAN_HOME/lib/image_fetch.py" "$ref" "$out" \
         "${flags[@]}" >/dev/null 2>"$err"; then
      if jq -e '.truncated == true' "$out/meta.json" >/dev/null 2>&1; then
        # Read, but not whole.  What was found stands; what was not is unknown.
        IMAGE_UNREAD="the image $ref was larger than the read limit"
        log_warn "[$full_name] $IMAGE_UNREAD, so its findings are held as they were"
      fi
      IMAGE_CONTENT_DIRS+=("$ref"$'\t'"$out")
    else
      IMAGE_UNREAD="could not read the image $ref: $(tail -1 "$err" 2>/dev/null | tr -d '\n' | cut -c1-300)"
      log_warn "[$full_name] $IMAGE_UNREAD, so its findings are held as they were"
      rm -rf -- "$out"
    fi
  done < <(printf '%s' "$refs" | jq -r '.[] | [.ref, .source] | @tsv')
}

# image_contents_findings <clone_dir> <full_name> <out file>
# The structural rules, as misconfiguration rows.  Run before
# image_contents_prune, which deletes the files the repository already holds,
# the start script among them.  Called in this shell, so IMAGE_UNREAD set on a
# failure survives; the rows go to <out file>.
image_contents_findings() {
  local dir="$1" full_name="$2" acc="$3"
  echo '[]' > "$acc"
  local py; py=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
  [[ -n "$py" ]] || { IMAGE_UNREAD="no python to check the published image"; return 0; }
  local entry ref out part
  for entry in "${IMAGE_CONTENT_DIRS[@]}"; do
    ref="${entry%%$'\t'*}"; out="${entry#*$'\t'}"
    part=$(tmp_file image_check)
    if "$py" -I "$GHSCAN_HOME/lib/image_check.py" image "$out" "$dir" "$full_name" "$ref" \
         > "$part" 2>"$GHSCAN_TMPROOT/imagecheck.log" && jq -e 'type == "array"' "$part" >/dev/null 2>&1; then
      jq -s -c 'add' "$acc" "$part" > "$acc.new" && mv "$acc.new" "$acc"
    else
      IMAGE_UNREAD="the image $ref could not be checked: $(tail -1 "$GHSCAN_TMPROOT/imagecheck.log" 2>/dev/null | cut -c1-300)"
      log_warn "[$full_name] $IMAGE_UNREAD"
    fi
  done
}

# image_contents_secrets <full_name> <repo_json> <want_gitleaks> <want_trufflehog> <out file>
#
# The credential engines over what only the image has, through the same facts,
# masking and triage as everything else, so a key in an image is held to the
# same standard as a key in a commit and is never stored in the clear.  Writes
# the partitioned set ({reported, filtered, suppressed}) to <out file>.
#
# The triage is git aware and an image is not a commit, so it is handed no
# checkout: nothing about branches or history applies.  What it does say about
# exposure is replaced, because a key in a published image is exposed to
# everyone who can pull it, whatever the repository's history says.
image_contents_secrets() {
  local full_name="$1" repo_json="$2" want_gl="$3" want_th="$4" result="$5"
  echo '{"reported":[],"filtered":[],"suppressed":[]}' > "$result"
  local entry ref out raw part tri keep_low
  keep_low=$(cfg_bool '.scan.secrets.triage.path_rule_downgrades_only' true && echo true || echo false)
  for entry in "${IMAGE_CONTENT_DIRS[@]}"; do
    ref="${entry%%$'\t'*}"; out="${entry#*$'\t'}"
    raw=$(tmp_file image_raw); : > "$raw"
    if (( want_gl )); then
      part=$(tmp_file image_gl)
      run_gitleaks_worktree "$out/scan" "$full_name" "$part"
      normalize_gitleaks "$part" "$full_name" | derive_secret_facts "" \
        | image_contents_secret_paths "$ref" >> "$raw"
      wipe_file "$part"
    fi
    if (( want_th )); then
      part=$(tmp_file image_th)
      run_trufflehog_worktree "$out/scan" "$full_name" "$part"
      # trufflehog names files by their full path; the rest is the same.
      jq -c --arg root "$out/scan/" '
        if (.SourceMetadata.Data.Filesystem.file // "") | startswith($root)
        then .SourceMetadata.Data.Filesystem.file |= ltrimstr($root) else . end' \
        "$part" 2>/dev/null > "$part.rel" || : > "$part.rel"
      normalize_trufflehog "$part.rel" "$full_name" | derive_secret_facts "" \
        | image_contents_secret_paths "$ref" >> "$raw"
      wipe_file "$part"; wipe_file "$part.rel"
    fi
    if [[ -s "$raw" ]]; then
      tri=$(tmp_file image_tri)
      triage_findings "" "$raw" "$repo_json" > "$tri" || : > "$tri"
      part=$(tmp_file image_part)
      triage_partition "$tri" "$keep_low" | jq -c --arg ref "$ref" '
        def fix: map(. + {image: $ref, exposure: "published_image", url: "",
                          branch_urls: [], blame_url: null, file_history_url: null,
                          commit_url: null});
        {reported: (.reported // [] | fix), filtered: (.filtered // [] | fix),
         suppressed: (.suppressed // [] | fix)}' > "$part" 2>/dev/null \
        || echo '{"reported":[],"filtered":[],"suppressed":[]}' > "$part"
      jq -s -c '{reported: (map(.reported) | add), filtered: (map(.filtered) | add),
                 suppressed: (map(.suppressed) | add)}' "$result" "$part" > "$result.new" \
        && mv "$result.new" "$result"
      wipe_file "$tri"
    fi
    shred -u "$raw" 2>/dev/null || rm -f "$raw"
  done
}

# image_contents_prune <clone_dir>
# Drops every image file the repository already holds, and duplicate copies,
# so the credential pass reads only what the image alone has.
image_contents_prune() {
  local dir="$1" entry out
  local py; py=$(ghscan_venv_bin python3 2>/dev/null || command -v python3 || true)
  [[ -n "$py" ]] || return 0
  for entry in "${IMAGE_CONTENT_DIRS[@]}"; do
    out="${entry#*$'\t'}"
    "$py" -I "$GHSCAN_HOME/lib/image_check.py" prune "$out" "$dir" >/dev/null 2>&1 || true
  done
}

# image_contents_secret_paths <jsonl candidates> <ref> -> the same, with each
# file named as it sits in the image, and the image recorded.
#
# The engines report a path inside the scan directory.  scan/fs/<p> is a file
# the image ships; scan/deleted/<n>/<p> is one a later layer removed or
# replaced, which is still in layer n for anyone who pulls the image; scan/env
# is the image's configured environment.
image_contents_secret_paths() {
  local ref="$1"
  jq -c --arg ref "$ref" '
    (.file // "") as $f
    | (if ($f | startswith("fs/")) then "/" + ($f | ltrimstr("fs/"))
       elif ($f | test("^deleted/[0-9]+/")) then
         ($f | capture("^deleted/(?<n>[0-9]+)/(?<p>.*)$")) as $d
         | "/" + $d.p + " (removed by a later layer, still in layer " + $d.n + ")"
       elif $f == "env" then "image configuration: environment"
       else $f end) as $shown
    | . + {file: $shown, image: $ref, url: "", commit: "", image_scan_path: $f}'
}

# image_contents_cleanup -- the copies are in memory, and contain whatever
# credentials the image does, so they go as soon as the repository is done.
image_contents_cleanup() {
  local entry
  for entry in "${IMAGE_CONTENT_DIRS[@]}"; do
    rm -rf -- "${entry#*$'\t'}"
  done
  IMAGE_CONTENT_DIRS=()
}
