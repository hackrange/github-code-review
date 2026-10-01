#!/usr/bin/env bash
# SBOM generation and license reporting.
# shellcheck shell=bash

# sbom_syft <dir> <full_name> <out_cyclonedx> [out_spdx] -> 0 on success
sbom_syft() {
  local dir="$1" full_name="$2" out_cdx="$3" out_spdx="${4:-}"
  have_cmd syft || { log_warn "syft is not on the path, so there is no SBOM and no license data"; return 1; }

  # Absolute output paths: syft itself runs with the clone as its cwd so that
  # component locations are repo-relative and no scanner path leaks into the SBOM.
  out_cdx=$(readlink -f "$out_cdx" 2>/dev/null || printf '%s' "$out_cdx")
  [[ -n "$out_spdx" ]] && out_spdx=$(readlink -f "$out_spdx" 2>/dev/null || printf '%s' "$out_spdx")

  local rev; rev=$(git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo "unknown")
  # Our configuration, named outright.  syft otherwise looks for one in its
  # working directory, which is the repository being scanned.
  local syft_cfg="${GHSCAN_HOME:-.}/config/syft.yaml"
  if [[ ! -r "$syft_cfg" ]]; then
    log_warn "$full_name: $syft_cfg is missing, so there is no SBOM rather than one built with the repository's own syft settings"
    return 1
  fi
  local args=(scan "dir:." --quiet --config "$syft_cfg"
              --source-name "$full_name" --source-version "$rev")

  local cat; cat=$(cfg '.scan.sbom.catalogers' '')
  [[ -n "$cat" ]] && args+=(--select-catalogers "$cat")

  local e
  while IFS= read -r e; do [[ -n "$e" ]] && args+=(--enrich "$e"); done \
    < <(cfg_arr '.scan.sbom.enrich')

  local formats; formats=$(cfg_json '.scan.sbom.formats // ["cyclonedx-json"]')
  local outs=()
  printf '%s' "$formats" | jq -e 'index("cyclonedx-json")' >/dev/null && outs+=(-o "cyclonedx-json=$out_cdx")
  if [[ -n "$out_spdx" ]] && printf '%s' "$formats" | jq -e 'index("spdx-json")' >/dev/null; then
    outs+=(-o "spdx-json=$out_spdx")
  fi
  (( ${#outs[@]} )) || outs=(-o "cyclonedx-json=$out_cdx")

  log_debug "$full_name: syft ${args[*]}"
  if ! ( cd "$dir" && SYFT_CHECK_FOR_APP_UPDATE=false syft "${args[@]}" "${outs[@]}" ) \
       2>"$GHSCAN_TMPROOT/syft.log"; then
    log_warn "$full_name: syft failed: $(tail -2 "$GHSCAN_TMPROOT/syft.log" | tr '\n' ' ')"
    return 1
  fi
  sbom_add_dotnet "$dir" "$full_name" "$out_cdx"
  [[ -s "$out_cdx" ]]
}

# sbom_add_dotnet <dir> <full_name> <out_cyclonedx>
#
# syft finds nothing in a .NET project that has not been built: its catalogers
# read a deps.json, a packages.lock.json or a compiled assembly, and a source
# repository has a csproj and a packages.config instead.  Those are read here
# and added to the SBOM, where the vulnerability matcher already looks.
sbom_add_dotnet() {
  local dir="$1" full_name="$2" cdx="$3"
  local helper="${GHSCAN_HOME:-}/lib/dotnet_packages.py"
  [[ -r "$helper" && -s "$cdx" ]] || return 0
  local python; python=$(command -v python3 || true)
  [[ -n "$python" ]] || return 0

  local found; found=$(tmp_file dotnetpkgs)
  "$python" "$helper" "$dir" > "$found" 2>/dev/null || return 0
  local n; n=$(jq 'length' "$found" 2>/dev/null || echo 0)
  [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )) || return 0

  # Only what syft did not already have.  A project that was built and has a
  # deps.json is cataloged correctly and should not be listed twice.
  local merged; merged=$(tmp_file dotnetmerged)
  if jq -s '.[0] as $sbom | .[1] as $extra
      | ([ $sbom.components[]? | (.purl // "") | ascii_downcase ]) as $have
      | ($extra | map(select((.purl | ascii_downcase) as $p | ($have | index($p)) == null))) as $new
      | $sbom + {components: (($sbom.components // []) + $new)}' \
      "$cdx" "$found" > "$merged" 2>/dev/null && [[ -s "$merged" ]]; then
    local added; added=$(( $(jq '.components | length' "$merged") - $(jq '.components // [] | length' "$cdx") ))
    mv -f "$merged" "$cdx"
    (( added > 0 )) && log_info "$full_name: $added .NET package(s) read from project files that syft does not parse"
  fi
  return 0
}

# sbom_github <full_name> <out_spdx> - GitHub's own dependency-graph SBOM.
# Works without cloning and covers manifests GitHub already parsed.
sbom_github() {
  local full_name="$1" out="$2"
  # This is only ever the fallback for when syft found nothing.
  if ! provider_supports dependency_graph; then
    log_debug "$(provider_name) has no dependency graph to fall back on, so it is not asked for"
    : > "$out"; return 0
  fi
  local body
  body=$(api_get_quiet "/repos/${full_name}/dependency-graph/sbom")
  if [[ -z "$body" ]]; then
    log_debug "$full_name: dependency-graph SBOM unavailable"
    return 1
  fi
  printf '%s' "$body" | jq -c '.sbom // .' > "$out" 2>/dev/null || return 1
  [[ -s "$out" ]]
}

# sbom_merge_graph <spdx_from_github> <cyclonedx> <full_name>
#
# The dependency graph resolves what a manifest only declares.  A pom lists the
# libraries somebody chose; the graph lists those plus everything they drag in,
# which on a Java project is most of what is actually shipped and most of what
# is actually vulnerable.  syft does not resolve that tree - it would have to
# fetch and interpret every parent pom to do it - and neither should this:
# running a build to find out what a build would install means executing
# whatever the repository says, inside the scanner.
#
# So the resolved list is taken from the host, which already worked it out, and
# merged into the SBOM the matcher reads.  Only packages that are not already
# there are added, so a repository syft cataloged correctly gains only the
# transitive ones.
sbom_merge_graph() {
  local spdx="$1" cdx="$2" full_name="$3"
  [[ -s "$spdx" && -s "$cdx" ]] || return 0

  local merged; merged=$(tmp_file graphmerged)
  if ! jq -s '
      .[0] as $cdx | .[1] as $g
      | ([ $cdx.components[]? | (.purl // "") | ascii_downcase | select(. != "") ]) as $have
      | ([ $g.packages[]?
           | . as $p
           | (($p.externalRefs // [])[]? | select(.referenceType == "purl") | .referenceLocator) as $purl
           | select(($purl // "") != "")
           | select(($have | index($purl | ascii_downcase)) == null)
           | {type: "library",
              name: ($p.name // ""),
              version: ($p.versionInfo // ""),
              purl: $purl,
              properties: [{name: "gcr:source", value: "dependency graph"}]}
         ]) as $extra
      # Same package twice in the graph is normal; the matcher only needs it once.
      | ($extra | unique_by(.purl)) as $extra
      | $cdx + {components: (($cdx.components // []) + $extra)}
    ' "$cdx" "$spdx" > "$merged" 2>/dev/null || [[ ! -s "$merged" ]]; then
    return 0
  fi

  local before after
  before=$(jq '.components // [] | length' "$cdx" 2>/dev/null || echo 0)
  after=$(jq '.components // [] | length' "$merged" 2>/dev/null || echo 0)
  if (( after > before )); then
    mv -f "$merged" "$cdx"
    log_info "$full_name: $(( after - before )) package(s) from the dependency graph that the manifests do not name"
  fi
  return 0
}

# Repository-level license as GitHub detects it.
repo_license() {
  local full_name="$1"
  local body; body=$(api_get_quiet "/repos/${full_name}/license")
  if [[ -z "$body" ]]; then echo 'null'; return; fi
  printf '%s' "$body" | jq -c '{
    spdx_id: (.license.spdx_id // null),
    name:    (.license.name // null),
    key:     (.license.key // null),
    path:    (.path // null),
    url:     (.html_url // null)
  }' 2>/dev/null || echo 'null'
}

# Flatten a CycloneDX doc into the report's component list + license rollup.
sbom_summarize_cyclonedx() {
  local cdx="$1"
  [[ -s "$cdx" ]] || { echo 'null'; return; }
  local keep_files; keep_files=$(cfg_bool '.scan.sbom.include_file_components' false && echo true || echo false)
  jq -c --argjson keep_files "$keep_files" '
    def norm_lic:
      [ (.licenses // [])[]
        | (.license.id // .license.name // .expression // null)
        | select(. != null) | tostring
      ] | unique;

    (.components // []) as $c
    | [ $c[]
        | select($keep_files or (.type // "library") != "file")
        | {
          name, version,
          type: (.type // "library"),
          purl: (.purl // null),
          group: (.group // null),
          licenses: norm_lic,
          cpe: (.cpe // null),
          ecosystem: (((.purl // "") | capture("^pkg:(?<e>[^/@]+)/") | .e) // "unknown")
        } ] as $comps
    | {
        format: "CycloneDX",
        spec_version: (.specVersion // null),
        serial_number: (.serialNumber // null),
        component_count: ($comps | length),
        components: $comps,
        licenses: ( [ $comps[].licenses[]? ] | group_by(.) | map({license: .[0], count: length}) | sort_by(-.count) ),
        unlicensed_components: [ $comps[] | select((.licenses | length) == 0) | (.purl // (.name + "@" + (.version // "?"))) ],
        ecosystems: ( [ $comps[].ecosystem ] | group_by(.) | map({ecosystem: .[0], count: length}) | sort_by(-.count) )
      }
  ' "$cdx" 2>/dev/null || echo 'null'
}

# Summarize GitHub's SPDX dependency-graph SBOM the same way.
sbom_summarize_spdx() {
  local spdx="$1"
  [[ -s "$spdx" ]] || { echo 'null'; return; }
  jq -c '
    [ (.packages // [])[] | {
        name: (.name // "unknown"),
        version: (.versionInfo // null),
        type: "library",
        purl: ( [ (.externalRefs // [])[] | select(.referenceType == "purl") | .referenceLocator ] | first // null),
        group: null,
        licenses: ( [ (.licenseConcluded // empty), (.licenseDeclared // empty) ]
                    | map(select(. != null and . != "NOASSERTION" and . != "NONE")) | unique ),
        cpe: null,
        ecosystem: "unknown"
      } ] as $comps
    | {
        format: "SPDX",
        spec_version: (.spdxVersion // null),
        serial_number: (.documentNamespace // null),
        component_count: ($comps | length),
        components: $comps,
        licenses: ( [ $comps[].licenses[]? ] | group_by(.) | map({license: .[0], count: length}) | sort_by(-.count) ),
        unlicensed_components: [ $comps[] | select((.licenses | length) == 0) | (.purl // (.name + "@" + (.version // "?"))) ],
        ecosystems: []
      }
  ' "$spdx" 2>/dev/null || echo 'null'
}

# Apply the configured license policy to a summarized SBOM.
# Matching is case-insensitive substring containment on the SPDX id/expression,
# so "AGPL-3.0-only" also catches "AGPL-3.0-only WITH exception".
sbom_license_policy() {
  local summary="$1"
  cfg_bool '.scan.sbom.license_policy.enabled' true || { echo 'null'; return; }
  local allow_unknown; allow_unknown=$(cfg_bool '.scan.sbom.license_policy.allow_unknown' true && echo true || echo false)
  printf '%s' "$summary" | jq -c \
    --argjson denied  "$(cfg_json '.scan.sbom.license_policy.denied // []')" \
    --argjson flagged "$(cfg_json '.scan.sbom.license_policy.flagged // []')" \
    --argjson allow_unknown "$allow_unknown" '
    if . == null then null else
      ( $denied  | map(ascii_downcase) ) as $D
    | ( $flagged | map(ascii_downcase) ) as $F
    | [ .components[]?
        | . as $c
        | ( [ $c.licenses[]? | ascii_downcase ] ) as $L
        | ( $c.purl // ($c.name + "@" + ($c.version // "?")) ) as $id
        | if ($L | length) == 0 then
            (if $allow_unknown then empty
             else {component: $id, version: $c.version, license: "UNKNOWN", policy: "flagged", reason: "no license metadata"} end)
          elif any($L[]; . as $l | any($D[]; . as $d | ($l | contains($d)))) then
            {component: $id, version: $c.version, license: ($c.licenses | join(" OR ")), policy: "denied", reason: "matches license_policy.denied"}
          elif any($L[]; . as $l | any($F[]; . as $d | ($l | contains($d)))) then
            {component: $id, version: $c.version, license: ($c.licenses | join(" OR ")), policy: "flagged", reason: "matches license_policy.flagged"}
          else empty end
      ] as $v
    | {
        violations: $v,
        denied_count:  ([ $v[] | select(.policy == "denied") ]  | length),
        flagged_count: ([ $v[] | select(.policy == "flagged") ] | length),
        status: (if ([ $v[] | select(.policy == "denied") ] | length) > 0 then "fail"
                 elif ($v | length) > 0 then "warn" else "pass" end)
      }
    end' 2>/dev/null || echo 'null'
}

# Copy the raw syft documents out to where people expect to find them. These
# are untouched syft output, so they are valid CycloneDX and SPDX.
# Stamp every component with the repository it came from.
#
# An SBOM that says "left-pad 1.3.0" and nothing else is no use across an
# estate: the first question anybody asks is which repository has it.  Both
# formats have a place for this already, so nothing here invents a field.
#
#   CycloneDX  externalReferences of type "vcs", which is the spec's own way of
#              saying where the source lives, plus properties in our own
#              namespace for the branch and the commit.  syft already writes
#              properties under "syft:", so this sits alongside.
#   SPDX       sourceInfo, a free text field on a package that exists for
#              exactly this, plus an annotation for anything reading those.
#
# sbom_stamp_repo <cdx|spdx> <file> <full_name> <branch> <commit>
sbom_stamp_repo() {
  local kind="$1" file="$2" full_name="$3" branch="${4:-}" commit="${5:-}"
  [[ -s "$file" ]] || return 0

  local web; web=$(cfg '.github.web_url' 'https://github.com')
  local url="${web%/}/${full_name}"
  local tmp; tmp=$(tmp_file stamped)

  if [[ "$kind" == "cdx" ]]; then
    jq --arg repo "$full_name" --arg url "$url" \
       --arg branch "$branch" --arg commit "$commit" '
      def stamp:
        . + {
          externalReferences: (
            [ (.externalReferences // [])[] | select(.type != "vcs") ]
            + [{type: "vcs", url: $url, comment: ("repository " + $repo)}]
          ),
          properties: (
            [ (.properties // [])[] | select(.name | startswith("gcr:") | not) ]
            + [{name: "gcr:repository", value: $repo}]
            + (if $branch == "" then [] else [{name: "gcr:branch", value: $branch}] end)
            + (if $commit == "" then [] else [{name: "gcr:commit", value: $commit}] end)
          )
        };
      .components = [ (.components // [])[] | stamp ]
      | .metadata.component = ((.metadata.component // {}) | stamp)
    ' "$file" > "$tmp" 2>/dev/null && mv "$tmp" "$file"
  else
    jq --arg repo "$full_name" --arg url "$url" \
       --arg branch "$branch" --arg commit "$commit" '
      def source_line:
        "Found in " + $repo + " (" + $url + ")"
        + (if $branch == "" then "" else " on branch " + $branch end)
        + (if $commit == "" then "" else " at commit " + $commit end);
      .packages = [ (.packages // [])[] | . + {
        sourceInfo: source_line,
        annotations: (
          [ ((.annotations // [])[] | select((.comment // "") | startswith("repository=") | not)) ]
          + [{annotationType: "OTHER", annotator: "Tool: ghscan",
              annotationDate: (.annotationDate // (now | todate)),
              comment: ("repository=" + $repo)}]
        )
      } ]
    ' "$file" > "$tmp" 2>/dev/null && mv "$tmp" "$file"
  fi
  return 0
}

# sbom_graph_cyclonedx <file> - make sure the document has a dependency graph.
#
# A CycloneDX document with components and no `dependencies` array is a list,
# not a bill of materials, and the tools it gets loaded into read the graph
# rather than the list: Dependency-Track shows the project as having nothing in
# it, and a validator with the strict profile turned on rejects the file.  The
# per repository documents came out that way whenever syft found no
# relationships to write.  Anything added afterwards was missing from it too:
# a vendored library goes into the components and into nothing that reads
# them, even when syft did write a graph.
#
# What this can honestly say is written and no more.  Whatever graph is already
# there is kept exactly as it is; a component nothing else points at is
# attached to the document's own root component, because it is in the document
# and nothing recorded what pulled it in; and every remaining component gets an
# entry with an empty `dependsOn`.  An empty array with the reference present
# says "nothing was recorded here", which is a different statement from leaving
# the reference out, and it is the true one.
sbom_graph_cyclonedx() {
  local file="$1"
  [[ -s "$file" ]] || return 0
  local tmp; tmp=$(tmp_file graphed)

  jq '
    def refs: [ .. | objects | select(has("bom-ref")) | .["bom-ref"] ] | unique;

    # A document with no root component of its own gets one named here, so the
    # graph has somewhere to hang from.  Without it every component is a root
    # and the file says nothing about what it is a bill of materials for.
    (if (.metadata.component | type) == "object"
       and (.metadata.component["bom-ref"] // "") == ""
     then .metadata.component["bom-ref"] = "gcr:document" else . end)
    | (.metadata.component["bom-ref"] // "") as $root
    | ((.components // []) | refs) as $refs
    | (.dependencies // []) as $have
    | ($have | map({(.ref): true}) | add // {}) as $known
    | ([ $have[] | (.dependsOn // [])[] ] | unique) as $pointed
    | ($pointed | map({(.): true}) | add // {}) as $reached
    | [ $refs[] | select($reached[.] | not) ] as $orphans
    | .dependencies = (
        [ $have[]
          | if .ref == $root
            then {ref: .ref,
                  dependsOn: (((.dependsOn // []) + $orphans) | unique)}
            else . end ]
        + (if $root != "" and ($known[$root] | not)
           then [{ref: $root, dependsOn: $orphans}] else [] end)
        + [ $refs[] | select($known[.] | not) | {ref: ., dependsOn: []} ]
      )
  ' "$file" > "$tmp" 2>/dev/null && mv "$tmp" "$file"
  return 0
}

sbom_write_per_repo() {
  local full_name="$1" cdx="$2" spdx="$3" out_dir="$4"
  cfg_bool '.scan.sbom.write_per_repo_files' true || return 0
  local dir="$out_dir/sbom"
  mkdir -p "$dir" || return 1
  local slug; slug=$(slugify "$full_name")
  [[ -s "$cdx" ]]  && cp -f "$cdx"  "$dir/${slug}.cdx.json"
  [[ -s "$spdx" ]] && cp -f "$spdx" "$dir/${slug}.spdx.json"
  return 0
}

_uuid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'
  fi
}

# One CycloneDX document for the whole estate. Each repo becomes an application
# component with its own packages nested underneath.
sbom_merge_cyclonedx() {
  local sbom_dir="$1" tool_version="$2"
  local web; web=$(cfg '.github.web_url' 'https://github.com'); web="${web%/}"
  local files=("$sbom_dir"/*.cdx.json)
  [[ -e "${files[0]}" ]] || { echo ''; return 1; }

  local parts; parts=$(tmp_file cdxparts); echo '[]' > "$parts"
  local f slug repo
  for f in "${files[@]}"; do
    [[ -s "$f" ]] || continue
    slug=$(basename "$f" .cdx.json)
    repo=$(printf '%s' "$slug" | sed 's|__|/|')
    # Every reference is prefixed with the repository it came from.  syft
    # keys a component by its content and its path, so the same package at
    # the same version in two repositories can arrive with the same
    # reference, and one document holding two of the same reference is a
    # document where half the graph points at the wrong thing.
    jq -c --slurpfile acc "$parts" --arg repo "$repo" --arg web "$web" '
      def prefix($ref): ($repo + "|" + $ref);
      def stamp:
        if type == "object" then
            (if has("bom-ref") then .["bom-ref"] |= prefix(.) else . end)
          | (if has("components") then .components |= map(stamp) else . end)
        else . end;

      {
        app: {
          type: "application",
          "bom-ref": ("repo:" + $repo),
          name: $repo,
          version: ((.metadata.component.version // "unknown") | tostring),
          externalReferences: [{type: "vcs", url: ($web + "/" + $repo)}],
          components: [ (.components // [])[] | stamp ]
        },
        root: (if (.metadata.component["bom-ref"] // "") == "" then null
               else prefix(.metadata.component["bom-ref"]) end),
        deps: [ (.dependencies // [])[]
                | {ref: prefix(.ref),
                   dependsOn: [ (.dependsOn // [])[] | prefix(.) ]} ]
      } as $part
      | $acc[0] + [$part]' "$f" > "${parts}.n" && mv "${parts}.n" "$parts"
  done

  # The graph of the whole estate: it holds repositories, and a repository
  # holds its packages.  Whatever a repository's own document said about what
  # depends on what is carried across rather than flattened, because that is
  # the part nothing else can reconstruct afterwards.
  jq -n --slurpfile repos "$parts" \
        --arg uuid "$(_uuid)" --arg ts "$(now_iso)" --arg ver "$tool_version" '
    def refs: [ .. | objects | select(has("bom-ref")) | .["bom-ref"] ] | unique;

    # A license stated for a package in one repository is stated for the same
    # package everywhere.  The scanner reads a license off whatever the tree
    # in front of it carried, so the same version of the same library comes
    # back licensed from the repository that pinned it in a manifest with the
    # field filled in and unlicensed from the one that did not.  Both are the
    # same package, identified by the same purl, under the same license.
    #
    # This is not a guess and it is not left to look like one: the copy that
    # is filled in says where the license came from, so anybody using this
    # document for license work can tell the two apart.
    ([ $repos[0][] | .app.components[]? | .. | objects
       | select(((.purl // "") != "") and (((.licenses // []) | length) > 0))
       | {key: .purl, value: .licenses} ] | from_entries) as $licensed
    | def fill:
        if type == "object" then
            (if (((.licenses // []) | length) == 0)
                and (($licensed[.purl // ""] // null) != null)
             then . + {
               licenses: $licensed[.purl],
               properties: ((.properties // [])
                            + [{name: "gcr:license-from",
                                value: ("stated for this package in another "
                                        + "repository in the same scan")}])}
             else . end)
          | (if has("components") then .components |= map(fill) else . end)
        else . end;

    [ $repos[0][]
      | . as $part
      | ($part.app["bom-ref"]) as $app
      | (($part.app.components // []) | refs) as $refs
      | ($refs | map({(.): true}) | add // {}) as $exists
      | ([ $part.deps[] | select(.ref != $part.root) | select($exists[.ref])
           | {ref: .ref,
              dependsOn: [ .dependsOn[] | select($exists[.]) ]} ]) as $inner
      | ([ $part.deps[] | select(.ref == $part.root)
           | .dependsOn[] | select($exists[.]) ]) as $direct
      | ($inner | map({(.ref): true}) | add // {}) as $known
      | ([ $inner[] | .dependsOn[] ] | unique) as $pointed
      | ($pointed | map({(.): true}) | add // {}) as $reached
      | [{ref: $app,
           dependsOn: (((if ($direct | length) > 0 then $direct else $refs end)
                        + [ $refs[] | select($reached[.] | not) ]) | unique)}]
        + $inner
        + [ $refs[] | select($known[.] | not) | {ref: ., dependsOn: []} ]
    ] as $graphs
    | {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: ("urn:uuid:" + $uuid),
    version: 1,
    metadata: {
      timestamp: $ts,
      tools: {components: [{type: "application", name: "ghscan", version: $ver}]},
      component: {type: "application", "bom-ref": "ghscan:estate",
                  name: "github-estate", version: $ts}
    },
    components: [ $repos[0][] | .app | fill ],
    dependencies: (
      [{ref: "ghscan:estate", dependsOn: [ $repos[0][] | .app["bom-ref"] ]}]
      + [ $graphs[][] ]
    )
  }'
}

# One SPDX document listing every package found, tagged with its repo. The
# per-repo files keep the original relationship graph; this one is a roll-up.
sbom_merge_spdx() {
  local sbom_dir="$1" tool_version="$2"
  local files=("$sbom_dir"/*.spdx.json)
  [[ -e "${files[0]}" ]] || { echo ''; return 1; }

  local parts; parts=$(tmp_file spdxparts); echo '[]' > "$parts"
  local f slug repo idx=0
  for f in "${files[@]}"; do
    [[ -s "$f" ]] || continue
    slug=$(basename "$f" .spdx.json)
    repo=$(printf '%s' "$slug" | sed 's|__|/|')
    idx=$(( idx + 1 ))
    jq -c --slurpfile acc "$parts" --arg repo "$repo" --arg pfx "R${idx}" \
       --arg ts "$(now_iso)" '
      $acc[0] + [ (.packages // [])[] | . + {
        SPDXID: ("SPDXRef-" + $pfx + "-" + ((.SPDXID // "pkg") | ltrimstr("SPDXRef-"))),
        annotations: [{
          annotationType: "OTHER",
          annotator: "Tool: ghscan",
          annotationDate: $ts,
          comment: ("repository=" + $repo)
        }]
      } ]' "$f" > "${parts}.n" && mv "${parts}.n" "$parts"
  done

  jq -n --slurpfile pkgs "$parts" \
        --arg uuid "$(_uuid)" --arg ts "$(now_iso)" --arg ver "$tool_version" '{
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "ghscan-combined",
    documentNamespace: ("https://ghscan.invalid/spdx/" + $uuid),
    creationInfo: {created: $ts, creators: ["Tool: ghscan-" + $ver]},
    packages: $pkgs[0],
    relationships: [ $pkgs[0][] | {
      spdxElementId: "SPDXRef-DOCUMENT",
      relatedSpdxElement: .SPDXID,
      relationshipType: "DESCRIBES"
    } ]
  }'
}

# vendored_into_sbom <dir> <full_name> <cdx> -> adds copied-in libraries
#
# Dependency scanning reads manifests, so a library that was copied into the
# tree is not scanned and the report comes back clean about it.  A missing
# finding looks exactly like a repository with nothing wrong, which is worse
# than a noisy one.
vendored_into_sbom() {
  local dir="$1" full_name="$2" cdx="$3"
  cfg_bool '.scan.sbom.vendored' true || {
    log_debug "vendored library detection is switched off"; return 0; }
  [[ -s "$cdx" ]] || return 0
  local engine="$GHSCAN_HOME/lib/vendored.py"
  [[ -r "$engine" ]] || { log_debug "the vendored library pass is missing"; return 0; }
  local python; python=$(ghscan_python)
  [[ -n "$python" ]] || return 0

  local added
  added=$("$python" "$engine" "$dir" "$cdx" 2>"$GHSCAN_TMPROOT/vendored.log") || added=0
  [[ "$added" =~ ^[0-9]+$ ]] || added=0
  if (( added > 0 )); then
    # At warn level because a quiet scan still prints those, and a count that
    # only appears when it is non zero leaves nothing to compare against.
    log_warn "$full_name: $added vendored librar$( ((added==1)) && echo y || echo ies) with no manifest entry, now in the SBOM"
  fi
}
