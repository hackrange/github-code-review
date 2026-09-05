#!/usr/bin/env bash
# Whether a repository could take a dynamic pass at all.
#
# This reads files and runs nothing.  It is the half of dynamic testing that is
# free, and it has to exist before the half that is expensive, because the
# expensive half is only worth building for the repositories that can take it.
#
# The estate says that is not many.  Roughly one repository in six ships a
# compose file or a Dockerfile, and of four real compose files read to check
# the assumption, not one built the application from its own repository: two
# stood up a database and a cache so somebody could run the code outside the
# container, one was a matrix of six database engines for testing, and the rest
# pulled a published image by tag.
#
# That last shape is the one worth refusing loudly.  Composing up a published
# image tests a release somebody built at some point, not the commit that was
# scanned, and reporting evidence about a different version of the code as
# though it settled a finding in this one is the same mistake as closing a
# finding nobody probed.  So the qualifying test is narrow and mechanical: a
# service has to build from this repository, and something has to publish a
# port.
#
# Three outcomes, and they are three different things.  Qualified means a
# dynamic pass could run here.  Declined means it could not, and says why.
# Unknown means the files could not be read, which is not the same as no and
# must never be counted as one: a dashboard that shows a missing answer and an
# answer of no in the same color is lying about coverage.
# shellcheck shell=bash

QUALIFIED="qualified"
DECLINED="declined"
DAST_UNKNOWN="unknown"

# The compose file names docker itself looks for, in its order of preference.
DAST_COMPOSE_NAMES=(
  "compose.yaml" "compose.yml"
  "docker-compose.yaml" "docker-compose.yml"
)

# dast_compose_file <dir> -> path, or empty
#
# Only the root.  A compose file three directories down is usually a fixture
# for one component rather than the way the application starts, and guessing
# wrong here means standing up the wrong thing.
dast_compose_file() {
  local dir="$1" name
  for name in "${DAST_COMPOSE_NAMES[@]}"; do
    [[ -f "$dir/$name" ]] && { printf '%s' "$dir/$name"; return 0; }
  done
  return 1
}

# dast_compose_verdict <compose_file> -> verdict|how|detail
#
# Answers two questions of the file: does any service build from this
# repository, and does any service publish a port.  Both have to be true of the
# same service for the pass to be testing the code that was scanned.
#
# Parsed with a small reader rather than a YAML library, because the scanner
# ships no YAML parser and adding one to answer a yes or no question is the
# wrong trade.  The shapes it understands are the ones compose files actually
# use; anything it cannot read comes back unknown rather than no.
dast_compose_verdict() {
  local file="$1"
  local service="" indent_service="" builds="" ports="" in_services=0
  local best_service="" best_builds="" best_ports=""
  local line stripped indent

  while IFS= read -r line || [[ -n "$line" ]]; do
    # Comments and blanks decide nothing.
    stripped="${line%%#*}"
    [[ -z "${stripped// }" ]] && continue

    indent="${stripped%%[! ]*}"
    local trimmed="${stripped#"${stripped%%[! ]*}"}"

    # Top level keys reset where we are.
    if [[ ${#indent} -eq 0 ]]; then
      [[ "$trimmed" == services:* ]] && { in_services=1; continue; }
      in_services=0; continue
    fi
    (( in_services )) || continue

    # A service name: the first level of indent under services.
    if [[ -z "$indent_service" || ${#indent} -le ${#indent_service} ]]; then
      if [[ "$trimmed" =~ ^[A-Za-z0-9._-]+: ]]; then
        # Bank whatever the previous service established before moving on.
        if [[ -n "$service" && -n "$builds" && -n "$ports" ]]; then
          best_service="$service"; best_builds="$builds"; best_ports="$ports"
        fi
        indent_service="$indent"
        service="${trimmed%%:*}"
        builds=""; ports=""
        continue
      fi
    fi

    [[ -n "$service" ]] || continue

    # build: . or build: {context: .} or a build block underneath.  What makes
    # it ours is that the context is inside this repository, which is anything
    # that is not a URL.
    if [[ "$trimmed" == build:* ]]; then
      local rest="${trimmed#build:}"; rest="${rest# }"
      if [[ -z "$rest" || "$rest" == "|" ]]; then
        builds="block"                     # a block follows; context checked below
      elif [[ "$rest" == http*://* || "$rest" == git@* ]]; then
        builds=""                          # built from somewhere else entirely
      else
        builds="$rest"
      fi
      continue
    fi
    if [[ "$trimmed" == context:* ]]; then
      local ctx="${ctx:-}"; ctx="${trimmed#context:}"; ctx="${ctx# }"
      if [[ "$ctx" == http*://* || "$ctx" == git@* ]]; then
        builds=""
      else
        builds="${ctx:-block}"
      fi
      continue
    fi
    # image: alone is the shape that must not qualify.  It is only recorded so
    # the reason can say so; it never sets builds.
    if [[ "$trimmed" == ports:* ]]; then
      local rest="${trimmed#ports:}"; rest="${rest# }"
      # ports: ["8080:80"] on one line, or a list underneath.
      [[ -n "$rest" && "$rest" != "|" ]] && ports="$rest"
      [[ -z "$ports" ]] && ports="list"
      continue
    fi
    # A list item under ports: - "8080:80"
    if [[ "$trimmed" == -\ * && "$ports" == "list" ]]; then
      local item="${trimmed#- }"; item="${item//\"/}"; item="${item//\'/}"
      [[ "$item" == *:* ]] && ports="$item"
      continue
    fi
  done < "$file"

  if [[ -n "$service" && -n "$builds" && -n "$ports" ]]; then
    best_service="$service"; best_builds="$builds"; best_ports="$ports"
  fi

  if [[ -n "$best_service" ]]; then
    printf '%s|compose|the %s service builds from this repository and publishes %s' \
           "$QUALIFIED" "$best_service" "${best_ports//list/a port}"
    return 0
  fi
  printf '%s|compose|a compose file is here, but no service both builds from this repository and publishes a port' \
         "$DECLINED"
}

# dast_dockerfile_verdict <dir> -> verdict|how|detail
#
# The fallback when there is no compose file worth using.  A Dockerfile that
# serves a port can be built and run on its own, which works for an application
# whose state lives somewhere it can be told about and fails for one that needs
# a database nobody started.  That failure is a declined at run time, not here.
dast_dockerfile_verdict() {
  local dir="$1"
  [[ -f "$dir/Dockerfile" ]] || {
    printf '%s|none|no compose file and no Dockerfile, so there is nothing to stand up' "$DECLINED"
    return 0; }

  local exposed
  exposed=$(grep -iE '^[[:space:]]*EXPOSE[[:space:]]+' "$dir/Dockerfile" 2>/dev/null \
            | head -1 | awk '{print $2}')
  if [[ -n "$exposed" ]]; then
    printf '%s|dockerfile|the Dockerfile exposes %s' "$QUALIFIED" "$exposed"
    return 0
  fi
  printf '%s|dockerfile|a Dockerfile is here but it exposes no port, so nothing would answer a request' \
         "$DECLINED"
}

# dast_qualify <dir> <full_name> -> one JSON object
#
# Never fails the scan.  A repository this cannot read comes back unknown with
# the reason, which is the honest answer and keeps it out of the qualified
# count without pretending it was refused.
dast_qualify() {
  local dir="$1" full_name="$2"
  local verdict how detail out compose

  if [[ ! -d "$dir" ]]; then
    verdict="$DAST_UNKNOWN"; how="none"
    detail="there was no checkout to read"
  elif compose=$(dast_compose_file "$dir"); then
    out=$(dast_compose_verdict "$compose" 2>/dev/null) || out=""
    if [[ -z "$out" ]]; then
      verdict="$DAST_UNKNOWN"; how="compose"
      detail="the compose file could not be read, so this is unknown rather than no"
    else
      verdict="${out%%|*}"; out="${out#*|}"
      how="${out%%|*}"; detail="${out#*|}"
      # A compose file that does not qualify is not the end of it: the
      # repository may still carry a Dockerfile that would serve on its own.
      if [[ "$verdict" == "$DECLINED" ]]; then
        local fallback; fallback=$(dast_dockerfile_verdict "$dir")
        if [[ "${fallback%%|*}" == "$QUALIFIED" ]]; then
          verdict="${fallback%%|*}"; fallback="${fallback#*|}"
          how="${fallback%%|*}"; detail="${fallback#*|}"
        fi
      fi
    fi
  else
    out=$(dast_dockerfile_verdict "$dir")
    verdict="${out%%|*}"; out="${out#*|}"
    how="${out%%|*}"; detail="${out#*|}"
  fi

  log_debug "$full_name: dynamic pass $verdict ($how): $detail"
  jq -cn --arg v "$verdict" --arg h "$how" --arg d "$detail" \
     '{verdict: $v, how: $h, reason: $d, ran: false,
       note: "qualification only: nothing was built and nothing was run"}'
}
