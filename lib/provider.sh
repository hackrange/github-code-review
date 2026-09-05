#!/usr/bin/env bash
# Which host we are talking to, and the handful of things that differ.
#
# Of everything this scanner does, almost none of it cares where the code came
# from: gitleaks and trufflehog work on a clone, semgrep on the files, syft and
# grype and osv-scanner on the dependencies, and triage, exclusions and the
# report writers on the findings.  What differs is finding the work, presenting
# a credential, cloning, and the shape of a permalink.
#
# So each provider supplies those, and nothing else changes.  A function that
# is not defined for a provider falls back to the GitHub one, which keeps the
# diff for a new provider to the parts that are genuinely different.
# shellcheck shell=bash

# github, gitlab or bitbucket.  Anything that predates the provider column is
# GitHub, so that is the default rather than an error.
provider_name() {
  local p; p=$(cfg '.provider' 'github')
  case "$p" in
    github|gitlab|bitbucket|azure|assembla|beanstalk|codecommit|gcsr|\
    subversion|perforce) printf '%s' "$p" ;;
    *) log_warn "unknown provider '$p', treating it as github"; printf 'github' ;;
  esac
}

# Does this host keep git history, in a form the credential engines can walk?
#
# The most valuable thing this tool finds is a credential that was committed
# and later deleted, and gitleaks and trufflehog find those by walking git
# history.  Subversion and Perforce are not git, so a checkout is the current
# revision and nothing else.  That is a real scan and worth running, but it
# covers the half people already know about, and a report that does not say so
# is worse than no report.
provider_keeps_history() {
  case "$(provider_name)" in
    subversion|perforce) return 1 ;;
    *) return 0 ;;
  esac
}

# What the scanner actually gets a working copy with.  git for everything git
# shaped; the other two bring their own client.
provider_checkout_kind() {
  case "$(provider_name)" in
    subversion) printf 'svn' ;;
    perforce)   printf 'p4' ;;
    *)          printf 'git' ;;
  esac
}

# Call provider_<name>_<fn> if it exists, else provider_github_<fn>.
provider_call() {
  local fn="$1"; shift
  local impl="provider_$(provider_name)_${fn}"
  if declare -F "$impl" >/dev/null 2>&1; then
    "$impl" "$@"
    return $?
  fi
  impl="provider_github_${fn}"
  declare -F "$impl" >/dev/null 2>&1 || die "no implementation of $fn for any provider"
  "$impl" "$@"
}

# Does this host offer a thing at all?
#
# Dependabot alerts, code scanning and GHAS secret alerts are GitHub features.
# GitLab has its own security reports and only on the paid tiers, and a free or
# self managed instance often has none of it.  Bitbucket has no equivalent.
# Asking first means a scan says "this host does not offer that" instead of
# treating an empty answer as good news.
provider_supports() {
  local feature="$1"
  case "$(provider_name)" in
    github)
      case "$feature" in
        dependabot_alerts|code_scanning|secret_scanning_alerts|dependency_graph|\
        org_members|two_factor_status|teams|outside_collaborators|pull_history)
          return 0 ;;
        *) return 1 ;;
      esac
      ;;
    gitlab)
      # Members and merge requests are free tier.  The security features are
      # not, and on a self managed instance they are often absent entirely,
      # so they are asked for rather than assumed.
      case "$feature" in
        org_members|pull_history) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    bitbucket)
      # Nothing yet.  Pull requests exist there and are not wired up, and
      # claiming a feature the scanner cannot fetch would call a GitHub path
      # and read the failure as "none found".
      return 1
      ;;
    azure)
      # Pull requests and members both exist and are not wired up yet.  Saying
      # so here rather than claiming them keeps an empty answer meaning empty.
      return 1
      ;;
    assembla|beanstalk|codecommit|gcsr|subversion|perforce)
      # None of these has an equivalent this scanner reads.  CodeCommit and
      # Cloud Source Repositories have no code scanning of their own at all;
      # Subversion and Perforce have no API to ask.
      return 1
      ;;
    *) return 1 ;;
  esac
}

# What to call a group of repositories, for messages people read.
provider_group_noun() {
  case "$(provider_name)" in
    gitlab)     printf 'group' ;;
    bitbucket)  printf 'workspace' ;;
    azure)      printf 'project' ;;
    assembla)   printf 'space' ;;
    beanstalk)  printf 'account' ;;
    codecommit) printf 'region' ;;
    gcsr)       printf 'project' ;;
    subversion) printf 'server' ;;
    perforce)   printf 'depot' ;;
    *)          printf 'organization' ;;
  esac
}

# A provider that needs a program this image may not carry says so once, by
# name, rather than returning nothing and letting the scan read that as a
# clean estate.  This is the gosec lesson: an engine that cannot run must not
# look like an engine that found nothing.
provider_requires_tool() {
  case "$(provider_name)" in
    codecommit) printf 'aws' ;;
    gcsr)       printf 'gcloud' ;;
    subversion) printf 'svn' ;;
    perforce)   printf 'p4' ;;
    *)          printf '' ;;
  esac
}

provider_check_tool() {
  local tool; tool=$(provider_requires_tool)
  [[ -z "$tool" ]] && return 0
  have_cmd "$tool" && return 0
  log_error "$(provider_name) needs the '$tool' command and it is not installed here. Refusing to report an empty estate that only means the tool is missing."
  return 1
}
