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
    gitea|forgejo|subversion|perforce) printf '%s' "$p" ;;
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

# Which file answers for this host.
#
# Forgejo is a fork of Gitea and still speaks the same /api/v1, so one
# implementation serves both.  The two names stay apart everywhere a person
# reads one, because somebody running Forgejo should not be told they are
# running Gitea, and they are joined here, where the only question is which
# functions to call.
provider_impl_name() {
  # Read once.  provider_call runs for every API request, and provider_name
  # shells out to jq, so asking twice here doubles that for the whole scan.
  local p; p=$(provider_name)
  case "$p" in
    forgejo) printf 'gitea' ;;
    *)       printf '%s' "$p" ;;
  esac
}

# Call provider_<impl>_<fn> if it exists, else provider_github_<fn>.
provider_call() {
  local fn="$1"; shift
  local impl="provider_$(provider_impl_name)_${fn}"
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
    gitea|forgejo)
      # No dependency alerts, no code scanning, no secret scanning alerts and
      # no dependency graph: none of that exists here, so there is nothing to
      # read.  Members, teams and pull requests do exist, and are spelled
      # differently enough that the GitHub calls come back wrong rather than
      # empty - the member listing has no role filter, so asking it for the
      # administrators returns everybody, and a report saying every member is
      # an owner is worse than a report that does not say.  Claiming those
      # means writing them, not switching them on here.
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
    gitea|forgejo) printf 'organization' ;;
    subversion) printf 'server' ;;
    perforce)   printf 'depot' ;;
    *)          printf 'organization' ;;
  esac
}

# Where a host puts a file, a commit and a line of history in its own URLs.
#
# Nearly every link this scanner writes is the same three parts: the instance,
# the repository, and a path saying "this file at this ref".  Only the last
# part differs, and it differed in eleven jq programs that all assumed GitHub.
# So it is described once, here, and read from there.
#
#   blob         the path to a file at a branch
#   blob_commit  the same at a commit, which some hosts spell differently
#   commit       the path to a commit on its own
#   blame        line by line authorship of a file at a branch
#   blame_commit the same at a commit
#   history      the commits that touched one file
#   line         what goes in front of a line number in the anchor
#
# An empty value means this host has no such link, and the writer emits
# nothing rather than a URL that returns a 404.  A host that is not named here
# gets the GitHub shape, which is what it had before this existed: wrong for
# some of them, and not made wrong by this.
provider_link_parts() {
  case "$(provider_name)" in
    gitlab)
      jq -cn '{blob:"-/blob", blob_commit:"-/blob", commit:"-/commit",
               blame:"-/blame", blame_commit:"-/blame",
               history:"-/commits", line:"#L"}' ;;
    gitea|forgejo)
      # Gitea says which kind of ref it is being handed rather than working it
      # out, so a branch and a commit are different paths.  There is no /blob/
      # route at all: a GitHub shaped link is not a redirect here, it is a 404.
      jq -cn '{blob:"src/branch", blob_commit:"src/commit", commit:"commit",
               blame:"blame/branch", blame_commit:"blame/commit",
               history:"commits/branch", line:"#L"}' ;;
    bitbucket)
      # Bitbucket anchors a line as #lines-12, and has no file history page
      # worth linking to, so that one is left out rather than guessed at.
      jq -cn '{blob:"src", blob_commit:"src", commit:"commits",
               blame:"annotate", blame_commit:"annotate",
               history:"", line:"#lines-"}' ;;
    *)
      jq -cn '{blob:"blob", blob_commit:"blob", commit:"commit",
               blame:"blame", blame_commit:"blame",
               history:"commits", line:"#L"}' ;;
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
