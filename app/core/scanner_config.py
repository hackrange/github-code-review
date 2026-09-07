"""Building the scanner's config from what is in the database.

The scanner is a bash program and it wants JSON on disk.  That file used to be
something you edited by hand, which meant the name of whatever you scan lived
in the source tree.  Now the shape comes from scanner_defaults, the site
specific parts come from the settings table, and the result is written into a
temp directory when a scan starts and deleted when it finishes.

The token never goes in the file.  It goes in as an environment variable, so it
is never written to disk at all.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import stat
from pathlib import Path

from app.core import exclusions as exclusions_store
from app.core import settings_store as store
from app.core.scanner_defaults import template

log = logging.getLogger("gcr.scanner.config")

# Detection rules that ship with the app rather than being configured.
RULES_DIR = Path(__file__).resolve().parents[2] / "config"


def _text(session, key, fallback=""):
    value = store.get(session, key)
    return str(value) if value not in (None, "") else fallback


def _int(session, key, fallback=0):
    try:
        return int(store.get(session, key))
    except (TypeError, ValueError):
        return fallback


# What somebody types when they mean everything.  Everything is what an empty
# list already means here, so these all become one.
EVERYTHING = {"*", "all", "any", "everything"}


def widen(items) -> list:
    """Turn "everything" into an empty list, which is how it is expressed.

    A star left as a literal switches discovery off and sends the scanner
    looking for an organization by that name, which finds nothing and reports
    success.  That is the worst kind of wrong: a scheduled scan that runs every
    night and covers nothing at all.
    """
    if not items:
        return []
    cleaned = [str(item).strip() for item in items if str(item).strip()]
    if any(item.lower() in EVERYTHING for item in cleaned):
        return []
    return cleaned


def _list(session, key):
    value = store.get(session, key)
    items = list(value) if isinstance(value, (list, tuple)) else []
    return widen(items)


def _write_resume_state(session, out_dir: Path, connection) -> Path:
    """Where each repository's history walk got to, for the scanner to resume.

    The scanner is a separate program with no database, so what it needs to
    carry on comes in the same way its configuration does: a file it is handed,
    written when the scan starts and gone with the temp directory afterwards.
    """
    from app.core.models import Repository

    state = {}
    query = session.query(Repository.full_name, Repository.history_from,
                          Repository.history_complete, Repository.last_scanned_at)
    if connection is not None:
        query = query.filter(Repository.connection_id == connection.id)
    for full_name, since, complete, seen in query:
        if not full_name:
            continue
        # "head" is when this repository was last looked at from the newest end.
        # Walking backwards through old history must not mean ignoring what has
        # been pushed since: a repository six runs from the far end would have
        # six runs of new commits nobody examined.
        state[full_name] = {"from": since or "",
                            "complete": bool(complete),
                            "head": seen.strftime("%Y-%m-%d") if seen else ""}

    path = out_dir / "history-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return path


def build(session, out_dir: Path, orgs=None, repos=None, connection=None) -> Path:
    """Write a scanner config and give back the path.

    orgs and repos override what is stored, which is how a scan of one
    organization from the Schedules page works without changing settings.

    connection points the whole thing at one account: its address, its
    credential and the organizations it covers.  Without one it falls back to
    the settings, which is what an install that predates connections has.
    """
    document = template()

    # Which host this connection points at.  The scanner reads it to pick an
    # implementation; everything downstream of the clone is the same either way.
    document["provider"] = (getattr(connection, "provider", None) or "github"
                            if connection is not None else "github")

    github = document["github"]
    if connection is not None:
        github["api_url"] = connection.api_url or "https://api.github.com"
        github["web_url"] = connection.web_url or "https://github.com"
        method = connection.auth_method or "pat"
        app_id = connection.app_id or ""
        installation = connection.app_installation or ""
    else:
        github["api_url"] = _text(session, "github.api_url", "https://api.github.com")
        github["web_url"] = _text(session, "github.web_url", "https://github.com")
        method = _text(session, "github.auth_method", "pat")
        app_id = _text(session, "github.app_id")
        installation = _text(session, "github.app_installation")
    github["graphql_url"] = github["api_url"].rstrip("/") + "/graphql"

    auth = github["auth"]
    auth["method"] = method
    auth["pat"]["token_env"] = "GHSCAN_TOKEN"
    auth["pat"]["token_file"] = ""
    auth["app"]["app_id"] = app_id
    auth["app"]["installation_id"] = installation
    auth["app"]["private_key_path"] = (
        str(out_dir / "github-app.pem") if method == "app" else "")

    scope = github["scope"]
    # widen here too: orgs can arrive from a schedule rather than the settings.
    if orgs is not None:
        scope["orgs"] = widen(orgs)
    elif connection is not None:
        scope["orgs"] = widen(connection.scope_orgs())
    else:
        scope["orgs"] = _list(session, "scan.organizations")
    scope["users"] = []
    if repos is not None:
        scope["include_repos"] = widen(repos)
    elif connection is not None:
        scope["include_repos"] = widen(connection.scope_repos())
    else:
        scope["include_repos"] = _list(session, "scan.repositories")
    scope["exclude_repos"] = _list(session, "scan.exclude_repos")
    scope["exclude_repo_regex"] = ""
    scope["include_archived"] = bool(store.get(session, "scan.include_archived"))
    scope["include_forks"] = bool(store.get(session, "scan.include_forks"))
    scope["max_repos"] = _int(session, "scan.max_repos", 0)
    # Only go looking when nothing was named.  Naming an organization means
    # that organization: pulling in everything else the credential happens to
    # reach turns a scan of one org into a scan of whatever is lying around,
    # and it does it while reporting the org you asked for.
    named = bool(scope["orgs"] or scope["include_repos"])
    scope["auto_discover_orgs"] = not named
    scope["include_collaborator_repos"] = not named

    branches = github["branches"]
    branches["mode"] = _text(session, "branches.mode", "all")
    branches["include"] = _list(session, "branches.include")
    branches["exclude"] = _list(session, "branches.exclude")
    branches["scan_full_history"] = bool(store.get(session, "branches.full_history"))
    # These two were in the scanner from the start and had no way to reach it
    # from here, so the only lever a big estate had was dropping to the default
    # branch and giving up everything else.
    branches["max_per_repo"] = _int(session, "branches.max_per_repo", 0)
    branches["stale_days"] = _int(session, "branches.stale_days", 0)

    # A connection can name its own branches, and when it does they win.
    #
    # One rule for the whole estate is the wrong shape: an account holding a
    # few release repositories and an account holding thousands of abandoned
    # feature branches want different answers, and the only place that
    # difference is known is the connection.  Empty here, or a star, leaves the
    # setting above in charge.
    named_branches = (widen(connection.scope_branches())
                      if connection is not None else [])
    if named_branches:
        branches["mode"] = "list"
        branches["include"] = named_branches
        # The skip list is written for the estate, not for this account.  A
        # connection that asks for master has asked for it, so a global glob
        # that would swallow one of these names is dropped rather than quietly
        # winning and scanning nothing.
        kept = [pattern for pattern in branches["exclude"]
                if not any(fnmatch.fnmatchcase(name, pattern)
                           for name in named_branches)]
        if kept != branches["exclude"]:
            log.info("connection %s names branches the global skip list would "
                     "have dropped; the connection wins", connection.name)
        branches["exclude"] = kept

    clone = document["clone"]
    clone["workdir"] = str(out_dir / "work")
    clone["max_repo_size_mb"] = _int(session, "clone.max_repo_size_mb", 4096)

    scan = document["scan"]
    scan["parallel_repos"] = _int(session, "github.parallel_repos", 4)
    scan["timeout_per_repo_sec"] = _int(session, "scan.timeout_per_repo", 3600)

    secrets = scan["secrets"]
    secrets["enabled"] = bool(store.get(session, "secrets.enabled"))
    secrets["resolve_commit_authors"] = bool(store.get(session, "secrets.resolve_authors"))
    secrets["trufflehog"]["verify"] = bool(store.get(session, "secrets.verify"))
    secrets["trufflehog"]["concurrency"] = max(1, _int(session, "secrets.concurrency", 8))
    # Walking the history a window at a time, and picking up where the last run
    # stopped.  Zero keeps the single pass over everything.
    secrets["history_window_days"] = max(0, _int(session, "secrets.history_window_days", 0))
    if secrets["history_window_days"] > 0:
        secrets["resume_file"] = str(_write_resume_state(session, out_dir, connection))
    try:
        secrets["triage"]["min_entropy"] = float(store.get(session, "secrets.min_entropy"))
    except (TypeError, ValueError):
        secrets["triage"]["min_entropy"] = 3.0
    try:
        secrets["triage"]["min_length"] = int(store.get(session, "secrets.min_length"))
    except (TypeError, ValueError):
        secrets["triage"]["min_length"] = 12
    secrets["triage"]["drop_unverified_below_entropy"] = bool(
        store.get(session, "secrets.drop_below_entropy"))

    # What counts as an example rather than a credential.  The shipped rules
    # plus whatever this installation added, minus any shipped one it turned
    # off.  Built here rather than left as the template's list so a rule an
    # admin wrote reaches the scanner without anybody editing the image.
    from app.core import triage_rules
    rules = triage_rules.effective(session)
    secrets["triage"]["placeholder_patterns"] = rules["value"]
    secrets["triage"]["placeholder_paths"] = rules["path"]

    # A cap on any one file, which is not the same as the cap on the whole
    # repository.  A repository well under the repository limit can still hold
    # one enormous file, and reading it whole is what took the scanner to 28 GB
    # and got it killed by the kernel.
    secrets["gitleaks"]["max_target_megabytes"] = _int(session, "secrets.max_file_mb", 25)
    # Read by both engines rather than one, unlike the code pass equivalent.
    # A list that half the pass ignores is worse than no list: it reads as
    # done and is not.
    secrets["exclude_paths"] = _list(session, "secrets.exclude_paths")

    secrets["gitleaks"]["config_path"] = str(RULES_DIR / "gitleaks-extra.toml")
    # The allowlist used to be a second file.  Exclusions cover the same ground
    # and they are in the database, so there is nothing to point at here.
    secrets["triage"]["allowlist_file"] = ""

    code = scan["code_analysis"]
    code["enabled"] = bool(store.get(session, "code.enabled"))
    code["rulesets"] = _list(session, "code.rulesets")
    # semgrep's own parallelism.  Two was chosen for a machine with four cores
    # and stayed there, which on a large one means twenty rule packs walking a
    # big repository on two processes while sixty cores watch.
    code["jobs"] = max(1, _int(session, "code.jobs", 2))
    code["exclude_paths"] = _list(session, "code.exclude_paths")
    # Shipped with the product, not fetched: the registry can be unavailable
    # and these cover weaknesses the public packs miss outright.
    code["extra_rules_path"] = str(RULES_DIR / "semgrep-extra.yaml")
    code["triage"] = True
    # Only rules somebody agreed to set aside.  A request that nobody has
    # approved does not reach the scanner, so its findings keep arriving.
    from app.core import rule_mutes
    code["muted_rules"] = rule_mutes.effective(session)

    sbom = scan["sbom"]
    sbom["enabled"] = bool(store.get(session, "sbom.enabled"))
    sbom["enrich"] = _list(session, "sbom.enrich")
    sbom["scan_branches"] = _text(session, "sbom.scan_branches", "default")
    sbom["license_policy"]["denied"] = _list(session, "sbom.denied_licenses")
    sbom["license_policy"]["flagged"] = _list(session, "sbom.flagged_licenses")

    scan["images"]["enabled"] = bool(store.get(session, "images.enabled"))

    vulns = scan["vulnerabilities"]
    vulns["enabled"] = bool(store.get(session, "vulns.enabled"))
    vulns["min_severity"] = _text(session, "vulns.min_severity", "all")

    scan["access"]["enabled"] = bool(store.get(session, "access.enabled"))
    scan["pull_history"]["enabled"] = bool(store.get(session, "pulls.enabled"))

    intel = scan["threat_intel"]
    intel["enabled"] = bool(store.get(session, "intel.enabled"))
    intel["kev_url"] = _text(session, "intel.kev_url", intel.get("kev_url", ""))
    intel["epss_url"] = _text(session, "intel.epss_url", intel.get("epss_url", ""))
    intel["max_age_hours"] = _int(session, "intel.max_age_hours", 24)

    # The exclusions go out as a CSV next to the config.
    rules_csv = out_dir / "exclusions.csv"
    # Only the exclusions that apply to what this system holds.  A rule that
    # names a label this connection carries is simply left out, so the finding
    # arrives normally rather than being hidden.
    exclusions_store.write_csv(
        session, rules_csv,
        getattr(connection, "sensitivity", "") if connection is not None else "")
    scan["exclusions"]["enabled"] = bool(store.get(session, "exclusions.enabled"))
    scan["exclusions"]["file"] = str(rules_csv)

    output = document["output"]
    output["dir"] = str(out_dir / "scan-output")
    output["per_repo_files"] = bool(store.get(session, "output.per_repo_files"))
    output["include_clean_repos"] = bool(store.get(session, "output.include_clean"))

    limits = document["rate_limit"]
    limits["min_remaining"] = _int(session, "rate.min_remaining", 100)
    limits["adaptive_pacing"] = bool(store.get(session, "rate.adaptive_pacing"))
    # Under an hour and a wait for the reset gets cut short, then the retries
    # burn out against a limit that has not moved yet.
    limits["max_sleep_sec"] = max(3700, _int(session, "rate.max_sleep_sec", 3900))
    limits["retries"] = _int(session, "rate.retries", 5)

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "scanner-config.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return path


def scanner_env(session, base_env: dict = None, connection=None) -> dict:
    """The environment the scanner runs with.

    The token goes in as a variable rather than into the config file, so it is
    never written to disk at all.
    """
    from app.core import connections as connection_store

    env = dict(base_env if base_env is not None else os.environ)
    if connection is not None:
        token = connection_store.secret_of(connection, "token")
    else:
        token = store.get(session, "github.token") or ""
    if token:
        env["GHSCAN_TOKEN"] = token
    env.setdefault("GHSCAN_COLOR", "never")

    # How many threads each Go engine may use.
    #
    # gitleaks, trufflehog, syft and grype are all Go, and a Go program with no
    # GOMAXPROCS helps itself to every core on the machine.  That is right for
    # one repository at a time and wrong for sixteen: sixty four cores times
    # sixteen workers is a thousand threads fighting over the same cores, and
    # the scan gets slower the more of the machine it is given.  Divide the
    # machine by the workers instead.  Anything already set is left alone,
    # because somebody who set it meant it.
    #
    # The workers are not this scan's alone.  Repositories at once is per scan,
    # and scans at once decides how many of those there are, so the two
    # multiply: twelve of one and eight of the other is ninety six workers, and
    # dividing by twelve hands each of them a share of a machine that ninety six
    # of them are already sharing.
    #
    # Divide by what is actually running rather than by what is allowed.  A scan
    # on its own gets the whole machine, which is the common case and the one
    # that would be paid for twice over by budgeting for a crowd that never
    # turned up; a scan starting into seven others gets a share.  Scans already
    # under way keep the budget they started with, because their engines are
    # long since running and there is nothing to tell.
    if "GOMAXPROCS" not in env:
        cores = os.cpu_count() or 4
        per_scan = max(1, _int(session, "github.parallel_repos", 4))
        allowed = max(1, _int(session, "scan.max_concurrent", 1))
        try:
            from app.core.models import ScanRun
            live = (session.query(ScanRun)
                    .filter(ScanRun.status == "running").count())
        except Exception:
            # No answer means assume the worst rather than the best: a budget
            # that is too small is slow, one that is too large is a thrash.
            live = allowed - 1
        sharing = min(allowed, max(1, live + 1))
        env["GOMAXPROCS"] = str(max(2, cores // (per_scan * sharing)))
    return env


def write_app_key(session, path: Path, connection=None) -> bool:
    """Drop the GitHub App private key where the scanner expects it."""
    from app.core import connections as connection_store

    if connection is not None:
        key = connection_store.secret_of(connection, "app_key")
    else:
        key = store.get(session, "github.app_key") or ""
    if not key:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key if key.endswith("\n") else key + "\n", encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return True
