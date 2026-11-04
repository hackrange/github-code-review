"""External sites: the company's domains as the internet sees them.

The rest of this product reads code.  This is where the host names live, what
answers on them, the dynamic scans run against them and which server ran
each one, and the repositories behind them, so a finding on the live site
and a finding in the code can be read side by side.

Administrators only, and only when switched on in Settings.

The pieces:

    inventory     the hosts, their tags and their application
    telemetry     external_probe, the outside view of each host
    mapping       which repositories are behind a host, worked out and said
    scans         external_dast plus dast_engines here, a nextgen-dast server
                  driven through its API, or a scan recorded by hand or API
    AI            a triage of one scan, and a read of a site's dynamic and
                  static findings together, both through app.core.ai and both
                  counted on the AI cost page

A host marked no scan, or under a domain marked no scan, never has a scan
started against it from here.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from sqlalchemy import func

from app.config import settings as app_settings
from app.core.db import session_scope
from app.core.models import (
    DastServer, ExternalAsset, ExternalAssetRepo, ExternalAssetTag,
    ExternalDastScan, Finding, FindingState, Repository, RepoDiagram, utcnow,
)

log = logging.getLogger("gcr.external")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SCAN_SOURCES = {"builtin": "Built in", "remote": "DAST server", "recorded": "Recorded"}
SERVER_KINDS = {"nextgen-dast": "nextgen-dast (started and read from here)",
                "other": "Other (scans are recorded by hand or through the API)"}
BUILTIN_SERVER = "Git Code Review"
# The starting list.  The real one is the external.environments setting; see
# environments().  A site stores the name in lower case, so renaming Prod to
# PROD keeps every site in it, and these four match what sites always held.
ENVIRONMENTS = {"prod": "Prod", "dev": "Dev", "stage": "Stage", "clone": "Clone"}
ENV_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()/&+-]{0,39}$")


def env_key(name) -> str:
    return re.sub(r"\s+", " ", str(name or "")).strip().casefold()[:40]


def clean_environments(raw) -> list:
    """The Settings list, checked.  Comma or line separated.  Raises ValueError."""
    if isinstance(raw, str):
        raw = raw.replace("\r", "\n").replace("\n", ",").split(",")
    out, seen = [], set()
    for item in raw or []:
        name = re.sub(r"\s+", " ", str(item or "")).strip()
        if not name:
            continue
        if not ENV_NAME.fullmatch(name):
            raise ValueError(f"Environment {name[:60]!r} has to be up to 40 letters, numbers, "
                             "spaces or . _ ( ) / & + - and start with a letter or number.")
        if env_key(name) not in seen:
            seen.add(env_key(name))
            out.append(name)
    if not out:
        raise ValueError("Keep at least one environment.")
    if len(out) > 40:
        raise ValueError("At most 40 environments.")
    return out


def environments(db) -> dict:
    """{key: name} from Settings, in its order.  The first is the default."""
    from app.core import settings_store

    try:
        names = clean_environments(settings_store.get(db, "external.environments") or [])
    except ValueError:
        names = list(ENVIRONMENTS.values())
    return {env_key(n): n for n in names}


def default_environment(db) -> str:
    return next(iter(environments(db)))
STATUSES = {"active": "Active", "obsolete": "Obsolete"}
MAX_PICKS = 200
MAX_BRANCHES = 300

# How sure a worked out link between a host and a repository has to be before
# it counts without anybody saying so.  Below this it is a suggestion.
LINK_THRESHOLD = 60
MAX_WHITEBOX_REPOS = 3
MAX_FINDINGS = 3000


# ------------------------------------------------------------------ settings

def enabled(db) -> bool:
    from app.core import settings_store

    return bool(settings_store.get(db, "external.enabled"))


def options(db) -> dict:
    from app.core import external_probe, settings_store as s

    # Every request a scan or a telemetry read makes uses this one.
    external_probe.set_user_agent(s.get(db, "external.user_agent") or "")
    return {"screenshots": bool(s.get(db, "external.screenshots")),
            "allow_private": bool(s.get(db, "external.allow_private")),
            "refresh_days": int(s.get(db, "external.refresh_days") or 0),
            "max_age_days": int(s.get(db, "dast.max_age_days") or 0),
            "whitebox": bool(s.get(db, "external.whitebox"))}


def data_dir() -> Path:
    path = app_settings.data_dir / "external"
    path.mkdir(parents=True, exist_ok=True)
    return path


def shot_path(asset_id: int) -> Path:
    return data_dir() / "shots" / f"{int(asset_id)}.png"


def thumb_path(asset_id: int) -> Path:
    """The small JPEG the list shows in place of the full screenshot."""
    return data_dir() / "shots" / f"{int(asset_id)}.thumb.jpg"


def drop_shot(asset_id: int) -> None:
    shot_path(asset_id).unlink(missing_ok=True)
    thumb_path(asset_id).unlink(missing_ok=True)


def thumb_fresh(asset_id: int) -> bool:
    """A thumbnail made from the screenshot that is there now."""
    try:
        return thumb_path(asset_id).stat().st_mtime >= shot_path(asset_id).stat().st_mtime
    except OSError:
        return False


def make_thumbs(asset_ids) -> int:
    """Shrink these sites' screenshots in one browser.  -> how many written.
    Quietly does nothing where Playwright is not installed; the list then
    falls back to the full screenshot."""
    import subprocess

    from app.core import external_probe

    py = external_probe.playwright_python()
    script = Path(__file__).with_name("browser_thumb.py")
    argv = []
    for asset_id in asset_ids:
        if shot_path(asset_id).is_file():
            argv += [str(shot_path(asset_id)), str(thumb_path(asset_id))]
    if not py or not script.is_file() or not argv:
        return 0
    written = 0
    for start in range(0, len(argv), 100):  # 50 a browser keeps argv short
        try:
            proc = subprocess.run([py, str(script), *argv[start:start + 100]],
                                  capture_output=True, text=True, timeout=300)
            got = json.loads((proc.stdout or "").strip().splitlines()[-1])
        except (subprocess.TimeoutExpired, ValueError, IndexError, OSError) as exc:
            log.warning("thumbnails failed: %s", exc)
            continue
        written += int(got.get("written") or 0)
        if got.get("error"):
            log.warning("thumbnails: %s", got["error"])
    return written


_thumb_lock = threading.Lock()


def backfill_thumbs(asset_ids) -> bool:
    """Make missing or stale thumbnails off the request thread.  One pass at
    a time; a pass already running is left to finish.  -> started or not."""
    todo = [a for a in asset_ids if shot_path(a).is_file() and not thumb_fresh(a)]
    if not todo or not _thumb_lock.acquire(blocking=False):
        return False

    def run():
        try:
            make_thumbs(todo)
        finally:
            _thumb_lock.release()

    threading.Thread(target=run, name="gcr-thumbs", daemon=True).start()
    return True


# ------------------------------------------------------------------ hosts

def parent_of(host: str) -> str:
    from app.core.diagram import registrable

    return registrable(host) or host


def parse_lines(text: str) -> tuple:
    """Hosts from a pasted list or CSV.  -> ([{host, application, tags}], [problems])

    One per line: host, then optionally an application, then tags separated
    by semicolons or bars.  A header line and # comments are skipped.
    """
    import csv
    import io

    from app.core.external_probe import clean_host

    rows, problems, seen = [], [], set()
    for number, cells in enumerate(csv.reader(io.StringIO(text or "")), 1):
        if not cells or not cells[0].strip() or cells[0].lstrip().startswith("#"):
            continue
        raw = cells[0].strip()
        if number == 1 and raw.lower() in ("host", "domain", "hostname", "fqdn", "url", "site"):
            continue
        host = clean_host(raw)
        if not host:
            problems.append(f"line {number}: {raw[:80]!r} is not a host name")
            continue
        if host in seen:
            continue
        seen.add(host)
        tags = []
        if len(cells) > 2:
            tags = [t for t in re.split(r"[;|]", cells[2]) if t.strip()]
        rows.append({"host": host, "application": (cells[1].strip() if len(cells) > 1 else "")[:200],
                     "tags": tags})
        if len(rows) > 5000:
            problems.append("stopped at 5000 hosts")
            break
    return rows, problems


def clean_tags(values) -> list:
    out, seen = [], set()
    for value in values or []:
        tag = re.sub(r"\s+", " ", str(value or "")).strip()[:100]
        if tag and tag.casefold() not in seen:
            seen.add(tag.casefold())
            out.append(tag)
    return out[:30]


def clean_owners(value, what: str) -> str:
    """One or more addresses, comma or space separated.  -> "a@x.com, b@y.com"

    Raises ValueError naming the first entry that is not an address.  An owner
    field holding a name instead of an address is one nobody can mail.
    """
    from app.core import tagging

    out = []
    for part in re.split(r"[,;\s]+", str(value or "").strip()):
        if not part:
            continue
        if not tagging.ADDRESS.fullmatch(part) or len(part) > 254:
            raise ValueError(f"{what}: {part[:80]!r} is not an email address.")
        if part.lower() not in (o.lower() for o in out):
            out.append(part)
    text = ", ".join(out)
    if len(text) > 500:
        raise ValueError(f"{what}: too many addresses.")
    return text


def clean_details(data: dict, partial: bool = False, envs: dict = None,
                  keep_env: str = "") -> dict:
    """The fields a person fills in about a site, checked.

    data holds strings as a form sends them, or JSON values from the API.
    With partial, fields that are absent are left out of the answer so an
    update only touches what it names.  Raises ValueError with a sentence.
    """
    out = {}

    def present(key):
        return key in data and data[key] is not None

    if present("executive_owner") or not partial:
        out["executive_owner"] = clean_owners(data.get("executive_owner"), "Executive owner")
    if present("technical_owner") or not partial:
        out["technical_owner"] = clean_owners(data.get("technical_owner"), "Technical owner")
    for key in ("comments", "notes"):
        if present(key):
            out["notes"] = str(data[key])[:4000].strip()
            break
    else:
        if not partial:
            out["notes"] = ""
    if present("status") or not partial:
        value = str(data.get("status") or "active").strip().lower()
        if value not in STATUSES:
            raise ValueError("Status is Active or Obsolete.")
        out["status"] = value
    if present("environment") or not partial:
        envs = envs or ENVIRONMENTS
        value = env_key(data.get("environment")) or next(iter(envs))
        # A site may keep an environment that was taken off the list since.
        if value not in envs and value != env_key(keep_env):
            names = list(envs.values())
            raise ValueError("Environment is " + (", ".join(names[:-1]) + " or " + names[-1]
                                                  if len(names) > 1 else names[0]) + ".")
        out["environment"] = value
    for key in ("external_auth_needed", "whitelist_needed"):
        if present(key) or not partial:
            value = data.get(key)
            if isinstance(value, str):
                value = value.strip().lower() in ("1", "on", "true", "yes")
            out[key] = bool(value)
    if present("default_profile") or not partial:
        from app.core import dast_engines

        value = str(data.get("default_profile") or "").strip().lower()
        if value and value not in dast_engines.PROFILES:
            raise ValueError("The default scan profile is baseline, quick, standard, "
                             "thorough or premium.")
        out["default_profile"] = value
    if present("change_frequency_days") or not partial:
        raw = data.get("change_frequency_days")
        if raw in (None, ""):
            out["change_frequency_days"] = None
        else:
            try:
                days = int(str(raw).strip())
            except ValueError:
                raise ValueError("Change frequency is a number of days.")
            if not 0 < days <= 3650:
                raise ValueError("Change frequency is between 1 and 3650 days.")
            out["change_frequency_days"] = days
    return out


PROXY_RE = re.compile(r"^https?://([^:@/\s]+(:[^@/\s]*)?@)?[A-Za-z0-9.-]+(:\d{1,5})?/?$")


def proxy_of(asset) -> str:
    """The site's proxy, decrypted, or empty."""
    from app.core import settings_store as store

    if not getattr(asset, "proxy", ""):
        return ""
    try:
        return store._decrypt(asset.proxy) or ""
    except Exception:  # noqa: BLE001 - a key change makes it unreadable
        return ""


def proxy_shown_url(url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(url or "")
    user = f"{parsed.username}:****@" if parsed.username else ""
    return f"{parsed.scheme}://{user}{parsed.hostname}:{parsed.port or 80}" if url else ""


def proxy_shown(asset) -> str:
    """The proxy as the page and the API may show it: never its password."""
    from urllib.parse import urlparse

    url = proxy_of(asset)
    if not url:
        return ""
    parsed = urlparse(url)
    user = f"{parsed.username}:****@" if parsed.username else ""
    return f"{parsed.scheme}://{user}{parsed.hostname}:{parsed.port or 80}"


def set_proxy(asset, value) -> None:
    """Set the site's proxy, or clear it with an empty value.  Raises ValueError."""
    from urllib.parse import urlparse

    from app.core import settings_store as store

    text = str(value or "").strip()
    if not text:
        asset.proxy = ""
        return
    if len(text) > 500 or not PROXY_RE.fullmatch(text):
        raise ValueError("The proxy is http://host:port, or http://user:password@host:port.")
    port = urlparse(text).port
    if port is not None and not 0 < port < 65536:
        raise ValueError("The proxy's port is 1 to 65535.")
    asset.proxy = store._encrypt(text)


BULK_FIELDS = ("application", "executive_owner", "technical_owner", "environment",
               "status", "external_auth_needed", "whitelist_needed",
               "change_frequency_days", "default_profile")


def bulk_update(db, assets: list, changes: dict, actor: str, user=None) -> list:
    """Apply the same changes to many sites, all or nothing.

    changes holds only what is to change:
        details      {field: value} for BULK_FIELDS, checked like Edit
        tags         (add | remove | replace, [tags])
        comments     (replace | append, text)
        no_scan      (bool, reason)
        proxy        a proxy address, or "" to remove it
        auth         (kind, {values}) as Edit takes it; kind "" removes it
        repositories (add | replace | clear, [(repository id, branch)])

    Every site is checked before any is written; the first one that will not
    take a change raises ValueError naming it, and the caller rolls back.
    -> the hosts changed
    """
    from app.core import external_auth

    envs = environments(db)
    details = dict(changes.get("details") or {})
    application = details.pop("application", None)
    cleaned = clean_details(details, partial=True, envs=envs) if details else {}
    tags = changes.get("tags")
    if tags and tags[0] not in ("add", "remove", "replace"):
        raise ValueError("Tags are added, removed or replaced.")
    comments = changes.get("comments")
    if comments and comments[0] not in ("replace", "append"):
        raise ValueError("Comments are replaced or added to.")
    repos = changes.get("repositories")
    if repos and repos[0] not in ("add", "replace", "clear"):
        raise ValueError("Repositories are added, replaced or cleared.")
    changed = []
    for asset in assets:
        try:
            if application is not None:
                asset.application = str(application)[:200].strip()
            for key, value in cleaned.items():
                setattr(asset, key, value)
            if tags:
                mode, values = tags
                have = asset.tag_list()
                wanted = clean_tags(values)
                if mode == "add":
                    set_tags(asset, have + wanted)
                elif mode == "remove":
                    drop = {t.casefold() for t in wanted}
                    set_tags(asset, [t for t in have if t.casefold() not in drop])
                else:
                    set_tags(asset, wanted)
            if comments:
                mode, text = comments
                text = str(text or "").strip()
                if mode == "append" and asset.notes and text:
                    text = (asset.notes.rstrip() + "\n" + text)
                asset.notes = text[:4000] if (mode == "replace" or text) else asset.notes
            if changes.get("no_scan") is not None:
                flag, reason = changes["no_scan"]
                asset.no_scan = bool(flag)
                asset.no_scan_reason = (str(reason or "")[:300] if flag else "")
            if "proxy" in changes:
                set_proxy(asset, changes["proxy"] or "")
            if changes.get("auth") is not None:
                kind, values = changes["auth"]
                external_auth.save(asset, kind, values, actor, asset.parent_domain)
            if repos:
                mode, picks = repos
                if mode == "add":
                    current = [tuple(p.split("|", 1)) for p in picks_of(db, asset)]
                    merged = [(int(r), b) for r, b in current]
                    merged += [p for p in picks if p not in merged]
                    set_picks(db, asset, merged, actor, user)
                elif mode == "replace":
                    set_picks(db, asset, picks, actor, user)
                else:
                    set_picks(db, asset, [], actor, user)
        except ValueError as exc:
            raise ValueError(f"{asset.host}: {exc}")
        changed.append(asset.host)
    db.flush()
    return changed


def profile_for(asset: ExternalAsset) -> str:
    """The profile a scan of this site starts with when nobody picks one."""
    from app.core import dast_engines

    value = (getattr(asset, "default_profile", "") or "").lower()
    return value if value in dast_engines.PROFILES else dast_engines.DEFAULT_PROFILE


def apply_details(asset: ExternalAsset, details: dict) -> None:
    for key, value in details.items():
        setattr(asset, key, value)


def branches_of(repo) -> list:
    """Every branch name the scans have seen on a repository, default first."""
    names = []
    for raw in (repo.branch_names_present, repo.branch_names):
        try:
            for name in json.loads(raw or "[]") or []:
                if isinstance(name, str) and name and name not in names:
                    names.append(name)
        except ValueError:
            continue
    default = repo.default_branch or ""
    if default:
        names = [default] + [n for n in names if n != default]
    return names[:MAX_BRANCHES]


def recommend(db, user, hosts: list, application: str = "", tags=None,
              asset: ExternalAsset = None) -> list:
    """Repositories likely behind these hosts, best first, for the picker.

    The same evidence the site page uses: web addresses on the Repositories
    page, another environment of one of them, the code a diagram read, and
    the application and repository names.  -> [{id, full_name, score,
    reasons, links_itself, hosts}]
    """
    from app.core.external_probe import clean_host

    mapper = Mapper(db, user)
    found = {}
    targets = [asset] if asset is not None else []
    for raw in (hosts or [])[:50]:
        host = clean_host(raw)
        if host:
            probe = ExternalAsset(host=host, application=application or "")
            probe.tags = [ExternalAssetTag(tag=t) for t in clean_tags(tags or [])]
            targets.append(probe)
    for target in targets:
        for link in mapper.links(target):
            if link["source"] == "hidden":
                continue
            entry = found.setdefault(link["id"], {
                "id": link["id"], "full_name": link["full_name"], "score": 0,
                "reasons": [], "hosts": []})
            entry["score"] = max(entry["score"], link["score"])
            for reason in link["reasons"]:
                if reason not in entry["reasons"]:
                    entry["reasons"].append(reason)
            if target.host not in entry["hosts"]:
                entry["hosts"].append(target.host)
    out = sorted(found.values(), key=lambda e: (-e["score"], e["full_name"]))
    for entry in out:
        entry["links_itself"] = entry["score"] >= LINK_THRESHOLD
    apps, seen = [], set()
    for target in targets:
        for app in mapper.applications(target):
            if app["key"] in seen:
                continue
            seen.add(app["key"])
            apps.append({"name": app["name"] if app["named"] else "",
                         "owners": app["owners"], "technical": app["technical"],
                         "urls": app["urls"][:10],
                         "repositories": [r["full_name"] for r in app["repos"]][:20],
                         "exact": target.host in {clean_host(u) for u in app["urls"]}})
    apps.sort(key=lambda a: not a["exact"])
    return {"repositories": out[:40], "applications": apps[:10]}


def repo_choices(db, user) -> list:
    """Every repository this person may see, with its branches, for the picker."""
    from app.core import rbac

    out = []
    for repo in (rbac.visible_repositories(db, user)
                 .order_by(Repository.organization, Repository.name).all()):
        out.append({"id": repo.id, "organization": repo.organization,
                    "repository": repo.name, "full_name": repo.full_name,
                    "default": repo.default_branch or "",
                    "branches": branches_of(repo),
                    "archived": bool(getattr(repo, "archived", False))})
    return out


def parse_picks(values) -> list:
    """Picks as a form sends them, "<repository id>|<branch>".  -> [(id, branch)]"""
    out = []
    for value in values or []:
        text = str(value or "")
        repo_id, _, branch = text.partition("|")
        try:
            pick = (int(repo_id), branch.strip()[:255])
        except ValueError:
            raise ValueError("A repository pick was not understood.")
        if pick not in out:
            out.append(pick)
    if len(out) > MAX_PICKS:
        raise ValueError(f"Pick at most {MAX_PICKS} repositories and branches.")
    return out


def picks_from_names(db, items) -> list:
    """The API's form: [{"repository": "org/name", "branch": "main"}]."""
    if not isinstance(items, list):
        raise ValueError("repositories has to be a list.")
    out = []
    for item in items:
        if isinstance(item, str):
            item = {"repository": item}
        if not isinstance(item, dict) or not isinstance(item.get("repository"), str):
            raise ValueError("Each repository is an object with a repository name.")
        repo = (db.query(Repository)
                .filter(Repository.full_name == item["repository"].strip()).one_or_none())
        if repo is None:
            raise ValueError(f"No repository called {item['repository'][:120]}.")
        branch = item.get("branch") or ""
        if not isinstance(branch, str):
            raise ValueError("branch has to be a string.")
        out.append((repo.id, branch.strip()[:255]))
    return out


def set_picks(db, asset: ExternalAsset, picks: list, actor: str, user=None) -> list:
    """Make the repositories and branches somebody picked the site's own links.

    Picks for repositories the person cannot see, and branches the scans have
    never seen on that repository, are refused the same way: as not there.
    Links that were picked before and are not picked now go back to being
    worked out.  Links found in the code by a scan and links hidden on
    purpose are left alone unless the repository is picked again.
    -> the repositories linked, as full names
    """
    from app.core import rbac

    base = rbac.visible_repositories(db, user) if user is not None else db.query(Repository)
    wanted = {}
    for repo_id, branch in picks:
        repo = base.filter(Repository.id == repo_id).one_or_none()
        if repo is None:
            raise ValueError("One of the picked repositories is not one you can see.")
        if branch and branch not in branches_of(repo):
            raise ValueError(f"{repo.full_name} has no branch called {branch[:120]}.")
        entry = wanted.setdefault(repo.id, {"repo": repo, "branches": []})
        if branch and branch not in entry["branches"]:
            entry["branches"].append(branch)
    if asset.id is None:
        db.flush()
    rows = {r.repository_id: r for r in db.query(ExternalAssetRepo)
            .filter(ExternalAssetRepo.asset_id == asset.id)}
    for repo_id, row in rows.items():
        if row.source == "manual" and repo_id not in wanted:
            db.delete(row)
    for repo_id, entry in wanted.items():
        row = rows.get(repo_id)
        if row is None:
            row = ExternalAssetRepo(asset_id=asset.id, repository_id=repo_id)
            db.add(row)
        row.source = "manual"
        row.branches = json.dumps(entry["branches"]) if entry["branches"] else ""
        row.added_by = (actor or "")[:120]
        row.added_at = utcnow()
    db.flush()
    return [e["repo"].full_name for e in wanted.values()]


def picks_of(db, asset: ExternalAsset) -> list:
    """What was picked, as the form sends it: ["<id>|<branch>", ...]."""
    out = []
    for row in (db.query(ExternalAssetRepo)
                .filter(ExternalAssetRepo.asset_id == asset.id,
                        ExternalAssetRepo.source == "manual")):
        branches = _branch_list(row.branches)
        out += [f"{row.repository_id}|{b}" for b in branches] or [f"{row.repository_id}|"]
    return out


def _branch_list(raw) -> list:
    try:
        value = json.loads(raw or "[]")
    except ValueError:
        return []
    return [b for b in value if isinstance(b, str)] if isinstance(value, list) else []


def set_tags(asset: ExternalAsset, tags) -> None:
    wanted = clean_tags(tags)
    keep = {t.casefold() for t in wanted}
    for row in list(asset.tags):
        if row.tag.casefold() not in keep:
            asset.tags.remove(row)
    have = {t.tag.casefold() for t in asset.tags}
    for tag in wanted:
        if tag.casefold() not in have:
            asset.tags.append(ExternalAssetTag(tag=tag))


def add_assets(db, rows: list, actor: str, no_scan: bool = False,
               no_scan_reason: str = "", extra_tags=None, details: dict = None,
               picks: list = None, user=None) -> dict:
    """Add hosts.  An existing host gets the new tags and, when it had none,
    the application.  details and picks go on the hosts added here, not on
    ones already listed, which keep what somebody already said about them.
    -> {added, existing}"""
    added, existing = [], []
    for row in rows:
        asset = db.query(ExternalAsset).filter(ExternalAsset.host == row["host"]).one_or_none()
        if asset is None:
            parent = parent_of(row["host"])
            asset = ExternalAsset(host=row["host"], parent_domain=parent,
                                  kind="domain" if parent == row["host"] else "subdomain",
                                  application=row.get("application") or "",
                                  added_by=(actor or "")[:120],
                                  no_scan=bool(no_scan or row.get("no_scan")),
                                  no_scan_reason=(row.get("no_scan_reason")
                                                  or no_scan_reason or "")[:300])
            db.add(asset)
            asset.environment = default_environment(db)
            apply_details(asset, details or {})
            db.flush()
            if picks:
                set_picks(db, asset, picks, actor, user)
            added.append(row["host"])
        else:
            existing.append(row["host"])
            if row.get("application") and not asset.application:
                asset.application = row["application"]
        set_tags(asset, [t.tag for t in asset.tags] + list(row.get("tags") or [])
                 + list(extra_tags or []))
    db.flush()
    return {"added": added, "existing": existing}


def blocked(db, asset: ExternalAsset) -> str:
    """Why a host may not be scanned, or empty when it may."""
    if asset.no_scan:
        return asset.no_scan_reason or "marked no scan"
    for other in db.query(ExternalAsset).filter(ExternalAsset.no_scan.is_(True)).all():
        if other.id != asset.id and asset.host.endswith("." + other.host):
            return f"under {other.host}, which is marked no scan" + (
                f": {other.no_scan_reason}" if other.no_scan_reason else "")
    return ""


def blocked_hosts(db) -> list:
    return [a.host for a in db.query(ExternalAsset).filter(ExternalAsset.no_scan.is_(True))]


def is_blocked(host: str, blocked_list: list, own_flag: bool) -> bool:
    return own_flag or any(host == b or host.endswith("." + b) for b in blocked_list)


# ------------------------------------------------------------------ mapping

_ENV_WORDS = re.compile(r"^(?:dev|qa|uat|stg|stage|staging|prod|prd|test|tst|"
                        r"sandbox|sbx|demo|preprod|pre|int|perf|dr|www)\d*|"
                        r"(?:dev|qa|uat|stg|stage|staging|prod|prd|test|tst|"
                        r"sandbox|sbx|demo|dr)\d*$")


def _stem(text: str) -> str:
    """A name with its environment words and punctuation taken off."""
    value = re.sub(r"[^a-z0-9]", "", (text or "").lower())
    for _ in range(2):
        value = _ENV_WORDS.sub("", value)
    return re.sub(r"\d+$", "", value)


class Mapper:
    """Works out which repositories are behind which hosts, for a whole list
    at once.  Read everything once here rather than once per host."""

    def __init__(self, db, user=None):
        from app.core import rbac, tagging
        from app.core.external_probe import clean_host

        self.db = db
        # Only the repositories this person may see, so a link can never show
        # them a repository, or its findings, their groups keep from them.
        # The scheduled jobs pass nobody and see the whole estate.
        base = rbac.visible_repositories(db, user) if user is not None else db.query(Repository)
        repos = base.all()
        self.repos = {r.id: r for r in repos}
        applies = tagging.effective_many(db, repos)
        self.by_host, self.by_app, self.by_stem = {}, {}, {}
        # The same site in another environment: prodorders and qaorders are
        # one application, so a repository serving one likely serves both.
        self.by_url_stem, self.by_app_stem = {}, {}
        for repo in repos:
            said = applies.get(repo.id, {})
            name = ((said.get("application_name") or {}).get("value") or "").strip()
            if name:
                self.by_app.setdefault(name.casefold(), []).append(repo.id)
                app_stem = _stem(name)
                if len(app_stem) >= 4:
                    self.by_app_stem.setdefault(app_stem, []).append(repo.id)
            urls = (said.get("web_app_urls") or {}).get("value") or repo.web_app_urls or ""
            for part in str(urls).replace(",", " ").split():
                host = clean_host(part)
                if host:
                    self.by_host.setdefault(host, {}).setdefault(repo.id, "its web addresses")
                    url_stem = _stem(host.split(".")[0])
                    if len(url_stem) >= 4:
                        self.by_url_stem.setdefault(url_stem, {}).setdefault(repo.id, host)
            stem = _stem(repo.name)
            if len(stem) >= 4:
                self.by_stem.setdefault(stem, []).append(repo.id)
        self.app_names = {r.id: ((applies.get(r.id, {}).get("application_name") or {})
                                 .get("value") or "").strip() for r in repos}
        # Hosts a diagram found written into each repository's code.
        for name, graph in db.query(RepoDiagram.repository, RepoDiagram.graph).all():
            try:
                addresses = (json.loads(graph or "{}") or {}).get("addresses") or []
            except ValueError:
                continue
            repo = next((r for r in repos if r.full_name == name), None)
            if repo is None:
                continue
            for entry in addresses:
                host = clean_host((entry or {}).get("url") or "")
                if host:
                    self.by_host.setdefault(host, {}).setdefault(repo.id, "the code, found by its diagram")
        # The Web Applications tab's view: repositories grouped by
        # application, with the addresses and owners each application has.
        # A host one application lists ties every repository in it to the
        # site, not only the one that happens to carry the address.
        from app.core import webapps

        self.apps_by_host, self.apps_by_stem = {}, {}
        try:
            apps = webapps.inventory(db, base=base)
        except Exception:  # noqa: BLE001 - the mapping still works without it
            log.warning("could not read the web applications", exc_info=True)
            apps = []
        for app in apps:
            app["repo_ids"] = [r["id"] for r in app["repos"] if r["id"] in self.repos]
            for url in app["urls"]:
                host = clean_host(url)
                if not host:
                    continue
                if app not in self.apps_by_host.setdefault(host, []):
                    self.apps_by_host[host].append(app)
                url_stem = _stem(host.split(".")[0])
                if len(url_stem) >= 4:
                    self.apps_by_stem.setdefault(url_stem, {}).setdefault(app["key"], (app, host))
        self.manual = {}
        for row in db.query(ExternalAssetRepo).filter(
                ExternalAssetRepo.repository_id.in_(list(self.repos) or [0])).all():
            self.manual.setdefault(row.asset_id, {})[row.repository_id] = row

    def applications(self, asset: ExternalAsset) -> list:
        """The web applications this host belongs to, exactly or as another
        environment of one of their addresses.  -> [app], exact ones first."""
        out = list(self.apps_by_host.get(asset.host, []))
        stem = _stem(asset.host.split(".")[0])
        for app, _other in (self.apps_by_stem.get(stem) or {}).values() if len(stem) >= 4 else []:
            if app not in out:
                out.append(app)
        return out

    def links(self, asset: ExternalAsset) -> list:
        """-> [{repo, score, reasons, linked, source}] best first."""
        found = {}

        def add(repo_id, score, reason):
            entry = found.setdefault(repo_id, {"score": 0, "reasons": []})
            entry["score"] = max(entry["score"], score)
            if reason not in entry["reasons"]:
                entry["reasons"].append(reason)

        for repo_id, how in (self.by_host.get(asset.host) or {}).items():
            add(repo_id, 95 if how == "its web addresses" else 80, f"host named in {how}")
        for app in self.apps_by_host.get(asset.host, []):
            for repo_id in app["repo_ids"]:
                add(repo_id, 90, f"part of web application {app['name']}, which lists this host")
        names = [asset.application] + [t.tag for t in asset.tags]
        for name in names:
            for repo_id in self.by_app.get((name or "").strip().casefold(), []):
                add(repo_id, 70, f"application {name} matches")
        label = asset.host.split(".")[0]
        stem = _stem(label)
        if len(stem) >= 4:
            for repo_id, other in (self.by_url_stem.get(stem) or {}).items():
                if other != asset.host:
                    add(repo_id, 75, f"another environment of {other}, in its web addresses")
            for app, other in (self.apps_by_stem.get(stem) or {}).values():
                if other != asset.host:
                    for repo_id in app["repo_ids"]:
                        add(repo_id, 75, f"web application {app['name']} lists {other}, "
                                         "another environment of this host")
            for repo_id in self.by_stem.get(stem, []):
                add(repo_id, 60, f"host {label} matches the repository name")
            for repo_id in self.by_app_stem.get(stem, []):
                add(repo_id, 60, f"host {label} matches its application name")
            if len(stem) >= 6:
                for other, ids in self.by_app_stem.items():
                    if other != stem and len(other) >= 5 and (other in stem or stem in other):
                        for repo_id in ids:
                            add(repo_id, 40, f"host {label} is like its application name")
            if len(stem) >= 6:
                for other, ids in self.by_stem.items():
                    if other != stem and len(other) >= 6 and (other in stem or stem in other):
                        for repo_id in ids:
                            add(repo_id, 40, f"host {label} is like the repository name")
        out = []
        for repo_id, row in (self.manual.get(asset.id) or {}).items():
            if row.source == "hidden":
                found.pop(repo_id, None)
                continue
            entry = found.setdefault(repo_id, {"score": 0, "reasons": []})
            entry["score"] = 100
            entry["reasons"].insert(0, "confirmed in the code by a scan"
                                    if row.source == "code" else f"picked by {row.added_by or 'hand'}")
            entry["source"] = row.source
            entry["branches"] = _branch_list(row.branches)
        for repo_id, entry in found.items():
            repo = self.repos.get(repo_id)
            if repo is None:
                continue
            out.append({"repo": repo, "id": repo.id, "full_name": repo.full_name,
                        "application": self.app_names.get(repo_id, ""),
                        "score": entry["score"], "reasons": entry["reasons"],
                        "linked": entry["score"] >= LINK_THRESHOLD,
                        "source": entry.get("source", "found"),
                        "branches": entry.get("branches") or []})
        out.sort(key=lambda e: (-e["score"], e["full_name"]))
        return out


def _findings(db, user):
    from app.core import rbac

    return rbac.visible_findings(db, user) if user is not None else db.query(Finding)


def sast_counts(db, names, user=None) -> dict:
    """Open findings per repository and severity.  -> {full_name: {sev: n}}"""
    names = [n for n in names if n]
    if not names:
        return {}
    out = {}
    for repo, severity, total in (
            _findings(db, user).with_entities(
                Finding.repository, Finding.severity, func.count(Finding.id))
            .filter(Finding.repository.in_(names))
            .filter(Finding.state == FindingState.OPEN)
            .filter(Finding.out_of_scope.is_(False))
            .group_by(Finding.repository, Finding.severity).all()):
        out.setdefault(repo, {})[getattr(severity, "value", str(severity))] = total
    return out


def sast_findings(db, names, limit: int = 80, user=None) -> list:
    """The worst open findings across these repositories, for the AI."""
    from app.core.models import Severity

    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3}
    rows = (_findings(db, user).filter(Finding.repository.in_(list(names) or [""]))
            .filter(Finding.state == FindingState.OPEN)
            .filter(Finding.out_of_scope.is_(False))
            .filter(Finding.severity.in_(list(order))).limit(2000).all())
    rows.sort(key=lambda f: (order.get(f.severity, 9), -(f.risk_score or 0)))
    return rows[:limit]


RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0}


def combined_risk(asset: ExternalAsset, counts: dict) -> dict:
    """One rating from the live site and the code behind it.

    The live result leads, because it is what an attacker can reach today.
    Code findings raise it when the site is up, one step below their own
    level, since the code may not be what is deployed.  Both sides at medium
    or worse moves it up one more: two independent readings agreeing is
    worth more than either alone.
    """
    reasons = []
    dast = RANK.get(asset.last_dast_severity or "", 0)
    if asset.last_dast_at:
        reasons.append(f"last dynamic scan: {asset.last_dast_severity or 'none'}")
    else:
        reasons.append("never dynamically scanned")
    sast = 0
    for sev in ("critical", "high", "medium", "low"):
        if any((c or {}).get(sev) for c in counts.values()):
            sast = RANK[sev]
            reasons.append(f"open {sev} findings in the code behind it")
            break
    live = asset.category in ("live", "redir", "gated", "err4", "err5")
    level = dast
    if live and sast:
        level = max(level, sast - 1)
    if dast >= 2 and sast >= 2:
        level = min(4, level + 1)
        reasons.append("the site and its code both have problems")
    if not asset.last_dast_at and not counts:
        return {"level": "unknown", "reasons": reasons}
    name = next((k for k, v in RANK.items() if v == level and k != "none"), "info")
    return {"level": name if level else "low" if (dast or sast) else "info",
            "reasons": reasons}


# ------------------------------------------------------------------ telemetry fields

# Every telemetry field, in the order the site page shows them.  The scan
# fills each one in, and any of them can be filled in or corrected by hand.
# The first group is what the standalone site report wrote to its CSV; the
# DNS and registration fields are on top of that.
TELEMETRY_FIELDS = [
    ("Summary", [
        ("category", "Status"), ("status_code", "HTTP status"),
        ("probe_url", "Probe URL"), ("final_url", "Final URL"),
        ("redirect_target", "Redirect target"), ("title", "Page title"),
        ("server", "Server header"), ("powered_by", "X-Powered-By"),
        ("cdn", "CDN or firewall"), ("bot_check", "Bot check"),
        ("waf_block", "Firewall block page"), ("origin_down", "CDN could not reach the site"),
        ("http_to_https", "HTTP redirects to HTTPS"),
        ("grade", "Grade"), ("score", "Score"),
    ]),
    ("Network", [
        ("ip", "Resolved IP"), ("ips", "All IPv4 addresses"), ("ipv6", "IPv6 addresses"),
        ("ptr", "Reverse DNS"), ("isp", "ISP / netblock owner"), ("asn", "ASN"),
        ("netblock", "Netblock"), ("open_ports", "Open ports"),
    ]),
    ("DNS and registration", [
        ("nameservers", "Nameservers"), ("cname", "CNAME chain"), ("mx", "Mail servers"),
        ("registrar", "Registrar"), ("domain_created", "Domain created"),
        ("domain_expires", "Domain expires"),
    ]),
    ("TLS", [
        ("tls_version", "Negotiated version"), ("tls_cipher", "Negotiated cipher"),
        ("tls_key_type", "Key type"), ("tls_key_bits", "Key bits"),
        ("tls_signature", "Signature algorithm"), ("tls_subject", "Subject"),
        ("tls_issuer", "Issuer"), ("tls_not_before", "Not before"),
        ("tls_not_after", "Not after"), ("tls_days_left", "Days until expiry"),
        ("tls_trusted", "Chain trusted"), ("tls_legacy", "Legacy protocols accepted"),
        ("tls_san", "Subject alternative names"), ("tls_weaknesses", "TLS weaknesses"),
    ]),
    ("Headers", [
        ("missing_headers", "Missing security headers"),
    ]),
]
FIELD_KEYS = [key for _group, fields in TELEMETRY_FIELDS for key, _label in fields]
FIELD_LABELS = {key: label for _group, fields in TELEMETRY_FIELDS for key, label in fields}
INT_FIELDS = {"status_code", "score", "tls_days_left", "tls_key_bits"}

# What each security header is for, the way the site report explained it.
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "Keeps repeat visitors on HTTPS."),
    ("content-security-policy", "CSP", "Limits which scripts and resources the page may load."),
    ("x-frame-options", "X-Frame-Options", "Stops other sites framing the page (clickjacking)."),
    ("x-content-type-options", "X-Content-Type-Options", "Stops the browser guessing file types."),
    ("referrer-policy", "Referrer-Policy", "Limits what the Referer header gives away."),
    ("permissions-policy", "Permissions-Policy", "Turns off browser features the page does not use."),
    ("cross-origin-opener-policy", "COOP", "Isolates the page from windows it opens."),
    ("cross-origin-resource-policy", "CORP", "Limits who may embed what the site serves."),
]


def _joined(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value if v not in (None, ""))
    return str(value)


def flatten(rec: dict) -> dict:
    """A telemetry record as the named fields.  -> {field: text}"""
    from app.core import external_probe

    rec = rec or {}
    tls = rec.get("tls") or {}
    dns = rec.get("dns") or {}
    who = rec.get("whois") or {}
    score = rec.get("score") or {}
    legacy = [k.replace("_", ".") for k, v in (tls.get("supported") or {}).items() if v]
    out = {
        "category": external_probe.CATEGORY_NAMES.get(rec.get("category"), rec.get("category") or ""),
        "status_code": rec.get("status") or "",
        "probe_url": f"https://{rec['host']}/" if rec.get("host") else "",
        "final_url": (rec.get("rendered_url") or rec.get("final_url")) if rec.get("status") else "",
        "redirect_target": (rec.get("redirects") or [""])[-1],
        # What a browser shows beats what the first answer said: behind a
        # bot check the first answer is the check, with no title at all.
        "title": rec.get("rendered_title") or rec.get("title"), "server": rec.get("server"),
        "powered_by": rec.get("powered_by"),
        "waf_block": rec.get("waf_block") if rec.get("status") else None,
        "origin_down": rec.get("origin_down") if rec.get("status") else None,
        "cdn": rec.get("cdn"),
        "bot_check": (f"{rec['bot_check']}'s, passed by a real browser; scanners still meet it"
                      if rec.get("bot_check") and rec.get("bot_check_passed") else
                      f"{rec['bot_check']}'s bot check answers instead of the page"
                      if rec.get("bot_check") else ("none seen" if rec.get("status") else "")),
        "http_to_https": rec.get("http_to_https"),
        "grade": score.get("grade") if score.get("grade") != "N/A" else "",
        "score": score.get("score") if score.get("grade") not in (None, "N/A") else "",
        "ip": rec.get("ip"), "ips": rec.get("ips"), "ipv6": dns.get("ipv6"),
        "ptr": dns.get("ptr"), "isp": rec.get("isp"), "asn": who.get("asn"),
        "netblock": who.get("netblock"),
        "open_ports": ([f"{len(rec.get('ports') or [])} of the ports checked answer, which is "
                        "the CDN or firewall in front accepting everything, not the site's "
                        "own services"] if rec.get("ports_unreliable")
                       else [str(p) for p in rec.get("ports") or []]),
        "nameservers": dns.get("nameservers"), "cname": dns.get("cname"),
        "mx": dns.get("mx"), "registrar": who.get("registrar"),
        "domain_created": who.get("domain_created"),
        "domain_expires": who.get("domain_expires"),
        "tls_version": tls.get("negotiated_version"),
        "tls_cipher": tls.get("negotiated_cipher"), "tls_key_type": tls.get("key_type"),
        "tls_key_bits": tls.get("key_bits"), "tls_signature": tls.get("signature_algorithm"),
        "tls_subject": tls.get("subject"), "tls_issuer": tls.get("issuer"),
        "tls_not_before": (tls.get("not_before") or "")[:19].replace("T", " "),
        "tls_not_after": (tls.get("not_after") or "")[:19].replace("T", " "),
        "tls_days_left": tls.get("days_left") if tls.get("not_after") else "",
        "tls_trusted": tls.get("trusted") if tls else None,
        "tls_legacy": legacy if tls else "",
        "tls_san": tls.get("san"), "tls_weaknesses": tls.get("weaknesses"),
        "missing_headers": rec.get("missing_headers"),
    }
    return {key: _joined(out.get(key)) for key in FIELD_KEYS}


def manual_of(asset: ExternalAsset) -> dict:
    try:
        value = json.loads(asset.manual_telemetry or "{}") or {}
    except ValueError:
        return {}
    return {k: str(v) for k, v in value.items() if k in FIELD_KEYS and v not in (None, "")}


def fields_of(asset: ExternalAsset) -> list:
    """-> [(group, [{key, label, value, scan, manual}])] for the page and API."""
    scanned = flatten(telemetry_of(asset)) if asset.telemetry else {k: "" for k in FIELD_KEYS}
    by_hand = manual_of(asset)
    out = []
    for group, fields in TELEMETRY_FIELDS:
        rows = []
        for key, label in fields:
            rows.append({"key": key, "label": label,
                         "value": by_hand.get(key, scanned.get(key, "")),
                         "scan": scanned.get(key, ""), "manual": key in by_hand})
        out.append((group, rows))
    return out


def field_values(asset: ExternalAsset) -> dict:
    return {row["key"]: row["value"] for _g, rows in fields_of(asset) for row in rows}


def set_manual(asset: ExternalAsset, values: dict, replace: bool = False) -> None:
    """Fill in or clear telemetry fields by hand.  An empty value clears one.

    replace sets the whole hand filled set, as a form that shows every field
    sends it; otherwise only the fields named change, as the API does.
    """
    current = {} if replace else manual_of(asset)
    for key, value in (values or {}).items():
        if key not in FIELD_KEYS:
            raise ValueError(f"There is no telemetry field called {str(key)[:60]}.")
        text = "" if value is None else str(value).strip()
        if len(text) > 2000:
            raise ValueError(f"{FIELD_LABELS[key]} is too long.")
        if text and key in INT_FIELDS:
            try:
                int(text)
            except ValueError:
                raise ValueError(f"{FIELD_LABELS[key]} is a whole number.")
        if text:
            current[key] = text
        else:
            current.pop(key, None)
    asset.manual_telemetry = json.dumps(current) if current else ""
    sync_columns(asset)


def sync_columns(asset: ExternalAsset) -> None:
    """Copy what the list filters on out of the fields, hand filled or not."""
    from app.core import external_probe

    values = field_values(asset)
    reverse = {v: k for k, v in external_probe.CATEGORY_NAMES.items()}

    def number(key):
        try:
            return int(values.get(key) or "")
        except ValueError:
            return None

    asset.ip = (values.get("ip") or "")[:64]
    asset.category = reverse.get(values.get("category"), values.get("category") or "")[:16]
    asset.status_code = number("status_code") or 0
    asset.grade = (values.get("grade") or "")[:4]
    asset.score = number("score") or 0
    asset.tls_days_left = number("tls_days_left")


# ------------------------------------------------------------------ views

def due_status(asset: ExternalAsset, max_age_days: int, now=None) -> str:
    if asset.status == "obsolete":
        return "obsolete"
    if asset.no_scan:
        return "no-scan"
    if not asset.last_dast_at:
        return "never"
    now = now or datetime.now(timezone.utc)
    last = asset.last_dast_at if asset.last_dast_at.tzinfo else \
        asset.last_dast_at.replace(tzinfo=timezone.utc)
    if max_age_days and last < now - timedelta(days=max_age_days):
        return "due"
    return "current"


def telemetry_of(asset: ExternalAsset) -> dict:
    try:
        return json.loads(asset.telemetry or "{}") or {}
    except ValueError:
        return {}


def asset_dict(asset: ExternalAsset, links: list = None, counts: dict = None,
               blocked_reason: str = "", max_age_days: int = 0,
               base_url: str = "") -> dict:
    """The JSON the API returns for one host."""
    links = links or []
    counts = counts or {}
    linked = [l for l in links if l["linked"]]
    tele = telemetry_of(asset)
    return {
        "id": asset.id, "host": asset.host, "kind": asset.kind,
        "parent_domain": asset.parent_domain, "application": asset.application,
        "tags": asset.tag_list(), "notes": asset.notes or "",
        "comments": asset.notes or "",
        "executive_owner": asset.executive_owner or "",
        "technical_owner": asset.technical_owner or "",
        "status": asset.status or "active",
        "environment": asset.environment or "",
        "external_auth_needed": bool(asset.external_auth_needed),
        "whitelist_needed": bool(asset.whitelist_needed),
        "change_frequency_days": asset.change_frequency_days,
        "default_profile": profile_for(asset),
        "scan_auth": _auth_view(asset),
        "proxy": proxy_shown(asset) or None,
        "no_scan": bool(asset.no_scan), "no_scan_reason": asset.no_scan_reason or "",
        "scan_blocked": bool(blocked_reason), "scan_blocked_reason": blocked_reason,
        "added_at": _iso(asset.added_at), "added_by": asset.added_by,
        "telemetry": {
            "at": _iso(asset.telemetry_at), "status": asset.telemetry_status,
            "error": asset.telemetry_error or "", "ip": asset.ip,
            "isp": tele.get("isp", ""), "category": asset.category,
            "status_code": asset.status_code, "grade": asset.grade,
            "score": asset.score, "tls_days_left": asset.tls_days_left,
            "open_ports": tele.get("ports", []), "server": tele.get("server", ""),
            "title": tele.get("title", ""), "final_url": tele.get("final_url", ""),
            "missing_headers": tele.get("missing_headers", []),
            "waf_block": bool(tele.get("waf_block")),
            "screenshot": asset.screenshot,
            "screenshot_url": (f"{base_url}/external/{asset.id}/screenshot.png"
                               if asset.screenshot in ("ok", "blank", "waf") else ""),
        },
        "fields": {row["key"]: {"value": row["value"], "scan": row["scan"],
                                "manual": row["manual"]}
                   for _g, rows in fields_of(asset) for row in rows},
        "last_dast": {
            "scanned_at": _iso(asset.last_dast_at),
            "severity": asset.last_dast_severity or "",
            "result_url": asset.last_dast_url or "",
            "server": asset.last_dast_server or "",
            "status": due_status(asset, max_age_days),
        },
        # How big a scan of the site is, from the newest scan that counted.
        "url_paths": {"reachable": asset.last_paths,
                      "scanned_at": _iso(asset.last_paths_at),
                      "profile": asset.last_paths_profile or ""},
        "repositories": [{"full_name": l["full_name"], "score": l["score"],
                          "linked": l["linked"], "reasons": l["reasons"],
                          "picked": l["source"] == "manual",
                          "branches": l.get("branches") or [],
                          "open_findings": counts.get(l["full_name"], {})}
                         for l in links],
        "combined_risk": combined_risk(asset, {l["full_name"]: counts.get(l["full_name"], {})
                                               for l in linked}),
    }


def _auth_view(asset) -> dict:
    from app.core import external_auth

    return external_auth.describe(asset) or None


def scan_dict(scan: ExternalDastScan, findings: bool = False) -> dict:
    out = {"id": scan.id, "asset_id": scan.asset_id, "server": scan.server_name,
           "source": scan.source, "provider": scan.provider or "",
           "status": scan.status, "profile": scan.profile or "",
           "authenticated": bool(scan.authenticated), "auth_kind": scan.auth_kind or "",
           "step": scan.step or "", "remote_id": scan.remote_id or "",
           "started_at": _iso(scan.started_at), "scanned_at": _iso(scan.scanned_at),
           "severity": scan.severity or "",
           "counts": {s: getattr(scan, s) or 0 for s in SEVERITIES},
           "summary_only": bool(scan.summary_only),
           "result_url": scan.result_url or "", "error": scan.error or "",
           "note": scan.note or "", "recorded_by": scan.recorded_by,
           "ai": {"status": scan.ai_status or "", "calls": scan.ai_calls or 0,
                  "input_tokens": scan.ai_input_tokens or 0,
                  "output_tokens": scan.ai_output_tokens or 0,
                  "cost": scan.ai_cost or ""}}
    try:
        out["engines"] = json.loads(scan.engines or "[]")
    except ValueError:
        out["engines"] = []
    from app.core import dast_paths

    out["coverage"] = dast_paths.load(scan.paths).get("counts") or {}
    if findings:
        out["findings"] = findings_of(scan)
        try:
            out["ai"]["summary"] = json.loads(scan.ai_summary or "{}")
        except ValueError:
            out["ai"]["summary"] = {}
    return out


def findings_of(scan: ExternalDastScan) -> list:
    try:
        return json.loads(scan.findings or "[]") or []
    except ValueError:
        return []


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


# ------------------------------------------------------------------ telemetry

_tele_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="external-probe")


def start_telemetry(ids: list) -> int:
    """Queue a telemetry pass for these hosts.  -> how many were queued."""
    queued = 0
    with session_scope() as db:
        for asset in db.query(ExternalAsset).filter(ExternalAsset.id.in_(ids or [0])):
            if asset.telemetry_status == "running":
                continue
            asset.telemetry_status = "running"
            asset.telemetry_error = ""
            queued += 1
            _tele_pool.submit(_telemetry, asset.id)
    return queued


def _telemetry(asset_id: int) -> None:
    from app.core import external_probe

    try:
        with session_scope() as db:
            asset = db.get(ExternalAsset, asset_id)
            if asset is None:
                return
            host, opts, why = asset.host, options(db), blocked(db, asset)
        path = shot_path(asset_id)
        with session_scope() as db:
            proxy = proxy_of(db.get(ExternalAsset, asset_id))
        with external_probe.via_proxy(proxy):
            rec = external_probe.probe(host, shot_path=path, screenshots=opts["screenshots"],
                                       allow_private=opts["allow_private"], passive=bool(why))
        if proxy:
            rec["proxied"] = True
        save_telemetry(asset_id, rec)
    except Exception as exc:  # noqa: BLE001 - never leave a row saying running
        log.exception("telemetry for %s failed", asset_id)
        with session_scope() as db:
            asset = db.get(ExternalAsset, asset_id)
            if asset is not None:
                asset.telemetry_status = "failed"
                asset.telemetry_error = f"{type(exc).__name__}: {exc}"[:500]


def save_telemetry(asset_id: int, rec: dict) -> None:
    keep = dict(rec)
    keep["body_sample"] = ""  # what the page said is not worth a row
    with session_scope() as db:
        asset = db.get(ExternalAsset, asset_id)
        if asset is None:
            return
        asset.telemetry = json.dumps(keep, default=str)
        asset.telemetry_at = utcnow()
        asset.telemetry_status = "idle"
        asset.telemetry_error = ""
        sync_columns(asset)
        if not asset.category:
            asset.category = rec.get("category") or ""
        if rec.get("shot"):
            asset.screenshot = rec["shot"][:16]
            if rec["shot"] not in ("ok", "blank", "waf") or not shot_path(asset_id).exists():
                drop_shot(asset_id)
    if shot_path(asset_id).is_file() and not thumb_fresh(asset_id):
        # Made now, while the probe's thread is spent anyway, so the list
        # never waits on the full picture.
        make_thumbs([asset_id])


def refresh_stale() -> int:
    """The scheduled pass: hosts whose telemetry is older than the setting,
    and sites whose finding exceptions have ended."""
    with session_scope() as db:
        if not enabled(db):
            return 0
    from app.core import external_decisions

    try:
        external_decisions.recount_expired()
    except Exception:  # noqa: BLE001 - the next night tries again
        log.warning("could not recount expired exceptions", exc_info=True)
    with session_scope() as db:
        days = options(db)["refresh_days"]
        if not days:
            return 0
        cutoff = utcnow() - timedelta(days=days)
        ids = [a.id for a in db.query(ExternalAsset.id).filter(
            ExternalAsset.status != "obsolete").filter(
            (ExternalAsset.telemetry_at.is_(None)) | (ExternalAsset.telemetry_at < cutoff))]
    return start_telemetry(ids)


# ------------------------------------------------------------------ scans

class _Slots:
    """How many engine scans run at once on this server.  The limit is read
    from Settings each time a scan waits, so a change takes effect on the
    next scan without a restart."""

    def __init__(self):
        self._cond = threading.Condition()
        self._busy = 0

    def limit(self) -> int:
        try:
            from app.core import settings_store

            with session_scope() as db:
                value = int(settings_store.get(db, "external.max_concurrent") or 1)
        except Exception:  # noqa: BLE001 - a bad value is one at a time
            value = 1
        return max(1, min(value, MAX_CONCURRENT))

    def __enter__(self):
        with self._cond:
            while self._busy >= self.limit():
                self._cond.wait(timeout=5)
            self._busy += 1
        return self

    def __exit__(self, *exc):
        with self._cond:
            self._busy -= 1
            self._cond.notify_all()
        return False

    @property
    def busy(self) -> int:
        return self._busy


MAX_CONCURRENT = 12
_slots = _Slots()
_stopping: set = set()


def start_scan(asset_id: int, profile: str, actor: str, ai_triage: bool = False,
               server_id: int = None, authenticated: bool = None,
               ias_config: str = "") -> tuple:
    """Start a dynamic scan here, on a server, or on InsightAppSec.  -> (scan id, problem)

    authenticated None means sign in when the site has a sign in set.  A
    scan config id in ias_config means InsightAppSec, which signs in with
    whatever its scan config says, never with the sign in saved here.
    """
    from app.core import dast_engines, external_auth

    if ias_config:
        return _start_ias(asset_id, ias_config, actor, ai_triage)

    with session_scope() as db:
        if not enabled(db):
            return None, "External sites are switched off in Settings."
        asset = db.get(ExternalAsset, asset_id)
        if asset is None:
            return None, "No such site."
        why = blocked(db, asset)
        if why:
            return None, f"{asset.host} may not be scanned: {why}."
        if db.query(ExternalDastScan).filter(
                ExternalDastScan.asset_id == asset_id,
                ExternalDastScan.status.in_(("queued", "running"))).first():
            return None, f"A scan of {asset.host} is already running."
        server = None
        if server_id:
            server = db.get(DastServer, server_id)
            if server is None or server.kind != "nextgen-dast":
                return None, "That server cannot be started from here."
            if profile not in ("quick", "standard", "thorough", "premium"):
                profile = server.profile or "quick"
        elif profile not in dast_engines.PROFILES:
            return None, "Pick a scan profile."
        auth = external_auth.load(asset)
        sign_in = bool(auth) if authenticated is None else bool(authenticated)
        if sign_in and not auth:
            return None, f"{asset.host} has no sign in set.  Add one in Edit first."
        if sign_in and server:
            try:
                external_auth.for_nextgen(auth)
            except ValueError as exc:
                return None, str(exc)
        scan = ExternalDastScan(
            asset_id=asset_id, server_id=server.id if server else None,
            server_name=(server.name if server else BUILTIN_SERVER)[:120],
            source="remote" if server else "builtin", status="queued",
            profile=profile, started_at=utcnow(), recorded_by=(actor or "")[:120],
            ai_status="wanted" if ai_triage else "",
            authenticated=sign_in, auth_kind=auth.get("kind", "") if sign_in else "")
        db.add(scan)
        db.flush()
        scan_id = scan.id
    if server_id:
        threading.Thread(target=_start_remote, args=(scan_id,), daemon=True,
                         name=f"dast-remote-{scan_id}").start()
    else:
        threading.Thread(target=_run_builtin, args=(scan_id,), daemon=True,
                         name=f"dast-{scan_id}").start()
    return scan_id, ""


def stop_scan(scan_id: int) -> bool:
    from app.core import dast_engines

    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None or scan.status not in ("queued", "running"):
            return False
        if scan.source == "remote" and scan.provider == "insightappsec":
            remote_id = scan.remote_id
        elif scan.source == "remote":
            scan.status = "failed"
            scan.error = "stopped here; the server may still be running it"
            return True
        else:
            remote_id = None
    if remote_id is not None:
        return _stop_ias(scan_id, remote_id)
    _stopping.add(scan_id)
    _update(scan_id, step="stopping")
    dast_engines.stop(scan_id)
    return True


def running_scans(db, asset_ids=None) -> dict:
    """The scan queued or running on each site, at most one each.  -> {asset id: scan}"""
    query = db.query(ExternalDastScan).filter(
        ExternalDastScan.status.in_(("queued", "running")))
    if asset_ids is not None:
        query = query.filter(ExternalDastScan.asset_id.in_(list(asset_ids) or [0]))
    return {s.asset_id: s for s in query.order_by(ExternalDastScan.id)}


def _update(scan_id: int, **fields) -> None:
    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is not None:
            for key, value in fields.items():
                setattr(scan, key, value)


def _run_builtin(scan_id: int) -> None:
    try:
        _update(scan_id, step="waiting for a free slot")
        with _slots:
            if scan_id in _stopping:
                # Stopped while it waited its turn: it never sent a request.
                _update(scan_id, status="failed", step="",
                        error="stopped before it started", scanned_at=utcnow())
                return
            _builtin(scan_id)
    except Exception as exc:  # noqa: BLE001 - never leave a row saying running
        log.exception("dynamic scan %s failed", scan_id)
        _update(scan_id, status="failed", step="",
                error=f"{type(exc).__name__}: {exc}"[:500])
    finally:
        _stopping.discard(scan_id)


def _whitebox(scan_id: int, asset_id: int, host: str) -> dict:
    """Check out the repositories behind the site and read routes from them."""
    from app.core import dast_whitebox, recheck

    with session_scope() as db:
        asset = db.get(ExternalAsset, asset_id)
        scan = db.get(ExternalDastScan, scan_id)
        who = actor_user(db, scan.recorded_by if scan else "")
        if who is _NOBODY:
            return {"repos": [], "routes": [], "by_repo": {}}
        links = [l for l in Mapper(db, who).links(asset) if l["linked"]]
        # Picked first: somebody said which code is behind the site, and on
        # which branches.  Each branch is its own checkout, so the cap is on
        # checkouts rather than repositories.
        links.sort(key=lambda l: l["source"] != "manual")
        plan = []
        for l in links:
            for branch in (l.get("branches") or [l["repo"].default_branch or ""]):
                plan.append((l["repo"].id, l["full_name"], l["repo"].connection or "", branch))
        plan = plan[:MAX_WHITEBOX_REPOS]
    out = {"repos": [], "routes": [], "by_repo": {}}
    for repo_id, name, connection, branch in plan:
        if scan_id in _stopping:
            break
        _update(scan_id, step=f"reading {name} for routes")
        entry = {"repository": name, "branch": branch, "routes": 0,
                 "host_in_code": [], "error": ""}
        try:
            with recheck.branch_tip(connection, name, branch) as (root, why):
                if root is None:
                    entry["error"] = why or "could not fetch it"
                else:
                    got = dast_whitebox.read(root, host)
                    entry["routes"] = len(got["routes"])
                    entry["host_in_code"] = got["host_files"]
                    have = out["by_repo"].setdefault(repo_id, [])
                    have += [r for r in got["routes"] if r not in have]
                    for route in got["routes"]:
                        if route not in out["routes"]:
                            out["routes"].append(route)
        except Exception as exc:  # noqa: BLE001 - the scan carries on without it
            entry["error"] = f"{type(exc).__name__}: {exc}"[:200]
        out["repos"].append(entry)
        if entry["host_in_code"]:
            # The host is written in the code: the strongest evidence a
            # mapping is right, so keep it as a link of its own.
            with session_scope() as db:
                row = (db.query(ExternalAssetRepo)
                       .filter_by(asset_id=asset_id, repository_id=repo_id).one_or_none())
                if row is None:
                    db.add(ExternalAssetRepo(asset_id=asset_id, repository_id=repo_id,
                                             source="code", added_by="scan"))
    out["routes"] = out["routes"][:300]
    return out


def _builtin(scan_id: int) -> None:
    from app.core import dast_engines, external_dast

    from app.core import external_auth

    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        asset = db.get(ExternalAsset, scan.asset_id)
        host, asset_id, profile = asset.host, asset.id, scan.profile
        opts = options(db)
        why = blocked(db, asset)
        auth = external_auth.load(asset) if scan.authenticated else {}
        proxy = proxy_of(asset)
    if why:
        _update(scan_id, status="failed", error=f"may not be scanned: {why}"[:500])
        return
    _update(scan_id, status="running", step="baseline checks", started_at=utcnow())
    from app.core import external_probe as _probe

    with _probe.via_proxy(proxy):
        _builtin_run(scan_id, host, asset_id, profile, opts, auth, proxy)


def _builtin_run(scan_id, host, asset_id, profile, opts, auth, proxy) -> None:
    from app.core import dast_engines, external_auth, external_dast
    engines = []
    base = external_dast.scan(host, allow_private=opts["allow_private"])
    findings = [dict(f, tool="baseline") for f in base["findings"]]
    engines.append({"tool": "baseline", "name": "Baseline checks", "status": "ok",
                    "detail": f"{len(findings)} findings, {base['requests']} requests"
                              + (f", {base.get('note')}" if base.get("note") else ""),
                    "seconds": 0})
    save_telemetry(asset_id, dict(base["telemetry"], shot=""))
    url = base["base_url"]
    plan = dast_engines.PLANS.get(profile, [])
    routes = []
    wb = {"routes": [], "by_repo": {}}
    seen = {"baseline": [{"url": url, "status": base["telemetry"].get("status"),
                          "method": "GET"}] if url else []}
    if url and plan and opts["whitebox"]:
        wb = _whitebox(scan_id, asset_id, host)
        routes = [url.rstrip("/") + r for r in wb["routes"]]
        engines.append({"tool": "whitebox", "name": "Code behind the site",
                        "status": "ok" if wb["repos"] else "skipped",
                        "detail": (f"{len(wb['routes'])} routes from "
                                   + ", ".join(r["repository"] for r in wb["repos"])
                                   if wb["repos"] else "no repository is mapped"),
                        "repos": wb["repos"], "seconds": 0})
    # Signing in, for the engines.  Baseline and testssl stay signed out:
    # one reads the public posture, the other only talks TLS.
    session, secrets = {}, []
    if auth and url and plan:
        _update(scan_id, step="signing in")
        session = external_auth.session_for(auth, opts["allow_private"])
        secrets = external_auth.secrets_of(auth, session.get("cookie", ""))
        engines.append({"tool": "signin", "name": "Sign in",
                        "status": "ok" if session["ok"] else "failed",
                        "detail": external_auth.redact(
                            f"{external_auth.KINDS[auth['kind']].lower()}: {session['detail']}"
                            + ("" if session["ok"] else
                               (".  wapiti will try the form itself; the other engines run "
                                "signed out" if auth["kind"] == "form" else "")), secrets),
                        "seconds": 0})
    elif auth:
        secrets = external_auth.secrets_of(auth)
    if proxy:
        from urllib.parse import urlparse as _up

        if _up(proxy).password and len(_up(proxy).password) >= 4:
            secrets = sorted(set(secrets) | {_up(proxy).password}, key=len, reverse=True)
        engines.append({"tool": "proxy", "name": "Proxy", "status": "ok", "seconds": 0,
                        "detail": f"pages, the screenshot, sign in and engines went through "
                                  f"{proxy_shown_url(proxy)}; DNS, ports and TLS were read directly"})
    _update(scan_id, engines=json.dumps(engines))
    if url and plan:
        workdir = app_settings.work_dir / "dast" / str(scan_id)
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            # Links on the front page, then the routes from the code.
            extra = dast_engines.links_in(url, base["telemetry"].get("body_sample") or "")
            extra += [r for r in routes if r not in extra]
            for tool in plan:
                if scan_id in _stopping:
                    engines.append({"tool": tool, "name": dast_engines.ENGINE_NAMES[tool],
                                    "status": "stopped", "detail": "scan stopped", "seconds": 0})
                    continue
                if tool == "testssl" and 443 not in (base["telemetry"].get("ports") or []):
                    engines.append({"tool": tool, "name": dast_engines.ENGINE_NAMES[tool],
                                    "status": "skipped", "detail": "nothing answers TLS on 443",
                                    "seconds": 0})
                    continue
                _update(scan_id, step=f"running {dast_engines.ENGINE_NAMES[tool]}")
                args = external_auth.engine_args(tool, session) \
                    if tool in external_auth.SIGNS_IN else []
                result = dast_engines.run_engine(tool, url, host, profile, workdir,
                                                 scan_id, paths=extra, auth_args=args,
                                                 proxy=proxy)
                if session:
                    result["signed_in"] = bool(args)
                if tool == "ffuf":
                    extra += [p for p in result.get("paths", []) if p not in extra]
                findings += result.pop("findings")
                result.pop("paths", None)
                seen[tool] = result.pop("seen", None) or []
                if seen[tool]:
                    result["reached"] = len(seen[tool])
                engines.append(result)
                _update(scan_id, engines=json.dumps(engines))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    # Nothing an engine echoed back of the sign in is kept.
    findings = external_auth.redact(findings, secrets)
    engines = external_auth.redact(engines, secrets)
    findings, dropped = drop_soft_404(findings, url, opts["allow_private"])
    if dropped:
        engines.append({"tool": "verify", "name": "Soft 404 check", "status": "ok",
                        "seconds": 0,
                        "detail": f"left out {dropped} finding{'s' if dropped != 1 else ''} "
                                  "for paths that answer with the same page as one that "
                                  "cannot exist"})
    findings = merge(findings)
    stopped = scan_id in _stopping
    if url:
        try:
            _paths_and_code(scan_id, asset_id, url, seen, findings, wb, opts, stopped)
        except Exception:  # noqa: BLE001 - the findings stand without it
            log.exception("scan %s: the paths and the code behind them were not read", scan_id)
    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        want_ai = scan.ai_status == "wanted"
    finish(scan_id, findings, status="failed" if stopped else "done",
           error="stopped before it finished" if stopped else "",
           engines=engines)
    if want_ai and not stopped:
        triage(scan_id)


# Engines that report a path because it answered, which a site that serves
# its home page for every address answers every time.
PATH_ENGINES = {"nikto", "nuclei", "ffuf"}
MAX_VERIFY = 80


def drop_soft_404(findings: list, base_url: str, allow_private: bool = False) -> tuple:
    """Leave out path findings whose page is the site's not found page.

    One request to an address that cannot exist gives the site's answer for
    nothing.  A finding whose address answers with the same body found
    nothing either.  -> (kept, how many were left out)
    """
    import hashlib
    import secrets as _s
    from urllib.parse import urljoin, urlparse

    from app.core import external_probe

    if not base_url:
        return findings, 0
    control = external_probe.fetch(urljoin(base_url, f"/gcr-{_s.token_hex(6)}/{_s.token_hex(4)}.html"),
                                   allow_private=allow_private, body_limit=65536)
    if control["status"] != 200 or not control["body"]:
        return findings, 0      # a real 404 page: the engines already saw it

    def norm(body: str) -> str:
        # Pages that echo the address back differ only by the address.
        return hashlib.sha256(re.sub(r"\s+", " ", re.sub(r"gcr-[0-9a-f]+", "", body or ""))
                              .encode()).hexdigest()

    fingerprint = norm(control["body"])
    size = len(control["body"])
    seen, kept, dropped, checked = {}, [], 0, 0
    for f in findings:
        url = f.get("url") or ""
        path = urlparse(url).path or "/"
        if f.get("tool") not in PATH_ENGINES or path in ("", "/") or checked >= MAX_VERIFY:
            kept.append(f)
            continue
        if url not in seen:
            checked += 1
            got = external_probe.fetch(url, allow_private=allow_private, follow=False,
                                       body_limit=65536)
            seen[url] = (got["status"] == 200 and
                         (norm(got["body"]) == fingerprint
                          or abs(len(got["body"]) - size) < 16 and
                          "html" in got["headers"].get("content-type", "")))
        if seen[url]:
            dropped += 1
        else:
            kept.append(f)
    return kept, dropped


def merge(findings: list) -> list:
    """One row per problem.  Two engines saying the same thing is one finding
    that both found, kept at the worse severity."""
    by_key = {}
    for f in findings:
        key = (re.sub(r"\W+", " ", (f.get("title") or "").lower()).strip()[:120],
               (f.get("url") or "").split("?")[0].rstrip("/").lower())
        have = by_key.get(key)
        if have is None:
            by_key[key] = dict(f, tools=[f.get("tool") or f.get("check") or ""])
            continue
        tool = f.get("tool") or f.get("check") or ""
        if tool not in have["tools"]:
            have["tools"].append(tool)
        if RANK.get(f.get("severity"), 0) > RANK.get(have.get("severity"), 0):
            have["severity"] = f["severity"]
    out = list(by_key.values())
    out.sort(key=lambda f: (-RANK.get(f.get("severity"), 0), f.get("title") or ""))
    return out[:MAX_FINDINGS]


def _paths_and_code(scan_id, asset_id, url, seen, findings, wb, opts, stopped) -> None:
    """What the scan reached, and the repositories whose routes it answered."""
    from urllib.parse import urljoin

    from app.core import dast_paths, external_probe

    _update(scan_id, step="matching the paths it reached to code")
    records = dast_paths.inventory(url, seen, findings, from_code=wb.get("routes") or [])

    def fetch(path):
        got = external_probe.fetch(urljoin(url, path), allow_private=opts["allow_private"],
                                   follow=False, body_limit=65536)
        return {"status": got.get("status"), "body": got.get("body") or ""}

    controls = {}
    if not stopped:
        controls = dast_paths.classify(records, fetch)
    with session_scope() as db:
        index, names = code_index(db, wb.get("by_repo"))
    if controls and not stopped:
        # The pages that could point at code get their second request first.
        first = {r["p"] for r in records if r.get("v") and index.any_match(r["p"])}
        dast_paths.verify(records, controls, fetch, first)
    paths = {"control": {p: c["status"] for p, c in controls.items()},
             "paths": records, "counts": dast_paths.counts(records)}
    _update(scan_id, paths=json.dumps(paths), paths_count=paths["counts"]["answered"],
            paths_real=paths["counts"]["reachable"], code_matches=json.dumps(
        _code_matches(asset_id, records, index, names)))


def code_index(db, extra: dict = None):
    """Every repository's declared routes, with the routes the scan just read
    from the ones linked to the site.  -> (dast_paths.Index, {id: name})"""
    from app.core import dast_paths

    routes, names = {}, {}
    for repo_id, full_name, raw in (db.query(Repository.id, Repository.full_name,
                                             Repository.default_routes)
                                    .filter(Repository.archived.is_(False),
                                            Repository.default_routes.isnot(None),
                                            Repository.default_routes != "")):
        try:
            value = json.loads(raw or "[]")
        except ValueError:
            continue
        if isinstance(value, list) and value:
            routes[repo_id] = value
            names[repo_id] = full_name
    for repo_id, extra_routes in (extra or {}).items():
        have = routes.setdefault(repo_id, [])
        have += [r for r in extra_routes if r not in have]
        if repo_id not in names:
            repo = db.get(Repository, repo_id)
            names[repo_id] = repo.full_name if repo else ""
    return dast_paths.Index(routes), names


def _code_matches(asset_id: int, records: list, index, names: dict) -> dict:
    from app.core import dast_paths

    found = dast_paths.match(records, index, names)
    shown = [c for c in found if c["confidence"] >= dast_paths.SHOW_AT][:dast_paths.MAX_CANDIDATES]
    linked = []
    with session_scope() as db:
        asset = db.get(ExternalAsset, asset_id)
        for link in (Mapper(db).links(asset) if asset is not None else []):
            if link["linked"]:
                linked.append(dict(dast_paths.reached(records, index, link["id"]),
                                   repo_id=link["id"], full_name=link["full_name"]))
    return {"at": utcnow().isoformat(), "indexed": len(index.routes),
            "candidates": shown, "linked": linked}


def rematch(scan_id: int) -> bool:
    """Match a finished scan's paths again, against the routes as they are
    now.  Nothing is sent to the site: a page that needed a second look and
    did not get one still does not count.  -> False when it has no paths"""
    from app.core import dast_paths

    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None:
            return False
        records = dast_paths.load(scan.paths).get("paths") or []
        asset_id = scan.asset_id
        if not records:
            return False
        index, names = code_index(db)
    _update(scan_id, code_matches=json.dumps(_code_matches(asset_id, records, index, names)))
    return True


def code_behind(db, user, scan: ExternalDastScan, asset: ExternalAsset) -> dict:
    """The scan's code matches as one person may see them: only repositories
    in their scope, each marked with how it is linked to the site now."""
    from app.core import dast_paths, rbac

    data = dast_paths.load(scan.code_matches)
    paths = dast_paths.load(scan.paths)
    if not data and not paths:
        return {}
    ids = set()
    for c in (data.get("candidates") or []) + (data.get("linked") or []):
        ids.add(c.get("repo_id"))
    visible = {r.id: r for r in rbac.visible_repositories(db, user)
               .filter(Repository.id.in_([i for i in ids if isinstance(i, int)]))}
    links = {l["id"]: l for l in Mapper(db, user).links(asset)}
    out = []
    for c in data.get("candidates") or []:
        repo = visible.get(c.get("repo_id"))
        if repo is None:
            continue
        link = links.get(repo.id) or {}
        out.append(dict(c, full_name=repo.full_name, linked=bool(link.get("linked")),
                        link_source=link.get("source") or "",
                        link_reasons=link.get("reasons") or []))
    linked = [dict(l, full_name=visible[l["repo_id"]].full_name)
              for l in data.get("linked") or [] if l.get("repo_id") in visible]
    return {"counts": paths.get("counts") or {}, "control": paths.get("control") or {},
            "candidates": out, "linked": linked, "indexed": data.get("indexed", 0),
            "at": data.get("at", ""), "has_paths": bool(paths.get("paths"))}


def paths_of(scan: ExternalDastScan) -> list:
    from app.core import dast_paths

    return dast_paths.load(scan.paths).get("paths") or []


def finish(scan_id: int, findings: list, status: str = "done", error: str = "",
           engines: list = None, result_url: str = None, when=None) -> None:
    """Store a scan's findings and copy its result onto the site."""
    from app.core import external_dast, external_decisions

    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None:
            return
        # What people already decided about these findings on this site
        # carries into the new scan.
        findings = external_decisions.apply(findings, external_decisions.for_asset(db, scan.asset_id),
                                            scan_id=scan.id)
        roll = external_dast.rollup([f for f in findings if external_decisions.counted(f)])
        scan.findings = json.dumps(findings, default=str)
        scan.status = status
        scan.error = (error or "")[:500]
        scan.step = ""
        scan.scanned_at = when or utcnow()
        for sev in SEVERITIES:
            setattr(scan, sev, roll[sev])
        scan.severity = roll["severity"]
        if engines is not None:
            scan.engines = json.dumps(engines)
        if result_url is not None:
            scan.result_url = result_url[:1000]
        elif not scan.result_url and scan.source == "builtin":
            scan.result_url = f"/external/{scan.asset_id}/scans/{scan.id}"
        if status == "done":
            touch_asset(db, scan)


def touch_asset(db, scan: ExternalDastScan) -> None:
    """Copy the newest finished scan onto its site, and tell the Web
    Applications tab the applications behind it were tested."""
    from app.core import webapps

    asset = db.get(ExternalAsset, scan.asset_id)
    if asset is None:
        return
    copy_newest(db, asset)
    when = webapps.date_of((scan.scanned_at or utcnow()).strftime("%Y-%m-%d"))
    if when is None:
        return
    seen = set()
    for link in Mapper(db).links(asset):
        repo = link["repo"]
        if not link["linked"] or not repo.web_app:
            continue
        key = webapps.app_key(link["application"], repo.full_name)
        if key in seen:
            continue
        seen.add(key)
        webapps.record_test(db, {"key": key, "name": link["application"] or repo.full_name},
                            "dast", when, scan.server_name,
                            scan.result_url or "", f"Dynamic scan of {asset.host}",
                            scan.recorded_by)


def scoping_by_asset(db, asset_ids=None) -> dict:
    """The pen test scoping numbers of each site, from its newest finished
    scan that recorded paths, the same scan url_paths comes from.
    -> {asset id: {"scan": scan, "scope": dast_paths.scoping(...)}}"""
    from app.core import dast_paths

    query = (db.query(ExternalDastScan.id, ExternalDastScan.asset_id)
             .filter(ExternalDastScan.status == "done",
                     ExternalDastScan.paths_count.isnot(None)))
    if asset_ids is not None:
        query = query.filter(ExternalDastScan.asset_id.in_(list(asset_ids) or [0]))
    newest = {}
    for scan_id, asset_id in query.order_by(ExternalDastScan.scanned_at.desc(),
                                            ExternalDastScan.id.desc()):
        newest.setdefault(asset_id, scan_id)
    out = {}
    for asset_id, scan_id in newest.items():
        scan = db.get(ExternalDastScan, scan_id)
        out[asset_id] = {"scan": scan, "scope": dast_paths.scoping(
            dast_paths.load(scan.paths).get("paths") or [])}
    return out


def copy_newest(db, asset: ExternalAsset) -> None:
    """The newest finished scan onto the site, or nothing when there is none."""
    newest = (db.query(ExternalDastScan)
              .filter(ExternalDastScan.asset_id == asset.id,
                      ExternalDastScan.status == "done")
              .order_by(ExternalDastScan.scanned_at.desc(), ExternalDastScan.id.desc())
              .first())
    asset.last_dast_at = newest.scanned_at if newest else None
    asset.last_dast_severity = (newest.severity or "") if newest else ""
    asset.last_dast_url = (newest.result_url or "") if newest else ""
    asset.last_dast_server = (newest.server_name or "") if newest else ""
    # The newest scan that counted its paths, which a recorded scan never does.
    counted = (db.query(ExternalDastScan)
               .filter(ExternalDastScan.asset_id == asset.id,
                       ExternalDastScan.status == "done",
                       ExternalDastScan.paths_count.isnot(None))
               .order_by(ExternalDastScan.scanned_at.desc(), ExternalDastScan.id.desc())
               .first())
    asset.last_paths = counted.paths_real if counted else None
    asset.last_paths_at = counted.scanned_at if counted else None
    asset.last_paths_profile = (counted.profile or "") if counted else ""


def record_scan(db, asset: ExternalAsset, data: dict, actor: str) -> ExternalDastScan:
    """A scan run somewhere else, told to us.  Raises ValueError on bad input."""
    from app.core import external_dast

    server_name = str(data.get("server") or "").strip()[:120]
    if not server_name:
        raise ValueError("Say which DAST server ran the scan.")
    server = db.query(DastServer).filter(func.lower(DastServer.name) == server_name.lower()).first()
    when = parse_when(data.get("scanned_at"))
    url = str(data.get("result_url") or "").strip()
    if url and not re.match(r"^https?://[^\s]+$", url):
        raise ValueError("result_url has to be an http or https address.")
    findings = data.get("findings") or []
    if not isinstance(findings, list):
        raise ValueError("findings has to be a list.")
    cleaned = []
    for item in findings[:MAX_FINDINGS]:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "info").lower()
        cleaned.append({"title": str(item.get("title") or "")[:300],
                        "severity": sev if sev in SEVERITIES else "info",
                        "url": str(item.get("url") or "")[:1000],
                        "evidence": str(item.get("evidence") or "")[:800],
                        "cwe": str(item.get("cwe") or "")[:40],
                        "remediation": str(item.get("remediation") or "")[:1500],
                        "tool": server_name})
    counts = data.get("counts") or {}
    if not isinstance(counts, dict):
        raise ValueError("counts has to be an object.")
    if cleaned and not counts:
        roll = external_dast.rollup(cleaned)
    else:
        roll = {s: _count(counts.get(s)) for s in SEVERITIES}
        roll["severity"] = next((s for s in SEVERITIES if roll[s]), "none")
    severity = str(data.get("severity") or "").lower() or roll["severity"]
    if severity not in SEVERITIES + ["none"]:
        raise ValueError("severity is one of critical, high, medium, low, info or none.")
    scan = ExternalDastScan(
        asset_id=asset.id, server_id=server.id if server else None,
        server_name=server.name if server else server_name, source="recorded",
        status="done", scanned_at=when, started_at=when, severity=severity,
        result_url=url, findings=json.dumps(cleaned),
        note=str(data.get("note") or "")[:4000], recorded_by=(actor or "")[:120],
        remote_id=str(data.get("scan_id") or "")[:64],
        **{s: roll[s] for s in SEVERITIES})
    db.add(scan)
    db.flush()
    if cleaned:
        from app.core import external_decisions

        external_decisions.recount(db, asset.id)
    touch_asset(db, scan)
    return scan


def _count(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        raise ValueError("counts have to be whole numbers.")


def parse_when(value):
    """An ISO date or time, not in the future.  Now when empty."""
    if value in (None, ""):
        return utcnow()
    text = str(value).strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text) if "T" in text or " " in text \
            else datetime.strptime(text[:10], "%Y-%m-%d")
    except ValueError:
        raise ValueError("scanned_at has to be a date (2026-11-03) or an ISO time.")
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    if when > utcnow() + timedelta(hours=1):
        raise ValueError("scanned_at is in the future.")
    return when


# ------------------------------------------------------------------ nextgen-dast

def server_token(server: DastServer) -> str:
    from app.core import settings_store as store

    try:
        return store._decrypt(server.token) if server.token else ""
    except Exception:  # noqa: BLE001
        return ""


def set_server_token(server: DastServer, value: str) -> None:
    from app.core import settings_store as store

    server.token = store._encrypt(value) if value else ""


def _ngd(server_url: str, token: str, method: str, path: str, body=None,
         timeout: float = 30):
    import httpx

    resp = httpx.request(method, server_url.rstrip("/") + "/api/v1" + path,
                         headers={"Authorization": f"Bearer {token}",
                                  "Accept": "application/json"},
                         json=body, timeout=timeout)
    if resp.status_code >= 400:
        raise RuntimeError(f"{resp.status_code} from the server: {resp.text[:200]}")
    return resp.json()


def test_server(server_id: int) -> tuple:
    """-> (ok, what happened)"""
    with session_scope() as db:
        server = db.get(DastServer, server_id)
        if server is None:
            return False, "No such server."
        url, token, kind = server.base_url, server_token(server), server.kind
    if kind != "nextgen-dast":
        return True, "Nothing to test: scans from this server are recorded, not fetched."
    try:
        _ngd(url, token, "GET", "/scans?limit=1", timeout=15)
        return True, "Connected and the token was accepted."
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {str(exc)[:200]}"


def _start_remote(scan_id: int) -> None:
    try:
        with session_scope() as db:
            scan = db.get(ExternalDastScan, scan_id)
            server = db.get(DastServer, scan.server_id)
            asset = db.get(ExternalAsset, scan.asset_id)
            url, token = server.base_url, server_token(server)
            body = {"fqdn": asset.host, "profile": scan.profile or "quick",
                    "llm_tier": "none", "scan_http": True, "scan_https": True,
                    "application_id": (asset.application or asset.host)[:128]}
            if scan.authenticated:
                from app.core import external_auth

                body.update(external_auth.for_nextgen(external_auth.load(asset)))
        got = _ngd(url, token, "POST", "/scans", body)
        _update(scan_id, status="running", remote_id=str(got.get("scan_id") or "")[:64],
                step=f"queued on {url}",
                result_url=f"{url.rstrip('/')}/assessment/{got.get('scan_id')}")
    except Exception as exc:  # noqa: BLE001
        # The request carried the password, so nothing from it is repeated.
        _update(scan_id, status="failed", step="",
                error=f"could not start it: {type(exc).__name__}: {str(exc)[:200]}"
                .replace(str(body.get("creds_password") or "\x00"), "[redacted]")
                if "body" in locals() else f"could not start it: {type(exc).__name__}")


# ------------------------------------------------------------------ InsightAppSec

# Paused and blacked out scans can wait a day there, and a long site takes
# hours, so this is longer than a DAST server gets.
IAS_GIVE_UP_HOURS = 72
_ias_backoff = {"until": 0.0}


def ias_running(db) -> int:
    return (db.query(ExternalDastScan)
            .filter(ExternalDastScan.provider == "insightappsec",
                    ExternalDastScan.status.in_(("queued", "running"))).count())


def _start_ias(asset_id: int, config_id: str, actor: str, ai_triage: bool) -> tuple:
    from app.core import insightappsec as ias

    with session_scope() as db:
        if not enabled(db):
            return None, "External sites are switched off in Settings."
        cfg = ias.config(db)
        if not cfg["ready"]:
            return None, ("InsightAppSec is not set up.  Turn it on and give the API "
                          "key on the Integrations tab in Settings.")
        asset = db.get(ExternalAsset, asset_id)
        if asset is None:
            return None, "No such site."
        why = blocked(db, asset)
        if why:
            return None, f"{asset.host} may not be scanned: {why}."
        if not ias.is_uuid(config_id):
            return None, "Pick an InsightAppSec scan config."
        if db.query(ExternalDastScan).filter(
                ExternalDastScan.asset_id == asset_id,
                ExternalDastScan.status.in_(("queued", "running"))).first():
            return None, f"A scan of {asset.host} is already running."
        if ias_running(db) >= cfg["max_concurrent"]:
            return None, (f"{cfg['max_concurrent']} InsightAppSec scan"
                          f"{'s are' if cfg['max_concurrent'] != 1 else ' is'} already "
                          f"running from here, the most the Integrations tab allows.")
        known = ias.find_config(config_id)
        asset.ias_scan_config_id = config_id
        scan = ExternalDastScan(
            asset_id=asset_id, server_id=None, server_name=ias.NAME,
            source="remote", provider=ias.PROVIDER, status="queued",
            profile="", started_at=utcnow(), recorded_by=(actor or "")[:120],
            ai_status="wanted" if ai_triage else "", authenticated=False,
            step=(f"starting {known['name']}" if known else "starting")[:120],
            note=(f"InsightAppSec scan config {known['name']} ({known['app']})"
                  if known else f"InsightAppSec scan config {config_id}")[:500])
        db.add(scan)
        db.flush()
        scan_id = scan.id
        region, key = cfg["region"], cfg["key"]
        app_id = (known or {}).get("app_id", "")
    try:
        remote = ias.start(region, key, config_id)
    except ias.IASError as exc:
        # Kept as a failed scan, so the site's history shows the attempt.
        _update(scan_id, status="failed", step="", error=f"could not start it: {exc}"[:500])
        return None, f"InsightAppSec would not start it: {exc}"
    _update(scan_id, status="running", remote_id=remote, step="queued in InsightAppSec",
            result_url=ias.scan_link(region, app_id, config_id, remote))
    return scan_id, ""


def _stop_ias(scan_id: int, remote_id: str) -> bool:
    """Ask InsightAppSec to stop it.  STOP keeps what it found so far, and the
    poll reads that back when the scan reaches its end."""
    from app.core import insightappsec as ias

    cfg = ias.config()
    if not remote_id:
        _update(scan_id, status="failed", step="", error="stopped before it started")
        return True
    try:
        ias.act(cfg["region"], cfg["key"], remote_id, "STOP")
    except ias.IASError as exc:
        _update(scan_id, step=f"could not stop it: {exc}"[:120])
        return False
    _update(scan_id, step="stopping in InsightAppSec")
    return True


def _poll_ias(scan_id: int, remote_id: str, started) -> int:
    """One InsightAppSec scan: its status, and its findings once it is done."""
    from app.core import insightappsec as ias

    if _ias_backoff["until"] > time.time():
        return 0
    cfg = ias.config()
    if not cfg["key"]:
        _update(scan_id, status="failed", step="",
                error="the InsightAppSec key was removed from Settings")
        return 0
    if not remote_id:
        _update(scan_id, status="failed", step="", error="InsightAppSec gave it no id")
        return 0
    region, key = cfg["region"], cfg["key"]
    try:
        state = ias.status(region, key, remote_id)
        now = str(state.get("status") or "")
        if now == "COMPLETE":
            vulns = ias.scan_vulns(region, key, remote_id)
            app_id = (state.get("app") or {}).get("id", "")
            config_id = (state.get("scan_config") or {}).get("id", "")
            _ias_store(ias, region, key, scan_id, vulns,
                       ias.scan_link(region, app_id, config_id, remote_id))
            with session_scope() as db:
                row = db.get(ExternalDastScan, scan_id)
                want_ai = row.ai_status == "wanted" and not row.summary_only
            if want_ai:
                triage(scan_id)
            return 1
        if now == "FAILED":
            why = ias.failure(state)
            event = ias.last_event(region, key, remote_id)
            _update(scan_id, status="failed", step="",
                    error=(why + (f".  Last event: {event}" if event else ""))[:500])
            return 0
        _update(scan_id, step=f"{now}: {ias.STATUS_WORDS.get(now, now.lower())}"[:120])
        if started and _aware(started) < utcnow() - timedelta(hours=IAS_GIVE_UP_HOURS):
            _update(scan_id, status="failed", step="",
                    error=f"no result after {IAS_GIVE_UP_HOURS} hours; it may still be "
                          f"running in InsightAppSec")
    except ias.IASError as exc:
        if exc.retry_at:
            _ias_backoff["until"] = exc.retry_at
        elif exc.status == 404:
            _update(scan_id, status="failed", step="",
                    error="InsightAppSec no longer has this scan, or the key cannot see it")
        log.warning("polling InsightAppSec scan %s: %s", scan_id, exc)
    return 0


def poll_remote() -> int:
    """Read back every remote scan still running.  The scheduler calls this."""
    with session_scope() as db:
        if not enabled(db):
            return 0
        rows = [(s.id, s.remote_id, s.server_id, s.started_at, s.provider) for s in
                db.query(ExternalDastScan).filter(
                    ExternalDastScan.source == "remote",
                    ExternalDastScan.status == "running")]
    done = 0
    for scan_id, remote_id, server_id, started, provider in rows:
        if provider == "insightappsec":
            done += _poll_ias(scan_id, remote_id, started)
            continue
        try:
            with session_scope() as db:
                server = db.get(DastServer, server_id) if server_id else None
                if server is None or not remote_id:
                    _update(scan_id, status="failed", error="the server was removed")
                    continue
                url, token = server.base_url, server_token(server)
            state = _ngd(url, token, "GET", f"/scans/{remote_id}")
            status = str(state.get("status") or "")
            _update(scan_id, step=f"{status}: {state.get('current_step') or ''}"[:120])
            if status == "done":
                got = _ngd(url, token, "GET", f"/scans/{remote_id}/results", timeout=120)
                findings = [{
                    "title": str(f.get("title") or "")[:300],
                    "severity": (str(f.get("severity") or "info").lower()
                                 if str(f.get("severity") or "").lower() in SEVERITIES else "info"),
                    "url": str(f.get("evidence_url") or "")[:1000],
                    "evidence": str(f.get("description") or "")[:800],
                    "cwe": str(f.get("cwe") or "")[:40],
                    "remediation": str(f.get("remediation") or "")[:1500],
                    "tool": str(f.get("source_tool") or "")[:40],
                    "validation": str(f.get("validation_status") or "")[:32],
                } for f in got.get("findings") or []]
                finish(scan_id, merge(findings))
                with session_scope() as db:
                    want_ai = db.get(ExternalDastScan, scan_id).ai_status == "wanted"
                if want_ai:
                    triage(scan_id)
                done += 1
            elif status in ("error", "failed", "cancelled", "canceled"):
                _update(scan_id, status="failed", step="",
                        error=str(state.get("error_text") or f"the server said {status}")[:500])
            elif started and _aware(started) < utcnow() - timedelta(hours=24):
                _update(scan_id, status="failed", step="",
                        error="no result after 24 hours")
        except Exception as exc:  # noqa: BLE001 - try again on the next tick
            log.warning("polling remote scan %s: %s", scan_id, exc)
    return done


# Scans a finished Rapid7 scan is read for in one run.  The first run on an
# old account has a backlog; the rest of it comes in on the next runs.
IAS_IMPORT_BUDGET = 300
IAS_IMPORT_MINUTES = 20
IAS_IMPORTED_BY = "InsightAppSec import"
_ias_import_lock = threading.Lock()


def import_ias() -> dict:
    """Bring in what Rapid7 already found, old scans included.

    Every scan that reached COMPLETE in InsightAppSec is read once.  Its
    findings are split by the host in each one's address, and every host that
    is a site here gets the scan as a finished scan of its own, dated when
    Rapid7 finished it.  A host the scan config starts on gets the scan even
    when nothing was found there, because a clean scan is a result too.

    What was read is kept in the data volume with the hosts each scan touched,
    so a site added later picks up its old scans on the next run, and a scan
    is never asked for twice when nothing new needs it.  The scheduler runs
    this every hour.  -> the summary shown on the Integrations tab
    """
    from app.core import insightappsec as ias

    if not _ias_import_lock.acquire(blocking=False):
        return {"skipped": "an import is already running"}
    try:
        return _import_ias(ias)
    finally:
        _ias_import_lock.release()


def _import_ias(ias) -> dict:
    with session_scope() as db:
        if not enabled(db):
            return {"skipped": "External sites are switched off"}
        cfg = ias.config(db)
        if not cfg["ready"]:
            return {"skipped": "InsightAppSec is not turned on"}
        sites = {a.host.lower(): a.id for a in db.query(ExternalAsset.host, ExternalAsset.id)}
        have = {(a, r) for a, r in db.query(ExternalDastScan.asset_id, ExternalDastScan.remote_id)
                .filter(ExternalDastScan.provider == ias.PROVIDER,
                        ExternalDastScan.status.in_(("done", "queued", "running")))}
    if _ias_backoff["until"] > time.time():
        return {"skipped": "Rapid7 asked us to wait"}
    region, key = cfg["region"], cfg["key"]
    state = ias.load_import()
    seen = state["scans"]
    catalog = {c["id"]: c for c in ias.load_catalog().get("configs") or []}
    started = time.time()
    summary = {"ran_at": utcnow().isoformat(), "finished": 0, "read": 0,
               "imported": 0, "sites": [], "left": 0, "error": ""}
    touched = set()
    cache = ias.new_cache()
    try:
        with ias._client() as client:
            scans = ias.finished_scans(region, key, client=client)
            summary["finished"] = len(scans)
            for scan in scans:
                known = seen.get(scan["id"])
                if known is not None:
                    wanted = [h for h in known.get("hosts") or []
                              if h in sites and (sites[h], scan["id"]) not in have]
                    if not wanted:
                        continue
                if (summary["read"] >= IAS_IMPORT_BUDGET
                        or time.time() - started > IAS_IMPORT_MINUTES * 60):
                    summary["left"] += 1
                    continue
                vulns = ias.scan_vulns(region, key, scan["id"], client=client)
                summary["read"] += 1
                config = catalog.get(scan["config_id"]) or {}
                by_host = {}
                for v in vulns:
                    by_host.setdefault(ias.host_of((v.get("root_cause") or {}).get("url")),
                                       []).append(v)
                by_host.pop("", None)
                hosts = set(by_host) | set(config.get("hosts") or [])
                seen[scan["id"]] = {"hosts": sorted(hosts), "completed": scan["completed"],
                                    "config_id": scan["config_id"],
                                    "counts": {h: len(v) for h, v in by_host.items()}}
                for host in sorted(hosts):
                    asset_id = sites.get(host)
                    if asset_id is None or (asset_id, scan["id"]) in have:
                        continue
                    _ias_import_one(ias, region, key, asset_id, scan, config,
                                    by_host.get(host, []), cache, client)
                    have.add((asset_id, scan["id"]))
                    touched.add(host)
                    summary["imported"] += 1
                ias.save_import(state)
    except ias.IASError as exc:
        if exc.retry_at:
            _ias_backoff["until"] = exc.retry_at
        summary["error"] = str(exc)[:300]
        log.warning("importing from InsightAppSec: %s", exc)
    summary["sites"] = sorted(touched)
    # Hosts Rapid7 has results for that are not sites here, busiest first,
    # so somebody can add the ones that matter.
    other = {}
    for row in seen.values():
        for host in row.get("hosts") or []:
            if host not in sites:
                got = other.setdefault(host, {"host": host, "scans": 0, "last": ""})
                got["scans"] += 1
                got["last"] = max(got["last"], row.get("completed") or "")
    summary["not_sites"] = sorted(other.values(), key=lambda r: (-r["scans"], r["host"]))[:50]
    summary["not_sites_count"] = len(other)
    summary["known"] = len(seen)
    state["last"] = summary
    ias.save_import(state)
    return summary


def _ias_import_one(ias, region: str, key: str, asset_id: int, scan: dict, config: dict,
                    vulns: list, cache: dict, client) -> int:
    """One finished Rapid7 scan as a finished scan of one site."""
    done = ias.when(scan["completed"]) or utcnow()
    name = config.get("name") or scan["config_id"]
    app = config.get("app") or ""
    with session_scope() as db:
        row = ExternalDastScan(
            asset_id=asset_id, server_id=None, server_name=ias.NAME,
            # Failed until finish() fills it in, so a row an error leaves
            # behind says so, and is never taken for a scan still running.
            source="remote", provider=ias.PROVIDER, status="failed",
            error="the import did not finish", remote_id=scan["id"], profile="",
            started_at=ias.when(scan["submitted"]) or done,
            recorded_by=IAS_IMPORTED_BY, authenticated=False, step="",
            note=(f"Imported from InsightAppSec: scan config {name}"
                  + (f" ({app})" if app else "") + ".")[:500])
        db.add(row)
        db.flush()
        row_id = row.id
    _ias_store(ias, region, key, row_id, vulns,
               ias.scan_link(region, scan["app_id"], scan["config_id"], scan["id"]),
               when=done, cache=cache, client=client)
    return row_id


def _ias_store(ias, region: str, key: str, scan_id: int, vulns: list, result_url: str,
               when=None, cache: dict = None, client=None) -> None:
    """A finished Rapid7 scan onto its row.  A few findings are kept whole.
    Past that only the counts are kept, and the detail stays in Rapid7, so
    this database does not fill up with what Rapid7 already holds."""
    if len(vulns) <= ias.DETAIL_LIMIT:
        found = ias.describe(region, key, vulns, cache=cache, client=client)
        finish(scan_id, merge(found), when=when, result_url=result_url)
        return
    roll = ias.counts(vulns)
    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None:
            return
        scan.findings = ""
        scan.summary_only = True
        scan.status = "done"
        scan.error = ""
        scan.step = ""
        scan.scanned_at = when or utcnow()
        scan.result_url = (result_url or "")[:1000]
        for sev in SEVERITIES:
            setattr(scan, sev, roll[sev])
        scan.severity = roll["severity"]
        touch_asset(db, scan)


def start_ias_import() -> bool:
    """The import in the background, for the button and for turning it on."""
    if _ias_import_lock.locked():
        return False
    threading.Thread(target=import_ias, name="ias-import", daemon=True).start()
    return True


def _aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def recover() -> int:
    """Scans a restart cut short.  Built in ones cannot be resumed."""
    with session_scope() as db:
        rows = (db.query(ExternalDastScan)
                .filter(ExternalDastScan.source == "builtin",
                        ExternalDastScan.status.in_(("queued", "running"))).all())
        for scan in rows:
            scan.status = "failed"
            scan.step = ""
            scan.error = "the server restarted while it ran"
        stuck = (db.query(ExternalAsset)
                 .filter(ExternalAsset.telemetry_status == "running").all())
        for asset in stuck:
            asset.telemetry_status = "failed"
            asset.telemetry_error = "the server restarted while it ran"
        for asset in db.query(ExternalAsset).filter(ExternalAsset.ai_status == "running"):
            asset.ai_status = "failed"
            asset.ai_error = "the server restarted while it ran"
        return len(rows)


# ------------------------------------------------------------------ AI

# Path traversal strings in an engine's evidence are attack payloads, not
# facts the model needs, and some AI gateways refuse a request carrying them.
# They are left out of what is sent rather than disguised.
_PAYLOADS = re.compile(r"(?:\.\./|\.\.\\|%2e%2e|/etc/(?:passwd|shadow|hosts)|"
                       r"c:\\windows|<script|onerror=|onload=)", re.I)

TRIAGE_SYSTEM = """You review the results of a dynamic application security scan \
(DAST) of one public web site.  You also get the open static analysis (SAST) \
findings from the source code repositories believed to be behind the site.

For each DAST finding decide: likely_real, likely_false_positive, or \
needs_review.  Scanners report many false positives: version banners that are \
patched, generic header advice, reflected input that is encoded, and template \
matches on a soft 404 page.  When a SAST finding in the code supports a DAST \
finding (same weakness, same route or parameter), say so; that raises \
confidence a great deal.

Do not change severities.  Do not invent findings.

Answer with JSON only, in this shape:
{"summary": "three to five sentences for an engineer, plain US English",
 "verdicts": [{"id": "finding id", "verdict": "likely_real", "why": "one sentence",
   "sast": "matching SAST finding id or empty"}],
 "priorities": ["the three things to fix first, one sentence each"]}"""

RISK_SYSTEM = """You assess the security risk of one public web site from two \
sources: what a dynamic scan (DAST) found on the live site and what static \
analysis (SAST) found in the code repositories behind it.  DAST shows what is \
reachable now.  SAST shows what is in the code, which may or may not be \
deployed.  A weakness seen in both is the strongest signal there is.

Answer with JSON only:
{"rating": "critical|high|medium|low",
 "summary": "four to six sentences in plain US English for a business owner",
 "correlations": [{"dast": "DAST finding title", "sast": "SAST finding id and rule", \
"why": "one sentence"}],
 "next_steps": ["up to five actions, most important first"]}"""


def _json_answer(text: str) -> dict:
    start, end = (text or "").find("{"), (text or "").rfind("}")
    if start < 0 or end <= start:
        raise ValueError("the answer had no JSON in it")
    return json.loads(text[start:end + 1])


def _clean(text) -> str:
    return _PAYLOADS.sub("[payload removed]", str(text or ""))


def _sast_lines(rows) -> list:
    return [{"id": f.vuln_id, "severity": getattr(f.severity, "value", ""),
             "kind": getattr(f.kind, "value", ""), "rule": (f.rule or "")[:120],
             "cwe": (f.cwe or "")[:60], "title": _clean((f.title or "")[:200]),
             "repository": f.repository, "file": _clean(f.file_path or "")[:200],
             "line": f.line} for f in rows]


def _spent(cfg, answers: list) -> dict:
    from app.core import ai_cost

    total = {"calls": len(answers), "in": 0, "out": 0, "cost": Decimal(0), "priced": False}
    for a in answers:
        total["in"] += a.get("input_tokens") or 0
        total["out"] += a.get("output_tokens") or 0
        cost = ai_cost.cost_of(cfg, a)
        if cost is not None:
            total["priced"] = True
            total["cost"] += cost
    total["cost_text"] = f"{total['cost']:.4f}" if total["priced"] else ""
    return total


def triage(scan_id: int, actor: str = "") -> None:
    """Ask the model to sort one scan's findings.  Runs in the caller's thread."""
    from app.core import ai

    with session_scope() as db:
        cfg = ai.config(db)
        problem = ai.missing(cfg)
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None:
            return
        if problem:
            scan.ai_status = "failed"
            scan.ai_summary = json.dumps({"error": problem})
            return
        # A finding somebody already called a false positive is not sent, but
        # it is kept: what is saved back below is the whole list.
        from app.core.external_decisions import finding_key

        all_findings = findings_of(scan)
        for f in all_findings:
            f["key"] = f.get("key") or finding_key(f)
        findings = [f for f in all_findings
                    if (f.get("decision") or {}).get("kind") != "false_positive"]
        if not findings:
            # Nothing to read, so nothing is sent and nothing is billed.  Saying
            # the model failed here sent people looking at their AI settings.
            scan.ai_status = "done"
            scan.ai_summary = json.dumps({
                "summary": "The scan found nothing, so there was nothing for the "
                           "model to read.  No request was sent.",
                "priorities": [], "model": "", "error": "", "at": utcnow().isoformat()})
            return
        scan.ai_status = "running"
        asset = db.get(ExternalAsset, scan.asset_id)
        who = actor_user(db, actor or scan.recorded_by)
        sast = []
        if who is not _NOBODY:
            links = [l for l in Mapper(db, who).links(asset) if l["linked"]]
            if links:
                sast = _sast_lines(sast_findings(db, [l["full_name"] for l in links], 60, who))
        host = asset.host
    answers, verdicts, summaries, priorities, unreadable = [], {}, [], [], 0
    chunk = 120
    for start in range(0, max(1, len(findings)), chunk):
        part = findings[start:start + chunk]
        if not part:
            break
        prompt = json.dumps({
            "site": host,
            "dast_findings": [{"id": f.get("id") or f["key"], "tool": f.get("tool"),
                               "severity": f.get("severity"), "title": _clean(f.get("title")),
                               "url": _clean(f.get("url"))[:300],
                               "evidence": _clean(f.get("evidence"))[:300],
                               "cwe": f.get("cwe")} for f in part],
            "sast_findings_in_code_behind_the_site": sast,
        }, indent=1)
        answer = ai.complete(cfg, TRIAGE_SYSTEM, prompt, purpose="dast-triage")
        answers.append(answer)
        if not answer["ok"]:
            continue
        try:
            got = _json_answer(answer["text"])
        except ValueError:
            unreadable += 1
            log.warning("dast triage of scan %s: answer was not JSON (%d chars, finish %r) "
                        "starts %r", scan_id, len(answer["text"] or ""),
                        answer.get("finish"), (answer["text"] or "")[:200])
            continue
        summaries.append(str(got.get("summary") or ""))
        priorities += [str(p) for p in got.get("priorities") or []][:5]
        for v in got.get("verdicts") or []:
            if isinstance(v, dict) and v.get("id"):
                verdicts[str(v["id"])] = v
    spent = _spent(cfg, answers)
    ok = any(a["ok"] for a in answers) and (summaries or verdicts)
    for f in all_findings:
        v = verdicts.get(str(f.get("id") or f["key"])) or verdicts.get(f["key"])
        if v:
            verdict = str(v.get("verdict") or "")
            f["ai_verdict"] = verdict if verdict in (
                "likely_real", "likely_false_positive", "needs_review") else "needs_review"
            f["ai_why"] = str(v.get("why") or "")[:400]
            f["ai_sast"] = str(v.get("sast") or "")[:40]
    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        scan.findings = json.dumps(all_findings, default=str)
        scan.ai_status = "done" if ok else "failed"
        scan.ai_summary = json.dumps({
            "summary": " ".join(summaries)[:4000], "priorities": priorities[:8],
            "model": next((a.get("model") for a in answers if a.get("model")), ""),
            "error": "" if ok else next(
                (a["error"] for a in answers if a.get("error")),
                ("The model answered, but not with the JSON it was asked for"
                 + (", and the answer was cut off at its length limit" if any(
                     a.get("cut_off") for a in answers) else "")
                 + ".  Try again, or raise the longest answer on the AI page.")
                if unreadable else "The model gave no usable answer."),
            "at": utcnow().isoformat()})
        scan.ai_calls = (scan.ai_calls or 0) + spent["calls"]
        scan.ai_input_tokens = (scan.ai_input_tokens or 0) + spent["in"]
        scan.ai_output_tokens = (scan.ai_output_tokens or 0) + spent["out"]
        if spent["priced"]:
            before = Decimal(scan.ai_cost or "0")
            scan.ai_cost = f"{before + spent['cost']:.4f}"


def start_triage(scan_id: int, actor: str = "") -> str:
    from app.core import ai

    with session_scope() as db:
        problem = ai.missing(ai.config(db))
        if problem:
            return problem
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None or scan.status != "done":
            return "Only a finished scan can be triaged."
        if scan.ai_status == "running":
            return "That scan is already being triaged."
        scan.ai_status = "running"
    threading.Thread(target=triage, args=(scan_id, actor), daemon=True,
                     name=f"dast-triage-{scan_id}").start()
    return ""


def start_risk_read(asset_id: int, actor: str = "") -> str:
    from app.core import ai

    with session_scope() as db:
        problem = ai.missing(ai.config(db))
        if problem:
            return problem
        asset = db.get(ExternalAsset, asset_id)
        if asset is None:
            return "No such site."
        if asset.ai_status == "running":
            return "A read of this site is already running."
        asset.ai_status = "running"
        asset.ai_error = ""
    threading.Thread(target=_risk_read, args=(asset_id, actor), daemon=True,
                     name=f"external-risk-{asset_id}").start()
    return ""


def actor_user(db, username: str):
    """The person who asked, so a background job sees what they may see.
    Nobody, when they are gone or disabled: then the job reads no code."""
    from app.core.models import User

    user = db.query(User).filter(User.username == (username or "")).one_or_none()
    if user is None or user.disabled:
        return _NOBODY
    return user


class _Nobody:
    """Stands in for a missing person.  Sees nothing."""
    role = None
    groups = []
    github_login = ""
    id = 0
    username = ""
    disabled = True


_NOBODY = _Nobody()


def _risk_read(asset_id: int, actor: str = "") -> None:
    from app.core import ai

    try:
        with session_scope() as db:
            cfg = ai.config(db)
            asset = db.get(ExternalAsset, asset_id)
            who = actor_user(db, actor)
            if who is _NOBODY:
                links, names, counts = [], [], {}
            else:
                links = [l for l in Mapper(db, who).links(asset) if l["linked"]]
                names = [l["full_name"] for l in links]
                counts = sast_counts(db, names, who)
            latest = (db.query(ExternalDastScan)
                      .filter(ExternalDastScan.asset_id == asset_id,
                              ExternalDastScan.status == "done")
                      .order_by(ExternalDastScan.scanned_at.desc()).first())
            dast = findings_of(latest)[:80] if latest else []
            tele = telemetry_of(asset)
            prompt = json.dumps({
                "site": asset.host, "application": asset.application,
                "tags": asset.tag_list(),
                "telemetry": {"category": asset.category, "grade": asset.grade,
                              "open_ports": tele.get("ports"),
                              "server": tele.get("server"),
                              "tls_weaknesses": (tele.get("tls") or {}).get("weaknesses"),
                              "missing_headers": tele.get("missing_headers"),
                              "behind_waf": bool(tele.get("waf_block"))},
                "last_dast_scan": {
                    "server": latest.server_name if latest else None,
                    "scanned_at": _iso(latest.scanned_at) if latest else None,
                    "findings": [{"severity": f.get("severity"),
                                  "title": _clean(f.get("title")),
                                  "url": _clean(f.get("url"))[:200], "cwe": f.get("cwe"),
                                  "ai_verdict": f.get("ai_verdict", "")} for f in dast]},
                "repositories_behind_it": [{"name": l["full_name"], "why": l["reasons"],
                                            "open_findings": counts.get(l["full_name"], {})}
                                           for l in links],
                "worst_sast_findings": _sast_lines(
                    sast_findings(db, names, 60, who) if names else []),
            }, indent=1)
        answer = ai.complete(cfg, RISK_SYSTEM, prompt, purpose="external-risk")
        spent = _spent(cfg, [answer])
        with session_scope() as db:
            asset = db.get(ExternalAsset, asset_id)
            asset.ai_input_tokens = (asset.ai_input_tokens or 0) + spent["in"]
            asset.ai_output_tokens = (asset.ai_output_tokens or 0) + spent["out"]
            if spent["priced"]:
                asset.ai_cost = f"{Decimal(asset.ai_cost or '0') + spent['cost']:.4f}"
            if not answer["ok"]:
                asset.ai_status, asset.ai_error = "failed", (answer["error"] or "no answer")[:500]
                return
            try:
                got = _json_answer(answer["text"])
            except ValueError as exc:
                asset.ai_status, asset.ai_error = "failed", f"The answer was not JSON: {exc}"[:500]
                return
            got["model"] = answer.get("model") or ""
            asset.ai_review = json.dumps(got)
            asset.ai_status = "done"
            asset.ai_at = utcnow()
    except Exception as exc:  # noqa: BLE001 - never leave it saying running
        log.exception("risk read of %s failed", asset_id)
        with session_scope() as db:
            asset = db.get(ExternalAsset, asset_id)
            if asset is not None:
                asset.ai_status = "failed"
                asset.ai_error = f"{type(exc).__name__}: {exc}"[:500]
