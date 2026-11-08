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
# The exposure a site shows from the two vantage check.  open means the non
# allow listed side also reaches it, so it is public; whitelisted means only
# the allow listed side does.
EXPOSURES = {"open": "Open to the world", "whitelisted": "Whitelisted",
             "unreachable": "Unreachable", "anomaly": "Reversed, check setup"}
MAX_PICKS = 200
MAX_BRANCHES = 300

# How sure a worked out link between a host and a repository has to be before
# it counts without anybody saying so.  Below this it is a suggestion.
LINK_THRESHOLD = 60
MAX_WHITEBOX_REPOS = 3
MAX_WHITEBOX_SINKS = 300
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


def exposure_proxy(db) -> str:
    """The saved non allow listed proxy, decrypted, or empty."""
    from app.core import settings_store as s

    return (s.get(db, "dast.unwhitelisted_proxy") or "").strip()


def egress_ip(proxy: str = "", echo_url: str = "", allow_private: bool = False) -> dict:
    """Ask a service that echoes the caller's IP what address a request leaves
    from, optionally through a proxy.  -> {ok, ip, detail}."""
    import ipaddress

    from app.core import external_probe

    url = (echo_url or "https://api.ipify.org").strip()
    try:
        with external_probe.via_proxy(proxy or ""):
            got = external_probe.fetch(url, allow_private=allow_private, body_limit=256)
    except Exception as exc:  # noqa: BLE001 - every failure is an answer
        return {"ok": False, "ip": "", "detail": f"{type(exc).__name__}: {str(exc)[:160]}"}
    body = (got.get("body") or "").strip()
    candidate = body.split()[0] if body else ""
    try:
        return {"ok": True, "ip": str(ipaddress.ip_address(candidate)), "detail": ""}
    except ValueError:
        detail = got.get("error") or (f"the service answered {got['status']}: {body[:80]}"
                                      if got.get("status") else "no answer from the echo service")
        return {"ok": False, "ip": "", "detail": detail}


def validate_proxy(echo_url: str, proxy: str, allow_private: bool = False) -> dict:
    """The egress IP this server shows directly, and the one the proxy shows.
    -> {direct: {...}, through: {...}}."""
    return {"direct": egress_ip("", echo_url, allow_private),
            "through": egress_ip(proxy, echo_url, allow_private)}


def _serves_site(rec: dict) -> bool:
    """Whether a probe reached the real site, not a firewall block, a bot check,
    or nothing at all."""
    from app.core import external_probe

    if not rec or rec.get("error"):
        return False
    if rec.get("waf_block") or rec.get("bot_check"):
        return False
    return bool(rec.get("category") in external_probe.WEB_CATEGORIES and rec.get("status"))


def _exposure_from(whitelisted_ok: bool, public_ok: bool) -> tuple:
    """The posture and a sentence, from whether each vantage reached the site."""
    if whitelisted_ok and public_ok:
        return "open", ("The site answers the non allow listed vantage as well as the "
                        "allow listed one, so anyone on the internet reaches it.")
    if whitelisted_ok and not public_ok:
        return "whitelisted", ("The site answers the allow listed vantage but turns the "
                               "non allow listed one away, so its allow list is working.")
    if public_ok and not whitelisted_ok:
        return "anomaly", ("The non allow listed vantage reaches the site but the allow "
                           "listed one does not, which is backwards.  Check which vantage "
                           "is really allow listed.")
    return "unreachable", ("Neither vantage reached the site, so it is down, or it blocks "
                           "both of these addresses.")


def _probe_through(proxy: str, host: str, allow_private: bool) -> dict:
    """A light look at a site from the proxy's vantage: fetch the front page to
    see whether the real site answers.  It skips the port scan and TLS work,
    which an HTTP proxy does not carry anyway.  -> a small telemetry-like rec."""
    from app.core import external_probe

    rec = {"status": 0, "category": "none", "waf_block": False, "bot_check": "",
           "error": "", "final_url": f"https://{host}/"}
    got = {"status": 0, "error": "no answer", "body": "", "final_url": ""}
    for scheme in ("https", "http"):
        try:
            with external_probe.via_proxy(proxy):
                got = external_probe.fetch(f"{scheme}://{host}/", allow_private=allow_private)
        except Exception as exc:  # noqa: BLE001 - a failure is an answer: not reached
            got = {"status": 0, "error": f"{type(exc).__name__}: {str(exc)[:160]}",
                   "body": "", "final_url": ""}
        if got.get("status"):
            break
    rec["status"] = got.get("status", 0)
    rec["error"] = got.get("error", "")
    rec["final_url"] = got.get("final_url") or f"https://{host}/"
    body = got.get("body") or ""
    rec["category"] = external_probe.classify(rec["status"], bool(rec["status"]))
    if rec["category"] in external_probe.WEB_CATEGORIES:
        rec["waf_block"] = external_probe.detect_waf_block(body, rec["status"])
        rec["bot_check"] = external_probe.bot_check(body, rec["status"])
    return rec


def _proxy_screenshot(proxy: str, url: str, out_path: Path, allow_private: bool) -> None:
    """Photograph the site through the proxy, for the public view."""
    from app.core import external_probe

    try:
        with external_probe.via_proxy(proxy):
            external_probe.playwright_shot([url], out_path, allow_private)
    except Exception:  # noqa: BLE001 - the posture stands without the picture
        log.warning("exposure screenshot through the proxy failed", exc_info=True)


def run_exposure_check(asset_id: int, host: str, opts: dict, inside: dict) -> None:
    """Load the site again from the proxy, then set the site's exposure from the
    two vantages.  inside is the telemetry rec from the server's own IP.  Which
    vantage counts as allow listed comes from the setting, since either the
    server or the proxy may be the one a target lets in."""
    from app.core import settings_store as s

    with session_scope() as db:
        proxy = exposure_proxy(db)
        vantage = (s.get(db, "dast.whitelisted_vantage") or "direct").strip()
    if not proxy:
        return
    outside = _probe_through(proxy, host, opts["allow_private"])
    direct_ok, proxy_ok = _serves_site(inside), _serves_site(outside)
    # A second picture only earns its place when the proxy reached the site but
    # the server's own view did not.  When both see it (open to the world) the
    # direct picture already shows it, so there is no need for two; when the
    # proxy is turned away there is nothing to show.
    if opts.get("screenshots") and proxy_ok and not direct_ok:
        _proxy_screenshot(proxy, outside["final_url"], shot_proxy_path(asset_id),
                          opts["allow_private"])
    else:
        shot_proxy_path(asset_id).unlink(missing_ok=True)
    # Map the two transports to roles: the allow listed vantage and the public,
    # non allow listed one.
    if vantage == "proxy":
        whitelisted_ok, public_ok = proxy_ok, direct_ok
    else:
        whitelisted_ok, public_ok = direct_ok, proxy_ok
    posture, detail = _exposure_from(whitelisted_ok, public_ok)
    with session_scope() as db:
        asset = db.get(ExternalAsset, asset_id)
        if asset is not None:
            asset.exposure = posture
            asset.exposure_detail = detail[:500]
            asset.exposure_at = utcnow()


def data_dir() -> Path:
    path = app_settings.data_dir / "external"
    path.mkdir(parents=True, exist_ok=True)
    return path


def shot_path(asset_id: int) -> Path:
    return data_dir() / "shots" / f"{int(asset_id)}.png"


def thumb_path(asset_id: int) -> Path:
    """The small JPEG the list shows in place of the full screenshot."""
    return data_dir() / "shots" / f"{int(asset_id)}.thumb.jpg"


def shot_proxy_path(asset_id: int) -> Path:
    """The screenshot taken through the exposure proxy, the other vantage."""
    return data_dir() / "shots" / f"{int(asset_id)}-proxy.png"


def drop_shot(asset_id: int) -> None:
    shot_path(asset_id).unlink(missing_ok=True)


def proof_path(scan_id: int, name: str) -> Path:
    """A proof screenshot for a finding on a scan.  name is like <hash>-a.png."""
    safe = re.sub(r"[^a-z0-9.\-]", "", str(name).lower())[:80]
    return data_dir() / "proof" / str(int(scan_id)) / safe


def _attach_proof_shots(scan_id, findings, a_headers, b_headers, opts) -> int:
    """For each cross account finding, photograph the object as the first
    account and again as the second, so a person can compare what each one
    sees and judge whether the access is really broken.  -> how many were
    captured.  Best effort: no browser here, or a picture that will not take,
    just leaves the finding without one.  A scan is never failed over a picture.
    """
    import hashlib

    from app.core import external_probe
    if not external_probe.playwright_python() or not (a_headers and b_headers):
        return 0
    done = 0
    for f in findings:
        if f.get("proof_kind") != "two_account" or done >= 6:
            continue
        url = f.get("proof_url") or f.get("url")
        if not url:
            continue
        key = hashlib.sha1((str(f.get("rule_id") or "") + "|" + url).encode()).hexdigest()[:16]
        shots = {}
        for who, hdrs in (("a", a_headers), ("b", b_headers)):
            name = f"{key}-{who}.png"
            dest = proof_path(scan_id, name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                res = external_probe.playwright_shot(
                    [url], dest, allow_private=opts["allow_private"], timeout=30, headers=hdrs)
            except Exception:  # noqa: BLE001 - a picture never breaks the scan
                res = {"status": "failed"}
            if res.get("status") in ("ok", "blank") and dest.is_file() and dest.stat().st_size:
                shots[who] = name
        if shots:
            f["proof"] = shots
            done += 1
    return done
    thumb_path(asset_id).unlink(missing_ok=True)
    shot_proxy_path(asset_id).unlink(missing_ok=True)


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


def saved_profile_names(db) -> set:
    """The names of the saved scan profiles, for validating a site's default."""
    from app.core.models import DastScanProfile

    return {row[0] for row in db.query(DastScanProfile.name).all()}


def clean_details(data: dict, partial: bool = False, envs: dict = None,
                  keep_env: str = "", profile_names: set = None) -> dict:
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

        raw = str(data.get("default_profile") or "").strip()
        if not raw:
            out["default_profile"] = ""
        elif raw.lower() in dast_engines.PROFILES:
            out["default_profile"] = raw.lower()          # a plain depth
        elif profile_names and raw in profile_names:
            out["default_profile"] = raw[:80]             # a saved profile name
        else:
            raise ValueError("The default scan profile must be baseline, quick, "
                             "standard, thorough, premium, or a saved profile name.")
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
    cleaned = clean_details(details, partial=True, envs=envs, profile_names=saved_profile_names(db)) if details else {}
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
            if changes.get("auth_b") is not None:
                kind, values = changes["auth_b"]
                external_auth.save(asset, kind, values, actor, asset.parent_domain,
                                   slot="b")
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
    """The profile a scan of this site starts with when nobody picks one.

    A plain depth is returned as is.  A saved scan profile name is returned
    when a profile by that name still exists, so a site can default to, say,
    the PHP profile.  Anything else falls back to the product default.
    """
    from app.core import dast_engines
    from app.core.models import DastScanProfile

    value = (getattr(asset, "default_profile", "") or "")
    if value.lower() in dast_engines.PROFILES:
        return value.lower()
    if value:
        with session_scope() as db:
            if db.query(DastScanProfile).filter(
                    DastScanProfile.name == value).first():
                return value
    return dast_engines.DEFAULT_PROFILE


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
            .filter(Finding.excepted.is_(False))
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
            .filter(Finding.excepted.is_(False))
            .filter(Finding.out_of_scope.is_(False))
            .filter(Finding.severity.in_(list(order))).limit(2000).all())
    rows.sort(key=lambda f: (order.get(f.severity, 9), -(f.risk_score or 0)))
    return rows[:limit]


# How a code finding is named everywhere: GCR- and twelve hex digits.
_VULN_ID = re.compile(r"\bGCR-[0-9A-F]{12}\b")


def settled_sast(db, ids) -> set:
    """The code findings among these ids a person took out of the counts.

    An exception (an approved waiver or an exclusion rule sets excepted), a
    not deployed scope, or a false positive, which is a regrade to info.  A
    fixed finding is not here: it was real, and saying so is still true.
    """
    from app.core.models import Severity

    ids = sorted({i for i in ids if i})
    if not ids:
        return set()
    out = set()
    for start in range(0, len(ids), 500):
        for vuln_id, excepted, out_of_scope, state, severity in (
                db.query(Finding.vuln_id, Finding.excepted, Finding.out_of_scope,
                         Finding.state, Finding.severity)
                .filter(Finding.vuln_id.in_(ids[start:start + 500])).all()):
            if (excepted or out_of_scope or state == FindingState.WAIVED
                    or severity == Severity.INFO):
                out.add(vuln_id)
    return out


def _cites(text, settled) -> bool:
    return any(i in settled for i in _VULN_ID.findall(str(text or "")))


def _drop_sentences(text, settled) -> str:
    parts = re.split(r"(?<=[.!?])\s+", str(text or ""))
    return "  ".join(p for p in parts if not _cites(p, settled)).strip()


def _dast_marks(f: dict) -> set:
    """What a model's sentence about this DAST finding would contain: its id,
    and the file or page it is about."""
    from urllib.parse import unquote, urlparse

    marks = {str(m).lower() for m in (f.get("id"), f.get("key")) if m}
    path = unquote(urlparse(str(f.get("url") or "")).path or "").rstrip("/")
    name = path.rsplit("/", 1)[-1]
    if len(name) >= 5:
        marks.add(name.lower())
    return marks


def scrub_dast_review(review: dict, findings: list, removed: list = None) -> dict:
    """The model's summary and priorities, less every sentence about a DAST
    finding that is no longer reported: one a person called a false positive
    or gave an exception, or one the model itself took out.

    The answer was written once, before those decisions, and is shown on every
    page and report after them.  A sentence goes when it names a settled
    finding by id, or by a file or page that no reported finding shares.
    "withheld_dast" says how many sentences went.
    """
    review = dict(review or {})
    settled, live = set(), set()
    for f in findings or []:
        out = (f.get("decision") or {}).get("kind") in ("false_positive", "exception")
        (settled if out else live).update(_dast_marks(f))
    for f in removed or []:
        settled.update(_dast_marks(f))
    settled -= live
    if not settled:
        review["withheld_dast"] = 0
        return review

    def names(text) -> bool:
        low = str(text or "").lower()
        return any(m in low for m in settled)

    gone = 0
    parts = re.split(r"(?<=[.!?])\s+", str(review.get("summary") or ""))
    keep = [p for p in parts if not names(p)]
    gone += len(parts) - len(keep)
    review["summary"] = "  ".join(keep).strip()
    for k in ("priorities", "next_steps"):
        if review.get(k):
            left = [x for x in review[k] if not names(x)]
            gone += len(review[k]) - len(left)
            review[k] = left
    review["withheld_dast"] = gone
    return review


def scrub_review(db, review: dict, findings: list = None,
                 text: str = "summary", lists=("priorities", "next_steps")) -> dict:
    """A saved model answer, less what it said about settled code findings.

    The answer is kept as it was written, so a finding somebody later called
    a false positive or gave an exception would go on being reported.  This
    is applied every time one is shown.  The summary goes whole when it names
    one, since the sentences around the id are about the same code.  Returns
    a copy, with "withheld" set to how many settled findings it named.
    """
    review = dict(review or {})
    findings = findings if findings is not None else []
    seen = set()
    for value in [review.get(text)] + [x for k in lists for x in review.get(k) or []]:
        seen.update(_VULN_ID.findall(str(value or "")))
    for c in review.get("correlations") or []:
        if isinstance(c, dict):
            seen.update(_VULN_ID.findall(str(c.get("sast") or "")))
    for f in findings:
        seen.update(_VULN_ID.findall(str(f.get("ai_sast") or "") + " " + str(f.get("ai_why") or "")))
    settled = settled_sast(db, seen)
    review["withheld"] = 0
    if not settled:
        return review
    named = set()
    for value in [review.get(text)] + [x for k in lists for x in review.get(k) or []]:
        named.update(i for i in _VULN_ID.findall(str(value or "")) if i in settled)
    if _cites(review.get(text), settled):
        review[text] = ""
    for k in lists:
        if review.get(k):
            review[k] = [x for x in review[k] if not _cites(x, settled)]
    if review.get("correlations"):
        kept = []
        for c in review["correlations"]:
            if isinstance(c, dict) and _cites(c.get("sast"), settled):
                named.update(i for i in _VULN_ID.findall(str(c.get("sast"))) if i in settled)
                continue
            kept.append(c)
        review["correlations"] = kept
    for f in findings:
        if _cites(f.get("ai_sast"), settled):
            f["ai_sast"] = ""
        if _cites(f.get("ai_why"), settled):
            f["ai_why"] = _drop_sentences(f["ai_why"], settled)
    review["withheld"] = len(named)
    return review


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
        from sqlalchemy.orm import object_session

        db = object_session(scan)
        if db is not None and isinstance(out["ai"]["summary"], dict):
            out["ai"]["summary"] = scrub_review(db, out["ai"]["summary"], out["findings"])
    return out


def findings_of(scan: ExternalDastScan) -> list:
    try:
        return json.loads(scan.findings or "[]") or []
    except ValueError:
        return []


# The telemetry sources a site's scans can come from, grouped for the risk
# trend.  The key decides which scans share a chart; the label titles it.
_SOURCE_ORDER = {"builtin": 0, "insightappsec": 1, "remote": 2, "recorded": 3}


def _scan_source(scan: ExternalDastScan) -> tuple:
    """(group key, shown label) for one scan's telemetry source.  Rapid7 scans
    come in as source "remote" with the InsightAppSec provider, so they are
    split off from any other remote server by the provider."""
    if (scan.provider or "") == "insightappsec":
        return "insightappsec", "Rapid7 InsightAppSec"
    if scan.source == "builtin":
        return "builtin", "Built-in DAST"
    if scan.source == "remote":
        return "remote", (scan.server_name or "DAST server")
    if scan.source == "recorded":
        return "recorded", "Recorded"
    return (scan.source or "other"), SCAN_SOURCES.get(
        scan.source, (scan.source or "Other").title())


def scan_risk_value(scan: ExternalDastScan) -> int:
    """One weighted risk number from a scan's severity counts, so every scan -
    a full built-in report, a counts-only InsightAppSec import, a recorded one
    - lands on the same scale.  The weights are the report's own per-finding
    demerits, so a point here means what a point in the grade means: higher is
    worse."""
    from app.core.dast_report import DEMERIT

    return sum(DEMERIT.get(s, 0) * (getattr(scan, s) or 0) for s in SEVERITIES)


def _scan_when_ts(scan: ExternalDastScan) -> float:
    """A sortable timestamp for a scan, by its own date then when it started,
    tolerant of a naive datetime coming back from SQLite."""
    when = scan.scanned_at or scan.started_at
    if when is None:
        return 0.0
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.timestamp()


def risk_trends(db, asset_id: int) -> list:
    """One risk-over-time line per telemetry source for a site.  A site scanned
    by both the built-in DAST and Rapid7 gets two charts, one each: the two
    measure different things and must not be drawn as a single line.  Only
    finished scans carry final counts, so only those become points."""
    from app.core import charts

    scans = (db.query(ExternalDastScan)
             .filter(ExternalDastScan.asset_id == asset_id,
                     ExternalDastScan.status == "done")
             .all())
    groups: dict = {}
    for s in scans:
        key, label = _scan_source(s)
        groups.setdefault(key, {"label": label, "scans": []})["scans"].append(s)
    out = []
    for key in sorted(groups, key=lambda k: (_SOURCE_ORDER.get(k, 9), k)):
        g = groups[key]
        ordered = sorted(g["scans"], key=lambda s: (_scan_when_ts(s), s.id))
        points = []
        for s in ordered:
            when = s.scanned_at or s.started_at
            points.append({
                "value": scan_risk_value(s), "id": s.id,
                "label": when.strftime("%d %b") if when else "",
                "date": when.strftime("%Y-%m-%d %H:%M") if when else "",
                "worst": s.severity or "none",
                "counts": {sev: getattr(s, sev) or 0 for sev in SEVERITIES},
            })
        out.append({"key": key, "label": g["label"],
                    "count": len(points), "chart": charts.risk_line(points)})
    return out


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
        from app.core import settings_store as _s

        with session_scope() as db:
            do_exposure = (bool(_s.get(db, "dast.exposure_check"))
                           and bool(exposure_proxy(db)))
        if do_exposure and not why:
            run_exposure_check(asset_id, host, opts, rec)
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
        # A saved scan profile resolves to a depth plus the rulesets to run.
        # After this, profile is a plain depth the engines understand, and the
        # chosen rulesets are recorded on the scan.
        profile, chosen_rulesets, from_saved = resolve_profile(db, profile)
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
            profile=profile,
            curated_rulesets=json.dumps(chosen_rulesets) if from_saved else "",
            started_at=utcnow(), recorded_by=(actor or "")[:120],
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
        adhoc = {"git": asset.adhoc_git_url or "", "archive": asset.adhoc_archive or "",
                 "asset_id": asset_id} if asset is not None else {}
    out = {"repos": [], "routes": [], "by_repo": {}, "sinks": []}
    for repo_id, name, connection, branch in plan:
        if scan_id in _stopping:
            break
        _update(scan_id, step=f"reading {name} for routes")
        entry = {"repository": name, "branch": branch, "routes": 0,
                 "host_in_code": [], "error": ""}
        try:
            # Prefer a RAM backed checkout (/dev/shm): faster and never on disk.
            # branch_tip falls back to the temp directory when RAM is tight.
            with recheck.branch_tip(connection, name, branch, in_memory=True) as (root, why):
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
                    for sink in got.get("sinks") or []:
                        if len(out["sinks"]) < MAX_WHITEBOX_SINKS:
                            out["sinks"].append(dict(sink, repository=name))
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
    # An ad-hoc code source the person pointed at this site: a git URL or an
    # uploaded archive, read the same way, when the code is not a mapped repo.
    if (adhoc.get("git") or adhoc.get("archive")) and scan_id not in _stopping:
        from app.core import dast_adhoc

        label = (adhoc.get("git") or f"uploaded {adhoc.get('archive')} archive")[:200]
        _update(scan_id, step="reading the ad-hoc code source")
        entry = {"repository": f"ad-hoc: {label}", "branch": "", "routes": 0,
                 "host_in_code": [], "error": ""}
        try:
            with dast_adhoc.checkout(adhoc) as (root, why):
                if root is None:
                    entry["error"] = why or "could not read it"
                else:
                    got = dast_whitebox.read(root, host)
                    entry["routes"] = len(got["routes"])
                    entry["host_in_code"] = got["host_files"]
                    for route in got["routes"]:
                        if route not in out["routes"]:
                            out["routes"].append(route)
                    for sink in got.get("sinks") or []:
                        if len(out["sinks"]) < MAX_WHITEBOX_SINKS:
                            out["sinks"].append(dict(sink, repository=label))
        except Exception as exc:  # noqa: BLE001 - the scan carries on without it
            entry["error"] = f"{type(exc).__name__}: {exc}"[:200]
        out["repos"].append(entry)
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


def resolve_profile(db, profile) -> tuple:
    """A scan's chosen profile to (depth, ruleset names, whether it was saved).

    A saved profile name gives its depth and its rulesets.  A plain depth gives
    itself, no recorded rulesets (the depth alone then decides, so premium runs
    them all), and from_saved False.
    """
    from app.core.dast_checks import profiles as prof_mod
    from app.core.models import DastScanProfile

    saved = db.query(DastScanProfile).filter(
        DastScanProfile.name == (profile or "")).first()
    if saved is None:
        return profile, [], False
    depth = saved.depth if saved.depth in prof_mod.DEPTHS else "premium"
    return depth, prof_mod._list(saved.rulesets), True


def _scan_rulesets(scan_id, profile) -> list:
    """The curated rulesets this scan runs.

    The scan's own recorded selection wins (set from a saved profile).  With
    none recorded, the depth string decides: premium runs them all, the rest
    run none, which is how it behaved before saved profiles existed.
    """
    from app.core.dast_checks import profiles

    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        recorded = (scan.curated_rulesets or "") if scan else ""
    if recorded:
        try:
            value = json.loads(recorded)
            if isinstance(value, list):
                return value
        except ValueError:
            pass
    return ["*"] if profile == "premium" else []


def _session_headers(sess: dict) -> dict:
    """The request headers a built session signs in with: cookie and any headers."""
    out = {}
    if not sess:
        return out
    if sess.get("cookie"):
        out["Cookie"] = sess["cookie"]
    for name, value in sess.get("headers") or []:
        out[name] = value
    return out


def _start_scan_proxy(session, host, upstream, workdir):
    """A local mitmproxy for the engine run, or None.  It signs every engine's
    requests in and refuses any host out of scope.  Off in settings, not
    installed, or failed to start -> None, and the engines run direct."""
    from app.core import dast_proxy
    from app.core import settings_store as s
    from app.core.dast_checks import scope

    with session_scope() as db:
        on = s.get(db, "dast.scan_proxy")
        on = True if on is None else bool(on)
        domains = scope.company_domains(s.get(db, "web.company_domains") or [])
    if not on:
        return None
    hosts = list(dict.fromkeys([host] + [d for d in domains if d]))
    return dast_proxy.start(_session_headers(session), hosts, upstream=upstream or "",
                            workdir=workdir)


def _browser_dom(scan_id, url, opts, proxy) -> tuple:
    """Load the page in a real browser, run its scripts, and read the JavaScript
    it loaded.  -> (findings, an engines summary row).  Findings are a secret
    hardcoded in client code or source exposed through a source map; both are
    proof the page itself hands over, so there are no false positives here.  A
    browser that cannot run is a skipped row, never a failed scan."""
    from app.core import dom_scan, external_probe

    with external_probe.via_proxy(proxy or ""):
        collected = external_probe.browser_dom_collect(url, allow_private=opts["allow_private"])
    name = "Headless DOM scan"
    if not collected.get("ok"):
        return [], {"tool": "dom", "name": name, "status": "skipped", "seconds": 0,
                    "detail": collected.get("error") or "the browser gave no answer"}
    try:
        findings = dom_scan.scan(collected, url)
    except Exception:  # noqa: BLE001 - the rest of the scan stands without it
        log.exception("scan %s: the DOM scan failed to read the page", scan_id)
        return [], {"tool": "dom", "name": name, "status": "skipped", "seconds": 0,
                    "detail": "the page loaded but could not be read"}
    loaded = len(collected.get("scripts") or []) + len(collected.get("inline") or [])
    return findings, {
        "tool": "dom", "name": name, "status": "ok", "seconds": 0,
        "detail": (f"read {loaded} script{'s' if loaded != 1 else ''} the page loaded; "
                   f"{len(findings)} finding{'s' if len(findings) != 1 else ''}")}


def _run_curated_rules(scan_id, asset_id, url, wb, session, opts, rulesets) -> tuple:
    """Run the enabled curated rules in the chosen rulesets against the site.

    rulesets is the list the scan profile chose (["*"] for all).  -> (findings,
    an engines summary row).  Every rule is validated again and runs through
    the engine, which holds the scope gate and the safety contract, so an out
    of scope host or an unsafe rule never gets a request.
    """
    from urllib.parse import urlparse

    from app.core import external_auth
    from app.core import settings_store as settings_mod
    from app.core.dast_checks import callback, engine, profiles, scope
    from app.core.dast_checks import spec as spec_mod
    from app.core.models import DastRule, ExternalAsset

    specs, domains = [], []
    excluded = invalid = 0
    auth_a = auth_b = None
    with session_scope() as db:
        for row in db.query(DastRule).filter(DastRule.enabled.is_(True)).all():
            if not profiles.selected(row.rule_class, row.rulesets, rulesets):
                excluded += 1   # enabled, but not in a ruleset this profile runs
                continue
            try:
                specs.append(spec_mod.validate(json.loads(row.spec or "{}")))
            except (ValueError, spec_mod.SpecError):
                invalid += 1   # a bad stored rule is skipped, never run
                continue
        domains = scope.company_domains(
            settings_mod.get(db, "web.company_domains") or [])
        oob = callback.for_scan(db)
        asset = db.get(ExternalAsset, asset_id)
        auth_a = (external_auth.load(asset) or None) if asset else None
        # The second account, for the compare checks.  Loaded only when at least
        # one enabled rule needs it.
        if asset and any("two_accounts" in (s.get("needs") or []) for s in specs):
            auth_b = external_auth.load_b(asset) or None

    # Sign in FRESH for this stage.  The curated rules run last, after the engines
    # (which on premium can take hours), by when the sign in from the start of the
    # scan has usually run out and the site answers "session expired".  Each
    # account is signed in again now, and the engine can sign in again once more
    # if a session still lapses while the checks run.
    def _fresh_headers(auth):
        if not auth:
            return None
        s = external_auth.session_for(auth, opts["allow_private"])
        return _session_headers(s) if s.get("ok") else None

    headers = _fresh_headers(auth_a) or _session_headers(session)
    second_headers = _fresh_headers(auth_b)
    reauth_a = (lambda: _fresh_headers(auth_a)) if auth_a else None
    reauth_b = (lambda: _fresh_headers(auth_b)) if auth_b else None

    host = urlparse(url).hostname or ""
    row = {"tool": "curated", "name": "Premium curated rules", "status": "ok",
           "seconds": 0}
    # The gate, stated once for the whole stage: an out of scope site runs none.
    if not scope.allowed(host, domains):
        row["status"] = "skipped"
        row["detail"] = scope.refuse_reason(host, domains)
        return [], row
    if not specs:
        row["status"] = "skipped"
        row["detail"] = "no curated rules are enabled"
        return [], row

    ctx = {"base_url": url, "host": host, "domains": domains,
           "allow_private": opts["allow_private"],
           "code_routes": list(wb.get("routes") or []),
           "headers": headers or None, "second_headers": second_headers,
           "reauth_a": reauth_a, "reauth_b": reauth_b,
           # What each account is meant to be able to do, so a cross account read
           # can be judged against the intended policy, not just reported.
           "intent_a": (auth_a or {}).get("intent", ""),
           "intent_b": (auth_b or {}).get("intent", ""),
           "budget": 60, "oob": oob}
    from collections import Counter

    started = time.monotonic()
    findings, ran, skipped, confirmed = [], 0, 0, 0
    skip_reasons = Counter()
    for spec in specs:
        if scan_id in _stopping:
            break
        result = engine.run_rule(spec, ctx)
        if result["status"] == "ok":
            ran += 1
            findings += result["findings"]
            confirmed += len(result["findings"])
        elif result["status"] == "skipped":
            skipped += 1
            skip_reasons[result.get("detail") or "a prerequisite was not met"] += 1
        else:
            log.info("curated rule %s: %s - %s", spec.get("id"),
                     result["status"], result.get("detail"))
    row["seconds"] = int(time.monotonic() - started)
    # Proof pictures for the cross account findings: what the first account sees
    # at the object, and what the second does, so a person can compare them.
    if second_headers and scan_id not in _stopping \
            and any(f.get("proof_kind") == "two_account" for f in findings):
        _update(scan_id, step="capturing proof screenshots")
        _attach_proof_shots(scan_id, findings, headers, second_headers, opts)
    detail = (f"{ran} rule{'' if ran == 1 else 's'} ran, "
              f"{confirmed} finding{'' if confirmed == 1 else 's'}, "
              f"{skipped} skipped")
    # Say why they skipped, grouped, so an admin can see what to set up.
    if skip_reasons:
        detail += " (" + "; ".join(f"{n} {reason}" for reason, n
                                   in skip_reasons.most_common()) + ")"
    notes = []
    if excluded:
        notes.append(f"{excluded} enabled rule{'' if excluded == 1 else 's'} "
                     "not in this profile's rulesets")
    if invalid:
        notes.append(f"{invalid} could not be read")
    if notes:
        detail += ".  " + "; ".join(notes)
    row["detail"] = detail
    return findings, row


def engine_timeouts_for(asset_id: int) -> dict:
    """Per engine minute overrides set on a site, {engine: minutes}.  A bad or
    non positive value is dropped, so the default is used for that engine."""
    with session_scope() as db:
        asset = db.get(ExternalAsset, asset_id)
        raw = getattr(asset, "engine_timeouts", "") if asset else ""
    try:
        got = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}
    out = {}
    for name, value in (got or {}).items():
        try:
            minutes = int(value)
        except (TypeError, ValueError):
            continue
        if minutes > 0 and str(name) in TIMEOUT_ENGINES:
            out[str(name)] = minutes
    return out


# The engines a site may set its own run time for.
TIMEOUT_ENGINES = ("nuclei", "nikto", "ffuf", "wapiti", "sqlmap", "dalfox")


def set_engine_timeouts(asset, values: dict) -> None:
    """Save the per engine minute overrides on a site from a {engine: minutes}
    map; an engine with a blank or zero value is left at the default."""
    from app.core import dast_engines

    clean = {}
    for name in TIMEOUT_ENGINES:
        raw = (values or {}).get(name)
        if raw in (None, ""):
            continue
        try:
            minutes = int(raw)
        except (TypeError, ValueError):
            continue
        if minutes > 0:
            clean[name] = min(minutes, dast_engines.MAX_TIMEOUT // 60)
    asset.engine_timeouts = json.dumps(clean) if clean else ""


def _builtin_run(scan_id, host, asset_id, profile, opts, auth, proxy) -> None:
    from app.core import dast_engines, external_auth, external_dast, external_probe
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
        scan_proxy = _start_scan_proxy(session, host, proxy, workdir)
        proxy_total = 0
        if scan_proxy:
            engines.append({"tool": "scan-proxy", "name": "Scan proxy", "status": "ok",
                            "seconds": 0, "detail": "the engines run through a local proxy "
                            "that signs each request in and refuses any host out of scope"})
            _update(scan_id, engines=json.dumps(engines))
        engine_proxy = scan_proxy.url if scan_proxy else proxy
        try:
            # Links on the front page, then the routes from the code.
            extra = dast_engines.links_in(url, base["telemetry"].get("body_sample") or "")
            extra += [r for r in routes if r not in extra]
            timeouts = engine_timeouts_for(asset_id)
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
                # testssl reads the site's own TLS, so it must reach it directly,
                # not through the proxy that terminates TLS with its own cert.
                tool_proxy = proxy if tool == "testssl" else engine_proxy
                before = scan_proxy.count() if scan_proxy else 0
                result = dast_engines.run_engine(
                    tool, url, host, profile, workdir, scan_id, paths=extra,
                    auth_args=args, proxy=tool_proxy,
                    timeout=dast_engines.effective_timeout(tool, timeouts))
                # How many requests this tool actually sent, counted at the proxy
                # (the one place that sees them all).  testssl goes direct, so it
                # is not counted here.
                if scan_proxy and tool != "testssl":
                    sent = max(0, scan_proxy.count() - before)
                    result["requests"] = sent
                    proxy_total += sent
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
            if scan_proxy:
                for e in engines:
                    if e.get("tool") == "scan-proxy":
                        e["requests"] = proxy_total
                        e["detail"] = ("the engines ran through a local proxy that signs "
                                       "each request in and refuses any host out of scope; "
                                       f"it forwarded {proxy_total:,} request"
                                       f"{'s' if proxy_total != 1 else ''} to the target "
                                       "(the attacks the tools sent)")
                        break
                _update(scan_id, engines=json.dumps(engines))
                scan_proxy.stop()
            shutil.rmtree(workdir, ignore_errors=True)
    # The headless DOM scan: load the page in a real browser, run its scripts,
    # and read the JavaScript it loaded for a secret hardcoded in client code or
    # source left exposed through a source map.  Both are proof, not a guess, so
    # it runs on the deeper profiles when a browser is on hand.
    if url and profile in ("thorough", "premium") and external_probe.playwright_python() \
            and scan_id not in _stopping:
        _update(scan_id, step="reading the page in a browser")
        dom_findings, dom_row = _browser_dom(scan_id, url, opts, proxy)
        findings += dom_findings
        engines.append(dom_row)
        _update(scan_id, engines=json.dumps(engines))
    # The premium curated rules: the enhanced, high fidelity checks.  They run
    # last, only on premium, and only against the company's own domains.  With
    # no rules enabled (the default) this does nothing.
    if url and plan:
        rulesets = _scan_rulesets(scan_id, profile)
        if rulesets:
            rule_findings, rule_row = _run_curated_rules(scan_id, asset_id, url, wb,
                                                         session, opts, rulesets)
            findings += rule_findings
            engines.append(rule_row)
            _update(scan_id, engines=json.dumps(engines))
    # Nothing an engine echoed back of the sign in is kept.
    findings = external_auth.redact(findings, secrets)
    engines = external_auth.redact(engines, secrets)
    findings, dropped = drop_soft_404(findings, url, opts["allow_private"])
    if dropped:
        engines.append({"tool": "verify", "name": "Soft 404 check", "status": "ok",
                        "seconds": 0,
                        "detail": f"left out {dropped} finding{'s' if dropped != 1 else ''} "
                                  "for paths that answer not found, or with the same "
                                  "page as one that cannot exist"})
    csp = (base["telemetry"].get("headers") or {}).get("content-security-policy", "")
    findings, lowered = soften_blocked_xss(findings, csp)
    if lowered:
        engines.append({"tool": "verify", "name": "CSP check", "status": "ok", "seconds": 0,
                        "detail": f"lowered {lowered} reflected XSS finding"
                                  f"{'s' if lowered != 1 else ''} to informational: the "
                                  "site's content security policy blocks inline script"})
    findings, csrf_dropped = drop_samesite_csrf(findings, base["telemetry"].get("set_cookies") or [])
    if csrf_dropped:
        engines.append({"tool": "verify", "name": "SameSite check", "status": "ok", "seconds": 0,
                        "detail": f"left out {csrf_dropped} CSRF finding"
                                  f"{'s' if csrf_dropped != 1 else ''}: the site's session "
                                  "cookie is SameSite, so a cross site form cannot carry it"})
    findings = merge(roll_up(findings, url))
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


# Engines whose URL findings are re-checked against the live response.  The
# path discovery ones (nikto, nuclei, ffuf) report a path because it answered,
# which a site that serves its home page for every address answers every time.
# Wapiti is here too: its form and header findings (CSRF, CSP, htaccess and the
# like) are moot when the URL is access controlled, a not found, or a redirect
# to a login, so they are dropped the same way.
PATH_ENGINES = {"nikto", "nuclei", "ffuf", "wapiti"}
MAX_VERIFY = 400
SOFT_404_BODY = 65536
NOT_THERE = (404, 410)
# A path that answers with sign in required or forbidden is access controlled,
# not exposed.  An engine that calls such a path a finding read a working
# control, or a "your session has expired" page, not a served file.
PROTECTED = (401, 403)
# A redirect whose target is a sign in page says the same thing a 403 does: the
# path is behind a login, so an engine that reached it found the login, not the
# page.  Matched on the redirect target, not the path, so a plain http to https
# or trailing slash redirect is left alone.
_LOGIN_URL = re.compile(r"log[\-_]?in|sign[\-_]?in|/auth\b|/authentica|/sso\b|/oauth|"
                        r"/openid|/account/|/session|/idp/|saml|/login\.", re.I)
# A claim that an access restriction was bypassed (wapiti's htaccess module and
# the like).  On a path that a plain request already reads, there was no
# restriction to get past, so the claim is empty.
_WEAK_RESTRICTION = re.compile(r"bypassable|weak restriction|htaccess bypass|"
                               r"restriction.{0,20}bypass|bypass.{0,20}restriction", re.I)
REFLECTED = re.compile(r"xss|cross.site.script|reflect|crlf|header injection|response split"
                       r"|CWE-79\b|CWE-113\b", re.I)


def drop_soft_404(findings: list, base_url: str, allow_private: bool = False) -> tuple:
    """Leave out path findings whose page is the site's not found page.

    One request to an address that cannot exist gives the site's answer for
    nothing.  A finding whose address answers with the same body found
    nothing either.  Two such addresses are asked: a file under a folder,
    and a name that starts with a dot.  Some sites (Adobe Experience
    Manager among them) answer a missing page with a real 404 but serve the
    home page for "/.anything", so a reported "/.bash_history" is only the
    home page.  -> (kept, how many were left out)
    """
    import secrets as _s
    from urllib.parse import unquote, urljoin, urlparse

    from app.core import external_probe

    if not base_url:
        return findings, 0

    def norm(body: str, *echoed: str) -> str:
        # Pages that echo the address back differ only by the address, and
        # Cloudflare re-encodes protected email addresses on every request.
        body = re.sub(r"gcr-[0-9a-f]+", "", body or "")
        for word in echoed:
            if len(word) >= 3:
                body = body.replace(word, "")
        body = re.sub(r"[0-9a-fA-F]{16,}", "", body)
        return re.sub(r"\s+", " ", body)

    def same(a: str, a_cut: bool, b: str, b_cut: bool) -> bool:
        # A body cut at the limit ends wherever the limit fell, which moves
        # with the length of the echoed address, so only what both hold is
        # compared, and only when that is most of a page.
        if a_cut or b_cut:
            n = min(len(a), len(b))
            return n >= SOFT_404_BODY // 2 and a[:n] == b[:n]
        return a == b

    controls = []
    for probe in (f"/gcr-{_s.token_hex(6)}/{_s.token_hex(4)}.html", f"/.gcr-{_s.token_hex(6)}"):
        got = external_probe.fetch(urljoin(base_url, probe), allow_private=allow_private,
                                   body_limit=SOFT_404_BODY)
        if got["status"] == 200 and got["body"]:
            controls.append((norm(got["body"]), len(got["body"]),
                             len(got["body"]) >= SOFT_404_BODY))

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
                                       body_limit=SOFT_404_BODY)
            name = unquote(path.rstrip("/").rsplit("/", 1)[-1])
            # The bare name, as the control's own name is taken out, so
            # whatever was around it (a leading dot) stays on both sides.
            echoed = (name.lstrip("."),)
            html = "html" in got["headers"].get("content-type", "")
            body, cut = got["body"], len(got["body"]) >= SOFT_404_BODY
            loc = got["headers"].get("location", "")
            to_login = 300 <= got["status"] < 400 and bool(_LOGIN_URL.search(loc))
            seen[url] = (got["status"], to_login, got["status"] == 200 and any(
                same(norm(body, *echoed), cut, mark, mark_cut)
                # Bodies cut at the limit all have its length, so only a
                # whole page can be matched on size.
                or html and not (cut or mark_cut) and abs(len(body) - size) < 16
                for mark, size, mark_cut in controls))
        status, to_login, soft = seen[url]
        # Nothing is there: a claim that a file or page was found is only the
        # site's not found page.  What the page itself carries stays: input
        # it echoes back, or a key in it, is on the 404 page too.
        if soft or status in NOT_THERE:
            if not about_content(f):
                dropped += 1
                continue
            # True, but of the page every missing address gets, so roll_up
            # can say that once instead of once per address.
            f = dict(f, answer="not_found")
        elif status in PROTECTED or to_login:
            # Sign in required, forbidden, or redirected to a login page: the
            # path is access controlled, so an engine calling it reachable
            # found the control working, or a session expired page, not a
            # served file.  A finding about what the page echoes or holds is
            # kept; a bare "this path is here" is dropped, the same as a not
            # found.
            if not about_content(f):
                dropped += 1
                continue
            f = dict(f, answer="protected")
        elif status == 200 and _WEAK_RESTRICTION.search(
                f"{f.get('title') or ''} {f.get('evidence') or ''}"):
            # A bypass of an access restriction, but a plain request already
            # reads the path, so there was no restriction to get past.
            dropped += 1
            continue
        elif status:
            f = dict(f, answer="found")
        kept.append(f)
    return kept, dropped


def about_content(f: dict) -> bool:
    """A finding about what a page holds or echoes, not about a path being
    there.  Such a finding is as true on a not found page as anywhere."""
    text = f"{f.get('title') or ''} {f.get('cwe') or ''} {f.get('evidence') or ''}"
    return bool(REFLECTED.search(text) or SECRET_WORDS.search(text))


# Reflected cross site scripting that works by injecting an inline script or an
# event handler.  A strong Content-Security-Policy stops those from running.
XSS_WORDS = re.compile(r"\bxss\b|cross.site.script|CWE-79\b", re.I)
# Script sources broad enough that an attacker can still load a script: a bare
# scheme or a wildcard, which allow a script from anywhere on that scheme.
_BROAD_SCRIPT_SRC = {"*", "http:", "https:", "data:", "blob:", "'unsafe-inline'"}


def _csp_blocks_inline_script(csp: str) -> bool:
    """Whether a Content-Security-Policy stops an injected inline script.

    True only when script is governed (by script-src, or default-src when
    there is no script-src), inline script is not allowed, and the allowed
    sources are not opened up to a whole scheme or a wildcard.  A missing,
    unsafe-inline, or wide open policy returns False, so a real reflected XSS
    is never hidden by a weak policy.
    """
    directives = {}
    for part in (csp or "").split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, rest = part.partition(" ")
        directives[name.lower()] = rest.lower().split()
    src = directives.get("script-src")
    if src is None:
        src = directives.get("default-src")
    if not src:
        return False
    return not any(token in _BROAD_SCRIPT_SRC for token in src)


def soften_blocked_xss(findings: list, csp: str) -> tuple:
    """Lower reflected XSS findings to informational when the site's policy
    blocks inline script, with the reason.  -> (findings, how many lowered).

    Lowered, not dropped: a policy does not stop DOM based XSS or a reflected
    script that lands in an allowed source, so the finding is kept to verify
    by hand, but it is no longer rated as if it ran.
    """
    if not _csp_blocks_inline_script(csp):
        return findings, 0
    note = ("  The site sends a Content-Security-Policy that does not allow "
            "inline script, so an injected inline script or event handler will "
            "not run.  Lowered to informational: confirm by hand that a script "
            "source or a DOM sink makes it exploitable before acting on it.")
    lowered, out = 0, []
    for f in findings:
        text = f"{f.get('title') or ''} {f.get('cwe') or ''} {f.get('evidence') or ''}"
        if (f.get("tool") in ("dalfox", "wapiti", "nuclei", "nikto")
                and XSS_WORDS.search(text)
                and RANK.get(f.get("severity"), 0) > RANK.get("info")):
            f = dict(f, severity="info", evidence=((f.get("evidence") or "")[:400] + note))
            lowered += 1
        out.append(f)
    return out, lowered


# Cross site request forgery findings, by name.  A form that carries no anti
# CSRF token is the usual trigger.
CSRF_WORDS = re.compile(r"\bcsrf\b|cross.site.request|CWE-352\b", re.I)
# Cookie names that look like they carry a session, so SameSite on them matters.
_SESSION_COOKIE = re.compile(r"sess|auth|token|sid|jwt|login|csrf", re.I)


def _cookies_samesite(set_cookies: list) -> bool:
    """Whether every session like cookie the site sets is SameSite Strict or
    Lax, so a form on another site cannot send it.  False when there is no such
    cookie, or any one lacks SameSite, so a real CSRF is never hidden."""
    session_seen = False
    for raw in set_cookies or []:
        name = (raw.split("=", 1)[0] or "").strip()
        if not _SESSION_COOKIE.search(name):
            continue
        session_seen = True
        flags = {p.strip().lower() for p in raw.split(";")[1:]}
        samesite = next((f.split("=", 1)[1].strip() for f in flags
                         if f.startswith("samesite") and "=" in f), "")
        if samesite not in ("strict", "lax"):
            return False
    return session_seen


def drop_samesite_csrf(findings: list, set_cookies: list) -> tuple:
    """Leave out CSRF findings when the site's session cookie is SameSite, so a
    form on another site cannot carry it, which is the way the attack works.
    -> (kept, dropped).  A heuristic engine finding with no request shown is not
    worth keeping once the cookie already blocks it."""
    if not _cookies_samesite(set_cookies):
        return findings, 0
    kept, dropped = [], 0
    for f in findings:
        text = f"{f.get('title') or ''} {f.get('cwe') or ''} {f.get('evidence') or ''}"
        if f.get("tool") in ("wapiti", "nuclei", "nikto") and CSRF_WORDS.search(text):
            dropped += 1
            continue
        kept.append(f)
    return kept, dropped


ROLL_UP_AT = 3
MAX_ROLLED_URLS = 200
_PATH_PREFIX = re.compile(r"^/\S*:\s+")


def rolled_title(f: dict) -> str:
    """The title without the path some engines put in front of it."""
    return _PATH_PREFIX.sub("", str(f.get("title") or "")).strip()


def roll_up(findings: list, base_url: str, keep=lambda f: False) -> list:
    """One finding for one problem seen on many addresses.

    A key in the site's 404 page, or one missing header, is reported once
    for every address an engine tried.  The same engine giving the same
    title on ROLL_UP_AT or more addresses becomes one finding at the site's
    root, at the worst severity, that lists them.  Its key no longer moves
    with whichever addresses a scan happened to try, so a decision on it
    holds for the next scan.  keep(f) leaves a finding out of it (one that
    already has a decision of its own).
    """
    from urllib.parse import urlparse

    root = base_url
    if base_url:
        u = urlparse(base_url)
        root = f"{u.scheme}://{u.netloc}/" if u.netloc else base_url
    groups, order = {}, []
    for f in findings:
        if keep(f) or f.get("rolled_up"):
            order.append(("one", f))
            continue
        tool, title = f.get("tool") or f.get("check") or "", rolled_title(f).lower()
        k = (tool, title)
        if k not in groups:
            # Engines cut long titles (nikto at 200 characters), so a long
            # path in front leaves less of the same message: one that is the
            # start of another, or the other way round, is the same message.
            k = next((g for g in groups if g[0] == tool and min(len(g[1]), len(title)) >= 40
                      and (g[1].startswith(title) or title.startswith(g[1]))), k)
        if k not in groups:
            groups[k] = []
            order.append(("group", k))
        groups[k].append(f)
    out = []
    for kind, item in order:
        if kind == "one":
            out.append(item)
            continue
        members = groups[item]
        urls = list(dict.fromkeys(m.get("url") or "" for m in members if m.get("url")))
        if len(urls) < ROLL_UP_AT:
            out.extend(members)
            continue
        worst = max(members, key=lambda m: RANK.get(m.get("severity"), 0))
        paths = [urlparse(x).path or "/" for x in urls]
        one = dict(worst)
        for gone in ("key", "id", "decision", "ai_verdict", "ai_why", "ai_sast", "ai_kept",
                     "answer"):
            one.pop(gone, None)
        title = max((rolled_title(m) for m in members), key=len) or worst.get("title") or ""
        among = ", ".join(paths[:10]) + (" ..." if len(paths) > 10 else "")
        # Of the addresses that were asked again: only so many are, and an
        # address nobody checked says nothing either way.
        missing = sum(1 for m in members if m.get("answer") == "not_found")
        checked = sum(1 for m in members if m.get("answer"))
        if checked and missing * 2 > checked:
            # Said once, of the page itself: the problem is in the page the
            # site gives for an address that does not exist, not at each one.
            title = f"The site's not found page: {title}"
            evidence = (f"Every address that does not exist answers with the same page, "
                        f"and the page has this in it.  Seen on {len(urls)} addresses, "
                        f"among them: {among}")
        else:
            evidence = f"Seen on {len(urls)} addresses, among them: {among}"
        one.update(title=title[:300], url=root or worst.get("url"), evidence=evidence[:600],
                   urls=urls[:MAX_ROLLED_URLS], rolled_up=len(urls))
        from app.core.external_decisions import finding_key

        one["key"] = finding_key(one)
        one["id"] = one["key"][:12]
        out.append(one)
    return out


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
    sinks = _correlate_sinks(wb.get("sinks") or [], records)
    _update(scan_id, paths=json.dumps(paths), paths_count=paths["counts"]["answered"],
            paths_real=paths["counts"]["reachable"],
            code_sinks=json.dumps(sinks), code_matches=json.dumps(
        _code_matches(asset_id, records, index, names)))


def _correlate_sinks(sinks: list, records: list) -> list:
    """Mark each code sink reachable when the dynamic scan reached one of the
    routes its file declares.  A reachable sink is a lead worth proving; one
    that is not reachable is context, a thing to look at, not a dynamic bug."""
    reached = {r["p"] for r in records if r.get("r") is True}
    out = []
    for s in sinks:
        hit = sorted(set(s.get("routes") or []) & reached)
        out.append({"file": s.get("file"), "line": s.get("line"),
                    "type": s.get("type"), "repository": s.get("repository", ""),
                    "routes": (s.get("routes") or [])[:4],
                    "reachable": bool(hit), "reached_route": hit[0] if hit else ""})
    # Reachable ones first, then by type, so the report leads with what matters.
    out.sort(key=lambda s: (not s["reachable"], s["type"], s["file"]))
    return out


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
    linked = []
    for l in data.get("linked") or []:
        rid = l.get("repo_id")
        if rid not in visible:
            continue
        link = links.get(rid) or {}
        # A repository un-pinned since the scan is no longer linked, so it drops
        # out of here at once: the code section then shows straight away that it
        # is gone, which is the plain sign that the un-pin took.
        if not link.get("linked"):
            continue
        src = link.get("source") or ""
        total = int(l.get("routes_total") or 0)
        reached = int(l.get("routes_reached") or 0)
        # A repository pinned to this subdomain that declares routes none of
        # which the scan reached, and whose link is not from the host being
        # written in its code, is probably not what powers this site.  Flag it
        # so somebody can un-pin it: developers often do not know which sites
        # their code serves, so the mapping drifts and nobody corrects it.
        unlikely = total > 0 and reached == 0 and src != "code"
        linked.append(dict(l, full_name=visible[rid].full_name, source=src,
                           unlikely=unlikely))
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
    """A finished Rapid7 scan onto its row.  The site's most recent few scans
    keep their full findings, so their detail, a PDF report and AI triage all
    work here.  Older scans keep only their counts, so this database does not
    hold the whole history in full."""
    when = when or utcnow()
    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None:
            return
        asset_id = scan.asset_id
        keep = ias.detail_scans(db)
        # This row is not "done" yet, so it is not in the count of scans newer
        # than it.  Only the site's own InsightAppSec scans count.
        newer = (db.query(ExternalDastScan)
                 .filter(ExternalDastScan.asset_id == asset_id,
                         ExternalDastScan.provider == ias.PROVIDER,
                         ExternalDastScan.status == "done",
                         ExternalDastScan.id != scan_id,
                         ExternalDastScan.scanned_at.isnot(None),
                         ExternalDastScan.scanned_at > when).count())
    if keep > 0 and newer < keep:
        found = ias.describe(region, key, vulns, cache=cache, client=client)
        finish(scan_id, merge(found), when=when, result_url=result_url)
        with session_scope() as db:
            scan = db.get(ExternalDastScan, scan_id)
            if scan is not None:
                scan.summary_only = False
    else:
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
            scan.scanned_at = when
            scan.result_url = (result_url or "")[:1000]
            for sev in SEVERITIES:
                setattr(scan, sev, roll[sev])
            scan.severity = roll["severity"]
            touch_asset(db, scan)
    with session_scope() as db:
        _ias_prune(db, asset_id, keep)


def _ias_prune(db, asset_id: int, keep: int) -> None:
    """Keep full findings on only the site's newest `keep` InsightAppSec scans;
    roll older detailed ones back to counts (their counts stay on the row), so
    the detail kept here stays bounded to the most recent scans."""
    scans = (db.query(ExternalDastScan)
             .filter(ExternalDastScan.asset_id == asset_id,
                     ExternalDastScan.provider == "insightappsec",
                     ExternalDastScan.status == "done")
             .order_by(ExternalDastScan.scanned_at.desc()).all())
    for scan in scans[max(0, keep):]:
        if not scan.summary_only and scan.findings:
            scan.findings = ""
            scan.summary_only = True


def pull_ias_detail(scan_id: int) -> tuple:
    """Pull a counts-only InsightAppSec scan's full findings from Rapid7 and
    store them on the row, so its detail, a PDF report and AI triage all work
    here without signing in to Rapid7.  -> (ok, message).  Slow (API calls), so
    the caller runs it off the event loop."""
    from app.core import insightappsec as ias

    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is None:
            return False, "No such scan."
        if scan.provider != ias.PROVIDER or not scan.remote_id:
            return False, "This is not an InsightAppSec scan."
        if scan.status not in ("done", "failed"):
            return False, "Wait for the scan to finish."
        remote_id, result_url, when = scan.remote_id, scan.result_url, scan.scanned_at
        cfg = ias.config(db)
    if not cfg["ready"]:
        return False, "InsightAppSec is turned off, so its results cannot be pulled."
    try:
        vulns = ias.scan_vulns(cfg["region"], cfg["key"], remote_id)
        found = ias.describe(cfg["region"], cfg["key"], vulns)
    except ias.IASError as exc:
        return False, f"InsightAppSec: {exc}"[:200]
    finish(scan_id, merge(found), when=when, result_url=result_url)
    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        if scan is not None:
            scan.summary_only = False
    n = len(found)
    return True, f"Pulled {n} finding{'' if n == 1 else 's'} from InsightAppSec."


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
findings from the code behind the site, the site's exposure from a two vantage \
check, and, for each finding, a deterministic risk score and, when the weakness \
is a known class, a VERIFIED real world precedent.

For each DAST finding do two things.

1) Decide a verdict: likely_real, likely_false_positive, or needs_review.  \
Scanners report many false positives: version banners that are patched, generic \
header advice, reflected input that is encoded, and template matches on a soft \
404 page.  A finding you call likely_false_positive is taken out of the \
results, so use it only when the evidence shows it is noise.  When unsure, say \
needs_review.  A finding about an exposed secret stays whatever you say.

For a cross account, broken access finding, judge it against what each account \
is meant to do (account_a_is_meant_to and account_b_is_meant_to, when given): \
if the first account reaching the second account's object is within its stated \
role, for example a read only auditor that may see everything, call it \
likely_false_positive and say which part of the stated role makes it expected; \
if reaching that object is outside its stated role, it is likely_real, a true \
broken access control.  With no stated role, say needs_review and that a person \
must confirm the intended access.

2) Write "why" as a short risk narrative for an engineer, three to five \
sentences, in this order:
 - what can go wrong: what an attacker gains if the finding is real, and, when \
the finding would expose the data the app holds, what that breach means in real \
terms using ONLY the consequence provided in data_the_app_holds (for example SOX \
fines, breach notification, customer and reputational loss); name no consequence \
that was not provided;
 - how an abuser attacks it: the concrete steps against THIS finding, at this url;
 - how likely it is to lead to a breach: reason from the site's exposure (open \
to the world raises it, allow listed lowers it), the attack surface and \
reachability (a sensitive or unauthenticated endpoint, a path reachable with no \
session), any compensating control visible in the evidence (authentication \
required, input encoded, a patch already applied), and the fact that modern \
attackers automate discovery and exploitation at scale, increasingly with AI \
assistance, so an internet reachable and easily automated weakness (enumeration, \
guessing, injection, or an exposed secret that bots scrape within minutes) is \
more likely to be reached than its manual difficulty suggests.

FACTS ONLY.  This is a hard rule, never break it:
 - Use ONLY the verified real world precedent provided with the finding.  Never \
invent or recall a CVE number, a company, a breach size, a date or a statistic.  \
If no precedent is provided, describe the mechanism and name no incident.
 - A precedent is a comparable case, not this site's fate.  Do not say this site \
was breached or will be.
 - Do not overstate.  If the exposure is allow listed, or a compensating control \
is present, say plainly that the likelihood is lower, and why.
 - Keep the severities and the deterministic risk as given.  Explain them; do \
not override them.  Do not invent findings.

When a SAST finding in the code supports a DAST finding (same weakness, same \
route or parameter), say so; that raises confidence a great deal.

Answer with JSON only, in this shape:
{"summary": "three to five sentences for an engineer, plain US English",
 "verdicts": [{"id": "finding id", "verdict": "likely_real", "why": "the risk narrative",
   "sast": "matching SAST finding id or empty"}],
 "priorities": ["the three things to fix first, worst risk first, one sentence each"]}

Whenever you mention a SAST finding, give its id (GCR- and twelve characters).  \
Whenever the summary or a priority is about a DAST finding, give its id in \
square brackets, as [id]."""

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
 "next_steps": ["up to five actions, most important first"]}

Whenever you mention a SAST finding, give its id (GCR- and twelve characters).  \
Whenever the summary or a priority is about a DAST finding, give its id in \
square brackets, as [id]."""


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


def _evfp(f: dict) -> str:
    """A fingerprint of what the model would read, so an unchanged finding can
    reuse the verdict it already got instead of being sent again."""
    import hashlib

    basis = f"{f.get('evidence') or ''}|{f.get('severity') or ''}|{f.get('title') or ''}"
    return hashlib.md5(basis.encode("utf-8", "replace")).hexdigest()[:12]


def _prior_verdicts(db, asset_id: int, scan_id: int) -> dict:
    """The AI verdicts from this site's last reviewed scan, by finding key, so a
    finding that has not changed reuses its verdict and is not sent again."""
    from app.core.external_decisions import finding_key

    prev = (db.query(ExternalDastScan)
            .filter(ExternalDastScan.asset_id == asset_id,
                    ExternalDastScan.id != scan_id,
                    ExternalDastScan.ai_status == "done")
            .order_by(ExternalDastScan.id.desc()).first())
    if prev is None:
        return {}
    out = {}
    for f in findings_of(prev):
        if f.get("ai_verdict"):
            out[f.get("key") or finding_key(f)] = {
                "verdict": f["ai_verdict"], "why": f.get("ai_why", ""),
                "sast": f.get("ai_sast", ""), "evfp": _evfp(f)}
    return out


def triage(scan_id: int, actor: str = "") -> None:
    """Ask the model to sort one scan's findings.  Runs in the caller's thread.

    Guardrails so the model is a bounded advisor, not the scanner: it is only
    ever sent findings that passed the deterministic filters; a finding
    unchanged since the last scan reuses its verdict without a call; and no more
    than the cap go to the model, highest risk first, so a noisy scan cannot run
    up a bill."""
    from app.core import ai
    from app.core import settings_store as settings_mod

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
        exposure = (getattr(asset, "exposure", "") or "")
        exposure_detail = (getattr(asset, "exposure_detail", "") or "")
        from app.core import data_classification

        data_profile = data_classification.profile_for_asset(db, asset)
        cap = max(1, int(settings_mod.get(db, "dast.ai_max_findings") or 40))
        prior = _prior_verdicts(db, scan.asset_id, scan_id)
    # Deterministic risk (likelihood x breachability, weighted by exposure and by
    # the data the app holds) and the verified real world precedent for each
    # weakness class, computed before the model is asked, so it reasons from
    # these facts rather than its memory.
    from app.core import dast_precedent, dast_risk

    dast_risk.annotate(all_findings, exposure, data_profile["classes"])
    dast_precedent.annotate(all_findings)
    # Reuse a verdict for any finding unchanged since the last reviewed scan.
    reused = 0
    for f in findings:
        pv = prior.get(f["key"])
        if pv and pv["evfp"] == _evfp(f):
            f["ai_verdict"], f["ai_why"], f["ai_sast"] = pv["verdict"], pv["why"], pv["sast"]
            f["ai_cached"] = True
            reused += 1
    # Of the rest, send only the cap, highest severity first; the overflow keeps
    # its computed risk and is marked not reviewed.
    to_send = sorted((f for f in findings if not f.get("ai_cached")),
                     key=lambda f: RANK.get(f.get("severity"), 0), reverse=True)
    capped = len(to_send) - cap
    for f in to_send[cap:]:
        f["ai_note"] = "not reviewed by the model: over the per scan cap"
    to_send = to_send[:cap]
    answers, verdicts, summaries, priorities, unreadable = [], {}, [], [], 0
    chunk = 120
    for start in range(0, max(1, len(to_send)), chunk):
        part = to_send[start:start + chunk]
        if not part:
            break
        prompt = json.dumps({
            "site": host,
            "site_exposure": {
                "reachable": exposure or "unknown",
                "meaning": ("open means reachable from the open internet; "
                            "whitelisted means only from allow listed networks; "
                            "unknown means the exposure check did not run"),
                "detail": _clean(exposure_detail)[:200],
            },
            "data_the_app_holds": {
                "classes": data_profile["labels"],
                "consequence_if_breached": data_profile["consequence"],
                "source": "derived from the code repositories linked to this site",
            },
            "dast_findings": [{"id": f.get("id") or f["key"], "tool": f.get("tool"),
                               "severity": f.get("severity"), "title": _clean(f.get("title")),
                               "url": _clean(f.get("url"))[:300],
                               "evidence": _clean(f.get("evidence"))[:600],
                               "cwe": f.get("cwe"),
                               "account_a_is_meant_to": f.get("intent_a") or "",
                               "account_b_is_meant_to": f.get("intent_b") or "",
                               "computed_likelihood": f.get("likelihood_label"),
                               "computed_impact": f.get("breachability_label"),
                               "computed_risk": f.get("risk"),
                               "risk_basis": _clean(f.get("risk_basis"))[:300],
                               "verified_real_world_precedent": f.get("precedent") or "",
                               "precedent_reference": f.get("precedent_ref") or "",
                               "how_the_class_is_abused": f.get("abuse") or ""}
                              for f in part],
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
    # A pass that only reused verdicts made no call, and that is a success, not
    # a failure.
    ok = (any(a["ok"] for a in answers) and (summaries or verdicts)) or (
        not answers and reused > 0)
    for f in all_findings:
        v = verdicts.get(str(f.get("id") or f["key"])) or verdicts.get(f["key"])
        if v:
            verdict = str(v.get("verdict") or "")
            f["ai_verdict"] = verdict if verdict in (
                "likely_real", "likely_false_positive", "needs_review") else "needs_review"
            f["ai_why"] = str(v.get("why") or "")[:900]
            f["ai_sast"] = str(v.get("sast") or "")[:40]
    with session_scope() as db:
        scan = db.get(ExternalDastScan, scan_id)
        try:
            before = json.loads(scan.ai_summary or "{}")
        except ValueError:
            before = {}
        kept, removed = split_ai_false_positives(all_findings)
        removed = _merge_removed((before.get("removed") if isinstance(before, dict) else None),
                                 removed)
        scan.findings = json.dumps(kept, default=str)
        scan.ai_status = "done" if ok else "failed"
        scan.ai_summary = json.dumps({
            "removed": removed, "tidied": (before or {}).get("tidied") if isinstance(before, dict) else None,
            "summary": " ".join(summaries)[:4000], "priorities": priorities[:8],
            "reused": reused, "capped": max(0, capped),
            "model": next((a.get("model") for a in answers if a.get("model")), ""),
            "error": "" if ok else next(
                (a["error"] for a in answers if a.get("error")),
                ("The model answered, but not with the JSON it was asked for"
                 + (", and the answer was cut off at its length limit" if any(
                     a.get("cut_off") for a in answers) else "")
                 + ".  Try again, or raise the longest answer on the AI page.")
                if unreadable else "The model gave no usable answer."),
            "at": utcnow().isoformat()})
        if removed:
            from app.core import external_decisions

            db.flush()
            external_decisions.recount(db, scan.asset_id)
        scan.ai_calls = (scan.ai_calls or 0) + spent["calls"]
        scan.ai_input_tokens = (scan.ai_input_tokens or 0) + spent["in"]
        scan.ai_output_tokens = (scan.ai_output_tokens or 0) + spent["out"]
        if spent["priced"]:
            before = Decimal(scan.ai_cost or "0")
            scan.ai_cost = f"{before + spent['cost']:.4f}"


# A finding that quotes or names a secret is only annotated by the model,
# never removed: only proof that the secret is dead lowers a credential.
SECRET_WORDS = re.compile(r"api.?key|secret|passw|token|private.key|credential|"
                          r"access.key|\.htpasswd|\.npmrc|\.pgpass|id_rsa|\.aws", re.I)


def ai_removable(f: dict) -> bool:
    """The model called it a likely false positive, nobody has decided on it
    or put it back, and it is not about a secret."""
    return (f.get("ai_verdict") == "likely_false_positive" and not f.get("decision")
            and not f.get("ai_kept")
            and not SECRET_WORDS.search(f"{f.get('title') or ''} {f.get('evidence') or ''} "
                                        f"{f.get('url') or ''}"))


def split_ai_false_positives(findings: list) -> tuple:
    """-> (findings kept, what was taken out, kept short so it can be shown
    and put back)."""
    kept, removed = [], []
    for f in findings or []:
        (removed if ai_removable(f) else kept).append(f)
    return kept, [{k: f.get(k) for k in REMOVED_FIELDS if f.get(k) not in (None, "")}
                  | {"removed_at": utcnow().isoformat(), "removed_why": "ai"} for f in removed]


REMOVED_FIELDS = ("id", "key", "check", "tool", "tools", "title", "severity", "severity_found",
                  "url", "evidence", "remediation", "cwe", "reference", "ai_verdict", "ai_why",
                  "ai_sast")
MAX_REMOVED = 5000


def _merge_removed(old, new: list) -> list:
    out = {}
    for f in list(old or []) + list(new or []):
        if isinstance(f, dict) and f.get("key"):
            out.setdefault(f["key"], f)
    return list(out.values())[:MAX_REMOVED]


def removed_of(scan: ExternalDastScan) -> list:
    try:
        summary = json.loads(scan.ai_summary or "{}")
    except ValueError:
        return []
    return [f for f in (summary.get("removed") or []) if isinstance(f, dict)] \
        if isinstance(summary, dict) else []


def dast_confirmations_for(db, finding) -> list:
    """Live dynamic findings that point back at one code (SAST) finding.

    A DAST finding names the code finding it matches in ai_sast (the GCR id).
    When one does, and it was not dismissed, a dynamic scan has shown this exact
    code weakness is reachable on a running site: it is not only in the code, it
    is exploitable now.  -> a short list to show on the finding and to warn on
    before it is waived.  Looks only at the newest done scan of each site linked
    to the finding's repository, so it is a couple of queries, not a sweep.
    """
    from app.core import dast_risk, external_decisions
    from app.core.models import ExternalAssetRepo, Repository

    vid = (getattr(finding, "vuln_id", "") or "")
    repo = (getattr(finding, "repository", "") or "")
    if not vid or not repo:
        return []
    repo_row = (db.query(Repository)
                .filter(Repository.full_name == repo).one_or_none())
    if repo_row is None:
        return []
    asset_ids = [r.asset_id for r in db.query(ExternalAssetRepo)
                 .filter(ExternalAssetRepo.repository_id == repo_row.id).all()]
    out = []
    for aid in asset_ids:
        scan = (db.query(ExternalDastScan)
                .filter(ExternalDastScan.asset_id == aid,
                        ExternalDastScan.status == "done")
                .order_by(ExternalDastScan.id.desc()).first())
        if scan is None:
            continue
        asset = db.get(ExternalAsset, aid)
        found = external_decisions.apply(findings_of(scan),
                                         external_decisions.for_asset(db, aid),
                                         scan_id=scan.id)
        for f in found:
            if vid not in str(f.get("ai_sast") or ""):
                continue
            if f.get("ai_verdict") == "likely_false_positive":
                continue
            if (f.get("decision") or {}).get("kind") == "false_positive":
                continue
            lk = int(f.get("likelihood") or 0)
            out.append({
                "host": asset.host if asset else "",
                "asset_id": aid, "scan_id": scan.id,
                "title": f.get("title") or "", "severity": f.get("severity") or "",
                "likelihood": lk,
                "likelihood_label": dast_risk.LIKELIHOOD_LABEL.get(lk, ""),
                "verdict": f.get("ai_verdict") or "", "url": f.get("url") or "",
                "when": scan.scanned_at or scan.started_at})
    return out


def restore_removed(db, scan: ExternalDastScan, key: str, actor: str) -> dict:
    """Put a finding the model took out back on the scan.  -> the finding,
    or {} when it was not taken out."""
    from app.core import external_decisions

    summary = json.loads(scan.ai_summary or "{}")
    removed = summary.get("removed") or []
    back = next((f for f in removed if isinstance(f, dict) and f.get("key") == key), None)
    if back is None:
        return {}
    summary["removed"] = [f for f in removed if f is not back]
    back = {k: v for k, v in back.items() if k != "removed_at"}
    back["ai_kept"] = {"by": (actor or "")[:120], "at": utcnow().isoformat()}
    scan.ai_summary = json.dumps(summary, default=str)
    scan.findings = json.dumps(findings_of(scan) + [back], default=str)
    db.flush()
    external_decisions.recount(db, scan.asset_id)
    return back


TIDY_VERSION = 1


def tidy_findings(scan: ExternalDastScan, findings: list) -> tuple:
    """A finished scan's findings under the rules a new scan gets: no path
    claim the site answered not found, one finding for one problem on many
    addresses, and none the model called a likely false positive.  Findings
    with a person's decision are left as they are.  -> (kept, removed)"""
    from urllib.parse import urlparse

    from app.core import dast_paths

    status = {}
    for r in dast_paths.load(scan.paths).get("paths") or []:
        if isinstance(r, dict) and r.get("p"):
            status[r["p"]] = r.get("s")
    kept, removed = [], []
    for f in findings:
        path = urlparse(str(f.get("url") or "")).path or "/"
        missing = (f.get("tool") in PATH_ENGINES and path != "/"
                   and status.get(path) in NOT_THERE)
        if missing and not f.get("decision"):
            if not about_content(f):
                removed.append(dict(f, removed_why="not_found"))
                continue
            f = dict(f, answer="not_found")
        elif status.get(path) and f.get("tool") in PATH_ENGINES:
            f = dict(f, answer="found")
        kept.append(f)
    url = next((f.get("url") for f in kept if f.get("url")), "")
    kept = roll_up(kept, url, keep=lambda f: bool(f.get("decision")))
    kept, by_ai = split_ai_false_positives(kept)
    slim = [{k: f.get(k) for k in REMOVED_FIELDS + ("removed_why",) if f.get(k) not in (None, "")}
            | {"removed_at": utcnow().isoformat()} for f in removed]
    return kept, slim + by_ai


def tidy_old_scans() -> int:
    """Once at start, then never again for the same scan: scans finished
    before these rules get them.  -> findings taken out or rolled into one."""
    from app.core import external_decisions

    total = 0
    with session_scope() as db:
        ids = [i for (i,) in db.query(ExternalDastScan.id).filter(
            ExternalDastScan.status == "done", ExternalDastScan.source == "builtin")]
    for scan_id in ids:
        with session_scope() as db:
            scan = db.get(ExternalDastScan, scan_id)
            try:
                summary = json.loads(scan.ai_summary or "{}")
            except ValueError:
                summary = {}
            summary = summary if isinstance(summary, dict) else {}
            if summary.get("tidied") == TIDY_VERSION:
                continue
            before = findings_of(scan)
            kept, removed = tidy_findings(scan, before)
            summary["tidied"] = TIDY_VERSION
            if removed:
                summary["removed"] = _merge_removed(summary.get("removed"), removed)
            scan.ai_summary = json.dumps(summary, default=str)
            if len(kept) != len(before):
                scan.findings = json.dumps(kept, default=str)
                db.flush()
                external_decisions.recount(db, scan.asset_id)
                total += len(before) - len(kept)
    return total


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
