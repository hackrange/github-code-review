"""Rapid7 InsightAppSec: start dynamic scans there and read the findings back.

The first of the integrations on the Settings page.  What it does:

    test        the key against the platform, then against InsightAppSec
    catalog     the apps and scan configs the key can see, with the start
                addresses of each config, so a site can be matched to one
    start       a scan from a scan config, which is the only way InsightAppSec
                starts one: the config holds the start address, the attack
                template, the engine and the sign in
    poll        the scan's status until it is COMPLETE or FAILED
    findings    the vulnerabilities that scan found, as this product's
                dynamic scan findings

Written against the published v1 API (OpenAPI 3.1, read 2026-11-04):
https://help.rapid7.com/insightappsec/en-us/api/v1/insightappsec-api-v1.json

Things that are easy to get wrong, all from that reading:

  * The API address is a fixed literal per region, never built from what was
    typed.  A region of "attacker.example/" would otherwise send the key
    somewhere else.  Rapid7's own GitHub Action does the same.
  * GET /scan-configs, /scans and /vulnerabilities take no filters.  A
    scan's findings come from POST /search with vulnerability.scans.id.
  * POST /scans answers 201 with no body.  The new scan's id is the last
    part of the Location header.
  * A scan is finished at COMPLETE or FAILED and nowhere else.  PAUSED and
    BLACKED_OUT can sit for a day.  AWAITING_AUTHENTICATION waits for a
    person to sign in through Rapid7's browser extension.
  * Search values are single quoted, and the only values put in a query
    here are ids checked to be UUIDs, so nothing typed reaches the query.
  * No rate limit is documented for InsightAppSec.  The platform says
    requests may be limited and sends RateLimit-Reset when they are.
"""

from __future__ import annotations

import html
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("gcr.insightappsec")

NAME = "Rapid7 InsightAppSec"
PROVIDER = "insightappsec"
GUIDE = "/docs/integrations-insightappsec"

# code: (what the platform calls it, the API host).  The full list on
# https://docs.rapid7.com/insight/product-apis/#supported-regions.  Each host
# is a literal on purpose; see the module note.
REGIONS = {
    "us":   ("United States 1", "https://us.api.insight.rapid7.com"),
    "us2":  ("United States 2", "https://us2.api.insight.rapid7.com"),
    "us3":  ("United States 3", "https://us3.api.insight.rapid7.com"),
    "eu":   ("Europe", "https://eu.api.insight.rapid7.com"),
    "ca":   ("Canada", "https://ca.api.insight.rapid7.com"),
    "au":   ("Australia", "https://au.api.insight.rapid7.com"),
    "ap":   ("Japan", "https://ap.api.insight.rapid7.com"),
    "me1":  ("Middle East (UAE)", "https://me1.api.insight.rapid7.com"),
    "aps2": ("India", "https://aps2.api.insight.rapid7.com"),
}
# Where a person signs in to look at a scan, by the same code.
CONSOLES = {code: f"https://{code}.appsec.insight.rapid7.com" for code in REGIONS}

FINISHED = {"COMPLETE", "FAILED"}
# What each status means, for the step line on the scan page.  From
# https://docs.rapid7.com/insightappsec/concepts/#scan-status where Rapid7
# says, and plain words for the rest.
STATUS_WORDS = {
    "PENDING": "waiting for an engine",
    "QUEUED": "queued in InsightAppSec",
    "PROVISIONING": "starting an engine",
    "RUNNING": "scanning",
    "SCANNED": "scanned, processing the results",
    "PROCESSED": "processed, writing the reports",
    "COMPLETE": "complete",
    "PAUSED": "paused in InsightAppSec",
    "BLACKED_OUT": "held by a blackout window; it continues when the window ends",
    "AWAITING_AUTHENTICATION": "waiting for somebody to sign in for it in InsightAppSec",
    "AUTHENTICATED": "signed in",
    "AUTHENTICATING": "signing in",
    "PAUSING": "pausing",
    "RESUMING": "resuming",
    "STOPPING": "stopping",
    "CANCELING": "canceling",
    "FAILED": "failed",
}
# failure_reason, said plainly.  From
# https://docs.rapid7.com/insightappsec/failed-scan-status-codes/ where it
# says.  LICENSE_INVALID is not about the license.
FAILURES = {
    "CANCELED": "it was canceled",
    "NETWORK_UNAVAILABLE": "the site did not answer the engine",
    "SYSTEM_ERROR": "InsightAppSec had an internal error",
    "CONFIGURATION_INVALID": "the scan config is not valid, usually its addresses",
    "BAD_AUTH": "the sign in in the scan config did not work",
    "LICENSE_INVALID": "an address in the scan config is not on the Targets allowlist",
    "TARGETS_INVALID": "the scan config has no valid target",
    "ENGINE_UNAVAILABLE": "no engine was available",
    "INITIALIZATION_FAILURE": "the engine could not start the scan",
    "SWAGGER_PARSING_ERROR": "the API definition file would not parse",
    "DATABASE_TOO_LARGE": "the scan database grew too large",
    "INSUFFICIENT_DISK_SPACE": "the engine ran out of disk",
    "INSUFFICIENT_MEMORY": "the engine ran out of memory",
    "TOO_MANY_THREADS": "the engine ran too many threads",
    "RASP_FAILURE": "the runtime protection step failed",
    "BOOTSTRAP_AUTHENTICATION_FAILURE": "the bootstrap sign in failed",
    "REPORT_GENERATION_FAILURE": "the report could not be built",
}
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
            "LOW": "low", "INFORMATIONAL": "info", "SAFE": "info"}
STATUS_NAMES = {"UNREVIEWED": "unreviewed", "VERIFIED": "verified",
                "FALSE_POSITIVE": "false positive", "IGNORED": "ignored",
                "REMEDIATED": "remediated", "DUPLICATE": "duplicate"}

PAGE = 1000            # the most the API gives in one page
MAX_PAGES = 50         # 50,000 rows, well past any real scan
MAX_CONFIGS = 1000     # read the options of at most this many configs
MAX_FINDINGS = 2000
TIMEOUT = 30
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_catalog_lock = threading.Lock()


class IASError(RuntimeError):
    """What went wrong, in words, with Rapid7's correlation id when it sent one.

    Never carries the key.  Nothing the key is sent with is repeated."""

    def __init__(self, message: str, status: int = 0, correlation: str = "",
                 retry_at: float = 0):
        super().__init__(message)
        self.status = status
        self.correlation = correlation
        self.retry_at = retry_at

    def __str__(self):
        text = super().__str__()
        return f"{text} (Rapid7 reference {self.correlation})" if self.correlation else text


def is_uuid(value) -> bool:
    return bool(UUID.match(str(value or "")))


# ------------------------------------------------------------------ settings

def config(db=None) -> dict:
    """What the Settings page says.  -> {enabled, region, key, max_concurrent, ready}"""
    from app.core import settings_store as store
    from app.core.db import session_scope

    def read(session):
        region = str(store.get(session, "ias.region") or "us").lower()
        key = store.get(session, "ias.api_key") or ""
        out = {"enabled": bool(store.get(session, "ias.enabled")),
               "region": region if region in REGIONS else "us",
               "key": key,
               "max_concurrent": int(store.get(session, "ias.max_concurrent") or 2)}
        out["ready"] = out["enabled"] and bool(key)
        return out

    if db is not None:
        return read(db)
    with session_scope() as session:
        return read(session)


def api_base(region: str) -> str:
    try:
        return REGIONS[region][1] + "/ias/v1"
    except KeyError:
        raise IASError(f"{region!r} is not an Insight platform region.") from None


# ------------------------------------------------------------------ requests

def _client():
    import httpx

    # Redirects are not followed.  The API never sends one, and a sign in page
    # is what answers when the address is wrong; following it would hand the
    # key to whatever it pointed at.
    return httpx.Client(timeout=TIMEOUT, follow_redirects=False,
                        headers={"Accept": "application/json",
                                 "User-Agent": "git-code-review"})


def _explain(resp) -> IASError:
    """A response that is not a success, as something a person can act on."""
    correlation = resp.headers.get("r7-correlation-id", "")
    said = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            said = str(body.get("message") or "")
            code = body.get("errorCode") or body.get("error_code")
            if code:
                said = f"{said} [{code}]".strip()
            for one in (body.get("errors") or [])[:3]:
                if isinstance(one, dict) and one.get("explanation"):
                    said += f"; {one.get('context') or ''} {one['explanation']}".rstrip()
    except ValueError:
        said = ""
    said = said[:300]
    status = resp.status_code
    if status == 401:
        text = ("The API key was refused.  Check that it was copied whole, has not "
                "been deleted, and belongs to an organization in this region.")
    elif status == 403:
        text = ("The key is not allowed to do that.  A user key has the rights of "
                "its user; see the setup guide for the role it needs.")
    elif status == 404:
        text = "InsightAppSec has no such thing, or the key cannot see it."
    elif status == 409:
        text = "InsightAppSec refused that in the scan's current state."
    elif status == 422:
        text = "InsightAppSec would not accept that."
    elif status == 429:
        reset = resp.headers.get("RateLimit-Reset", "")
        try:
            retry_at = float(reset)
        except ValueError:
            retry_at = 300
        # Rapid7 documents epoch seconds.  A small number is a wait instead,
        # the way some gateways send it, and is read that way.
        if retry_at < 1_000_000_000:
            retry_at = time.time() + min(max(retry_at, 30), 3600)
        return IASError("Rapid7 is limiting requests from this key for now.  "
                        "Polling picks up again on its own.", status, correlation,
                        retry_at=retry_at)
    elif 300 <= status < 400:
        text = ("InsightAppSec answered with a redirect instead of the API.  The "
                "region is probably wrong.")
    else:
        text = f"InsightAppSec answered {status}."
    if said and said.lower() not in ("unauthorized", "unauthenticated"):
        text += f"  It said: {said}"
    return IASError(text, status, correlation)


def call(region: str, key: str, method: str, path: str, body=None, params=None,
         client=None, absolute: str = ""):
    """One request.  -> (parsed JSON or None, response headers)"""
    import httpx

    if not key:
        raise IASError("No API key is set.")
    url = absolute or api_base(region) + path
    own = client is None
    client = client or _client()
    try:
        resp = client.request(method, url, params=params, json=body,
                              headers={"X-Api-Key": key})
    except httpx.TimeoutException:
        raise IASError("InsightAppSec did not answer in time.") from None
    except httpx.HTTPError as exc:
        raise IASError(f"Could not reach InsightAppSec: {type(exc).__name__}.") from None
    finally:
        if own:
            client.close()
    if resp.status_code >= 300:
        raise _explain(resp)
    if not resp.content:
        return None, resp.headers
    if "json" not in (resp.headers.get("content-type") or ""):
        raise IASError("InsightAppSec answered with a web page, not the API.  The "
                       "region is probably wrong.", resp.status_code,
                       resp.headers.get("r7-correlation-id", ""))
    try:
        return resp.json(), resp.headers
    except ValueError:
        raise IASError("InsightAppSec sent something that is not JSON.") from None


def paged(region: str, key: str, method: str, path: str, body=None, params=None,
          client=None) -> list:
    """Every row of a paged list or search, a thousand at a time."""
    rows = []
    index = 0
    while index < MAX_PAGES:
        query = dict(params or {}, index=index, size=PAGE)
        got, _headers = call(region, key, method, path, body=body, params=query,
                             client=client)
        got = got or {}
        rows.extend(got.get("data") or [])
        meta = got.get("metadata") or {}
        pages = int(meta.get("total_pages") or 0)
        index += 1
        if index >= pages or not got.get("data"):
            break
    return rows


def search(region: str, key: str, kind: str, query: str, client=None) -> list:
    return paged(region, key, "POST", "/search",
                 body={"type": kind, "query": query}, client=client)


# ------------------------------------------------------------------ test

def test(region: str, key: str) -> tuple:
    """-> (ok, what happened).  Reads only; nothing is started or changed.

    The platform's /validate says whether the key is real.  It does not say
    the key can reach InsightAppSec, so the app and scan config counts follow.
    """
    if region not in REGIONS:
        return False, "Pick a region."
    if not key:
        return False, "Give the API key first."
    try:
        with _client() as client:
            call(region, key, "GET", "", client=client,
                 absolute=REGIONS[region][1] + "/validate")
            apps, _h = call(region, key, "GET", "/apps", params={"size": 1}, client=client)
            configs, _h = call(region, key, "GET", "/scan-configs",
                               params={"size": 1, "include-errors": "false"},
                               client=client)
    except IASError as exc:
        return False, str(exc)
    app_count = int(((apps or {}).get("metadata") or {}).get("total_data") or 0)
    config_count = int(((configs or {}).get("metadata") or {}).get("total_data") or 0)
    if not app_count:
        return True, ("The key works, but it can see no apps.  Give its user access "
                      "to the apps in InsightAppSec, or use a key with wider rights.")
    return True, (f"Connected to {REGIONS[region][0]}.  The key can see {app_count} "
                  f"app{'s' if app_count != 1 else ''} and {config_count} scan "
                  f"config{'s' if config_count != 1 else ''}.  Whether it may start "
                  f"scans only shows on the first one.")


# ------------------------------------------------------------------ catalog

def catalog_path() -> Path:
    from app.config import settings as app_settings

    return app_settings.data_dir / "integrations" / "insightappsec-catalog.json"


def load_catalog() -> dict:
    try:
        return json.loads(catalog_path().read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def host_of(url: str) -> str:
    try:
        return (urlparse(str(url or "").strip()).hostname or "").lower()
    except ValueError:
        return ""


def refresh_catalog(region: str, key: str) -> dict:
    """Read every app and scan config the key can see, and each config's start
    addresses.  Kept in the data volume, not the settings table: a big
    account's list does not fit in one settings row."""
    with _catalog_lock, _client() as client:
        apps = {a.get("id"): a.get("name") or "" for a in
                paged(region, key, "GET", "/apps", client=client) if a.get("id")}
        configs = paged(region, key, "GET", "/scan-configs",
                        params={"include-errors": "true"}, client=client)

    def seeds(cfg_id):
        try:
            got, _h = call(region, key, "GET", f"/scan-configs/{cfg_id}/options")
        except IASError as exc:
            log.info("options of scan config %s: %s", cfg_id, exc)
            return None
        crawl = (got or {}).get("crawl_config") or {}
        return [str(s.get("value") or "")[:500] for s in crawl.get("seed_url_list") or []
                if isinstance(s, dict) and s.get("value")][:20]

    usable = [c for c in configs if is_uuid(c.get("id"))][:MAX_CONFIGS]
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="ias-options") as pool:
        found = list(pool.map(lambda c: seeds(c["id"]), usable))

    rows = []
    for cfg, urls in zip(usable, found):
        app_id = (cfg.get("app") or {}).get("id") or ""
        rows.append({
            "id": cfg["id"], "name": str(cfg.get("name") or "")[:200],
            "app_id": app_id, "app": apps.get(app_id, "")[:200],
            "environment": ((cfg.get("assignment") or {}).get("environment") or "CLOUD"),
            "seeds": urls or [], "seeds_read": urls is not None,
            "hosts": sorted({h for h in (host_of(u) for u in urls or []) if h}),
            "errors": [str((e or {}).get("explanation") if isinstance(e, dict) else e)[:200]
                       for e in (cfg.get("errors") or [])][:5],
        })
    rows.sort(key=lambda r: (r["app"].lower(), r["name"].lower()))
    out = {"region": region, "fetched_at": datetime.now(timezone.utc).isoformat(),
           "apps": len(apps), "configs": rows,
           "truncated": len(configs) > MAX_CONFIGS}
    path = catalog_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(out), encoding="utf-8")
    tmp.replace(path)
    return out


def configs_for(host: str, catalog: dict = None) -> list:
    """Every scan config, the ones that start on this host first, then the ones
    on a host under the same domain.  -> [(config, how it matched)]"""
    catalog = load_catalog() if catalog is None else catalog
    host = (host or "").lower()
    parent = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host

    def rank(cfg):
        hosts = cfg.get("hosts") or []
        if host in hosts:
            return 0, "starts on this host"
        if parent and any(h == parent or h.endswith("." + parent) for h in hosts):
            return 1, "same domain"
        return 2, ""

    ranked = [(rank(c), c) for c in catalog.get("configs") or []]
    ranked.sort(key=lambda x: (x[0][0], x[1].get("app", "").lower(),
                               x[1].get("name", "").lower()))
    return [(c, why) for (_n, why), c in ranked]


def find_config(config_id: str, catalog: dict = None) -> dict | None:
    catalog = load_catalog() if catalog is None else catalog
    return next((c for c in catalog.get("configs") or [] if c.get("id") == config_id), None)


# ------------------------------------------------------------------ scans

def start(region: str, key: str, config_id: str) -> str:
    """Start a scan from one scan config.  -> the new scan's id"""
    if not is_uuid(config_id):
        raise IASError("That is not a scan config id.")
    _body, headers = call(region, key, "POST", "/scans",
                          body={"scan_config": {"id": config_id}})
    scan_id = (headers.get("location") or "").rstrip("/").rsplit("/", 1)[-1]
    if not is_uuid(scan_id):
        raise IASError("InsightAppSec accepted the scan but did not say its id.")
    return scan_id


def status(region: str, key: str, scan_id: str) -> dict:
    if not is_uuid(scan_id):
        raise IASError("That is not a scan id.")
    got, _h = call(region, key, "GET", f"/scans/{scan_id}")
    return got or {}


def act(region: str, key: str, scan_id: str, action: str) -> None:
    """PAUSE, RESUME, STOP or CANCEL.  STOP ends it and keeps what it found;
    CANCEL forces it to FAILED."""
    if action not in ("PAUSE", "RESUME", "STOP", "CANCEL") or not is_uuid(scan_id):
        raise IASError("Not an action this sends.")
    call(region, key, "PUT", f"/scans/{scan_id}/action", body={"action": action})


def last_event(region: str, key: str, scan_id: str) -> str:
    """The newest platform event, which is where a failed scan says why."""
    try:
        got, _h = call(region, key, "GET", f"/scans/{scan_id}/platform-events")
    except IASError:
        return ""
    events = got if isinstance(got, list) else (got or {}).get("data") or []
    events = [e for e in events if isinstance(e, dict) and e.get("event")]
    return str(events[-1]["event"])[:200] if events else ""


def failure(state: dict) -> str:
    reason = str(state.get("failure_reason") or "")
    said = FAILURES.get(reason, reason.lower().replace("_", " ") or "no reason given")
    return f"InsightAppSec failed it: {said}"


def scan_link(region: str, app_id: str, config_id: str, scan_id: str) -> str:
    """The scan in the InsightAppSec console.  The shape Rapid7's own GitHub
    Action builds; it needs a sign in to open."""
    base = CONSOLES.get(region, CONSOLES["us"])
    if not (is_uuid(app_id) and is_uuid(config_id) and is_uuid(scan_id)):
        return base
    return f"{base}/#/apps/{app_id}/configuration/{config_id}/scan/{scan_id}"


# ------------------------------------------------------------------ findings

_TAGS = re.compile(r"<[^>]+>")
_CWE = re.compile(r"CWE[-_ ]?(\d{1,5})", re.I)


def _plain(value, limit: int) -> str:
    text = html.unescape(_TAGS.sub(" ", str(value or "")))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def new_cache() -> dict:
    """Module names and fix text, kept across every scan of one import, since
    the same few modules turn up in nearly every scan."""
    return {"modules": {}, "docs": {}}


def findings(region: str, key: str, scan_id: str, cache: dict = None,
             client=None) -> list:
    """The vulnerabilities this scan found, as dynamic scan findings."""
    if not is_uuid(scan_id):
        raise IASError("That is not a scan id.")
    cache = cache if cache is not None else new_cache()
    modules, docs = cache["modules"], cache["docs"]
    own = client is None
    client = client or _client()
    try:
        vulns = search(region, key, "VULNERABILITY",
                       f"vulnerability.scans.id='{scan_id}'", client=client)[:MAX_FINDINGS]
        for v in vulns:
            variance = ((v.get("variances") or [{}]) or [{}])[0] or {}
            module = str((variance.get("module") or {}).get("id") or "")
            attack = str((variance.get("attack") or {}).get("id") or "")
            if is_uuid(module) and module not in modules and len(modules) < 1000:
                try:
                    got, _h = call(region, key, "GET", f"/modules/{module}", client=client)
                    modules[module] = got or {}
                except IASError as exc:
                    if exc.retry_at:
                        raise
                    modules[module] = {}
            pair = (module, attack)
            if (is_uuid(module) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", attack or "")
                    and pair not in docs and len(docs) < 1000):
                try:
                    got, _h = call(region, key, "GET",
                                   f"/modules/{module}/attacks/{attack}/documentation",
                                   client=client)
                    docs[pair] = got or {}
                except IASError as exc:
                    if exc.retry_at:
                        raise
                    docs[pair] = {}
    finally:
        if own:
            client.close()
    return [to_finding(v, modules, docs) for v in vulns]


# ------------------------------------------------------------------ history

def import_path() -> Path:
    """What the import has read so far: each finished Rapid7 scan and the hosts
    it touched, so a site added later picks up its old scans too."""
    return catalog_path().with_name("insightappsec-import.json")


def load_import() -> dict:
    try:
        got = json.loads(import_path().read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        got = {}
    got.setdefault("scans", {})
    got.setdefault("last", {})
    return got


def save_import(state: dict) -> None:
    path = import_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(path)


def when(value):
    """A Rapid7 time, which comes without a zone and is UTC.  None when absent."""
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        got = datetime.fromisoformat(text)
    except ValueError:
        return None
    return got if got.tzinfo else got.replace(tzinfo=timezone.utc)


def finished_scans(region: str, key: str, client=None) -> list:
    """Every scan that reached COMPLETE, newest first.  GET /scans takes no
    filter, so this reads them all and keeps the finished ones."""
    rows = []
    for s in paged(region, key, "GET", "/scans", client=client):
        if str(s.get("status") or "") != "COMPLETE" or not is_uuid(s.get("id")):
            continue
        rows.append({"id": s["id"],
                     "app_id": str((s.get("app") or {}).get("id") or ""),
                     "config_id": str((s.get("scan_config") or {}).get("id") or ""),
                     "submitted": str(s.get("submit_time") or ""),
                     "completed": str(s.get("completion_time") or s.get("submit_time") or "")})
    rows.sort(key=lambda r: r["completed"], reverse=True)
    return rows


def to_finding(v: dict, modules: dict = None, docs: dict = None) -> dict:
    """One InsightAppSec vulnerability in the shape every dynamic scan finding has.

    The title carries the parameter, because two findings of one kind on one
    address are only told apart by it, and a scan's findings are merged on
    title and address."""
    modules, docs = modules or {}, docs or {}
    cause = v.get("root_cause") or {}
    variance = ((v.get("variances") or [{}]) or [{}])[0] or {}
    module_id = str((variance.get("module") or {}).get("id") or "")
    attack_id = str((variance.get("attack") or {}).get("id") or "")
    module = modules.get(module_id) or {}
    doc = docs.get((module_id, attack_id)) or {}

    name = _plain(module.get("name"), 200) or attack_id or "InsightAppSec finding"
    param = str(cause.get("parameter") or "")[:120]
    title = f"{name} in parameter {param}" if param else name
    method = str(cause.get("method") or "").upper()[:10]
    url = str(cause.get("url") or "")[:1000]

    said = []
    for field in ("message", "proof_description", "proof"):
        if variance.get(field):
            said.append(_plain(variance[field], 300))
    if variance.get("attack_value"):
        said.append("Attack value: " + _plain(variance["attack_value"], 150))
    evidence = " ".join([f"{method} {url}".strip()] + said).strip()[:800]

    refs = json.dumps([doc.get("references"), variance.get("references")], default=str)
    cwe = _CWE.search(refs) or _CWE.search(str(doc.get("description") or ""))
    status_word = STATUS_NAMES.get(str(v.get("status") or ""), "")
    out = {
        "title": title[:300],
        "severity": SEVERITY.get(str(v.get("severity") or "").upper(), "info"),
        "url": url,
        "evidence": evidence,
        "remediation": _plain(doc.get("recommendation"), 1500),
        "cwe": f"CWE-{cwe.group(1)}" if cwe else "",
        "reference": str(v.get("insight_ui_url") or "")[:1000],
        "tool": PROVIDER,
        "validation": f"Rapid7: {status_word}" if status_word else "",
        "ias_id": str(v.get("id") or "")[:64],
        "ias_status": str(v.get("status") or "")[:32],
    }
    if v.get("vector_string"):
        out["cvss_vector"] = str(v["vector_string"])[:200]
    if v.get("vulnerability_score") is not None:
        try:
            out["cvss_score"] = round(float(v["vulnerability_score"]), 1)
        except (TypeError, ValueError):
            pass
    return out
