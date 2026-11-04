"""External sites: the pages, the form posts and the token API.

Every route here goes through the same two gates before it reads anything:
the person may manage external sites, which only administrators can, and the
module is switched on in Settings.  Switched off, every address here is a 404,
as if it did not exist.

Every lookup by id is checked against the id it hangs off.  A scan is looked
up by the site id and the scan id together, a link by the site and the
repository, so an id that belongs to some other site comes back as nothing.
Repositories and code findings are read through rbac for the person asking,
so a group that narrows what someone sees narrows it here too.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from app.core import external, rbac
from app.core import external_auth as external_auth_mod
from app.core import external_schedule
from app.core.models import ExternalScanSchedule
from app.core.audit import record
from app.core.db import session_scope
from app.core.models import utcnow as m_utcnow
from app.core.models import (
    DastServer, ExternalAsset, ExternalAssetRepo, ExternalAssetTag,
    ExternalDastScan, User,
)
from app.web.render import notice_class, page
from app.web.security import (
    check_csrf, clean_notice, clean_remote_url, clean_text, client_ip,
    current_user, redirect,
)

log = logging.getLogger("gcr.external")
router = APIRouter()
api = APIRouter(prefix="/external")

NOT_FOUND = "Not Found"


def _back(where: str, message: str, kind: str = "ok") -> str:
    from urllib.parse import quote

    return "%s%smsg=%s&kind=%s" % (where, "&" if "?" in where else "?",
                                   quote(message), kind)


def _guard(db, user) -> None:
    """Administrators only, and only while the module is on.

    Off answers 404 rather than 403, so the address says nothing about a
    feature that is not there.
    """
    if not rbac.can(user, "external.manage"):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    if not external.enabled(db):
        raise HTTPException(status_code=404, detail=NOT_FOUND)


def _asset(db, asset_id: int) -> ExternalAsset:
    asset = db.get(ExternalAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="No such site.")
    return asset


def _scan(db, asset_id: int, scan_id: int) -> ExternalDastScan:
    """A scan, only when it belongs to this site."""
    scan = (db.query(ExternalDastScan)
            .filter(ExternalDastScan.id == scan_id,
                    ExternalDastScan.asset_id == asset_id).one_or_none())
    if scan is None:
        raise HTTPException(status_code=404, detail="No such scan.")
    return scan


def _shared(db, user):
    from app.web.routes_pages import _shared as shared

    return shared(db, user)


def _checked(form, name: str) -> bool:
    return str(form.get(name) or "").lower() in ("1", "on", "true", "yes")


DETAIL_FIELDS = ("executive_owner", "technical_owner", "comments", "status",
                 "environment", "external_auth_needed", "whitelist_needed",
                 "change_frequency_days", "default_profile")


def _detail_form(form) -> dict:
    """The site details as a form sends them.  A tick box left unticked is
    not sent at all, so it is read as no rather than as not mentioned."""
    out = {key: form.get(key) for key in DETAIL_FIELDS}
    for key in ("external_auth_needed", "whitelist_needed"):
        out[key] = _checked(form, key)
    return out


@router.get("/external/repo-choices")
def repo_choices(user: User = Depends(current_user)):
    """Every repository the person may see, with its branches, for the picker."""
    with session_scope() as db:
        _guard(db, user)
        return JSONResponse(external.repo_choices(db, user),
                            headers={"Cache-Control": "private, no-store"})


@router.get("/external/repo-recommendations")
def repo_recommendations(hosts: str = "", application: str = "", tags: str = "",
                         asset: int = 0, user: User = Depends(current_user)):
    """The repositories likely behind some hosts, or behind one site."""
    with session_scope() as db:
        _guard(db, user)
        site = _asset(db, asset) if asset else None
        names = [h for h in hosts.replace(",", "\n").splitlines() if h.strip()][:50]
        found = external.recommend(
            db, user, names,
            clean_text(application, "Application", limit=200, required=False),
            [t for t in tags.split(",") if t.strip()][:30], asset=site)
        if site is None:
            db.expunge_all()
        return JSONResponse(found, headers={"Cache-Control": "private, no-store"})


# ------------------------------------------------------------------ list

# Rows a page of the list shows.  The first is the default: a page of sites
# is a page of screenshots, and fifty keep the first paint quick.
PAGE_SIZES = [50, 100, 200, 500, 1000]


@router.get("/external")
def list_page(request: Request, q: str = "", tag: str = "", app: str = "",
              grade: str = "", dast: str = "", risk: str = "", scope: str = "",
              env: str = "", status: str = "",
              page_no: str = Query("1", alias="page"), per_page: str = "",
              user: User = Depends(current_user)):
    """Every external site, newest problems first."""
    with session_scope() as db:
        _guard(db, user)
        q = clean_text(q, "Search", limit=200, required=False).lower()
        tag = clean_text(tag, "Tag", limit=100, required=False)
        app = clean_text(app, "Application", limit=200, required=False)
        opts = external.options(db)
        mapper = external.Mapper(db, user)
        envs = external.environments(db)
        assets = db.query(ExternalAsset).order_by(ExternalAsset.host).all()
        blocked = external.blocked_hosts(db)
        every_link = {a.id: mapper.links(a) for a in assets}
        scanning = external.running_scans(db)
        from app.core.models import ExternalScanSchedule
        from sqlalchemy import func as _f

        next_runs = dict(db.query(ExternalScanSchedule.asset_id, _f.min(ExternalScanSchedule.next_run_at))
                         .filter(ExternalScanSchedule.enabled.is_(True))
                         .group_by(ExternalScanSchedule.asset_id).all())
        names = {l["full_name"] for links in every_link.values() for l in links if l["linked"]}
        counts = external.sast_counts(db, names, user)
        rows = []
        for a in assets:
            links = every_link[a.id]
            linked = [l for l in links if l["linked"]]
            mine = {l["full_name"]: counts.get(l["full_name"], {}) for l in linked}
            row = {
                "a": a, "tags": a.tag_list(), "links": linked,
                "suggested": len(links) - len(linked),
                "sast": {s: sum((c or {}).get(s, 0) for c in mine.values())
                         for s in ("critical", "high", "medium", "low")},
                "risk": external.combined_risk(a, mine),
                "due": external.due_status(a, opts["max_age_days"]),
                "blocked": external.is_blocked(a.host, blocked, a.no_scan),
                "tele": external.telemetry_of(a),
                "scan": scanning.get(a.id),
                "next_run": next_runs.get(a.id),
                "has_shot": a.screenshot == "waf" and external.shot_path(a.id).is_file(),
            }
            if env and (a.environment or "") != env:
                continue
            if status and (a.status or "active") != status:
                continue
            if q and q not in " ".join([a.host, a.application or "", a.ip or "",
                                        a.executive_owner or "", a.technical_owner or "",
                                        " ".join(row["tags"]),
                                        " ".join(l["full_name"] for l in linked)]).lower():
                continue
            if tag and tag.casefold() not in {t.casefold() for t in row["tags"]}:
                continue
            if app and (a.application or "").casefold() != app.casefold():
                continue
            if grade and (a.grade or "") != grade:
                continue
            if dast and row["due"] != dast:
                continue
            if risk and row["risk"]["level"] != risk:
                continue
            if scope == "no-scan" and not row["blocked"]:
                continue
            if scope == "mapped" and not linked:
                continue
            if scope == "unmapped" and linked:
                continue
            rows.append(row)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        rows.sort(key=lambda r: (order.get(r["risk"]["level"], 9), r["a"].host))
        # One page of what matched.  A size off the list, or a page past the
        # end, falls back to the nearest one there is rather than an error.
        try:
            size = int(per_page or PAGE_SIZES[0])
        except ValueError:
            size = PAGE_SIZES[0]
        if size not in PAGE_SIZES:
            size = PAGE_SIZES[0]
        matched = len(rows)
        pages = max(1, -(-matched // size))
        try:
            page_no = min(max(1, int(page_no or 1)), pages)
        except ValueError:
            page_no = 1
        offset = (page_no - 1) * size
        rows = rows[offset:offset + size]
        from urllib.parse import urlencode

        filters = [(k, v) for k, v in (("q", q), ("tag", tag), ("app", app), ("grade", grade),
                                       ("dast", dast), ("risk", risk), ("scope", scope),
                                       ("env", env), ("status", status)) if v]
        paging = {"page": page_no, "pages": pages, "size": size, "sizes": PAGE_SIZES,
                  "offset": offset, "matched": matched,
                  # Filters, and the size when it is not the default, so
                  # every page link keeps both.
                  "query": urlencode(filters + ([("per_page", size)] if size != PAGE_SIZES[0] else [])),
                  "filters": urlencode(filters)}
        all_tags = sorted({t.tag for t in db.query(ExternalAssetTag.tag).distinct()},
                          key=str.casefold)
        apps = sorted({a.application for a in assets if a.application}, key=str.casefold)
        totals = {
            "sites": len(assets), "shown": matched,
            "domains": sum(1 for a in assets if a.kind == "domain"),
            "live": sum(1 for a in assets if a.category in ("live", "redir", "gated")),
            "never": sum(1 for a in assets if not a.last_dast_at and not a.no_scan
                         and a.status != "obsolete"),
            "obsolete": sum(1 for a in assets if a.status == "obsolete"),
            "due": sum(1 for a in assets if external.due_status(a, opts["max_age_days"]) == "due"),
            "dast_bad": sum(1 for a in assets if a.last_dast_severity in ("critical", "high")),
            "no_scan": sum(1 for a in assets if external.is_blocked(a.host, blocked, a.no_scan)),
            "mapped": sum(1 for a in assets if any(l["linked"] for l in every_link[a.id])),
        }
        servers = db.query(DastServer).order_by(DastServer.name).all()
        # Screenshots taken before thumbnails existed, or by a server
        # without Playwright, get theirs made in the background; until then
        # those rows load the full picture.
        external.backfill_thumbs([r["a"].id for r in rows])
        context = _shared(db, user)
        from app.core import dast_engines

        context.update(active_page="external", rows=rows, totals=totals,
                       profiles=dast_engines.PROFILES, default_profile=dast_engines.DEFAULT_PROFILE,
                       auth_kinds=external_auth_mod.KINDS,
                       q=q, tag=tag, app=app, grade=grade, dast=dast, risk=risk,
                       scope=scope, all_tags=all_tags, apps=apps, opts=opts, paging=paging,
                       env=env, status=status, environments=envs,
                       statuses=external.STATUSES,
                       servers=servers,
                       running=sum(1 for a in assets if a.telemetry_status == "running"),
                       scanning=len(scanning), max_concurrent=external._slots.limit(),
                       flash=clean_notice(request.query_params.get("msg", ""), limit=300),
                       flash_kind=notice_class(request.query_params.get("kind", "")))
        return page(request, "external.html", **context)


@router.get("/external.csv")
def export_csv(request: Request, user: User = Depends(current_user)):
    """Every site with its telemetry, last dynamic scan and repositories."""
    from app.core.reports import _quote_formula

    with session_scope() as db:
        _guard(db, user)
        mapper = external.Mapper(db, user)
        envs = external.environments(db)
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["host", "kind", "parent_domain", "application", "tags",
                         "environment", "status", "executive_owner", "technical_owner",
                         "external_auth_needed", "whitelist_needed",
                         "change_frequency_days", "no_scan", "no_scan_reason",
                         "telemetry_at", "last_dast_at", "last_dast_severity",
                         "last_dast_server", "last_dast_url", "repositories", "comments"]
                        + external.FIELD_KEYS)
        for a in db.query(ExternalAsset).order_by(ExternalAsset.host):
            values = external.field_values(a)
            repos = []
            for l in mapper.links(a):
                if l["linked"]:
                    repos += [f"{l['full_name']}@{b}" for b in l.get("branches") or []] \
                        or [l["full_name"]]
            writer.writerow([_quote_formula(str(c)) for c in [
                a.host, a.kind, a.parent_domain, a.application, "; ".join(a.tag_list()),
                envs.get(a.environment, a.environment or ""),
                external.STATUSES.get(a.status, a.status or ""),
                a.executive_owner or "", a.technical_owner or "",
                "yes" if a.external_auth_needed else "no",
                "yes" if a.whitelist_needed else "no",
                a.change_frequency_days or "",
                "yes" if a.no_scan else "", a.no_scan_reason or "",
                a.telemetry_at.strftime("%Y-%m-%d %H:%M") if a.telemetry_at else "",
                a.last_dast_at.strftime("%Y-%m-%d") if a.last_dast_at else "",
                a.last_dast_severity or "", a.last_dast_server or "",
                a.last_dast_url or "", " ".join(repos),
                (a.notes or "").replace("\n", " ")] + [values.get(k, "") for k in external.FIELD_KEYS]])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(content=out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="external-sites-{stamp}.csv"'})


@router.post("/external/add")
async def add(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    with session_scope() as db:
        _guard(db, user)
        text = str(form.get("hosts") or "")[:500_000]
        rows, problems = external.parse_lines(text)
        if not rows:
            return redirect(_back("/external", "No host names in that.  " + "; ".join(problems[:3]), "error"))
        application = clean_text(form.get("application"), "Application", limit=200, required=False)
        for row in rows:
            row["application"] = row["application"] or application
        tags = [t for t in str(form.get("tags") or "").replace(";", ",").split(",")]
        no_scan = _checked(form, "no_scan")
        reason = clean_text(form.get("no_scan_reason"), "Reason", limit=300, required=False)
        try:
            details = external.clean_details(_detail_form(form), envs=external.environments(db))
            picks = external.parse_picks(form.getlist("pick"))
            got = external.add_assets(db, rows, user.username, no_scan, reason, tags,
                                      details=details, picks=picks, user=user)
        except ValueError as exc:
            db.rollback()
            return redirect(_back("/external", str(exc), "error"))
        record(db, "external.added", actor=user.username,
               target=f"{len(got['added'])} sites",
               detail=", ".join(got["added"][:20])[:500], source_ip=client_ip(request))
        ids = [a.id for a in db.query(ExternalAsset.id).filter(ExternalAsset.host.in_(got["added"]))]
    if ids and _checked(form, "probe"):
        external.start_telemetry(ids)
    message = f"Added {len(got['added'])}"
    if got["existing"]:
        message += f", {len(got['existing'])} were already listed"
    if problems:
        message += f".  Skipped: {'; '.join(problems[:3])}"
    return redirect(_back("/external", message + "."))


@router.post("/external/import")
async def import_known(request: Request, user: User = Depends(current_user)):
    """Every company domain in Settings and every host in a repository's web
    addresses, added once each."""
    await check_csrf(request)
    from app.core import settings_store
    from app.core.external_probe import clean_host
    from app.core.models import Repository

    with session_scope() as db:
        _guard(db, user)
        hosts = []
        for value in settings_store.get(db, "web.company_domains") or []:
            hosts.append(clean_host(value))
        for repo in rbac.visible_repositories(db, user).filter(
                Repository.web_app_urls != "").all():
            for part in str(repo.web_app_urls or "").replace(",", " ").split():
                hosts.append(clean_host(part))
        rows = [{"host": h, "application": "", "tags": []}
                for h in dict.fromkeys(h for h in hosts if h)]
        got = external.add_assets(db, rows, user.username)
        record(db, "external.imported", actor=user.username,
               target=f"{len(got['added'])} sites", source_ip=client_ip(request))
    return redirect(_back("/external", f"Added {len(got['added'])} from the company "
                                       f"domains and repository web addresses."))


@router.post("/external/refresh")
async def refresh_many(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    with session_scope() as db:
        _guard(db, user)
        if _checked(form, "all"):
            ids = [a.id for a in db.query(ExternalAsset.id)]
        else:
            ids = []
            for raw in form.getlist("id"):
                try:
                    ids.append(int(raw))
                except (TypeError, ValueError):
                    continue
    queued = external.start_telemetry(ids)
    return redirect(_back("/external", f"Reading telemetry for {queued} site{'s' if queued != 1 else ''}."))


def _ticked(form) -> list:
    ids = []
    for raw in form.getlist("id"):
        try:
            ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    return list(dict.fromkeys(ids))[:500]


def _bulk_changes(form) -> dict:
    """What the bulk edit dialog asks to change: only the ticked fields."""
    def on(name):
        return _checked(form, f"apply_{name}")

    changes, details = {}, {}
    for key in external.BULK_FIELDS:
        if on(key):
            value = form.get(key)
            if key in ("external_auth_needed", "whitelist_needed"):
                value = str(value or "").lower() in ("1", "yes", "true", "on")
            details[key] = value if value is not None else ""
    if details:
        changes["details"] = details
    if on("tags"):
        changes["tags"] = (str(form.get("tags_mode") or "add"),
                           str(form.get("tags") or "").replace(";", ",").split(","))
    if on("comments"):
        changes["comments"] = (str(form.get("comments_mode") or "replace"),
                               clean_text(form.get("comments"), "Comments", limit=4000, required=False))
    if on("no_scan"):
        changes["no_scan"] = (str(form.get("no_scan") or "").lower() in ("1", "yes"),
                              clean_text(form.get("no_scan_reason"), "Reason", limit=300, required=False))
    if on("proxy"):
        changes["proxy"] = "" if form.get("proxy_mode") == "clear" else str(form.get("proxy") or "")
        if changes["proxy"] == "" and form.get("proxy_mode") != "clear":
            raise ValueError("Give the proxy address, or choose to remove it.")
    if on("auth"):
        changes["auth"] = (str(form.get("auth_kind") or ""), {
            key: form.get(f"auth_{key}") or "" for key in (
                "header_name", "header_value", "cookie", "login_url", "username",
                "password", "username_field", "password_field")})
    if on("repositories"):
        changes["repositories"] = (str(form.get("repositories_mode") or "add"),
                                   external.parse_picks(form.getlist("pick")))
    return changes


@router.post("/external/bulk-edit")
async def bulk_edit(request: Request, user: User = Depends(current_user)):
    """Change the same things on every ticked site, all or nothing."""
    await check_csrf(request)
    form = await request.form()
    with session_scope() as db:
        _guard(db, user)
        ids = _ticked(form)
        if not ids:
            return redirect(_back("/external", "Tick the sites to change first.", "error"))
        try:
            changes = _bulk_changes(form)
            if not changes:
                return redirect(_back("/external", "Tick Change beside what to change.", "error"))
            assets = db.query(ExternalAsset).filter(ExternalAsset.id.in_(ids)).all()
            changed = external.bulk_update(db, assets, changes, user.username, user)
        except ValueError as exc:
            db.rollback()
            return redirect(_back("/external", f"Nothing was changed.  {exc}", "error"))
        record(db, "external.bulk_edit", actor=user.username, target=f"{len(changed)} sites",
               detail=(", ".join(sorted(changes)) + ": " + ", ".join(changed))[:500],
               source_ip=client_ip(request))
    return redirect(_back("/external", f"Changed {len(changed)} site{'s' if len(changed) != 1 else ''}."))


@router.post("/external/delete-many")
async def delete_many(request: Request, user: User = Depends(current_user)):
    """Remove the ticked sites and their scan history.  One with a scan
    running is left alone and said so."""
    await check_csrf(request)
    form = await request.form()
    removed, kept = [], []
    with session_scope() as db:
        _guard(db, user)
        ids = _ticked(form)
        if not ids:
            return redirect(_back("/external", "Tick the sites to remove first.", "error"))
        busy = {s.asset_id for s in db.query(ExternalDastScan).filter(
            ExternalDastScan.asset_id.in_(ids),
            ExternalDastScan.status.in_(("queued", "running")))}
        for asset in db.query(ExternalAsset).filter(ExternalAsset.id.in_(ids)).all():
            if asset.id in busy:
                kept.append(asset.host)
                continue
            removed.append((asset.id, asset.host))
            db.delete(asset)
        record(db, "external.deleted", actor=user.username,
               target=f"{len(removed)} sites",
               detail=", ".join(h for _i, h in removed)[:500], source_ip=client_ip(request))
    for asset_id, _host in removed:
        external.drop_shot(asset_id)
    message = f"Removed {len(removed)} site{'s' if len(removed) != 1 else ''}."
    if kept:
        message += f"  Left {', '.join(kept[:5])}: a scan is running."
    return redirect(_back("/external", message, "error" if kept and not removed else "ok"))


@router.post("/external/scan-many")
async def scan_many(request: Request, user: User = Depends(current_user)):
    """Start the same scan on every ticked site.  They queue and run one at a
    time.  Sites marked no scan, or already scanning, are skipped and named."""
    await check_csrf(request)
    from app.core import dast_engines

    form = await request.form()
    profile = str(form.get("profile") or "default")
    with session_scope() as db:
        _guard(db, user)
        ids = _ticked(form)[:50]
        each = {a.id: external.profile_for(a) for a in
                db.query(ExternalAsset).filter(ExternalAsset.id.in_(ids or [0]))}
        if not ids:
            return redirect(_back("/external", "Tick the sites to scan first.", "error"))
        if profile != "default" and profile not in dast_engines.PROFILES:
            return redirect(_back("/external", "Pick a scan profile.", "error"))
        chosen = {i: (each.get(i, dast_engines.DEFAULT_PROFILE) if profile == "default" else profile)
                  for i in ids}
        signs_in = db.query(ExternalAsset).filter(
            ExternalAsset.id.in_([i for i, p in chosen.items() if p != "baseline"] or [0]),
            ExternalAsset.auth_kind != "").count()
        active = any(p in dast_engines.ACTIVE_PROFILES for p in chosen.values())
        if (active or signs_in) and not _checked(form, "confirm"):
            return redirect(_back("/external", "Tick the box to confirm you are allowed to "
                                               "scan these sites this way.", "error"))
    started, skipped = 0, []
    for asset_id in ids:
        scan_id, problem = external.start_scan(asset_id, chosen[asset_id], user.username,
                                               ai_triage=_checked(form, "ai"))
        if scan_id:
            started += 1
        else:
            skipped.append(problem)
    with session_scope() as db:
        record(db, "external.scan_started", actor=user.username,
               target=f"{started} sites", detail=f"{profile}, {len(skipped)} skipped",
               source_ip=client_ip(request))
    label = "each site's default" if profile == "default" else f"a {profile}"
    message = f"Started {label} scan of {started} site{'s' if started != 1 else ''}.  They run one at a time."
    if skipped:
        message += "  Skipped: " + "; ".join(skipped[:3])
    return redirect(_back("/external", message, "ok" if started else "error"))


# ------------------------------------------------------------------ one site

SCANS_PER_PAGE = 5


def _safe_back(raw, asset_id: int, fallback: str) -> str:
    """Where a button on one of our pages asked to go back to: the list, or
    this site's page, with at most a page number of its scans.  Anything else
    is ignored, so the field cannot send anybody off the site."""
    import re as _re

    text = str(raw or "")
    if text == "/external" or _re.fullmatch(rf"/external/{int(asset_id)}(\?scans=\d{{1,5}})?", text):
        return text
    return fallback


@router.get("/external/{asset_id}")
def detail_page(asset_id: int, request: Request, scans: int = 1,
                user: User = Depends(current_user)):
    from app.core import ai, dast_engines

    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        opts = external.options(db)
        links = external.Mapper(db, user).links(asset)
        names = [l["full_name"] for l in links]
        counts = external.sast_counts(db, names, user)
        # Newest first, a page at a time.  Started, then finished, time
        # order and id order agree, so the id is the cheap way to sort.
        scan_query = db.query(ExternalDastScan).filter(ExternalDastScan.asset_id == asset.id)
        scan_total = scan_query.count()
        scan_pages = max(1, -(-scan_total // SCANS_PER_PAGE))
        scan_page = min(max(1, scans), scan_pages)
        page_scans = (scan_query.order_by(ExternalDastScan.id.desc())
                      .offset((scan_page - 1) * SCANS_PER_PAGE).limit(SCANS_PER_PAGE).all())
        running = external.running_scans(db, [asset.id])
        linked = {l["full_name"]: counts.get(l["full_name"], {}) for l in links if l["linked"]}
        try:
            review = json.loads(asset.ai_review or "{}") if asset.ai_review else {}
        except ValueError:
            review = {}
        active_scan = running.get(asset.id)
        busy = (asset.telemetry_status == "running" or asset.ai_status == "running"
                or active_scan is not None
                or any(s.ai_status == "running" for s in page_scans))
        context = _shared(db, user)
        context.update(
            active_page="external", asset=asset, tele=external.telemetry_of(asset),
            tags=asset.tag_list(), links=links, counts=counts,
            risk=external.combined_risk(asset, linked),
            due=external.due_status(asset, opts["max_age_days"]),
            blocked=external.blocked(db, asset), scans=page_scans, active_scan=active_scan,
            scan_page=scan_page, scan_pages=scan_pages, scan_total=scan_total,
            fields=external.fields_of(asset), security_headers=external.SECURITY_HEADERS,
            auth=external_auth_mod.describe(asset), auth_kinds=external_auth_mod.KINDS,
            site_profile=external.profile_for(asset), proxy_label=external.proxy_shown(asset),
            has_shot=external.shot_path(asset.id).is_file(),
            schedules=[external_schedule.as_dict(x) for x in db.query(ExternalScanSchedule)
                       .filter_by(asset_id=asset.id).order_by(ExternalScanSchedule.id)],
            frequencies=external_schedule.FREQUENCIES, weekdays=external_schedule.WEEKDAYS,
            zone_name=str(external_schedule.zone()),
            picks_json=json.dumps(external.picks_of(db, asset)),
            environments=external.environments(db), statuses=external.STATUSES,
            scan_views=[external.scan_dict(s) for s in page_scans],
            servers=db.query(DastServer).order_by(DastServer.name).all(),
            profiles=dast_engines.PROFILES, active=dast_engines.ACTIVE_PROFILES,
            plans=dast_engines.PLANS, engines=dast_engines.installed(),
            engine_names=dast_engines.ENGINE_NAMES,
            ai_ready=not ai.missing(ai.config(db)), review=review, busy=busy,
            port_names=__import__("app.core.external_probe", fromlist=["x"]).PORT_NAMES,
            categories=__import__("app.core.external_probe", fromlist=["x"]).CATEGORY_NAMES,
            today=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            flash=clean_notice(request.query_params.get("msg", ""), limit=300),
            flash_kind=notice_class(request.query_params.get("kind", "")))
        return page(request, "external_site.html", **context)


@router.get("/external/{asset_id}/screenshot.png")
def screenshot(asset_id: int, user: User = Depends(current_user)):
    with session_scope() as db:
        _guard(db, user)
        _asset(db, asset_id)
    path = external.shot_path(asset_id)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No screenshot.")
    return FileResponse(path, media_type="image/png",
                        headers={"Cache-Control": "private, max-age=300"})


@router.get("/external/{asset_id}/thumb.jpg")
def screenshot_thumb(asset_id: int, v: str = "", user: User = Depends(current_user)):
    """The list's small picture.  The list adds ?v= from when telemetry was
    read, so a new screenshot is a new address and the browser may keep
    this one for a day.  Without a thumbnail yet it answers with the full
    screenshot, kept only briefly so the small one replaces it soon."""
    with session_scope() as db:
        _guard(db, user)
        _asset(db, asset_id)
    if external.thumb_fresh(asset_id):
        return FileResponse(external.thumb_path(asset_id), media_type="image/jpeg",
                            headers={"Cache-Control": "private, max-age=86400"})
    path = external.shot_path(asset_id)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No screenshot.")
    return FileResponse(path, media_type="image/png",
                        headers={"Cache-Control": "private, max-age=60"})


@router.post("/external/{asset_id}/edit")
async def edit(asset_id: int, request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    here = f"/external/{asset_id}"
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        before = asset.no_scan
        asset.application = clean_text(form.get("application"), "Application",
                                       limit=200, required=False)
        try:
            external.apply_details(asset, external.clean_details(
                _detail_form(form), envs=external.environments(db), keep_env=asset.environment))
            if form.get("with_picks"):
                external.set_picks(db, asset, external.parse_picks(form.getlist("pick")),
                                   user.username, user)
            if form.get("with_fields"):
                external.set_manual(asset, {key: form.get(f"f:{key}") or ""
                                            for key in external.FIELD_KEYS}, replace=True)
            if form.get("with_proxy"):
                before_proxy = external.proxy_shown(asset)
                if _checked(form, "proxy_clear"):
                    external.set_proxy(asset, "")
                elif form.get("proxy"):
                    external.set_proxy(asset, form.get("proxy"))
                if external.proxy_shown(asset) != before_proxy or form.get("proxy"):
                    record(db, "external.proxy_set", actor=user.username, target=asset.host,
                           detail=(external.proxy_shown(asset) or "removed")[:200],
                           source_ip=client_ip(request))
            if form.get("with_auth"):
                from app.core import external_auth

                before_kind = asset.auth_kind or ""
                external_auth.save(asset, form.get("auth_kind") or "", {
                    key: form.get(f"auth_{key}") or "" for key in (
                        "header_name", "header_value", "cookie", "login_url",
                        "username", "password", "username_field", "password_field")},
                    user.username, asset.parent_domain)
                if (asset.auth_kind or "") != before_kind or any(
                        form.get(f"auth_{k}") for k in ("header_value", "cookie", "password")):
                    record(db, "external.auth_set", actor=user.username, target=asset.host,
                           detail=external_auth.KINDS.get(asset.auth_kind, "")[:100],
                           source_ip=client_ip(request))
        except ValueError as exc:
            db.rollback()
            return redirect(_back(here, str(exc), "error"))
        asset.no_scan = _checked(form, "no_scan")
        asset.no_scan_reason = clean_text(form.get("no_scan_reason"), "Reason",
                                          limit=300, required=False) if asset.no_scan else ""
        external.set_tags(asset, str(form.get("tags") or "").replace(";", ",").split(","))
        record(db, "external.edited", actor=user.username, target=asset.host,
               detail=("marked no scan" if asset.no_scan and not before else
                       "no scan removed" if before and not asset.no_scan else "")[:200],
               source_ip=client_ip(request))
    return redirect(_back(here, "Saved."))


@router.post("/external/{asset_id}/delete")
async def delete(asset_id: int, request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        if db.query(ExternalDastScan).filter(
                ExternalDastScan.asset_id == asset.id,
                ExternalDastScan.status.in_(("queued", "running"))).first():
            return redirect(_back(f"/external/{asset_id}",
                                  "Stop the running scan first.", "error"))
        host = asset.host
        record(db, "external.deleted", actor=user.username, target=host,
               source_ip=client_ip(request))
        db.delete(asset)
    external.drop_shot(asset_id)
    return redirect(_back("/external", f"Removed {host} and its scan history."))


@router.post("/external/{asset_id}/refresh")
async def refresh_one(asset_id: int, request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    with session_scope() as db:
        _guard(db, user)
        _asset(db, asset_id)
    external.start_telemetry([asset_id])
    return redirect(_back(f"/external/{asset_id}", "Reading its telemetry.  This page "
                                                   "refreshes until it is done."))


@router.post("/external/{asset_id}/repos")
async def link_repo(asset_id: int, request: Request, user: User = Depends(current_user)):
    """Link a repository by name, or confirm, hide or forget a found one."""
    await check_csrf(request)
    from app.core.models import Repository

    form = await request.form()
    here = f"/external/{asset_id}"
    action = str(form.get("action") or "link")
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        name = clean_text(form.get("repository"), "Repository", limit=320)
        # Through rbac, so a name the person cannot see is the same as a
        # name that does not exist.
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.full_name == name).one_or_none())
        if repo is None:
            return redirect(_back(here, f"No repository called {name}.", "error"))
        row = (db.query(ExternalAssetRepo)
               .filter(ExternalAssetRepo.asset_id == asset.id,
                       ExternalAssetRepo.repository_id == repo.id).one_or_none())
        if action == "forget":
            if row is not None:
                db.delete(row)
            message = f"{repo.full_name} is back to being worked out."
        else:
            if row is None:
                row = ExternalAssetRepo(asset_id=asset.id, repository_id=repo.id)
                db.add(row)
            row.source = "hidden" if action == "hide" else "manual"
            row.added_by = user.username[:120]
            message = (f"{repo.full_name} will not be linked to {asset.host}."
                       if action == "hide" else f"Linked {repo.full_name}.")
        record(db, f"external.repo_{action}", actor=user.username,
               target=asset.host, detail=repo.full_name, source_ip=client_ip(request))
    return redirect(_back(here, message))


@router.post("/external/{asset_id}/scan")
async def start_scan(asset_id: int, request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    from app.core import dast_engines

    form = await request.form()
    here = f"/external/{asset_id}"
    profile = str(form.get("profile") or "")
    server_id = None
    target = str(form.get("server") or "builtin")
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        profile = profile or external.profile_for(asset)
        if target != "builtin":
            try:
                server_id = int(target)
            except ValueError:
                raise HTTPException(status_code=400, detail="Pick a server.")
        sign_in = bool(asset.auth_kind) and _checked(form, "authenticated")
        if (server_id or profile in dast_engines.ACTIVE_PROFILES
                or (sign_in and profile != "baseline")) and not _checked(form, "confirm"):
            return redirect(_back(here, "Tick the box to confirm you are allowed to scan this "
                                        "site this way.  A signed in scan acts as that user.", "error"))
        host = asset.host
    scan_id, problem = external.start_scan(asset_id, profile, user.username,
                                           ai_triage=_checked(form, "ai"),
                                           server_id=server_id, authenticated=sign_in)
    with session_scope() as db:
        record(db, "external.scan_started" if scan_id else "external.scan_refused",
               actor=user.username, target=host,
               detail=(f"{profile} on " + ("this server" if not server_id else f"server {server_id}")
                       + (f": {problem}" if problem else ""))[:300],
               source_ip=client_ip(request), outcome="ok" if scan_id else "refused")
    if problem:
        return redirect(_back(here, problem, "error"))
    return redirect(_back(f"{here}/scans/{scan_id}", "Scan started.  This page refreshes "
                                                     "while it runs."))


@router.post("/external/{asset_id}/scans/record")
async def record_scan(asset_id: int, request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    here = f"/external/{asset_id}"
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        data = {"server": clean_text(form.get("server"), "Server", limit=120),
                "scanned_at": str(form.get("scanned_at") or ""),
                "result_url": clean_text(form.get("result_url"), "Result", limit=1000,
                                         required=False),
                "severity": str(form.get("severity") or ""),
                "note": clean_text(form.get("note"), "Note", limit=4000, required=False),
                "counts": {s: form.get(s) or 0 for s in external.SEVERITIES}}
        try:
            scan = external.record_scan(db, asset, data, user.username)
        except ValueError as exc:
            return redirect(_back(here, str(exc), "error"))
        record(db, "external.scan_recorded", actor=user.username, target=asset.host,
               detail=f"{scan.server_name}, {scan.severity}", source_ip=client_ip(request))
    return redirect(_back(here, "Recorded the scan."))


def _report(db, asset, scan, user):
    """-> (pdf bytes, file name) for a scan this server ran."""
    import base64

    from app.core import dast_report, settings_store
    from app.web.render import render_partial

    if not dast_report.available(scan):
        raise HTTPException(status_code=404, detail=(
            "Reports are made for finished scans this server ran.  A DAST "
            "server's scan has its own report on that server."))
    organization = settings_store.get(db, "report.organization_name", "") or ""
    context = dast_report.build(db, asset, scan, user, organization)
    shot = external.shot_path(asset.id)
    if asset.screenshot in ("ok", "blank", "waf") and shot.is_file() and shot.stat().st_size < 4_000_000:
        context["screenshot"] = "data:image/png;base64," + base64.b64encode(
            shot.read_bytes()).decode()
    logo = (settings_store.get(db, "report.logo", "") or "").strip()
    context.update(title=f"Dynamic Scan Report: {asset.host}", logo=logo,
                   footer_text=settings_store.get(db, "report.footer", "") or "",
                   issued_at=datetime.now(timezone.utc).strftime("%B %d, %Y").replace(" 0", " "))
    html = render_partial("dast_report_pdf.html", **context)
    try:
        pdf = dast_report.render_pdf(html, logo, organization)
    except ImportError:
        raise HTTPException(status_code=503, detail=(
            "Reports need the typesetting libraries, which are not installed on this server."))
    return pdf, dast_report.filename(asset, scan)


KEY_RE = __import__("re").compile(r"^[0-9a-f]{32}$")


def _decision_from(data: dict) -> dict:
    persist = data.get("persist")
    if isinstance(persist, str):
        persist = persist.lower() in ("1", "on", "true", "yes")
    return {"kind": str(data.get("kind") or ""), "reason": str(data.get("reason") or ""),
            "severity": str(data.get("severity") or ""), "expires": str(data.get("expires") or ""),
            "persist": True if persist is None else bool(persist)}


@router.post("/external/{asset_id}/scans/{scan_id}/findings/{key}/{action}")
async def finding_decision(asset_id: int, scan_id: int, key: str, action: str,
                           request: Request, user: User = Depends(current_user)):
    """Call a finding a false positive, give it another severity, or make an
    exception for it, or take that back."""
    await check_csrf(request)
    from app.core import external_decisions

    form = await request.form()
    if key == "form":
        # The dialog is shared by every finding, so it sends the key itself.
        key = str(form.get("key") or "")
    if not KEY_RE.fullmatch(key) or action not in ("decide", "undo"):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    here = f"/external/{asset_id}/scans/{scan_id}"
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        if action == "undo":
            if not external_decisions.undo(db, asset, key, scan.id):
                return redirect(_back(here, "There was no decision on it.", "error"))
            record(db, "external.finding_undecided", actor=user.username, target=asset.host,
                   detail=f"finding {key[:12]}", source_ip=client_ip(request))
            return redirect(_back(here, "Taken back.  It counts as found again."))
        d = _decision_from(form)
        if form.get("with_persist"):
            d["persist"] = _checked(form, "persist")
        try:
            row = external_decisions.decide(db, asset, scan, key, d["kind"], d["reason"],
                                            user.username, d["severity"], d["expires"], persist=d["persist"])
        except ValueError as exc:
            db.rollback()
            return redirect(_back(here, str(exc), "error"))
        record(db, "external.finding_decided", actor=user.username, target=asset.host,
               detail=f"{row.kind}{' ' + row.severity if row.severity else ''}: {row.title}"[:300],
               source_ip=client_ip(request))
        word = external_decisions.KINDS[row.kind].lower()
        where = (f"on {asset.host} in every scan, new ones too" if not row.only_scan_id
                 else "in this scan only")
    return redirect(_back(here, f"Recorded: {word}, {where}."))


@router.get("/external/{asset_id}/scans/{scan_id}/report.pdf")
def scan_report(asset_id: int, scan_id: int, request: Request,
                user: User = Depends(current_user)):
    """The PDF report on one scan this server ran, typeset now."""
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        pdf, name = _report(db, asset, scan, user)
        record(db, "external.report", actor=user.username, target=asset.host,
               detail=f"scan {scan_id}", source_ip=client_ip(request))
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# Before the page below, or "5.json" is read as a scan id and refused.
@router.get("/external/{asset_id}/scans/{scan_id}.json")
def scan_json(asset_id: int, scan_id: int, user: User = Depends(current_user)):
    with session_scope() as db:
        _guard(db, user)
        _asset(db, asset_id)
        body = external.scan_dict(_scan(db, asset_id, scan_id), findings=True)
    return JSONResponse(body, headers={"Content-Disposition":
                                       f'attachment; filename="dast-scan-{scan_id}.json"'})


@router.get("/external/{asset_id}/scans/{scan_id}")
def scan_page(asset_id: int, scan_id: int, request: Request, sev: str = "",
              verdict: str = "", user: User = Depends(current_user)):
    from app.core import ai

    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        from app.core import external_decisions

        view = external.scan_dict(scan, findings=True)
        # Decisions made since the scan, applied as the page is drawn.
        view["findings"] = external_decisions.apply(view["findings"],
                                                    external_decisions.for_asset(db, asset.id),
                                                    scan_id=scan.id)
        findings = view["findings"]
        decided = sum(1 for f in findings if f.get("decision"))
        if sev:
            findings = [f for f in findings if f.get("severity") == sev]
        if verdict and verdict != "decided":
            findings = [f for f in findings if f.get("ai_verdict", "") == verdict]
        context = _shared(db, user)
        if verdict == "decided":
            findings = [f for f in findings if f.get("decision")]
        context.update(active_page="external", asset=asset, scan=scan, view=view,
                       findings=findings, sev=sev, verdict=verdict, decided=decided,
                       decision_kinds=external_decisions.KINDS,
                       severities=external_decisions.SEVERITIES,
                       today=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                       max_day=(datetime.now(timezone.utc) + __import__("datetime").timedelta(
                           days=external_decisions.MAX_EXCEPTION_DAYS)).strftime("%Y-%m-%d"),
                       ai_ready=not ai.missing(ai.config(db)),
                       busy=scan.status in ("queued", "running") or scan.ai_status == "running",
                       flash=clean_notice(request.query_params.get("msg", ""), limit=300),
                       flash_kind=notice_class(request.query_params.get("kind", "")))
        return page(request, "external_scan.html", **context)


@router.post("/external/{asset_id}/scans/{scan_id}/{action}")
async def scan_action(asset_id: int, scan_id: int, action: str, request: Request,
                      user: User = Depends(current_user)):
    await check_csrf(request)
    here = f"/external/{asset_id}/scans/{scan_id}"
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        host = asset.host
        if action == "delete":
            form = await request.form()
            back = _safe_back(form.get("back"), asset_id, f"/external/{asset_id}")
            if scan.status in ("queued", "running"):
                return redirect(_back(back if back != f"/external/{asset_id}" else here,
                                      "Stop it first.", "error"))
            db.delete(scan)
            db.flush()
            external.copy_newest(db, asset)
            record(db, "external.scan_deleted", actor=user.username, target=host,
                   detail=f"scan {scan_id}", source_ip=client_ip(request))
            return redirect(_back(back, "Removed that scan."))
    if action == "stop":
        ok = external.stop_scan(scan_id)
        message, kind = ("Stopping the scan of " + host + ".", "ok") if ok \
            else ("It is not running.", "error")
        form = await request.form()
        # Back to where the Stop was pressed, and only to a page of ours.
        here = _safe_back(form.get("back"), asset_id, here)
    elif action == "triage":
        problem = external.start_triage(scan_id, user.username)
        message, kind = (problem, "error") if problem else ("Asking the model.  This page "
                                                            "refreshes until it answers.", "ok")
    else:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    with session_scope() as db:
        record(db, f"external.scan_{action}", actor=user.username, target=host,
               detail=f"scan {scan_id}", source_ip=client_ip(request))
    return redirect(_back(here, message, kind))


@router.post("/external/{asset_id}/schedules")
async def add_schedule(asset_id: int, request: Request, user: User = Depends(current_user)):
    """Scan this site on a schedule."""
    await check_csrf(request)
    from app.core import dast_engines

    form = await request.form()
    here = f"/external/{asset_id}"
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        if external.blocked(db, asset):
            return redirect(_back(here, "This site may not be scanned, so it cannot have a schedule.", "error"))
        profile = str(form.get("profile") or "") or external.profile_for(asset)
        signs_in = _checked(form, "authenticated")
        if (profile in dast_engines.ACTIVE_PROFILES or (signs_in and profile != "baseline")) \
                and not _checked(form, "confirm"):
            return redirect(_back(here, "Tick the box to confirm you are allowed to scan this "
                                        "site this way, every time the schedule runs.", "error"))
        try:
            sched = external_schedule.create(db, asset, {
                "frequency": form.get("frequency"), "time_of_day": form.get("time_of_day"),
                "run_on": form.get("run_on"), "weekday": form.get("weekday"),
                "day_of_month": form.get("day_of_month"), "profile": profile,
                "authenticated": signs_in, "ai_triage": _checked(form, "ai")}, user.username)
        except ValueError as exc:
            db.rollback()
            return redirect(_back(here, str(exc), "error"))
        record(db, "external.schedule_added", actor=user.username, target=asset.host,
               detail=f"{external_schedule.describe(sched)}, {profile}"[:300],
               source_ip=client_ip(request))
        when = sched.next_run_at
    return redirect(_back(here, f"Scheduled.  The first run is {when:%Y-%m-%d %H:%M} UTC."))


@router.post("/external/{asset_id}/schedules/{schedule_id}/{action}")
async def schedule_action(asset_id: int, schedule_id: int, action: str, request: Request,
                          user: User = Depends(current_user)):
    await check_csrf(request)
    here = f"/external/{asset_id}"
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        sched = (db.query(ExternalScanSchedule)
                 .filter_by(id=schedule_id, asset_id=asset_id).one_or_none())
        if sched is None:
            raise HTTPException(status_code=404, detail="No such schedule.")
        if action == "delete":
            db.delete(sched)
            message = "Removed the schedule."
        elif action in ("pause", "resume"):
            sched.enabled = action == "resume"
            sched.next_run_at = external_schedule.next_run(sched, m_utcnow()) if sched.enabled else None
            if sched.enabled and sched.next_run_at is None:
                sched.enabled = False
                return redirect(_back(here, "Its time has passed, so it cannot be resumed.", "error"))
            message = "Resumed the schedule." if sched.enabled else "Paused the schedule."
        else:
            raise HTTPException(status_code=404, detail=NOT_FOUND)
        record(db, f"external.schedule_{action}", actor=user.username, target=asset.host,
               detail=f"schedule {schedule_id}", source_ip=client_ip(request))
    return redirect(_back(here, message))


@router.post("/external/{asset_id}/ai")
async def risk_read(asset_id: int, request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    with session_scope() as db:
        _guard(db, user)
        host = _asset(db, asset_id).host
    problem = external.start_risk_read(asset_id, user.username)
    with session_scope() as db:
        record(db, "external.risk_read", actor=user.username, target=host,
               outcome="refused" if problem else "ok", detail=problem[:200],
               source_ip=client_ip(request))
    return redirect(_back(f"/external/{asset_id}", problem or "Asking the model.  This "
                          "page refreshes until it answers.", "error" if problem else "ok"))


# ------------------------------------------------------------------ servers

@router.get("/external-servers")
def servers_page(request: Request, user: User = Depends(current_user)):
    from app.core import dast_engines

    with session_scope() as db:
        _guard(db, user)
        servers = db.query(DastServer).order_by(DastServer.name).all()
        used = dict(db.query(ExternalDastScan.server_name,
                             __import__("sqlalchemy").func.count(ExternalDastScan.id))
                    .group_by(ExternalDastScan.server_name).all())
        context = _shared(db, user)
        context.update(active_page="external", servers=servers, used=used,
                       kinds=external.SERVER_KINDS, engines=dast_engines.installed(),
                       engine_names=dast_engines.ENGINE_NAMES,
                       builtin=external.BUILTIN_SERVER,
                       flash=clean_notice(request.query_params.get("msg", ""), limit=300),
                       flash_kind=notice_class(request.query_params.get("kind", "")))
        return page(request, "external_servers.html", **context)


@router.post("/external-servers")
async def save_server(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    back = "/external-servers"
    with session_scope() as db:
        _guard(db, user)
        server_id = form.get("id")
        if server_id:
            try:
                server = db.get(DastServer, int(server_id))
            except ValueError:
                server = None
            if server is None:
                raise HTTPException(status_code=404, detail="No such server.")
        else:
            server = DastServer(created_by=user.username[:120])
        name = clean_text(form.get("name"), "Name", limit=120)
        if name.casefold() == external.BUILTIN_SERVER.casefold():
            return redirect(_back(back, "That name is this product's own scanner.", "error"))
        clash = db.query(DastServer).filter(DastServer.name == name,
                                            DastServer.id != (server.id or 0)).first()
        if clash:
            return redirect(_back(back, f"There is already a server called {name}.", "error"))
        kind = str(form.get("kind") or "other")
        if kind not in external.SERVER_KINDS:
            kind = "other"
        server.name, server.kind = name, kind
        server.base_url = clean_remote_url(form.get("base_url"), "Address",
                                           required=kind == "nextgen-dast")
        profile = str(form.get("profile") or "quick")
        server.profile = profile if profile in ("quick", "standard", "thorough", "premium") else "quick"
        server.notes = clean_text(form.get("notes"), "Notes", limit=2000, required=False)
        token = str(form.get("token") or "").strip()
        if token:
            external.set_server_token(server, token[:500])
        if kind == "nextgen-dast" and not server.token:
            return redirect(_back(back, "A nextgen-dast server needs an API token.", "error"))
        if server.id is None:
            db.add(server)
        record(db, "external.server_saved", actor=user.username, target=name,
               detail=kind, source_ip=client_ip(request))
    return redirect(_back(back, f"Saved {name}."))


@router.post("/external-servers/{server_id}/{action}")
async def server_action(server_id: int, action: str, request: Request,
                        user: User = Depends(current_user)):
    await check_csrf(request)
    back = "/external-servers"
    with session_scope() as db:
        _guard(db, user)
        server = db.get(DastServer, server_id)
        if server is None:
            raise HTTPException(status_code=404, detail="No such server.")
        name = server.name
        if action == "delete":
            db.delete(server)
            record(db, "external.server_deleted", actor=user.username, target=name,
                   source_ip=client_ip(request))
            return redirect(_back(back, f"Removed {name}.  Scans it ran keep its name."))
        if action != "test":
            raise HTTPException(status_code=404, detail=NOT_FOUND)
    ok, message = external.test_server(server_id)
    return redirect(_back(back, f"{name}: {message}", "ok" if ok else "error"))


# ------------------------------------------------------------------ token API
#
# Mounted under /api/v1 by routes_api_v1, so it shares that router's token
# handling and shows up in the API reference test.

def _api_caller():
    from app.web.routes_api_v1 import caller_for

    return caller_for("external")


def _api_me(db, caller):
    """The token's owner, loaded here, and both gates checked again."""
    from app.web.routes_api_v1 import _me

    me = _me(db, caller)
    _guard(db, me)
    return me


async def _body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Send JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Send an object.")
    return body


def _view(db, asset, me, request: Request):
    from app.web.security import public_base

    mapper = external.Mapper(db, me)
    links = mapper.links(asset)
    counts = external.sast_counts(db, [l["full_name"] for l in links], me)
    return external.asset_dict(asset, links, counts, external.blocked(db, asset),
                               external.options(db)["max_age_days"],
                               public_base(request))


def _api_details(body: dict) -> dict:
    """The site details from a JSON body, each checked for its type."""
    out = {}
    for key in ("executive_owner", "technical_owner", "comments", "notes",
                "status", "environment", "default_profile"):
        if body.get(key) is not None:
            if not isinstance(body[key], str):
                raise HTTPException(status_code=400, detail=f"{key} has to be a string.")
            out[key] = body[key]
    for key in ("external_auth_needed", "whitelist_needed"):
        if body.get(key) is not None:
            if not isinstance(body[key], bool):
                raise HTTPException(status_code=400, detail=f"{key} has to be true or false.")
            out[key] = body[key]
    if "change_frequency_days" in body:
        value = body["change_frequency_days"]
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise HTTPException(status_code=400,
                                detail="change_frequency_days has to be a whole number.")
        out["change_frequency_days"] = value
    return out


def _api_fields(body: dict) -> dict:
    value = body.get("telemetry_fields")
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="telemetry_fields has to be an object.")
    for key, item in value.items():
        if item is not None and not isinstance(item, (str, int)):
            raise HTTPException(status_code=400,
                                detail=f"telemetry_fields.{key} has to be text, a number or null.")
    return value


def _paging(request: Request) -> tuple:
    try:
        limit = int(request.query_params.get("limit", 100))
        offset = int(request.query_params.get("offset", 0))
    except ValueError:
        raise HTTPException(status_code=400, detail="limit and offset are numbers.")
    if not 1 <= limit <= 1000 or offset < 0:
        raise HTTPException(status_code=400, detail="limit is 1 to 1000, offset 0 or more.")
    return limit, offset


def _str_field(body, name, limit, what=None):
    value = body.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{name} has to be a string.")
    return clean_text(value, what or name, limit=limit, required=False)


@api.get("/assets")
def api_list(request: Request, caller=Depends(_api_caller())):
    from sqlalchemy import or_

    limit, offset = _paging(request)
    params = request.query_params
    with session_scope() as db:
        me = _api_me(db, caller)
        query = db.query(ExternalAsset)
        if params.get("q"):
            needle = f"%{params['q'][:200]}%"
            query = query.filter(or_(ExternalAsset.host.ilike(needle),
                                     ExternalAsset.application.ilike(needle)))
        if params.get("host"):
            query = query.filter(ExternalAsset.host == params["host"].strip().lower()[:253])
        if params.get("application"):
            query = query.filter(ExternalAsset.application == params["application"][:200])
        if params.get("tag"):
            query = query.filter(ExternalAsset.tags.any(
                ExternalAssetTag.tag == params["tag"][:100]))
        if params.get("severity"):
            query = query.filter(ExternalAsset.last_dast_severity == params["severity"][:16])
        if params.get("environment"):
            query = query.filter(ExternalAsset.environment == external.env_key(params["environment"]))
        if params.get("status"):
            query = query.filter(ExternalAsset.status == params["status"].lower()[:16])
        total = query.count()
        rows = query.order_by(ExternalAsset.host).offset(offset).limit(limit).all()
        return {"total": total, "limit": limit, "offset": offset,
                "assets": [_view(db, a, me, request) for a in rows]}


@api.post("/assets")
async def api_add(request: Request, caller=Depends(_api_caller())):
    body = await _body(request)
    from app.core.external_probe import clean_host

    host = clean_host(body.get("host") if isinstance(body.get("host"), str) else "")
    if not host:
        raise HTTPException(status_code=400, detail="host has to be a domain or subdomain name.")
    tags = body.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise HTTPException(status_code=400, detail="tags has to be a list of strings.")
    if body.get("no_scan") is not None and not isinstance(body.get("no_scan"), bool):
        raise HTTPException(status_code=400, detail="no_scan has to be true or false.")
    with session_scope() as db:
        me = _api_me(db, caller)
        existed = db.query(ExternalAsset).filter(ExternalAsset.host == host).one_or_none()
        try:
            details = external.clean_details(_api_details(body), envs=external.environments(db))
            picks = external.picks_from_names(db, body.get("repositories") or [])
            got = external.add_assets(db, [{
                "host": host, "application": _str_field(body, "application", 200) or "",
                "tags": tags, "no_scan": bool(body.get("no_scan")),
                "no_scan_reason": _str_field(body, "no_scan_reason", 300) or ""}],
                me.username, details=details, picks=picks, user=me)
            asset = db.query(ExternalAsset).filter(ExternalAsset.host == host).one()
            if body.get("telemetry_fields") is not None and not existed:
                external.set_manual(asset, _api_fields(body))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        record(db, "external.added", actor=me.username, target=host,
               detail=f"api token {caller.token.prefix}", source_ip=client_ip(request))
        out = _view(db, asset, me, request)
        asset_id = asset.id
    if got["added"] and body.get("telemetry", True) is not False:
        external.start_telemetry([asset_id])
    return JSONResponse(status_code=200 if existed else 201, content=out)


@api.get("/assets/{asset_id}")
def api_get(asset_id: int, request: Request, caller=Depends(_api_caller())):
    with session_scope() as db:
        me = _api_me(db, caller)
        return _view(db, _asset(db, asset_id), me, request)


@api.patch("/assets/{asset_id}")
async def api_patch(asset_id: int, request: Request, caller=Depends(_api_caller())):
    body = await _body(request)
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        value = _str_field(body, "application", 200)
        if value is not None:
            asset.application = value
        try:
            external.apply_details(asset, external.clean_details(
                _api_details(body), partial=True, envs=external.environments(db),
                keep_env=asset.environment))
            if "repositories" in body:
                external.set_picks(db, asset,
                                   external.picks_from_names(db, body["repositories"] or []),
                                   me.username, me)
            if body.get("telemetry_fields") is not None:
                external.set_manual(asset, _api_fields(body))
            if "proxy" in body:
                if body["proxy"] is not None and not isinstance(body["proxy"], str):
                    raise ValueError("proxy has to be a string, or null to remove it.")
                external.set_proxy(asset, body["proxy"] or "")
                record(db, "external.proxy_set", actor=me.username, target=asset.host,
                       detail=f"{external.proxy_shown(asset) or 'removed'}, api token "
                              f"{caller.token.prefix}"[:200], source_ip=client_ip(request))
            if "scan_auth" in body:
                from app.core import external_auth

                auth = body["scan_auth"]
                if auth is not None and not isinstance(auth, dict):
                    raise ValueError("scan_auth has to be an object, or null to remove it.")
                auth = auth or {}
                if not all(isinstance(v, str) for v in auth.values()):
                    raise ValueError("Every scan_auth value has to be a string.")
                external_auth.save(asset, auth.get("kind", ""), auth, me.username,
                                   asset.parent_domain)
                record(db, "external.auth_set", actor=me.username, target=asset.host,
                       detail=f"{external_auth.KINDS.get(asset.auth_kind, '')}, api token "
                              f"{caller.token.prefix}", source_ip=client_ip(request))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if "tags" in body:
            if not isinstance(body["tags"], list) or not all(isinstance(t, str) for t in body["tags"]):
                raise HTTPException(status_code=400, detail="tags has to be a list of strings.")
            external.set_tags(asset, body["tags"])
        if "no_scan" in body:
            if not isinstance(body["no_scan"], bool):
                raise HTTPException(status_code=400, detail="no_scan has to be true or false.")
            asset.no_scan = body["no_scan"]
            asset.no_scan_reason = (_str_field(body, "no_scan_reason", 300) or "") \
                if asset.no_scan else ""
        record(db, "external.edited", actor=me.username, target=asset.host,
               detail=f"api token {caller.token.prefix}", source_ip=client_ip(request))
        db.flush()
        return _view(db, asset, me, request)


@api.patch("/assets")
async def api_bulk_patch(request: Request, caller=Depends(_api_caller())):
    """Change the same things on many sites, all or nothing."""
    body = await _body(request)
    ids = body.get("ids")
    if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids) or len(ids) > 500:
        raise HTTPException(status_code=400, detail="ids is a list of up to 500 site ids.")
    with session_scope() as db:
        me = _api_me(db, caller)
        assets = db.query(ExternalAsset).filter(ExternalAsset.id.in_(ids)).all()
        missing = set(ids) - {a.id for a in assets}
        if missing:
            raise HTTPException(status_code=404, detail=f"No such sites: {sorted(missing)[:10]}")
        changes, details = {}, {}
        try:
            for key in external.BULK_FIELDS:
                if key in body:
                    details[key] = body[key]
            src = _api_details({k: v for k, v in body.items() if k in external.BULK_FIELDS})
            details.update(src)
            if "application" in body:
                if not isinstance(body["application"], str):
                    raise ValueError("application has to be a string.")
                details["application"] = body["application"]
            if details:
                changes["details"] = details
            for key, modes in (("tags", ("add", "remove", "replace")),
                               ("comments", ("replace", "append")),
                               ("repositories", ("add", "replace", "clear"))):
                if key in body:
                    mode = body.get(f"{key}_mode") or modes[0]
                    if mode not in modes:
                        raise ValueError(f"{key}_mode is one of {', '.join(modes)}.")
                    value = body[key]
                    if key == "repositories":
                        value = external.picks_from_names(db, value or [])
                    elif key == "tags" and (not isinstance(value, list)
                                            or not all(isinstance(t, str) for t in value)):
                        raise ValueError("tags has to be a list of strings.")
                    elif key == "comments" and not isinstance(value, str):
                        raise ValueError("comments has to be a string.")
                    changes[key] = (mode, value)
            if "no_scan" in body:
                if not isinstance(body["no_scan"], bool):
                    raise ValueError("no_scan has to be true or false.")
                changes["no_scan"] = (body["no_scan"], str(body.get("no_scan_reason") or ""))
            if "proxy" in body:
                if body["proxy"] is not None and not isinstance(body["proxy"], str):
                    raise ValueError("proxy has to be a string, or null to remove it.")
                changes["proxy"] = body["proxy"] or ""
            if "scan_auth" in body:
                auth = body["scan_auth"] or {}
                if not isinstance(auth, dict) or not all(isinstance(v, str) for v in auth.values()):
                    raise ValueError("scan_auth has to be an object of strings, or null.")
                changes["auth"] = (auth.get("kind", ""), auth)
            if not changes:
                raise ValueError("Name at least one thing to change.")
            changed = external.bulk_update(db, assets, changes, me.username, me)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=400, detail=f"Nothing was changed.  {exc}")
        record(db, "external.bulk_edit", actor=me.username, target=f"{len(changed)} sites",
               detail=(", ".join(sorted(changes)) + f", api token {caller.token.prefix}")[:500],
               source_ip=client_ip(request))
        return {"changed": len(changed), "hosts": changed}


@api.delete("/assets/{asset_id}")
def api_delete(asset_id: int, request: Request, caller=Depends(_api_caller())):
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        if db.query(ExternalDastScan).filter(
                ExternalDastScan.asset_id == asset.id,
                ExternalDastScan.status.in_(("queued", "running"))).first():
            raise HTTPException(status_code=409, detail="A scan is running.  Stop it first.")
        record(db, "external.deleted", actor=me.username, target=asset.host,
               detail=f"api token {caller.token.prefix}", source_ip=client_ip(request))
        db.delete(asset)
    external.drop_shot(asset_id)
    return Response(status_code=204)


@api.post("/assets/{asset_id}/telemetry")
def api_telemetry(asset_id: int, caller=Depends(_api_caller())):
    with session_scope() as db:
        _api_me(db, caller)
        _asset(db, asset_id)
    queued = external.start_telemetry([asset_id])
    return JSONResponse(status_code=202, content={"queued": bool(queued)})


@api.get("/assets/{asset_id}/scans")
def api_scans(asset_id: int, request: Request, caller=Depends(_api_caller())):
    limit, offset = _paging(request)
    with session_scope() as db:
        _api_me(db, caller)
        _asset(db, asset_id)
        query = (db.query(ExternalDastScan).filter(ExternalDastScan.asset_id == asset_id)
                 .order_by(ExternalDastScan.id.desc()))
        return {"total": query.count(), "limit": limit, "offset": offset,
                "scans": [external.scan_dict(s) for s in query.offset(offset).limit(limit)]}


@api.get("/assets/{asset_id}/scans/{scan_id}")
def api_scan(asset_id: int, scan_id: int, caller=Depends(_api_caller())):
    with session_scope() as db:
        _api_me(db, caller)
        _asset(db, asset_id)
        return external.scan_dict(_scan(db, asset_id, scan_id), findings=True)


@api.get("/assets/{asset_id}/scans/{scan_id}/report.pdf")
def api_report(asset_id: int, scan_id: int, request: Request, caller=Depends(_api_caller())):
    """The PDF report on a finished scan this server ran."""
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        pdf, name = _report(db, asset, scan, me)
        record(db, "external.report", actor=me.username, target=asset.host,
               detail=f"scan {scan_id}, api token {caller.token.prefix}",
               source_ip=client_ip(request))
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@api.get("/assets/{asset_id}/schedules")
def api_schedules(asset_id: int, caller=Depends(_api_caller())):
    with session_scope() as db:
        _api_me(db, caller)
        _asset(db, asset_id)
        return {"schedules": [external_schedule.as_dict(x) for x in db.query(ExternalScanSchedule)
                              .filter_by(asset_id=asset_id).order_by(ExternalScanSchedule.id)],
                "time_zone": str(external_schedule.zone())}


@api.post("/assets/{asset_id}/schedules")
async def api_add_schedule(asset_id: int, request: Request, caller=Depends(_api_caller())):
    from app.core import dast_engines

    body = await _body(request)
    for key in ("frequency", "time_of_day", "run_on", "profile"):
        if body.get(key) is not None and not isinstance(body[key], str):
            raise HTTPException(status_code=400, detail=f"{key} has to be a string.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        if external.blocked(db, asset):
            raise HTTPException(status_code=409, detail="This site may not be scanned.")
        profile = body.get("profile") or external.profile_for(asset)
        if (profile in dast_engines.ACTIVE_PROFILES or (body.get("authenticated") is True
                                                        and profile != "baseline")) \
                and body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail=(
                "This schedule sends attack payloads or acts as a signed in user.  Send "
                "confirm true to say you are allowed to scan the site this way."))
        try:
            sched = external_schedule.create(db, asset, dict(body, profile=profile,
                                                             ai_triage=body.get("ai")), me.username)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        record(db, "external.schedule_added", actor=me.username, target=asset.host,
               detail=f"{external_schedule.describe(sched)}, api token {caller.token.prefix}"[:300],
               source_ip=client_ip(request))
        return JSONResponse(status_code=201, content=external_schedule.as_dict(sched))


@api.delete("/assets/{asset_id}/schedules/{schedule_id}")
def api_delete_schedule(asset_id: int, schedule_id: int, request: Request,
                        caller=Depends(_api_caller())):
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        sched = (db.query(ExternalScanSchedule)
                 .filter_by(id=schedule_id, asset_id=asset_id).one_or_none())
        if sched is None:
            raise HTTPException(status_code=404, detail="No such schedule.")
        db.delete(sched)
        record(db, "external.schedule_delete", actor=me.username, target=asset.host,
               detail=f"schedule {schedule_id}, api token {caller.token.prefix}",
               source_ip=client_ip(request))
    return Response(status_code=204)


@api.post("/assets/{asset_id}/scans/{scan_id}/findings/{key}/decision")
async def api_decide(asset_id: int, scan_id: int, key: str, request: Request,
                     caller=Depends(_api_caller())):
    from app.core import external_decisions

    if not KEY_RE.fullmatch(key):
        raise HTTPException(status_code=404, detail="No such finding.")
    body = await _body(request)
    for field in ("kind", "reason", "severity", "expires"):
        if body.get(field) is not None and not isinstance(body[field], str):
            raise HTTPException(status_code=400, detail=f"{field} has to be a string.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        d = _decision_from(body)
        try:
            row = external_decisions.decide(db, asset, scan, key, d["kind"], d["reason"],
                                            me.username, d["severity"], d["expires"], persist=d["persist"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        record(db, "external.finding_decided", actor=me.username, target=asset.host,
               detail=f"{row.kind}: {row.title}, api token {caller.token.prefix}"[:300],
               source_ip=client_ip(request))
        return JSONResponse(status_code=201, content=external.scan_dict(db.get(ExternalDastScan, scan_id)))


@api.delete("/assets/{asset_id}/scans/{scan_id}/findings/{key}/decision")
def api_undecide(asset_id: int, scan_id: int, key: str, request: Request,
                 caller=Depends(_api_caller())):
    from app.core import external_decisions

    if not KEY_RE.fullmatch(key):
        raise HTTPException(status_code=404, detail="No such finding.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        _scan(db, asset_id, scan_id)
        if not external_decisions.undo(db, asset, key, scan_id):
            raise HTTPException(status_code=404, detail="There is no decision on it.")
        record(db, "external.finding_undecided", actor=me.username, target=asset.host,
               detail=f"finding {key[:12]}, api token {caller.token.prefix}", source_ip=client_ip(request))
    return Response(status_code=204)


@api.post("/assets/{asset_id}/scans")
async def api_record(asset_id: int, request: Request, caller=Depends(_api_caller())):
    """Record a scan run elsewhere: severity, result address, when, which server."""
    body = await _body(request)
    for field in ("server", "result_url", "severity", "note", "scanned_at"):
        if body.get(field) is not None and not isinstance(body[field], str):
            raise HTTPException(status_code=400, detail=f"{field} has to be a string.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        try:
            scan = external.record_scan(db, asset, body, me.username)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        record(db, "external.scan_recorded", actor=me.username, target=asset.host,
               detail=f"{scan.server_name}, {scan.severity}, api token {caller.token.prefix}",
               source_ip=client_ip(request))
        return JSONResponse(status_code=201, content=external.scan_dict(scan))


@api.post("/scans")
async def api_record_by_host(request: Request, caller=Depends(_api_caller())):
    """The same, by host name, for a DAST server that does not know our ids.
    create true adds the host first when it is not listed."""
    from app.core.external_probe import clean_host

    body = await _body(request)
    host = clean_host(body.get("host") if isinstance(body.get("host"), str) else "")
    if not host:
        raise HTTPException(status_code=400, detail="host has to be a domain or subdomain name.")
    for field in ("server", "result_url", "severity", "note", "scanned_at"):
        if body.get(field) is not None and not isinstance(body[field], str):
            raise HTTPException(status_code=400, detail=f"{field} has to be a string.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = db.query(ExternalAsset).filter(ExternalAsset.host == host).one_or_none()
        if asset is None:
            if body.get("create") is not True:
                raise HTTPException(status_code=404,
                                    detail="That host is not listed.  Send create true to add it.")
            external.add_assets(db, [{"host": host, "application": "", "tags": []}], me.username)
            asset = db.query(ExternalAsset).filter(ExternalAsset.host == host).one()
        try:
            scan = external.record_scan(db, asset, body, me.username)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        record(db, "external.scan_recorded", actor=me.username, target=asset.host,
               detail=f"{scan.server_name}, {scan.severity}, api token {caller.token.prefix}",
               source_ip=client_ip(request))
        return JSONResponse(status_code=201, content=external.scan_dict(scan))


@api.post("/assets/{asset_id}/dast")
async def api_start(asset_id: int, request: Request, caller=Depends(_api_caller())):
    """Start a scan here or on a nextgen-dast server."""
    from app.core import dast_engines

    body = await _body(request)
    profile = body.get("profile") or ""
    server = body.get("server")
    if not isinstance(profile, str) or (server is not None and not isinstance(server, str)):
        raise HTTPException(status_code=400, detail="profile and server are strings.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        profile = profile or external.profile_for(asset)
        server_id = None
        if server and server != "builtin":
            row = db.query(DastServer).filter(DastServer.name == server).one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail="No such server.")
            server_id = row.id
        if body.get("authenticated") is not None and not isinstance(body["authenticated"], bool):
            raise HTTPException(status_code=400, detail="authenticated has to be true or false.")
        sign_in = bool(asset.auth_kind) if body.get("authenticated") is None else body["authenticated"]
        if (server_id or profile in dast_engines.ACTIVE_PROFILES
                or (sign_in and profile != "baseline")) and body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail=(
                "This sends attack payloads or acts as a signed in user.  Send confirm "
                "true to say you are allowed to scan the site this way."))
        host, username = asset.host, me.username
    scan_id, problem = external.start_scan(asset_id, profile, username,
                                           ai_triage=body.get("ai") is True,
                                           server_id=server_id, authenticated=sign_in)
    with session_scope() as db:
        record(db, "external.scan_started" if scan_id else "external.scan_refused",
               actor=username, target=host,
               detail=f"{profile}, api token {caller.token.prefix}"
                      + (f": {problem}" if problem else ""),
               source_ip=client_ip(request), outcome="ok" if scan_id else "refused")
    if problem:
        raise HTTPException(status_code=409, detail=problem)
    with session_scope() as db:
        return JSONResponse(status_code=202,
                            content=external.scan_dict(db.get(ExternalDastScan, scan_id)))
