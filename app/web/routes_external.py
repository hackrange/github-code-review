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

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from app.core import external, rbac
from app.core.audit import record
from app.core.db import session_scope
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
                 "change_frequency_days")


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

@router.get("/external")
def list_page(request: Request, q: str = "", tag: str = "", app: str = "",
              grade: str = "", dast: str = "", risk: str = "", scope: str = "",
              env: str = "", status: str = "", user: User = Depends(current_user)):
    """Every external site, newest problems first."""
    with session_scope() as db:
        _guard(db, user)
        q = clean_text(q, "Search", limit=200, required=False).lower()
        tag = clean_text(tag, "Tag", limit=100, required=False)
        app = clean_text(app, "Application", limit=200, required=False)
        opts = external.options(db)
        mapper = external.Mapper(db, user)
        assets = db.query(ExternalAsset).order_by(ExternalAsset.host).all()
        blocked = external.blocked_hosts(db)
        every_link = {a.id: mapper.links(a) for a in assets}
        scanning = external.running_scans(db)
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
            }
            if env and (a.environment or "prod") != env:
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
        all_tags = sorted({t.tag for t in db.query(ExternalAssetTag.tag).distinct()},
                          key=str.casefold)
        apps = sorted({a.application for a in assets if a.application}, key=str.casefold)
        totals = {
            "sites": len(assets), "shown": len(rows),
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
        context = _shared(db, user)
        from app.core import dast_engines

        context.update(active_page="external", rows=rows, totals=totals,
                       profiles=dast_engines.PROFILES,
                       q=q, tag=tag, app=app, grade=grade, dast=dast, risk=risk,
                       scope=scope, all_tags=all_tags, apps=apps, opts=opts,
                       env=env, status=status, environments=external.ENVIRONMENTS,
                       statuses=external.STATUSES,
                       servers=servers,
                       running=sum(1 for a in assets if a.telemetry_status == "running"),
                       scanning=len(scanning),
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
                external.ENVIRONMENTS.get(a.environment, a.environment or ""),
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
            details = external.clean_details(_detail_form(form))
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
        external.shot_path(asset_id).unlink(missing_ok=True)
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
    profile = str(form.get("profile") or "baseline")
    with session_scope() as db:
        _guard(db, user)
        ids = _ticked(form)[:50]
        if not ids:
            return redirect(_back("/external", "Tick the sites to scan first.", "error"))
        if profile not in dast_engines.PROFILES:
            return redirect(_back("/external", "Pick a scan profile.", "error"))
        if profile in dast_engines.ACTIVE_PROFILES and not _checked(form, "confirm"):
            return redirect(_back("/external", "Tick the box to confirm you are allowed to "
                                               "send attack payloads to these sites.", "error"))
    started, skipped = 0, []
    for asset_id in ids:
        scan_id, problem = external.start_scan(asset_id, profile, user.username,
                                               ai_triage=_checked(form, "ai"))
        if scan_id:
            started += 1
        else:
            skipped.append(problem)
    with session_scope() as db:
        record(db, "external.scan_started", actor=user.username,
               target=f"{started} sites", detail=f"{profile}, {len(skipped)} skipped",
               source_ip=client_ip(request))
    message = f"Started a {profile} scan of {started} site{'s' if started != 1 else ''}.  They run one at a time."
    if skipped:
        message += "  Skipped: " + "; ".join(skipped[:3])
    return redirect(_back("/external", message, "ok" if started else "error"))


# ------------------------------------------------------------------ one site

@router.get("/external/{asset_id}")
def detail_page(asset_id: int, request: Request, user: User = Depends(current_user)):
    from app.core import ai, dast_engines

    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        opts = external.options(db)
        links = external.Mapper(db, user).links(asset)
        names = [l["full_name"] for l in links]
        counts = external.sast_counts(db, names, user)
        scans = (db.query(ExternalDastScan)
                 .filter(ExternalDastScan.asset_id == asset.id)
                 .order_by(ExternalDastScan.id.desc()).limit(100).all())
        linked = {l["full_name"]: counts.get(l["full_name"], {}) for l in links if l["linked"]}
        try:
            review = json.loads(asset.ai_review or "{}") if asset.ai_review else {}
        except ValueError:
            review = {}
        busy = (asset.telemetry_status == "running" or asset.ai_status == "running"
                or any(s.status in ("queued", "running") or s.ai_status == "running"
                       for s in scans))
        active_scan = next((s for s in scans if s.status in ("queued", "running")), None)
        context = _shared(db, user)
        context.update(
            active_page="external", asset=asset, tele=external.telemetry_of(asset),
            tags=asset.tag_list(), links=links, counts=counts,
            risk=external.combined_risk(asset, linked),
            due=external.due_status(asset, opts["max_age_days"]),
            blocked=external.blocked(db, asset), scans=scans, active_scan=active_scan,
            fields=external.fields_of(asset), security_headers=external.SECURITY_HEADERS,
            picks_json=json.dumps(external.picks_of(db, asset)),
            environments=external.ENVIRONMENTS, statuses=external.STATUSES,
            scan_views=[external.scan_dict(s) for s in scans],
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
            external.apply_details(asset, external.clean_details(_detail_form(form)))
            if form.get("with_picks"):
                external.set_picks(db, asset, external.parse_picks(form.getlist("pick")),
                                   user.username, user)
            if form.get("with_fields"):
                external.set_manual(asset, {key: form.get(f"f:{key}") or ""
                                            for key in external.FIELD_KEYS}, replace=True)
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
    external.shot_path(asset_id).unlink(missing_ok=True)
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
    profile = str(form.get("profile") or "baseline")
    server_id = None
    target = str(form.get("server") or "builtin")
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        if target != "builtin":
            try:
                server_id = int(target)
            except ValueError:
                raise HTTPException(status_code=400, detail="Pick a server.")
        if (server_id or profile in dast_engines.ACTIVE_PROFILES) and not _checked(form, "confirm"):
            return redirect(_back(here, "Tick the box to confirm you are allowed to send "
                                        "attack payloads to this site.", "error"))
        host = asset.host
    scan_id, problem = external.start_scan(asset_id, profile, user.username,
                                           ai_triage=_checked(form, "ai"),
                                           server_id=server_id)
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
        view = external.scan_dict(scan, findings=True)
        findings = view["findings"]
        if sev:
            findings = [f for f in findings if f.get("severity") == sev]
        if verdict:
            findings = [f for f in findings if f.get("ai_verdict", "") == verdict]
        context = _shared(db, user)
        context.update(active_page="external", asset=asset, scan=scan, view=view,
                       findings=findings, sev=sev, verdict=verdict,
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
            if scan.status in ("queued", "running"):
                return redirect(_back(here, "Stop it first.", "error"))
            db.delete(scan)
            db.flush()
            external.copy_newest(db, asset)
            record(db, "external.scan_deleted", actor=user.username, target=host,
                   detail=f"scan {scan_id}", source_ip=client_ip(request))
            return redirect(_back(f"/external/{asset_id}", "Removed that scan."))
    if action == "stop":
        ok = external.stop_scan(scan_id)
        message, kind = ("Stopping the scan of " + host + ".", "ok") if ok \
            else ("It is not running.", "error")
        form = await request.form()
        # Back to where the Stop was pressed, and only to a page of ours.
        back = str(form.get("back") or "")
        if back in ("/external", f"/external/{asset_id}"):
            here = back
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
                "status", "environment"):
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
            query = query.filter(ExternalAsset.environment == params["environment"].lower()[:16])
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
            details = external.clean_details(_api_details(body))
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
            external.apply_details(asset, external.clean_details(_api_details(body),
                                                                 partial=True))
            if "repositories" in body:
                external.set_picks(db, asset,
                                   external.picks_from_names(db, body["repositories"] or []),
                                   me.username, me)
            if body.get("telemetry_fields") is not None:
                external.set_manual(asset, _api_fields(body))
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
    external.shot_path(asset_id).unlink(missing_ok=True)
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
    profile = body.get("profile") or "baseline"
    server = body.get("server")
    if not isinstance(profile, str) or (server is not None and not isinstance(server, str)):
        raise HTTPException(status_code=400, detail="profile and server are strings.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        server_id = None
        if server and server != "builtin":
            row = db.query(DastServer).filter(DastServer.name == server).one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail="No such server.")
            server_id = row.id
        if (server_id or profile in dast_engines.ACTIVE_PROFILES) and body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail=(
                "This sends attack payloads.  Send confirm true to say you are "
                "allowed to scan the site."))
        host, username = asset.host, me.username
    scan_id, problem = external.start_scan(asset_id, profile, username,
                                           ai_triage=body.get("ai") is True,
                                           server_id=server_id)
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
