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
import re
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
    DastScanProfile, DastServer, ExternalAsset, ExternalAssetRepo,
    ExternalAssetTag, ExternalDastScan, User,
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

    # A #section stays at the end, where the browser reads it.
    where, hash_mark, section = where.partition("#")
    return "%s%smsg=%s&kind=%s%s" % (where, "&" if "?" in where else "?",
                                     quote(message), kind, hash_mark + section)


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
        # The DAST grade of each shown site's newest scan, worked out now so
        # a decision or a review made since the scan already counts.
        from app.core import dast_report

        grades = dast_report.latest_grades(db, [r["a"].id for r in rows])
        for r in rows:
            r["dast_grade"] = grades.get(r["a"].id)
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
                       scan_profiles=db.query(DastScanProfile).order_by(DastScanProfile.name).all(),
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
                         "last_dast_server", "last_dast_url",
                         "url_paths", "url_paths_scan",
                         "http_200_paths", "unique_endpoints", "scan_blocked",
                         "paths_answered",
                         "repositories", "comments"]
                        + external.FIELD_KEYS)
        # One read of each site's newest counted scan, not one per column.
        scoped = external.scoping_by_asset(db)
        from app.core import dast_paths as _dast_paths
        from app.core import webapps as _webapps
        for a in db.query(ExternalAsset).order_by(ExternalAsset.host):
            values = external.field_values(a)
            scope = (scoped.get(a.id) or {}).get("scope")
            repos, moved = [], []
            for l in mapper.links(a):
                if l["linked"]:
                    repos += [f"{l['full_name']}@{b}" for b in l.get("branches") or []] \
                        or [l["full_name"]]
                    days = _webapps.changed(l["repo"])["days"]
                    if days is not None:
                        moved.append(days)
            # Typed on the site wins.  Otherwise the newest change on any
            # linked repository's default branch, the same number the Web
            # Applications tab shows on an application's line.
            if a.change_frequency_days:
                frequency = a.change_frequency_days
            else:
                frequency = min(moved) if moved else ""
            writer.writerow([_quote_formula(str(c)) for c in [
                a.host, a.kind, a.parent_domain, a.application, "; ".join(a.tag_list()),
                envs.get(a.environment, a.environment or ""),
                external.STATUSES.get(a.status, a.status or ""),
                a.executive_owner or "", a.technical_owner or "",
                "yes" if a.external_auth_needed else "no",
                "yes" if a.whitelist_needed else "no",
                frequency,
                "yes" if a.no_scan else "", a.no_scan_reason or "",
                a.telemetry_at.strftime("%Y-%m-%d %H:%M") if a.telemetry_at else "",
                a.last_dast_at.strftime("%Y-%m-%d") if a.last_dast_at else "",
                a.last_dast_severity or "", a.last_dast_server or "",
                a.last_dast_url or "",
                "" if a.last_paths is None else a.last_paths,
                (a.last_paths_at.strftime("%Y-%m-%d") + " " + (a.last_paths_profile or "")).strip()
                if a.last_paths_at else "",
                "" if scope is None else scope["http_200"],
                "" if scope is None else len(scope["endpoints"]),
                "" if scope is None else (_dast_paths.blocked_text(scope) or "no"),
                "" if scope is None else scope["answered"],
                " ".join(repos),
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
            details = external.clean_details(_detail_form(form), envs=external.environments(db), profile_names=external.saved_profile_names(db))
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


@router.post("/external/schedule-monthly")
async def schedule_monthly(request: Request, user: User = Depends(current_user)):
    """A monthly scan for the ticked sites, or every site, spread over the
    month and inside a time window, such as 22:00 to 04:00."""
    await check_csrf(request)
    from app.core import dast_engines, external_schedule

    form = await request.form()
    profile = str(form.get("bulk_profile") or "standard")
    start = str(form.get("window_start") or "22:00")
    end = str(form.get("window_end") or "04:00")
    every = str(form.get("bulk_scope") or "") == "all"
    with session_scope() as db:
        _guard(db, user)
        ids = _ticked(form)
        if not every and not ids:
            return redirect(_back("/external", "Tick the sites to schedule, or pick every site.",
                                  "error"))
        if profile in dast_engines.ACTIVE_PROFILES and not _checked(form, "bulk_confirm"):
            return redirect(_back("/external", "Tick the box to confirm you are allowed to "
                                               "scan these sites this way.", "error"))
        query = db.query(ExternalAsset)
        if not every:
            query = query.filter(ExternalAsset.id.in_(ids))
        try:
            got = external_schedule.bulk_monthly(db, query.all(), profile, start, end,
                                                 user.username)
        except ValueError as exc:
            db.rollback()
            return redirect(_back("/external", f"Nothing was scheduled.  {exc}", "error"))
        record(db, "external.schedules_added", actor=user.username,
               target=f"{len(got['created'])} sites",
               detail=(f"monthly {profile}, {start} to {end}, {len(got['skipped'])} skipped: "
                       + ", ".join(h for h, _w in got["created"]))[:500],
               source_ip=client_ip(request))
    count = len(got["created"])
    message = (f"Scheduled a monthly {profile} scan of {count} site{'s' if count != 1 else ''} "
               f"between {start} and {end}.")
    if got["skipped"]:
        message += (f"  Skipped {len(got['skipped'])}: "
                    + "; ".join(f"{h} ({w})" for h, w in got["skipped"][:3]))
    return redirect(_back("/external", message, "ok" if count else "error"))


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
        if isinstance(review, dict) and review:
            review = external.scrub_review(db, review)
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
            ias=_ias_choices(db, asset),
            profiles=dast_engines.PROFILES, active=dast_engines.ACTIVE_PROFILES,
            scan_profiles=db.query(DastScanProfile).order_by(DastScanProfile.name).all(),
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
                _detail_form(form), envs=external.environments(db), keep_env=asset.environment, profile_names=external.saved_profile_names(db)))
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
    # A Pin on a scan page goes back to that scan's code section.
    back = str(form.get("back") or "")
    if re.fullmatch(rf"/external/{int(asset_id)}/scans/\d{{1,9}}", back):
        here = back + "#code"
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


def _ias_choices(db, asset) -> dict:
    """InsightAppSec for the scan form: whether it is set up, and its scan
    configs with the ones that start on this site first."""
    from app.core import insightappsec as ias

    cfg = ias.config(db)
    if not cfg["ready"]:
        return {"ready": False, "guide": ias.GUIDE}
    catalog = ias.load_catalog()
    ranked = ias.configs_for(asset.host, catalog)
    chosen = asset.ias_scan_config_id or ""
    if not chosen and ranked and ranked[0][1] == "starts on this host":
        chosen = ranked[0][0]["id"]
    return {"ready": True, "guide": ias.GUIDE, "name": ias.NAME,
            "configs": [dict(c, why=why) for c, why in ranked],
            "chosen": chosen, "fetched_at": catalog.get("fetched_at", ""),
            "running": external.ias_running(db), "max": cfg["max_concurrent"]}


@router.post("/external/{asset_id}/scan")
async def start_scan(asset_id: int, request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    from app.core import dast_engines

    form = await request.form()
    here = f"/external/{asset_id}"
    profile = str(form.get("profile") or "")
    server_id = None
    target = str(form.get("server") or "builtin")
    if target == "insightappsec":
        return await _start_ias_scan(asset_id, form, request, user)
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
        # A saved scan profile (a name, not a plain depth) runs the active
        # engines and the curated rules, so it needs the same confirmation.
        saved = profile not in dast_engines.PROFILES
        if (server_id or saved or profile in dast_engines.ACTIVE_PROFILES
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


async def _start_ias_scan(asset_id: int, form, request: Request, user: User):
    """A scan on Rapid7 InsightAppSec, from the scan config picked for the site."""
    here = f"/external/{asset_id}"
    config_id = str(form.get("ias_config") or "").strip()
    with session_scope() as db:
        _guard(db, user)
        host = _asset(db, asset_id).host
    if not _checked(form, "confirm"):
        return redirect(_back(here, "Tick the box to confirm you are allowed to scan this "
                                    "site this way.  InsightAppSec sends attack payloads.",
                              "error"))
    from starlette.concurrency import run_in_threadpool

    # Starting it is a call to Rapid7, so it runs off the event loop.
    scan_id, problem = await run_in_threadpool(
        external.start_scan, asset_id, "", user.username,
        ai_triage=_checked(form, "ai"), ias_config=config_id)
    with session_scope() as db:
        record(db, "external.scan_started" if scan_id else "external.scan_refused",
               actor=user.username, target=host,
               detail=(f"InsightAppSec scan config {config_id}"
                       + (f": {problem}" if problem else ""))[:300],
               source_ip=client_ip(request), outcome="ok" if scan_id else "refused")
    if problem:
        return redirect(_back(here, problem[:290], "error"))
    return redirect(_back(f"{here}/scans/{scan_id}",
                          "Started on InsightAppSec.  Its status is read every few "
                          "minutes, and the findings come in when it completes."))


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
    here = f"/external/{asset_id}/scans/{scan_id}"
    if key == "bulk" and action == "decide":
        # Many findings and a recount: off the event loop, or every page waits.
        from starlette.concurrency import run_in_threadpool

        return await run_in_threadpool(_decide_bulk, asset_id, scan_id, form, request, user, here)
    if key == "form":
        # The dialog is shared by every finding, so it sends the key itself.
        key = str(form.get("key") or "")
    if not KEY_RE.fullmatch(key) or action not in ("decide", "undo", "restore"):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        if action == "restore":
            back = external.restore_removed(db, scan, key, user.username)
            if not back:
                return redirect(_back(here, "That finding was not taken out.", "error"))
            record(db, "external.finding_restored", actor=user.username, target=asset.host,
                   detail=f"put back: {back.get('title') or key[:12]}"[:300],
                   source_ip=client_ip(request))
            return redirect(_back(here, "Put back.  It counts as found again."))
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


def _decide_bulk(asset_id, scan_id, form, request, user, here):
    """One decision on every ticked finding."""
    from app.core import external_decisions

    keys = [k for k in (str(x) for x in form.getlist("keys")) if KEY_RE.fullmatch(k)]
    if not keys:
        return redirect(_back(here, "Tick the findings first.", "error"))
    if len(keys) > 2000:
        return redirect(_back(here, "At most 2,000 findings at once.", "error"))
    with session_scope() as db:
        _guard(db, user)
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        d = _decision_from(form)
        if form.get("with_persist"):
            d["persist"] = _checked(form, "persist")
        if d["kind"] not in external_decisions.KINDS or len(d["reason"].strip()) < 10:
            return redirect(_back(here, "Pick a decision and say why, in at least 10 characters.",
                                  "error"))
        done, skipped = external_decisions.decide_many(
            db, asset, scan, keys, d["kind"], d["reason"], user.username, d["severity"],
            d["expires"], persist=d["persist"])
        if not done:
            db.rollback()
            why = skipped[0][1] if skipped else "Nothing was recorded."
            return redirect(_back(here, why, "error"))
        word = external_decisions.KINDS[d["kind"]].lower()
        record(db, "external.finding_decided", actor=user.username, target=asset.host,
               detail=f"{d['kind']}{' ' + d['severity'] if d['kind'] == 'severity' else ''} "
                      f"on {len(done)} findings"[:300], source_ip=client_ip(request))
    note = f"Recorded: {word} on {len(done)} finding{'' if len(done) == 1 else 's'}."
    if skipped:
        note += f"  {len(skipped)} skipped: {skipped[0][1]}"
    return redirect(_back(here, note))


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
        asset = _asset(db, asset_id)
        scan = _scan(db, asset_id, scan_id)
        body = external.scan_dict(scan, findings=True)
        body["code_behind"] = external.code_behind(db, user, scan, asset)
        body["paths"] = external.paths_of(scan)
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
        removed = external.removed_of(scan)
        if isinstance(view["ai"].get("summary"), dict):
            view["ai"]["summary"] = external.scrub_dast_review(view["ai"]["summary"], findings,
                                                               removed)
        decided = sum(1 for f in findings if f.get("decision"))
        if sev:
            findings = [f for f in findings if f.get("severity") == sev]
        if verdict and verdict not in ("decided", "removed"):
            findings = [f for f in findings if f.get("ai_verdict", "") == verdict]
        context = _shared(db, user)
        if verdict == "decided":
            findings = [f for f in findings if f.get("decision")]
        if verdict == "removed":
            findings = []
        from app.core import dast_paths as _dast_paths

        scope = (_dast_paths.scoping(_dast_paths.load(scan.paths).get("paths") or [])
                 if scan.paths_count is not None else None)
        context.update(active_page="external", asset=asset, scan=scan, view=view,
                       scope=scope, blocked_text=_dast_paths.blocked_text(scope or {}),
                       code=external.code_behind(db, user, scan, asset),
                       findings=findings, sev=sev, verdict=verdict, decided=decided,
                       removed=removed if verdict == "removed" else [],
                       removed_count=len(removed),
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
        scan_status = scan.status
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
        from starlette.concurrency import run_in_threadpool

        # An InsightAppSec scan is stopped with a call to Rapid7.
        ok = await run_in_threadpool(external.stop_scan, scan_id)
        message, kind = ("Stopping the scan of " + host + ".", "ok") if ok \
            else ("It is not running, or it could not be stopped.  The scan's status "
                  "says which.", "error")
        form = await request.form()
        # Back to where the Stop was pressed, and only to a page of ours.
        here = _safe_back(form.get("back"), asset_id, here)
    elif action == "rematch":
        if scan_status in ("queued", "running"):
            message, kind = "Wait for the scan to finish.", "error"
        elif external.rematch(scan_id):
            message, kind = "Matched its paths again against the routes as they are now.", "ok"
        else:
            message, kind = "This scan kept no paths to match.", "error"
        here = here + "#code"
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
        on_ias = str(form.get("server") or "") == "insightappsec"
        ias_config = str(form.get("ias_config") or "").strip() if on_ias else ""
        if on_ias and not ias_config:
            return redirect(_back(here, "Pick the InsightAppSec scan config to run.", "error"))
        if on_ias:
            profile, signs_in = "", False
        if (on_ias or profile in dast_engines.ACTIVE_PROFILES
                or (signs_in and profile != "baseline")) and not _checked(form, "confirm"):
            return redirect(_back(here, "Tick the box to confirm you are allowed to scan this "
                                        "site this way, every time the schedule runs.", "error"))
        try:
            sched = external_schedule.create(db, asset, {
                "frequency": form.get("frequency"), "time_of_day": form.get("time_of_day"),
                "run_on": form.get("run_on"), "weekday": form.get("weekday"),
                "day_of_month": form.get("day_of_month"), "profile": profile,
                "ias_config": ias_config,
                "authenticated": signs_in, "ai_triage": _checked(form, "ai")}, user.username)
        except ValueError as exc:
            db.rollback()
            return redirect(_back(here, str(exc), "error"))
        record(db, "external.schedule_added", actor=user.username, target=asset.host,
               detail=(f"{external_schedule.describe(sched)}, "
                       + (f"InsightAppSec scan config {ias_config}" if ias_config else profile))[:300],
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


# ------------------------------------------------------------------ DAST admin
#
# The admin home for dynamic scanning, reached from the External sites page.
# It keeps the DAST settings out of the crowded general Settings, and it holds
# the premium curated rules: the enhanced, high fidelity checks.


def _rules_by_class(db):
    """Every rule, grouped under its class, for the admin page."""
    from app.core.dast_checks import spec as spec_mod
    from app.core.models import DastRule

    rows = db.query(DastRule).order_by(DastRule.rule_class, DastRule.rule_id).all()
    groups = {cls: {"label": label, "rules": []}
              for cls, label in spec_mod.CLASSES.items()}
    for row in rows:
        groups.setdefault(row.rule_class,
                          {"label": row.rule_class, "rules": []})["rules"].append(row)
    return groups


def _available_rulesets(db):
    """Every ruleset name a profile can pick: the classes, plus any tags on
    rules."""
    from app.core.dast_checks import profiles, spec as spec_mod
    from app.core.models import DastRule

    names = set(spec_mod.CLASSES)
    for row in db.query(DastRule).all():
        names |= profiles.membership(row.rule_class, row.rulesets)
    return sorted(names)


def _rule_context(db, user):
    from app.core import ai, settings_store
    from app.core.dast_checks import profiles, spec as spec_mod
    from app.core.models import DastRuleDraft, DastScanProfile

    drafts = db.query(DastRuleDraft).order_by(DastRuleDraft.created_at.desc()).all()
    saved = db.query(DastScanProfile).order_by(DastScanProfile.name).all()
    profile_rulesets = {p.id: profiles._list(p.rulesets) for p in saved}
    context = _shared(db, user)
    context.update(active_page="external", classes=spec_mod.CLASSES,
                   safety=spec_mod.SAFETY, severities=spec_mod.SEVERITIES,
                   groups=_rules_by_class(db), depths=profiles.DEPTHS,
                   scan_profiles=saved, profile_rulesets=profile_rulesets,
                   available_rulesets=_available_rulesets(db),
                   oob_url=settings_store.get(db, "dast.oob_url") or "",
                   drafts=drafts, drafting=any(d.status == "working" for d in drafts),
                   ai_on=ai.enabled(ai.config(db)))
    return context


@router.api_route("/oob/{token}", methods=["GET", "POST", "HEAD"],
                  include_in_schema=False)
async def oob_callback(token: str, request: Request):
    """The out of band callback.  Public on purpose: a scanned site hits it.

    Records a hit only for a token this product minted, so it cannot be used to
    fill the table, and answers a tiny 200 either way so it gives nothing away.
    """
    from app.core.dast_checks import callback

    detail = f"{request.method} {str(request.url.path)[:120]}"
    callback.record(token, kind="http", source_ip=client_ip(request), detail=detail)
    return Response(content="ok\n", media_type="text/plain")


@router.get("/dast-admin/rule-schema.json")
def dast_rule_schema(user: User = Depends(current_user)):
    """The rule standard as JSON Schema, so any tool or model can draft to it."""
    from pathlib import Path

    with session_scope() as db:
        _guard(db, user)
    path = Path(__file__).resolve().parents[2] / "schema" / "dast_rule.schema.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return FileResponse(str(path), media_type="application/schema+json")


@router.get("/dast-admin")
def dast_admin_page(request: Request, user: User = Depends(current_user)):
    with session_scope() as db:
        _guard(db, user)
        context = _rule_context(db, user)
        context.update(
            flash=clean_notice(request.query_params.get("msg", ""), limit=600),
            flash_kind=notice_class(request.query_params.get("kind", "")),
            draft=request.query_params.get("draft", ""))
        return page(request, "dast_admin.html", **context)


@router.post("/dast-admin/settings")
async def save_dast_settings(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    back = "/dast-admin#tab-settings"
    from app.core import settings_store

    oob = str(form.get("oob_url") or "").strip()[:500]
    if oob and not oob.startswith(("http://", "https://")):
        return redirect(_back(back, "The callback address must start with http:// "
                              "or https://, or be left empty.", "error"))
    with session_scope() as db:
        _guard(db, user)
        settings_store.set_value(db, "dast.oob_url", oob, user.username)
        record(db, "dast.settings_saved", actor=user.username,
               detail="oob_url set" if oob else "oob_url cleared",
               source_ip=client_ip(request))
    return redirect(_back(back, "Saved DAST settings."))


@router.post("/dast-admin/profiles")
async def save_scan_profile(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    back = "/dast-admin#tab-profiles"
    from app.core.dast_checks import profiles
    from app.core.models import DastScanProfile

    with session_scope() as db:
        _guard(db, user)
        name = clean_text(form.get("name"), "Name", limit=80)
        depth = str(form.get("depth") or "premium")
        if depth not in profiles.DEPTHS:
            return redirect(_back(back, "Pick a depth.", "error"))
        chosen = [r for r in form.getlist("rulesets") if r]
        editing = str(form.get("editing") or "")
        clash = db.query(DastScanProfile).filter(
            DastScanProfile.name == name,
            DastScanProfile.id != (int(editing) if editing.isdigit() else 0)).first()
        if clash:
            return redirect(_back(back, f"There is already a profile called {name}.",
                                  "error"))
        row = None
        if editing.isdigit():
            row = db.get(DastScanProfile, int(editing))
        if row is None:
            row = DastScanProfile(created_by=user.username[:120])
            db.add(row)
        row.name = name
        row.depth = depth
        row.rulesets = json.dumps(chosen, ensure_ascii=False)
        row.notes = clean_text(form.get("notes"), "Notes", limit=2000, required=False)
        record(db, "dast.profile_saved", actor=user.username, target=name,
               detail=f"{depth}: {', '.join(chosen) or 'no rulesets'}",
               source_ip=client_ip(request))
    return redirect(_back(back, f"Saved scan profile {name}."))


@router.post("/dast-admin/profiles/{profile_id}/delete")
async def delete_scan_profile(profile_id: int, request: Request,
                              user: User = Depends(current_user)):
    await check_csrf(request)
    back = "/dast-admin#tab-profiles"
    from app.core.models import DastScanProfile

    with session_scope() as db:
        _guard(db, user)
        row = db.get(DastScanProfile, profile_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such profile.")
        name = row.name
        db.delete(row)
        record(db, "dast.profile_deleted", actor=user.username, target=name,
               source_ip=client_ip(request))
    return redirect(_back(back, f"Removed scan profile {name}."))


@router.post("/dast-admin/rules/load")
async def load_curated(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    back = "/dast-admin#tab-rules"
    from app.core.dast_checks import seed

    with session_scope() as db:
        _guard(db, user)
        counts = seed.sync(db)
        record(db, "dast.rules_loaded", actor=user.username,
               detail=f"added {counts['added']}, refreshed {counts['refreshed']}",
               source_ip=client_ip(request))
    return redirect(_back(back, f"Loaded curated rules: {counts['added']} added, "
                          f"{counts['refreshed']} refreshed.  They start disabled, "
                          "so enable the ones you want."))


@router.post("/dast-admin/rules")
async def save_rule(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    back = "/dast-admin#tab-rules"
    from app.core.dast_checks import spec as spec_mod
    from app.core.models import DastRule

    with session_scope() as db:
        _guard(db, user)
        raw = str(form.get("spec") or "").strip()
        try:
            data = json.loads(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            return redirect(_back(back, f"The rule is not valid JSON: {exc}", "error"))
        try:
            clean = spec_mod.validate(data)
        except spec_mod.SpecError as exc:
            return redirect(_back(back, f"The rule did not meet the standard: {exc}",
                                  "error"))
        existing = db.query(DastRule).filter(
            DastRule.rule_id == clean["id"]).first()
        editing = str(form.get("editing") or "")
        if existing and str(existing.id) != editing:
            return redirect(_back(back, f"There is already a rule called "
                                  f"{clean['id']}.", "error"))
        row = existing or DastRule(rule_id=clean["id"], created_by=user.username[:120],
                                   origin=str(form.get("origin") or "custom")[:16])
        row.rule_class = clean["class"]
        row.title = clean["title"][:300]
        row.safety = clean["safety"]
        row.severity_floor = clean["severity_floor"]
        row.spec = json.dumps(clean, ensure_ascii=False)
        row.updated_by = user.username[:120]
        if existing:
            row.version = (row.version or 1) + 1
        else:
            db.add(row)
        record(db, "dast.rule_saved", actor=user.username, target=clean["id"],
               detail=clean["class"], source_ip=client_ip(request))
        # If this came from an AI draft, the draft has served its purpose.
        from_draft = str(form.get("from_draft") or "")
        if from_draft.isdigit():
            from app.core.models import DastRuleDraft

            draft = db.get(DastRuleDraft, int(from_draft))
            if draft is not None:
                db.delete(draft)
    return redirect(_back(back, f"Saved rule {clean['id']}."))


@router.post("/dast-admin/rules/bulk")
async def bulk_rules(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    back = "/dast-admin#tab-rules"
    from app.core.models import DastRule

    action = str(form.get("action") or "")
    if action not in ("enable", "disable"):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    want = action == "enable"
    only_class = str(form.get("rule_class") or "").strip()
    ids = [int(v) for v in form.getlist("rule_id") if str(v).isdigit()]
    with session_scope() as db:
        _guard(db, user)
        query = db.query(DastRule)
        if ids:
            query = query.filter(DastRule.id.in_(ids))
        elif only_class:
            query = query.filter(DastRule.rule_class == only_class)
        else:
            return redirect(_back(back, "Nothing was selected.", "error"))
        changed = 0
        for row in query.all():
            if row.enabled != want:
                row.enabled = want
                changed += 1
        record(db, "dast.rules_bulk", actor=user.username,
               target=only_class or f"{len(ids)} rules", detail=action,
               source_ip=client_ip(request))
    verb = "Enabled" if want else "Disabled"
    return redirect(_back(back, f"{verb} {changed} rule{'' if changed == 1 else 's'}."))


@router.post("/dast-admin/rules/{rule_db_id}/{action}")
async def rule_action(rule_db_id: int, action: str, request: Request,
                      user: User = Depends(current_user)):
    await check_csrf(request)
    back = "/dast-admin#tab-rules"
    from app.core.models import DastRule

    with session_scope() as db:
        _guard(db, user)
        row = db.get(DastRule, rule_db_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such rule.")
        name = row.rule_id
        if action in ("enable", "disable"):
            row.enabled = action == "enable"
            row.updated_by = user.username[:120]
            record(db, "dast.rule_toggled", actor=user.username, target=name,
                   detail=action, source_ip=client_ip(request))
            return redirect(_back(back, f"{action.title()}d {name}."))
        if action == "delete":
            db.delete(row)
            record(db, "dast.rule_deleted", actor=user.username, target=name,
                   source_ip=client_ip(request))
            return redirect(_back(back, f"Removed {name}."))
        raise HTTPException(status_code=404, detail=NOT_FOUND)


@router.post("/dast-admin/rules/ai")
async def ai_draft_rule(request: Request, user: User = Depends(current_user)):
    await check_csrf(request)
    form = await request.form()
    back = "/dast-admin#tab-rules"
    from app.core import ai
    from app.core.dast_checks import generate

    prompt = str(form.get("prompt") or "").strip()
    with session_scope() as db:
        _guard(db, user)
        cfg = ai.config(db)
        if not ai.enabled(cfg):
            return redirect(_back(back, "The built in AI is off.  Turn it on in "
                                  "Settings to draft a rule from a prompt.", "error"))
    if not prompt:
        return redirect(_back(back, "Say what the rule should detect.", "error"))
    # The model can be slow, so it runs in the background.  The draft shows up
    # under Drafted rules when it is done; this returns at once.
    generate.start_draft(cfg, prompt, user.username)
    with session_scope() as db:
        record(db, "dast.rule_ai_draft", actor=user.username, target=prompt[:120],
               outcome="started", source_ip=client_ip(request))
    return redirect(_back(back, "Drafting a rule.  It shows up under Drafted "
                          "rules below when it is ready; the page refreshes "
                          "until then."))


@router.post("/dast-admin/drafts/{draft_id}/delete")
async def delete_draft(draft_id: int, request: Request,
                       user: User = Depends(current_user)):
    await check_csrf(request)
    from app.core.models import DastRuleDraft

    with session_scope() as db:
        _guard(db, user)
        row = db.get(DastRuleDraft, draft_id)
        if row is not None:
            db.delete(row)
    return redirect(_back("/dast-admin#tab-rules", "Dismissed the draft."))


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
            details = external.clean_details(_api_details(body), envs=external.environments(db), profile_names=external.saved_profile_names(db))
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
                keep_env=asset.environment, profile_names=external.saved_profile_names(db)))
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
    for key in ("frequency", "time_of_day", "run_on", "profile", "ias_config"):
        if body.get(key) is not None and not isinstance(body[key], str):
            raise HTTPException(status_code=400, detail=f"{key} has to be a string.")
    with session_scope() as db:
        me = _api_me(db, caller)
        asset = _asset(db, asset_id)
        if external.blocked(db, asset):
            raise HTTPException(status_code=409, detail="This site may not be scanned.")
        on_ias = bool(body.get("ias_config"))
        profile = "" if on_ias else (body.get("profile") or external.profile_for(asset))
        if (on_ias or profile in dast_engines.ACTIVE_PROFILES
                or (body.get("authenticated") is True and profile != "baseline")) \
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
