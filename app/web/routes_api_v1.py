"""The JSON API, for editors and pipelines.

Everything else in this app talks to a browser: form posts, redirects, a
session cookie and a CSRF token.  None of that works from an editor plugin or a
CI job, so this is a separate door with its own lock.

Three rules hold it together.

A token is a person.  Every request resolves to the account that made the
token, and the same scope rules apply, so a developer's plugin sees the
repositories that developer was given and nothing else.

Almost nothing here changes anything.  A review is worked out and thrown
away; it is never written to the database, never becomes a finding somebody
has to waive, and never touches a scan.  The one write is a request for an
exception, and it stays a request until somebody approves it in a browser.

Code arrives in the request and leaves in the response.  It is written to a
temporary directory, looked at, and deleted.  Nothing is kept.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.config import VERSION
from app.core.db import session_scope

log = logging.getLogger("gcr.api")

router = APIRouter(prefix="/api/v1")

# What a client may send in one request.  A review is meant to be the file
# somebody is editing, or the diff of a branch, not a repository.
MAX_FILES = 200
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
REVIEW_TIMEOUT = 120

GHSCAN = Path(__file__).resolve().parents[2] / "bin" / "ghscan"


class Caller:
    """Who is asking, and what they may do."""

    def __init__(self, token, user):
        self.token = token
        self.user = user


def _bearer(authorization: str = Header(default="")) -> str:
    parts = (authorization or "").split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Send a token: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"})
    return parts[1].strip()


def caller_for(scope: str):
    """A dependency that resolves a token to the person behind it."""

    def resolve(request: Request, presented: str = Depends(_bearer)) -> Caller:
        from app.core import api_tokens
        from app.web.security import client_ip

        with session_scope() as db:
            token, user = api_tokens.verify(db, presented, scope=scope,
                                            source_ip=client_ip(request))
            if token is None:
                # One answer for expired, revoked, unknown and wrong scope.
                # Telling a caller which of those it was only helps somebody
                # working through a list of guesses.
                raise HTTPException(
                    status_code=401, detail="That token will not do.",
                    headers={"WWW-Authenticate": "Bearer"})
            db.expunge(token)
            db.expunge(user)
        return Caller(token, user)

    return resolve


def _iso(stamp: float) -> str:
    """A file's timestamp, in the one format everything downstream can read."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(stamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _safe_path(raw: str) -> str:
    """A path from a request, made safe to write under a directory we chose.

    Anything absolute, anything with a parent reference and anything with a
    drive letter is refused rather than cleaned up, because a request that
    contains one is not a mistake worth guessing at.
    """
    text = (raw or "").strip().replace("\\", "/")
    if not text:
        raise HTTPException(status_code=400, detail="A file needs a path.")
    if text.startswith("/") or text.startswith("~") or ":" in text.split("/")[0]:
        raise HTTPException(status_code=400, detail=f"Path must be relative: {raw!r}")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise HTTPException(status_code=400, detail=f"Path may not climb out: {raw!r}")
    if len(parts) > 40:
        raise HTTPException(status_code=400, detail="That path is unreasonably deep.")
    return "/".join(parts)


# The files a scan produced, whole.
#
# Every other endpoint here takes something the caller already has and gives an
# opinion about it.  This one hands over the estate: vulnerabilities.json is
# every finding in every organization on the install, and an SBOM names every
# repository and what each is built from.
#
# So it is gated three times over, and the layers are deliberately different
# kinds of check rather than three spellings of one.  The token must carry the
# reports scope, which no editor token has.  The person behind it must see
# everything, because a token is its owner with less of them and a scoped
# reader must not get by a file what the screen refuses them.  And the name has
# to be one of a fixed list, so no request decides what gets read off disk.
REPORT_FILES = {
    "vulnerabilities.json": "application/json",
    "vulnerabilities.csv": "text/csv",
    "vex.openvex.json": "application/json",
    "vex.cyclonedx.json": "application/json",
    "sbom.cdx.json": "application/json",
    "sbom.spdx.json": "application/json",
    "sbom-summary.json": "application/json",
}


def _report_files(directory):
    """-> {name: media type} for everything a scan actually wrote.

    The seven above, plus one per repository under the SBOM directory, because
    "give me the SBOM for this repository" is the question somebody answering a
    customer actually has and the combined file is the wrong shape for it.

    Built from the directory rather than fixed, so a per repository name never
    has to be guessed at, and every name is still one this function put in the
    set: a request chooses from the list, it does not describe a path.
    """
    from app.core.reports import SBOM_DIRECTORY

    known = dict(REPORT_FILES)
    nested = directory / SBOM_DIRECTORY
    if nested.is_dir():
        for child in nested.iterdir():
            if child.is_file() and child.suffix == ".json":
                known["%s/%s" % (SBOM_DIRECTORY, child.name)] = "application/json"
    return known


@router.get("/reports")
def list_reports(caller=Depends(caller_for("reports"))):
    """What is there to fetch, and how old each one is."""
    from app.core import rbac
    from app.core import reports as reports_mod

    # report.files, the permission the Reports page itself asks for, rather
    # than sees_everything, which readers pass too: the roles document gives
    # these files to administrators only.
    if not rbac.can(caller.user, "report.files"):
        raise HTTPException(status_code=403,
                            detail="These files cover every organization on "
                                   "this install, so they need an account "
                                   "allowed the report files.")
    with session_scope() as db:
        directory = reports_mod.output_dir(db)

    out = []
    for name in sorted(_report_files(directory)):
        path = directory / name
        if not path.is_file():
            continue
        stat = path.stat()
        out.append({"name": name, "bytes": stat.st_size,
                    "written_at": _iso(stat.st_mtime)})
    return {"reports": out}


@router.get("/reports/{name:path}")
def download_one_report(name: str, caller=Depends(caller_for("reports"))):
    """One report file, as it is on disk."""
    from fastapi.responses import FileResponse

    from app.core import rbac
    from app.core import reports as reports_mod

    # report.files, the permission the Reports page itself asks for, rather
    # than sees_everything, which readers pass too: the roles document gives
    # these files to administrators only.
    if not rbac.can(caller.user, "report.files"):
        raise HTTPException(status_code=403,
                            detail="These files cover every organization on "
                                   "this install, so they need an account "
                                   "allowed the report files.")
    # Matched against the list rather than cleaned up.  A name that is not on
    # it is refused whatever it looks like, so nothing here has to reason about
    # dots and slashes.
    with session_scope() as db:
        directory = reports_mod.output_dir(db)

    media = _report_files(directory).get(name)
    if media is None:
        raise HTTPException(
            status_code=404,
            detail="No such report.  Ask /api/v1/reports for the list.")
    path = directory / name
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="That report has not been written yet.  It appears after "
                   "the first scan that finishes.")
    return FileResponse(str(path), media_type=media, filename=name)


@router.get("/ping")
def ping(caller: Caller = Depends(caller_for(""))) -> JSONResponse:
    """Somewhere for a client to check its token without doing any work.

    Any live token will do.  A pipeline holding only the reports scope needs
    a way to check its token too.
    """
    return JSONResponse({
        "ok": True,
        "version": VERSION,
        "user": caller.user.username,
        "scopes": sorted({s.strip() for s in (caller.token.scopes or "").split(",")}),
        "expires_at": (caller.token.expires_at.isoformat()
                       if caller.token.expires_at else None),
    })


@router.get("/rules")
def rules(request: Request,
          caller: Caller = Depends(caller_for("rules"))) -> JSONResponse:
    """What this installation treats as noise, so a client can agree with it.

    Sent with an ETag because a plugin asks for this on every start and the
    answer changes about once a month.
    """
    from app.core import exclusions as exclusions_store
    from app.core import rbac, rule_mutes, triage_rules

    with session_scope() as db:
        effective = triage_rules.effective(db)
        body = {
            "version": VERSION,
            "triage": {
                "value_patterns": effective["value"],
                "path_patterns": effective["path"],
            },
            "muted_rules": rule_mutes.effective(db),
            # Only the ones this account may see.  An exclusion names a
            # repository, and a repository is not everybody's business.
            "exclusions": exclusions_store.as_dicts(
                db, rules=exclusions_store.visible(db, _me(db, caller))),
        }
        # A client needs what an exclusion matches, not why it exists.  The
        # reason, the ticket and who reviewed it are the decision itself,
        # which the Exclusions page keeps to administrators; through here
        # every role could read them.
        if not rbac.can(caller.user, "exclusion.read"):
            for row in body["exclusions"]:
                for private in ("reason", "ticket", "reviewed_by", "reviewed_date"):
                    row.pop(private, None)

    payload = json.dumps(body, sort_keys=True, default=str)
    etag = '"' + hashlib.sha256(payload.encode()).hexdigest()[:32] + '"'
    if request.headers.get("if-none-match") == etag:
        return JSONResponse(status_code=304, content=None,
                            headers={"ETag": etag, "Cache-Control": "no-cache"})
    return JSONResponse(json.loads(payload),
                        headers={"ETag": etag, "Cache-Control": "no-cache"})


@router.post("/review")
async def review(request: Request,
                 caller: Caller = Depends(caller_for("review"))) -> JSONResponse:
    """Look at some code and say what is wrong with it.

    The code comes in the request and goes back out in the response.  Nothing
    is written to the database, so a review never becomes a finding somebody
    has to explain, and a client can call this on every save.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Send JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Send an object.")

    files = body.get("files")
    if not isinstance(files, list) or not files:
        raise HTTPException(
            status_code=400,
            detail='Send {"files": [{"path": "a/b.py", "content": "..."}]}')
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=413,
                            detail=f"That is more than {MAX_FILES} files.")

    only = str(body.get("only", "secrets,code")).strip() or "secrets,code"
    if any(part not in {"secrets", "code"} for part in only.split(",")):
        raise HTTPException(status_code=400, detail="only is secrets, code, or both.")

    workdir = tempfile.mkdtemp(prefix="gcr-review-")
    try:
        total = 0
        for entry in files:
            if not isinstance(entry, dict):
                raise HTTPException(status_code=400, detail="Each file is an object.")
            relative = _safe_path(entry.get("path", ""))
            content = entry.get("content")
            if not isinstance(content, str):
                raise HTTPException(
                    status_code=400,
                    detail=f"{relative}: content has to be a string.")
            raw = content.encode("utf-8", "replace")
            if len(raw) > MAX_FILE_BYTES:
                raise HTTPException(status_code=413, detail=f"{relative} is too large.")
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise HTTPException(status_code=413,
                                    detail="That is more than this will look at at once.")
            target = Path(workdir) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)

        completed = subprocess.run(
            [str(GHSCAN), "review", workdir, "--only", only, "--fail-on", "none"],
            capture_output=True, text=True, timeout=REVIEW_TIMEOUT,
            env={**os.environ, "GHSCAN_LOG_LEVEL": "warn"})

        if completed.returncode not in (0, 3) or not completed.stdout.strip():
            tail = (completed.stderr or "").strip().splitlines()[-3:]
            log.error("review failed for %s: %s", caller.user.username, tail)
            raise HTTPException(status_code=500,
                                detail="The review did not finish.")
        try:
            result = json.loads(completed.stdout)
        except ValueError:
            raise HTTPException(status_code=500,
                                detail="The review produced nothing readable.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504,
                            detail="The review took too long and was stopped.")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # The directory it ran in is ours, not the caller's, and saying where it
    # was tells them nothing useful and us something we would rather not.
    result.pop("reviewed", None)
    for finding in result.get("findings", []):
        path = finding.get("file", "")
        if path.startswith(workdir):
            finding["file"] = path[len(workdir):].lstrip("/")

    return JSONResponse(result)


# --- Your own slice of the data -------------------------------------------
#
# The report files above are the whole estate, so they stay with the people
# who may read the whole estate.  Everything below is the same data cut down
# to what the person behind the token can open on the screen.  Each endpoint
# starts from the rbac query the matching page starts from, so a token can
# never reach a repository its owner could not click on.
#
# One thing a token may write: a request for an exception.  It is only ever a
# request, even on an administrator's token.  A token that leaks should not be
# able to take findings out of the report files, so the approval still has to
# happen in a browser, with a second factor behind it.

MAX_PAGE = 1000
DEFAULT_PAGE = 100


def _me(db, caller):
    """The token's owner, loaded in this session.

    The one on the caller was read in another session and let go, so its
    scanning groups cannot be loaded from it.  The scope filter needs them, so
    every scoped endpoint asks for the person again here.
    """
    from app.core.models import User

    user = db.get(User, caller.user.id)
    if user is None or user.disabled:
        raise HTTPException(status_code=401, detail="That token will not do.",
                            headers={"WWW-Authenticate": "Bearer"})
    return user



def _require(user, permission: str) -> None:
    from app.core import rbac

    if not rbac.can(user, permission):
        raise HTTPException(status_code=403,
                            detail="Your account is not allowed that.")


def _paging(params) -> tuple:
    try:
        limit = int(params.get("limit", DEFAULT_PAGE))
        offset = int(params.get("offset", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400,
                            detail="limit and offset are whole numbers.")
    if limit < 1 or limit > MAX_PAGE:
        raise HTTPException(status_code=400,
                            detail=f"limit is between 1 and {MAX_PAGE}.")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset cannot be negative.")
    return limit, offset


def _stamp(value) -> str:
    if value is None:
        return None
    from datetime import timezone

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _exception_dict(waiver, finding=None) -> dict:
    out = {
        "id": waiver.id,
        "finding": waiver.finding_id,
        "status": getattr(waiver.status, "value", str(waiver.status or "")),
        "category": waiver.category or "",
        "reason": waiver.reason or "",
        "ticket": waiver.ticket or "",
        "requested_by": waiver.requested_by or "",
        "requested_at": _stamp(waiver.requested_at),
        "expires_at": _stamp(waiver.expires_at),
        "decided_by": waiver.decided_by or "",
        "decided_at": _stamp(waiver.decided_at),
        "decision_note": waiver.decision_note or "",
    }
    if finding is not None:
        out["vuln_id"] = finding.vuln_id or ""
        out["repository"] = finding.repository or ""
        out["title"] = finding.title or ""
    return out


def _own_waiver(user, waiver):
    """The waiver, or None when this person may not read it.

    The same rule as the Exceptions page: somebody who cannot approve one sees
    only their own, because an exception is an argument a person made.
    """
    from app.core import rbac

    if waiver is None:
        return None
    if rbac.can(user, "waiver.approve"):
        return waiver
    if (waiver.requested_by or "").lower() == (user.username or "").lower():
        return waiver
    return None


def _ai_reviews(db, rows) -> dict:
    """{finding id: what the AI said that still holds}, for a page of rows.

    The newest model answer that still stands, the same one the security
    report quotes: an answer about code that has since changed is left out.
    Failing that, the learned rule that graded it, which carries a reason but
    no fix.  A finding nobody asked about has no entry.
    """
    from app.core import assessment
    from app.core.models import AIGrade

    out = {}
    if not rows:
        return out
    for finding_id, said in assessment.validations(db, rows).items():
        out[finding_id] = {
            "source": "analysis",
            "rating": said["rating"],
            "severity": said["severity"],
            "confidence": said["confidence"],
            "model": said["model"],
            "reviewed_at": _stamp(said.get("created_at")),
            "summary": said["what"],
            "why": said["why"],
            "fix": said["fix"],
            "what_to_check": said.get("check", ""),
            "compensating_controls": said.get("controls", ""),
        }
    ids = [r.id for r in rows if r.id not in out]
    for start in range(0, len(ids), 500):
        for grade in (db.query(AIGrade)
                      .filter(AIGrade.finding_id.in_(ids[start:start + 500]),
                              AIGrade.rule_id.isnot(None))
                      .order_by(AIGrade.created_at.asc(), AIGrade.id.asc())):
            sev = getattr(grade.severity, "value", str(grade.severity or ""))
            out[grade.finding_id] = {
                "source": "learned_rule",
                "rule": grade.rule_id,
                "rating": sev.upper(),
                "severity": sev,
                "reviewed_at": _stamp(grade.created_at),
                "why": grade.reason or "",
                "fix": "",
            }
    return out


def _finding_dicts(db, user, rows) -> list:
    """The API's view of a page of findings.  Lookups are made once per page."""
    from app.core.models import Waiver
    from app.core.reports import as_dict, repo_facts

    if not rows:
        return []
    facts = repo_facts(db, rows)
    ids = [r.id for r in rows]
    waivers = {}
    for start in range(0, len(ids), 500):
        for w in db.query(Waiver).filter(Waiver.finding_id.in_(ids[start:start + 500])):
            waivers[w.finding_id] = w
    reviews = _ai_reviews(db, rows)

    out = []
    for finding in rows:
        body = {"id": finding.id}
        body.update(as_dict(finding, facts))
        body["excepted"] = bool(finding.excepted)
        waiver = _own_waiver(user, waivers.get(finding.id))
        body["exception"] = _exception_dict(waiver) if waiver else None
        body["ai_reviewed"] = finding.id in reviews
        body["ai_review"] = reviews.get(finding.id)
        out.append(body)
    return out


@router.get("/findings")
def list_findings(request: Request,
                  caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Findings, filtered the way the Findings page filters them."""
    from app.core.models import Finding
    from app.web.routes_pages import _filtered_findings, _priority_order

    _require(caller.user, "findings.read")
    params = request.query_params
    limit, offset = _paging(params)

    with session_scope() as db:
        me = _me(db, caller)
        query = _filtered_findings(db, me, params)
        total = query.order_by(None).count()
        rows = (query.order_by(_priority_order(), Finding.last_found_at.desc(),
                               Finding.id.asc())
                .offset(offset).limit(limit).all())
        findings = _finding_dicts(db, me, rows)

    return JSONResponse({"total": total, "limit": limit, "offset": offset,
                         "count": len(findings), "findings": findings})


@router.get("/findings/{finding_id}")
def one_finding(finding_id: int,
                caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """One finding, if it is yours to see.  Otherwise it does not exist."""
    from app.core import rbac

    _require(caller.user, "findings.read")
    with session_scope() as db:
        me = _me(db, caller)
        row = rbac.visible_finding(db, me, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        return JSONResponse(_finding_dicts(db, me, [row])[0])


@router.get("/exceptions")
def list_exceptions(request: Request,
                    caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Exceptions on findings you can see.  Only your own, unless you approve them."""
    from datetime import datetime, timezone

    from app.core import rbac
    from app.core.models import Finding, Waiver

    _require(caller.user, "findings.read")
    params = request.query_params
    limit, offset = _paging(params)
    wanted = (params.get("status", "") or "").strip().lower()
    if wanted not in {"", "requested", "approved", "rejected", "revoked", "expired"}:
        raise HTTPException(
            status_code=400,
            detail="status is requested, approved, rejected, revoked or expired.")

    with session_scope() as db:
        me = _me(db, caller)
        shown = rbac.visible_findings(db, me)
        if not rbac.can(me, "repo.scope"):
            shown = shown.filter(Finding.out_of_scope.is_(False))
        base = db.query(Waiver).filter(
            Waiver.finding_id.in_(shown.with_entities(Finding.id).scalar_subquery()))
        if not rbac.can(me, "waiver.approve"):
            base = base.filter(Waiver.requested_by == me.username)
        if wanted == "expired":
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            base = base.filter(Waiver.expires_at.isnot(None),
                               Waiver.expires_at < now)
        elif wanted:
            base = base.filter(Waiver.status == wanted)

        total = base.count()
        rows = (base.order_by(Waiver.requested_at.desc(), Waiver.id.desc())
                .offset(offset).limit(limit).all())
        findings = {f.id: f for f in db.query(Finding).filter(
            Finding.id.in_([w.finding_id for w in rows])).all()} if rows else {}
        out = [_exception_dict(w, findings.get(w.finding_id)) for w in rows]

    return JSONResponse({"total": total, "limit": limit, "offset": offset,
                         "count": len(out), "exceptions": out})


@router.post("/findings/{finding_id}/exceptions")
async def ask_for_exception(finding_id: int, request: Request,
                            caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Ask for an exception on one finding.  It waits for an administrator."""
    from app.core import rbac
    from app.core.audit import record
    from app.core.models import (FindingKind, Waiver, WaiverStatus, utcnow)
    from app.web.routes_api import _parse_expiry, _waiver_category
    from app.web.security import clean_text, client_ip

    _require(caller.user, "waiver.request")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Send JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Send an object.")
    for field in ("reason", "expires", "ticket", "category"):
        if body.get(field) is not None and not isinstance(body.get(field), str):
            raise HTTPException(status_code=400,
                                detail=f"{field} has to be a string.")

    reason = clean_text(body.get("reason", ""), "Reason", limit=2000)
    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say a bit more about why this is acceptable, at least 20 characters.")
    ticket = clean_text(body.get("ticket", ""), "Ticket", limit=120, required=False)
    expires_at = _parse_expiry(body.get("expires", ""))
    category = _waiver_category(body.get("category", ""))

    with session_scope() as db:
        me = _me(db, caller)
        finding = rbac.visible_finding(db, me, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        if category == "not_deployed" and finding.kind == FindingKind.CREDENTIAL:
            raise HTTPException(status_code=400, detail=(
                "A credential works wherever it was pushed, deployed or not.  "
                "Rotate it, or ask for an accepted risk exception instead."))

        existing = db.query(Waiver).filter(
            Waiver.finding_id == finding.id).one_or_none()
        if existing is not None and existing.status in {
                WaiverStatus.REQUESTED, WaiverStatus.APPROVED}:
            raise HTTPException(status_code=409,
                                detail="There is already an exception on this one.")

        waiver = existing or Waiver(finding_id=finding.id)
        waiver.reason = reason
        waiver.ticket = ticket
        waiver.category = category
        waiver.requested_by = caller.user.username
        waiver.requested_at = utcnow()
        waiver.expires_at = expires_at
        waiver.status = WaiverStatus.REQUESTED
        waiver.decided_by = ""
        waiver.decided_at = None
        waiver.decision_note = ""
        if existing is None:
            db.add(waiver)
        db.flush()

        record(db, "waiver.requested", actor=caller.user.username,
               target=finding.fingerprint,
               detail=(f"{finding.repository} {finding.file_path} until "
                       f"{expires_at:%Y-%m-%d} (api token {caller.token.prefix})"
                       + (" (not deployed)" if category else "")),
               source_ip=client_ip(request))
        out = _exception_dict(waiver, finding)

    return JSONResponse(status_code=201, content=out)


@router.get("/repositories")
def list_repositories(request: Request,
                      caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """The repositories you can see, and whether an SBOM is on file for each."""
    from app.core import rbac
    from app.core import reports as reports_mod
    from app.core.models import Repository

    _require(caller.user, "repo.read")
    params = request.query_params
    limit, offset = _paging(params)
    organization = (params.get("org", "") or "").strip()[:255]

    with session_scope() as db:
        me = _me(db, caller)
        query = rbac.visible_repositories(db, me)
        if organization:
            query = query.filter(Repository.organization == organization)
        total = query.count()
        rows = (query.order_by(Repository.full_name.asc())
                .offset(offset).limit(limit).all())
        on_file = _sbom_slugs(reports_mod.output_dir(db))
        out = [{
            "full_name": r.full_name,
            "organization": r.organization or "",
            "default_branch": r.default_branch or "",
            "archived": bool(r.archived),
            "last_scanned_at": _stamp(r.last_scanned_at),
            "sbom": sorted(on_file.get(_slug(r.full_name), {})),
        } for r in rows]

    return JSONResponse({"total": total, "limit": limit, "offset": offset,
                         "count": len(out), "repositories": out})


SBOM_FORMATS = {"cdx": "CycloneDX", "spdx": "SPDX"}


def _slug(full_name: str) -> str:
    """The file name the scanner gives a repository's SBOM.  See slugify in lib/common.sh."""
    text = (full_name or "").replace("/", "__")
    for ch in ":@ ":
        text = text.replace(ch, "_")
    return text


def _sbom_slugs(directory) -> dict:
    """-> {slug: {format: path}} for every per repository SBOM on disk."""
    from app.core.reports import SBOM_DIRECTORY

    found = {}
    nested = directory / SBOM_DIRECTORY
    if not nested.is_dir():
        return found
    for child in nested.iterdir():
        if not child.is_file():
            continue
        for fmt in SBOM_FORMATS:
            suffix = f".{fmt}.json"
            if child.name.endswith(suffix):
                found.setdefault(child.name[:-len(suffix)], {})[fmt] = child
    return found


@router.get("/sbom")
def list_sboms(caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Per repository SBOMs on file, for the repositories you can see."""
    from app.core import rbac
    from app.core import reports as reports_mod
    from app.core.models import Repository

    _require(caller.user, "repo.read")
    with session_scope() as db:
        me = _me(db, caller)
        names = [n for (n,) in rbac.visible_repositories(db, me)
                 .with_entities(Repository.full_name).all() if n]
        on_file = _sbom_slugs(reports_mod.output_dir(db))

    out = []
    for name in sorted(set(names)):
        for fmt, path in sorted(on_file.get(_slug(name), {}).items()):
            stat = path.stat()
            out.append({"repository": name, "format": fmt,
                        "bytes": stat.st_size, "written_at": _iso(stat.st_mtime)})
    return JSONResponse({"count": len(out), "sboms": out})


@router.get("/sbom/{repository:path}")
def one_sbom(repository: str, format: str = "cdx",
             caller: Caller = Depends(caller_for("reports"))):
    """One repository's SBOM, if you can see the repository."""
    from fastapi.responses import FileResponse

    from app.core import rbac
    from app.core import reports as reports_mod
    from app.core.models import Repository

    _require(caller.user, "repo.read")
    fmt = (format or "cdx").strip().lower()
    if fmt not in SBOM_FORMATS:
        raise HTTPException(status_code=400, detail="format is cdx or spdx.")
    wanted = (repository or "").strip()

    with session_scope() as db:
        me = _me(db, caller)
        # Matched against the names this person may see, never turned into a
        # path on its own, so nothing in the request decides what is read.
        seen = (rbac.visible_repositories(db, me)
                .filter(Repository.full_name == wanted)
                .with_entities(Repository.full_name).first())
        directory = reports_mod.output_dir(db)
    if seen is None:
        raise HTTPException(status_code=404, detail="No such repository.")
    path = _sbom_slugs(directory).get(_slug(seen[0]), {}).get(fmt)
    if path is None:
        raise HTTPException(
            status_code=404,
            detail="No SBOM on file for that repository yet.  One is written "
                   "the next time a scan reads it.")
    return FileResponse(str(path), media_type="application/json",
                        filename=path.name)


TREND_WINDOWS = (1, 7, 30, 90, 365)


@router.get("/trends")
def trend_lines(request: Request,
                caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Daily counts by severity, narrowed to what you can see."""
    from datetime import datetime, timedelta, timezone

    from app.core import rbac, trends
    from app.web.security import clean_text

    _require(caller.user, "trend.read")
    params = request.query_params

    basis = (params.get("basis", "actions") or "actions").strip().lower()
    if basis not in ("actions", "advisories"):
        raise HTTPException(status_code=400, detail="basis is actions or advisories.")
    try:
        window = int(params.get("days", "30"))
    except ValueError:
        window = 0
    if window not in TREND_WINDOWS:
        raise HTTPException(status_code=400,
                            detail="days is one of 1, 7, 30, 90 or 365.")
    organization = clean_text(params.get("org", ""), "Organization",
                              limit=255, required=False)
    repository = clean_text(params.get("repo", ""), "Repository",
                            limit=320, required=False)
    branch = clean_text(params.get("branch", ""), "Branch",
                        limit=255, required=False)
    connection = clean_text(params.get("connection", ""), "Connection",
                            limit=120, required=False)
    if repository and "/" in repository:
        organization = repository.split("/")[0]

    since = datetime.now(timezone.utc) - timedelta(days=window)
    with session_scope() as db:
        me = _me(db, caller)
        base = rbac.visible_trends(db, me)
        scope = {"organization": organization, "repository": repository,
                 "branch": branch, "connection": connection, "since": since}
        points = trends.series(db, basis=basis, base=base, **scope)
        grid = trends.heatmap(db, basis=basis, base=base, **scope)

    for point in points:
        point["day"] = point["day"].strftime("%Y-%m-%d") if point["day"] else None
    if grid.get("day") is not None:
        grid["day"] = grid["day"].strftime("%Y-%m-%d")

    return JSONResponse({
        "basis": basis, "days": window,
        "filters": {"org": organization, "repo": repository,
                    "branch": branch, "connection": connection},
        "series": points,
        "breakdown": grid,
    })


# --- Before a deploy --------------------------------------------------------
#
# A deploy script wants one question answered: is there anything on this
# repository and branch that has to be fixed first.  This answers it from what
# the scans already found, so it takes a second rather than the minutes a gate
# run takes.  It does not read new code.  For a change that has not been
# scanned yet, the pull request gate is the right tool.
#
# Findings are sorted into areas, because "fix the build" and "upgrade a
# package" are different jobs for different people:
#   package  a vulnerable package the application ships with
#   image    a vulnerable package in a container image
#   build    a problem in how it is built: a CI workflow, a Dockerfile, a
#            build script, or a package only the build and tests pull in
#   config   any other misconfiguration, such as infrastructure as code
#   credential, code  the other two kinds, only when asked for

CHECK_AREAS = ("package", "image", "build", "config", "credential", "code")
CHECK_DEFAULT_AREAS = ("package", "image", "build")
CHECK_LIMIT = 5000
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
                 "unknown": 0}

# Files that describe how something is built or shipped rather than what it
# does.  Matched on the path, lower case.
BUILD_NAMES = ("dockerfile", "containerfile", "jenkinsfile", "makefile",
               ".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml",
               "azure-pipelines.yaml", "bitbucket-pipelines.yml",
               "buildspec.yml", "buildspec.yaml", "cloudbuild.yaml",
               "cloudbuild.yml", ".travis.yml", "appveyor.yml",
               "docker-compose.yml", "docker-compose.yaml", "compose.yml",
               "compose.yaml", "skaffold.yaml", "taskfile.yml")
BUILD_DIRS = (".github/workflows/", ".github/actions/", ".circleci/",
              ".buildkite/", ".tekton/", ".drone", "ci/", ".ci/")


def _is_build_file(path: str) -> bool:
    text = (path or "").replace("\\", "/").lower()
    if not text:
        return False
    if any(("/" + text).find("/" + d) >= 0 for d in BUILD_DIRS):
        return True
    base = text.rsplit("/", 1)[-1]
    if base in BUILD_NAMES:
        return True
    # Dockerfile.prod, api.Dockerfile and the like.
    return "dockerfile" in base or "containerfile" in base


def _area(finding) -> str:
    kind = getattr(finding.kind, "value", str(finding.kind or "")).lower()
    if kind == "dependency":
        if finding.image_ref:
            return "image"
        if (finding.dependency_scope or "").lower() == "development":
            return "build"
        if _is_build_file(finding.manifest_path or ""):
            return "build"
        return "package"
    if kind == "misconfiguration":
        return "build" if _is_build_file(finding.file_path) else "config"
    return "credential" if kind == "credential" else "code"


CREDENTIAL_FIX = ("Rotate this credential at its provider first, then take it out of "
                  "the code and load it from a secret store.  Deleting the line is not "
                  "enough on its own: the old value stays in the git history.")


def _check_row(finding, area: str, blocking: bool, why: str, link: str,
               review: dict = None) -> dict:
    kind = getattr(finding.kind, "value", str(finding.kind or "")).lower()
    severity = getattr(finding.severity, "value", str(finding.severity or "")).lower()
    row = {
        "id": finding.id,
        "vuln_id": finding.vuln_id or "",
        "area": area,
        "kind": kind,
        "severity": severity,
        "blocking": blocking,
        "why": why,
        "title": finding.title or "",
        "branch": finding.branch or "",
        # From the repository root.  Some manifest paths are stored with a
        # leading slash, and tools matching a path to a file do not want one.
        "file": ((finding.manifest_path or finding.file_path or "") if kind == "dependency"
                 else (finding.file_path or "")).lstrip("/"),
        "line": finding.line or 0,
        "rule": finding.rule or "",
        "known_exploited": bool(finding.known_exploited),
        "malicious": bool(finding.malicious),
        "link": link,
    }
    if kind == "dependency":
        row["package"] = {
            "name": finding.package_name or "",
            "version": finding.package_version or "",
            "ecosystem": finding.ecosystem or "",
            "fixed_in": finding.fixed_in or "",
            "scope": finding.dependency_scope or "unknown",
            "image": finding.image_ref or "",
        }
        row["vulnerability"] = finding.vulnerability_id or ""
        row["fix"] = (f"Upgrade {finding.package_name} to {finding.fixed_in} or later."
                      if finding.fixed_in else
                      "No fixed version is published yet.  Remove or replace the package, "
                      "or ask for an exception.")
    elif kind == "credential":
        row["credential"] = {
            "preview": finding.secret_preview or "",
            "verified": bool(finding.verified),
            "verification_status": getattr(finding.verification_status, "value",
                                           str(finding.verification_status or "")) or "unknown",
            "exposure": finding.exposure or "",
            "commit": finding.commit_sha or "",
            "commit_url": finding.commit_url or "",
        }
        row["fix"] = CREDENTIAL_FIX
    else:
        # Code and configuration advice only comes from an AI review that still
        # holds for the code as it is.  A generic tip for a rule is not advice
        # about this line.
        if review and review.get("fix"):
            row["fix"] = review["fix"]
    row["ai_reviewed"] = review is not None
    row["ai_review"] = review
    return row


@router.get("/check")
def deploy_check(request: Request,
                 caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Is there anything on this repository and branch to fix before a deploy."""
    from datetime import datetime, timezone

    from sqlalchemy import or_

    from app.core import rbac
    from app.core.models import Component, Finding, Repository
    from app.web.routes_pages import _filtered_findings, _priority_order
    from app.web.security import clean_text

    _require(caller.user, "findings.read")
    params = request.query_params

    repository = clean_text(params.get("repo", ""), "Repository", limit=320,
                            required=False)
    if not repository or "/" not in repository:
        raise HTTPException(status_code=400,
                            detail="repo is required, as the full name: org/name.")
    branch = clean_text(params.get("branch", ""), "Branch", limit=255,
                        required=False)

    fail_on = (params.get("fail_on", "high") or "high").strip().lower()
    if fail_on not in SEVERITY_RANK or fail_on == "unknown":
        raise HTTPException(
            status_code=400,
            detail="fail_on is critical, high, medium, low or info.")
    threshold = SEVERITY_RANK[fail_on]

    raw_areas = (params.get("include", "") or "").strip().lower()
    if raw_areas in ("", "default"):
        areas = set(CHECK_DEFAULT_AREAS)
    elif raw_areas == "all":
        areas = set(CHECK_AREAS)
    else:
        areas = {a.strip() for a in raw_areas.split(",") if a.strip()}
        unknown = areas - set(CHECK_AREAS)
        if unknown:
            raise HTTPException(
                status_code=400,
                detail="include takes " + ", ".join(CHECK_AREAS) + ", or all.")

    flag = (params.get("block_exploited", "1") or "1").strip().lower()
    block_exploited = flag not in ("0", "false", "no")

    from app.config import settings

    from app.web.security import public_base

    site = public_base(request) + (settings.base_path or "")

    with session_scope() as db:
        me = _me(db, caller)
        repo = (rbac.visible_repositories(db, me)
                .filter(Repository.full_name == repository).one_or_none())
        if repo is None:
            # Out of scope and does not exist look the same, on purpose.
            raise HTTPException(status_code=404, detail="No such repository.")
        branch = branch or repo.default_branch or ""

        # The filters a deploy needs, laid over the Findings page defaults.
        # The whole backlog counts, not just what is new since the baseline,
        # because old code ships too.
        wanted = dict(params)
        wanted.update({"repo": repository, "state": "open",
                       "exception": "without", "baseline": "any"})
        if branch:
            wanted["branch"] = branch
        else:
            wanted.pop("branch", None)
        for name in ("kind", "severity", "q", "org", "since"):
            wanted.pop(name, None)

        rows = (_filtered_findings(db, me, wanted)
                .order_by(_priority_order(), Finding.id.asc())
                .limit(CHECK_LIMIT + 1).all())
        truncated = len(rows) > CHECK_LIMIT
        rows = rows[:CHECK_LIMIT]

        # Was this branch ever read?  No findings on a branch nobody scanned is
        # not a pass.  The software inventory is written for every branch a
        # scan reads, so a row there says the branch was looked at.
        short = repository.split("/", 1)[1]
        read = bool(rows) or not branch or db.query(
            db.query(Component.id).filter(
                or_(Component.repository == repository,
                    (Component.organization == repo.organization)
                    & (Component.repository == short)),
                Component.branch == branch).exists()).scalar()
        if not read:
            from app.core import branch_scope

            read = db.query(db.query(Finding.id).filter(
                Finding.repository == repository).filter(
                branch_scope.matches(branch)).exists()).scalar()

        reviews = _ai_reviews(db, [f for f in rows if _area(f) in areas])
        blocking, other = [], []
        by_area = {a: 0 for a in sorted(areas)}
        by_severity = {s: 0 for s in SEVERITY_RANK}
        for f in rows:
            area = _area(f)
            if area not in areas:
                continue
            severity = getattr(f.severity, "value", str(f.severity or "")).lower()
            reasons = []
            if SEVERITY_RANK.get(severity, 0) >= threshold:
                reasons.append(f"{severity} is at or above {fail_on}")
            if block_exploited and f.known_exploited:
                reasons.append("known to be exploited")
            if block_exploited and f.malicious:
                reasons.append("malicious package")
            link = f"{site}/findings/{f.id}"
            row = _check_row(f, area, bool(reasons), "; ".join(reasons), link,
                             reviews.get(f.id))
            (blocking if reasons else other).append(row)
            by_area[area] = by_area.get(area, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

        last_scanned = _stamp(repo.last_scanned_at)

    if not read:
        verdict = "unknown"
        message = (f"Branch {branch} of {repository} has not been scanned, so "
                   "there is nothing to check it against.  Add it to the scan "
                   "scope, or use the pull request gate.")
    elif blocking:
        verdict = "fail"
        message = (f"{len(blocking)} finding(s) to fix before this deploys.")
    else:
        verdict = "pass"
        message = "Nothing at or above the threshold."

    return JSONResponse({
        "verdict": verdict,
        "message": message,
        "repository": repository,
        "branch": branch,
        "fail_on": fail_on,
        "include": sorted(areas),
        "block_exploited": block_exploited,
        "last_scanned_at": last_scanned,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "truncated": truncated,
        "summary": {"blocking": len(blocking), "other": len(other),
                    "by_area": by_area,
                    "by_severity": {k: v for k, v in by_severity.items() if v}},
        "blocking": blocking,
        "other": other,
    })
