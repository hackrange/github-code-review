"""The JSON API, for editors and pipelines.

Everything else in this app talks to a browser: form posts, redirects, a
session cookie and a CSRF token.  None of that works from an editor plugin or a
CI job, so this is a separate door with its own lock.

Three rules hold it together.

A token is a person.  Every request resolves to the account that made the
token, and the same scope rules apply, so a developer's plugin sees the
repositories that developer was given and nothing else.

Little here changes anything.  A review is worked out and thrown away; it
is never written to the database, never becomes a finding somebody has to
waive, and never touches a scan.  The writes are about exceptions.  A token
with the reports scope can ask for one, change or withdraw its own, and an
administrator's can revoke one.  Approving, rejecting, excluding and marking
a false positive need the approve scope, which only an administrator's token
can carry, and the role behind it is checked again on every call.

Code arrives in the request and leaves in the response.  It is written to a
temporary directory, looked at, and deleted.  Nothing is kept.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from starlette.concurrency import run_in_threadpool
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


def caller_for_any(*scopes: str):
    """caller_for, satisfied by any one of these scopes."""
    checks = [caller_for(scope) for scope in scopes]

    def resolve(request: Request, presented: str = Depends(_bearer)) -> Caller:
        for check in checks[:-1]:
            try:
                return check(request, presented)
            except HTTPException:
                continue
        return checks[-1](request, presented)

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

        # Run the scanner off the event loop.  It is a blocking subprocess, and
        # this is the one web worker: calling it inline would freeze every other
        # request, including sign in and the health check, for the whole scan.
        # run_in_threadpool also bounds how many run at once to the thread pool.
        completed = await run_in_threadpool(
            functools.partial(
                subprocess.run,
                [str(GHSCAN), "review", workdir, "--only", only, "--fail-on", "none"],
                capture_output=True, text=True, timeout=REVIEW_TIMEOUT,
                env={**os.environ, "GHSCAN_LOG_LEVEL": "warn"}))

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
# What a reports token may write is a request for an exception.  Anything
# that takes a finding out of the report files, approving included, needs the
# approve scope as well, so a pipeline token that leaks cannot hide anything.

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
        "external_ref": waiver.external_ref or "",
    }
    if finding is not None:
        out["vuln_id"] = finding.vuln_id or ""
        out["repository"] = finding.repository or ""
        out["title"] = finding.title or ""
    return out


# What another system may call an exception it keeps a copy of.
_EXTERNAL_REF = re.compile(r"^[A-Za-z0-9:_-]{1,64}$")


def _external_ref(raw) -> str:
    """A caller's own id for an exception, checked, or blank."""
    if raw is None or raw == "":
        return ""
    if not isinstance(raw, str) or not _EXTERNAL_REF.match(raw):
        raise HTTPException(
            status_code=400,
            detail="external_ref is up to 64 letters, digits, colons, "
                   "underscores or dashes.")
    return raw


def _since(params, name: str):
    """An ISO 8601 time from the query string, as naive UTC, or None."""
    from datetime import datetime, timezone

    raw = (params.get(name, "") or "").strip()
    if not raw:
        return None
    if len(raw) > 40:
        raise HTTPException(status_code=400, detail=f"{name} is an ISO 8601 time.")
    try:
        when = datetime.fromisoformat(raw.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400,
                            detail=f"{name} is an ISO 8601 time, like "
                                   "2026-11-23T08:00:00Z.")
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).replace(tzinfo=None)


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


# Why a grade stands, for the grades nobody wrote a sentence for.
_BUILT_IN_REASONS = {
    "kev_raise": ("Listed in CISA's Known Exploited Vulnerabilities catalog, "
                  "so it is graded at least high."),
    "base_image": ("A distribution package in a base image the build "
                   "upgrades after pulling it, so it is graded low."),
    "built_in_rule": "A default severity rule that ships with this product.",
}

# Where these come from: the grades set by a person or a model can change
# between scans, so the live record is checked before what ingest wrote.
_LIVE_SOURCES = {"custom", "ai_validation", "learned_rule"}


def _grade_source(finding, ai_grade) -> str:
    severity = _value(finding.severity)
    if (finding.custom_severity is not None
            and _value(finding.custom_severity) == severity):
        return "custom"
    if ai_grade is not None and _value(ai_grade.severity) == severity:
        return "learned_rule" if ai_grade.rule_id else "ai_validation"
    engine = (finding.engine_severity or "").lower()
    if not engine or engine == severity:
        return "engine"
    stored = finding.severity_source or ""
    if stored and stored not in _LIVE_SOURCES and stored != "engine":
        return stored
    # Graded away from the engine before this was recorded.  The next scan
    # writes it down.
    return "unknown"


def _value(enum_or_text) -> str:
    return getattr(enum_or_text, "value", str(enum_or_text or "")).lower()


def _grade(finding, ai_grade, rules, review) -> dict:
    """The grade that stands, what set it, and the record behind it."""
    source = _grade_source(finding, ai_grade)
    out = {
        "severity": _value(finding.severity),
        "engine_severity": (finding.engine_severity or "").lower()
                           or _value(finding.severity),
        "source": source,
        "rule_id": None,
        "by": None, "at": None, "reason": None,
        "custom": None, "ai": None, "validation": None,
    }
    if finding.custom_severity is not None:
        out["custom"] = {
            "severity": _value(finding.custom_severity),
            "reason": finding.custom_severity_reason or "",
            "by": finding.custom_severity_by or "",
            "at": _stamp(finding.custom_severity_at),
        }
    if ai_grade is not None:
        out["ai"] = {
            "severity": _value(ai_grade.severity),
            "was": ai_grade.was or "",
            "reason": ai_grade.reason or "",
            "source": ai_grade.source or "",
            "rule_id": ai_grade.rule_id,
            "model": ai_grade.model or "",
            "by": ai_grade.created_by or "",
            "at": _stamp(ai_grade.created_at),
        }
    if review and review.get("source") == "analysis":
        out["validation"] = {"rating": (review.get("rating") or "").lower(),
                             "confidence": (review.get("confidence") or "").lower(),
                             "model": review.get("model") or ""}

    if source == "custom":
        out.update(by=out["custom"]["by"], at=out["custom"]["at"],
                   reason=out["custom"]["reason"])
    elif source in ("ai_validation", "learned_rule"):
        out.update(by=out["ai"]["by"], at=out["ai"]["at"],
                   reason=out["ai"]["reason"], rule_id=ai_grade.rule_id)
    elif source == "org_rule":
        rule = rules.get(finding.severity_rule_id)
        out["rule_id"] = finding.severity_rule_id
        if rule is not None:
            out.update(by=rule.created_by or "", at=_stamp(rule.created_at),
                       reason=rule.reason or "")
    elif source in ("expired_secret", "encrypted_secret", "not_applicable"):
        out["reason"] = finding.triage_reason or ""
    elif source == "reach_unlikely":
        out["reason"] = finding.reachability_reason or ""
    elif source in _BUILT_IN_REASONS:
        out["reason"] = _BUILT_IN_REASONS[source]
    return out


def _exception_source(finding, waiver) -> str:
    if not finding.excepted:
        return None
    if waiver is not None and waiver.active():
        return "waiver"
    return "exclusion"


def _finding_dicts(db, user, rows) -> list:
    """The API's view of a page of findings.  Lookups are made once per page."""
    from app.core import rbac
    from app.core.models import AIGrade, SeverityRule, Waiver
    from app.core.reports import as_dict, repo_facts

    if not rows:
        return []
    facts = repo_facts(db, rows)
    ids = [r.id for r in rows]
    waivers, ai_grades = {}, {}
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        for w in db.query(Waiver).filter(Waiver.finding_id.in_(chunk)):
            waivers[w.finding_id] = w
        for g in db.query(AIGrade).filter(AIGrade.finding_id.in_(chunk)):
            ai_grades[g.finding_id] = g
    rule_ids = {r.severity_rule_id for r in rows if r.severity_rule_id}
    rules = ({r.id: r for r in db.query(SeverityRule)
              .filter(SeverityRule.id.in_(rule_ids))} if rule_ids else {})
    reviews = _ai_reviews(db, rows)
    reads_exclusions = rbac.can(user, "exclusion.read")

    out = []
    for finding in rows:
        body = {"id": finding.id}
        body.update(as_dict(finding, facts))
        body["excepted"] = bool(finding.excepted)
        stored = waivers.get(finding.id)
        waiver = _own_waiver(user, stored)
        if waiver is not None:
            body["exception"] = _exception_dict(waiver)
        elif stored is not None:
            # Somebody else's argument stays theirs, but whether one is
            # waiting or approved is what a mirror needs to show.
            body["exception"] = {"status": _value(stored.status), "restricted": True}
        else:
            body["exception"] = None

        # What made "excepted" true.  The reason and who decided are left out
        # where this person could not read the decision itself.
        source = _exception_source(finding, stored)
        readable = ((source == "waiver" and waiver is not None)
                    or (source == "exclusion" and reads_exclusions))
        body["exception_source"] = source
        body["exception_reason"] = (finding.exception_reason or "") if readable else None
        body["exception_by"] = (finding.exception_by or "") if readable else None
        body["exception_at"] = _stamp(finding.exception_at) if source else None
        body["exception_expires_at"] = (_stamp(finding.exception_expires_at)
                                        if source else None)

        body["ai_reviewed"] = finding.id in reviews
        body["ai_review"] = reviews.get(finding.id)
        body["grade"] = _grade(finding, ai_grades.get(finding.id), rules,
                               reviews.get(finding.id))
        body["triage"] = {"state": finding.triage or "",
                          "reason": finding.triage_reason or ""}
        body["confidence"] = finding.confidence or ""
        body["engines"] = [e.strip() for e in (finding.engines or "").split(",")
                           if e.strip()]
        body["corroborated"] = bool(finding.corroborated)
        body["engine_impact"] = finding.engine_impact or ""
        body["engine_likelihood"] = finding.engine_likelihood or ""
        body["resolved_at"] = _stamp(finding.resolved_at)
        body["out_of_scope"] = bool(finding.out_of_scope)
        body["updated_at"] = _stamp(finding.updated_at or finding.first_found_at)
        out.append(body)
    return out


@router.get("/findings")
def list_findings(request: Request,
                  caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Findings, filtered the way the Findings page filters them.

    Three more filters than the page, for a system keeping a copy:
    exception=requested (a request waiting on a decision), updated_since and
    resolved_since, both ISO 8601.
    """
    from app.core import waiver_expiry
    from app.core.models import Finding, Waiver, WaiverStatus
    from app.web.routes_pages import _filtered_findings, _priority_order

    _require(caller.user, "findings.read")
    params = request.query_params
    limit, offset = _paging(params)
    updated_since = _since(params, "updated_since")
    resolved_since = _since(params, "resolved_since")
    waiting = (params.get("exception", "") or "").strip().lower() == "requested"
    if waiting:
        # The page's filter does not know this value, so it is handed "any"
        # and the waiting requests are picked out here.
        params = dict(params)
        params["exception"] = "any"

    waiver_expiry.on_read()
    with session_scope() as db:
        me = _me(db, caller)
        query = _filtered_findings(db, me, params)
        if waiting:
            query = query.filter(Finding.id.in_(
                db.query(Waiver.finding_id)
                .filter(Waiver.status == WaiverStatus.REQUESTED)
                .scalar_subquery()))
        if updated_since is not None:
            # A row nothing has touched since updated_at arrived reads as
            # its first sighting, the same as the response says.
            from sqlalchemy import and_, or_
            query = query.filter(or_(
                Finding.updated_at >= updated_since,
                and_(Finding.updated_at.is_(None),
                     Finding.first_found_at >= updated_since)))
        if resolved_since is not None:
            query = query.filter(Finding.resolved_at >= resolved_since)
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
    from app.core import rbac, waiver_expiry

    _require(caller.user, "findings.read")
    waiver_expiry.on_read()
    with session_scope() as db:
        me = _me(db, caller)
        row = rbac.visible_finding(db, me, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        return JSONResponse(_finding_dicts(db, me, [row])[0])


@router.get("/exceptions")
def list_exceptions(request: Request,
                    caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Exceptions on findings you can see.  Only your own, unless you approve them.

    Filters: status, finding, id, vuln_id, external_ref, and requested_since
    or decided_since as ISO 8601 times.
    """
    from datetime import datetime, timezone

    from sqlalchemy import or_

    from app.core import rbac, waiver_expiry
    from app.core.models import Finding, Waiver, WaiverStatus

    _require(caller.user, "findings.read")
    params = request.query_params
    limit, offset = _paging(params)
    wanted = (params.get("status", "") or "").strip().lower()
    if wanted not in {"", "requested", "approved", "rejected", "revoked", "expired"}:
        raise HTTPException(
            status_code=400,
            detail="status is requested, approved, rejected, revoked or expired.")
    external_ref = _external_ref((params.get("external_ref", "") or "").strip())
    requested_since = _since(params, "requested_since")
    decided_since = _since(params, "decided_since")

    waiver_expiry.on_read()
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
            base = base.filter(or_(Waiver.status == WaiverStatus.EXPIRED,
                                   (Waiver.expires_at.isnot(None))
                                   & (Waiver.expires_at < now)))
        elif wanted:
            base = base.filter(Waiver.status == wanted)
        if external_ref:
            base = base.filter(Waiver.external_ref == external_ref)
        if requested_since is not None:
            base = base.filter(Waiver.requested_at >= requested_since)
        if decided_since is not None:
            base = base.filter(Waiver.decided_at >= decided_since)
        finding_raw = (params.get("finding", "") or "").strip()
        if finding_raw:
            if not finding_raw.isdigit():
                raise HTTPException(status_code=400,
                                    detail="finding is a finding number.")
            base = base.filter(Waiver.finding_id == int(finding_raw))
        id_raw = (params.get("id", "") or "").strip()
        if id_raw:
            ids = [part.strip() for part in id_raw.split(",") if part.strip()]
            if not ids or len(ids) > 500 or not all(i.isdigit() for i in ids):
                raise HTTPException(
                    status_code=400,
                    detail="id is an exception number, or up to 500 of them "
                           "separated by commas.")
            base = base.filter(Waiver.id.in_({int(i) for i in ids}))
        vuln_raw = (params.get("vuln_id", "") or "").strip().upper()
        if vuln_raw:
            if len(vuln_raw) > 64:
                raise HTTPException(status_code=400,
                                    detail="vuln_id is a GCR id, like GCR-1A2B3C4D5E6F.")
            base = base.filter(Waiver.finding_id.in_(
                shown.filter(Finding.vuln_id == vuln_raw)
                .with_entities(Finding.id).scalar_subquery()))

        total = base.count()
        rows = (base.order_by(Waiver.requested_at.desc(), Waiver.id.desc())
                .offset(offset).limit(limit).all())
        findings = {f.id: f for f in db.query(Finding).filter(
            Finding.id.in_([w.finding_id for w in rows])).all()} if rows else {}
        out = [_exception_dict(w, findings.get(w.finding_id)) for w in rows]

    return JSONResponse({"total": total, "limit": limit, "offset": offset,
                         "count": len(out), "exceptions": out})


class _Exists(Exception):
    """The finding already has a live exception.  Carries what to answer."""

    def __init__(self, body: dict):
        super().__init__("exists")
        self.body = body


_ITEM_FIELDS = ("reason", "expires", "ticket", "category", "external_ref")


def _check_item(body: dict) -> dict:
    """One exception's fields, checked before anything is looked up."""
    from app.web.routes_api import _parse_expiry, _waiver_category
    from app.web.security import clean_text

    for field in _ITEM_FIELDS:
        if body.get(field) is not None and not isinstance(body.get(field), str):
            raise HTTPException(status_code=400,
                                detail=f"{field} has to be a string.")
    approve = body.get("approve", False)
    if not isinstance(approve, bool):
        raise HTTPException(status_code=400, detail="approve is true or false.")
    reason = clean_text(body.get("reason", ""), "Reason", limit=2000)
    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say a bit more about why this is acceptable, at least 20 characters.")
    return {
        "reason": reason,
        "ticket": clean_text(body.get("ticket", ""), "Ticket", limit=120,
                             required=False),
        "expires_at": _parse_expiry(body.get("expires", "")),
        "category": _waiver_category(body.get("category", "")),
        "external_ref": _external_ref(body.get("external_ref")),
        "approve": approve,
    }


def _may_approve(caller, me) -> bool:
    """The token carries the approve scope and its owner may approve."""
    from app.core import rbac

    return caller.token.may("approve") and rbac.can(me, "waiver.approve")


def _create_exception(db, me, caller, finding_id, item: dict, source_ip: str):
    """Ask for, or ask for and approve, an exception on one finding.

    -> (waiver dict, approved).  Raises HTTPException for anything wrong
    with this one, or _Exists when it already has one.
    """
    from app.core import rbac
    from app.core.audit import record
    from app.core.models import (FindingKind, FindingState, Waiver,
                                 WaiverStatus, utcnow)
    from app.web.routes_api import _mirror_waiver, _set_exception

    if item["approve"] and not _may_approve(caller, me):
        raise HTTPException(
            status_code=403,
            detail="Approving needs a token with the approve scope, owned by "
                   "somebody allowed to approve exceptions.")
    finding = rbac.visible_finding(db, me, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="No such finding.")
    if item["category"] == "not_deployed" and finding.kind == FindingKind.CREDENTIAL:
        raise HTTPException(status_code=400, detail=(
            "A credential works wherever it was pushed, deployed or not.  "
            "Rotate it, or ask for an accepted risk exception instead."))

    existing = db.query(Waiver).filter(
        Waiver.finding_id == finding.id).one_or_none()
    if existing is not None and existing.status in {
            WaiverStatus.REQUESTED, WaiverStatus.APPROVED}:
        body = {"detail": "There is already an exception on this one.",
                "error": "exists"}
        # Its id only when this person could read it anyway, so this does
        # not become a way to look up other people's requests.
        if _own_waiver(me, existing) is not None:
            body["exception"] = _exception_dict(existing, finding)
        raise _Exists(body)

    approve = item["approve"]
    waiver = existing or Waiver(finding_id=finding.id)
    waiver.reason = item["reason"]
    waiver.ticket = item["ticket"]
    waiver.category = item["category"]
    waiver.external_ref = item["external_ref"]
    waiver.requested_by = me.username
    waiver.requested_at = utcnow()
    waiver.expires_at = item["expires_at"]
    waiver.status = WaiverStatus.APPROVED if approve else WaiverStatus.REQUESTED
    waiver.decided_by = me.username if approve else ""
    waiver.decided_at = utcnow() if approve else None
    waiver.decision_note = ("approved when it was made, by api token"
                            if approve else "")
    if existing is None:
        db.add(waiver)
    db.flush()

    if approve:
        # The same as the web form does for an administrator.
        finding.state = FindingState.WAIVED
        _set_exception(finding, waiver, me.username)
        _mirror_waiver(db, finding, waiver, me.username)
        db.flush()

    record(db, "waiver.approved" if approve else "waiver.requested",
           actor=me.username, target=finding.fingerprint,
           detail=(f"{finding.repository} {finding.file_path} until "
                   f"{item['expires_at']:%Y-%m-%d} (api token {caller.token.prefix})"
                   + (" (not deployed)" if item["category"] else "")
                   + (f" ref {item['external_ref']}" if item["external_ref"] else "")),
           source_ip=source_ip)
    return _exception_dict(waiver, finding), approve


@router.post("/findings/{finding_id}/exceptions")
async def ask_for_exception(finding_id: int, request: Request,
                            caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Ask for an exception on one finding.  It waits for an administrator.

    Send "approve": true on a token that also has the approve scope, owned
    by somebody who may approve, to approve it in the same call.  A finding
    that already has one answers 409 with that exception, when it is one you
    could read.
    """
    from app.core.reports import request_rewrite
    from app.web.security import client_ip

    _require(caller.user, "waiver.request")
    item = _check_item(await _json_object(request))

    with session_scope() as db:
        me = _me(db, caller)
        try:
            out, approved = _create_exception(db, me, caller, finding_id, item,
                                              client_ip(request))
        except _Exists as exists:
            return JSONResponse(status_code=409, content=exists.body)
    if approved:
        request_rewrite()
    return JSONResponse(status_code=201, content=out)


# --- many at once ----------------------------------------------------------
#
# One decision elsewhere can cover hundreds of findings here.  One call each
# is slow and runs into the rate limit, so this takes up to 500.  Every item
# goes through exactly the checks the single call makes, and each one gets
# its own answer: one bad item does not fail the rest.

MAX_BULK_EXCEPTIONS = 500
# Bulk calls per token per minute, on top of the general API limit.
BULK_PER_MINUTE = 20
_bulk_calls = {}
_bulk_lock = threading.Lock()


def _bulk_allowed(token_id: int) -> bool:
    import time

    now = time.monotonic()
    with _bulk_lock:
        recent = [t for t in _bulk_calls.get(token_id, []) if now - t < 60]
        if len(recent) >= BULK_PER_MINUTE:
            _bulk_calls[token_id] = recent
            return False
        recent.append(now)
        _bulk_calls[token_id] = recent
        return True


def _bulk_exceptions(caller, items, source_ip: str) -> dict:
    """The work behind POST /exceptions/bulk, off the event loop."""
    from app.core.audit import record
    from app.core.reports import request_rewrite

    results = []
    counts = {"created": 0, "approved": 0, "exists": 0, "failed": 0}
    with session_scope() as db:
        me = _me(db, caller)
        for index, raw in enumerate(items):
            entry = {"index": index, "finding": None}
            try:
                if not isinstance(raw, dict):
                    raise HTTPException(status_code=400, detail="Each item is an object.")
                finding_id = raw.get("finding")
                if isinstance(finding_id, bool) or not isinstance(finding_id, int):
                    raise HTTPException(status_code=400,
                                        detail="finding is a finding number.")
                entry["finding"] = finding_id
                item = _check_item(raw)
                out, approved = _create_exception(db, me, caller, finding_id,
                                                  item, source_ip)
                entry.update(status=201, result="created", exception=out)
                counts["approved" if approved else "created"] += 1
            except _Exists as exists:
                entry.update(status=409, result="exists",
                             error=exists.body["detail"],
                             exception=exists.body.get("exception"))
                counts["exists"] += 1
            except HTTPException as refused:
                entry.update(status=refused.status_code, result="failed",
                             error=str(refused.detail))
                counts["failed"] += 1
            results.append(entry)
        record(db, "waiver.bulk", actor=me.username,
               target=f"{len(items)} items",
               detail=(f"{counts['created']} requested, {counts['approved']} "
                       f"approved, {counts['exists']} already had one, "
                       f"{counts['failed']} failed (api token {caller.token.prefix})"),
               source_ip=source_ip)
    if counts["approved"]:
        request_rewrite()
    return {"count": len(results), **counts, "results": results}


@router.post("/exceptions/bulk")
async def bulk_exceptions(request: Request,
                          caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Up to 500 exceptions in one call, each answered on its own.

    Send {"items": [{finding, reason, expires, category, ticket,
    external_ref, approve}, ...]}.  The answer lists every item with the
    status it would have had as a single call.
    """
    from app.web.security import client_ip

    _require(caller.user, "waiver.request")
    if not _bulk_allowed(caller.token.id):
        return JSONResponse(status_code=429,
                            content={"detail": "Too many bulk calls.  Wait a minute."},
                            headers={"Retry-After": "60"})
    body = await _json_object(request)
    items = body.get("items")
    if not isinstance(items, list) or not items:
        raise HTTPException(status_code=400,
                            detail='Send {"items": [{"finding": 1, "reason": "...", '
                                   '"expires": "2027-01-31"}]}')
    if len(items) > MAX_BULK_EXCEPTIONS:
        raise HTTPException(status_code=413,
                            detail=f"That is more than {MAX_BULK_EXCEPTIONS} items.")
    out = await run_in_threadpool(_bulk_exceptions, caller, items,
                                  client_ip(request))
    return JSONResponse(out)


# --- one exception: read, change, withdraw, revoke -------------------------
#
# Every call here finds the exception through the findings the token's owner
# can see, then applies the same rule as the Exceptions page.  An id that is
# not yours answers 404, the same as one that does not exist, so it cannot be
# used to find out what other teams asked for.

_EDITABLE = ("reason", "expires", "ticket", "category")


def _visible_waiver(db, me, waiver_id):
    """(waiver, finding) when this person may read it, else a 404."""
    from app.core import rbac
    from app.core.models import Waiver

    waiver = db.query(Waiver).filter(Waiver.id == waiver_id).one_or_none()
    finding = (rbac.visible_finding(db, me, waiver.finding_id)
               if waiver is not None else None)
    if (finding is None or (finding.out_of_scope and not rbac.can(me, "repo.scope"))
            or _own_waiver(me, waiver) is None):
        raise HTTPException(status_code=404, detail="No such exception.")
    return waiver, finding


def _is_owner(me, waiver) -> bool:
    return (waiver.requested_by or "").lower() == (me.username or "").lower()


async def _json_object(request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Send JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Send an object.")
    return body


@router.get("/exceptions/{exception_id}")
def one_exception(exception_id: int,
                  caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """One exception.  Yours, or any you could approve."""
    _require(caller.user, "findings.read")
    with session_scope() as db:
        me = _me(db, caller)
        waiver, finding = _visible_waiver(db, me, exception_id)
        return JSONResponse(_exception_dict(waiver, finding))


@router.patch("/exceptions/{exception_id}")
async def edit_exception(exception_id: int, request: Request,
                         caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Change your own exception.

    Only the person who asked can change it, whatever their role, so an
    approver cannot rewrite somebody else's argument under their name.  An
    approved exception that is changed goes back to waiting: what was signed
    off is not what it says any more, so its finding comes back into the
    report files until an administrator agrees again.  A rejected or withdrawn
    one goes back to waiting too, the same as asking again.
    """
    from app.core.audit import record
    from app.core.models import FindingKind, WaiverStatus, utcnow
    from app.web.routes_api import (_parse_expiry, _waiver_category,
                                    take_back_waiver)
    from app.core.reports import request_rewrite
    from app.web.security import clean_text, client_ip

    _require(caller.user, "waiver.request")
    body = await _json_object(request)
    unknown = sorted(set(body) - set(_EDITABLE))
    if unknown:
        raise HTTPException(status_code=400,
                            detail="Only reason, expires, ticket and category "
                                   "can be changed.")
    if not any(field in body for field in _EDITABLE):
        raise HTTPException(status_code=400, detail="Send something to change.")
    for field in _EDITABLE:
        if body.get(field) is not None and not isinstance(body.get(field), str):
            raise HTTPException(status_code=400,
                                detail=f"{field} has to be a string.")

    with session_scope() as db:
        me = _me(db, caller)
        waiver, finding = _visible_waiver(db, me, exception_id)
        if not _is_owner(me, waiver):
            raise HTTPException(status_code=403,
                                detail="Only the person who asked for it can change it.")
        if waiver.status not in {WaiverStatus.REQUESTED, WaiverStatus.APPROVED,
                                 WaiverStatus.REJECTED, WaiverStatus.REVOKED}:
            raise HTTPException(status_code=409,
                                detail="That one cannot be changed.")
        reopened = waiver.status in {WaiverStatus.REJECTED, WaiverStatus.REVOKED}

        if "reason" in body:
            reason = clean_text(body.get("reason") or "", "Reason", limit=2000)
            if len(reason) < 20:
                raise HTTPException(
                    status_code=400,
                    detail="Say a bit more about why this is acceptable, at "
                           "least 20 characters.")
            waiver.reason = reason
        if "ticket" in body:
            waiver.ticket = clean_text(body.get("ticket") or "", "Ticket",
                                       limit=120, required=False)
        if "expires" in body:
            waiver.expires_at = _parse_expiry(body.get("expires") or "")
        if "category" in body:
            category = _waiver_category(body.get("category") or "")
            if category == "not_deployed" and finding.kind == FindingKind.CREDENTIAL:
                raise HTTPException(status_code=400, detail=(
                    "A credential works wherever it was pushed, deployed or not.  "
                    "Rotate it, or ask for an accepted risk exception instead."))
            waiver.category = category

        was_approved = waiver.status == WaiverStatus.APPROVED
        if was_approved:
            take_back_waiver(db, waiver, finding, me.username)
        waiver.status = WaiverStatus.REQUESTED
        waiver.requested_at = utcnow()
        waiver.decided_by = ""
        waiver.decided_at = None
        waiver.decision_note = ""
        db.flush()

        record(db, "waiver.edited", actor=me.username, target=finding.fingerprint,
               detail=(f"{', '.join(sorted(body))} changed"
                       + ("; approval undone, waiting again" if was_approved else "")
                       + ("; sent for approval again" if reopened else "")
                       + f" (api token {caller.token.prefix})"),
               source_ip=client_ip(request))
        if was_approved:
            request_rewrite()
        return JSONResponse(_exception_dict(waiver, finding))


@router.post("/exceptions/{exception_id}/withdraw")
def withdraw_exception(exception_id: int, request: Request,
                       caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Take back your own exception, waiting or approved.

    Only the person who asked.  It is kept as revoked with a note saying it
    was withdrawn, and an approved one's finding comes straight back.
    """
    from app.core.audit import record
    from app.core.models import WaiverStatus
    from app.core.reports import request_rewrite
    from app.web.routes_api import take_back_waiver
    from app.web.security import client_ip

    _require(caller.user, "waiver.request")
    with session_scope() as db:
        me = _me(db, caller)
        waiver, finding = _visible_waiver(db, me, exception_id)
        if not _is_owner(me, waiver):
            raise HTTPException(status_code=403,
                                detail="Only the person who asked for it can withdraw it.")
        if waiver.status not in {WaiverStatus.REQUESTED, WaiverStatus.APPROVED}:
            raise HTTPException(status_code=409,
                                detail="That one is already closed.")
        was_approved = waiver.status == WaiverStatus.APPROVED
        take_back_waiver(db, waiver, finding, me.username,
                         note="Withdrawn by the person who asked for it.")
        db.flush()
        record(db, "waiver.withdrawn", actor=me.username,
               target=finding.fingerprint,
               detail=f"api token {caller.token.prefix}",
               source_ip=client_ip(request))
        if was_approved:
            request_rewrite()
        return JSONResponse(_exception_dict(waiver, finding))


@router.post("/exceptions/{exception_id}/revoke")
def revoke_exception(exception_id: int, request: Request,
                     caller: Caller = Depends(caller_for_any("reports", "approve"))) -> JSONResponse:
    """Take back an approved exception, as an administrator.

    The safe direction for a token to have: the finding comes back into the
    report files, it never leaves them.  So a token with either the reports
    or the approve scope may do it, as long as its owner may revoke.  Find
    the id by the reference you gave it: GET /exceptions?external_ref=...
    """
    from app.core.audit import record
    from app.core.models import WaiverStatus
    from app.core.reports import request_rewrite
    from app.web.routes_api import take_back_waiver
    from app.web.security import client_ip

    _require(caller.user, "waiver.revoke")
    with session_scope() as db:
        me = _me(db, caller)
        waiver, finding = _visible_waiver(db, me, exception_id)
        if waiver.status != WaiverStatus.APPROVED:
            raise HTTPException(status_code=409,
                                detail="Only an approved exception can be revoked.")
        take_back_waiver(db, waiver, finding, me.username)
        db.flush()
        record(db, "waiver.revoked", actor=me.username, target=finding.fingerprint,
               detail=f"api token {caller.token.prefix}",
               source_ip=client_ip(request))
        request_rewrite()
        return JSONResponse(_exception_dict(waiver, finding))


# --- signing off, on the approve scope -------------------------------------
#
# The calls that take findings out of the report files.  A token needs the
# approve scope, which only an administrator can put on one, and the account
# behind it is checked again on every call in case it has since lost the role.

async def _note(request) -> str:
    from app.web.security import clean_text

    raw = await request.body()
    if not raw:
        return ""
    body = await _json_object(request)
    if body.get("note") is not None and not isinstance(body.get("note"), str):
        raise HTTPException(status_code=400, detail="note has to be a string.")
    return clean_text(body.get("note") or "", "Note", limit=1000, required=False)


@router.post("/exceptions/{exception_id}/approve")
async def approve_exception(exception_id: int, request: Request,
                            caller: Caller = Depends(caller_for("approve"))) -> JSONResponse:
    """Approve a waiting exception.  Its finding leaves both report files.

    Approving a request the same person made is allowed.  It is what the web
    form does when an administrator asks for one, and a token can only carry
    this scope when its owner is allowed to approve.
    """
    from app.core.audit import record
    from app.core.models import FindingState, WaiverStatus, utcnow
    from app.core.reports import request_rewrite
    from app.web.routes_api import _mirror_waiver, _set_exception
    from app.web.security import client_ip

    _require(caller.user, "waiver.approve")
    note = await _note(request)
    with session_scope() as db:
        me = _me(db, caller)
        waiver, finding = _visible_waiver(db, me, exception_id)
        if waiver.status != WaiverStatus.REQUESTED:
            raise HTTPException(status_code=409,
                                detail="That one is not waiting on a decision.")
        waiver.status = WaiverStatus.APPROVED
        waiver.decided_by = me.username
        waiver.decided_at = utcnow()
        waiver.decision_note = note
        finding.state = FindingState.WAIVED
        _set_exception(finding, waiver, me.username)
        _mirror_waiver(db, finding, waiver, me.username)
        db.flush()
        record(db, "waiver.approved", actor=me.username, target=finding.fingerprint,
               detail=(f"asked for by {waiver.requested_by} "
                       f"(api token {caller.token.prefix})"),
               source_ip=client_ip(request))
        request_rewrite()
        return JSONResponse(_exception_dict(waiver, finding))


@router.post("/exceptions/{exception_id}/reject")
async def reject_exception(exception_id: int, request: Request,
                           caller: Caller = Depends(caller_for("approve"))) -> JSONResponse:
    """Turn down a waiting exception.  Nothing on disk moves."""
    from app.core.audit import record
    from app.core.models import WaiverStatus, utcnow
    from app.web.security import client_ip

    _require(caller.user, "waiver.approve")
    note = await _note(request)
    with session_scope() as db:
        me = _me(db, caller)
        waiver, finding = _visible_waiver(db, me, exception_id)
        if waiver.status != WaiverStatus.REQUESTED:
            raise HTTPException(status_code=409,
                                detail="That one is not waiting on a decision.")
        waiver.status = WaiverStatus.REJECTED
        waiver.decided_by = me.username
        waiver.decided_at = utcnow()
        waiver.decision_note = note
        db.flush()
        record(db, "waiver.rejected", actor=me.username, target=str(finding.id),
               detail=f"{note} (api token {caller.token.prefix})".strip(),
               source_ip=client_ip(request))
        return JSONResponse(_exception_dict(waiver, finding))


# --- false positives ---------------------------------------------------------
#
# What the product calls a false positive on a finding: a person's grade of
# info, with the reason, the same as "Confirmed as a false positive" from a
# security report.  It survives the next scan while the flagged code is the
# same, and is lifted when that code changes.  It does not hide the finding;
# an exception or an exclusion does that.

FALSE_POSITIVE_PREFIX = "False positive: "


@router.post("/findings/{finding_id}/false-positive")
async def mark_false_positive(finding_id: int, request: Request,
                              caller: Caller = Depends(caller_for("approve"))) -> JSONResponse:
    """Grade one finding info as a false positive, with the reason."""
    from app.core import learned, rbac
    from app.core.audit import record
    from app.core.models import Severity, utcnow
    from app.core.reports import request_rewrite
    from app.web.security import clean_text, client_ip

    _require(caller.user, "finding.regrade")
    body = await _json_object(request)
    if body.get("reason") is not None and not isinstance(body.get("reason"), str):
        raise HTTPException(status_code=400, detail="reason has to be a string.")
    reason = clean_text(body.get("reason") or "", "Reason", limit=1900)
    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say why it is a false positive, at least 20 characters.")

    with session_scope() as db:
        me = _me(db, caller)
        finding = rbac.visible_finding(db, me, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        was = finding.severity
        finding.engine_severity = finding.engine_severity or was.value
        finding.custom_severity = Severity.INFO
        finding.custom_severity_reason = FALSE_POSITIVE_PREFIX + reason
        finding.custom_severity_by = me.username
        finding.custom_severity_at = utcnow()
        finding.severity = Severity.INFO
        db.flush()
        learned.record_basis(db, finding, "person")
        record(db, "finding.false_positive", actor=me.username,
               target=finding.vuln_id or str(finding.id),
               detail=(f"{was.value} to info: {reason[:200]} "
                       f"(api token {caller.token.prefix})"),
               source_ip=client_ip(request))
        out = _finding_dicts(db, me, [finding])[0]
    request_rewrite()
    return JSONResponse(out)


@router.delete("/findings/{finding_id}/false-positive")
def clear_false_positive(finding_id: int, request: Request,
                         caller: Caller = Depends(caller_for("approve"))) -> JSONResponse:
    """Take a false positive back.  Only one this API, or a person, marked as one."""
    from app.core import rbac
    from app.core.audit import record
    from app.core.reports import request_rewrite
    from app.web.routes_api import clear_custom_grade
    from app.web.security import client_ip

    _require(caller.user, "finding.regrade")
    with session_scope() as db:
        me = _me(db, caller)
        finding = rbac.visible_finding(db, me, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        if (finding.custom_severity is None
                or not (finding.custom_severity_reason or "").startswith(
                    FALSE_POSITIVE_PREFIX)):
            raise HTTPException(status_code=409,
                                detail="That finding is not marked a false positive.")
        clear_custom_grade(db, finding)
        record(db, "finding.false_positive_cleared", actor=me.username,
               target=finding.vuln_id or str(finding.id),
               detail=f"api token {caller.token.prefix}",
               source_ip=client_ip(request))
        out = _finding_dicts(db, me, [finding])[0]
    request_rewrite()
    return JSONResponse(out)


@router.post("/exclusions")
async def add_exclusion(request: Request,
                        caller: Caller = Depends(caller_for("approve"))) -> JSONResponse:
    """Write an exclusion: a value everywhere, or one finding.

    Send a fingerprint to exclude that value wherever it turns up, the same as
    "Exclude this value" on a finding page.  organization and repository
    narrow it to one place.  Or send a finding number to exclude just that
    finding, with by_value to cover its value everywhere instead.
    """
    from app.core import exclusions as exclusions_store
    from app.core import ingest, rbac
    from app.core.audit import record
    from app.core.models import Exclusion, utcnow
    from app.core.reports import request_rewrite
    from app.web.routes_api import _exclusion_kind, _parse_expiry
    from app.web.security import clean_text, client_ip

    _require(caller.user, "exclusion.write")
    body = await _json_object(request)
    for field in ("fingerprint", "reason", "ticket", "expires",
                  "organization", "repository"):
        if body.get(field) is not None and not isinstance(body.get(field), str):
            raise HTTPException(status_code=400, detail=f"{field} has to be a string.")
    finding_id = body.get("finding")
    if finding_id is not None and (isinstance(finding_id, bool)
                                   or not isinstance(finding_id, int)):
        raise HTTPException(status_code=400, detail="finding is a finding number.")
    if (finding_id is None) == (not (body.get("fingerprint") or "").strip()):
        raise HTTPException(status_code=400,
                            detail="Send a fingerprint or a finding, not both.")

    reason = clean_text(body.get("reason") or "", "Reason", limit=4000)
    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say why in a sentence or two.  Somebody reading this in a "
                   "year has to be able to tell whether it still holds.")
    ticket = clean_text(body.get("ticket") or "", "Ticket", limit=120, required=False)
    expires_raw = (body.get("expires") or "").strip()
    expires_at = _parse_expiry(expires_raw) if expires_raw else None
    organization = clean_text(body.get("organization") or "", "Organization",
                              limit=255, required=False) or "*"
    repository = clean_text(body.get("repository") or "", "Repository",
                            limit=320, required=False) or "*"

    with session_scope() as db:
        me = _me(db, caller)
        kind, vuln_id, path, rule = "secret", "", "*", "*"
        fingerprint = ""
        if finding_id is not None:
            target = rbac.visible_finding(db, me, finding_id)
            if target is None:
                raise HTTPException(status_code=404, detail="No such finding.")
            kind = _exclusion_kind(target)
            if body.get("by_value"):
                if not target.fingerprint:
                    raise HTTPException(status_code=400,
                                        detail="That finding has no value to exclude.")
                fingerprint = target.fingerprint
            else:
                vuln_id = target.vuln_id or ""
                organization = target.organization or "*"
                repository = target.repository or "*"
                path = target.file_path or "*"
                rule = target.rule or "*"
        else:
            fingerprint = _fingerprint_param(body["fingerprint"])
            kind = {"cred": "secret", "code": "code", "dep": "vuln"}[
                fingerprint.split(":", 1)[0]]

        # The same rule as the page: everywhere is an administrator's call,
        # and a named place has to be one this account can see.
        if organization == "*" and not rbac.can(me, "settings.write"):
            raise HTTPException(status_code=403, detail="Name the organization this covers.")
        if organization != "*" and not rbac.in_scope(
                me, organization, repository if repository != "*" else "", db):
            raise HTTPException(status_code=403, detail="That is not yours to exclude.")

        same = [r for r in exclusions_store.active_rules(db)
                if (r.fingerprint or "") == fingerprint
                and (r.vuln_id or "") == vuln_id
                and (r.organization or "*") == organization
                and (r.repository or "*") == repository
                and (r.path or "*") == path]
        if same:
            raise HTTPException(status_code=409,
                                detail=f"Exclusion {same[0].id} already covers that.")

        row = Exclusion(vuln_id=vuln_id, kind=kind, organization=organization,
                        repository=repository, path=path, rule=rule,
                        fingerprint=fingerprint, reason=reason, ticket=ticket,
                        reviewed_by=me.username, reviewed_date=utcnow(),
                        expires_at=expires_at, active=True)
        db.add(row)
        db.flush()
        # Off the event loop: it reads every open finding (see
        # routes_api._reapply_exceptions).
        changed = await run_in_threadpool(ingest.apply_exceptions, db)
        if changed:
            request_rewrite()
        record(db, "exclusion.added", actor=me.username,
               target=(fingerprint if fingerprint
                       else f"{organization}/{repository}:{path}"),
               detail=f"{kind}: {reason[:200]} (api token {caller.token.prefix})",
               source_ip=client_ip(request))
        out = _exclusion_out(db, row)
        out["findings_excluded"] = changed

    return JSONResponse(status_code=201, content=out)


# --- exclusions ------------------------------------------------------------
#
# The rules that hide findings, written on the Exclusions page.  Reading and
# revoking them follows that page exactly: administrators only today, and
# only the rules the Exclusions page would show this account.  There is no
# way to add one here, for the same reason a token cannot approve an
# exception.

def _exclusion_out(db, row) -> dict:
    from app.core import exclusions as exclusions_store

    out = exclusions_store.as_dicts(db, rules=[row])[0]
    out["revoked"] = not row.active
    return out


def _fingerprint_param(raw: str) -> str:
    from app.core import exclusions as exclusions_store

    text = exclusions_store.normalize_fingerprint(raw or "", "secret")
    if text and not exclusions_store.FINGERPRINT.match(text):
        raise HTTPException(status_code=400,
                            detail="A fingerprint is the hash off the finding, "
                                   "on its own or with cred: in front.")
    return text


@router.get("/exclusions")
def list_exclusions(request: Request,
                    caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Exclusion rules you can see, by fingerprint, by finding, or all of them."""
    from app.core import exclusions as exclusions_store

    _require(caller.user, "exclusion.read")
    params = request.query_params
    limit, offset = _paging(params)
    status = (params.get("status", "") or "").strip().lower()
    if status not in {"", "live", "expired", "revoked"}:
        raise HTTPException(status_code=400,
                            detail="status is live, expired or revoked.")
    fingerprint = _fingerprint_param(params.get("fingerprint", ""))
    finding_raw = (params.get("finding", "") or "").strip()
    if finding_raw and not finding_raw.isdigit():
        raise HTTPException(status_code=400, detail="finding is a finding number.")

    with session_scope() as db:
        me = _me(db, caller)
        rows = exclusions_store.visible(
            db, me, status="expired" if status in {"expired", "revoked"} else status)
        if status == "revoked":
            rows = [r for r in rows if not r.active]
        elif status == "expired":
            rows = [r for r in rows if r.active]
        if fingerprint:
            rows = [r for r in rows if (r.fingerprint or "") == fingerprint]
        if finding_raw:
            from app.core import rbac

            target = rbac.visible_finding(db, me, int(finding_raw))
            if target is None:
                raise HTTPException(status_code=404, detail="No such finding.")
            rows = [r for r in rows if r.live() and exclusions_store.matches(r, target)]
        total = len(rows)
        out = [_exclusion_out(db, r) for r in rows[offset:offset + limit]]

    return JSONResponse({"total": total, "limit": limit, "offset": offset,
                         "count": len(out), "exclusions": out})


def _revoke_rows(db, me, caller, request, rows) -> list:
    from app.web.routes_api import revoke_exclusion_rows
    from app.web.security import client_ip

    live = [r for r in rows if r.active]
    revoke_exclusion_rows(db, live, me.username, source_ip=client_ip(request),
                          via=f"api token {caller.token.prefix}")
    return [_exclusion_out(db, r) for r in live]


@router.post("/exclusions/{exclusion_id}/revoke")
def revoke_one_exclusion(exclusion_id: int, request: Request,
                         caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Switch one rule off.  It stays on the record, marked revoked."""
    from app.core import exclusions as exclusions_store

    _require(caller.user, "exclusion.write")
    with session_scope() as db:
        me = _me(db, caller)
        row = next((r for r in exclusions_store.visible(db, me)
                    if r.id == exclusion_id), None)
        if row is None:
            raise HTTPException(status_code=404, detail="No such exclusion.")
        if not row.active:
            raise HTTPException(status_code=409, detail="That one is already revoked.")
        return JSONResponse(_revoke_rows(db, me, caller, request, [row])[0])


@router.post("/exclusions/revoke")
async def revoke_by_fingerprint(request: Request,
                                caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """Switch off every rule you can see that names this fingerprint.

    What "Exclude this value" on a finding wrote, taken back in one call.
    """
    from app.core import exclusions as exclusions_store

    _require(caller.user, "exclusion.write")
    body = await _json_object(request)
    if not isinstance(body.get("fingerprint"), str) or not body["fingerprint"].strip():
        raise HTTPException(status_code=400, detail="Send the fingerprint.")
    fingerprint = _fingerprint_param(body["fingerprint"])
    with session_scope() as db:
        me = _me(db, caller)
        rows = [r for r in exclusions_store.visible(db, me)
                if (r.fingerprint or "") == fingerprint and r.active]
        if not rows:
            raise HTTPException(status_code=404,
                                detail="No exclusion on that fingerprint.")
        out = await run_in_threadpool(_revoke_rows, db, me, caller, request,
                                      rows)
    return JSONResponse({"fingerprint": fingerprint, "count": len(out),
                         "revoked": out})


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


@router.get("/repositories/{repository:path}/certifications")
def repository_certifications(repository: str,
                              caller: Caller = Depends(caller_for("reports"))) -> JSONResponse:
    """The branch sign offs on one repository, and what each says today."""
    from app.core import certification, rbac
    from app.core.models import Certification, Repository

    _require(caller.user, "repo.read")
    wanted = (repository or "").strip()[:320]
    with session_scope() as db:
        me = _me(db, caller)
        seen = (rbac.visible_repositories(db, me)
                .filter(Repository.full_name == wanted)
                .with_entities(Repository.full_name).first())
        if seen is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        rows = (rbac.visible_certifications(db, me)
                .filter(Certification.repository == seen[0])
                .order_by(Certification.branch.asc()).all())
        out = []
        for row, said in zip(rows, certification.statuses(db, rows)):
            out.append({
                "branch": row.branch or "",
                "status": said.get("state") or "",
                "why": said.get("why") or "",
                "reviewed_by": row.certified_by or "",
                "reviewed_at": _stamp(row.certified_at),
                "expires_at": _stamp(row.expires_at),
                "commit": row.commit_sha or "",
                "automatic": bool(row.automatic),
                "note": row.note or "",
                "withdrawn": row.revoked_at is not None,
                "withdrawn_by": row.revoked_by or "",
                "withdrawn_at": _stamp(row.revoked_at),
                "reason": row.revoked_reason or "",
            })
    return JSONResponse({"repository": seen[0], "count": len(out),
                         "certifications": out})


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


# External sites and their dynamic scans live in their own module, under this
# router so they share its token handling and its place in the API reference.
from app.web.routes_external import api as _external_api  # noqa: E402

# Added route by route rather than with include_router, which in this FastAPI
# wraps the whole router and hides its paths from router.routes.
for _route in _external_api.routes:
    router.add_api_route(_route.path, _route.endpoint, methods=list(_route.methods),
                         name=_route.name)
