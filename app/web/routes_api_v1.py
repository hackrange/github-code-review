"""The JSON API, for editors and pipelines.

Everything else in this app talks to a browser: form posts, redirects, a
session cookie and a CSRF token.  None of that works from an editor plugin or a
CI job, so this is a separate door with its own lock.

Three rules hold it together.

A token is a person.  Every request resolves to the account that made the
token, and the same scope rules apply, so a developer's plugin sees the
repositories that developer was given and nothing else.

Nothing here changes anything.  A review is worked out and thrown away; it is
never written to the database, never becomes a finding somebody has to waive,
and never touches a scan.  The worst a stolen token can do is read the rules
and spend some CPU.

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
def ping(caller: Caller = Depends(caller_for("rules"))) -> JSONResponse:
    """Somewhere for a client to check its token without doing any work."""
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
                db, rules=exclusions_store.visible(db, caller.user)),
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
