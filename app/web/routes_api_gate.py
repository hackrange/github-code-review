"""The pull request gate, for CI jobs.

POST /api/v1/gate queues a check of one pull request and answers at once with
where to ask for the result.  GET /api/v1/gate/runs/{id} says how it went, and
/sarif hands back the new findings in the format a code host shows inline.

The same lock as the rest of /api/v1: a token is a person, and that person
has to be able to see the repository.  The gate only checks repositories this
installation already monitors, because it fetches with the credential the
nightly scan uses, and a request naming any other is refused.

Nothing here writes to the code host.  The CI job uploads the SARIF with its
own token.
"""

from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func

from app.core.db import session_scope
from app.web.routes_api_v1 import Caller, caller_for

router = APIRouter(prefix="/api/v1")

SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")


def _repo_name(raw) -> str:
    """owner/name, from however a CI system spells it.

    GitHub Actions has github.repository, which is owner/name.  Other systems
    hand over a URL or host/owner/name, so a leading scheme, a host and a
    trailing .git are taken off.  A GitLab subgroup path stays whole.
    """
    text = str(raw or "").strip()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text, flags=re.I)
    text = re.sub(r"\.git$", "", text).strip("/")
    parts = [p for p in text.split("/") if p]
    if len(parts) >= 3 and "." in parts[0]:
        parts = parts[1:]
    return "/".join(parts)


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _here(db, user):
    """The caller, in this session.  The one on Caller was detached when its
    own session closed, and access reads relationships off it."""
    from app.core.models import User
    return db.get(User, user.id)


def _visible_repository(db, user, name: str):
    from app.core import rbac
    from app.core.models import Repository

    rows = (rbac.visible_repositories(db, user)
            .filter(func.lower(Repository.full_name) == name.lower())
            .filter(Repository.archived.is_(False))
            .all())
    if not rows:
        return None
    # Two connections can hold the same name.  Prefer the one scanned most
    # recently, since that is the credential most likely to still work.
    rows.sort(key=lambda r: (r.last_scanned_at is not None,
                             r.last_scanned_at or 0), reverse=True)
    return rows[0]


@router.post("/gate")
async def gate_start(request: Request,
                     caller: Caller = Depends(caller_for("gate"))) -> JSONResponse:
    from app.core import gate

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Send JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Send an object.")

    name = _repo_name(body.get("repo"))
    base_sha = str(body.get("base_sha") or "").strip()
    head_sha = str(body.get("head_sha") or "").strip()
    if not name or "/" not in name:
        raise HTTPException(status_code=400, detail="repo is owner/name.")
    if not SHA.match(base_sha) or not SHA.match(head_sha):
        raise HTTPException(status_code=400,
                            detail="base_sha and head_sha are commit ids.")
    mode = str(body.get("mode") or "").strip().lower()
    if mode not in ("", "monitor", "enforce"):
        raise HTTPException(status_code=400, detail="mode is monitor or enforce.")
    pr = body.get("pr")
    if pr is not None:
        try:
            pr = int(pr)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="pr is a number.")
    if body.get("files"):
        # Uploading the changed files is in the design, for runners that can
        # reach this server and not the code host.  It is not built yet, and
        # saying so beats checking something other than what was asked.
        raise HTTPException(
            status_code=400,
            detail="Uploaded files are not supported yet.  Leave files out "
                   "and the server fetches the commits itself.")

    with session_scope() as db:
        user = _here(db, caller.user)
        repo = _visible_repository(db, user, name)
        if repo is None:
            # The same answer for "not monitored" and "not yours", so a token
            # cannot be used to find out which repositories exist here.
            raise HTTPException(
                status_code=404,
                detail=f"{name} is not a repository this installation monitors "
                       f"for this token.")
        run = gate.start(db, user, caller.token, repo, base_sha.lower(),
                         head_sha.lower(), pull_request=pr, mode=mode)
        payload = gate.as_dict(run, _base_url(request))
        run_id = run.id
    gate.submit(run_id)
    return JSONResponse(payload, status_code=202,
                        headers={"Location": payload["status_url"]})


def _visible_run(db, user, run_id: int):
    from app.core import rbac
    from app.core.models import GateRun

    run = db.get(GateRun, run_id)
    if run is None:
        return None
    if run.caller == user.username or rbac.sees_everything(user):
        return run
    # Somebody else's run on a repository this person can see is theirs to
    # read too: a team shares a pipeline token less often than a repository.
    if _visible_repository(db, user, run.repository) is not None:
        return run
    return None


@router.get("/gate/runs/{run_id}")
def gate_run(run_id: int, request: Request,
             caller: Caller = Depends(caller_for("gate"))) -> JSONResponse:
    from app.core import gate

    with session_scope() as db:
        run = _visible_run(db, _here(db, caller.user), run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="No such gate run.")
        payload = gate.as_dict(run, _base_url(request))
    # A run still going is asked about again, so say when.
    headers = {"Retry-After": "5"} if payload["status"] in ("queued", "running") else {}
    return JSONResponse(payload, headers=headers)


@router.get("/gate/runs/{run_id}/sarif")
def gate_sarif(run_id: int,
               caller: Caller = Depends(caller_for("gate"))) -> JSONResponse:
    with session_scope() as db:
        run = _visible_run(db, _here(db, caller.user), run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="No such gate run.")
        if run.status != "done":
            raise HTTPException(status_code=409, detail="That run has no results yet.")
        if not run.sarif:
            raise HTTPException(status_code=409, detail=run.error or "That run kept no SARIF.")
        document = json.loads(run.sarif)
    return JSONResponse(document, media_type="application/sarif+json")
