"""Actions.

Everything here changes something, so everything here checks CSRF, checks the
role, and checks the scope before it does anything.  Findings are always
fetched through rbac.visible_finding, never by a bare id.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request

from app.core import live, rbac
from app.core.audit import record
from app.core.db import session_scope
from app.core.models import (
    Finding, FindingAnalysis, FindingKind, FindingState,
    RuleMute as m_RuleMute,
    ApiToken as m_ApiToken, Severity,
    SeverityRule as m_SeverityRule, User, UserRole, Waiver, WaiverStatus,
    utcnow,
)
from app.core.reports import request_rewrite, write_reports
from app.auth import service as auth_service
from app.web.security import (
    SESSION_COOKIE, check_csrf, clean_email, clean_int, clean_remote_url,
    clean_text, client_ip, current_user, redirect,
)

log = logging.getLogger("gcr.api")
router = APIRouter()

MAX_WAIVER_DAYS = 365


def _safe_back(raw: str) -> str:
    """Where to send the reader afterwards, from a value they supplied.

    Only a path on this site.  Anything absolute, scheme relative or carrying a
    host is replaced rather than cleaned up, because a redirect target that came
    in on a form is the classic way to turn a trusted page into somebody else's
    landing page.

    The query string is kept.  Some of these pages are addressed entirely by
    one: a sign off page is a repository and a branch in the query string and
    nothing else, so dropping it sent somebody who had just signed a branch off
    to a page that answered 404, with the sign off already recorded and no sign
    of it.  A filtered list loses its filter the same way.

    msg and kind are dropped, because they are put back on below.  A value
    arriving on the form would otherwise be the one the page read, which is a
    banner in our own voice saying whatever the link that was clicked chose.
    """
    text = (raw or "").strip()
    if not text.startswith("/") or text.startswith("//") or "\\" in text:
        return "/repositories"
    # A newline here is a second header, so this is not only about tidiness.
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        return "/repositories"
    # Longer than any page of ours, so it is replaced rather than cut down.
    # A truncated address is a 404 that reads as the page having been right
    # to refuse, which is the failure this whole helper is here to stop.
    if len(text) > 900:
        return "/repositories"
    path, _, query = text.partition("?")
    kept = [pair for pair in query.split("&")
            if pair and pair.partition("=")[0] not in ("msg", "kind")]
    return path + ("?" + "&".join(kept) if kept else "")


def _findings_back(form) -> str:
    """The findings list as the reader had it filtered, or the whole list."""
    where = _safe_back(str(form.get("back", "") or ""))
    return where if where.startswith("/findings") else "/findings"


def _back_with(where: str, message: str, kind: str = "ok") -> str:
    """That page, with the line to show the reader when it opens."""
    from urllib.parse import quote

    return "%s%smsg=%s&kind=%s" % (where, "&" if "?" in where else "?",
                                   quote(message), kind)


# The kinds of exception somebody can ask for, by what is stored.
WAIVER_CATEGORIES = {"": "Accepted risk",
                     "not_deployed": "Not in scope: this code does not get deployed"}


def _waiver_category(raw) -> str:
    value = str(raw or "").strip().lower()
    if value not in WAIVER_CATEGORIES:
        raise HTTPException(status_code=400, detail="Pick a kind of exception.")
    return value


def _parse_expiry(value: str) -> datetime:
    """A date, in the future, and not absurdly far into it.

    An exception with no end is just a decision nobody has to revisit.
    """
    text = (value or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Pick an expiration date.")
    try:
        when = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=400,
                            detail="Use a date like 2027-01-31.")

    now = datetime.now(timezone.utc)
    if when <= now:
        raise HTTPException(status_code=400,
                            detail="That date has already passed.")
    if when > now + timedelta(days=MAX_WAIVER_DAYS):
        raise HTTPException(
            status_code=400,
            detail=f"Keep it within {MAX_WAIVER_DAYS} days so it gets looked at again.")
    return when


def _set_exception(finding, waiver, actor: str) -> None:
    """Flip the flag that keeps a finding out of the report files."""
    finding.excepted = True
    finding.exception_reason = waiver.reason or ""
    finding.exception_by = actor
    finding.exception_at = utcnow()
    finding.exception_expires_at = waiver.expires_at


def _clear_exception(finding) -> None:
    finding.excepted = False
    finding.exception_reason = ""
    finding.exception_by = ""
    finding.exception_at = None
    finding.exception_expires_at = None


def _exclusion_kind(finding) -> str:
    """Which scanner bucket this finding lives in."""
    value = getattr(finding.kind, "value", str(finding.kind or "")).lower()
    if "cred" in value or "secret" in value:
        return "secret"
    if "code" in value:
        return "code"
    return "vuln"


def _mirror_waiver(db, finding, waiver, actor: str) -> None:
    """Turn an approved exception into an exclusion the scanner honors.

    Taking the finding out of the report files is only half of it.  Without
    this the next scan finds the same thing, writes it back in, and somebody
    gets to waive it again every night.  The exclusion makes the decision stick
    where the work happens.
    """
    from app.core.models import Exclusion

    kind = _exclusion_kind(finding)
    organization = finding.organization or "*"
    repository = finding.repository or "*"
    path = finding.file_path or "*"
    # A credential is matched by its fingerprint, which does not move even when
    # somebody reformats the file around it.  The others go by rule and path.
    fingerprint = finding.fingerprint if kind == "secret" else ""
    rule = finding.rule or (finding.vulnerability_id or "*") if kind != "secret" else "*"

    row = (db.query(Exclusion)
           .filter(Exclusion.vuln_id == (finding.vuln_id or ""),
                   Exclusion.organization == organization,
                   Exclusion.repository == repository,
                   Exclusion.path == path,
                   Exclusion.rule == (rule or "*"),
                   Exclusion.fingerprint == fingerprint)
           .one_or_none())
    if row is None:
        row = Exclusion(vuln_id=finding.vuln_id or "",
                        organization=organization, repository=repository,
                        path=path, rule=rule or "*", fingerprint=fingerprint)
        db.add(row)

    row.kind = kind
    row.reason = waiver.reason or ""
    row.ticket = waiver.ticket or ""
    row.reviewed_by = actor
    row.reviewed_date = utcnow()
    row.expires_at = waiver.expires_at
    row.active = True


def _retire_exclusion(db, finding) -> None:
    """Switch off the exclusion a waiver created, if there is one."""
    from app.core.models import Exclusion

    kind = _exclusion_kind(finding)
    fingerprint = finding.fingerprint if kind == "secret" else ""
    rows = (db.query(Exclusion)
            .filter(Exclusion.organization == (finding.organization or "*"),
                    Exclusion.repository == (finding.repository or "*"),
                    Exclusion.path == (finding.file_path or "*"),
                    Exclusion.fingerprint == fingerprint)
            .all())
    for row in rows:
        row.active = False


@router.post("/findings/{finding_id}/waive")
async def request_waiver(finding_id: int, request: Request,
                         reason: str = Form(""),
                         expires: str = Form(""),
                         ticket: str = Form(""),
                         category: str = Form(""),
                         user: User = Depends(current_user)):
    """Ask for an exception.

    A developer can ask on anything they can see.  Nothing leaves the report
    files until an admin approves it.  An admin asking for one approves it in
    the same step, since making them click twice adds nothing.
    """
    await check_csrf(request)
    rbac.require(user, "waiver.request")

    reason_text = clean_text(reason, "Reason", limit=2000)
    if len(reason_text) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say a bit more about why this is acceptable, at least 20 characters.")
    ticket_text = clean_text(ticket, "Ticket", limit=120, required=False)
    expires_at = _parse_expiry(expires)
    category_value = _waiver_category(category)

    with session_scope() as db:
        finding = rbac.visible_finding(db, user, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        if category_value == "not_deployed" and finding.kind == FindingKind.CREDENTIAL:
            raise HTTPException(status_code=400, detail=(
                "A credential works wherever it was pushed, deployed or not.  "
                "Rotate it, or ask for an accepted risk exception instead."))

        existing = db.query(Waiver).filter(
            Waiver.finding_id == finding.id).one_or_none()
        if existing is not None and existing.status in {
                WaiverStatus.REQUESTED, WaiverStatus.APPROVED}:
            raise HTTPException(status_code=409,
                                detail="There is already an exception on this one.")

        auto_approve = rbac.can(user, "waiver.approve")
        waiver = existing or Waiver(finding_id=finding.id)
        waiver.reason = reason_text
        waiver.ticket = ticket_text
        waiver.category = category_value
        waiver.requested_by = user.username
        waiver.requested_at = utcnow()
        waiver.expires_at = expires_at
        waiver.status = (WaiverStatus.APPROVED if auto_approve
                         else WaiverStatus.REQUESTED)
        waiver.decided_by = user.username if auto_approve else ""
        waiver.decided_at = utcnow() if auto_approve else None
        waiver.decision_note = "requested by an admin" if auto_approve else ""
        if existing is None:
            db.add(waiver)
        db.flush()

        if auto_approve:
            finding.state = FindingState.WAIVED
            _set_exception(finding, waiver, user.username)
            _mirror_waiver(db, finding, waiver, user.username)

        record(db, "waiver.approved" if auto_approve else "waiver.requested",
               actor=user.username, target=finding.fingerprint,
               detail=(f"{finding.repository} {finding.file_path} until {expires}"
                       + (" (not deployed)" if category_value else "")),
               source_ip=client_ip(request))

        if auto_approve:
            # An approval changes what is on disk, so rewrite both files now.
            request_rewrite()

    message = ("Exception approved and the finding has left both report files."
               if auto_approve else
               "Exception requested. An admin has to approve it before "
               "anything changes on disk.")
    return redirect(f"/findings?msg={message.replace(' ', '+')}&kind=ok")


# Enough for a whole filtered view of a large estate, and small enough that one
# request cannot sit there for a minute holding the database.
MAX_BULK_WAIVE = 5000


@router.post("/findings/waive-bulk")
async def waive_many(request: Request, user: User = Depends(current_user)):
    """Waive everything that is ticked, or everything a filter matches.

    A scan of a real estate produces hundreds of findings that one decision
    covers.  Waiving them one at a time is not a review, it is data entry.
    """
    await check_csrf(request)
    rbac.require(user, "waiver.request")


    form = await request.form()
    reason_text = clean_text(form.get("reason"), "Reason", limit=2000)
    if len(reason_text) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say a bit more about why these are acceptable. The same "
                   "reason goes on every one of them.")
    ticket_text = clean_text(form.get("ticket"), "Ticket", limit=120,
                             required=False)
    expires_at = _parse_expiry(str(form.get("expires", "")))
    category_value = _waiver_category(form.get("category", ""))

    wanted = []
    for raw in form.getlist("ids"):
        for piece in str(raw).split(","):
            piece = piece.strip()
            if piece.isdigit():
                wanted.append(int(piece))

    everything = str(form.get("all_matching", "")).lower() in {"1", "on", "true"}
    if not wanted and not everything:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    auto_approve = rbac.can(user, "waiver.approve")
    counts = {"waived": 0, "already": 0, "skipped": 0}

    with session_scope() as db:
        # Always through the scope filter, so a list of ids from somewhere else
        # matches nothing rather than waiving somebody else's findings.
        query = rbac.visible_findings(db, user)
        if everything:
            query = _apply_finding_filters(query, form, db, user)
        else:
            query = query.filter(Finding.id.in_(wanted))

        findings = query.limit(MAX_BULK_WAIVE + 1).all()
        if len(findings) > MAX_BULK_WAIVE:
            raise HTTPException(
                status_code=400,
                detail=f"That is more than {MAX_BULK_WAIVE} findings. Narrow "
                       "the filters and do it in batches.")

        for finding in findings:
            existing = db.query(Waiver).filter(
                Waiver.finding_id == finding.id).one_or_none()
            if existing is not None and existing.status in {
                    WaiverStatus.REQUESTED, WaiverStatus.APPROVED}:
                counts["already"] += 1
                continue
            # Credentials in the set are left alone rather than failing the
            # lot.  The count says so.
            if (category_value == "not_deployed"
                    and finding.kind == FindingKind.CREDENTIAL):
                counts["skipped"] += 1
                continue

            waiver = existing or Waiver(finding_id=finding.id)
            waiver.reason = reason_text
            waiver.ticket = ticket_text
            waiver.category = category_value
            waiver.requested_by = user.username
            waiver.requested_at = utcnow()
            waiver.expires_at = expires_at
            waiver.status = (WaiverStatus.APPROVED if auto_approve
                             else WaiverStatus.REQUESTED)
            waiver.decided_by = user.username if auto_approve else ""
            waiver.decided_at = utcnow() if auto_approve else None
            waiver.decision_note = "part of a bulk decision" if auto_approve else ""
            if existing is None:
                db.add(waiver)
            db.flush()

            if auto_approve:
                finding.state = FindingState.WAIVED
                _set_exception(finding, waiver, user.username)
                _mirror_waiver(db, finding, waiver, user.username)
            counts["waived"] += 1

        # One audit line for the decision, not one per finding.  The waivers
        # themselves carry the detail.
        record(db, "waiver.approved" if auto_approve else "waiver.requested",
               actor=user.username, target=f"{counts['waived']} findings",
               detail=f"bulk: {reason_text[:150]}",
               source_ip=client_ip(request))

        if auto_approve and counts["waived"]:
            request_rewrite()

    parts = []
    if auto_approve:
        parts.append(f"{counts['waived']} finding(s) waived and out of both "
                     "report files")
    else:
        parts.append(f"{counts['waived']} exception(s) requested, waiting on "
                     "an admin")
    if counts["already"]:
        parts.append(f"{counts['already']} already had one")
    if counts["skipped"]:
        parts.append(f"{counts['skipped']} credential(s) left alone, because a "
                     "key works whether or not the code is deployed")

    return redirect(_back_with(_findings_back(form), '. '.join(parts)))


# Deleting in chunks rather than one enormous statement, so a delete-the-lot
# on a large estate does not sit there holding every row lock at once.
DELETE_CHUNK = 1000


@router.post("/findings/delete-bulk")
async def delete_many(request: Request, user: User = Depends(current_user)):
    """Remove findings outright.  Admin only, and it does not undo.

    This is not waiving.  A waiver is a decision that carries a reason, an
    expiry and somebody's name; the finding stays, and it comes back when the
    waiver lapses.  This just takes the rows out.

    Worth being straight about what it does and does not do: the next scan
    finds the same code again and files the same findings, with today's date
    as the first time anybody saw them.  So it clears history, it does not
    suppress anything.  If the intent is "stop showing me this", the exception
    workflow or a rule mute is the thing that actually holds.
    """
    await check_csrf(request)
    rbac.require(user, "findings.delete")

    from urllib.parse import quote

    form = await request.form()

    # The dialog sends one comma separated field; a caller ticking real
    # checkboxes sends many.  Both are read, so neither has to know about the
    # other.
    wanted = []
    for raw in form.getlist("delete_ids") + form.getlist("ids"):
        for piece in str(raw).split(","):
            piece = piece.strip()
            if piece.isdigit():
                wanted.append(int(piece))

    truthy = {"1", "on", "true", "yes"}
    everything = str(form.get("everything", "")).lower() in truthy
    matching = str(form.get("all_matching", "")).lower() in truthy

    # Typed confirmation for the whole estate.  A modal on its own is one
    # stray click; this asks for a word, which is hard to do by accident.
    if everything:
        typed = str(form.get("confirm", "")).strip().upper()
        if typed != "DELETE":
            raise HTTPException(
                status_code=400,
                detail="Type DELETE to confirm removing every finding.")
    elif not wanted and not matching:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    with session_scope() as db:
        # Through the scope filter every time, so a list of ids from somewhere
        # else deletes nothing rather than somebody else's findings.
        query = rbac.visible_findings(db, user)
        if everything:
            scope = "every finding"
        elif matching:
            query = _apply_finding_filters(query, form, db, user)
            scope = "everything matching the filters on screen"
        else:
            query = query.filter(Finding.id.in_(wanted))
            scope = f"{len(wanted)} selected"

        ids = [row[0] for row in query.with_entities(Finding.id).all()]
        removed = 0
        for start in range(0, len(ids), DELETE_CHUNK):
            chunk = ids[start:start + DELETE_CHUNK]
            # Waivers go with them.  The column is ON DELETE CASCADE, but not
            # every engine enforces that by default, so say it out loud.
            db.query(Waiver).filter(Waiver.finding_id.in_(chunk)).delete(
                synchronize_session=False)
            db.query(FindingAnalysis).filter(
                FindingAnalysis.finding_id.in_(chunk)).delete(
                synchronize_session=False)
            removed += db.query(Finding).filter(Finding.id.in_(chunk)).delete(
                synchronize_session=False)
            db.flush()

        record(db, "finding.deleted", actor=user.username,
               target=f"{removed} findings", detail=scope,
               source_ip=client_ip(request))

        # The report files are the thing other people read.  Leaving them
        # showing rows that no longer exist would be worse than the delete.
        if removed:
            request_rewrite()

    note = (f"{removed} finding(s) deleted. The next scan files them again if "
            "the code still matches.")
    return redirect(f"/findings?msg={quote(note)}&kind=ok")


def _apply_finding_filters(query, form, db=None, user=None):
    """The same filters the page was showing, applied to a bulk action.

    The ids are not sent for a select-all, so the filters have to be, or the
    request would mean something different from what was on screen.  So the
    list is built by the page's own builder rather than a copy of it: the copy
    had fallen behind, and ignored the repository, branch, triage, reach,
    window and the dashboard's exploited, live and malicious filters.  "All
    matching" from the live credentials list reached every finding the other
    filters allowed.
    """
    from app.web.routes_pages import _filtered_findings

    if db is None or user is None:
        raise ValueError("a bulk filter needs the session and the person")
    chosen = _filtered_findings(db, user, form).with_entities(Finding.id)
    return query.filter(Finding.id.in_(chosen.scalar_subquery()))

def form_ids(form, *names) -> list:
    """Whole numbers out of a form, under any of these field names.

    The bulk dialogs send one comma separated hidden field; a caller ticking
    real checkboxes sends the field many times.  Both are read, so neither has
    to know about the other.
    """
    out = []
    for name in names:
        for raw in form.getlist(name):
            for piece in str(raw).split(","):
                piece = piece.strip()
                if piece.isdigit():
                    out.append(int(piece))
    return out


@router.post("/waivers/revoke-bulk")
async def revoke_waivers(request: Request, user: User = Depends(current_user)):
    """Take back a batch of approved exceptions in one go.

    A quarter's worth of exceptions expiring together is one decision, and
    clicking through it one row at a time is data entry rather than review.
    Each finding comes straight back, and the exclusion each one created is
    retired with it.
    """
    await check_csrf(request)
    rbac.require(user, "waiver.revoke")

    from urllib.parse import quote

    wanted = []
    for raw in form_ids(await request.form(), "waiver_ids", "ids"):
        wanted.append(raw)
    if not wanted:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    revoked = skipped = 0
    with session_scope() as db:
        rows = db.query(Waiver).filter(Waiver.id.in_(wanted)).all()
        for waiver in rows:
            if waiver.status != WaiverStatus.APPROVED:
                skipped += 1
                continue
            finding = db.query(Finding).filter(
                Finding.id == waiver.finding_id).one_or_none()
            # The scope check the single revoke gets from the page: an id from
            # another team must do nothing rather than revoke their decision.
            if finding is not None and rbac.visible_finding(
                    db, user, finding.id) is None:
                skipped += 1
                continue
            waiver.status = WaiverStatus.REVOKED
            waiver.decided_by = user.username
            waiver.decided_at = utcnow()
            if finding is not None:
                finding.state = FindingState.OPEN
                _clear_exception(finding)
                _retire_exclusion(db, finding)
            revoked += 1
        db.flush()

        # One line for the decision.  The waivers carry the detail.
        record(db, "waiver.revoked", actor=user.username,
               target=f"{revoked} exceptions", detail="bulk",
               source_ip=client_ip(request))
        if revoked:
            request_rewrite()

    note = f"{revoked} exception(s) revoked. Their findings are back."
    if skipped:
        note += f" {skipped} were not approved, or not yours, and were left."
    return redirect(f"/waivers?msg={quote(note)}&kind=warn")


def _bulk_reason(form) -> str:
    """The sentence that has to cover every row in the batch.

    A decision taken on forty findings at once is still a decision, and the
    only thing that explains it later is what was typed here.  Same floor as
    asking for an exception in the first place: twenty characters is not much,
    but it rules out "ok".
    """
    text = clean_text(form.get("reason", ""), "Reason", limit=2000)
    if len(text) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say a bit more about the decision, at least 20 characters.")
    return text


@router.post("/waivers/approve-bulk")
async def approve_waivers(request: Request, user: User = Depends(current_user)):
    """Agree to a batch of requests in one go.

    One dependency bump turns up as the same finding in forty repositories and
    forty people ask for the same exception in the same afternoon.  That is one
    decision, so it gets taken once.  The reason typed here goes on every
    waiver in the batch, so each one still says why on its own.
    """
    await check_csrf(request)
    rbac.require(user, "waiver.approve")

    from urllib.parse import quote

    form = await request.form()
    reason = _bulk_reason(form)
    wanted = form_ids(form, "waiver_ids", "ids")
    if not wanted:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    approved = skipped = 0
    with session_scope() as db:
        for waiver in db.query(Waiver).filter(Waiver.id.in_(wanted)).all():
            if waiver.status != WaiverStatus.REQUESTED:
                skipped += 1
                continue
            # The scope check the single approve gets from the page: an id
            # from another team must do nothing rather than sign off on a
            # finding this account cannot even see.
            finding = rbac.visible_finding(db, user, waiver.finding_id)
            if finding is None:
                skipped += 1
                continue
            waiver.status = WaiverStatus.APPROVED
            waiver.decided_by = user.username
            waiver.decided_at = utcnow()
            waiver.decision_note = reason
            finding.state = FindingState.WAIVED
            _set_exception(finding, waiver, user.username)
            _mirror_waiver(db, finding, waiver, user.username)
            approved += 1
        db.flush()

        # One line for the decision, carrying the reason.  The waivers carry
        # the detail of which findings it covered.
        record(db, "waiver.approved", actor=user.username,
               target=f"{approved} exceptions", detail=f"bulk: {reason}",
               source_ip=client_ip(request))
        if approved:
            # An approval changes what is on disk, so rewrite both files now.
            request_rewrite()

    note = (f"{approved} exception(s) approved. Their findings have left both "
            "report files.")
    if skipped:
        note += (f" {skipped} were not waiting on a decision, or not yours, "
                 "and were left alone.")
    return redirect(f"/waivers?msg={quote(note)}&kind=ok")


@router.post("/waivers/reject-bulk")
async def reject_waivers(request: Request, user: User = Depends(current_user)):
    """Turn down a batch of requests in one go.

    Nothing on disk moves either way: these findings were never out of the
    report files.  What changes is that the people who asked get an answer,
    and the answer is written down.
    """
    await check_csrf(request)
    rbac.require(user, "waiver.approve")

    from urllib.parse import quote

    form = await request.form()
    reason = _bulk_reason(form)
    wanted = form_ids(form, "waiver_ids", "ids")
    if not wanted:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    rejected = skipped = 0
    with session_scope() as db:
        for waiver in db.query(Waiver).filter(Waiver.id.in_(wanted)).all():
            if waiver.status != WaiverStatus.REQUESTED:
                skipped += 1
                continue
            if rbac.visible_finding(db, user, waiver.finding_id) is None:
                skipped += 1
                continue
            waiver.status = WaiverStatus.REJECTED
            waiver.decided_by = user.username
            waiver.decided_at = utcnow()
            waiver.decision_note = reason
            rejected += 1
        db.flush()

        record(db, "waiver.rejected", actor=user.username,
               target=f"{rejected} exceptions", detail=f"bulk: {reason}",
               source_ip=client_ip(request))

    note = (f"{rejected} exception(s) rejected. Their findings stay in both "
            "report files.")
    if skipped:
        note += (f" {skipped} were not waiting on a decision, or not yours, "
                 "and were left alone.")
    return redirect(f"/waivers?msg={quote(note)}&kind=info")


@router.post("/exclusions/delete-bulk")
async def delete_exclusions(request: Request, user: User = Depends(current_user)):
    """Remove a batch of exclusion rules.

    Same shape as the single delete: the rows go, the audit log keeps who
    added them and who removed them, and anything they were covering comes
    back unless a waiver still holds it.
    """
    await check_csrf(request)
    rbac.require(user, "exclusion.write")

    from urllib.parse import quote

    from app.core.exclusions import visible

    wanted = set(form_ids(await request.form(), "exclusion_ids", "ids"))
    if not wanted:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    removed = 0
    with session_scope() as db:
        # Through the same filter the page uses, so an id from another team
        # matches nothing rather than deleting their rule.
        rows = [r for r in visible(db, user) if r.id in wanted]
        for row in rows:
            record(db, "exclusion.deleted", actor=user.username,
                   target=f"{row.organization}/{row.repository}:{row.path}",
                   detail=(row.reason or "")[:200], source_ip=client_ip(request))
            db.delete(row)
            removed += 1
        db.flush()
        if removed:
            _reapply_exceptions(db)

    note = (f"{removed} exclusion(s) deleted. Anything they covered is back "
            "in both report files.")
    return redirect(f"/exclusions?msg={quote(note)}&kind=ok")


@router.post("/reports/rebuild")
async def rebuild_reports(request: Request, user: User = Depends(current_user)):
    """Write both files again from what is in the database right now."""
    await check_csrf(request)
    rbac.require(user, "findings.export")

    # Asked for, so it is done now and the count is the answer, but in a
    # worker thread: rebuilding every open finding on the event loop held up
    # every other request on the site until it finished.
    from starlette.concurrency import run_in_threadpool

    def _rebuild():
        with session_scope() as db:
            return write_reports(db)

    result = await run_in_threadpool(_rebuild)
    with session_scope() as db:
        record(db, "reports.rebuilt", actor=user.username,
               detail=f"{result['findings']} findings",
               source_ip=client_ip(request))

    return redirect(f"/reports?msg=Wrote+{result['findings']}+findings.&kind=ok")


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
@router.post("/scans/start")
async def start_scan(request: Request, user: User = Depends(current_user)):
    """Kick off a scan and come straight back.

    A developer only ever scans what they can already see, so the scope comes
    from their assignments rather than from anything they send us.
    """
    await check_csrf(request)
    rbac.require(user, "scan.run")

    from app.core import scanner

    if scanner.is_running():
        return redirect("/scans?msg=A+scan+is+already+running.&kind=warn")

    orgs = repos = None
    if not rbac.sees_everything(user):
        orgs = [org for org, repo in rbac.scope_pairs(user) if not repo]
        repos = [f"{org}/{repo}" for org, repo in rbac.scope_pairs(user) if repo]
        if not orgs and not repos:
            raise HTTPException(
                status_code=403,
                detail="You have no repositories assigned, so there is nothing to scan.")

    started = scanner.start_background(triggered_by=user.username,
                                       trigger="manual", orgs=orgs, repos=repos)
    with session_scope() as db:
        record(db, "scan.requested", actor=user.username,
               detail=f"orgs={orgs or 'all'} repos={repos or 'all'}",
               source_ip=client_ip(request))

    if not started:
        return redirect("/scans?msg=A+scan+is+already+running.&kind=warn")
    return redirect("/scans?msg=Scan+started.+This+page+updates+as+it+goes.&kind=ok")


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------
@router.post("/schedules/save")
async def save_schedule(request: Request,
                        schedule_id: str = Form(""),
                        name: str = Form(""),
                        kind: str = Form("scan"),
                        cron: str = Form(""),
                        enabled: str = Form(""),
                        scope_orgs: str = Form(""),
                        user: User = Depends(current_user)):
    await check_csrf(request)
    rbac.require(user, "schedule.write")

    from app.core import scheduler
    from app.core.models import Schedule

    label = clean_text(name, "Name", limit=120)
    expression = clean_text(cron, "Cron", limit=120)
    if kind not in {"scan", "feeds"}:
        raise HTTPException(status_code=400, detail="Kind must be scan or feeds.")
    if not scheduler.valid_cron(expression):
        raise HTTPException(
            status_code=400,
            detail="That is not a cron expression we can read. Try something like 17 2 * * *")

    from app.core.scanner_config import widen

    # Store what it means rather than what was typed, so the Schedules page and
    # the scanner cannot read the same row differently.
    orgs = ", ".join(widen(clean_text(scope_orgs, "Organizations", limit=1000,
                                      required=False).split(",")))

    with session_scope() as db:
        row = None
        if schedule_id.strip():
            row = db.query(Schedule).filter(
                Schedule.id == clean_int(schedule_id, "Schedule")).one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail="No such schedule.")
        else:
            row = Schedule(created_by=user.username)
            db.add(row)

        row.name = label
        row.kind = kind
        row.cron = expression
        row.enabled = enabled.lower() in {"1", "on", "true", "yes"}
        row.scope_orgs = orgs
        row.next_run_at = scheduler.next_run_for(expression)
        db.flush()

        record(db, "schedule.saved", actor=user.username, target=label,
               detail=f"{kind} at {expression}", source_ip=client_ip(request))

    scheduler.reload_jobs()
    return redirect("/schedules?msg=Saved.&kind=ok")


@router.post("/schedules/{schedule_id}/delete")
async def delete_schedule(schedule_id: int, request: Request,
                          user: User = Depends(current_user)):
    await check_csrf(request)
    rbac.require(user, "schedule.write")

    from app.core import scheduler
    from app.core.models import Schedule

    with session_scope() as db:
        row = db.query(Schedule).filter(Schedule.id == schedule_id).one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="No such schedule.")
        record(db, "schedule.deleted", actor=user.username, target=row.name,
               source_ip=client_ip(request))
        db.delete(row)

    scheduler.reload_jobs()
    return redirect("/schedules?msg=Deleted.&kind=info")


@router.post("/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: int, request: Request,
                           user: User = Depends(current_user)):
    """Fire one now, without waiting for its time to come round."""
    await check_csrf(request)
    rbac.require(user, "schedule.write")

    from app.core import scanner, scheduler
    from app.core.models import Schedule

    with session_scope() as db:
        row = db.query(Schedule).filter(Schedule.id == schedule_id).one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="No such schedule.")
        kind, label = row.kind, row.name
        orgs = [o.strip() for o in (row.scope_orgs or "").split(",") if o.strip()]

    if kind == "feeds":
        import threading
        threading.Thread(target=scanner.refresh_feeds, daemon=True).start()
        return redirect("/schedules?msg=Refreshing+the+feeds.&kind=ok")

    if not scanner.start_background(triggered_by=user.username,
                                    trigger="manual", orgs=orgs or None):
        return redirect("/schedules?msg=A+scan+is+already+running.&kind=warn")
    return redirect("/schedules?msg=Scan+started.&kind=ok")


@router.post("/schedules/split")
async def split_schedules(request: Request, user: User = Depends(current_user)):
    """Make one nightly schedule per organization.

    Better than one job over everything: each run is smaller, a failure costs
    one organization instead of the lot, and the hourly API budget is spread
    across the night rather than spent in one go.
    """
    await check_csrf(request)
    rbac.require(user, "schedule.write")

    from app.core import scheduler

    with session_scope() as db:
        made = scheduler.split_by_organization(db, user.username)
        if made:
            record(db, "schedule.split", actor=user.username,
                   detail=f"{len(made)} organization schedules",
                   source_ip=client_ip(request))

    if not made:
        return redirect("/schedules?msg=No+organizations+to+split+by+yet.+Name+"
                        "them+on+the+Settings+page+or+run+a+scan+first.&kind=warn")

    scheduler.reload_jobs()
    return redirect(f"/schedules?msg=Made+{len(made)}+schedules,+one+per+"
                    "organization,+forty+minutes+apart.&kind=ok")


@router.post("/scans/{run_id}/delete")
async def delete_scan_run(run_id: int, request: Request,
                          user: User = Depends(current_user)):
    """Remove one line from the scan history.

    History only.  The findings a scan brought in belong to the finding, not to
    the run, so nothing about what was found changes.
    """
    await check_csrf(request)
    rbac.require(user, "scan.history.delete")

    from app.core.models import ScanRun

    with session_scope() as db:
        run = db.query(ScanRun).filter(ScanRun.id == run_id).one_or_none()
        if run is None:
            raise HTTPException(status_code=404, detail="No such scan.")
        if run.status == "running":
            raise HTTPException(
                status_code=400,
                detail="That scan is still running. Stop it first, then it can "
                       "be removed.")
        # Stopped is not the same as done with.  A stop marks the row finished
        # and then goes looking for the repositories that had completed, and
        # those are on disk until it has read them.  Removing the row in that
        # window used to throw the work away without saying so.
        if _results_still_unread(run.id):
            raise HTTPException(
                status_code=400,
                detail="That scan is still saving the repositories it "
                       "finished. Give it a moment, then it can be removed.")
        started = run.started_at
        db.delete(run)
        record(db, "scan.history_deleted", actor=user.username,
               target=str(run_id),
               detail=f"started {started:%Y-%m-%d %H:%M}" if started else "",
               source_ip=client_ip(request))

    return redirect("/scans?msg=Removed+from+the+history.&kind=ok")


def _results_still_unread(run_id) -> bool:
    """Whether a stopped run still has results nobody has ingested.

    The salvage removes the directory once it has read it, so its presence is
    the honest answer to "is this run finished with".
    """
    try:
        from app.config import settings as _settings
        from pathlib import Path as _Path
        d = _Path(_settings.work_dir) / f"gcr-results-{run_id}"
        return d.is_dir() and any(d.iterdir())
    except Exception:            # noqa: BLE001 - never block a delete on this
        return False


@router.post("/scans/clear")
async def clear_scan_history(request: Request,
                             user: User = Depends(current_user)):
    """Clear the history, or the older end of it.

    Anything still running is left alone, because a row that says running is
    the only handle the Stop button has.
    """
    await check_csrf(request)
    rbac.require(user, "scan.history.delete")

    from urllib.parse import quote

    from app.core.models import ScanRun

    form = await request.form()
    days = str(form.get("older_than_days", "")).strip()
    cutoff = None
    if days:
        keep = clean_int(days, "Days to keep", low=1, high=3650)
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep)

    with session_scope() as db:
        query = db.query(ScanRun).filter(ScanRun.status != "running")
        if cutoff is not None:
            query = query.filter(ScanRun.started_at < cutoff)
        rows = query.all()
        for run in rows:
            db.delete(run)
        count = len(rows)
        record(db, "scan.history_cleared", actor=user.username,
               detail=(f"{count} run(s)"
                       + (f" older than {days} days" if cutoff else ", all of them")),
               source_ip=client_ip(request))

    if not count:
        return redirect("/scans?msg=Nothing+to+remove.&kind=warn")
    what = f"older than {days} days" if cutoff else "from the history"
    return redirect(f"/scans?msg={quote(f'Removed {count} run(s) {what}. The findings are untouched.')}&kind=ok")


@router.post("/scans/stop")
async def stop_scan(request: Request, user: User = Depends(current_user)):
    """Stop the scan that is running.

    Whatever it had already found is thrown away with the working directory.
    Findings from earlier scans are untouched: nothing is written to the
    database until a scan finishes.
    """
    await check_csrf(request)
    rbac.require(user, "scan.run")

    from app.core import scanner

    from urllib.parse import quote

    form = await request.form()
    wanted = str(form.get("run_id", "")).strip()
    run_id = int(wanted) if wanted.isdigit() else None

    # Whose run this is.
    #
    # The id arrives in the form and was acted on without asking whether the
    # person sending it had anything to do with that run.  Anybody who could
    # re-scan one repository of their own could therefore end the nightly
    # sweep over the whole estate, by posting a number.
    #
    # A developer keeps the ability to stop what they started, because they
    # can start it.  Everything else needs the permission an administrator
    # has.  Naming no run at all means "stop whatever is running", which is a
    # claim over somebody else's work by definition, so that stays with the
    # administrators too.
    if not rbac.can(user, "scan.stop.any"):
        from app.core.models import ScanRun

        if run_id is None:
            raise HTTPException(
                status_code=403,
                detail="Say which scan to stop.  Only an administrator can "
                       "stop whichever one happens to be running.")
        with session_scope() as db:
            row = (db.query(ScanRun)
                   .filter(ScanRun.id == run_id).one_or_none())
            owner = (row.triggered_by or "") if row else ""
        # A run that is not there and a run that is somebody else's answer the
        # same way.  Telling them apart is how an id becomes a way to find out
        # what exists.
        if row is None or owner != user.username:
            raise HTTPException(status_code=404, detail="No such scan.")

    result = scanner.stop_scan(run_id)
    with session_scope() as db:
        record(db, "scan.stop_requested", actor=user.username,
               target=(str(run_id) if run_id else ""),
               outcome="ok" if result["ok"] else "error",
               detail=result.get("reason", ""), source_ip=client_ip(request))

    if not result["ok"]:
        return redirect("/scans?kind=warn&msg=" + quote(result["reason"]))
    # What it had already finished is kept now, so the message says so rather
    # than repeating that nothing was saved.
    kept = result.get("kept", 0)
    if kept:
        return redirect("/scans?kind=ok&msg=" + quote(
            f"Stopped.  The {kept} repository(ies) it had already finished "
            "were kept; anything it never reached is unchanged."))
    return redirect("/scans?kind=ok&msg=" + quote(
        "Stopped.  It had not finished any repository, so nothing was kept."))


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------
@router.post("/connections/save")
async def save_connection(request: Request, user: User = Depends(current_user)):
    """Add an account, or change one.

    Each row is one credential.  A fine grained token reaches one resource
    owner, so an estate across several organizations needs one row each.
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from app.core import connections as connection_store
    from app.core.models import Connection

    form = await request.form()
    name = clean_text(form.get("name"), "Name", limit=120)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,119}", name):
        raise HTTPException(
            status_code=400,
            detail="Names are letters, numbers, spaces, dot, dash and underscore.")

    api_url = clean_text(form.get("api_url"), "API address", limit=300,
                         required=False)
    web_url = clean_text(form.get("web_url"), "Web address", limit=300,
                         required=False)

    provider = str(form.get("provider", "github")).strip().lower()
    if provider not in {"github", "gitlab", "bitbucket", "azure", "assembla",
                        "beanstalk", "codecommit", "gcsr", "gitea", "forgejo",
                        "subversion", "perforce"}:
        raise HTTPException(
            status_code=400,
            detail="That is not a host this knows about. Pick one from the list.")

    # Whatever was pasted, turned into the two addresses this needs.  Somebody
    # who pastes the /api/v4/projects URL they just checked in a browser, with a
    # trailing slash and no scheme, means the same thing as somebody who types
    # the host, so it is translated rather than refused.
    web_url, api_url = connection_store.normalize_urls(provider, web_url, api_url)
    for label, value in (("The API address", api_url), ("The web address", web_url)):
        if not value.startswith(("http://", "https://")):
            raise HTTPException(status_code=400,
                                detail=f"{label} has to start with http:// or https://")

    method = str(form.get("auth_method", "pat")).strip().lower()
    if method not in {"pat", "app"}:
        raise HTTPException(status_code=400, detail="Pick a token or a GitHub App.")
    if provider != "github" and method == "app":
        raise HTTPException(
            status_code=400,
            detail="A GitHub App is a GitHub thing. Everywhere else takes a token.")

    from app.core import settings_store as store_mod

    application_name = clean_text(form.get("application_name"), "Application name",
                                  limit=200, required=False)
    # Owners are addresses, not names.  Somebody reading this in a year needs
    # to be able to send the question somewhere.
    application_owner = clean_email(form.get("application_owner"),
                                    "Application owner")
    technical_owner = clean_email(form.get("technical_owner"), "Technical owner")
    # Anybody else who should hear about this account.  A rota address, a ticket
    # queue, the vendor who maintains it.
    notify_extra = clean_email(form.get("notify_extra"), "Other addresses")
    notify_app = _checked(form, "notify_application_owner")
    notify_tech = _checked(form, "notify_technical_owner")
    # A tick box with nothing beside it would be a setting that silently does
    # nothing, and the person who ticked it would find out by never being told
    # about a critical.
    if notify_app and not application_owner:
        raise HTTPException(
            status_code=400,
            detail="Fill in the application owner before sending them the digest.")
    if notify_tech and not technical_owner:
        raise HTTPException(
            status_code=400,
            detail="Fill in the technical owner before sending them the digest.")

    organizations = ", ".join(_csv_list(clean_text(
        form.get("organizations"), "Organizations", limit=4000, required=False)))
    repositories = ", ".join(_csv_list(clean_text(
        form.get("repositories"), "Repositories", limit=4000, required=False)))

    # Branches this account is limited to, one per line.  Empty, or a star,
    # means every branch, which _csv_list already turns into an empty list.
    # A browser sends a textarea with CRLF line endings and clean_text refuses
    # a carriage return, so the box has to be flattened before it is checked or
    # every multi line list comes back as characters that do not belong.
    branch_names = _csv_list(clean_text(
        str(form.get("branches", "")).replace("\r\n", "\n").replace("\r", "\n"),
        "Branches", limit=4000, required=False))
    if len(branch_names) > 200:
        raise HTTPException(
            status_code=400,
            detail="That is more branches than a list is any use for. "
                   "Use a pattern such as release/* instead.")
    for entry in branch_names:
        # Branch names and the globs that match them, and nothing else.  What
        # is typed here ends up as a match pattern in the scanner, so a line
        # that is not one is a line that silently matches nothing.
        if not re.fullmatch(r"[A-Za-z0-9._/*?\[\]!+-]{1,255}", entry):
            raise HTTPException(
                status_code=400,
                detail=f"{entry} is not a branch name or a pattern. "
                       "Letters, numbers, dot, dash, underscore, slash, and "
                       "* ? [ ] for matching.")
    branches = "\n".join(branch_names)

    connection_id = str(form.get("connection_id", "")).strip()

    with session_scope() as db:
        row = None
        if connection_id:
            row = connection_store.by_id(db, connection_id)
            if row is None:
                raise HTTPException(status_code=404, detail="No such connection.")

        # Check the name before anything is added to the session.  A query
        # after an add flushes the half built row, and a half built row has no
        # name on it yet.
        clash = connection_store.by_name(db, name)
        if clash is not None and (row is None or clash.id != row.id):
            raise HTTPException(status_code=409,
                                detail=f"There is already one called {name}.")

        if row is None:
            row = Connection(name=name, created_by=user.username)
            db.add(row)

        row.name = name
        row.api_url = api_url
        row.web_url = web_url
        row.provider = provider
        row.application_name = application_name
        row.application_owner = application_owner
        row.technical_owner = technical_owner
        row.notify_application_owner = notify_app
        row.notify_technical_owner = notify_tech
        row.notify_extra = notify_extra
        # Only labels this install actually uses, so a renamed one cannot leave
        # a connection carrying a tag nothing matches any more.
        row.sensitivity = ", ".join(
            label for label in store_mod.sensitivity_labels(db)
            if _checked(form, f"sensitivity:{label}"))
        row.auth_method = method
        row.organizations = organizations
        row.repositories = repositories
        row.branches = branches
        row.enabled = str(form.get("enabled", "")).lower() in {"1", "on", "true", "yes"}
        row.app_id = clean_text(form.get("app_id"), "App id", limit=60,
                                required=False)
        row.app_installation = clean_text(form.get("app_installation"),
                                          "Installation id", limit=60,
                                          required=False)
        # Empty leaves what is stored alone, so editing does not wipe a token
        # nobody retyped.
        connection_store.put_secret(row, "token",
                                    str(form.get("token", "")).strip())
        connection_store.put_secret(row, "app_key",
                                    str(form.get("app_key", "")).strip())
        db.flush()

        scope_detail = f"{method}, {organizations or 'every org it can reach'}"
        # Who gets mailed is worth a line in the audit log.  An address added
        # here starts receiving findings from the next scan, and somebody will
        # eventually ask when that began.
        told = row.notify_addresses()
        if told:
            scope_detail += f", notifying {', '.join(told)}"
        # Worth saying out loud in the log: narrowing the branches narrows what
        # a scan can possibly find, and somebody reading a thin report later
        # needs to see when that happened.
        scope_detail += (f", branches: {', '.join(branch_names)}"
                         if branch_names else ", every branch")
        record(db, "connection.saved", actor=user.username, target=name,
               detail=scope_detail, source_ip=client_ip(request))

    return redirect("/connections?msg=Saved.&kind=ok")


@router.post("/connections/{connection_id}/delete")
async def delete_connection(connection_id: int, request: Request,
                            user: User = Depends(current_user)):
    """Remove one account and its credential.

    The findings it brought in stay.  They keep the name of the connection they
    came from, so the history still reads properly, they just stop being
    refreshed by a credential that is no longer here.
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from app.core import connections as connection_store

    with session_scope() as db:
        row = connection_store.by_id(db, connection_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such connection.")
        name = row.name
        kept = (db.query(Finding)
                .filter(Finding.connection_id == row.id).count())
        db.delete(row)
        record(db, "connection.deleted", actor=user.username, target=name,
               detail=f"{kept} finding(s) kept, tagged {name}",
               source_ip=client_ip(request))

    message = f"Deleted {name}. Its credential is gone."
    if kept:
        message += (f" The {kept} finding(s) it found are still here, still "
                    f"labeled {name}.")
    from urllib.parse import quote
    return redirect(f"/connections?msg={quote(message)}&kind=ok")


@router.post("/connections/flush")
async def flush_connection_data(request: Request,
                                user: User = Depends(current_user)):
    """Remove everything a connection brought in.

    A connection can be deleted while its findings, its repositories and its
    history stay, which is the right default: taking away the way in should
    not quietly take away the evidence.  The cost is a name that goes on
    appearing in every filter and every report with nothing behind it, and no
    way to be rid of it short of the database.

    Not reversible, so the name has to be typed rather than clicked, and the
    counts come back so the answer says what went rather than "done".
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import connections as connection_data
    from app.core.models import Connection

    form = await request.form()
    name = clean_text(form.get("name"), "Connection", limit=120)
    typed = clean_text(form.get("confirm"), "Confirmation", limit=120,
                       required=False)
    if typed != name:
        raise HTTPException(
            status_code=400,
            detail="Type the connection name to confirm.  This removes its "
                   "findings and cannot be undone.")

    with session_scope() as db:
        # Refuse where the connection still exists.  Removing the data under a
        # working connection would have it all arrive again on the next scan,
        # minus every decision anybody had recorded on it, which is a very
        # expensive way to achieve nothing.
        live = (db.query(Connection)
                .filter(Connection.name == name).one_or_none())
        if live is not None:
            raise HTTPException(
                status_code=400,
                detail="That connection still exists.  Delete the connection "
                       "first, or its data will simply be scanned again "
                       "without the decisions recorded on it.")

        removed = connection_data.flush(db, name, actor=user.username)
        record(db, "connection.flushed", actor=user.username, target=name,
               detail="%d row(s): %d finding(s), %d repositor(y/ies), "
                      "%d component(s), %d trend point(s)"
                      % (removed["total"], removed.get("findings", 0),
                         removed.get("repositories", 0),
                         removed.get("components", 0),
                         removed.get("trend_points", 0)),
               source_ip=client_ip(request))

    return redirect("/connections?msg=" + quote(
        "Removed %d row(s) left by %s. The scan history is kept."
        % (removed["total"], name)) + "&kind=ok")


@router.post("/connections/{connection_id}/test")
async def test_connection(connection_id: int, request: Request,
                          user: User = Depends(current_user)):
    """Ask GitHub who this one is, and how much it can see."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import connections as connection_store
    from app.core.scanner import check_credential

    with session_scope() as db:
        row = connection_store.by_id(db, connection_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such connection.")
        name = row.name

    result = check_credential(connection_id=connection_id)
    status = "ok" if result["ok"] else "error"
    if result["ok"]:
        # Signed in says nothing about what it can read.  A repository the
        # token lost is never listed, so it quietly stops being scanned.
        from app.core import repo_reach
        reach = repo_reach.check(connection_id)
        if reach["missing"]:
            # First, so the short line on the connections table shows it.
            result["detail"] = reach["detail"] + "  " + result["detail"]
        elif reach["detail"]:
            result["detail"] = result["detail"] + "  " + reach["detail"]
        if reach["missing"]:
            status = "partial"

    with session_scope() as db:
        row = connection_store.by_id(db, connection_id)
        if row is not None:
            row.last_checked_at = utcnow()
            row.last_status = status
            row.last_detail = result["detail"][:1000]
        record(db, "connection.tested", actor=user.username, target=name,
               outcome=status, detail=result["detail"][:400],
               source_ip=client_ip(request))

    kind = {"ok": "ok", "partial": "warn"}.get(status, "error")
    return redirect(f"/connections?msg={quote(name + ': ' + result['detail'][:800])}"
                    f"&kind={kind}")


@router.post("/connections/{connection_id}/scan")
async def scan_connection(connection_id: int, request: Request,
                          user: User = Depends(current_user)):
    """Scan one account now."""
    await check_csrf(request)
    rbac.require(user, "scan.run")
    # A whole account, with its credential, is the estate rather than one
    # person's repositories.  scan.run alone let a developer start a full scan
    # of any team's account by id and read the run back on their own scan
    # history.  Developers scan what they can see from the repository pages.
    # Not found rather than refused, so the ids that exist are not answered.
    if not rbac.can(user, "scan.read.any"):
        raise HTTPException(status_code=404, detail="No such connection.")

    from app.core import connections as connection_store, scanner

    with session_scope() as db:
        row = connection_store.by_id(db, connection_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such connection.")
        name = row.name

    if scanner.connection_is_scanning(connection_id):
        return redirect(f"/connections?msg={name}+is+already+being+scanned.&kind=warn")
    if not scanner.start_background(triggered_by=user.username, trigger="manual",
                                    connection_id=connection_id):
        return redirect("/connections?msg=A+scan+is+already+running.&kind=warn")
    return redirect(f"/connections?msg=Scanning+{name}.&kind=ok")


@router.post("/repositories/{repo_id}/scan")
async def scan_one_repository(repo_id: int, request: Request,
                              user: User = Depends(current_user)):
    """Scan one repository now, rather than the account it sits in.

    The scanner has always been able to do this: run_scan takes a list of
    repositories and turns it into the scope the shell reads.  Nothing in the
    web application ever called it that way, so the smallest thing anybody
    could ask for was an account, and on an account holding thirty one
    repositories that is a long wait to re-read one file.

    It still takes a scan slot, because it is a real scan with real clones and
    real engines.  What it does not take is the other thirty.
    """
    await check_csrf(request)
    rbac.require(user, "scan.run")

    from urllib.parse import quote

    from app.core import connections as connection_store, scanner
    from app.core.models import Repository

    with session_scope() as db:
        # Scoped, so a repository this reader may not see is simply not there
        # rather than refused.  Somebody who cannot read a repository's findings
        # does not get to send the scanner to look at it on their behalf.
        row = (rbac.visible_repositories(db, user)
               .filter(Repository.id == repo_id).one_or_none())
        if row is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        full_name = row.full_name
        # The id the row already stores, before the name it was written with.
        # Resolving the name is a lookup that comes back empty the moment
        # somebody renames the account, and an empty answer here does not
        # refuse the scan, it starts a second one.  The name is still tried
        # for rows written before the id was recorded.
        connection_id = row.connection_id
        if connection_id is None and row.connection:
            connection_id = getattr(
                connection_store.by_name(db, row.connection), "id", None)

    # One branch, when the caller named one.  A finding lives on a branch, and
    # re-reading it means reading that branch; walking the other thirty six is
    # the same waste as scanning the other thirty repositories.  Validated as a
    # branch name rather than trusted, because it reaches a scanner config.
    wanted = clean_text((await request.form()).get("branch", ""), "Branch",
                        limit=255, required=False)
    branches = [wanted] if wanted else None

    back = request.headers.get("referer") or "/repositories"
    if "://" in back:
        back = "/" + back.split("/", 3)[-1] if back.count("/") > 2 else "/repositories"

    # Two different refusals, and saying which is the whole value of saying
    # anything.  "That account is mid scan" is a wait of minutes and the
    # repository is probably being read anyway; "every slot is busy" is a wait
    # on unrelated work.  One message for both taught people to ignore it.
    if connection_id is not None and scanner.connection_is_scanning(connection_id):
        return redirect("%s%smsg=%s&kind=warn"
                        % (back, "&" if "?" in back else "?",
                           quote("That account is being scanned right now, so "
                                 "this repository is already in hand.")))
    if not scanner.start_background(triggered_by=user.username, trigger="manual",
                                    repos=[full_name], branch_names=branches,
                                    connection_id=connection_id):
        return redirect("%s%smsg=%s&kind=warn"
                        % (back, "&" if "?" in back else "?",
                           quote("Every scan slot is busy. Try again shortly.")))
    return redirect("%s%smsg=%s&kind=ok"
                    % (back, "&" if "?" in back else "?",
                       quote("Scanning %s%s now."
                             % (full_name,
                                (" on " + wanted) if wanted else ""))))


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
def _csv_list(raw: str) -> list:
    """Split a comma or newline separated box into a clean list.

    A star, or the word all, means everything, and everything is what an empty
    list already means here.  Storing "*" as though it were the name of an
    organization would switch discovery off and scan nothing, which is a
    miserable way to find out it is not a wildcard.
    """
    text = (raw or "").replace("\r", "\n").replace("\n", ",")
    items = [item.strip() for item in text.split(",") if item.strip()]
    if any(item.lower() in {"*", "all", "any", "everything"} for item in items):
        return []
    return items


# What the scanner takes for a license lookup, which is the scanning engine's
# own list.  This box cannot go through _csv_list: there the word "all" means
# "no filter", and an empty list is how that gets stored.  Here "all" is a
# value, an empty list means look nothing up, and the two are opposites.  Typed
# into the wrong helper, asking for every ecosystem switched the lookups off.
SBOM_ENRICHERS = ("all", "golang", "java", "javascript", "python", "vcpkg")


def _enrich_list(raw: str) -> list:
    """The license lookup box, kept word for word.  -> what to look up.

    Empty means look nothing up, and so does off or none, because a box whose
    placeholder says off should take the word back.  Anything the engine does
    not know is refused rather than stored: a misspelled ecosystem saves
    quietly, looks like it is on, and comes back with no licenses at all.
    """
    text = (raw or "").replace("\r", "\n").replace("\n", ",")
    items = [item.strip().lower() for item in text.split(",") if item.strip()]
    if not items or all(item in {"off", "none", "no"} for item in items):
        return []
    unknown = [item for item in items if item not in SBOM_ENRICHERS]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=("License lookups takes " + ", ".join(SBOM_ENRICHERS)
                    + ", or off.  It does not know " + ", ".join(unknown[:3])
                    + "."))
    if "all" in items:
        return ["all"]
    return sorted(set(items))


def _checked(form, name: str) -> bool:
    return str(form.get(name, "")).lower() in {"1", "on", "true", "yes"}


@router.post("/settings/save")
async def save_settings(request: Request, user: User = Depends(current_user)):
    """Write the setup form into the database.

    Everything lands in the settings table, which lives in the database volume.
    None of it goes into a file, so nothing site specific ends up in the source
    tree.  The token and the App key are encrypted on the way in.
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from app.core import settings_store as store

    form = await request.form()

    def text(name, limit=4000):
        return clean_text(str(form.get(name, "")), name, limit=limit,
                          required=False)

    auth_mode = str(form.get("auth.mode", "local")).strip().lower()
    if auth_mode not in {"local", "oidc", "both"}:
        raise HTTPException(status_code=400,
                            detail="Sign in is local, oidc, or both.")

    # Empty is a real answer here and means refuse them, so this is checked
    # against the roles plus empty rather than being required.
    default_role = str(form.get("oidc.default_role", "")).strip().lower()
    if default_role and default_role not in {r.value for r in UserRole}:
        raise HTTPException(
            status_code=400,
            detail="The role for somebody in no group has to be a role, or "
                   "empty to refuse them.")

    branch_mode = str(form.get("branches.mode", "all"))
    if branch_mode not in {"all", "default", "list"}:
        raise HTTPException(status_code=400, detail="Pick a branch option.")

    severity = str(form.get("vulns.min_severity", "all"))
    if severity not in {"all", "low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="Pick a severity.")

    sbom_branches = str(form.get("sbom.scan_branches", "default"))
    if sbom_branches not in {"default", "all"}:
        raise HTTPException(status_code=400,
                            detail="SBOM branches is default or all.")

    try:
        entropy = float(form.get("secrets.min_entropy", 3.0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400,
                            detail="The placeholder threshold has to be a number.")
    if not 0 <= entropy <= 8:
        raise HTTPException(status_code=400,
                            detail="The placeholder threshold goes from 0 to 8.")

    out_dir = text("output.dir", 500) or "/out"
    if not out_dir.startswith("/"):
        raise HTTPException(
            status_code=400,
            detail="The output directory has to be a full path, and it has to "
                   "be a volume the container can write to.")

    # The app fetches these itself, so they get the same check as the issuer:
    # https only, and nothing pointed at the metadata address.
    feeds = {}
    for url_key in ("intel.kev_url", "intel.epss_url"):
        feeds[url_key] = clean_remote_url(text(url_key, 600), "The feed address")

    with session_scope() as db:
        moved = []

        def put(key, value):
            if store.set_value(db, key, value, user.username):
                moved.append(key)

        # The address, the credential and which organizations to cover belong
        # to a connection now, one per account.  This page stopped owning them
        # rather than owning a second copy nothing reads.
        put("scan.exclude_repos", _csv_list(text("scan.exclude_repos")))
        put("scan.include_archived", _checked(form, "scan.include_archived"))
        put("scan.include_forks", _checked(form, "scan.include_forks"))
        put("scan.max_repos", clean_int(form.get("scan.max_repos", 0) or 0,
                                        "The repository limit", low=0, high=100000))
        # Applied straight away, so an operator who raises it does not have to
        # restart to find out whether it worked.
        from app.core import scanner as _scanner
        concurrent = clean_int(form.get("scan.max_concurrent", 1) or 1,
                               "Scans at once", low=1, high=16)
        put("scan.max_concurrent", concurrent)
        _scanner.set_concurrency(concurrent)

        put("scan.timeout_per_repo",
            clean_int(form.get("scan.timeout_per_repo", 3600) or 3600,
                      "The repository timeout", low=60, high=86400))
        put("scan.max_hours",
            clean_int(form.get("scan.max_hours", 6) or 6,
                      "The whole scan timeout", low=1, high=168))
        put("code.jobs",
            clean_int(form.get("code.jobs", 2) or 2,
                      "The semgrep process count", low=1, high=64))
        put("secrets.concurrency",
            clean_int(form.get("secrets.concurrency", 8) or 8,
                      "The trufflehog thread count", low=1, high=64))
        put("clone.max_repo_size_mb",
            clean_int(form.get("clone.max_repo_size_mb", 4096) or 0,
                      "The repository size limit", low=0, high=1000000))
        put("catchup.enabled", _checked(form, "catchup.enabled"))
        put("catchup.repos_per_run",
            clean_int(form.get("catchup.repos_per_run", 5) or 5,
                      "Repositories per catch up pass", low=1, high=100))
        put("secrets.history_window_days",
            clean_int(form.get("secrets.history_window_days", 0) or 0,
                      "The history window", low=0, high=36500))
        put("secrets.max_file_mb",
            clean_int(form.get("secrets.max_file_mb", 25) or 0,
                      "The file size limit", low=0, high=10000))

        put("branches.mode", branch_mode)
        put("branches.include", _csv_list(text("branches.include")))
        put("branches.exclude", _csv_list(text("branches.exclude")))
        put("branches.full_history", _checked(form, "branches.full_history"))
        put("branches.max_per_repo",
            clean_int(form.get("branches.max_per_repo", 0) or 0,
                      "The branch limit", low=0, high=100000))
        put("branches.stale_days",
            clean_int(form.get("branches.stale_days", 0) or 0,
                      "The stale branch cutoff", low=0, high=3650))

        put("secrets.enabled", _checked(form, "secrets.enabled"))
        put("secrets.verify", _checked(form, "secrets.verify"))
        put("secrets.exclude_paths", _csv_list(text("secrets.exclude_paths")))
        put("secrets.resolve_authors", _checked(form, "secrets.resolve_authors"))
        put("secrets.min_entropy", entropy)
        put("code.enabled", _checked(form, "code.enabled"))
        # The packs are checkboxes on the form.  Anything else somebody wants
        # goes in the extra box, which is how a private pack gets in.
        chosen = [name for name in store.RULESET_NAMES
                  if _checked(form, f"ruleset:{name}")]
        for extra in _csv_list(text("code.rulesets_extra")):
            if extra not in chosen:
                chosen.append(extra)
        put("code.exclude_paths", _csv_list(text("code.exclude_paths")))
        put("code.rulesets", chosen)
        put("sbom.enabled", _checked(form, "sbom.enabled"))
        put("sbom.enrich", _enrich_list(text("sbom.enrich")))
        put("sbom.scan_branches", sbom_branches)
        put("sbom.denied_licenses", _csv_list(text("sbom.denied_licenses")))
        put("sbom.flagged_licenses", _csv_list(text("sbom.flagged_licenses")))
        put("vulns.enabled", _checked(form, "vulns.enabled"))
        put("images.enabled", _checked(form, "images.enabled"))
        put("vulns.min_severity", severity)
        put("access.enabled", _checked(form, "access.enabled"))
        put("pulls.enabled", _checked(form, "pulls.enabled"))
        put("exclusions.enabled", _checked(form, "exclusions.enabled"))

        put("intel.enabled", _checked(form, "intel.enabled"))
        put("intel.kev_url", feeds["intel.kev_url"])
        put("intel.epss_url", feeds["intel.epss_url"])
        put("intel.max_age_hours",
            clean_int(form.get("intel.max_age_hours", 24) or 24,
                      "The feed age", low=1, high=720))

        # What the generated reports say they are.
        #
        # The logo is checked for its scheme rather than trusted, because it
        # is rendered into a document that gets forwarded outside the company.
        # https or a data URI and nothing else: those are the two that carry
        # an image, and anything else in that box is either a mistake or an
        # attempt to make a report fetch something when it is opened.
        logo = text("report.logo", 2000)
        if logo and not (logo.lower().startswith("https://")
                         or logo.lower().startswith("data:image/")):
            raise HTTPException(
                status_code=400,
                detail="A report logo has to be an https link or a data URI "
                       "holding the image itself.")
        put("report.organization_name", text("report.organization_name", 200))
        put("report.logo", logo)
        put("report.footer", text("report.footer", 200))

        put("output.dir", out_dir)
        put("output.per_repo_files", _checked(form, "output.per_repo_files"))
        put("output.include_clean", _checked(form, "output.include_clean"))

        put("github.parallel_repos",
            clean_int(form.get("github.parallel_repos", 4) or 4,
                      "Repositories at once", low=1, high=64))
        put("rate.min_remaining",
            clean_int(form.get("rate.min_remaining", 100) or 100,
                      "The reserve", low=0, high=4000))
        put("rate.adaptive_pacing", _checked(form, "rate.adaptive_pacing"))
        put("rate.max_sleep_sec",
            clean_int(form.get("rate.max_sleep_sec", 3900) or 3900,
                      "The longest wait", low=3700, high=14400))
        put("rate.retries", clean_int(form.get("rate.retries", 5) or 5,
                                      "Retries", low=0, high=20))

        put("auth.mode", auth_mode)
        put("oidc.issuer",
            clean_remote_url(text("oidc.issuer", 500), "The issuer").rstrip("/"))
        put("oidc.client_id", text("oidc.client_id", 300))
        put("oidc.client_secret", str(form.get("oidc.client_secret", "")).strip())
        put("oidc.redirect_url", text("oidc.redirect_url", 500))
        put("oidc.scopes", text("oidc.scopes", 300) or "openid profile email groups")
        put("oidc.group_claim", text("oidc.group_claim", 120) or "groups")
        put("oidc.admin_groups", _csv_list(text("oidc.admin_groups")))
        put("oidc.developer_groups", _csv_list(text("oidc.developer_groups")))
        put("oidc.reader_groups", _csv_list(text("oidc.reader_groups")))
        put("oidc.default_role", default_role)

        put("session.hours", clean_int(form.get("session.hours", 12) or 12,
                                       "Session length", low=1, high=168))
        put("session.idle_minutes",
            clean_int(form.get("session.idle_minutes", 60) or 0,
                      "Idle timeout", low=0, high=1440))
        put("login.attempt_limit",
            clean_int(form.get("login.attempt_limit", 5) or 5,
                      "Wrong passwords allowed", low=1, high=50))
        put("login.lockout_minutes",
            clean_int(form.get("login.lockout_minutes", 15) or 15,
                      "Lockout", low=1, high=1440))
        zone = str(form.get("ui.timezone", "GMT")).strip() or "GMT"
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(zone)
        except Exception:
            raise HTTPException(status_code=400,
                                detail=f"{zone} is not a time zone this machine knows.")
        put("ui.timezone", zone)

        # Muting is asked for, not set.  Ticking a box raises a request that
        # somebody else has to agree to; unticking takes effect at once,
        # because putting findings back is never the dangerous direction.
        from app.core import rule_mutes

        wanted = [rule for rule in store.MUTED_RULE_NOTES
                  if _checked(form, f"mute:{rule}")]
        wanted += [rule for rule in _csv_list(text("code.muted_rules_extra"))
                   if rule not in wanted]

        # Not "live": that name belongs to the settings cache module imported
        # at the top of this file, and shadowing it broke saving entirely.
        standing = {row.rule for row in db.query(m_RuleMute).filter(
            m_RuleMute.status.in_(["requested", "approved"])).all()}
        # A rule the tool ships set aside is already in force with no row
        # behind it.  Without this it would look untouched, so unticking it
        # would fall through and change nothing at all.
        standing |= rule_mutes.shipped_active(db)

        if rbac.can(user, "rule.mute.request"):
            for rule in wanted:
                if rule not in standing:
                    rule_mutes.request(db, rule, user.username)
                    record(db, "rule.mute.requested", actor=user.username,
                           target=rule, source_ip=client_ip(request))
        for rule in standing - set(wanted):
            if rule_mutes.revoke(db, rule, user.username):
                record(db, "rule.mute.revoked", actor=user.username,
                       target=rule, source_ip=client_ip(request))

        db.flush()
        put("code.muted_rules", rule_mutes.effective(db))
        put("sensitivity.labels", _csv_list(text("sensitivity.labels")))

        put("security.force_https", _checked(form, "security.force_https"))
        put("security.trusted_proxies", _csv_list(text("security.trusted_proxies")))

        # Check what they just asked for before it takes effect.  Turning on a
        # provider that cannot answer would lock everybody out of their own
        # tool, and the only way back would be editing the database by hand.
        db.flush()
        live.invalidate()
        broken = live.auth_config().problems()
        if broken:
            raise HTTPException(status_code=400, detail="; ".join(broken))

        # Which settings moved, by name.  Never the values: some of these are
        # credentials, and the rest are somebody's configuration, and an audit
        # log is read by more people than the settings page is.
        if moved:
            named = ", ".join(sorted(moved))
            detail = f"{len(moved)} setting(s) changed: {named}"
        else:
            detail = "saved with nothing changed"
        record(db, "settings.saved", actor=user.username,
               detail=detail[:2000], source_ip=client_ip(request))

    live.invalidate()
    # The cron of every schedule is read in the configured zone, so a new zone
    # means every trigger has to be rebuilt.  Without this they keep firing on
    # the old offset until the next restart.
    try:
        from app.core import scheduler
        scheduler.reload_jobs()
    except Exception as exc:
        log.warning("could not re-arm schedules after a settings change: %s", exc)
    return redirect("/settings?msg=Saved.+The+next+scan+uses+this.&kind=ok")


@router.post("/settings/test")
async def test_settings(request: Request, user: User = Depends(current_user)):
    """Ask GitHub who this credential is, without scanning anything."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core.scanner import check_credential

    result = check_credential()
    with session_scope() as db:
        record(db, "settings.tested", actor=user.username,
               outcome="ok" if result["ok"] else "error",
               detail=result["detail"][:400], source_ip=client_ip(request))

    kind = "ok" if result["ok"] else "error"
    return redirect(f"/settings?msg={quote(result['detail'][:300])}&kind={kind}")


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------
@router.post("/baseline/set")
async def set_baseline(request: Request, user: User = Depends(current_user)):
    """Draw the line for one organization.

    Everything first seen before the date is the backlog.  Everything after is
    the work.  Nothing is deleted and nothing is hidden: both lists are on the
    findings page and the backlog keeps its grades, because a team that
    inherits this in two years still has to be able to find what was set down
    on day one.
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core.models import Baseline

    form = await request.form()
    organization = clean_text(form.get("organization"), "Organization",
                              limit=255)
    raw = str(form.get("at", "")).strip()

    # Blank means now, which is what somebody means when they click the button
    # on the day they start.  A date is for drawing the line where it actually
    # belongs after the fact.
    if raw:
        try:
            at = datetime.strptime(raw, "%Y-%m-%d").replace(
                tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400,
                                detail="A date looks like 2026-08-29.")
        if at > datetime.now(timezone.utc) + timedelta(days=1):
            raise HTTPException(
                status_code=400,
                detail="That is in the future, which would file work that has "
                       "not happened yet as a backlog.")
    else:
        at = datetime.now(timezone.utc)

    note = clean_text(form.get("note"), "Note", limit=2000, required=False)

    with session_scope() as db:
        row = (db.query(Baseline)
               .filter(Baseline.organization == organization).one_or_none())
        moved = row is not None and row.baseline_at != at
        if row is None:
            row = Baseline(organization=organization)
            db.add(row)
        row.baseline_at = at
        row.set_by = user.username
        row.set_at = datetime.now(timezone.utc)
        row.note = note
        record(db, "baseline.set", actor=user.username, target=organization,
               detail=f"line at {at:%Y-%m-%d}" + (" (moved)" if moved else ""),
               source_ip=client_ip(request))

    # Straight back to the list.  The findings page has no flash of its own,
    # and it does not need one here: the control says the date now, and the
    # count beside the filter has moved.
    return redirect(f"/findings?org={quote(organization)}")


@router.post("/baseline/clear")
async def clear_baseline(request: Request, user: User = Depends(current_user)):
    """Rub the line out, so the whole estate is the work list again."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core.models import Baseline

    form = await request.form()
    organization = clean_text(form.get("organization"), "Organization",
                              limit=255)

    with session_scope() as db:
        row = (db.query(Baseline)
               .filter(Baseline.organization == organization).one_or_none())
        if row is not None:
            db.delete(row)
            record(db, "baseline.clear", actor=user.username,
                   target=organization, source_ip=client_ip(request))

    return redirect(f"/findings?org={quote(organization)}")


@router.post("/exclusions/add")
async def add_exclusion(request: Request, user: User = Depends(current_user)):
    """Record a finding somebody reviewed and accepted.

    Same idea as a waiver, one level up: a waiver is about one finding, an
    exclusion is a rule that covers whatever matches it, now and later.
    """
    await check_csrf(request)
    rbac.require(user, "exclusion.write")

    from app.core import ingest
    from app.core.exclusions import FINGERPRINT, KINDS, normalize_fingerprint
    from app.core.models import Exclusion

    form = await request.form()
    kind = str(form.get("kind", "any")).strip().lower()
    if kind not in KINDS:
        raise HTTPException(status_code=400,
                            detail="Type is secret, code, vuln or any.")

    # The short way: paste the id off the finding and everything else is
    # filled in from it.
    vuln_id = clean_text(form.get("vuln_id"), "ID", limit=32,
                         required=False).upper()
    if vuln_id and not vuln_id.startswith("GCR-"):
        raise HTTPException(status_code=400,
                            detail="An id looks like GCR-1A2B3C4D5E6F.")

    organization = clean_text(form.get("organization"), "Organization",
                              limit=255, required=False) or "*"
    repository = clean_text(form.get("repository"), "Repository",
                            limit=320, required=False) or "*"
    path = clean_text(form.get("path"), "Path", limit=1024,
                      required=False) or "*"
    rule = clean_text(form.get("rule"), "Rule", limit=255, required=False) or "*"
    fingerprint = normalize_fingerprint(
        clean_text(form.get("fingerprint"), "Fingerprint", limit=128,
                   required=False), kind)
    if fingerprint and not FINGERPRINT.match(fingerprint):
        raise HTTPException(
            status_code=400,
            detail="A fingerprint is the hash off the finding page, either on "
                   "its own or with the cred: in front.")

    # A rule about a value is not a rule about a place.  The same secret in
    # another repository is the same fingerprint, and pinning it to wherever it
    # happened to be seen last is how it quietly stops matching.
    by_value = _checked(form, "by_value")

    reason = clean_text(form.get("reason"), "Reason", limit=4000)
    ticket = clean_text(form.get("ticket"), "Ticket", limit=120, required=False)

    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say why in a sentence or two. Somebody reading this in a "
                   "year has to be able to tell whether it still holds.")

    # A rule with no organization is a decision about everything, and that is
    # an admin call even though a developer can write one for their own repos.
    if organization == "*" and not rbac.can(user, "settings.write"):
        raise HTTPException(status_code=403,
                            detail="Name the organization this covers.")
    if organization != "*" and not rbac.in_scope(user, organization,
                                                 repository if repository != "*" else ""):
        raise HTTPException(status_code=403, detail="That is not yours to exclude.")

    expires_raw = str(form.get("expires", "")).strip()
    expires_at = _parse_expiry(expires_raw) if expires_raw else None

    with session_scope() as db:
        if vuln_id:
            # Check it exists and that this account is allowed to see it, so an
            # id from another team cannot be used to find out anything.
            target = (rbac.visible_findings(db, user)
                      .filter(Finding.vuln_id == vuln_id).one_or_none())
            if target is None:
                raise HTTPException(status_code=404,
                                    detail="No finding with that id.")
            kind = _exclusion_kind(target)
            if by_value:
                # Take the value off the finding and let it cover the value
                # wherever it is, which is the whole point of asking for this.
                fingerprint = target.fingerprint or fingerprint
                vuln_id = ""
                organization = repository = path = rule = "*"
            else:
                organization = target.organization or organization
                repository = target.repository or repository
                path = target.file_path or path
                rule = target.rule or rule

        # What this decision was not made for.  On a connection carrying any
        # of these the finding comes back rather than being hidden.
        from app.core import settings_store as excl_store
        unless = ", ".join(label for label in excl_store.sensitivity_labels(db)
                           if _checked(form, f"unless:{label}"))

        row = Exclusion(vuln_id=vuln_id, kind=kind, organization=organization,
                        repository=repository, path=path, rule=rule,
                        unless_sensitivity=unless,
                        fingerprint=fingerprint, reason=reason, ticket=ticket,
                        reviewed_by=user.username, reviewed_date=utcnow(),
                        expires_at=expires_at, active=True)
        db.add(row)
        db.flush()

        # Apply it now rather than waiting for the next scan, then rewrite the
        # files so anything it covers is gone from both of them straight away.
        changed = ingest.apply_exceptions(db)
        if changed:
            request_rewrite()

        # A rule about a value says nothing useful as a path, so name the
        # value.  It is a hash, so the log is still free of the secret itself.
        record(db, "exclusion.added", actor=user.username,
               target=(fingerprint if fingerprint
                       else f"{organization}/{repository}:{path}"),
               detail=f"{kind}: {reason[:200]}", source_ip=client_ip(request))

    return redirect("/exclusions?msg=Exclusion+added.+Anything+it+covers+has+"
                    "left+both+report+files.&kind=ok")


# A report of a few thousand findings is around a megabyte.  Ten is room to
# spare, and small enough that nobody can push the container over on memory.
MAX_IMPORT_BYTES = 10 * 1024 * 1024


@router.post("/exclusions/import")
async def import_exclusions(request: Request,
                            user: User = Depends(current_user)):
    """Take vulnerabilities.csv back as a list of things to exclude.

    The workflow this is for: filter the Findings page down to what has been
    reviewed and accepted, export, hand the file back here with one reason
    covering the lot.  Waiving four hundred findings one at a time is not a
    workflow.
    """
    await check_csrf(request)
    rbac.require(user, "exclusion.write")

    from urllib.parse import quote

    from app.core import exclusions as exclusions_store

    form = await request.form()
    upload = form.get("file")
    if upload is None or not getattr(upload, "filename", ""):
        raise HTTPException(status_code=400, detail="Pick a file first.")

    raw = await upload.read()
    if len(raw) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"That file is {len(raw) // (1024 * 1024)}MB. The limit is "
                   f"{MAX_IMPORT_BYTES // (1024 * 1024)}MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400,
                            detail="That file is not text. Export it as CSV.")

    reason = clean_text(form.get("reason"), "Reason", limit=4000)
    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say why in a sentence or two. It goes on every rule this "
                   "creates, so it has to hold for all of them.")
    ticket = clean_text(form.get("ticket"), "Ticket", limit=120, required=False)
    expires_raw = str(form.get("expires", "")).strip()
    expires_at = _parse_expiry(expires_raw) if expires_raw else None

    with session_scope() as db:
        # Only findings this account can already see, so an import cannot be
        # used to learn which ids exist elsewhere.
        visible_ids = None
        if not rbac.sees_everything(user):
            visible_ids = {f.id for f in rbac.visible_findings(db, user).all()}

        result = exclusions_store.import_rows(
            db, text, actor=user.username, reason=reason, ticket=ticket,
            expires_at=expires_at, visible_ids=visible_ids)

        if result["added"]:
            _reapply_exceptions(db)

        record(db, "exclusion.imported", actor=user.username,
               target=getattr(upload, "filename", "")[:200],
               detail=(f"{result['added']} added, {result['already']} already "
                       f"there, {result['unknown']} unknown, "
                       f"{result['skipped']} skipped"),
               source_ip=client_ip(request))

    parts = [f"{result['added']} exclusion(s) added from {result['rows']} row(s)"]
    if result["already"]:
        parts.append(f"{result['already']} were already excluded")
    if result["unknown"]:
        parts.append(f"{result['unknown']} id(s) matched no finding here")
    if result["skipped"]:
        parts.append(f"{result['skipped']} row(s) had nothing to match on")
    for problem in result.get("problems", [])[:2]:
        parts.append(problem)

    kind = "ok" if result["added"] else "warn"
    return redirect(f"/exclusions?msg={quote('. '.join(parts))}&kind={kind}")


@router.post("/exclusions/purge-expired")
async def purge_expired_exclusions(request: Request,
                                   user: User = Depends(current_user)):
    """Delete every rule that has run out.

    An expired rule does nothing except sit on the page.  The audit log keeps
    the record of what it was, which is the part worth keeping.
    """
    await check_csrf(request)
    rbac.require(user, "exclusion.write")

    from app.core.exclusions import visible

    with session_scope() as db:
        expired = [row for row in visible(db, user) if not row.live()]
        for row in expired:
            record(db, "exclusion.deleted", actor=user.username,
                   target=f"{row.organization}/{row.repository}:{row.path}",
                   detail=f"expired {row.expires_at:%Y-%m-%d}: {(row.reason or '')[:150]}"
                          if row.expires_at else (row.reason or "")[:150],
                   source_ip=client_ip(request))
            db.delete(row)
        db.flush()
        if expired:
            _reapply_exceptions(db)
        count = len(expired)

    if not count:
        return redirect("/exclusions?msg=Nothing+has+expired.&kind=warn")
    return redirect(f"/exclusions?msg=Deleted+{count}+expired+rule(s).+"
                    "The+audit+log+keeps+the+record.&kind=ok")


@router.post("/exclusions/{exclusion_id}/save")
async def save_exclusion(exclusion_id: int, request: Request,
                         user: User = Depends(current_user)):
    """Change a rule that is already there.

    The findings it used to cover are released first and then matched again, so
    narrowing a rule brings back whatever it no longer covers.
    """
    await check_csrf(request)
    rbac.require(user, "exclusion.write")

    from app.core import ingest
    from app.core.exclusions import (FINGERPRINT, KINDS, normalize_fingerprint,
                                     visible)

    form = await request.form()
    kind = str(form.get("kind", "any")).strip().lower()
    if kind not in KINDS:
        raise HTTPException(status_code=400,
                            detail="Type is secret, code, vuln or any.")

    organization = clean_text(form.get("organization"), "Organization",
                              limit=255, required=False) or "*"
    repository = clean_text(form.get("repository"), "Repository",
                            limit=320, required=False) or "*"
    path = clean_text(form.get("path"), "Path", limit=1024, required=False) or "*"
    rule = clean_text(form.get("rule"), "Rule", limit=255, required=False) or "*"
    fingerprint = normalize_fingerprint(
        clean_text(form.get("fingerprint"), "Fingerprint", limit=128,
                   required=False), kind)
    if fingerprint and not FINGERPRINT.match(fingerprint):
        raise HTTPException(
            status_code=400,
            detail="A fingerprint is the hash off the finding page, either on "
                   "its own or with the cred: in front.")
    reason = clean_text(form.get("reason"), "Reason", limit=4000)
    ticket = clean_text(form.get("ticket"), "Ticket", limit=120, required=False)

    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say why in a sentence or two. Somebody reading this in a "
                   "year has to be able to tell whether it still holds.")
    if organization == "*" and not rbac.can(user, "settings.write"):
        raise HTTPException(status_code=403,
                            detail="Name the organization this covers.")

    expires_raw = str(form.get("expires", "")).strip()
    expires_at = _parse_expiry(expires_raw) if expires_raw else None

    with session_scope() as db:
        row = next((r for r in visible(db, user) if r.id == exclusion_id), None)
        if row is None:
            raise HTTPException(status_code=404, detail="No such exclusion.")

        row.kind = kind
        row.organization = organization
        row.repository = repository
        row.path = path
        row.rule = rule
        row.fingerprint = fingerprint
        row.reason = reason
        row.ticket = ticket
        row.expires_at = expires_at
        row.reviewed_by = user.username
        row.reviewed_date = utcnow()
        db.flush()

        _reapply_exceptions(db)
        record(db, "exclusion.changed", actor=user.username,
               target=(fingerprint if fingerprint
                       else f"{organization}/{repository}:{path}"),
               detail=f"{kind}: {reason[:200]}", source_ip=client_ip(request))

    return redirect("/exclusions?msg=Saved.+Both+report+files+are+up+to+date.&kind=ok")


@router.post("/exclusions/{exclusion_id}/delete")
async def delete_exclusion(exclusion_id: int, request: Request,
                           user: User = Depends(current_user)):
    """Remove a rule.

    The row goes.  What it did does not: the audit log keeps who added it, who
    removed it and when, which is the part an auditor asks about.  Anything it
    was covering comes straight back unless a waiver still holds it.
    """
    await check_csrf(request)
    rbac.require(user, "exclusion.write")

    from app.core.exclusions import visible

    with session_scope() as db:
        # Through the same filter the page uses, so an id from another team
        # comes back as nothing.
        row = next((r for r in visible(db, user) if r.id == exclusion_id), None)
        if row is None:
            raise HTTPException(status_code=404, detail="No such exclusion.")

        target = f"{row.organization}/{row.repository}:{row.path}"
        reason = row.reason or ""
        db.delete(row)
        db.flush()

        _reapply_exceptions(db)
        record(db, "exclusion.deleted", actor=user.username, target=target,
               detail=reason[:200], source_ip=client_ip(request))

    return redirect("/exclusions?msg=Deleted.+Anything+it+covered+is+back+in+"
                    "both+report+files.&kind=ok")


def _reapply_exceptions(db) -> None:
    """Work the exception flags out again from scratch, then rewrite the files.

    Cheaper to redo than to reason about: a rule that changed might cover more,
    less, or something else entirely.  A finding held by an approved waiver
    keeps its flag regardless.
    """
    from app.core import ingest

    for finding in db.query(Finding).filter(Finding.excepted.is_(True)).all():
        if finding.waiver is not None and finding.waiver.active():
            continue
        _clear_exception(finding)
    db.flush()
    ingest.apply_exceptions(db)
    request_rewrite()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def _new_password() -> str:
    """Something long, and made of characters somebody can read off a screen."""
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(20))


def _load_user(db, user_id: int) -> User:
    try:
        wanted = int(user_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="No such account.")
    row = db.query(User).filter(User.id == wanted).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="No such account.")
    return row


def _other_admins(db, user_id: int) -> int:
    """How many enabled admins there would be without this one."""
    return (db.query(User)
            .filter(User.role == UserRole.ADMIN, User.disabled.is_(False),
                    User.id != user_id)
            .count())


def _apply_groups(db, row: User, form) -> None:
    """Put the account in exactly the groups that were ticked."""
    from app.core.models import ScanGroup

    wanted = set()
    for raw in form.getlist("groups"):
        for piece in str(raw).split(","):
            piece = piece.strip()
            if piece.isdigit():
                wanted.add(int(piece))

    row.groups = (db.query(ScanGroup).filter(ScanGroup.id.in_(wanted)).all()
                  if wanted else [])


def _apply_scopes(db, row: User, raw: str) -> None:
    """Replace what a developer can see with the list from the form.

    One per line, either an organization on its own or organization/repository.
    Anything else is a typo, and a typo that silently becomes a wider scope is
    the kind of thing that gets found during an audit.
    """
    from app.core.models import UserScope

    wanted = []
    for line in (raw or "").replace(",", "\n").splitlines():
        entry = line.strip()
        if not entry:
            continue
        if entry.count("/") > 1:
            raise HTTPException(
                status_code=400,
                detail=f"{entry} is not an organization or an organization/repository.")
        organization, _, repository = entry.partition("/")
        organization = clean_text(organization, "Organization", limit=255)
        repository = clean_text(repository, "Repository", limit=255,
                                required=False)
        wanted.append((organization, repository))

    db.query(UserScope).filter(UserScope.user_id == row.id).delete()
    db.flush()
    seen = set()
    for organization, repository in wanted:
        if (organization, repository) in seen:
            continue
        seen.add((organization, repository))
        db.add(UserScope(user_id=row.id, organization=organization,
                         repository=repository))


@router.post("/groups/save")
async def save_group(request: Request, user: User = Depends(current_user)):
    """Add a scanning group, or change one.

    A group is a list of repositories with a name on it.  Give somebody the
    group rather than pasting the list onto their account, and when the project
    grows a repository everybody in the group gets it at once.
    """
    await check_csrf(request)
    rbac.require(user, "user.write")

    from app.core.models import ScanGroup

    form = await request.form()
    name = clean_text(form.get("name"), "Name", limit=120)
    description = clean_text(form.get("description"), "What it is", limit=500,
                             required=False)
    entries_raw = clean_text(form.get("entries"), "Repositories", limit=20000,
                             required=False)

    cleaned = []
    for line in entries_raw.replace(",", "\n").splitlines():
        entry = line.strip()
        if not entry:
            continue
        if entry.count("/") > 1:
            raise HTTPException(
                status_code=400,
                detail=f"{entry} is not an organization or an "
                       "organization/repository.")
        cleaned.append(entry)
    if not cleaned:
        raise HTTPException(
            status_code=400,
            detail="List at least one organization or repository, one per line.")

    group_id = str(form.get("group_id", "")).strip()

    with session_scope() as db:
        row = None
        if group_id:
            row = db.query(ScanGroup).filter(
                ScanGroup.id == clean_int(group_id, "Group")).one_or_none()
            if row is None:
                raise HTTPException(status_code=404, detail="No such group.")

        clash = db.query(ScanGroup).filter(ScanGroup.name == name).one_or_none()
        if clash is not None and (row is None or clash.id != row.id):
            raise HTTPException(status_code=409,
                                detail=f"There is already a group called {name}.")

        if row is None:
            row = ScanGroup(name=name, created_by=user.username)
            db.add(row)

        row.name = name
        row.description = description
        row.entries = "\n".join(cleaned)
        db.flush()

        record(db, "group.saved", actor=user.username, target=name,
               detail=f"{len(cleaned)} entr(y/ies)", source_ip=client_ip(request))

    return redirect("/users?tab=groups&msg=Saved.&kind=ok")


@router.post("/groups/{group_id}/delete")
async def delete_group(group_id: int, request: Request,
                       user: User = Depends(current_user)):
    """Remove a group.

    Anybody in it loses what the group was giving them, and keeps whatever was
    put against their account directly.
    """
    await check_csrf(request)
    rbac.require(user, "user.write")

    from urllib.parse import quote

    from app.core.models import ScanGroup

    with session_scope() as db:
        row = db.query(ScanGroup).filter(ScanGroup.id == group_id).one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="No such group.")
        name = row.name
        members = len(row.members or [])
        db.delete(row)
        record(db, "group.deleted", actor=user.username, target=name,
               detail=f"{members} member(s) lose it", source_ip=client_ip(request))

    message = f"Deleted {name}."
    if members:
        message += (f" {members} account(s) lose what it gave them, and keep "
                    "anything set against them directly.")
    return redirect(f"/users?tab=groups&msg={quote(message)}&kind=ok")


@router.post("/users/add")
async def add_user(request: Request, user: User = Depends(current_user)):
    """Make a local account.

    The password is shown once, on the page, and never stored anywhere we can
    read back.  They have to change it and set up two step before the app lets
    them do anything at all.
    """
    await check_csrf(request)
    rbac.require(user, "user.write")

    from urllib.parse import quote

    from app.auth.service import hash_password
    from app.core.models import AuthSource

    form = await request.form()
    username = clean_text(form.get("username"), "Username", limit=120).lower()
    # An identity provider names people by email, and those accounts get made
    # here too, so a name with an @ in it has to be allowed.  The domain half
    # is still checked rather than letting anything through.
    if not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{1,119}"
            r"(@[a-z0-9][a-z0-9.-]*\.[a-z]{2,24})?", username):
        raise HTTPException(
            status_code=400,
            detail="Usernames are letters, numbers, dot, dash and underscore, "
                   "and may end in an email domain.")

    role_name = str(form.get("role", "reader")).strip().lower()
    if role_name not in {r.value for r in UserRole}:
        raise HTTPException(status_code=400, detail="Pick a role.")
    role = UserRole(role_name)

    source_name = str(form.get("source", "local")).strip().lower()
    if source_name not in {s.value for s in AuthSource}:
        raise HTTPException(status_code=400, detail="Pick local or the provider.")
    source = AuthSource(source_name)

    display_name = clean_text(form.get("display_name"), "Name", limit=255,
                              required=False)
    email = clean_text(form.get("email"), "Email", limit=255, required=False)
    # Set by an administrator, never guessed.  A sign in name here and a login
    # on the host are two different things, and matching them by guessing
    # hands somebody the wrong repositories.
    github_login = clean_text(form.get("github_login"), "Login on the host",
                              limit=255, required=False)
    if email and ("@" not in email or " " in email):
        raise HTTPException(status_code=400, detail="That is not an email address.")

    password = ""
    with session_scope() as db:
        if db.query(User).filter(User.username == username).count():
            raise HTTPException(status_code=409,
                                detail=f"There is already an account called {username}.")

        row = User(username=username, display_name=display_name, email=email,
                   github_login=github_login,
                   role=role, source=source)
        if source == AuthSource.LOCAL:
            password = _new_password()
            row.password_hash = hash_password(password)
            row.must_change_password = True
        db.add(row)
        db.flush()

        _apply_scopes(db, row, str(form.get("scopes", "")))
        _apply_groups(db, row, form)
        record(db, "user.added", actor=user.username, target=username,
               detail=f"{role.value}, {source.value}", source_ip=client_ip(request))

    if password:
        # The password goes by way of oneshot, never the URL, which every log
        # on the way would keep.
        from app.web import oneshot
        key = oneshot.put(user.id, f"Made {username}. The starting password is "
                                   f"{password} . It is shown once, so pass it on now.")
        return redirect(f"/users?once={quote(key)}&kind=ok")
    message = (f"Made {username}. They sign in through the provider, so "
               "there is no password to hand over.")
    return redirect(f"/users?msg={quote(message)}&kind=ok")


@router.post("/users/{user_id}/save")
async def save_user(user_id: int, request: Request,
                    user: User = Depends(current_user)):
    """Change a role, a name, or what a developer can see."""
    await check_csrf(request)
    rbac.require(user, "user.write")

    form = await request.form()
    role_name = str(form.get("role", "")).strip().lower()
    if role_name not in {r.value for r in UserRole}:
        raise HTTPException(status_code=400, detail="Pick a role.")
    role = UserRole(role_name)

    display_name = clean_text(form.get("display_name"), "Name", limit=255,
                              required=False)
    email = clean_text(form.get("email"), "Email", limit=255, required=False)
    # Set by an administrator, never guessed.  A sign in name here and a login
    # on the host are two different things, and matching them by guessing
    # hands somebody the wrong repositories.
    github_login = clean_text(form.get("github_login"), "Login on the host",
                              limit=255, required=False)

    with session_scope() as db:
        row = _load_user(db, user_id)

        # Taking the last admin away leaves nobody who can put it back, and the
        # only way out of that is the recovery script.
        if (row.role == UserRole.ADMIN and role != UserRole.ADMIN
                and not _other_admins(db, row.id)):
            raise HTTPException(
                status_code=400,
                detail="That is the only admin left. Make somebody else an "
                       "admin first.")

        row.role = role
        row.role_pinned = _checked(form, "role_pinned")
        row.display_name = display_name
        row.email = email
        row.github_login = github_login
        _apply_scopes(db, row, str(form.get("scopes", "")))
        _apply_groups(db, row, form)
        record(db, "user.changed", actor=user.username, target=row.username,
               detail=f"role {role.value}"
                      + (", held against the provider" if row.role_pinned else ""),
               source_ip=client_ip(request))

    return redirect("/users?msg=Saved.&kind=ok")


@router.post("/severity/add")
async def add_severity_rule(request: Request, user: User = Depends(current_user)):
    """Say what a rule or a CWE is worth here."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import settings_store as sev_store, severity_rules

    form = await request.form()
    # The conditions after the first.  Four slots, posted whether they were
    # filled in or not, and an empty pair is somebody not using that slot
    # rather than a mistake.
    extra = []
    for slot in (2, 3, 4, 5):
        field = str(form.get(f"field{slot}", "") or "").strip()
        value = clean_text(form.get(f"value{slot}"), "Value", limit=200,
                           required=False)
        if field or value:
            extra.append({"field": field, "value": value})

    with session_scope() as db:
        row, why = severity_rules.add(
            db,
            str(form.get("match_type", "rule")),
            clean_text(form.get("pattern"), "Pattern", limit=200),
            str(form.get("severity", "low")),
            actor=user.username,
            reason=clean_text(form.get("reason"), "Reason", limit=2000,
                              required=False),
            unless_sensitivity=", ".join(
                label for label in sev_store.sensitivity_labels(db)
                if _checked(form, f"unless:{label}")),
            conditions=extra,
            combine=str(form.get("combine", "all") or "all"))
        if row is None:
            return redirect(f"/severity?msg={quote(why)}&kind=error")
        described = severity_rules.describe(row)
        covers = severity_rules.matching_count(
            db, row, base=rbac.visible_findings(db, user))
        record(db, "severity.override.set", actor=user.username,
               target=described,
               detail=f"{row.severity.value}: {row.reason[:200]}",
               source_ip=client_ip(request))
        # How much this covers, said back straight away.  A rule is a decision
        # about a set somebody cannot see, and two findings and two hundred
        # are the same sentence.
        message = (f"{described} is {row.severity.value} here, "
                   f"which covers {covers} finding"
                   f"{'' if covers == 1 else 's'} today. "
                   "It applies from the next scan.")
    return redirect(f"/severity?msg={quote(message)}&kind=ok")


@router.post("/severity/{rule_id}/delete")
async def delete_severity_rule(rule_id: int, request: Request,
                               user: User = Depends(current_user)):
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import severity_rules

    with session_scope() as db:
        row = db.query(m_SeverityRule).filter(
            m_SeverityRule.id == rule_id).one_or_none()
        target = f"{row.match_type}:{row.pattern}" if row else str(rule_id)
        if not severity_rules.remove(db, rule_id):
            raise HTTPException(status_code=404, detail="No such override.")
        record(db, "severity.override.removed", actor=user.username,
               target=target, source_ip=client_ip(request))
    return redirect(f"/severity?msg={quote('Override removed.')}&kind=ok")


@router.post("/tokens/create")
async def create_token(request: Request, user: User = Depends(current_user)):
    """Make a token for yourself.

    No permission check beyond being signed in.  A token is the person who made
    it with less of them, so somebody making one gives away nothing they did
    not already have.
    """
    await check_csrf(request)

    from urllib.parse import quote

    from app.core import api_tokens

    form = await request.form()
    name = clean_text(form.get("name"), "Name", limit=120)
    wanted = [scope for scope in api_tokens.SCOPES
              if _checked(form, f"scope:{scope}")]
    days = clean_int(form.get("days", api_tokens.DEFAULT_DAYS), "Days",
                     low=1, high=api_tokens.MAX_DAYS)

    with session_scope() as db:
        owner = db.query(User).filter(User.id == user.id).one()
        try:
            row, raw = api_tokens.create(db, owner, name, wanted, days=days)
        except ValueError as exc:
            return redirect(f"/tokens?msg={quote(str(exc))}&kind=error")
        record(db, "api_token.created", actor=user.username, target=row.name,
               detail=f"{row.scopes}, {days} day(s)", source_ip=client_ip(request))

    # The only time it is ever readable.  It used to go in the address, which
    # left a live bearer token in every access log; now only a one time key
    # does, and the page takes the token out of memory once.
    from app.web import oneshot
    key = oneshot.put(user.id, raw)
    return redirect(f"/tokens?shown={quote(key)}&msg=" + quote(
        "Copy it now.  It cannot be shown again."))


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(token_id: int, request: Request,
                       user: User = Depends(current_user)):
    """Delete a token.  Your own, or anybody's if you administer users."""
    await check_csrf(request)

    from urllib.parse import quote

    from app.core import api_tokens

    with session_scope() as db:
        owner = db.query(User).filter(User.id == user.id).one()
        if not api_tokens.revoke(db, token_id, actor=owner):
            # Somebody else's token and not an administrator looks exactly
            # like one that is not there.
            raise HTTPException(status_code=404, detail="No such token.")
        record(db, "api_token.revoked", actor=user.username,
               target=str(token_id), source_ip=client_ip(request))

    return redirect("/tokens?msg=" + quote("That token no longer works."))


@router.post("/tokens/{token_id}/delete")
async def delete_token(token_id: int, request: Request,
                       user: User = Depends(current_user)):
    """Take the row away.

    Revoking stops a token working and keeps the row.  This removes it, which
    is what somebody clearing up wants.  The audit log keeps the record either
    way, so nothing worth having goes with it.
    """
    await check_csrf(request)

    from urllib.parse import quote

    from app.core import api_tokens

    with session_scope() as db:
        owner = db.query(User).filter(User.id == user.id).one()
        row = db.query(m_ApiToken).filter(m_ApiToken.id == token_id).one_or_none()
        name = row.name if row is not None else str(token_id)
        if not api_tokens.remove(db, token_id, actor=owner):
            raise HTTPException(status_code=404, detail="No such token.")
        record(db, "api_token.deleted", actor=user.username, target=name,
               source_ip=client_ip(request))

    return redirect("/tokens?msg=" + quote("Deleted."))


@router.post("/tagging/apply")
async def apply_tags(request: Request, user: User = Depends(current_user)):
    """Say what some repositories are, who owns them and what they hold.

    Takes several at once, because tagging an estate one repository at a time
    is not something anybody finishes.
    """
    await check_csrf(request)
    rbac.require(user, "repo.write")

    from urllib.parse import quote

    from app.core import tagging

    form = await request.form()
    ids = form_ids(form, "repo_ids", "ids")
    if not ids:
        raise HTTPException(status_code=400, detail="Pick a repository first.")

    values = {
        "application_name": clean_text(form.get("application_name"), "Application",
                                       limit=200, required=False),
        # An owner has to be somebody who can be asked, which means an address
        # rather than a name.
        "technical_owner": clean_email(form.get("technical_owner"),
                                       "Technical owner"),
        "application_owner": clean_email(form.get("application_owner"),
                                         "Application owner"),
    }

    with session_scope() as db:
        # The labels are tick boxes, so an empty set means "leave it alone"
        # unless somebody says otherwise on purpose.
        chosen = [label for label in tagging.labels(db)
                  if _checked(form, f"holds:{label}")]
        if chosen:
            values["sensitivity"] = ", ".join(chosen)
        elif str(form.get("clear_holds", "")) == "1":
            values["sensitivity"] = "-"

        changed = tagging.tag(db, ids, values, actor=user.username)
        if changed:
            said = ", ".join(f"{k.replace('_', ' ')}={v}"
                             for k, v in values.items() if v)
            record(db, "repository.tagged", actor=user.username,
                   target=f"{changed} repositories", detail=said[:200],
                   source_ip=client_ip(request))

    return redirect("/tagging?msg=" + quote(
        f"Tagged {changed} repositor{'y' if changed == 1 else 'ies'}."))


@router.post("/backup/create")
async def create_backup(request: Request, user: User = Depends(current_user)):
    """Everything this installation knows, as one encrypted file."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from fastapi.responses import Response

    from app.core import backup

    form = await request.form()
    password = str(form.get("password", ""))
    confirm = str(form.get("password_confirm", ""))
    if password != confirm:
        raise HTTPException(status_code=400, detail="The two passwords differ.")

    with session_scope() as db:
        try:
            blob = backup.create(db, password, actor=user.username)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # The password is not recorded anywhere, so the log says a backup was
        # taken and by whom, and nothing that would help open it.
        record(db, "backup.created", actor=user.username,
               detail=f"{len(blob)} bytes", source_ip=client_ip(request))

    stamp = utcnow().strftime("%Y%m%d-%H%M")
    return Response(
        content=blob, media_type="application/zip",
        headers={"Content-Disposition":
                 f'attachment; filename="git-code-review-backup-{stamp}.zip"',
                 "Cache-Control": "no-store"})


@router.post("/backup/restore")
async def restore_backup(request: Request, user: User = Depends(current_user)):
    """Replace this installation with the contents of a backup.

    Everything here goes, including the account doing the restoring.  That is
    the point of a restore, and it is why this asks for the word first.
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import backup

    form = await request.form()
    if str(form.get("confirm", "")).strip().upper() != "REPLACE":
        raise HTTPException(
            status_code=400,
            detail="Type REPLACE to confirm.  Restoring removes everything "
                   "here first, including your own account.")

    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise HTTPException(status_code=400, detail="Choose a backup file.")
    blob = await upload.read()
    if not blob:
        raise HTTPException(status_code=400, detail="That file is empty.")
    if len(blob) > backup.MAX_ARCHIVE_BYTES:
        raise HTTPException(status_code=413, detail="That file is too large.")

    password = str(form.get("password", ""))

    with session_scope() as db:
        try:
            result = backup.restore(db, blob, password)
        except ValueError as exc:
            return redirect(f"/backup?msg={quote(str(exc))}&kind=error")
        rows = sum(result["written"].values())
        made = result["manifest"].get("created_at", "")
        record(db, "backup.restored", actor=user.username,
               detail=f"{rows} rows from a backup taken {made}",
               source_ip=client_ip(request))

    # Every session went with the rest of it, so there is nothing to sign out.
    return redirect("/login?msg=" + quote(
        f"Restored {rows} rows.  Sign in with an account from the backup."))


@router.post("/findings/{finding_id}/regrade")
async def regrade_finding(finding_id: int, request: Request,
                          user: User = Depends(current_user)):
    """What this one finding is worth here.

    Not the same instrument as a severity rule.  A rule level override moves
    every finding that rule ever produced, which is right for "a plain HTTP
    link is a low here" and wrong for "this particular line is not a high".
    This covers one finding and nothing else, and it survives the next scan
    because ingest reapplies it after the engine has had its say.
    """
    await check_csrf(request)
    rbac.require(user, "finding.regrade")

    from urllib.parse import quote

    form = await request.form()
    wanted = str(form.get("severity", "")).strip().lower()
    try:
        severity = Severity(wanted)
    except ValueError:
        raise HTTPException(status_code=400, detail="That is not a severity.")

    reason = clean_text(form.get("reason"), "Reason", limit=2000)
    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say why in a sentence or two.  A grade nobody explained is "
                   "a grade nobody can review.")

    with session_scope() as db:
        finding = (rbac.visible_findings(db, user)
                   .filter(Finding.id == finding_id).one_or_none())
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")

        was = finding.severity
        # Keep whatever the engine said, once.  Regrading twice must not end up
        # recording the first override as though the engine had said it.
        finding.engine_severity = finding.engine_severity or was.value
        finding.custom_severity = severity
        finding.custom_severity_reason = reason
        finding.custom_severity_by = user.username
        finding.custom_severity_at = utcnow()
        finding.severity = severity
        db.flush()
        # The code this decision was made against, so a later scan keeps it
        # while that code is unchanged and lifts it once it is not.
        from app.core import learned
        learned.record_basis(db, finding, "person")

        request_rewrite()
        record(db, "finding.regraded", actor=user.username,
               target=finding.vuln_id or str(finding.id),
               detail=f"{was.value} to {severity.value}: {reason[:200]}",
               source_ip=client_ip(request))

    return redirect(f"/findings/{finding_id}?msg=" + quote(
        f"Graded {severity.value} here.  The engine's grade is still on the "
        "record beside it."))


@router.post("/findings/{finding_id}/certify")
async def certify_from_finding(finding_id: int, request: Request,
                               user: User = Depends(current_user)):
    """Sign off the branch this finding is on.

    Done from a finding because that is where somebody is when they finish
    reading one: they have the repository, the branch and the commit in front
    of them, and asking them to go and find the same three things on another
    page is how a review ends up recorded against the wrong branch.

    It changes nothing about any finding.  Not the grade, not the state, not
    what appears in a report.  It records that a person looked and what they
    concluded, and every page that shows the badge also shows when it stops
    being true.
    """
    await check_csrf(request)
    rbac.require(user, "repo.certify")

    from urllib.parse import quote

    from app.core import certification

    form = await request.form()
    note = clean_text(form.get("note"), "Note", limit=4000)
    expires_at = _parse_expiry(str(form.get("expires", "")))

    with session_scope() as db:
        finding = (rbac.visible_findings(db, user)
                   .filter(Finding.id == finding_id).one_or_none())
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")

        # The branch head, not this finding's commit.  The finding's commit is
        # where the finding was found, which may be years behind the branch;
        # certifying against it would report the review as out of date the
        # instant it was written.
        head = certification.head_of(db, finding.repository, finding.branch)
        row, problem = certification.certify(
            db, finding.repository, finding.branch, note, expires_at,
            user.username, head)
        if problem:
            raise HTTPException(status_code=400, detail=problem)

        record(db, "repo.certified", actor=user.username,
               target=f"{finding.repository}@{finding.branch or 'default'}",
               detail=f"until {row.expires_at:%Y-%m-%d}: {note[:150]}",
               source_ip=client_ip(request))
        where = f"{finding.repository} on {finding.branch or 'the default branch'}"

    return redirect(f"/findings/{finding_id}?msg=" + quote(
        f"Certified {where}.  It lapses on the date you set, and reads as out "
        "of date the moment a new finding arrives.") + "&kind=ok")


@router.post("/findings/{finding_id}/certify/revoke")
async def revoke_certification(finding_id: int, request: Request,
                               user: User = Depends(current_user)):
    """Take a sign off back.  Kept on the record, not deleted."""
    await check_csrf(request)
    rbac.require(user, "repo.certify")

    from urllib.parse import quote

    from app.core import certification

    form = await request.form()
    reason = clean_text(form.get("reason"), "Reason", limit=2000, required=False)

    with session_scope() as db:
        finding = (rbac.visible_findings(db, user)
                   .filter(Finding.id == finding_id).one_or_none())
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        _row, problem = certification.revoke(
            db, finding.repository, finding.branch, user.username, reason)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        record(db, "repo.certification_revoked", actor=user.username,
               target=f"{finding.repository}@{finding.branch or 'default'}",
               detail=reason[:200], source_ip=client_ip(request))

    return redirect(f"/findings/{finding_id}?msg=" + quote(
        "The certification is withdrawn.  The record that it was given, and "
        "taken back, stays.") + "&kind=warn")


@router.post("/findings/{finding_id}/certify/not-applicable")
async def exempt_from_certification(finding_id: int, request: Request,
                                    user: User = Depends(current_user)):
    """Say this branch is not one anybody is expected to sign off.

    Done from a finding for the same reason certifying is: the repository and
    the branch are already in front of whoever decided it.

    It certifies nothing.  The finding keeps its grade and its state, it stays
    in every report, and no badge turns green.  The only thing it changes is
    that the branch stops counting as coverage somebody still owes, which is
    what makes the coverage figure worth reading at all.
    """
    await check_csrf(request)
    rbac.require(user, "repo.certify.exempt")

    from urllib.parse import quote

    from app.core import certification

    form = await request.form()
    reason = clean_text(form.get("reason"), "Reason", limit=4000, required=True)

    with session_scope() as db:
        finding = (rbac.visible_findings(db, user)
                   .filter(Finding.id == finding_id).one_or_none())
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        _row, problem = certification.mark_not_applicable(
            db, finding.repository, finding.branch, reason, user.username)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        record(db, "repo.certification_not_applicable", actor=user.username,
               target=f"{finding.repository}@{finding.branch or 'default'}",
               detail=reason[:200], source_ip=client_ip(request))

    return redirect(f"/findings/{finding_id}?msg=" + quote(
        "Marked as not applicable.  This branch is left out of the coverage "
        "figure entirely, and every finding on it is reported as before.")
        + "&kind=ok")


@router.post("/findings/{finding_id}/certify/applicable")
async def unexempt_from_certification(finding_id: int, request: Request,
                                      user: User = Depends(current_user)):
    """Put the branch back among the ones a sign off is expected on."""
    await check_csrf(request)
    rbac.require(user, "repo.certify.exempt")

    from urllib.parse import quote

    from app.core import certification

    with session_scope() as db:
        finding = (rbac.visible_findings(db, user)
                   .filter(Finding.id == finding_id).one_or_none())
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        _row, problem = certification.clear_not_applicable(
            db, finding.repository, finding.branch, user.username)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        record(db, "repo.certification_applicable", actor=user.username,
               target=f"{finding.repository}@{finding.branch or 'default'}",
               detail="expected to be reviewed again",
               source_ip=client_ip(request))

    return redirect(f"/findings/{finding_id}?msg=" + quote(
        "This branch counts towards coverage again.") + "&kind=ok")


def _branch_in_reach(db, user, repository: str, branch: str):
    """The repository named, if this person may act on it.  -> row or None.

    Addressed by name rather than through a finding, so the answer has to come
    from the repository scope directly.  A repository the reader cannot see and
    one that is not there answer the same way, because telling them apart turns
    a name into a way to find out what exists.
    """
    from app.core.models import Repository

    if not repository:
        return None
    return (rbac.visible_repositories(db, user)
            .filter(Repository.full_name == repository).one_or_none())


@router.post("/certifications/certify")
async def certify_a_branch(request: Request,
                           user: User = Depends(current_user)):
    """Sign off a branch named directly, rather than through a finding.

    The form on a finding covers the case where somebody has just read one.
    It cannot cover the case that matters most here: a branch with no findings
    on it at all.  Those are exactly the branches a scan signs off
    automatically, and when somebody then pushes to one the badge turns amber
    and there is no finding anywhere on that branch to open the form from.

    So an amber badge on a branch nobody has ever filed a finding against could
    not be re-certified, withdrawn, or made to go away by any route in the
    product.  It simply sat there.
    """
    await check_csrf(request)
    rbac.require(user, "repo.certify")

    from app.core import certification

    form = await request.form()
    repository = clean_text(form.get("repository"), "Repository", limit=320)
    branch = clean_text(form.get("branch"), "Branch", limit=255, required=False)
    note = clean_text(form.get("note"), "Note", limit=4000)
    expires_at = _parse_expiry(str(form.get("expires", "")))
    back = str(form.get("back", "") or "/repositories")

    with session_scope() as db:
        if _branch_in_reach(db, user, repository, branch) is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        head = certification.head_of(db, repository, branch)
        row, problem = certification.certify(
            db, repository, branch, note, expires_at, user.username, head)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        record(db, "repo.certified", actor=user.username,
               target=f"{repository}@{branch or 'default'}",
               detail=f"until {row.expires_at:%Y-%m-%d}: {note[:150]}",
               source_ip=client_ip(request))
        where = f"{repository} on {branch or 'the default branch'}"

    return redirect(_back_with(
        _safe_back(back),
        f"Certified {where}.  It lapses on the date you set, and reads as out "
        "of date the moment somebody pushes or a new finding arrives."))


@router.post("/certifications/revoke")
async def revoke_a_branch(request: Request,
                          user: User = Depends(current_user)):
    """Withdraw a sign off on a branch named directly.  Kept, not deleted."""
    await check_csrf(request)
    rbac.require(user, "repo.certify")

    from app.core import certification

    form = await request.form()
    repository = clean_text(form.get("repository"), "Repository", limit=320)
    branch = clean_text(form.get("branch"), "Branch", limit=255, required=False)
    reason = clean_text(form.get("reason"), "Reason", limit=2000, required=False)
    back = str(form.get("back", "") or "/repositories")

    with session_scope() as db:
        if _branch_in_reach(db, user, repository, branch) is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        _row, problem = certification.revoke(
            db, repository, branch, user.username, reason)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        record(db, "repo.certification_revoked", actor=user.username,
               target=f"{repository}@{branch or 'default'}",
               detail=reason[:200], source_ip=client_ip(request))

    return redirect(_back_with(
        _safe_back(back),
        "The certification is withdrawn.  The record that it was given, and "
        "taken back, stays.", "warn"))


@router.post("/certifications/revoke-bulk")
async def revoke_branches(request: Request,
                          user: User = Depends(current_user)):
    """Withdraw a set of sign offs in one go.

    One dependency bump is the same finding in forty repositories, and one
    scan is the same automatic sign off across an estate.  Taking them back one
    at a time is how a list nobody can act on stays a list nobody acts on.

    Ticked rows rather than "everything matching the filter", because a filter
    can change under somebody between reading the page and pressing the button,
    and a mistake here is silent: a withdrawn sign off looks exactly like one
    that was never given.

    It is the same permission check as withdrawing one, applied per row.  A
    repository the account cannot see is skipped rather than withdrawn.
    """
    await check_csrf(request)
    rbac.require(user, "repo.certify")

    from app.core import certification

    form = await request.form()
    wanted = [str(v) for v in form.getlist("pair") if str(v).strip()]
    reason = clean_text(form.get("reason"), "Reason", limit=2000)
    back = str(form.get("back", "") or "/repositories")
    if not wanted:
        raise HTTPException(status_code=400,
                            detail="Tick the ones to withdraw first.")

    done = skipped = 0
    with session_scope() as db:
        for pair in wanted[:500]:
            # repository and branch, separated by a space: a branch may hold
            # every other punctuation mark and a repository name may not hold
            # a space at all.
            repository, _, branch = pair.partition(" ")
            if _branch_in_reach(db, user, repository, branch) is None:
                skipped += 1
                continue
            _row, problem = certification.revoke(
                db, repository, branch, user.username, reason)
            if problem:
                skipped += 1
                continue
            record(db, "repo.certification_revoked", actor=user.username,
                   target=f"{repository}@{branch or 'default'}",
                   detail=reason[:200], source_ip=client_ip(request))
            done += 1

    note = "%d certification%s withdrawn." % (done, "" if done == 1 else "s")
    if skipped:
        note += ("  %d left alone: already withdrawn, or not yours to take back."
                 % skipped)
    return redirect(_back_with(_safe_back(back), note, "warn"))


@router.post("/findings/regrade-bulk")
async def regrade_many(request: Request, user: User = Depends(current_user)):
    """What a set of findings is worth here, decided once.

    The single regrade covers one line, which is right when the argument is
    about that line.  It is the wrong instrument for the shape this keeps
    arriving in: one unpatched base image produced eighty six findings on a
    single repository, one Django rule on a codebase that does not use Django
    produced fifty two, and every one of them is the same decision made over
    and over.  Made one at a time that is not review, it is data entry, and
    data entry is where people stop reading what they are agreeing to.

    So the same reason goes on every one of them, and it is required, because
    the whole value of doing this in bulk is that somebody had one thought
    about a set rather than no thought about each.

    Not a severity rule, and the difference is worth keeping straight.  A rule
    level override moves every finding that rule will ever produce, anywhere.
    This moves the ones that were ticked, and a later scan finding a new one
    leaves it at whatever the engine says, which is the safe way round.
    """
    await check_csrf(request)
    rbac.require(user, "finding.regrade")


    form = await request.form()
    # new_severity rather than severity, because the bulk form already carries
    # severity as the filter that chose these findings.  One name for two
    # meanings would have graded everything to whatever the list was filtered
    # by, which is a silent and very wrong outcome.
    wanted_severity = str(form.get("new_severity", "")).strip().lower()
    try:
        severity = Severity(wanted_severity)
    except ValueError:
        raise HTTPException(status_code=400, detail="That is not a severity.")

    # regrade_reason rather than reason, for the same reason new_severity is
    # not severity: the waive panel shares this form and has a reason of its
    # own, and one key holding two panels' text is a wrong value that looks
    # like a right one.
    reason = clean_text(form.get("regrade_reason"), "Reason", limit=2000)
    if len(reason) < 20:
        raise HTTPException(
            status_code=400,
            detail="Say why in a sentence or two.  The same reason goes on "
                   "every one of these, and a grade nobody explained is a "
                   "grade nobody can review.")

    wanted = []
    for raw in form.getlist("ids"):
        for piece in str(raw).split(","):
            piece = piece.strip()
            if piece.isdigit():
                wanted.append(int(piece))

    everything = str(form.get("all_matching", "")).lower() in {"1", "on", "true"}
    if not wanted and not everything:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    counts = {"changed": 0, "already": 0}

    with session_scope() as db:
        # Always through the scope filter, so a list of ids from somewhere else
        # matches nothing rather than regrading somebody else's findings.
        query = rbac.visible_findings(db, user)
        if everything:
            query = _apply_finding_filters(query, form, db, user)
        else:
            query = query.filter(Finding.id.in_(wanted))

        findings = query.limit(MAX_BULK_WAIVE + 1).all()
        if len(findings) > MAX_BULK_WAIVE:
            raise HTTPException(
                status_code=400,
                detail=f"That is more than {MAX_BULK_WAIVE} findings. Narrow "
                       "the filters and do it in batches.")

        from app.core import learned
        for finding in findings:
            if finding.custom_severity == severity:
                counts["already"] += 1
                continue
            was = finding.severity
            # Keep whatever the engine said, once.  Regrading twice must not
            # record the first override as though the engine had said it.
            finding.engine_severity = finding.engine_severity or was.value
            finding.custom_severity = severity
            finding.custom_severity_reason = reason
            finding.custom_severity_by = user.username
            finding.custom_severity_at = utcnow()
            finding.severity = severity
            learned.record_basis(db, finding, "person")
            counts["changed"] += 1
        db.flush()

        if counts["changed"]:
            request_rewrite()
        # One audit line for one decision.  The findings carry who and why,
        # so a line each would say the same sentence a hundred times and bury
        # everything around it.
        record(db, "finding.regraded", actor=user.username,
               target=f"{counts['changed']} findings",
               detail=f"bulk to {severity.value}: {reason[:150]}",
               source_ip=client_ip(request))

    parts = [f"{counts['changed']} finding(s) graded {severity.value} here"]
    if counts["already"]:
        parts.append(f"{counts['already']} already were")
    parts.append("the engine's grades are still on the record beside them")
    return redirect(_back_with(_findings_back(form), '. '.join(parts) + '.'))


@router.post("/findings/{finding_id}/regrade/clear")
async def clear_regrade(finding_id: int, request: Request,
                        user: User = Depends(current_user)):
    """Put it back to what the engine and the rules say."""
    await check_csrf(request)
    rbac.require(user, "finding.regrade")

    from urllib.parse import quote

    with session_scope() as db:
        finding = (rbac.visible_findings(db, user)
                   .filter(Finding.id == finding_id).one_or_none())
        if finding is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        if finding.custom_severity is None:
            raise HTTPException(status_code=400,
                                detail="That finding has no override on it.")

        was = finding.custom_severity
        # Back to the engine's grade.  The next scan reapplies whatever rule
        # level override there is, which is the right answer and not this
        # endpoint's job to guess at.
        if finding.engine_severity:
            try:
                finding.severity = Severity(finding.engine_severity)
            except ValueError:
                pass
        finding.custom_severity = None
        finding.custom_severity_reason = ""
        finding.custom_severity_by = ""
        finding.custom_severity_at = None
        # An AI grade under the regrade stands again now that nobody is
        # speaking over it, the same as the next scan would decide.
        from app.core import learned
        from app.core.models import AIGrade, GradeBasis
        grade = db.query(AIGrade).filter(AIGrade.finding_id == finding.id).one_or_none()
        if (grade is not None and not learned.protected(finding)
                and learned.lower(finding.severity, grade.severity)):
            finding.severity = grade.severity
        db.query(GradeBasis).filter(GradeBasis.finding_id == finding.id,
                                    GradeBasis.source == "person").delete()
        db.flush()

        request_rewrite()
        record(db, "finding.regrade_cleared", actor=user.username,
               target=finding.vuln_id or str(finding.id),
               detail=f"was {was.value}", source_ip=client_ip(request))

    return redirect(f"/findings/{finding_id}?msg=" + quote(
        "Back to the grade the engine gave it."))


@router.post("/users/{user_id}/impersonate")
async def impersonate(user_id: int, request: Request,
                      user: User = Depends(current_user)):
    """Look at the product as somebody else.

    For the question an administrator cannot otherwise answer: what does this
    person actually see.  Scope, groups and role decide most of what is on
    every page here, and reading the rules is not the same as seeing the
    result.

    It is read only, enforced in middleware rather than here, and both ends of
    it are on the record.
    """
    await check_csrf(request)
    rbac.require(user, "user.impersonate")

    from urllib.parse import quote

    from app.core.models import Session as m_Session

    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        raise HTTPException(status_code=403, detail="No session to borrow with.")

    with session_scope() as db:
        row = auth_service.current_session(db, token, client_ip(request))
        if row is None:
            raise HTTPException(status_code=403, detail="No session to borrow with.")
        if row.impersonating_id:
            raise HTTPException(
                status_code=400,
                detail="You are already looking at this as somebody else.  "
                       "Stop first.")

        target = db.query(User).filter(User.id == user_id).one_or_none()
        if target is None:
            raise HTTPException(status_code=404, detail="No such user.")
        if target.id == row.user_id:
            raise HTTPException(status_code=400,
                                detail="That is you.")
        if target.disabled:
            raise HTTPException(
                status_code=400,
                detail="That account is disabled, so there is no view to see.")

        row.impersonating_id = target.id
        row.impersonating_since = utcnow()
        db.flush()

        record(db, "user.impersonation_started", actor=user.username,
               target=target.username,
               detail="read only; every page answers as they would see it",
               source_ip=client_ip(request))
        name = target.username

    return redirect("/?msg=" + quote(
        f"You are looking at this as {name}.  Nothing can be changed until "
        "you stop."))


@router.post("/impersonate/stop")
async def impersonate_stop(request: Request):
    """Give the view back.

    Deliberately not behind current_user: that returns the borrowed account,
    and the way out must not depend on what that account is allowed to do.
    The session itself is the authority here, and it still belongs to the
    administrator whatever it is currently showing.
    """
    await check_csrf(request)

    from urllib.parse import quote

    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return redirect("/login")

    with session_scope() as db:
        row = auth_service.current_session(db, token, client_ip(request))
        if row is None:
            return redirect("/login")
        if not row.impersonating_id:
            return redirect("/users?msg=" + quote("You were not impersonating."))

        borrowed = (db.query(User)
                    .filter(User.id == row.impersonating_id).one_or_none())
        real = db.query(User).filter(User.id == row.user_id).one_or_none()
        row.impersonating_id = None
        row.impersonating_since = None
        db.flush()

        record(db, "user.impersonation_stopped",
               actor=(real.username if real else ""),
               target=(borrowed.username if borrowed else ""),
               source_ip=client_ip(request))

    return redirect("/users?msg=" + quote("You are yourself again."))


@router.post("/tagging/import")
async def import_tagging(request: Request, user: User = Depends(current_user)):
    """Read a tagging spreadsheet back in.

    The workflow this is for: export, open it in whatever the asset list lives
    in, fill the columns, hand it back.  Tagging two hundred repositories
    through a form is data entry rather than a decision.
    """
    await check_csrf(request)
    rbac.require(user, "repo.write")

    from urllib.parse import quote

    from app.core import tagging

    form = await request.form()
    upload = form.get("file")
    if upload is None or not hasattr(upload, "read"):
        raise HTTPException(status_code=400, detail="Choose a file first.")

    raw = await upload.read()
    if len(raw) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"That file is larger than "
                   f"{MAX_IMPORT_BYTES // (1024 * 1024)}MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Spreadsheets on Windows still write this, and refusing it with a
        # decoding error tells nobody anything.
        text = raw.decode("latin-1", "replace")

    with session_scope() as db:
        result = tagging.from_csv(db, text, actor=user.username)
        record(db, "tagging.imported", actor=user.username,
               detail=(f"{result['changed']} changed, "
                       f"{result['unchanged']} unchanged, "
                       f"{result['unknown']} not recognized"),
               outcome="warn" if result["unknown"] else "ok",
               source_ip=client_ip(request))

    said = (f"{result['changed']} repository(ies) updated, "
            f"{result['unchanged']} already matched")
    if result["unknown"]:
        said += (f", {result['unknown']} not recognized: "
                 + "; ".join(result["problems"][:3]))
    return redirect("/tagging?kind=" + ("warn" if result["unknown"] else "ok")
                    + "&msg=" + quote(said))


@router.post("/blast-radius/repo/{repo_id}/describe")
async def describe_repository(repo_id: int, request: Request,
                              user: User = Depends(current_user)):
    """Say what a repository is, in somebody's own words.

    The tagging fields answer fixed questions.  This is for the sentence that
    decides what to do and fits none of them: that it is the payment gateway,
    that it is being retired in March, that the owner left.  An administrator
    only, because it is read as authoritative.
    """
    await check_csrf(request)
    rbac.require(user, "repo.describe")

    from app.core.models import Repository as m_Repository

    form = await request.form()
    note = clean_text(form.get("note"), "Description", limit=4000,
                      required=False)
    # Through the same check as every other return-to-where-you-were: a
    # leading slash on its own still leaves //somewhere.else, which a browser
    # reads as another host and follows.
    back = clean_text(form.get("back"), "Back", limit=300, required=False)
    back = _safe_back(back) if back else "/blast-radius"

    with session_scope() as db:
        repo = (db.query(m_Repository)
                .filter(m_Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")

        was = (repo.note or "").strip()
        repo.note = note
        if note != was:
            repo.note_by = user.username
            repo.note_at = utcnow()
        db.flush()

        record(db, "repo.described" if note else "repo.description_cleared",
               actor=user.username, target=repo.full_name,
               detail=note[:200], source_ip=client_ip(request))

    return redirect(_back_with(
        back, "Saved." if note else "Description removed."))


@router.post("/notifications/save")
async def save_notifications(request: Request,
                             user: User = Depends(current_user)):
    """Where messages go, and what is worth sending one about."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import settings_store as store

    form = await request.form()

    severity = str(form.get("notify.min_severity", "high")).strip().lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        raise HTTPException(status_code=400, detail="Pick a severity floor.")

    security = str(form.get("notify.smtp_security", "starttls")).strip().lower()
    if security not in {"starttls", "ssl", "none"}:
        raise HTTPException(status_code=400,
                            detail="Mail security is starttls, ssl, or none.")

    transport = str(form.get("notify.mail_transport", "smtp")).strip().lower()
    if transport not in {"smtp", "graph"}:
        raise HTTPException(status_code=400,
                            detail="Mail goes by SMTP or Microsoft 365.")

    fmt = str(form.get("notify.email_format", "text")).strip().lower()
    if fmt not in {"text", "html"}:
        raise HTTPException(status_code=400,
                            detail="Mail is plain text or HTML.")

    port = clean_int(form.get("notify.smtp_port", 587) or 587, "Port",
                     low=1, high=65535)

    base = clean_text(form.get("notify.base_url"), "Address", limit=500,
                      required=False)
    if base and not base.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400,
                            detail="The address starts with http:// or https://.")

    with session_scope() as db:
        moved = []

        def put(key, value):
            if store.set_value(db, key, value, user.username):
                moved.append(key)

        put("notify.enabled", _checked(form, "notify.enabled"))
        put("notify.min_severity", severity)
        put("notify.base_url", base.rstrip("/"))
        put("notify.email_to", clean_text(form.get("notify.email_to"), "To",
                                          limit=500, required=False))
        put("notify.email_from", clean_text(form.get("notify.email_from"),
                                            "From", limit=320, required=False))
        put("notify.smtp_host", clean_text(form.get("notify.smtp_host"),
                                           "Server", limit=255, required=False))
        put("notify.smtp_port", port)
        put("notify.smtp_security", security)
        # Both of these stay optional.  An internal relay that accepts mail
        # from this host by address wants no credential, and requiring one
        # would stop a working setup working.
        put("notify.smtp_user", clean_text(form.get("notify.smtp_user"),
                                           "Username", limit=255,
                                           required=False))

        put("notify.mail_transport", transport)
        put("notify.email_format", fmt)
        put("notify.attach_csv", _checked(form, "notify.attach_csv"))
        put("notify.graph_tenant", clean_text(form.get("notify.graph_tenant"),
                                              "Tenant id", limit=100,
                                              required=False))
        put("notify.graph_client_id", clean_text(form.get("notify.graph_client_id"),
                                                 "Client id", limit=100,
                                                 required=False))
        put("notify.graph_sender", clean_text(form.get("notify.graph_sender"),
                                              "Sender", limit=320,
                                              required=False))

        # A secret left empty means "keep the one you have", the same as every
        # other credential on the Settings page.  Otherwise saving the form to
        # change the severity floor would quietly wipe the webhooks.
        for key in ("notify.slack_webhook", "notify.teams_webhook",
                    "notify.webhook_url", "notify.smtp_password",
                    "notify.graph_secret"):
            typed = str(form.get(key, "")).strip()
            if not typed:
                continue
            if key in ("notify.smtp_password", "notify.graph_secret"):
                put(key, typed)
                continue
            # This server fetches these by itself, which is the definition of
            # the thing clean_remote_url exists to check: https only, and not
            # pointed at the link-local range where the cloud metadata service
            # lives.  A hand written prefix check here would have been a
            # second, weaker copy of a control the codebase already has.
            put(key, clean_remote_url(typed, "Webhook", required=True))

        record(db, "notifications.changed", actor=user.username,
               detail=(f"{len(moved)} setting(s) changed: "
                       + ", ".join(sorted(moved)))[:2000] if moved
                      else "saved with nothing changed",
               source_ip=client_ip(request))

    return redirect("/notifications?msg=" + quote("Saved."))


@router.post("/notifications/test")
async def test_notifications(request: Request,
                             user: User = Depends(current_user)):
    """One message with nothing in it, to prove the wiring before it matters."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import notify

    with session_scope() as db:
        results = notify.test_message(db)
        record(db, "notifications.tested", actor=user.username,
               detail=", ".join(f"{name}: {'ok' if ok else 'failed'}"
                                for name, ok in sorted(results.items())) or "nothing configured",
               outcome="ok" if results and all(results.values()) else "warn",
               source_ip=client_ip(request))

    if not results:
        return redirect("/notifications?kind=error&msg=" + quote(
            "Nothing is configured to send to yet."))
    worked = [name for name, ok in results.items() if ok]
    failed = [name for name, ok in results.items() if not ok]
    if failed:
        return redirect("/notifications?kind=error&msg=" + quote(
            f"Sent to {', '.join(worked) or 'nothing'}. "
            f"Could not send to {', '.join(failed)}. The log says why."))
    return redirect("/notifications?msg=" + quote(
        f"Sent to {', '.join(worked)}."))


@router.post("/ai/save")
async def save_ai(request: Request, user: User = Depends(current_user)):
    """Which model reads a finding, and how to reach it."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import ai, settings_store as store

    form = await request.form()

    try:
        values = ai.read_form(
            form,
            text=lambda v, what, limit: clean_text(v, what, limit=limit,
                                                   required=False),
            number=lambda v, what, low, high: clean_int(v, what, low=low,
                                                        high=high),
            url=lambda v, what: clean_remote_url(v, what, required=False),
            checked=lambda name: _checked(form, name))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    with session_scope() as db:
        moved = []

        def put(key, value):
            if store.set_value(db, key, value, user.username):
                moved.append(key)

        for key, value in values.items():
            put(key, value)

        # A secret left empty keeps the one already stored.
        for key in ai.SECRET_KEYS:
            typed = str(form.get(key, "")).strip()
            if typed:
                if len(typed) > 4000 or any(c in typed for c in "\r\n"):
                    raise HTTPException(status_code=400,
                                        detail="That key does not look like a key.")
                put(key, typed)

        # Names of what changed, never values: the template can carry
        # identifiers, and the keys are keys.
        record(db, "ai.changed", actor=user.username,
               detail=(f"{len(moved)} setting(s) changed: "
                       + ", ".join(sorted(moved)))[:2000] if moved
                      else "saved with nothing changed",
               source_ip=client_ip(request))

        cfg = ai.config(db)
        problem = ai.missing(cfg) if ai.enabled(cfg) else ""

    if problem:
        return redirect("/ai?kind=error&msg=" + quote("Saved, but " + problem[0].lower()
                                                      + problem[1:]))
    return redirect("/ai?msg=" + quote("Saved."))


@router.post("/ai/test")
async def test_ai(request: Request, user: User = Depends(current_user)):
    """One small question, before a real one costs anything."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from starlette.concurrency import run_in_threadpool

    from app.core import ai

    with session_scope() as db:
        cfg = ai.config(db)

    result = await run_in_threadpool(ai.test, cfg)

    with session_scope() as db:
        record(db, "ai.tested", actor=user.username,
               detail=(f"{result['provider']} {result.get('model') or ''}: "
                       + ("ok" if result["ok"] else result["error"]))[:400],
               outcome="ok" if result["ok"] else "error",
               source_ip=client_ip(request))

    if not result["ok"]:
        return redirect("/ai?kind=error&msg=" + quote(result["error"]))
    return redirect("/ai?msg=" + quote(
        f"{result.get('model') or result['provider']} answered in "
        f"{result['duration_ms'] / 1000:.1f}s: {result['text'][:80]}"))


@router.post("/ai/models")
async def ai_models(request: Request, user: User = Depends(current_user)):
    """The models a provider offers the saved key, for the picker."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from fastapi.responses import JSONResponse
    from starlette.concurrency import run_in_threadpool

    from app.core import ai

    try:
        body = await request.json()
    except ValueError:
        body = {}
    provider = str((body or {}).get("provider", "")).strip().lower()
    if provider not in ai.PROVIDERS[1:]:
        return JSONResponse({"ok": False, "models": [],
                             "error": "Pick a provider first."})

    with session_scope() as db:
        cfg = ai.config(db)
    result = await run_in_threadpool(ai.list_models, cfg, provider)
    return JSONResponse(result)


@router.post("/findings/{finding_id}/validate")
async def validate_finding(finding_id: int, request: Request,
                          user: User = Depends(current_user)):
    """Ask the configured model about one finding, and keep what it says.

    A reading lower than the grade lowers it, except on a credential or a
    known exploited package, and a person's regrade still has the last word.
    What the model says covers other findings is kept as a learned rule.
    """
    await check_csrf(request)
    rbac.require(user, "finding.validate")

    from urllib.parse import quote

    from starlette.concurrency import run_in_threadpool

    from app.core import analysis

    with session_scope() as db:
        # Scope is applied in the query, so a finding outside it is simply not
        # there rather than refused.
        row = (rbac.visible_findings(db, user)
               .filter(Finding.id == finding_id).one_or_none())
        if row is None:
            raise HTTPException(status_code=404, detail="No such finding.")
        vuln_id = row.vuln_id

    # Ask the model even when a learned rule already covers it.  Without the
    # box a rule answers, which costs nothing.
    form = await request.form()
    force = str(form.get("force", "")).lower() in {"1", "on", "true"}

    # Off the event loop: a clone and a model's answer can take minutes, and
    # every other request would wait behind it.
    result = await run_in_threadpool(analysis.run, finding_id, user, force)

    with session_scope() as db:
        record(db, "finding.validated", actor=user.username,
               target=vuln_id, detail=result.get("detail", "")[:400],
               outcome="ok" if result.get("ok") else "error",
               source_ip=client_ip(request))

    kind = "ok" if result.get("ok") else "error"
    anchor = "#validation" if result.get("ok") else ""
    return redirect(f"/findings/{finding_id}?msg={quote(result.get('detail', ''))}"
                    f"&kind={kind}{anchor}")


@router.post("/findings/validate-bulk")
async def validate_many(request: Request, user: User = Depends(current_user)):
    """Validate the ticked findings, or all matching the filters, with AI.

    Runs in the background and reports on the learned rules page.  Findings
    about the same thing go one after another, so what the model learns from
    the first answers the rest without being asked.
    """
    await check_csrf(request)
    rbac.require(user, "finding.validate")

    from app.core import ai, analysis

    form = await request.form()
    wanted = []
    for raw in form.getlist("ids"):
        for piece in str(raw).split(","):
            piece = piece.strip()
            if piece.isdigit():
                wanted.append(int(piece))
    everything = str(form.get("all_matching", "")).lower() in {"1", "on", "true"}
    if not wanted and not everything:
        raise HTTPException(status_code=400, detail="Nothing was selected.")

    with session_scope() as db:
        # With AI off, what has been learned still applies: the run answers
        # from the learned rules alone and sends nothing anywhere.
        cfg = ai.config(db)
        rules_only = (not ai.enabled(cfg)) or bool(ai.missing(cfg))
        query = rbac.visible_findings(db, user)
        if everything:
            query = _apply_finding_filters(query, form, db, user)
        else:
            query = query.filter(Finding.id.in_(wanted))
        ids = [row[0] for row in query.with_entities(Finding.id)
               .limit(analysis.MAX_BATCH + 1).all()]
        if len(ids) > analysis.MAX_BATCH:
            return redirect(_back_with(
                _findings_back(form),
                f"That is more than {analysis.MAX_BATCH} findings. Narrow the "
                "filters and validate in batches.", "error"))
        number = analysis.start_batch(ids, user, rules_only=rules_only)
        record(db, "finding.validated", actor=user.username,
               target=f"{len(ids)} findings",
               detail=(f"bulk learned rules #{number}" if rules_only
                       else f"bulk AI validation #{number}"),
               source_ip=client_ip(request))
    return redirect(f"/ai/learned?batch={number}")


@router.post("/ai/learned/{rule_id}/accept")
async def accept_learned(rule_id: int, request: Request,
                         user: User = Depends(current_user)):
    """Let a rule learned in one repository answer in every repository."""
    await check_csrf(request)
    rbac.require(user, "settings.write")
    from urllib.parse import quote

    from app.core import learned
    from app.core.reports import request_rewrite
    from app.core.models import LearnedRule

    with session_scope() as db:
        rule = db.get(LearnedRule, rule_id)
        if rule is None or rule.retired_at is not None:
            raise HTTPException(status_code=404, detail="No such live rule.")
        problems = learned.self_test(rule)
        if problems:
            return redirect("/ai/learned?kind=error&msg=" + quote(
                f"Rule #{rule.id} fails its own test: {problems[0]}."))
        rule.global_accepted_by = user.username
        rule.global_accepted_at = utcnow()
        moved = learned.apply_rule_now(db, rule, user.username)
        if moved:
            request_rewrite()
        record(db, "learned_rule.accepted", actor=user.username,
               target=f"rule {rule.id}", detail=learned.describe(rule)[:400],
               source_ip=client_ip(request))
    return redirect("/ai/learned?msg=" + quote(
        f"Rule #{rule_id} now applies everywhere; it graded {moved} more finding(s)."))


@router.post("/ai/learned/{rule_id}/retire")
async def retire_learned(rule_id: int, request: Request,
                         user: User = Depends(current_user)):
    """Stop a learned rule and take back every grade it gave."""
    await check_csrf(request)
    rbac.require(user, "settings.write")
    from urllib.parse import quote

    from app.core import learned
    from app.core.reports import request_rewrite
    from app.core.models import LearnedRule

    form = await request.form()
    why = clean_text(form.get("reason"), "Reason", limit=500, required=False) \
        or "retired by hand"
    with session_scope() as db:
        rule = db.get(LearnedRule, rule_id)
        if rule is None or rule.retired_at is not None:
            raise HTTPException(status_code=404, detail="No such live rule.")
        restored = learned.retire(db, rule, user.username, why)
        request_rewrite()
        record(db, "learned_rule.retired", actor=user.username,
               target=f"rule {rule.id}", detail=why[:400],
               source_ip=client_ip(request))
    return redirect("/ai/learned?msg=" + quote(
        f"Rule #{rule_id} retired; {restored} finding(s) went back to their grade."))


@router.post("/ai/learned/test")
async def test_learned(request: Request, user: User = Depends(current_user)):
    """Run every live rule's synthetic test, and retire the ones that fail."""
    await check_csrf(request)
    rbac.require(user, "settings.write")
    from urllib.parse import quote

    from app.core import learned
    from app.core.reports import request_rewrite
    from app.core.models import LearnedRule

    failed = []
    with session_scope() as db:
        live = db.query(LearnedRule).filter(LearnedRule.retired_at.is_(None)).all()
        for rule in live:
            problems = learned.self_test(rule)
            if problems:
                learned.retire(db, rule, user.username,
                               "failed its synthetic test: " + problems[0])
                failed.append(rule.id)
        if failed:
            request_rewrite()
        record(db, "learned_rule.tested", actor=user.username,
               target=f"{len(live)} rules", detail=f"failed: {failed}"[:400],
               source_ip=client_ip(request))
    message = (f"{len(live)} rule(s) tested; all passed." if not failed else
               f"{len(live)} rule(s) tested; retired {len(failed)} that failed: "
               + ", ".join(f"#{n}" for n in failed) + ".")
    return redirect("/ai/learned?msg=" + quote(message)
                    + ("&kind=error" if failed else ""))


@router.post("/triage/add")
async def add_triage_rule(request: Request, user: User = Depends(current_user)):
    """Teach the scanner that something is an example, not a credential."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import triage_rules

    form = await request.form()
    with session_scope() as db:
        row, why = triage_rules.add(
            db,
            str(form.get("target", "value")),
            clean_text(form.get("pattern"), "Pattern", limit=500),
            reason=clean_text(form.get("reason"), "Reason", limit=2000,
                              required=False),
            actor=user.username)
        if row is None:
            return redirect(f"/triage?msg={quote(why)}&kind=error")
        record(db, "triage.rule.added", actor=user.username,
               target=f"{row.target}:{row.pattern}",
               detail=(row.reason or "")[:200], source_ip=client_ip(request))
    return redirect("/triage?msg=" + quote(
        "Rule added.  It applies from the next scan."))


@router.post("/triage/toggle")
async def toggle_triage_rule(request: Request,
                             user: User = Depends(current_user)):
    """Turn one rule off, or back on.

    A shipped rule is turned off rather than deleted, so what the tool ships is
    still there to go back to.
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import triage_rules

    form = await request.form()
    target = str(form.get("target", ""))
    pattern = clean_text(form.get("pattern"), "Pattern", limit=500)
    on = str(form.get("on", "")) == "1"

    with session_scope() as db:
        done, why = triage_rules.set_enabled(db, target, pattern, on,
                                             actor=user.username)
        if not done:
            return redirect(f"/triage?msg={quote(why)}&kind=error")
        record(db, "triage.rule.enabled" if on else "triage.rule.disabled",
               actor=user.username, target=f"{target}:{pattern}",
               source_ip=client_ip(request))
    word = "back on" if on else "off"
    return redirect("/triage?msg=" + quote(
        f"That rule is {word} from the next scan."))


@router.post("/triage/{rule_id}/delete")
async def delete_triage_rule(rule_id: int, request: Request,
                             user: User = Depends(current_user)):
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import triage_rules
    from app.core.models import TriageRule

    with session_scope() as db:
        row = (db.query(TriageRule)
               .filter(TriageRule.id == rule_id).one_or_none())
        target = f"{row.target}:{row.pattern}" if row else str(rule_id)
        if not triage_rules.remove(db, rule_id):
            raise HTTPException(
                status_code=404,
                detail="No such rule, or it is one this tool ships. "
                       "A shipped rule is turned off, not deleted.")
        record(db, "triage.rule.removed", actor=user.username, target=target,
               source_ip=client_ip(request))
    return redirect("/triage?msg=" + quote("Rule removed."))


@router.post("/triage/restore")
async def restore_triage_rules(request: Request,
                               user: User = Depends(current_user)):
    """Back to the rules this tool ships.

    Every decision anybody made here goes: the rules they wrote and the shipped
    ones they turned off.  What is left is the defaults, which is why this is
    deleting rows rather than writing any.
    """
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import triage_rules

    with session_scope() as db:
        gone = triage_rules.restore_defaults(db)
        record(db, "triage.rules.restored", actor=user.username,
               detail=f"{gone} rule(s) of this installation's own were removed",
               source_ip=client_ip(request))
    return redirect("/triage?msg=" + quote(
        f"Back to the rules this tool ships.  {gone} of this installation's "
        "own were removed."))


@router.post("/triage/thresholds")
async def save_triage_thresholds(request: Request,
                                 user: User = Depends(current_user)):
    """The floors that apply before any pattern is looked at."""
    await check_csrf(request)
    rbac.require(user, "settings.write")

    from urllib.parse import quote

    from app.core import settings_store as store

    form = await request.form()
    try:
        entropy = float(form.get("secrets.min_entropy", 3.0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400,
                            detail="The entropy floor has to be a number.")
    if not 0 <= entropy <= 8:
        raise HTTPException(status_code=400,
                            detail="The entropy floor goes from 0 to 8.")

    length = clean_int(form.get("secrets.min_length", 12), "Shortest value",
                       low=0, high=512)

    with session_scope() as db:
        store.set_value(db, "secrets.min_entropy", entropy, user.username)
        store.set_value(db, "secrets.min_length", length, user.username)
        store.set_value(db, "secrets.drop_below_entropy",
                        _checked(form, "secrets.drop_below_entropy"),
                        user.username)
        record(db, "triage.thresholds.changed", actor=user.username,
               detail=f"entropy {entropy}, length {length}",
               source_ip=client_ip(request))
    return redirect("/triage?msg=" + quote(
        "Saved.  It applies from the next scan."))


@router.post("/noise/mute")
async def mute_from_noise(request: Request, user: User = Depends(current_user)):
    """Ask for a rule to be set aside, from the page that shows what it costs.

    The Settings page has been able to do this since mutes existed, from a
    fixed list and a free text box. What it could not do is tell somebody
    which rule was worth the decision, which is the whole point of the page
    this posts from.
    """
    await check_csrf(request)
    rbac.require(user, "rule.mute.request")

    from urllib.parse import quote

    from app.core import rule_mutes
    from app.core import settings_store as store

    form = await request.form()
    rule = clean_text(form.get("rule", ""), "Rule", limit=200)
    reason = clean_text(form.get("reason", ""), "Reason", limit=500,
                        required=False)
    back = "/noise?only=" + quote((form.get("only", "") or "")[:40])

    with session_scope() as db:
        # Unticking is immediate and ticking is a request, the same asymmetry
        # the Settings page uses: showing more findings is never the dangerous
        # direction, so nobody waits for permission to undo one.
        if (form.get("action", "") or "") == "unmute":
            # Undoing a mute is estate wide: it revokes a decision two
            # administrators made.  Somebody who cannot approve mutes may only
            # withdraw their own request that nobody has decided yet.
            live_mute = rule_mutes.current(db, rule)
            own_request = (live_mute is not None
                           and live_mute.status == rule_mutes.REQUESTED
                           and (live_mute.requested_by or "").lower()
                           == user.username.lower())
            if not rbac.can(user, "rule.mute.approve") and not own_request:
                message = ("Only an administrator can put a rule that is set "
                           "aside back in the work list.")
                return redirect(f"{back}&msg={quote(message)}&kind=error")
            if rule_mutes.revoke(db, rule, user.username):
                record(db, "rule.mute.revoked", actor=user.username,
                       target=rule, source_ip=client_ip(request))
                db.flush()
                store.set_value(db, "code.muted_rules",
                                rule_mutes.effective(db), actor=user.username)
                message, kind = f"{rule} is back in the work list.", "ok"
            else:
                message, kind = f"{rule} was not set aside.", "error"
        else:
            row, created = rule_mutes.request(db, rule, user.username, reason)
            if created:
                record(db, "rule.mute.requested", actor=user.username,
                       target=rule, detail=reason,
                       source_ip=client_ip(request))
                db.flush()
                store.set_value(db, "code.muted_rules",
                                rule_mutes.effective(db), actor=user.username)
                message = ("Asked for %s to be set aside. Another "
                           "administrator has to agree before it takes "
                           "effect." % rule)
                kind = "ok"
            elif row is not None:
                message = ("%s already has a request or a decision against "
                           "it." % rule)
                kind = "error"
            else:
                message, kind = "That is not a rule name.", "error"

    return redirect(f"{back}&msg={quote(message)}&kind={kind}")


@router.post("/rule-mutes/{mute_id}/{decision}")
async def decide_rule_mute(mute_id: int, decision: str, request: Request,
                           user: User = Depends(current_user)):
    """Agree to somebody else's request to set a rule aside, or turn it down."""
    await check_csrf(request)
    rbac.require(user, "rule.mute.approve")

    from urllib.parse import quote

    from app.core import rule_mutes

    if decision not in {"approve", "reject"}:
        raise HTTPException(status_code=404, detail="No such decision.")

    with session_scope() as db:
        row = db.query(m_RuleMute).filter(m_RuleMute.id == mute_id).one_or_none()
        rule = row.rule if row is not None else ""
        if decision == "approve":
            ok, why = rule_mutes.approve(db, mute_id, user.username)
        else:
            ok, why = rule_mutes.reject(db, mute_id, user.username)
        if ok:
            record(db, f"rule.mute.{decision}d", actor=user.username,
                   target=rule, source_ip=client_ip(request))
            db.flush()
            from app.core import settings_store as store
            store.set_value(db, "code.muted_rules", rule_mutes.effective(db),
                            actor=user.username)
            message = (f"{rule} is set aside." if decision == "approve"
                       else f"{rule} stays in the work list.")
            kind = "ok"
        else:
            message, kind = why, "error"

    return redirect(f"/settings?msg={quote(message)}&kind={kind}")


@router.post("/findings/{finding_id}/recheck")
async def recheck_finding(finding_id: int, request: Request,
                          user: User = Depends(current_user)):
    """Look at one finding again, now, and write none of it down.

    This deliberately does not take the scan lock, so it works while a scan is
    running.  It also deliberately does not update the finding: a scan decides
    state by walking every branch, this looks at one file, and a partial answer
    must not overwrite a complete one.
    """
    await check_csrf(request)
    # A recheck fetches the repository with the account's credential and can
    # close or reopen the finding, which is a scan in miniature.  It had no
    # permission check at all, so a reader, whose role is read only, could
    # change finding state and hold both recheck slots.
    rbac.require(user, "scan.run")

    from urllib.parse import quote

    from app.core import rbac as rbac_mod, recheck as recheck_mod

    with session_scope() as db:
        # Scope is applied in the query, so a finding outside it is simply not
        # there rather than refused.
        row = (rbac_mod.visible_findings(db, user)
               .filter(Finding.id == finding_id).one_or_none())
        if row is None:
            raise HTTPException(status_code=404, detail="No such finding.")

    result = recheck_mod.recheck(finding_id, actor=user.username)

    if not result.get("ok"):
        kind = "error"
        message = result.get("detail", "Could not check it.")
    elif result.get("present"):
        kind = "warn"
        message = result["detail"]
    else:
        kind = "ok"
        # Only claim to have changed something when something changed.  The
        # sentence used to say the finding stays open whatever happened, which
        # was true then and would be a lie now that a complete recheck closes
        # one.
        message = result["detail"]
        if result.get("wrote") != "closed":
            message += (" The finding stays open until every branch it is on "
                        "has been looked at.")

    with session_scope() as db:
        record(db, "finding.recheck.closed" if result.get("wrote") == "closed"
               else "finding.rechecked", actor=user.username,
               target=str(finding_id), detail=message[:400],
               outcome="ok" if result.get("ok") else "error",
               source_ip=client_ip(request))

    return redirect(f"/findings/{finding_id}?msg={quote(message)}&kind={kind}")


@router.post("/account/password")
async def change_own_password(request: Request,
                              user: User = Depends(current_user)):
    """Change your own password.

    The admin reset endpoint below issues a random one and is not this: it
    needs user.write, and it does not let somebody choose their own.
    """
    await check_csrf(request)

    from urllib.parse import quote

    from app.auth.service import (hash_password, password_problems,
                                  revoke_all_for_user, verify_password)
    from app.core.models import AuthSource

    form = await request.form()
    current = str(form.get("current_password", ""))
    fresh = str(form.get("new_password", ""))
    again = str(form.get("confirm_password", ""))

    def back(message: str):
        return redirect(f"/account/password?error={quote(message)}")

    with session_scope() as db:
        row = db.query(User).filter(User.id == user.id).one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="No such account.")
        if row.source != AuthSource.LOCAL:
            raise HTTPException(
                status_code=400,
                detail="You sign in through the provider, so there is no "
                       "password here to change.")

        # Prove it is them and not somebody who sat down at their desk.
        if not verify_password(row.password_hash, current):
            record(db, "password.change_failed", actor=row.username,
                   outcome="denied", detail="current password did not match",
                   source_ip=client_ip(request))
            return back("That is not your current password.")

        if fresh != again:
            return back("The two new passwords do not match.")
        if fresh == current:
            return back("That is the password you already have.")
        problems = password_problems(fresh)
        if problems:
            return back(" ".join(problems))

        row.password_hash = hash_password(fresh)
        row.must_change_password = False
        row.failed_logins = 0
        row.locked_until = None

        # A password change that leaves the old sessions signed in is not a
        # password change.  This one included: a fresh token goes out below.
        revoke_all_for_user(db, row.id, "password changed by the account owner")
        record(db, "password.changed", actor=row.username,
               source_ip=client_ip(request))
        user_id = row.id

    # Everything was just revoked, so hand this browser a new session rather
    # than bouncing somebody to the login page for doing the right thing.
    from app.auth.service import create_session
    from app.web.routes_auth import _set_session_cookie

    with session_scope() as db:
        row = db.query(User).filter(User.id == user_id).one()
        # create_session is fully signed in unless half_auth is asked for, so
        # there is nothing to promote here.
        token = create_session(db, row, source_ip=client_ip(request))

    response = redirect("/account?msg=Your+password+is+changed.&kind=ok")
    _set_session_cookie(response, token)
    return response


@router.post("/users/{user_id}/password")
async def reset_user_password(user_id: int, request: Request,
                              user: User = Depends(current_user)):
    """Give somebody a new starting password, shown once."""
    await check_csrf(request)
    rbac.require(user, "user.write")

    from urllib.parse import quote

    from app.auth.service import hash_password, revoke_all_for_user
    from app.core.models import AuthSource

    password = _new_password()
    with session_scope() as db:
        row = _load_user(db, user_id)
        if row.source != AuthSource.LOCAL:
            raise HTTPException(
                status_code=400,
                detail=f"{row.username} signs in through the provider, so there "
                       "is no password here to reset.")
        row.password_hash = hash_password(password)
        row.must_change_password = True
        row.failed_logins = 0
        row.locked_until = None
        # A reset that leaves their old sessions signed in is not a reset.
        revoke_all_for_user(db, row.id, "password reset by an administrator")
        record(db, "user.password_reset", actor=user.username,
               target=row.username, source_ip=client_ip(request))
        username = row.username

    from app.web import oneshot
    key = oneshot.put(user.id, f"New password for {username}: {password} . It is "
                               "shown once, and they have to change it at the next "
                               "sign in.")
    return redirect(f"/users?once={quote(key)}&kind=ok")


@router.post("/users/{user_id}/totp")
async def reset_user_totp(user_id: int, request: Request,
                          user: User = Depends(current_user)):
    """Clear two step so somebody can enroll a new phone."""
    await check_csrf(request)
    rbac.require(user, "user.write")

    from app.auth.service import revoke_all_for_user

    with session_scope() as db:
        row = _load_user(db, user_id)
        row.totp_secret = ""
        row.totp_confirmed = False
        row.recovery_hashes = ""
        row.failed_logins = 0
        row.locked_until = None
        revoke_all_for_user(db, row.id, "two step reset by an administrator")
        record(db, "user.totp_reset", actor=user.username, target=row.username,
               source_ip=client_ip(request))
        username = row.username

    return redirect(f"/users?msg=Two+step+is+cleared+for+{username}.+The+next+"
                    "sign+in+walks+them+through+setting+it+up+again.&kind=ok")


@router.post("/users/{user_id}/toggle")
async def toggle_user(user_id: int, request: Request,
                      user: User = Depends(current_user)):
    """Turn an account off, or back on."""
    await check_csrf(request)
    rbac.require(user, "user.write")

    from app.auth.service import revoke_all_for_user

    with session_scope() as db:
        row = _load_user(db, user_id)
        if row.id == user.id:
            raise HTTPException(status_code=400,
                                detail="Turning off your own account would sign "
                                       "you out with no way back in.")
        if (not row.disabled and row.role == UserRole.ADMIN
                and not _other_admins(db, row.id)):
            raise HTTPException(status_code=400,
                                detail="That is the only admin left.")

        row.disabled = not row.disabled
        if row.disabled:
            revoke_all_for_user(db, row.id, "account turned off")
        record(db, "user.disabled" if row.disabled else "user.enabled",
               actor=user.username, target=row.username,
               source_ip=client_ip(request))
        state = "off" if row.disabled else "back on"
        username = row.username

    return redirect(f"/users?msg={username}+is+{state}.&kind=ok")


@router.post("/users/{user_id}/unlock")
async def unlock_user(user_id: int, request: Request,
                      user: User = Depends(current_user)):
    """Clear a lockout after too many wrong passwords."""
    await check_csrf(request)
    rbac.require(user, "user.write")

    with session_scope() as db:
        row = _load_user(db, user_id)
        row.failed_logins = 0
        row.locked_until = None
        record(db, "user.unlocked", actor=user.username, target=row.username,
               source_ip=client_ip(request))
        username = row.username

    return redirect(f"/users?msg={username}+is+unlocked.&kind=ok")


@router.post("/users/{user_id}/delete")
async def delete_user(user_id: int, request: Request,
                      user: User = Depends(current_user)):
    """Remove an account for good.

    Their sessions and their scopes go with them.  The audit log does not: what
    they did stays on the record whether the account exists or not.
    """
    await check_csrf(request)
    rbac.require(user, "user.write")

    with session_scope() as db:
        row = _load_user(db, user_id)
        if row.id == user.id:
            raise HTTPException(status_code=400,
                                detail="You cannot delete the account you are "
                                       "signed in as.")
        if row.role == UserRole.ADMIN and not _other_admins(db, row.id):
            raise HTTPException(status_code=400,
                                detail="That is the only admin left.")
        username = row.username
        db.delete(row)
        record(db, "user.deleted", actor=user.username, target=username,
               source_ip=client_ip(request))

    return redirect(f"/users?msg={username}+is+gone.&kind=ok")


# ---- scan scope ---------------------------------------------------------------

# One bulk change across the Repositories page, at most.
MAX_SCOPE_REPOS = 500


@router.post("/scope/apply")
async def apply_scope(request: Request, user: User = Depends(current_user)):
    """Change which branches of one or more repositories get a full scan.

    Reached from the confirmation page, which has already shown what moves.
    The default branch going to credentials only needs its own tick box, here
    as well as on the page, so a hand built request cannot skip it.
    """
    await check_csrf(request)
    rbac.require(user, "repo.scope")

    from app.core import scan_scope

    form = await request.form()
    repositories = [str(v).strip() for v in form.getlist("repo") if str(v).strip()]
    branch = clean_text(form.get("branch"), "Branch", limit=255, required=False)
    mode = (str(form.get("mode", "")) or "").strip()
    patterns = clean_text(form.get("patterns"), "Branches", limit=4000,
                          required=False)
    reason = clean_text(form.get("reason"), "Reason", limit=2000)
    review = clean_text(form.get("review"), "Review date", limit=10,
                        required=False)
    confirmed_default = str(form.get("confirm_default", "")) == "1"
    back = _safe_back(str(form.get("back", "") or "/repositories"))
    if not repositories:
        raise HTTPException(status_code=400, detail="Pick a repository first.")
    if len(repositories) > MAX_SCOPE_REPOS:
        raise HTTPException(status_code=400, detail=(
            f"At most {MAX_SCOPE_REPOS} repositories at a time."))
    if branch and len(repositories) != 1:
        raise HTTPException(status_code=400, detail=(
            "A branch setting is for one repository at a time."))

    changes, skipped = [], 0
    with session_scope() as db:
        for repository in repositories:
            if _branch_in_reach(db, user, repository, branch) is None:
                skipped += 1
                continue
            impact = scan_scope.preview(db, repository, branch, mode, patterns)
            if impact["default_leaves"] and not confirmed_default:
                raise HTTPException(status_code=400, detail=(
                    f"This takes {impact['default_branch']}, the default branch "
                    f"of {repository}, down to credentials only.  Tick the box "
                    "that says you mean it."))
            change, problem = scan_scope.apply(
                db, repository, branch, mode, patterns, reason, review,
                user.username)
            if problem:
                raise HTTPException(status_code=400, detail=problem)
            record(db, "repo.scope_changed", actor=user.username,
                   target=f"{repository}@{branch}" if branch else repository,
                   detail=(f"change {change.id}: {impact['describe_before']} -> "
                           f"{impact['describe_after']}; {impact['hide_total']} "
                           f"finding(s) now not deployed, {impact['show_total']} "
                           f"back.  Reason: {reason}")[:4000],
                   source_ip=client_ip(request))
            changes.append(change.id)

    # What is reported changed, so the files follow.
    if changes:
        request_rewrite()
    note = "Scan scope changed on %d repositor%s." % (
        len(changes), "y" if len(changes) == 1 else "ies")
    if len(changes) == 1:
        note += "  Revert it from the repository's scope page if that was wrong."
    if skipped:
        note += "  %d left alone: not yours to change." % skipped
    return redirect(_back_with(back, note, "ok"))


@router.post("/scope/changes/{change_id}/revert")
async def revert_scope(change_id: int, request: Request,
                       user: User = Depends(current_user)):
    """Undo one change, as long as nothing has changed the same scope since."""
    await check_csrf(request)
    rbac.require(user, "repo.scope")

    from app.core import scan_scope
    from app.core.models import BranchScopeChange

    form = await request.form()
    back = _safe_back(str(form.get("back", "") or "/repositories"))
    with session_scope() as db:
        old = db.get(BranchScopeChange, change_id)
        if old is None or _branch_in_reach(db, user, old.repository,
                                           old.branch) is None:
            raise HTTPException(status_code=404, detail="No such change.")
        change, problem = scan_scope.revert(db, change_id, user.username)
        if problem:
            return redirect(_back_with(back, problem, "warn"))
        record(db, "repo.scope_reverted", actor=user.username,
               target=(f"{old.repository}@{old.branch}" if old.branch
                       else old.repository),
               detail=f"change {change.id} undid change {change_id}",
               source_ip=client_ip(request))
    request_rewrite()
    return redirect(_back_with(back, "Reverted.", "ok"))


# ---- diagrams -----------------------------------------------------------------

@router.post("/repositories/{repo_id}/diagram")
async def draw_diagram(repo_id: int, request: Request,
                       user: User = Depends(current_user)):
    """Create or re-create the drawing of a repository's default branch."""
    await check_csrf(request)
    rbac.require(user, "repo.diagram")

    from app.core import diagram
    from app.core.models import Repository

    with session_scope() as db:
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        full_name = repo.full_name
        record(db, "repo.diagram_requested", actor=user.username,
               target=full_name, detail=f"default branch {repo.default_branch}",
               source_ip=client_ip(request))
    started, problem = diagram.start(full_name, user.username)
    back = f"/repositories/{repo_id}/diagram"
    if not started:
        return redirect(_back_with(back, problem, "warn"))
    return redirect(_back_with(
        back, "Drawing started.  It usually takes a minute or two, and this "
              "page refreshes itself until it is done.", "ok"))



# Ticked branches on one connection's scope page.  The largest account seen
# held a few thousand, so this is room for that with plenty over.
MAX_SCOPE_FIELDS = 25000


@router.post("/scope/import/apply")
async def apply_scope_import(request: Request, user: User = Depends(current_user)):
    """The changes a scope CSV asked for, as the confirmation page showed them."""
    await request.form(max_fields=MAX_SCOPE_FIELDS)
    await check_csrf(request)
    rbac.require(user, "repo.scope")

    from app.core import scan_scope
    from app.core.models import Repository

    form = await request.form(max_fields=MAX_SCOPE_FIELDS)
    reason = clean_text(form.get("reason"), "Reason", limit=2000)
    review = clean_text(form.get("review"), "Review date", limit=10,
                        required=False)
    confirmed_default = str(form.get("confirm_default", "")) == "1"

    # "repository:branch:mode", one per change.  A colon can be in neither
    # a repository nor a branch name.  Checked again here, since a hand built
    # request can say anything.
    wanted = {}
    for raw in form.getlist("change"):
        repository, _, rest = str(raw).partition(":")
        branch, _, mode = rest.rpartition(":")
        ok = (mode in scan_scope.REPO_MODES if not branch
              else mode in scan_scope.BRANCH_MODES + ("inherit",))
        if repository and ok and mode != "chosen":
            wanted.setdefault(repository, []).append((branch, mode, ""))
    if not wanted:
        raise HTTPException(status_code=400, detail="Nothing to change.")

    done = steps = hidden = shown = 0
    with session_scope() as db:
        allowed = {name for (name,) in rbac.visible_repositories(db, user)
                   .filter(Repository.full_name.in_(sorted(wanted)))
                   .with_entities(Repository.full_name).all()}
        for repository, changes in sorted(wanted.items()):
            if repository not in allowed:
                continue
            impact = scan_scope.preview(db, repository, "", "", "",
                                        changes=changes)
            if impact["default_leaves"] and not confirmed_default:
                raise HTTPException(status_code=400, detail=(
                    f"This takes {impact['default_branch']}, the default branch "
                    f"of {repository}, down to credentials only.  Tick the box "
                    "that says you mean it."))
            ids, problem = scan_scope.apply_batch(db, repository, changes,
                                                  reason, review, user.username)
            if problem:
                raise HTTPException(status_code=400,
                                    detail=f"{repository}: {problem}")
            record(db, "repo.scope_changed", actor=user.username,
                   target=repository,
                   detail=(f"changes {ids[0]}-{ids[-1]} from a CSV import: "
                           f"{impact['describe_before']} -> "
                           f"{impact['describe_after']}; {len(changes)} setting(s), "
                           f"{impact['hide_total']} finding(s) now not deployed, "
                           f"{impact['show_total']} back.  Reason: {reason}")[:4000],
                   source_ip=client_ip(request))
            done += 1
            steps += len(changes)
            hidden += impact["hide_total"]
            shown += impact["show_total"]

    request_rewrite()
    note = (f"Scan scope imported: {steps} change(s) on {done} "
            f"repositor{'y' if done == 1 else 'ies'}, {hidden} finding(s) now "
            f"not deployed and {shown} back.  Credentials are still scanned "
            "everywhere.")
    return redirect(_back_with("/repositories", note, "ok"))


@router.post("/repositories/{repo_id}/scope/apply")
async def apply_repository_branches(repo_id: int, request: Request,
                                    user: User = Depends(current_user)):
    """The ticked branches of one repository, all set the same way at once."""
    await request.form(max_fields=MAX_SCOPE_FIELDS)
    await check_csrf(request)
    rbac.require(user, "repo.scope")

    from app.core import scan_scope
    from app.core.models import Repository

    form = await request.form(max_fields=MAX_SCOPE_FIELDS)
    action = str(form.get("action", "") or "")
    reason = clean_text(form.get("reason"), "Reason", limit=2000)
    review = clean_text(form.get("review"), "Review date", limit=10,
                        required=False)
    confirmed_default = str(form.get("confirm_default", "")) == "1"
    back = f"/repositories/{repo_id}/scope"

    with session_scope() as db:
        repo = (rbac.visible_repositories(db, user)
                .filter(Repository.id == repo_id).one_or_none())
        if repo is None:
            raise HTTPException(status_code=404, detail="No such repository.")
        # The confirm page sends "repository branch" pairs.  Only this
        # repository's count, whatever else a hand built request carries.
        pairs = []
        for raw in form.getlist("pair"):
            repository, _, branch = str(raw).partition(" ")
            if repository == repo.full_name and branch:
                pairs.append((repository, branch))
        changes = scan_scope.batch([], pairs, action).get(repo.full_name, [])
        if not changes:
            raise HTTPException(status_code=400, detail="Nothing to change.")
        impact = scan_scope.preview(db, repo.full_name, "", "", "",
                                    changes=changes)
        if impact["default_leaves"] and not confirmed_default:
            raise HTTPException(status_code=400, detail=(
                f"This takes {impact['default_branch']}, the default branch, "
                "down to credentials only.  Tick the box that says you mean it."))
        ids, problem = scan_scope.apply_batch(db, repo.full_name, changes,
                                              reason, review, user.username)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        record(db, "repo.scope_changed", actor=user.username,
               target=repo.full_name,
               detail=(f"changes {ids[0]}-{ids[-1]} from its branch page: "
                       f"{len(changes)} branch(es) to {action}; "
                       f"{impact['hide_total']} finding(s) now not deployed, "
                       f"{impact['show_total']} back.  Reason: {reason}")[:4000],
               source_ip=client_ip(request))

    request_rewrite()
    n = len(changes)
    note = (f"{n} branch{'' if n == 1 else 'es'} changed.  Credentials are "
            "still scanned everywhere.  Each change can be reverted below.")
    return redirect(_back_with(back, note, "ok"))


@router.post("/connections/{connection_id}/scope/apply")
async def apply_connection_scope(connection_id: int, request: Request,
                                 user: User = Depends(current_user)):
    """Scope every ticked repository and branch under one account at once."""
    # Read first, with room for every branch of a large account.  The form is
    # kept, so the CSRF check below reads this copy rather than parsing again
    # with the default limit of a thousand fields and finding no token.
    await request.form(max_fields=MAX_SCOPE_FIELDS)
    await check_csrf(request)
    rbac.require(user, "repo.scope")

    from app.core import connections as connection_store, scan_scope
    from app.core.models import Repository
    from sqlalchemy import or_ as sa_or

    form = await request.form(max_fields=MAX_SCOPE_FIELDS)
    action = str(form.get("action", "") or "")
    reason = clean_text(form.get("reason"), "Reason", limit=2000)
    review = clean_text(form.get("review"), "Review date", limit=10,
                        required=False)
    confirmed_default = str(form.get("confirm_default", "")) == "1"
    ticked_repos = [str(v) for v in form.getlist("repo") if str(v).strip()]
    ticked_pairs = []
    for raw in form.getlist("pair"):
        repository, _, branch = str(raw).partition(" ")
        if repository and branch:
            ticked_pairs.append((repository, branch))
    back = f"/connections/{connection_id}/scope"

    done = branches = 0
    with session_scope() as db:
        connection = connection_store.by_id(db, connection_id)
        if connection is None:
            raise HTTPException(status_code=404, detail="No such connection.")
        allowed = {name for (name,) in rbac.visible_repositories(db, user)
                   .filter(sa_or(Repository.connection_id == connection.id,
                                 Repository.connection == connection.name))
                   .with_entities(Repository.full_name).all()}
        plan = scan_scope.batch([r for r in ticked_repos if r in allowed],
                                [p for p in ticked_pairs if p[0] in allowed],
                                action)
        if not plan:
            raise HTTPException(status_code=400, detail="Nothing to change.")
        for repository, changes in sorted(plan.items()):
            impact = scan_scope.preview(db, repository, "", "", "",
                                        changes=changes)
            if impact["default_leaves"] and not confirmed_default:
                raise HTTPException(status_code=400, detail=(
                    f"This takes {impact['default_branch']}, the default branch "
                    f"of {repository}, down to credentials only.  Tick the box "
                    "that says you mean it."))
            ids, problem = scan_scope.apply_batch(db, repository, changes,
                                                  reason, review, user.username)
            if problem:
                raise HTTPException(status_code=400, detail=problem)
            record(db, "repo.scope_changed", actor=user.username,
                   target=repository,
                   detail=(f"changes {ids[0]}-{ids[-1]} from connection "
                           f"{connection.name}: {impact['describe_before']} -> "
                           f"{impact['describe_after']}; {len(changes)} setting(s), "
                           f"{impact['hide_total']} finding(s) now not deployed, "
                           f"{impact['show_total']} back.  Reason: {reason}")[:4000],
                   source_ip=client_ip(request))
            done += 1
            branches += sum(1 for b, _, _ in changes if b)

    request_rewrite()
    note = (f"Scan scope changed on {done} repositor{'y' if done == 1 else 'ies'}"
            + (f" and {branches} branch(es)" if branches else "") + ".  "
            "Credentials are still scanned everywhere.  Each change can be "
            "reverted from its repository's scope page.")
    return redirect(_back_with(back, note, "ok"))
