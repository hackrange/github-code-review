"""Exclusions: findings somebody reviewed and accepted.

They live in the database so the source tree stays free of anybody's real
repository names.  The scanner wants a CSV, so we write one into a temp
directory when a scan starts and it goes away with the rest of the run.
"""

from __future__ import annotations

import csv
import io
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from app.core.models import Exclusion, utcnow

KINDS = ("secret", "code", "vuln", "misconfig", "any")

# The order the scanner reads.  Do not shuffle these.
COLUMNS = ["type", "organization", "repository", "path", "rule", "fingerprint",
           "vuln_id", "reason", "reviewed_by", "reviewed_date", "expires",
           "ticket", "unless_sensitivity",
]

# A rule written against one finding by its id is applied when the findings
# land in the database, not by the scanner.  The scanner never sees a vuln_id:
# that comes from the fingerprint we work out on this side.


# A fingerprint as it is written down here: the kind of thing it is, then the
# hash of the thing itself.
FINGERPRINT = re.compile(r"^(cred|code|dep):[0-9a-f]{16,64}$")

# A bare hash, and the kind of finding it must have come from.  Credentials are
# the only kind the scanner hashes, so a bare hash on a rule that covers
# anything is a credential.
_PREFIX_FOR = {"secret": "cred", "code": "code", "vuln": "dep", "any": "cred"}


def normalize_fingerprint(value: str, kind: str = "secret") -> str:
    """The form the rest of the system stores.

    Somebody copying a hash out of a report or off a scan file gets the bare
    hex; a finding carries it with the kind in front.  Put the prefix back
    rather than storing something that matches nothing anywhere.
    """
    text = (value or "").strip().lower()
    if not text:
        return ""
    if ":" not in text:
        text = f"{_PREFIX_FOR.get(kind, 'cred')}:{text}"
    return text


def scanner_fingerprint(value: str) -> str:
    """What the scanner compares against.

    A credential is keyed here as cred:<hash>.  The scanner only ever sees the
    hash, so the prefix comes off on the way into the CSV.  Without this a rule
    written against a value matched on this side and never on that one, and the
    value went on being written into the scan's own files every night until the
    findings landed and got flagged after the fact.
    """
    text = (value or "").strip()
    return text.split(":", 1)[1] if text.startswith("cred:") else text


def _date(value) -> str:
    if not value:
        return ""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d")
    return str(value)[:10]


def active_rules(session, now: datetime = None) -> list:
    """Every rule still in force, newest first."""
    moment = now or utcnow()
    rows = session.query(Exclusion).order_by(Exclusion.id.desc()).all()
    return [row for row in rows if row.live(moment)]


log = logging.getLogger("gcr.exclusions")


def to_csv(session, rules=None) -> str:
    """The rules as the scanner's CSV.

    Same shape going out as coming in, so a set exported from one installation
    imports straight into another.  Pass rules to export a particular set,
    otherwise it is everything still in force.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for rule in (active_rules(session) if rules is None else rules):
        writer.writerow([
            (rule.kind or "any"),
            (rule.organization or "*"),
            (rule.repository or "*"),
            (rule.path or "*"),
            (rule.rule or "*"),
            scanner_fingerprint(rule.fingerprint),
            (rule.vuln_id or ""),
            (rule.reason or ""),
            (rule.reviewed_by or ""),
            _date(rule.reviewed_date),
            _date(rule.expires_at),
            (rule.ticket or ""),
            # Carried so a set exported from one installation keeps its guard
            # when it is imported into another.  The scanner ignores it: the
            # rule is filtered out before the file is written.
            (getattr(rule, "unless_sensitivity", "") or ""),
        ])
    return buffer.getvalue()


def as_dicts(session, rules=None) -> list:
    """The rules as plain objects, for the JSON export."""
    rows = active_rules(session) if rules is None else rules
    return [{
        "id": rule.id,
        "type": rule.kind or "any",
        "vuln_id": rule.vuln_id or "",
        "organization": rule.organization or "*",
        "repository": rule.repository or "*",
        "path": rule.path or "*",
        "rule": rule.rule or "*",
        "fingerprint": rule.fingerprint or "",
        "reason": rule.reason or "",
        "ticket": rule.ticket or "",
        "reviewed_by": rule.reviewed_by or "",
        "reviewed_date": _date(rule.reviewed_date),
        "expires": _date(rule.expires_at),
        "in_force": rule.live(),
    } for rule in rows]


def applicable(session, sensitivity: str = "") -> list:
    """The rules that apply to a system holding this.

    An exclusion can name what it was not written for.  Rather than teaching
    the scanner about labels, the rule is simply left out of the file built for
    that scan: the finding then arrives normally, which is the whole point.
    """
    carried = {t.strip().lower() for t in str(sensitivity or "").split(",")
               if t.strip()}
    out = []
    for rule in active_rules(session):
        unless = {t.strip().lower()
                  for t in str(getattr(rule, "unless_sensitivity", "") or "").split(",")
                  if t.strip()}
        if unless and (carried & unless):
            log.info("exclusion %s not applied: this system carries %s",
                     rule.id, ", ".join(sorted(carried & unless)))
            continue
        out.append(rule)
    return out


def write_csv(session, path: Path, sensitivity: str = "") -> Path:
    """Drop the CSV where the scanner will find it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_csv(session, applicable(session, sensitivity)),
                    encoding="utf-8")
    return path


def visible(session, user, search: str = "", kind: str = "",
            status: str = "") -> list:
    """What this account is allowed to look at, narrowed by the search box.

    A developer only gets the rules covering the repositories they were given.
    A rule with a wildcard organization is a decision about the whole estate,
    so it stays with the admins.
    """
    from app.core import rbac

    query = session.query(Exclusion)

    if kind in KINDS:
        query = query.filter(Exclusion.kind == kind)

    text = (search or "").strip()
    if text:
        like = f"%{text}%"
        query = query.filter(
            Exclusion.organization.ilike(like)
            | Exclusion.repository.ilike(like)
            | Exclusion.path.ilike(like)
            | Exclusion.rule.ilike(like)
            | Exclusion.reason.ilike(like)
            | Exclusion.ticket.ilike(like)
            | Exclusion.vuln_id.ilike(like)
            | Exclusion.fingerprint.ilike(like)
            | Exclusion.reviewed_by.ilike(like))

    rows = query.order_by(Exclusion.id.desc()).all()

    if status == "live":
        rows = [row for row in rows if row.live()]
    elif status == "expired":
        rows = [row for row in rows if not row.live()]

    if rbac.sees_everything(user):
        return rows

    out = []
    for row in rows:
        org = row.organization or "*"
        if org == "*":
            continue
        repo = row.repository or "*"
        if repo == "*":
            if rbac.in_scope(user, org, "", session):
                out.append(row)
            continue
        if rbac.in_scope(user, org, repo, session):
            out.append(row)
    return out


# What a row from vulnerabilities.csv calls a finding, and what an exclusion
# calls the same thing.
_KIND_FROM_REPORT = {"credential": "secret", "code": "code",
                     "dependency": "vuln", "misconfiguration": "misconfig"}

# Enough to stop somebody pasting a database dump in, not so little that a real
# report will not fit.  A scan of a large estate produces thousands of rows.
MAX_IMPORT_ROWS = 20000


def import_rows(session, text: str, actor: str, reason: str, ticket: str = "",
                expires_at=None, visible_ids=None) -> dict:
    """Turn a report CSV into exclusions, one rule per row.

    Takes vulnerabilities.csv as it is written, so the workflow is: filter the
    findings you have accepted, export, and hand the file back.  Our own
    exclusions CSV works too, for moving rules between installations.

    Rows are matched by vuln_id where there is one, because that is the id that
    does not move.  Anything already excluded is left alone rather than
    duplicated.
    """
    import csv as csv_module
    import io as io_module

    from app.core.models import Exclusion, Finding

    counts = {"added": 0, "already": 0, "unknown": 0, "skipped": 0, "rows": 0}
    problems = []

    # JSON out, JSON in.  An export is no use if it only goes one way.
    stripped = text.lstrip()
    if stripped.startswith(("[", "{")):
        return _import_json(session, stripped, actor, reason, ticket,
                            expires_at, visible_ids, counts, problems)

    try:
        reader = csv_module.DictReader(io_module.StringIO(text))
        fields = [name.strip().lower() for name in (reader.fieldnames or [])]
    except (csv_module.Error, ValueError) as exc:
        return {**counts, "problems": [f"could not read the file: {exc}"]}

    if not fields:
        return {**counts, "problems": ["that file has no header row"]}

    # Our own format, moved between installations.
    if "type" in fields and "organization" in fields and "reason" in fields:
        return _import_rules(session, reader, actor, counts, problems)

    if "vuln_id" not in fields and "repository" not in fields:
        return {**counts,
                "problems": ["that does not look like vulnerabilities.csv: it "
                             "needs a vuln_id or a repository column"]}

    existing_ids = {row.vuln_id for row in session.query(Exclusion).all()
                    if row.vuln_id}

    for raw in reader:
        counts["rows"] += 1
        if counts["rows"] > MAX_IMPORT_ROWS:
            problems.append(f"stopped after {MAX_IMPORT_ROWS} rows")
            break

        row = {(k or "").strip().lower(): (v or "").strip()
               for k, v in raw.items()}
        vuln_id = (row.get("vuln_id") or "").upper()

        finding = None
        if vuln_id:
            if vuln_id in existing_ids:
                counts["already"] += 1
                continue
            finding = (session.query(Finding)
                       .filter(Finding.vuln_id == vuln_id).one_or_none())
            if finding is None:
                counts["unknown"] += 1
                continue
            if visible_ids is not None and finding.id not in visible_ids:
                counts["skipped"] += 1
                continue

        if finding is not None:
            kind = _KIND_FROM_REPORT.get(
                getattr(finding.kind, "value", str(finding.kind)), "any")
            organization = finding.organization or "*"
            repository = finding.repository or "*"
            path = finding.file_path or "*"
            rule = finding.rule or "*"
            fingerprint = finding.fingerprint if kind == "secret" else ""
        else:
            # No id on the row, so fall back to what the report does carry.
            organization = row.get("organization") or "*"
            repository = row.get("repository") or "*"
            path = row.get("file") or "*"
            rule = row.get("rule") or row.get("vulnerability_id") or "*"
            kind = _KIND_FROM_REPORT.get(row.get("kind", ""), "any")
            fingerprint = ""
            if organization == "*" and repository == "*":
                counts["skipped"] += 1
                continue

        session.add(Exclusion(
            kind=kind, organization=organization, repository=repository,
            path=path, rule=rule, fingerprint=fingerprint, vuln_id=vuln_id,
            reason=reason, ticket=ticket, reviewed_by=actor,
            reviewed_date=utcnow(), expires_at=expires_at, active=True))
        if vuln_id:
            existing_ids.add(vuln_id)
        counts["added"] += 1

    session.flush()
    return {**counts, "problems": problems}


def _import_rules(session, reader, actor: str, counts: dict,
                  problems: list) -> dict:
    """Our own exclusions CSV, coming back in.

    Used to move a reviewed set from one installation to another, so the reason
    and the reviewer come from the file rather than from the form.
    """
    from datetime import datetime, timezone

    from app.core.models import Exclusion

    for raw in reader:
        counts["rows"] += 1
        if counts["rows"] > MAX_IMPORT_ROWS:
            problems.append(f"stopped after {MAX_IMPORT_ROWS} rows")
            break

        row = {(k or "").strip().lower(): (v or "").strip()
               for k, v in raw.items()}
        kind = (row.get("type") or "any").lower()
        if kind not in KINDS:
            counts["skipped"] += 1
            continue
        if len((row.get("reason") or "")) < 20:
            counts["skipped"] += 1
            continue

        expires = None
        if row.get("expires"):
            try:
                expires = datetime.strptime(row["expires"][:10], "%Y-%m-%d").replace(
                    tzinfo=timezone.utc)
            except ValueError:
                expires = None

        session.add(Exclusion(
            kind=kind, organization=row.get("organization") or "*",
            repository=row.get("repository") or "*",
            path=row.get("path") or "*", rule=row.get("rule") or "*",
            fingerprint=normalize_fingerprint(row.get("fingerprint"), kind),
            vuln_id=(row.get("vuln_id") or "").upper(),
            reason=row.get("reason") or "",
            ticket=row.get("ticket") or "",
            reviewed_by=row.get("reviewed_by") or actor,
            reviewed_date=utcnow(), expires_at=expires, active=True))
        counts["added"] += 1

    session.flush()
    return {**counts, "problems": problems}


def _import_json(session, text, actor, reason, ticket, expires_at, visible_ids,
                 counts, problems) -> dict:
    """The JSON export, coming back in.

    Same rows as the CSV, so it goes through the same path: turn each object
    into the CSV shape and hand it over.
    """
    import csv as csv_module
    import io as io_module
    import json as json_module

    try:
        document = json_module.loads(text)
    except ValueError as exc:
        return {**counts, "problems": [f"that is not valid JSON: {exc}"]}

    if isinstance(document, dict):
        rows = (document.get("exclusions") or document.get("findings")
                or document.get("rows") or [])
    else:
        rows = document
    if not isinstance(rows, list) or not rows:
        return {**counts, "problems": ["there are no rows in that file"]}

    flat = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        # A findings export nests the id, a rules export does not.
        entry = dict(item)
        if isinstance(item.get("credential"), dict):
            entry.setdefault("kind", item.get("kind", ""))
        flat.append({key: ("" if value is None else str(value))
                     for key, value in entry.items()
                     if not isinstance(value, (list, dict))})

    if not flat:
        return {**counts, "problems": ["nothing in that file looks like a row"]}

    buffer = io_module.StringIO()
    fields = sorted({key for row in flat for key in row})
    writer = csv_module.DictWriter(buffer, fieldnames=fields,
                                   extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in flat:
        writer.writerow(row)

    return import_rows(session, buffer.getvalue(), actor=actor, reason=reason,
                       ticket=ticket, expires_at=expires_at,
                       visible_ids=visible_ids)
