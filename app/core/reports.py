"""The two files on disk.

vulnerabilities.json and vulnerabilities.csv are a contract.  Another tool
reads them, so the path and the shape do not change on a whim.  Both are
rewritten from the database after every scan and after every waiver decision.

An approved waiver takes the finding out of both files.  Not hidden, gone.  A
waiver that is only requested, or one that has run out, leaves the finding
right where it was.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.config import APP_NAME, VERSION, settings
from app.core.models import (
    Finding, FindingState, Severity, Waiver, WaiverStatus,
)

log = logging.getLogger("gcr.reports")

# Order matters.  A tool reading the CSV should not have to guess.
CSV_COLUMNS = [
    "vuln_id", "finding_id", "kind", "severity", "state",
    "connection", "organization", "repository", "branch",
    "file", "line", "rule", "title",
    "package", "package_version", "ecosystem", "vulnerability_id",
    "risk_score", "risk_evidence", "impact", "likelihood",
    "cvss_score", "known_exploited", "epss_score", "fixed_in", "reachability",
    "image", "malicious",
    "cwe", "owasp",
    "secret_preview", "snippet", "verified", "exposure",
    "author", "author_login", "committed_at",
    "commit", "url",
    "first_found", "last_found",
    # Added after the rest, so a tool reading by position still finds every
    # column where it was.  What the finding is part of, the same five answers
    # the JSON carries in its asset block.
    "application", "business_owner", "technical_owner", "holds", "visibility",
    # Which file asks for a vulnerable package.  Appended for the same reason
    # the five above were: a reader that goes by position is unaffected, and a
    # reader that goes by name gets the one answer this file could not give
    # about the most common kind of finding in it.
    "declared_in",
]

# What turns a cell into a program.
#
# Excel, LibreOffice and Google Sheets all evaluate a cell whose first
# character is one of these, so a rule name or a file path out of somebody
# else's repository is code as soon as a reader double clicks the file.  Every
# value in this report comes from a repository this tool does not control.
#
# It is applied to the copy that gets mailed, and deliberately not to the file
# on disk: that file is a contract another tool reads, and an apostrophe in
# front of a value it has parsed for years would be this product corrupting its
# own output to defend a spreadsheet nobody opens it in.
SPREADSHEET_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}


def _iso(value) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _enum(value) -> str:
    return getattr(value, "value", value) or ""


def reportable(session) -> list:
    """Every finding that belongs in the files.

    Anything with the exception flag set is left out, and so is anything with
    a live approved waiver or anything already marked fixed.  The flag is the
    quick way to take one finding out by id; the waiver is the paperwork that
    usually sets it.

    The waived set is queried straight from the waivers table rather than read
    off finding.waiver.  A relationship loaded earlier in the same session can
    be stale, and a waiver that quietly failed to apply is the kind of bug you
    only notice during an audit.
    """
    now = datetime.now(timezone.utc)

    waived_ids = set()
    for waiver in session.query(Waiver).filter(
            Waiver.status == WaiverStatus.APPROVED).all():
        if waiver.active(now):
            waived_ids.add(waiver.finding_id)

    rows = (session.query(Finding)
            .filter(Finding.state != FindingState.FIXED)
            .filter(Finding.excepted.is_(False))
            .all())
    out = [f for f in rows if f.id not in waived_ids]

    out.sort(key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 9),
        f.organization or "",
        f.repository or "",
        f.file_path or "",
        f.line or 0,
    ))
    return out


# The four tagged answers, by the name they carry in the database and the name
# they go out under.  The names outside are the ones the finding page prints,
# because a person reading the file and a person reading the page are usually
# the same person having the same argument.
ASSET_FIELDS = {
    "application_name": "application",
    "application_owner": "business_owner",
    "technical_owner": "technical_owner",
    "sensitivity": "holds",
}


def _nothing_known() -> dict:
    """What a finding carries when its repository row has gone.

    The keys are present and empty rather than absent, so nothing reading the
    file has to tell a missing question from an unanswered one.
    """
    return {"application": "", "business_owner": "", "technical_owner": "",
            "holds": [], "visibility": "", "inherited": []}


def repo_facts(session, findings) -> dict:
    """What each finding's repository is, keyed by repository id.

    The same four answers the finding page shows beside a finding, plus whether
    the repository is public.  A hardcoded password is an incident in the
    payment gateway and a chore in a brochure site, and nothing in the finding
    itself says which, so a tool reading this file was making that call with
    less than the person on the page had.

    Read once for the whole report rather than per finding: an estate puts
    thousands of findings in a few hundred repositories.
    """
    from app.core import tagging
    from app.core.models import Repository

    ids = sorted({f.repo_id for f in findings if f.repo_id})
    if not ids:
        return {}

    rows = []
    # In batches, because an estate can name more repositories than a database
    # will take in one IN clause.
    for start in range(0, len(ids), 500):
        rows.extend(session.query(Repository)
                    .filter(Repository.id.in_(ids[start:start + 500])).all())

    applies = tagging.effective_many(session, rows)

    out = {}
    for row in rows:
        said = applies.get(row.id) or {}
        fact = _nothing_known()
        fact["visibility"] = row.visibility or ""
        for field, name in ASSET_FIELDS.items():
            value = (said.get(field) or {}).get("value", "")
            if name == "holds":
                # A list, not the comma separated string somebody typed, so a
                # reader can match on one label without splitting it first.
                fact[name] = [one.strip() for one in value.split(",") if one.strip()]
            else:
                fact[name] = value
        # Which of the four came from the account rather than this repository.
        # An empty value already says nobody has said anything; without this a
        # reader cannot tell an answer given about this repository from one
        # inherited by it along with two hundred others.
        fact["inherited"] = sorted(
            name for field, name in ASSET_FIELDS.items()
            if (said.get(field) or {}).get("from") == "connection")
        out[row.id] = fact
    return out


def as_dict(finding: Finding, facts: dict = None) -> dict:
    """One finding, the way it goes into the JSON.

    `facts` is what `repo_facts` returned for this set of findings.  Without it
    the repository half of the record is empty rather than absent.
    """
    branches = []
    try:
        branches = json.loads(finding.branches or "[]")
    except (ValueError, TypeError):
        branches = []

    record = {
        # The id to quote in a ticket, and the one an exception is written
        # against.  finding_id is the fingerprint it comes from.
        "vuln_id": finding.vuln_id or "",
        "finding_id": finding.fingerprint,
        "kind": _enum(finding.kind),
        "severity": _enum(finding.severity),
        "state": _enum(finding.state),
        # Which GitHub account it came from.  Two organizations in different
        # accounts can share a repository name.
        "connection": finding.connection or "",
        "organization": finding.organization or "",
        "repository": finding.repository or "",
        "branch": finding.branch or "",
        "branches": branches,
        "file": finding.file_path or "",
        "line": finding.line or 0,
        "start_column": finding.start_column or 0,
        "end_column": finding.end_column or 0,
        "rule": finding.rule or "",
        "title": finding.title or "",
        "description": finding.description or "",
        "url": finding.url or "",
        "commit": finding.commit_sha or "",
        "commit_url": finding.commit_url or "",
        "author": {
            "name": finding.author_name or "",
            "email": finding.author_email or "",
            "login": finding.author_login or "",
            "committed_at": _iso(finding.committed_at),
        },
        "first_found": _iso(finding.first_found_at),
        "last_found": _iso(finding.last_found_at),
        # The two halves of what the severity stands for, and the queue
        # position they come to.  Carried out of the product rather than kept
        # inside it: the ordering is most of what this is for, and a system
        # importing findings needs the same order the page shows.
        #
        # evidence says whether anybody proved this one.  It travels beside the
        # score and not inside it, so a reader can sort on the number and still
        # tell a demonstration from a deduction.
        "risk": {
            "score": finding.risk_score or 0,
            "evidence": finding.risk_evidence or "inferred",
            "impact": finding.impact or "",
            "impact_reason": finding.impact_reason or "",
            "likelihood": finding.likelihood or "",
            "likelihood_reason": finding.likelihood_reason or "",
        },
        # What the code is part of, who answers for it, and what it holds.
        "asset": (facts or {}).get(finding.repo_id) or _nothing_known(),
    }

    if _enum(finding.kind) == "credential":
        record["credential"] = {
            "preview": finding.secret_preview or "",
            "verified": bool(finding.verified),
            "exposure": finding.exposure or "",
        }
    elif _enum(finding.kind) == "dependency":
        record["package"] = {
            "name": finding.package_name or "",
            "version": finding.package_version or "",
            "ecosystem": finding.ecosystem or "",
            "fixed_in": finding.fixed_in or "",
            "image": finding.image_ref or "",
            # The manifest or lock file that asks for it.  A package has no line
            # of code to open, so this is the only location the kind carries.
            "declared_in": finding.manifest_path or "",
        "malicious": finding.malicious_signal if finding.malicious else "",
        }
        if finding.malicious:
            record["malicious"] = {
                "signal": finding.malicious_signal or "",
                "reason": finding.malicious_reason or "",
                "evidence": finding.malicious_evidence or "",
            }
        record["vulnerability"] = {
            "id": finding.vulnerability_id or "",
            "cvss_score": finding.cvss_score,
            "known_exploited": bool(finding.known_exploited),
            "epss_score": finding.epss_score,
        }
        if finding.reachability:
            record["reachability"] = {
                "verdict": finding.reachability,
                "reason": finding.reachability_reason or "",
                "direct": finding.dependency_direct or "unknown",
                "scope": finding.dependency_scope or "unknown",
            }
    elif _enum(finding.kind) == "code":
        record["weakness"] = {
            "cwe": [c for c in (finding.cwe or "").split(",") if c],
            "owasp": [o for o in (finding.owasp or "").split(";") if o],
        }

    return record


def as_row(finding: Finding, facts: dict = None) -> dict:
    """One finding, flattened for the CSV.

    `facts` is what `repo_facts` returned for this set of findings, the same as
    for `as_dict`.  Without it the five repository columns are empty.
    """
    asset = (facts or {}).get(finding.repo_id) or _nothing_known()
    return {
        "vuln_id": finding.vuln_id or "",
        "finding_id": finding.fingerprint,
        "kind": _enum(finding.kind),
        "severity": _enum(finding.severity),
        "state": _enum(finding.state),
        # Which GitHub account it came from.  Two organizations in different
        # accounts can share a repository name.
        "connection": finding.connection or "",
        "organization": finding.organization or "",
        "repository": finding.repository or "",
        "branch": finding.branch or "",
        "file": finding.file_path or "",
        "line": finding.line or 0,
        "start_column": finding.start_column or 0,
        "end_column": finding.end_column or 0,
        "rule": finding.rule or "",
        "title": (finding.title or "").replace("\n", " ").strip(),
        "risk_score": finding.risk_score or 0,
        "risk_evidence": finding.risk_evidence or "inferred",
        "impact": finding.impact or "",
        "likelihood": finding.likelihood or "",
        "package": finding.package_name or "",
        "package_version": finding.package_version or "",
        "ecosystem": finding.ecosystem or "",
        "vulnerability_id": finding.vulnerability_id or "",
        "cvss_score": "" if finding.cvss_score is None else finding.cvss_score,
        "known_exploited": "true" if finding.known_exploited else "false",
        "epss_score": "" if finding.epss_score is None else finding.epss_score,
        "fixed_in": finding.fixed_in or "",
        "reachability": finding.reachability or "",
        "image": finding.image_ref or "",
        "cwe": finding.cwe or "",
        "owasp": finding.owasp or "",
        "secret_preview": finding.secret_preview or "",
        "snippet": finding.snippet or "",
        # The line the engine matched, masked by the scanner.  Without it a
        # reader has the address of a finding and not the thing itself, which
        # for a rule like a mutable action tag means opening the file to learn
        # which action it is even about.
        "snippet": finding.snippet or "",
        "verified": "true" if finding.verified else "false",
        "exposure": finding.exposure or "",
        "author": finding.author_name or "",
        "author_login": finding.author_login or "",
        "committed_at": _iso(finding.committed_at),
        "commit": finding.commit_sha or "",
        "url": finding.url or "",
        "first_found": _iso(finding.first_found_at),
        "last_found": _iso(finding.last_found_at),
        "application": asset["application"],
        "business_owner": asset["business_owner"],
        "technical_owner": asset["technical_owner"],
        # Pipe delimited, the way the tagging spreadsheet writes it.  A comma
        # inside a cell is quoted correctly and then read back by eye as two
        # columns, and somebody always does that at least once.
        "holds": " | ".join(asset["holds"]),
        "visibility": asset["visibility"],
        "declared_in": finding.manifest_path or "",
    }


def csv_text(session, findings: list, *, for_spreadsheet: bool = False,
             facts: dict = None) -> str:
    """These findings as a CSV, in the same columns as the file on disk.

    One place builds a CSV, so the file written after a scan and the copy
    attached to a message can never drift into two different shapes.

    for_spreadsheet is for the copy that gets mailed.  It escapes the cells a
    spreadsheet would otherwise run and puts a byte order mark in front, which
    is what makes Excel on Windows read anything outside ASCII correctly.
    Neither belongs in the file on disk, which is parsed rather than opened.
    """
    # Read once where the caller has not already, since an estate puts
    # thousands of findings in a few hundred repositories.
    facts = facts if facts is not None else repo_facts(session, findings)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS,
                            extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for finding in findings:
        row = as_row(finding, facts)
        if for_spreadsheet:
            row = {name: _quote_formula(value) for name, value in row.items()}
        writer.writerow(row)
    return ("\ufeff" if for_spreadsheet else "") + buffer.getvalue()


def _quote_formula(value):
    """A cell a spreadsheet will show rather than run.

    An apostrophe in front is what every spreadsheet reads as "this is text",
    and it is not shown in the cell.  Numbers are safe to pass through because
    none of these columns can hold a negative one, so a leading minus is always
    somebody else's text rather than arithmetic.
    """
    if isinstance(value, (int, float)):
        return value
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in SPREADSHEET_TRIGGERS else text


def spreadsheet_row(row: dict) -> dict:
    """A CSV row with every cell made safe to open in a spreadsheet.

    For the downloads people open in Excel.  A commit author, a branch or a
    file path is whatever somebody pushed, and a cell that starts with = runs
    as a formula the moment the file opens.
    """
    return {name: _quote_formula(value) for name, value in row.items()}


def _write_atomic(path: Path, data: str) -> None:
    """Write to a temp file in the same directory, then rename over the top.

    A reader either gets the old file or the new one.  Never half of either,
    which matters when something else is polling these on a timer.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o640)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# The SBOM files a scan leaves behind.
#
# Unlike the two report files these cannot be rebuilt from the database: the
# database keeps vulnerable packages, not every component of every repository.
# So they are copied out of the scan's temporary directory while it still
# exists, and what is on disk is whatever the last scan that got that far
# produced.
SBOM_DIRECTORY = "sbom"
SBOM_COMBINED = {
    "cdx": ("ghscan-report-sbom.cdx.json", "sbom.cdx.json"),
    "spdx": ("ghscan-report-sbom.spdx.json", "sbom.spdx.json"),
    "summary": ("ghscan-report-sbom.json", "sbom-summary.json"),
}


def keep_sboms(scan_out_dir, reports_dir: Path = None) -> dict:
    """Copy a finished scan's SBOMs next to the report files.

    Called before the scan's temporary directory goes away, including when the
    scan was stopped or failed, because per repository SBOMs are written as
    each repository finishes and the ones from before the stop are still worth
    having.

    Nothing here may raise.  A scan that worked must not be recorded as failed
    because a copy did not land.
    """
    kept = {"repositories": 0, "combined": 0}
    try:
        scan_out_dir = Path(scan_out_dir)
        reports_dir = Path(reports_dir) if reports_dir else output_dir()

        for source_name, kept_name in SBOM_COMBINED.values():
            source = scan_out_dir / source_name
            if source.is_file() and source.stat().st_size:
                _write_atomic(reports_dir / kept_name,
                              source.read_text(encoding="utf-8"))
                kept["combined"] += 1

        source_dir = scan_out_dir / SBOM_DIRECTORY
        if source_dir.is_dir():
            target_dir = reports_dir / SBOM_DIRECTORY
            target_dir.mkdir(parents=True, exist_ok=True)
            # A repository that was removed from the scope should not keep a
            # stale SBOM here for ever, so the directory is replaced rather
            # than added to.  Only when the scan produced some: an empty
            # source directory means syft never ran, not that the estate has
            # no components.
            produced = sorted(p for p in source_dir.iterdir()
                              if p.is_file() and p.suffix == ".json")
            if produced:
                for old in target_dir.iterdir():
                    if old.is_file() and old.suffix == ".json":
                        try:
                            old.unlink()
                        except OSError:
                            pass
                for one in produced:
                    _write_atomic(target_dir / one.name,
                                  one.read_text(encoding="utf-8"))
                    kept["repositories"] += 1
    except Exception:            # noqa: BLE001 - a scan must survive this
        log.warning("could not keep the SBOMs from this scan", exc_info=True)
    return kept


def sbom_files(reports_dir: Path) -> list:
    """What is on disk to hand over, newest information first.

    One row per file the Report files page offers, in the order somebody wants
    them: the whole estate in both formats, then the per repository set.
    """
    reports_dir = Path(reports_dir)
    rows = []

    def describe(which, name, label, note, path):
        try:
            stat = path.stat()
            when = datetime.fromtimestamp(
                stat.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            return {"which": which, "name": name, "label": label, "note": note,
                    "exists": True, "size": stat.st_size, "modified": when}
        except OSError:
            return {"which": which, "name": name, "label": label, "note": note,
                    "exists": False, "size": 0, "modified": ""}

    rows.append(describe(
        "sbom-cdx", SBOM_COMBINED["cdx"][1], "CycloneDX",
        "every repository in one document", reports_dir / SBOM_COMBINED["cdx"][1]))
    rows.append(describe(
        "sbom-spdx", SBOM_COMBINED["spdx"][1], "SPDX",
        "the same, for tooling that reads SPDX",
        reports_dir / SBOM_COMBINED["spdx"][1]))
    rows.append(describe(
        "sbom-summary", SBOM_COMBINED["summary"][1], "Components and licenses",
        "the component and license rollup, per repository",
        reports_dir / SBOM_COMBINED["summary"][1]))

    directory = reports_dir / SBOM_DIRECTORY
    files = []
    try:
        files = [p for p in directory.iterdir()
                 if p.is_file() and p.suffix == ".json"]
    except OSError:
        files = []
    newest = max((p.stat().st_mtime for p in files), default=0)
    rows.append({
        "which": "sbom-repos", "name": f"{SBOM_DIRECTORY}/", "label": "Per repository",
        "note": f"{len(files)} file(s), downloaded as a zip",
        "exists": bool(files),
        "size": sum(p.stat().st_size for p in files),
        "modified": (datetime.fromtimestamp(newest, timezone.utc)
                     .strftime("%Y-%m-%d %H:%M:%SZ") if newest else ""),
    })
    return rows


def sbom_zip(reports_dir: Path) -> Path:
    """Every per repository SBOM in one archive, written to a temporary file.

    A temporary file rather than memory: an estate of a few thousand
    repositories is a zip nobody wants held in the web process while a browser
    on a slow link reads it.  The caller deletes it.
    """
    import zipfile

    directory = Path(reports_dir) / SBOM_DIRECTORY
    handle, name = tempfile.mkstemp(prefix="gcr-sbom-", suffix=".zip")
    os.close(handle)
    archive = Path(name)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for one in sorted(directory.iterdir()):
            if one.is_file() and one.suffix == ".json":
                bundle.write(one, arcname=f"{SBOM_DIRECTORY}/{one.name}")
    return archive


def output_dir(session=None) -> Path:
    """Where the two files go.

    The Settings page owns this once somebody has been through setup.  The
    environment provides the starting value, so a container that nobody has
    signed into yet still has somewhere to write.
    """
    fallback = Path(settings.reports_dir)
    if session is None:
        return fallback
    try:
        from app.core import settings_store as store
        # Only an explicit choice wins.  Otherwise the environment does, which
        # is what the container sets and what the tests set.
        value = store.stored(session, "output.dir")
        chosen = "" if value is store.MISSING else str(value or "").strip()
    except Exception:
        return fallback
    if not chosen:
        return fallback
    path = Path(chosen)
    if not path.is_absolute():
        # A relative path would land wherever the process happens to be, which
        # is not somewhere anybody mounted a volume.
        return fallback
    return path


def write_reports(session, reports_dir: Path = None) -> dict:
    """Rewrite both files from what is in the database right now.

    Call this after a scan and after any waiver decision.
    """
    reports_dir = Path(reports_dir) if reports_dir else output_dir(session)
    findings = reportable(session)
    facts = repo_facts(session, findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    counts = {}
    for finding in findings:
        key = _enum(finding.severity)
        counts[key] = counts.get(key, 0) + 1

    document = {
        "schema_version": "1.0",
        "generator": {"name": APP_NAME, "version": VERSION},
        "generated_at": generated,
        "summary": {
            "total": len(findings),
            "by_severity": counts,
            "by_kind": _tally(findings, lambda f: _enum(f.kind)),
            "organizations": sorted({f.organization for f in findings if f.organization}),
            "repositories": len({f.repository for f in findings if f.repository}),
        },
        "findings": [as_dict(f, facts) for f in findings],
    }
    _write_atomic(reports_dir / "vulnerabilities.json",
                  json.dumps(document, indent=2) + "\n")

    _write_atomic(reports_dir / "vulnerabilities.csv",
                  csv_text(session, findings, facts=facts))

    # The same decisions, in the format a customer's procurement team reads.
    # Written here rather than on a schedule so it can never describe a set of
    # waivers that has since changed.
    try:
        from app.core import vex
        vex.write(session, reports_dir)
    except Exception:            # noqa: BLE001 - a report must still be written
        log.warning("could not write the VEX documents", exc_info=True)

    return {"findings": len(findings), "generated_at": generated,
            "by_severity": counts}


def _tally(rows, key) -> dict:
    out = {}
    for row in rows:
        name = key(row)
        out[name] = out.get(name, 0) + 1
    return out
