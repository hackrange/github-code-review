"""Waivers are VEX statements under another name.

A waiver with a reason and an expiry, and a triage verdict of `not_applicable`
with the sentence explaining it, are exactly what a VEX document encodes: the
component is here, the vulnerability does not affect it, and this is why.

The value is not the format.  It is that a customer asking "your product
contains a vulnerable library" gets a machine readable answer that somebody
already reviewed and signed, instead of an email thread.  Both dialects are
written because procurement asks for whichever one the asker's tooling reads:
OpenVEX where a supplier wants a standalone statement, CycloneDX where they
want it beside the SBOM this already produces.

Three rules hold this honest:

  Only decisions somebody made.  A waiver has a reviewer, a reason and a date.
  A triage verdict of not_applicable has the sentence the pass wrote.  Nothing
  else is emitted, because a VEX statement is an assertion the supplier is
  standing behind and "the scanner did not look" is not one.

  The status is the one the evidence supports.  A waiver reading "accepted, we
  will fix it next quarter" is not_affected in nobody's reading; it is
  affected, with a note.  Getting that wrong is how a supplier ends up having
  told a customer something untrue in a format designed to be trusted.

  A guess is not a decision.  The reachability pass used to feed this, and it
  should never have.  It answers "does anything in the source import this
  package", which is a good way to sort a list and no way at all to tell a
  customer they are safe.  Everything a lockfile pulled in comes back
  `unlikely` because nothing imports it by name, so a library that runs on
  every request was being published as not_affected with the justification
  `vulnerable_code_not_in_execute_path`.  The verdict is still on the finding,
  where it helps somebody decide what to read first.  It is not signed and
  sent to anybody.

What is not in here matters as much as what is.  Only findings that are still
open and still count are described: a fixed one is not "not affected", it is
fixed, and one somebody excepted is a decision to stop looking rather than a
claim about the product.  The report files leave both out, and a VEX document
that disagrees with the file beside it is worse than neither.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from app.config import APP_NAME, VERSION
from app.core.models import (
    Finding, FindingKind, FindingState, Waiver, WaiverStatus,
)

# The OpenVEX vocabulary.  Four statuses, and the two that matter here.
NOT_AFFECTED = "not_affected"
AFFECTED = "affected"

# Why it is not affected, from the same vocabulary.  A justification is
# required for not_affected and the specification means it.
#
# `third_party` used to be in here, reading `vulnerable_code_not_in_execute_path`.
# It means the finding is in code this team did not write, which for a
# dependency is every finding there is, and says nothing whatever about
# whether the code runs.  A verdict that is true of everything justifies
# nothing, so it makes no statement now.
JUSTIFICATION = {
    "not_applicable": "vulnerable_code_not_present",
    "advisory": "vulnerable_code_not_present",
}


def _iso(when) -> str:
    if not when:
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _purl(finding) -> str:
    """A package URL for the component, which is what a VEX statement names."""
    eco = (finding.ecosystem or "").strip().lower()
    name = (finding.package_name or "").strip()
    if not name:
        return ""
    kind = {"npm": "npm", "python": "pypi", "pypi": "pypi", "go": "golang",
            "go-module": "golang", "java-archive": "maven", "gem": "gem",
            "rust-crate": "cargo", "php-composer": "composer",
            "deb": "deb", "apk": "apk", "rpm": "rpm"}.get(eco, eco or "generic")
    version = (finding.package_version or "").strip()
    return f"pkg:{kind}/{name}" + (f"@{version}" if version else "")


def statements(session) -> list:
    """Every assertion this installation is prepared to stand behind.

    One per (vulnerability, component) pair, because a document that
    contradicts itself is worse than no document.  Where two repositories
    reached different conclusions about the same package, `affected` wins:
    the same library is in both, and the safer of two claims is the one to
    stand behind.
    """
    waived = {}
    rows = (session.query(Waiver, Finding)
            .join(Finding, Finding.id == Waiver.finding_id)
            .filter(Waiver.status == WaiverStatus.APPROVED).all())
    for waiver, finding in rows:
        waived[finding.id] = waiver

    seen = {}

    def add(finding, status, justification, detail, author, when):
        vuln = (finding.vulnerability_id or finding.rule or "").strip()
        product = _purl(finding)
        if not vuln or not product:
            return
        key = (vuln, product)
        # Two repositories, one package, two conclusions.  Saying both would
        # be a document that argues with itself, so the stronger claim stands.
        if key in seen and seen[key]["status"] == AFFECTED:
            return
        seen[key] = {
            "vulnerability": vuln,
            "product": product,
            "status": status,
            "justification": justification,
            "detail": detail,
            "author": author,
            "timestamp": when,
            "repository": finding.repository or "",
        }

    # Only what is still open and still counts.  A fixed finding is not
    # "not affected", and one somebody excepted is a decision to stop looking
    # rather than a claim about the product.  Both are out of the report files
    # already, and this has to agree with them.
    findings = (session.query(Finding)
                .filter(Finding.kind == FindingKind.DEPENDENCY)
                .filter(Finding.state != FindingState.FIXED)
                .filter(Finding.excepted.is_(False)).all())
    for finding in findings:
        waiver = waived.get(finding.id)
        if waiver is not None:
            # A waiver is an acceptance of risk, which is not the same claim as
            # "this does not affect the product".  Saying not_affected here
            # would be telling a customer something untrue in a format built to
            # be trusted, so an accepted risk is reported as affected with the
            # reason attached.
            add(finding, AFFECTED, "",
                (waiver.reason or "").strip()
                + (f" Accepted until {_iso(waiver.expires_at)}."
                   if waiver.expires_at else " Accepted with no end date."),
                waiver.decided_by or waiver.requested_by or "",
                _iso(waiver.decided_at or waiver.created_at))
            continue

        verdict = (finding.triage or "").lower()
        if verdict in JUSTIFICATION:
            add(finding, NOT_AFFECTED, JUSTIFICATION[verdict],
                (finding.triage_reason or "").strip()
                or "set aside by the triage pass",
                APP_NAME, _iso(finding.last_found_at))

        # Nothing else.  A reachability verdict is a way to sort a list, not
        # something to sign.  See the note at the top of this file.

    return list(seen.values())


def openvex(session) -> dict:
    """The standalone dialect, for a supplier who wants a statement on its own."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = statements(session)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/{uuid.uuid4()}",
        "author": APP_NAME,
        "role": "Document Creator",
        "timestamp": now,
        "version": 1,
        "tooling": f"{APP_NAME} {VERSION}",
        "statements": [
            {
                "vulnerability": {"name": row["vulnerability"]},
                "products": [{"@id": row["product"]}],
                "status": row["status"],
                **({"justification": row["justification"]}
                   if row["status"] == NOT_AFFECTED and row["justification"] else {}),
                "status_notes": row["detail"],
                "timestamp": row["timestamp"] or now,
            }
            for row in rows
        ],
    }


def cyclonedx(session) -> dict:
    """The dialect that sits beside the SBOM this already writes."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = statements(session)
    # CycloneDX spells the same idea with different words.
    state = {NOT_AFFECTED: "not_affected", AFFECTED: "exploitable"}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": APP_NAME, "name": APP_NAME, "version": VERSION}],
        },
        "vulnerabilities": [
            {
                "id": row["vulnerability"],
                "affects": [{"ref": row["product"]}],
                "analysis": {
                    "state": state.get(row["status"], "in_triage"),
                    **({"justification": {
                        "vulnerable_code_not_present": "code_not_present",
                        "vulnerable_code_not_in_execute_path": "code_not_reachable",
                    }.get(row["justification"], "code_not_present")}
                       if row["status"] == NOT_AFFECTED else {}),
                    "detail": row["detail"],
                    "response": ["will_not_fix"] if row["status"] == NOT_AFFECTED else [],
                },
            }
            for row in rows
        ],
    }


def write(session, reports_dir) -> dict:
    """Both dialects, next to the report files.

    Written every time the reports are, because a VEX document that lags the
    decisions it describes is the one thing worse than not having one.
    """
    from pathlib import Path

    from app.core.reports import _write_atomic

    reports_dir = Path(reports_dir)
    rows = statements(session)
    _write_atomic(reports_dir / "vex.openvex.json",
                  json.dumps(openvex(session), indent=2) + "\n")
    _write_atomic(reports_dir / "vex.cyclonedx.json",
                  json.dumps(cyclonedx(session), indent=2) + "\n")
    return {"statements": len(rows)}
