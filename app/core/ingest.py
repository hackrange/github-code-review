"""Turning a scan into rows.

The scanner writes one big JSON document.  This reads it and folds it into the
database, matching findings that were already there instead of making new ones
every night.  That matching is what makes last_found mean anything.

Anything that was in a repo we just scanned, and did not come back this time,
gets marked fixed.  Repos that were not in this scan are left alone, so a scan
of one organization never marks another organization's findings as gone.
"""

from __future__ import annotations

import hashlib
import re
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from app.core.models import (
    CredentialVerification, Finding, FindingKind, FindingState, Repository,
    Severity, utcnow, vuln_id_for,
)

log = logging.getLogger("gcr.ingest")

# How many branch names to keep per repository.  A repository that has collected
# more than this has a housekeeping problem rather than a list worth reading,
# and the names are kept to offer a choice, not to be an inventory.
MAX_BRANCH_NAMES = 2000

# Which pass produces which kind of finding, by the names the scanner
# checkpoints under `passes_complete`.
#
# This is the whole basis for deciding that something has been fixed.  A
# finding is absent from a report either because it is gone or because nothing
# looked for it, and only the scanner knows which.  Any kind missing from this
# map is never held open, so a new kind behaves as it did before it was added
# rather than sticking open forever with nobody noticing.
KIND_PASS = {
    FindingKind.CODE: "code",
    FindingKind.CREDENTIAL: "secrets",
    FindingKind.DEPENDENCY: "vulnerabilities",
    FindingKind.MISCONFIGURATION: "misconfigurations",
}


def _segment_glob(pattern: str):
    """One `secrets.exclude_paths` glob, as a regex for a single path segment.

    The meaning has to be the scanner's, exactly, because the whole point is to
    know which paths its credential pass declined to read.  `lib/secrets.sh`
    defines it: a trailing slash is stripped, `*` and `?` stop at a separator,
    everything else is literal, and the pattern has to match a whole segment.
    Two implementations of one rule is a liability, and the alternative was
    worse.  Making the scanner list every dropped path in the report puts tens
    of thousands of lines into a document that already strains the row limit,
    to say something both sides can work out from a setting they both read.
    """
    out = []
    for c in pattern.rstrip("/"):
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
    return re.compile("^" + "".join(out) + "$")


def _skipped_by_credential_pass(session):
    """A test for "the credential pass was configured not to open this file".

    Nothing read those paths, so their findings must not be closed for silence.
    This is the same mistake as an unfinished pass and an unwalked history, in
    the one place that looked like a deliberate choice rather than a gap: the
    skip list is there so tens of thousands of recorded-traffic candidates do
    not drown the report, and it worked, and then the next run read the quiet
    it had created as the repository being clean.  Two private keys confirmed
    live were retired that way, out of a `.zip` the list says to skip.

    Returns a callable, and one that answers False when the list is empty or
    unreadable, so a broken setting cannot hold the whole estate open.
    """
    try:
        from app.core import settings_store as _store
        globs = _store.get(session, "secrets.exclude_paths") or []
    except Exception:            # noqa: BLE001 - a setting must not fail an ingest
        log.exception("could not read the credential skip list; "
                      "no path will be treated as skipped")
        return lambda path: False
    res = [_segment_glob(g) for g in globs if str(g).strip()]
    if not res:
        return lambda path: False

    def skipped(path: str) -> bool:
        if not path:
            return False
        return any(r.match(seg) for seg in str(path).split("/") for r in res)

    return skipped


def _sev(value) -> Severity:
    text = str(value or "unknown").strip().lower()
    if text in ("moderate",):
        text = "medium"
    if text in ("negligible", "note", "informational"):
        text = "info"
    try:
        return Severity(text)
    except ValueError:
        return Severity.UNKNOWN


def _when(value):
    """Parse whatever shape of timestamp the scanner handed us."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _digest(*parts) -> str:
    raw = "|".join(str(p or "") for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# How much free text is kept on a finding.
#
# These fields are explanations meant for a person and they are TEXT columns
# now, so this is not a column width: it is a sanity limit, so that an engine
# emitting something enormous produces a long sentence rather than a row that
# is slow to load and impossible to read.
#
# It was five hundred, which was the old column width doing double duty as an
# editorial decision, and several reasons were being cut mid sentence by it.
LONG_TEXT = 4000


def _as_list(value) -> list:
    """One of these, or several, or none.

    semgrep writes owasp and cwe as a bare string when there is one of them.
    Joining a string joins its characters, which turns "A01:2021 - Injection"
    into "A;0;1;:..." and nobody notices until they read a report.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _work_roots() -> list:
    """Where a scan clones a repository: <root>/gcr-scan-<run>-<random>/work/<org>__<repo>/.

    The root is the work directory, or the system temp directory when that is
    missing, which is where scanner.run_scan puts it.  Both spellings of each,
    in case one is reached through a link.
    """
    import tempfile

    from app.config import settings

    roots = []
    for root in (str(settings.work_dir), tempfile.gettempdir()):
        for spelling in (root, os.path.realpath(root)):
            spelling = spelling.strip("/")
            if spelling and spelling not in roots:
                roots.append(spelling)
    return roots


def in_repository(path) -> str:
    """A path as it is inside the repository, without the scan's clone folder.

    osv-scanner reports the manifest it read as an absolute path even when it
    is run from inside the clone.  Kept as it came, the path named a folder
    that only existed during one scan: every link to it was a 404, and the
    folder name is random per run, so anything keyed on it changed identity
    every night.

    Only a clone folder under a root a scan actually uses is taken out, so a
    repository that happens to hold a folder with a similar name keeps it, and
    a link keeps its repository address.
    """
    text = str(path or "")
    if "gcr-scan-" not in text:
        return text
    for root in _work_roots():
        folder = re.escape(root) + r"/gcr-scan-[^/]+/work/[^/]+/"
        if "://" in text:
            text = re.sub(r"/+" + folder, "/", text)
        else:
            text = re.sub(r"^/+" + folder, "", text, count=1)
    return text


def _strip_clone_paths(row: dict) -> None:
    """Every path on an arriving row, made relative to the repository."""
    for key in ("file", "url"):
        if isinstance(row.get(key), str) and row[key]:
            row[key] = in_repository(row[key])
    package = row.get("package")
    if isinstance(package, dict) and package.get("locations"):
        package["locations"] = [in_repository(where) if isinstance(where, str)
                                else where for where in _as_list(package["locations"])]
    bad = row.get("malicious")
    if isinstance(bad, dict) and bad.get("manifest"):
        bad["manifest"] = in_repository(bad["manifest"])


def repair_clone_paths(session) -> int:
    """Findings already stored with a clone folder in a path, put right.

    The path is corrected on every one.  An open finding for a malicious
    package also carried that folder in its fingerprint, so each scan closed
    it and opened it again as new.  Those move to the fingerprint the
    corrected path gives, which is the one the next scan will arrive with, so
    the finding and anything decided about it carry on.  Only when the old
    fingerprint recomputes exactly from the stored columns, and nothing
    already holds the new one: a guess here would split a finding in two.
    """
    like = "%/gcr-scan-%/work/%"
    rows = (session.query(Finding)
            .filter((Finding.manifest_path.like(like))
                    | (Finding.file_path.like(like))
                    | (Finding.url.like(like))).all())
    rekeyed = 0
    for finding in rows:
        old_manifest = finding.manifest_path or ""
        if (finding.state == FindingState.OPEN and finding.malicious
                and finding.kind == FindingKind.DEPENDENCY and old_manifest):
            parts = [finding.repository, finding.package_name,
                     finding.package_version, finding.rule]
            if finding.image_ref:
                parts.append(finding.image_ref)
            if finding.fingerprint == "dep:" + _digest(*parts, old_manifest):
                wanted = "dep:" + _digest(*parts, in_repository(old_manifest))
                taken = (session.query(Finding.id)
                         .filter(Finding.fingerprint == wanted).first())
                if taken is None:
                    finding.fingerprint = wanted
                    rekeyed += 1
        finding.manifest_path = in_repository(old_manifest)
        if finding.file_path:
            finding.file_path = in_repository(finding.file_path)
        if finding.url:
            finding.url = in_repository(finding.url)
    if rows:
        log.info("took the scan's clone folder out of %d finding path(s), "
                 "and kept %d malicious package finding(s) under a stable "
                 "fingerprint", len(rows), rekeyed)
    return len(rows)


def fingerprint_for(kind: str, row: dict) -> str:
    """What makes this the same finding as last time.

    Secrets come with one from the scanner, built from the secret itself, so it
    survives the file moving.

    Code findings get repo, file, rule, the expression that was matched, and
    which occurrence of it this is.  Not the line.

    Line used to be in there, on the reasoning that two hits of the same rule
    in one file are two different things.  That is true and the line is the
    wrong way to say it: inserting a function anywhere above a finding retires
    it and creates a new one, so every waiver and every regrade recorded on it
    stays attached to a row that has just been resolved.  Somebody graded the
    same three lines twice in one evening because of it, and a decision that
    evaporates teaches people the button does not work.

    The matched expression moves with the code, so an edit above it changes
    nothing.  The occurrence index keeps three identical calls in one file
    three findings, which was the whole point of having the line in there.
    Changing the matched code does change the identity, and that is correct:
    it is not the same code any more.

    Package findings get repo, package, version and advisory, no line at all.

    Package findings get repo, package, version and advisory, no line at all.
    """
    if kind == "credential":
        existing = row.get("secret_fingerprint")
        if existing:
            return f"cred:{existing}"
        return "cred:" + _digest(row.get("repository"), row.get("file"),
                                 row.get("detector"), row.get("start_line"))
    if kind == "code":
        matched = _normalize_match(row.get("matched"))
        if matched:
            return "code:" + _digest(row.get("repository"), row.get("file"),
                                     row.get("rule_name") or row.get("rule"),
                                     matched, row.get("_occurrence", 0))
        # No matched text: an engine that does not report column offsets, or
        # an older report being re-read.  The line is all there is, and it is
        # better than nothing so long as the fallback below can still find
        # what a person decided.
        return "code:" + _digest(row.get("repository"), row.get("file"),
                                 row.get("rule_name") or row.get("rule"),
                                 row.get("start_line"))


    if kind == "misconfiguration":
        # The resource rather than the line, where there is one.  Terraform
        # moves around a file far more than it gets renamed, and a finding that
        # changes identity every time somebody reorders a block takes every
        # waiver on it along too.
        return "misc:" + _digest(row.get("repository"), row.get("file"),
                                 row.get("rule_id"),
                                 row.get("resource") or row.get("start_line"))
    package = row.get("package") or {}
    parts = [row.get("repository"), package.get("name"),
             package.get("version"),
             row.get("id") or row.get("vulnerability_id")]
    # The same package at the same version in two base images is two findings,
    # so the image has to be part of what makes them different.  Appended only
    # when there is one, because adding an empty component would re-key every
    # dependency finding that already exists and make the whole backlog look
    # like it arrived this morning.
    if row.get("image"):
        parts.append(row["image"])
    bad = row.get("malicious") or {}
    if bad.get("manifest"):
        # Two signals on the same package in the same file are two findings,
        # and the same signal in two manifests is two as well.
        parts.append(bad["manifest"])
    return "dep:" + _digest(*parts)


def legacy_codeql_fingerprint(repository: str, rule_id: str) -> str:
    """What a CodeQL alert was keyed on while it was filed as a dependency.

    The alerts feed gave a package of null and null, so the name was built
    from the repository and the rule and nothing else.  Worked out by the same
    function that built it then, so the two cannot drift apart.
    """
    return fingerprint_for("dependency", {
        "repository": repository,
        "package": {"name": None, "version": None, "type": "source"},
        "id": rule_id})


def legacy_code_fingerprint(row: dict) -> str:
    """What this finding was called before identity stopped using the line.

    Kept so a decision somebody already made survives the change.  Without it
    every regrade and waiver on a code finding is orphaned once, on the scan
    after this ships, which is exactly the failure this whole change is about.
    """
    return "code:" + _digest(row.get("repository"), row.get("file"),
                             row.get("rule_name") or row.get("rule"),
                             row.get("start_line"))


_PADDING = re.compile(r"\s*([^\w\s])\s*")


def _normalize_match(value) -> str:
    """The matched expression, with formatting taken out of it.

    Reformatting is not a new finding.  Somebody running a formatter over a
    file should not lose every decision in it, and the difference between
    `f( a, b )` and `f(a, b)` is not a difference in what the rule found.

    Space next to punctuation is removed and space between two words is kept.
    Removing all of it would be simpler and would quietly merge `not x` with
    `notx`, which are two different pieces of code, and identity is the one
    place where being simpler is not worth being wrong.
    """
    text = " ".join(str(value or "").split())
    text = _PADDING.sub(r"\1", text)
    return text[:200]


def number_occurrences(rows) -> None:
    """Mark each code finding as the nth identical match in its file.

    Three identical calls in one file are three findings, and without this
    they would collapse into one and take two thirds of the decisions with
    them.  Ordered by line so the numbering is stable between scans as long as
    the code is in the same order, which is the same assumption every diff
    tool makes.
    """
    seen = {}
    for row in sorted(rows or [], key=lambda r: (
            str(r.get("file") or ""), int(r.get("start_line") or 0))):
        key = (row.get("repository"), row.get("file"),
               row.get("rule_name") or row.get("rule"),
               _normalize_match(row.get("matched")))
        row["_occurrence"] = seen.get(key, 0)
        seen[key] = row["_occurrence"] + 1


def adopt_renamed(session, rows) -> dict:
    """-> {new fingerprint: the existing finding it used to be}.

    Code findings were identified by their line number until this release.
    Changing that means every one of them looks new on the next scan, and
    every waiver and every regrade anybody recorded is orphaned exactly once,
    on the way to fixing the problem of decisions being orphaned.

    The old name cannot be recomputed, because it was built from the line the
    finding used to be on and the new report only knows where it is now.  So
    the pairing is positional: within one file and one rule, the findings
    already in the database and the ones arriving are both put in line order
    and matched off against each other.  That is the same assumption every
    diff makes, and it is right whenever the edit was an insertion or a
    deletion rather than a reordering.

    Only ever pairs what is left over.  Anything the new name already found is
    taken out first, so this can never move a decision onto a finding that
    already has one, and a row it does not pair is left to be created as new.
    """
    from collections import defaultdict

    incoming = defaultdict(list)
    for row in rows or []:
        key = (row.get("repository"), row.get("file"),
               row.get("rule_name") or row.get("rule"))
        if all(key):
            incoming[key].append(row)
    if not incoming:
        return {}

    out = {}
    for key, arriving in incoming.items():
        repository, path, rule = key
        existing = (session.query(Finding)
                    .filter(Finding.kind == FindingKind.CODE,
                            Finding.repository == repository,
                            Finding.file_path == path,
                            Finding.rule == rule,
                            Finding.state == FindingState.OPEN)
                    .all())
        if not existing:
            continue

        wanted = {fingerprint_for("code", row): row for row in arriving}
        # Whatever the new name already matches is not a rename.
        held = {row.fingerprint for row in existing}
        unclaimed_new = [(marker, row) for marker, row in wanted.items()
                         if marker not in held]
        unclaimed_old = [row for row in existing if row.fingerprint not in wanted]
        if not unclaimed_new or not unclaimed_old:
            continue

        unclaimed_new.sort(key=lambda pair: int(pair[1].get("start_line") or 0))
        unclaimed_old.sort(key=lambda row: int(row.line or 0))
        for (marker, _row), previous in zip(unclaimed_new, unclaimed_old):
            out[marker] = previous
    return out


# Severity words, weakest first, for "at least" comparisons.
_RANK = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def adopt_code_rows(session, finding, marker: str, row: dict, counts: dict):
    """A credential semgrep used to file as code takes those rows over.

    semgrep's secret detectors were code findings, one per line, until they
    were moved to the credential pass.  Left alone, every one of them would
    stop being reported and be closed as fixed: hundreds of keys marked
    remediated on the night nothing was done about them.

    So the first of them becomes this credential, keeping its id and every
    decision on it, the way a renamed finding is carried.  The rest were never
    separate problems, only the same value on another line, so their
    decisions move onto this credential where it has none of its own, and the
    rows go.  -> the finding to fill in.
    """
    from app.core.models import FindingAnalysis, Waiver

    rule = row.get("code_rule") or ""
    lines = [int(n) for n in (row.get("code_lines") or []) if str(n).isdigit()]
    if not lines and row.get("start_line"):
        lines = [int(row["start_line"])]
    if not rule or not lines or not row.get("repository") or not row.get("file"):
        return finding
    olds = (session.query(Finding)
            .filter(Finding.kind == FindingKind.CODE,
                    Finding.repository == row["repository"],
                    Finding.file_path == row["file"],
                    Finding.rule == rule,
                    Finding.line.in_(lines))
            .order_by(Finding.line, Finding.id)
            .all())
    # A fixed one too.  Before semgrep's keys reached the credential pass
    # intact, its code rows were closed as fixed with nothing done about the
    # key; taking them over reopens them as what they always were.  Open ones
    # are preferred, so a decision on a live row is the one carried.
    olds.sort(key=lambda row: (row.state == FindingState.FIXED, row.line or 0, row.id))
    if not olds:
        return finding
    if finding is None:
        finding = olds.pop(0)
        finding.kind = FindingKind.CREDENTIAL
        finding.fingerprint = marker
        if finding.state == FindingState.FIXED:
            finding.state = reopened_state(session, finding)
            finding.resolved_at = None
        # What the code pass said about it is not what the credential pass
        # says, and engine_severity is only ever filled when empty.
        finding.engine_severity = ""
        finding.triage = ""
        finding.triage_reason = ""
        counts["renamed"] = counts.get("renamed", 0) + 1
    session.flush()
    for old in olds:
        kept = session.query(Waiver).filter(Waiver.finding_id == finding.id).one_or_none()
        moving = session.query(Waiver).filter(Waiver.finding_id == old.id).one_or_none()
        if moving is not None and kept is None:
            moving.finding_id = finding.id
            for name in ("excepted", "exception_reason", "exception_by",
                         "exception_at", "exception_expires_at"):
                setattr(finding, name, getattr(old, name))
            if old.state == FindingState.WAIVED:
                finding.state = FindingState.WAIVED
        if finding.custom_severity is None and old.custom_severity is not None:
            for name in ("custom_severity", "custom_severity_reason",
                         "custom_severity_by", "custom_severity_at"):
                setattr(finding, name, getattr(old, name))
        (session.query(FindingAnalysis)
         .filter(FindingAnalysis.finding_id == old.id)
         .update({FindingAnalysis.finding_id: finding.id}, synchronize_session=False))
        session.flush()
        session.delete(old)
        counts["folded_into_credential"] = counts.get("folded_into_credential", 0) + 1
    return finding


def waived_now(session, finding) -> bool:
    """Does an approved waiver that has not expired cover this finding."""
    from app.core.models import Waiver, WaiverStatus
    if finding.id is None:
        return False
    waiver = (session.query(Waiver)
              .filter(Waiver.finding_id == finding.id,
                      Waiver.status == WaiverStatus.APPROVED)
              .one_or_none())
    if waiver is None or waiver.expires_at is None:
        return False
    expires = waiver.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > utcnow()


def reopened_state(session, finding):
    """What a finding that came back after being marked fixed is now.

    Open, unless somebody waived it and the waiver still stands.  A scan that
    did not see a waived finding marks it fixed, and windowed or partial
    scans miss findings all the time; reopening it as open when it came back
    threw the approved waiver away.  386 waived findings were back on the
    dashboard that way, among them a rotated key with an attestation on file.
    """
    return FindingState.WAIVED if waived_now(session, finding) else FindingState.OPEN


def restore_waived(session) -> int:
    """Put back to waived every open finding an approved waiver still covers.

    Repairs what the reopening above got wrong before it was fixed, and
    anything else that leaves a waived finding open.  Cheap: one join.
    """
    from app.core.models import Waiver, WaiverStatus
    rows = (session.query(Finding)
            .join(Waiver, Waiver.finding_id == Finding.id)
            .filter(Finding.state == FindingState.OPEN,
                    Waiver.status == WaiverStatus.APPROVED,
                    Waiver.expires_at > utcnow())
            .all())
    for finding in rows:
        finding.state = FindingState.WAIVED
    return len(rows)


def _repo_for(session, organization: str, full_name: str, cache: dict,
              connection=None) -> Repository:
    """Find or make the repository row.  Cached so a big scan is not chatty."""
    key = (full_name or "").lower()
    if key in cache:
        return cache[key]

    name = (full_name or "").split("/")[-1]
    repo = (session.query(Repository)
            .filter(Repository.full_name == full_name)
            .one_or_none())
    if repo is None:
        repo = Repository(organization=organization or full_name.split("/")[0],
                          name=name, full_name=full_name)
        session.add(repo)
        session.flush()

    # Say which account it came from, on the row and on every finding under it.
    if connection is not None:
        repo.connection_id = connection.id
        repo.connection = connection.name

    cache[key] = repo
    return repo


def _apply_common(finding: Finding, row: dict, seen_at) -> None:
    finding.organization = row.get("organization") or ""
    finding.repository = row.get("repository") or ""
    finding.branch = row.get("branch") or (row.get("branches") or [""])[0] or ""
    finding.branches = json.dumps(row.get("branches") or
                                  ([row["branch"]] if row.get("branch") else []))
    finding.file_path = row.get("file") or ""
    finding.line = int(row.get("start_line") or 0)
    finding.start_column = int(row.get("start_column") or 0)
    finding.end_column = int(row.get("end_column") or 0)
    finding.url = row.get("url") or row.get("reference") or ""
    finding.commit_sha = row.get("commit") or ""
    finding.commit_url = row.get("commit_url") or ""
    finding.last_found_at = seen_at


def _reach_map(session) -> dict:
    """How many people can reach each repository, in one query.

    The score reads this, and reading it per finding would be a query for every
    row in a report that runs to thousands.  One grouped pass up front instead,
    which is also what makes the number on the page and the number in the
    database the same number.
    """
    from sqlalchemy import func

    from app.core.models import RepoAccess

    try:
        rows = (session.query(RepoAccess.repository,
                              func.count(RepoAccess.id))
                .group_by(RepoAccess.repository).all())
    except Exception:            # noqa: BLE001 - an ingest must not fail on this
        log.warning("could not read who can reach what, so the score will not "
                    "count it", exc_info=True)
        return {}
    return {name: count for name, count in rows if name}


def _drop_certifications_for_gone_branches(session, repo, full_name,
                                           walked: set) -> int:
    """Take away the sign offs on branches this scan could not find.

    A branch that has been deleted is not a branch anybody can vouch for, and
    a green badge against one is a claim about code that is not there.  If it
    ever comes back it comes back unreviewed, which is the right starting
    point: whoever recreated it did not read it.

    Only ever on the evidence of a scan that looked, and only ever against the
    full list of branches that are there.  That is not the list a run walks:
    the quiet branch filter and the per repository cap both narrow it, so with
    `stale_days` set every branch nobody has touched lately was missing from
    the walked list and the sign off on it was being deleted on every scan.
    The two lists are now carried separately for exactly this reason.

    A name missing from the full list is missing because something went and
    checked, not because a run was cut short or a branch was skipped for being
    quiet.  Everything else in this file holds findings open on that same
    distinction, and deleting a row is far less forgiving than holding one
    open, so the bar is the same and the consequence of getting it wrong is
    worse.

    The default branch counts as walked whatever it is called, because a
    certification written against "" means whichever branch the repository
    deploys from.
    """
    from app.core.models import Certification

    if not walked:
        return 0
    default = (getattr(repo, "default_branch", "") or "")
    rows = (session.query(Certification)
            .filter(Certification.repository == full_name).all())
    dropped = 0
    for row in rows:
        named = (row.branch or default)
        if not named or named in walked:
            continue
        log.warning("the sign off on %s@%s is being removed: this scan found "
                    "%d branch(es) in the repository and that was not one of "
                    "them", full_name, named, len(walked))
        session.delete(row)
        dropped += 1
    if dropped:
        session.flush()
    return dropped


def _risk_context(repo, connection, reach: dict = None) -> dict:
    """What the repository holds, for the impact half of the assessment.

    The same fallback `tagging.effective` applies, done from the two rows
    already in hand rather than by querying for them.  Ingest walks thousands
    of findings across a few hundred repositories, and a query per finding to
    read a string somebody typed once is not a trade worth making.
    """
    own = (getattr(repo, "sensitivity", "") or "").strip()
    if own:
        sensitivity, said_by = own, "repository"
    else:
        sensitivity = (getattr(connection, "sensitivity", "") or "").strip()
        said_by = "connection" if sensitivity else "nobody"

    return {"sensitivity": {"value": sensitivity, "from": said_by},
            "visibility": getattr(repo, "visibility", "") or "",
            "people_total": (reach or {}).get(
                getattr(repo, "full_name", "") or "", 0)}


def _set_aside_placeholders(session, document, seen_at, seen_fingerprints) -> int:
    """Credentials this run read, recognised, and deliberately did not report.

    A value matching a triage rule, or one too short or too uniform to be a
    credential, is kept out of the reported set.  It is not thrown away: the
    scanner writes it into the report with its fingerprint, the file it sits in
    and which test it was that decided, and nothing on this side had ever read
    that list.

    So a finding whose value somebody had just ruled a placeholder went missing
    from the reported set, and the loop below closed it as fixed.  Fixed says
    the password was taken out of the code.  It is still on the same line, and
    the record now says otherwise, which is the reading an audit takes at face
    value a year later.

    The rule the rest of this file keeps is that absence from a report only
    means fixed if somebody looked.  This is the one case where the report says
    in as many words that somebody looked straight at the value and ruled it
    out.  So it is written down as a decision: set aside, kept, out of the work
    and out of the report files, rather than closed as though the code had been
    cleaned up.

    -> how many findings it changed.
    """
    # Which test it was, in the order that says the most about the value.  A
    # rule somebody wrote is a person's decision and outranks the heuristics,
    # which are the scanner's own reading of the shape of the string.
    reasons = (
        ("placeholder_pattern_match", "it matches a triage rule"),
        ("public_key",
         "it is a public key, which is meant to be shared and opens nothing "
         "by itself"),
        ("url_stand_in",
         "the login in the address is a stand-in for the reader to fill in, "
         "such as user:token@host, not a real one"),
        ("content_digest",
         "it is a hash of content rather than a credential: bare hex at exactly "
         "one hash length, and one of several of that same shape in the same "
         "file, which is what a generated report or a lock file looks like and "
         "what a credential never looks like"),
        ("object_key",
         "it is the name of the next entry in a JSON object, not a value.  "
         "The entry before it ends in a word like API, and the rule read the "
         "comma between them as an equals sign"),
        ("jwt_signature_stub",
         "its signature is the wrong length for the algorithm it names, so "
         "nobody could present it anywhere"),
        ("low_character_diversity",
         "it is built from too few distinct characters to be a credential"),
        ("below_min_length", "it is shorter than a credential"),
        ("below_min_entropy", "it is too predictable to be a credential"),
    )

    changed = 0
    for row in (document.get("placeholders_filtered") or []):
        if not isinstance(row, dict):
            continue
        digest = str(row.get("secret_fingerprint") or "").strip()
        if not digest:
            continue
        marker = "cred:" + digest
        # Read and ruled out is not missing.  Recorded before anything else
        # below, so the resolve loop leaves this one alone whatever happens.
        seen_fingerprints.add(marker)

        finding = (session.query(Finding)
                   .filter(Finding.fingerprint == marker).one_or_none())
        if finding is None or finding.kind != FindingKind.CREDENTIAL:
            continue

        triage = row.get("triage")
        triage = triage if isinstance(triage, dict) else {}
        why = next((text for key, text in reasons if triage.get(key)),
                   "it did not survive triage")
        sentence = ("The scanner read this value and did not report it, because "
                    "%s.  It is still in the code: this says it is not a "
                    "credential, not that it was removed." % why)

        touched = False
        if finding.triage != "not_applicable":
            finding.triage = "not_applicable"
            finding.triage_reason = sentence
            touched = True
        # Somebody else's decision is left as they made it.  A waiver carries
        # who asked and who agreed, and overwriting it would put a sentence
        # nobody wrote where their reason used to be.
        if not finding.excepted:
            finding.excepted = True
            finding.exception_reason = sentence
            finding.exception_by = "the triage rules"
            finding.exception_at = seen_at
            touched = True
        if finding.state != FindingState.WAIVED:
            finding.state = FindingState.WAIVED
            # It was never resolved.  A date here would be the same claim the
            # state used to make, kept in a field nobody looks at.
            finding.resolved_at = None
            touched = True
        changed += 1 if touched else 0
    return changed


def ingest_report(session, report_path: Path, scanned_repos: set = None,
                  connection=None) -> dict:
    """Fold one scanner report into the database.

    Returns what changed, so the scan history has something honest to show.
    """
    path = Path(report_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    seen_at = utcnow()

    from app.core import risk, severity_rules

    # Loaded once, not queried per finding.
    overrides = severity_rules.as_map(session)
    reach = _reach_map(session)
    # Waived findings an earlier scan reopened by mistake go back to waived.
    restored = restore_waived(session)

    # What AI validation decided and learned, and what code every standing
    # grade decision was made against.  Small tables, read once.
    from app.core import learned
    learned_rules = learned.load_rules(session)
    ai_grades = learned.load_grades(session)
    bases = learned.load_bases(session)
    rule_hits = {}

    cache = {}
    counts = {"new": 0, "updated": 0, "resolved": 0, "repositories": 0}
    if restored:
        counts["waivers_restored"] = restored
    new_findings = []
    touched_repos = set()
    seen_fingerprints = set()
    # Repositories where the credential walk stopped short this run.  A run
    # that only covered part of the history reports only what it covered, and
    # the rest is not gone, it is unread.
    partial_history = set()
    # Repositories whose worker died or timed out.  They still get an entry so
    # they do not vanish from the report, and nothing they did not say about
    # themselves counts for anything.
    failed_repos = set()
    # Did this run walk a window rather than the whole history.  One question,
    # asked once, because the answer decides whether absence from this report
    # means anything at all for credentials.
    try:
        from app.core import settings_store as _store
        windowed_run = int(_store.get(session, "secrets.history_window_days") or 0) > 0
    except Exception:            # noqa: BLE001 - a setting must not fail an ingest
        log.exception("could not tell whether this run used a history window; "
                      "treating it as windowed, which holds findings open")
        windowed_run = True

    # Repositories this run left out because they are archived.
    #
    # An archived repository stops appearing in reports from the moment it is
    # archived.  Nothing then updated the flag saying so, because only a report
    # could, and nothing closed its findings, because a repository nobody
    # looked at is a repository nobody looked at.  So it stayed in the product
    # forever: last scanned months ago, its findings open, counted as work
    # somebody owed on code that can no longer be changed.
    #
    # The findings are still not closed.  They were never shown to be fixed and
    # deleting the record of what a repository held when it was retired is the
    # part an auditor asks about.  What changes is that the product can now say
    # which they are, and stop counting them as outstanding work.
    #
    # Read defensively, the same as the partial-code list beside it and for the
    # same reason: an app is upgraded before the scanners feeding it are, so a
    # field of the wrong shape must never be able to take an ingest down.
    archived_now = set()
    for name in (document.get("archived_repositories") or []):
        if isinstance(name, dict):
            name = name.get("full_name")
        if isinstance(name, str) and name.strip():
            archived_now.add(name.strip())
    if archived_now:
        marked = (session.query(Repository)
                  .filter(Repository.full_name.in_(sorted(archived_now)))
                  .all())
        for repo_row in marked:
            repo_row.archived = True
        log.info("%d repositor%s archived on the host and left out of this "
                 "scan; %d of them known here and marked",
                 len(archived_now), "y" if len(archived_now) == 1 else "ies",
                 len(marked))
    # Which paths the credential pass was told not to open.  Built once: it
    # compiles the skip list, and the closing loop asks it per finding.
    skipped_path = _skipped_by_credential_pass(session)
    # Which passes actually finished, per repository, as the scanner reported
    # them.  A finding is only ever closed by the pass that would have found
    # it, so this is what decides that.
    passes_done = {}
    # The semgrep rules each repository's run had.  Empty means unknown.
    rules_loaded = {}

    # Repositories first, so findings can hang off them.
    for entry in document.get("repositories", []) or []:
        meta = entry.get("repository") or {}
        full_name = meta.get("full_name")
        if not full_name:
            continue
        repo = _repo_for(session, meta.get("owner") or meta.get("organization"),
                         full_name, cache, connection=connection)
        heads = entry.get("branch_heads")
        if isinstance(heads, dict) and heads:
            repo.branch_heads = json.dumps(heads)
        # When the default branch last got a commit.  Only from a run that
        # read it, so a report without it leaves the last answer standing.
        head = entry.get("default_head")
        if isinstance(head, dict) and head.get("committed_at"):
            _committed = _when(head.get("committed_at"))
            if _committed is not None:
                repo.default_committed_at = _committed
                count = head.get("commits_90d")
                repo.default_commits_90d = (int(count) if isinstance(count, int)
                                            and count >= 0 else None)
                times = head.get("commit_times")
                repo.default_commit_times = (
                    json.dumps(sorted((int(t) for t in times
                                       if isinstance(t, int) and t > 0),
                                      reverse=True)[:1500])
                    if isinstance(times, list) else "")
        dast = entry.get("dast")
        if isinstance(dast, dict) and dast.get("verdict"):
            repo.dast_verdict = str(dast.get("verdict"))[:16]
            repo.dast_reason = str(dast.get("reason") or "")[:500]
        repo.visibility = meta.get("visibility") or repo.visibility
        repo.default_branch = meta.get("default_branch") or repo.default_branch
        repo.archived = bool(meta.get("archived", repo.archived))
        repo.size_kb = int(meta.get("size_kb") or repo.size_kb or 0)
        # Kept rather than dropped.  The provider reports it on every
        # repository and nothing here was reading it, so a sign off that
        # stopped reading as current could say the branch had moved and not
        # when, which is the difference between a fact and something somebody
        # can act on.
        _pushed = _when(meta.get("pushed_at"))
        if _pushed is not None:
            repo.pushed_at = _pushed
        repo.html_url = meta.get("html_url") or repo.html_url
        # A worker that timed out or crashed still gets an entry, so that the
        # repository does not vanish from the report.  It did not look at
        # anything, so it does not get to claim a scan date: stamping one made
        # a repository nobody had ever read look freshly scanned and clean,
        # which is how four of them stayed invisible for a week.
        if str(entry.get("status", "ok")) != "failed":
            repo.last_scanned_at = seen_at
        else:
            failed_repos.add(full_name)
        loaded = entry.get("code_rules_loaded")
        if isinstance(loaded, list) and loaded:
            rules_loaded[full_name] = {str(name).strip() for name in loaded
                                       if str(name).strip()}
        declared = entry.get("passes_complete")
        if isinstance(declared, list):
            passes_done[full_name] = {str(name).strip() for name in declared
                                      if str(name).strip()}
        # What the scan actually walked.  Kept so the branch box on a
        # connection can offer real names, and so there is still a record of
        # the coverage once the report itself has gone.  Capped because one
        # repository with tens of thousands of refs should not write a blob
        # nobody will read to the end of.
        scanned = [str(name).strip()
                   for name in (entry.get("branches_scanned") or [])
                   if str(name).strip()]
        # And every branch that is there, which is a different list.  The
        # walked one is narrowed by the quiet branch filter and the per
        # repository cap, so a name missing from it does not mean the branch
        # has gone.  A sign off is only ever taken away on this one.
        present = [str(name).strip()
                   for name in (entry.get("branches_present") or [])
                   if str(name).strip()]
        if present:
            repo.branch_names_present = json.dumps(
                sorted(set(present))[:MAX_BRANCH_NAMES])
        if scanned:
            repo.branch_names = json.dumps(sorted(set(scanned))[:MAX_BRANCH_NAMES])
        # Only on the full list, and only when a scanner new enough to send it
        # did.  A report that does not carry one is not evidence that anything
        # has gone, and deleting a row is the one move here that cannot be
        # undone: the badge shows as unknown until a scan says otherwise,
        # which is the forgiving direction and the one every other guard in
        # this file takes.
        if present:
            counts["certifications_dropped"] = (
                counts.get("certifications_dropped", 0)
                + _drop_certifications_for_gone_branches(
                    session, repo, full_name, set(present)))

        # How far the credential engines walked here.  Only ever moved by a
        # run that actually walked something: a repository skipped this time
        # keeps the ground the last one covered.
        history = entry.get("history") or {}
        walked_from = str(history.get("walked_from") or "").strip()
        if walked_from:
            repo.history_from = walked_from[:32]
            repo.history_complete = bool(history.get("complete"))
        # A walk whose engine died is not a walk.
        #
        # The rule above is that a run which walked nothing leaves the marker
        # where the last one put it, which is right for a repository this run
        # simply did not get to.  It is wrong for one where the engine that
        # reads history was killed part way through: the repository keeps a
        # marker saying its history has been read end to end, and the catch up
        # pass, whose whole job is to find histories nobody has finished,
        # skips it for ever after.
        #
        # Only ever cleared, never set, and only on a report that names the
        # engine that died.  So this can lose a repository a marker it had
        # earned, which costs one more walk, and can never award one.
        elif str(entry.get("secrets_incomplete_reason") or "").strip():
            repo.history_complete = False
        # Two different claims, and conflating them cost three thousand
        # findings.
        #
        # `complete` says the walk has reached the first commit.  It does not
        # say this run reported everything in that history, and with a window
        # set it certainly did not: the run read one slice and said nothing
        # about the rest.  Absence from a windowed report is not evidence.
        #
        # So a windowed run makes every repository in it partial for
        # credentials, whatever the marker says.  Read from the setting rather
        # than from anything the scanner sends, because the failure this
        # prevents came from believing a report about its own completeness.
        #
        # What went wrong: an install with no markers had this latent, since
        # nothing was ever marked complete.  Crediting repositories with the
        # full walks they had genuinely had then turned the flag on, the next
        # windowed run reported "complete" honestly by its own meaning, this
        # read it as "nothing unwalked", and every credential older than the
        # window was marked fixed.  Two thousand nine hundred and sixty five of
        # them in one night.
        if windowed_run or (history and not history.get("complete", True)):
            partial_history.add(full_name)

        branch_list = ((entry.get("access") or {}).get("branches")) or []
        wanted = meta.get("default_branch") or repo.default_branch
        repo.default_branch_protected = any(
            b.get("protected") for b in branch_list
            if isinstance(b, dict) and b.get("name") == wanted)
        touched_repos.add(full_name)
        counts["repositories"] += 1

    def upsert(kind_name: str, kind_enum, rows, fill) -> None:
        # Which identical match this is, before anything is looked up.  The
        # numbering is over the whole set for a repository, so it cannot be
        # done a row at a time.
        renamed = {}
        if kind_name == "code":
            number_occurrences(rows)
            renamed = adopt_renamed(session, rows)

        for row in rows or []:
            full_name = row.get("repository") or ""
            if not full_name:
                continue
            touched_repos.add(full_name)
            repo = _repo_for(session, row.get("organization"), full_name, cache,
                             connection=connection)

            # Before the fingerprint, which some kinds build from a path.
            _strip_clone_paths(row)
            marker = fingerprint_for(kind_name, row)
            seen_fingerprints.add(marker)

            finding = (session.query(Finding)
                       .filter(Finding.fingerprint == marker)
                       .one_or_none())

            # Nothing under the new name.  It may be a finding this release
            # renamed rather than a new one: see adopt_renamed above.
            if finding is None and kind_name == "code":
                carried = renamed.pop(marker, None)
                if carried is not None:
                    carried.fingerprint = marker
                    finding = carried
                    counts["renamed"] = counts.get("renamed", 0) + 1
            # A CodeQL alert that used to be filed as a dependency.  Those
            # were keyed on rule alone, so one row stood for every alert of
            # that rule in the repository.  The first alert to arrive takes it
            # over, with every decision recorded on it, and the rest arrive as
            # the separate findings they always were.
            if finding is None and kind_name == "code" \
                    and row.get("source") == "codeql":
                old = legacy_codeql_fingerprint(full_name, row.get("rule_id"))
                carried = (session.query(Finding)
                           .filter(Finding.fingerprint == old,
                                   Finding.kind == FindingKind.DEPENDENCY)
                           .one_or_none())
                if carried is not None:
                    carried.fingerprint = marker
                    carried.kind = FindingKind.CODE
                    for name in ("package_name", "package_version",
                                 "package_source", "ecosystem", "manifest_path",
                                 "vulnerability_id", "fixed_in",
                                 "reachability", "reachability_reason"):
                        setattr(carried, name, "")
                    finding = carried
                    counts["renamed"] = counts.get("renamed", 0) + 1

            # A credential semgrep used to report as code.
            if kind_name == "credential" and row.get("code_rule"):
                finding = adopt_code_rows(session, finding, marker, row, counts)

            if finding is None:
                finding = Finding(fingerprint=marker,
                                  vuln_id=vuln_id_for(marker),
                                  kind=kind_enum, repo_id=repo.id,
                                  first_found_at=seen_at)
                session.add(finding)
                counts["new"] += 1
                # Kept so the notifier can say what arrived rather than what
                # is outstanding.  This is the one place that comparison
                # already happens, and a message about the standing backlog
                # trains people to filter the sender.
                new_findings.append(finding)
            else:
                counts["updated"] += 1
                # It came back, so it is not fixed any more.  A waived one
                # stays waived, including one a scan that missed it had
                # marked fixed in the meantime.
                if finding.state == FindingState.FIXED:
                    finding.state = reopened_state(session, finding)
                    finding.resolved_at = None

            # Older rows predate the readable id.  Fill it in as they come
            # back round rather than making a migration out of it.
            if not finding.vuln_id:
                finding.vuln_id = vuln_id_for(marker)

            finding.repo_id = repo.id
            if connection is not None:
                finding.connection_id = connection.id
                finding.connection = connection.name
            _apply_common(finding, row, seen_at)
            fill(finding, row)

            # What this organization says it is worth, if it has said.  Applied
            # after fill so it is the last word, and recorded so the engine's
            # own grade is not silently rewritten with nobody able to tell.
            # The triage already decided this is not what its rule was looking
            # for and wrote down why.  Leaving it graded high anyway is how a
            # work list fills with things nobody should be working on: finding
            # 13825 sat at HIGH with a verdict reading "cast to a number before
            # output, which cannot carry markup" on the same row.
            #
            # The engine's grade is kept beside it rather than overwritten, so
            # this reads as a decision somebody can disagree with.  A rule an
            # admin wrote still wins, because it is applied after.
            # A token that says it has expired.  Every correct validator rejects
            # it, so it cannot be used to get in, and an expired credential is
            # not a vulnerability.  Info rather than gone: the value is still
            # in the code, and whatever claims it carried in the clear are
            # still a disclosure, which the reason names.  A token the provider
            # confirmed still works is never lowered, whatever it says about
            # itself, and an admin rule or a regrade still has the last word.
            if (finding.kind == FindingKind.CREDENTIAL
                    and (finding.token_kind or "") == "jwt"
                    and finding.token_expired is True
                    and not finding.verified
                    and finding.severity != Severity.INFO):
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = Severity.INFO
                when = (finding.token_expires_at.strftime("%Y-%m-%d")
                        if finding.token_expires_at else "a date in the past")
                note = ("The token expired on %s, so it will not authenticate "
                        "anybody and is graded info." % when)
                claims = (finding.token_identity_claims or "").strip()
                if claims:
                    note += ("  It still carries %s in the clear, which is a "
                             "disclosure of its own." % claims)
                if not (finding.triage_reason or "").startswith("The token expired"):
                    finding.triage_reason = note

            # Somebody is exploiting this in the wild, and nothing here says
            # the code does not ship.  The advisory's own grade is a judgement
            # about the flaw in the abstract; CISA listing it is an
            # observation about attackers, and it outranks the abstract.
            #
            # 116 of 171 known exploited advisories were medium, among them a
            # jQuery XSS on 22 pages that load it, which is a work list that
            # puts "medium" beside "being exploited right now".  Raised to
            # high, never lowered, and the advisory's grade kept beside it.
            # Reachability "unlikely" is evidence it does not ship, so those
            # keep their grade and say why in their likelihood.
            if (finding.kind == FindingKind.DEPENDENCY
                    and finding.known_exploited
                    and (finding.reachability or "") != "unlikely"
                    and _RANK.get(finding.severity.value, 0) < _RANK["high"]):
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = Severity.HIGH

            # The tree says it does not ship.  Since 461e180 reachability only
            # says unlikely on evidence: the lockfile marks it development
            # only, only the test suite imports it, or it is a development
            # dependency nothing the application ships imports.  So the flaw
            # runs on developer and build machines, not in front of anybody,
            # and grading it the same as one in production is the noise that
            # buries the ones that are.  2,640 came in on one scan.
            #
            # Low rather than gone: build machines are still machines, and a
            # malicious input in CI is still an input.  Never a known
            # exploited one, and never a malicious package, which does its
            # damage at install time whatever imports it.
            if (finding.kind == FindingKind.DEPENDENCY
                    and (finding.reachability or "") == "unlikely"
                    and not finding.known_exploited
                    and not getattr(finding, "malicious", False)
                    and _RANK.get(finding.severity.value, 0) > _RANK["low"]):
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = Severity.LOW

            # A distribution package in a base image the build upgrades after
            # pulling it.  The image in the registry carries the old version
            # and the image that ships most likely does not, so these go to
            # the bottom together, at low, which is what the recommendation on
            # each one already said and what people were doing by hand, a
            # hundred at a time.  Only distribution packages: an upgrade does
            # not rebuild the Go runtime inside a binary, so a stdlib finding
            # keeps its grade.  An admin rule or a regrade still has the last
            # word, because both are applied below.  Known exploited ones keep
            # their grade: "probably upgraded" is not enough for those.
            if (finding.kind == FindingKind.DEPENDENCY
                    and finding.base_upgraded
                    and not finding.known_exploited
                    and (finding.ecosystem or "").lower() in ("deb", "rpm", "apk")
                    and finding.severity in (Severity.CRITICAL, Severity.HIGH,
                                             Severity.MEDIUM)):
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = Severity.LOW

            if (finding.triage == "not_applicable"
                    and finding.severity != Severity.INFO):
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = Severity.INFO

            # The whole finding, not just its rule name.  An override can ask
            # about the kind, the state, the leaked value, the exposure or who
            # committed the line, and about several of those at once, so it
            # has to be able to read them.
            override = severity_rules.apply(
                overrides, finding.rule, finding.cwe,
                getattr(connection, "sensitivity", "") if connection is not None else "",
                finding=finding)
            if override is not None and override != finding.severity:
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = override

            # What a model said, or a rule learned from what a model said.
            # Lower only, never a credential or a known exploited package, and
            # under a person's regrade, which is applied below.  A grade made
            # against code that has since changed no longer stands: it is
            # lifted, the finding goes back to what the engine says, and the
            # page says why.  The same code keeps it, so nothing is asked twice.
            grade = ai_grades.get(finding.id) if finding.id is not None else None
            if grade is not None and learned.code_changed(bases, finding, "ai"):
                learned.lift(bases, finding, "ai", grade.severity.value,
                             "the flagged code changed after the AI grade "
                             "was given", grade.created_by)
                session.delete(grade)
                ai_grades.pop(finding.id, None)
                grade = None
                counts["ai_lifted"] = counts.get("ai_lifted", 0) + 1
            if grade is not None and not learned.still_covers(learned_rules, grade, finding):
                # A rule narrowed since it gave this grade, or was retired:
                # the grade goes, and any other rule may still answer below.
                session.delete(grade)
                ai_grades.pop(finding.id, None)
                grade = None
                counts["rule_grades_dropped"] = counts.get("rule_grades_dropped", 0) + 1
            if grade is not None and (finding.id, "ai") not in bases:
                bases[(finding.id, "ai")] = learned.record_basis(session, finding, "ai")
            if grade is not None:
                if (not learned.protected(finding)
                        and learned.lower(finding.severity, grade.severity)):
                    finding.engine_severity = (finding.engine_severity
                                               or finding.severity.value)
                    finding.severity = grade.severity
            else:
                taught = learned.match(learned_rules, finding)
                if taught is not None:
                    rule_hits[taught.id] = rule_hits.get(taught.id, 0) + 1
                    # Kept as a grade, so retiring the rule can put this
                    # finding back straight away rather than on the next scan.
                    learned.give(session, finding, taught.severity, source="rule",
                                 reason="learned rule #%d: %s" % (taught.id, taught.reason),
                                 by="scan", rule_id=taught.id, model=taught.model)

            # A person's regrade stands for as long as the code it was about
            # does.  Rewritten flagged lines are a different question, and an
            # answer to the old one would hide it.
            if finding.custom_severity is not None and finding.id is not None:
                if learned.code_changed(bases, finding, "person"):
                    learned.lift(bases, finding, "person",
                                 finding.custom_severity.value,
                                 finding.custom_severity_reason,
                                 finding.custom_severity_by)
                    for name in ("custom_severity", "custom_severity_at"):
                        setattr(finding, name, None)
                    finding.custom_severity_reason = ""
                    finding.custom_severity_by = ""
                    counts["regrades_lifted"] = counts.get("regrades_lifted", 0) + 1
                elif (finding.id, "person") not in bases:
                    bases[(finding.id, "person")] = learned.record_basis(
                        session, finding, "person")

            # An administrator who regraded this one finding gets the last
            # word, after the engine and after any rule an admin wrote.  A
            # decision about one line survives the next scan finding it again,
            # which is the whole reason it is a column rather than a display.
            if finding.custom_severity is not None:
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = finding.custom_severity

            # The two halves of the grade, worked out last because impact
            # depends on what the repository holds and that is only known here.
            #
            # Deliberately after every override above rather than before: the
            # likelihood side reads the triage verdict, and the impact side
            # starts from whatever severity actually stands once an
            # administrator has had their say.  Reading a grade that was about
            # to be replaced would put a stale sentence on the finding.
            #
            # This never touches severity.  Where the pair disagrees with the
            # grade the recommendation says so on the page and waits for
            # somebody to accept it, the same as every other regrade.
            assessed = risk.assess(finding, _risk_context(repo, connection,
                                                          reach))
            finding.impact = assessed["impact"][:16]
            finding.likelihood = assessed["likelihood"][:16]
            finding.impact_reason = assessed["impact_reason"][:LONG_TEXT]
            finding.likelihood_reason = assessed["likelihood_reason"][:LONG_TEXT]
            finding.risk_score = assessed["score"]
            finding.risk_evidence = assessed["evidence"][:16]
            session.flush()

    def fill_credential(finding: Finding, row: dict) -> None:
        finding.severity = _sev(row.get("severity"))
        finding.rule = row.get("detector") or ""
        finding.title = row.get("description") or ""
        finding.secret_preview = row.get("secret_redacted") or ""
        # Already masked by the scanner.  Capped again here because a column
        # with no ceiling is a column somebody eventually fills.
        finding.snippet = (row.get("snippet") or "")[:2000]
        finding.verified = bool(row.get("verified"))
        # Which engines saw it.  A credential only semgrep saw lives or dies
        # with the code pass, and the resolve loop reads this to know that.
        engines = row.get("engines") or ([row["engine"]] if row.get("engine") else [])
        finding.engines = ", ".join(str(name) for name in engines)[:120]
        # The reason a credential could not be confirmed, kept this time rather
        # than dropped.  Capped because a verifier can return anything; the mask
        # upstream already keeps the secret itself out of it.
        finding.verification_error = (row.get("verification_error") or "")[:500]
        # Why `verified` reads the way it does.  A verifying engine (trufflehog)
        # that looked with verification on is the difference between "tried and
        # could not confirm" and "nothing ever checked this".  gitleaks, which
        # covers deep history, never verifies, so a history-only credential is
        # UNCHECKED and honest about it rather than a bare, misleading "no".
        verify_on = bool((document.get("scan") or {}).get(
            "live_verification_enabled"))
        checked = any("trufflehog" in str(name).lower() for name in engines)
        if finding.verified:
            finding.verification_status = CredentialVerification.VERIFIED
        elif checked and verify_on:
            finding.verification_status = CredentialVerification.ATTEMPTED
        else:
            finding.verification_status = CredentialVerification.UNCHECKED
        # Triage works this out from the value and the path, and it was being
        # dropped here, so every credential read as unrated.  Confirmed means
        # the provider said yes, which is as high as confidence goes.
        grade = str(row.get("confidence") or "").strip().lower()
        finding.confidence = "high" if grade == "confirmed" else (
            grade if grade in ("low", "medium", "high") else "")
        finding.exposure = row.get("exposure") or ""
        finding.author_name = row.get("author_name") or ""
        finding.author_email = row.get("author_email") or ""
        finding.author_login = row.get("author_login") or ""
        finding.committed_at = _when(row.get("committed_at"))

        # What the token said about itself, when the value was one.  The
        # scanner reads it while it still holds the value and sends on the
        # claim names only; nothing here can recover the token.
        if row.get("jwt"):
            finding.token_kind = "jwt"
            finding.token_alg = (row.get("jwt_alg") or "")[:32]
            finding.token_issuer = (row.get("jwt_issuer") or "")[:LONG_TEXT]
            finding.token_audience = (row.get("jwt_audience") or "")[:LONG_TEXT]
            finding.token_expires_at = _when(row.get("jwt_expires_at"))
            finding.token_issued_at = _when(row.get("jwt_issued_at"))
            expired = row.get("jwt_expired")
            finding.token_expired = None if expired is None else bool(expired)
            finding.token_claims = _names(row.get("jwt_claims"))[:LONG_TEXT]
            finding.token_identity_claims = _names(row.get("jwt_identity_claims"))[:500]
            finding.token_privilege_claims = _names(row.get("jwt_privilege_claims"))[:LONG_TEXT]
        else:
            # Said so explicitly rather than left blank, because "the detector
            # called this a token and it is not one" is the finding.
            finding.token_kind = ""
            finding.token_expired = None

    def _names(value) -> str:
        """A claim name list as text.  Names only; values never come here."""
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value if str(v).strip())
        return str(value or "")

    def _grade(value) -> str:
        """low / medium / high, or empty when the rule says nothing."""
        text = str(value or "").strip().lower()
        return text[:16] if text and text != "unknown" else ""

    def fill_code(finding: Finding, row: dict) -> None:
        finding.severity = _sev(row.get("severity"))
        # Take the engine at its word when it says it is unsure.
        #
        # A rule the engine itself grades low confidence, reporting something
        # it also grades low severity, is an observation rather than a problem.
        # Left at face value those dominate: on a real estate 86% of code
        # findings carry low confidence, and one such rule alone produced
        # 22,048 of them.  Graded to info they stay in the database, stay
        # searchable, and stop crowding out the findings somebody has to act
        # on this week.
        #
        # Only where both are low.  Low confidence about something serious is
        # still worth a person's time, which is the whole reason the engine
        # reports its own uncertainty rather than suppressing it.
        if (_grade(row.get("confidence")) == "low"
                and finding.severity in (Severity.LOW, Severity.INFO)):
            finding.severity = Severity.INFO
        # The line the engine matched, already masked by the scanner.
        #
        # Without it a code finding is an address and nothing else, and the
        # question people actually ask of one - is this string built from a
        # request or from a constant - can only be answered by cloning the
        # repository and opening the file.  The scanner has computed this on
        # every scan since there were code findings; only the credential path
        # was reading it, so 22,224 rows carried an empty column.
        #
        # Capped again here for the same reason it is capped there: a column
        # with no ceiling is a column somebody eventually fills.
        finding.snippet = (row.get("snippet") or "")[:2000]
        # Who last touched the line, from the blame pass.  The commit itself is
        # set in _apply_common, which every kind goes through.
        finding.author_name = row.get("author_name") or ""
        finding.author_email = row.get("author_email") or ""
        finding.author_login = row.get("author_login") or ""
        finding.committed_at = _when(row.get("committed_at"))
        # The engine's own view of how sure it is.  Kept so that eight hundred
        # audit grade findings can be triaged as a group rather than one
        # exception at a time.
        # The verdict from the fidelity pass, and why.  Kept so the work list
        # can be a work list without anything being thrown away.
        finding.triage = str(row.get("triage") or "")[:16]
        finding.triage_reason = str(row.get("triage_reason") or "")[:LONG_TEXT]
        engines = row.get("engines") or ([row["source"]] if row.get("source") else [])
        finding.engines = ", ".join(str(name) for name in engines)[:120]
        finding.corroborated = bool(row.get("corroborated"))
        finding.confidence = _grade(row.get("confidence"))
        # What the rule claims about itself, in the abstract.  The effective
        # pair is worked out below, once the repository this landed in is
        # known, because that is the half a rule cannot see.
        finding.engine_impact = _grade(row.get("impact"))
        finding.engine_likelihood = _grade(row.get("likelihood"))
        finding.rule = row.get("rule_name") or row.get("rule_id") or ""
        finding.title = (row.get("title") or "")[:2000]
        finding.description = (row.get("message") or "")[:4000]
        finding.cwe = ",".join(_as_list(row.get("cwe_ids")))[:255]
        finding.owasp = ";".join(_as_list(row.get("owasp")))[:255]

    def fill_misconfiguration(finding: Finding, row: dict) -> None:
        finding.severity = _sev(row.get("severity"))
        finding.rule = row.get("rule_id") or ""
        finding.title = (row.get("title") or "")[:2000]
        # The message says what is wrong with this one; the resolution says what
        # to do about it. Somebody reading the finding wants both.
        detail = row.get("message") or row.get("description") or ""
        fix = row.get("resolution") or ""
        if fix:
            detail = f"{detail}\n\nTo fix: {fix}".strip()
        finding.description = detail[:4000]
        finding.triage = str(row.get("triage") or "")[:16]
        finding.triage_reason = str(row.get("triage_reason") or "")[:LONG_TEXT]
        finding.confidence = _grade(row.get("confidence"))

    def fill_dependency(finding: Finding, row: dict) -> None:
        package = row.get("package") or {}
        finding.severity = _sev(row.get("severity"))
        finding.rule = row.get("id") or ""
        finding.title = (row.get("title") or "")[:2000]
        finding.package_name = package.get("name") or ""
        finding.package_version = package.get("version") or ""
        # Falls back to the package name, so the grouping key is never empty
        # and an ecosystem that has no separate source still groups by the
        # thing somebody would upgrade.
        finding.package_source = (package.get("source")
                                  or package.get("name") or "")[:255]
        finding.ecosystem = package.get("type") or ""
        # Which file asked for it.  Every engine that can say, says: grype
        # reports the manifest or lock file it read, osv-scanner reports
        # the manifest it resolved, and the provider alert feed reports the
        # manifest path on the alert.  A package scanned out of a container
        # image reports the image reference instead, and that is already kept
        # as image_ref, so it is not copied here where it would read as a path
        # somebody could open.
        declared = [str(where).strip() for where in _as_list(package.get("locations"))
                    if str(where).strip()]
        image = str(row.get("image") or "").strip()
        finding.manifest_path = next((where for where in declared
                                      if where != image), "")[:LONG_TEXT]
        finding.vulnerability_id = row.get("id") or ""
        finding.fixed_in = row.get("fixed_in") or ""
        finding.known_exploited = bool(row.get("known_exploited"))
        finding.base_upgraded = bool(row.get("base_upgraded"))
        finding.dockerfile = (row.get("dockerfile") or "")[:320]
        # The weakness class, which the code path has always kept and this one
        # dropped on the floor.  Every dependency finding in the database had
        # an empty cwe, and it read as "the advisories do not say", when what
        # was happening is that nobody here was looking.
        #
        # Three of the sources do say: the provider alert feed, the OSV
        # advisories, and the rule for a package that is itself the attack.
        # The two grype paths ask for a field grype does not publish, so those
        # stay empty, and that is the data being absent rather than lost.
        #
        # Spelled cwe here and cwe_ids in the code path because the two
        # engines spell it differently and both are read where they arrive.
        finding.cwe = ",".join(_as_list(row.get("cwe")))[:255]
        try:
            finding.cvss_score = float(row["cvss_score"]) if row.get("cvss_score") else None
        except (TypeError, ValueError):
            finding.cvss_score = None
        try:
            finding.epss_score = float(row["epss_score"]) if row.get("epss_score") else None
        except (TypeError, ValueError):
            finding.epss_score = None
        finding.image_ref = (row.get("image") or "")[:500]
        bad = row.get("malicious") or {}
        finding.malicious = bool(bad)
        finding.malicious_signal = (bad.get("signal") or "")[:32]
        finding.malicious_reason = (bad.get("reason") or "")[:LONG_TEXT]
        finding.malicious_evidence = (bad.get("evidence") or "")[:LONG_TEXT]
        # When the file that declares it last changed, and who by.
        #
        # A package has no line of code to blame, so this kind arrived with no
        # date at all and every report could only say when this tool first
        # noticed it.  The scanner now dates the manifest out of the clone,
        # which is a ceiling rather than an exact date: the package was being
        # asked for on or before the day that file was last edited.  Kept in the
        # same columns as every other kind's blame, because it answers the same
        # question a reader is asking, and the one it does not answer, which
        # line introduced it, has no answer for a package anywhere.
        declared = row.get("declared") or {}
        if declared.get("committed_at"):
            finding.committed_at = _when(declared.get("committed_at"))
            finding.author_name = (declared.get("author_name") or "")[:255]
            finding.author_email = (declared.get("author_email") or "")[:255]
            if declared.get("commit") and not finding.commit_sha:
                finding.commit_sha = str(declared["commit"])[:64]
        reach = row.get("reachability") or {}
        finding.reachability = (reach.get("verdict") or "")[:16]
        finding.reachability_reason = (reach.get("reason") or "")[:LONG_TEXT]
        finding.dependency_direct = (reach.get("direct") or "")[:16]
        finding.dependency_scope = (reach.get("scope") or "")[:16]

    upsert("credential", FindingKind.CREDENTIAL, document.get("secrets"),
           fill_credential)
    upsert("code", FindingKind.CODE, document.get("code_findings"), fill_code)
    upsert("misconfiguration", FindingKind.MISCONFIGURATION,
           document.get("misconfigurations"), fill_misconfiguration)
    upsert("dependency", FindingKind.DEPENDENCY, document.get("vulnerabilities"),
           fill_dependency)

    # Anything in a repo we just looked at that did not come back is fixed.
    # Only repos in this scan, so scanning one org never touches another.
    #
    # Unless the pass that would have found it did not finish.  A semgrep that
    # is killed part way through reports fewer findings, not a cleaner
    # repository, and closing those told people they had fixed something they
    # had not.  They came back on the next scan, which is how it was noticed.
    # Which repositories had their code pass cut short.  Read defensively on
    # purpose: this used to be built straight from row["repository"], and a
    # report that put the repository object there instead of its name raised
    # TypeError and took the whole ingest with it.  Every finding in that scan
    # was lost because one field had the wrong shape.  A field this small must
    # never be able to do that, and an app is upgraded before the scanners
    # feeding it are, so it has to read what an older one writes.
    partial_code = {}
    for row in (document.get("partial_code_repositories") or []):
        if not isinstance(row, dict):
            continue
        named = row.get("repository")
        if isinstance(named, dict):
            named = named.get("full_name")
        if not isinstance(named, str) or not named:
            log.warning("a partial-code entry did not name a repository, "
                        "so nothing is held open for it: %.120r", row)
            continue
        partial_code[named] = row.get("reason") or ""
    # Repositories whose CodeQL alerts could not be read from GitHub.  Only
    # findings CodeQL itself reported are held for these: semgrep still read
    # the code, and what it no longer reports really is gone.
    codeql_unread = set()
    for row in (document.get("codeql_unread_repositories") or []):
        named = row.get("repository") if isinstance(row, dict) else None
        if isinstance(named, str) and named:
            codeql_unread.add(named)
    # Before anything is closed, because the whole point of it is to keep a
    # value the scanner looked at out of the set that looks like it went away.
    counts["set_aside"] = _set_aside_placeholders(
        session, document, seen_at, seen_fingerprints)

    in_scope = scanned_repos if scanned_repos is not None else touched_repos
    withdrawn = set()
    if in_scope:
        stale = (session.query(Finding)
                 .filter(Finding.repository.in_(list(in_scope)))
                 .filter(Finding.state != FindingState.FIXED)
                 .all())
        for finding in stale:
            if finding.fingerprint in seen_fingerprints:
                continue
            # A credential somebody proved was live is not closed by silence.
            #
            # Every other guard here reasons about coverage: did the pass run,
            # did the walk finish, was this repository looked at.  Get any of
            # those wrong and a finding is closed that should not have been.
            # This one does not reason.  A verified credential was confirmed
            # live by asking the provider that issued it, which is the
            # strongest evidence this product ever holds about anything, and
            # the only thing that should retire it is equally positive
            # evidence: a run that looked and found it gone, or a person
            # deciding.
            #
            # It is the difference in consequence that earns the exception.  A
            # dependency finding closed by mistake is a number that is briefly
            # wrong.  A live credential closed by mistake is an all clear on a
            # working key, and the people who would have rotated it read the
            # all clear and do nothing.  Twenty of them went that way in one
            # night, four AWS tokens and two GitHub tokens among them, while
            # every coverage guard in this loop was working as designed and
            # simply had the wrong answer about coverage.
            #
            # So this sits above the coverage checks rather than beside them.
            # Being sure the pass ran is a good reason to close most things and
            # is not, on its own, a good enough reason to close this.
            # A file the credential pass is configured to skip was not read,
            # so its silence says nothing.
            #
            # This one hid behind looking intentional.  Every other gap in this
            # loop is a pass that broke or a walk that ran out of time, and
            # this is a list somebody wrote on purpose, which is why it went
            # unexamined for so long: of course the scanner skips recorded
            # traffic and build output, that is what the box is for.  It is
            # still an unread file.  The pass drops those candidates before
            # anything expensive touches them, reports nothing about them, and
            # the next ingest read that nothing as remediation.  Two private
            # keys confirmed live went out of a repository that way, inside a
            # `.zip`, and the list has `*.zip` on it.
            #
            # Above the verified check on purpose: this is not about how strong
            # the evidence for the finding was, it is that there is no evidence
            # either way this run.
            if (finding.kind == FindingKind.CREDENTIAL
                    and skipped_path(finding.file_path)):
                counts["held_open"] = counts.get("held_open", 0) + 1
                counts["skipped_held"] = counts.get("skipped_held", 0) + 1
                continue
            if (finding.kind == FindingKind.CREDENTIAL
                    and getattr(finding, "verified", False)):
                # Only a run that read everything may retire one, and it says
                # so out loud when it does.
                #
                # Refusing outright was the first instinct and it is wrong: a
                # credential that really was rotated would then stay open for
                # ever, and findings that cannot close become the noise people
                # learn to scroll past, which is how a real one gets missed.
                # The bar is raised instead of removed.  A full walk with the
                # credential pass finished genuinely looked everywhere this
                # product can look, and that is positive evidence.  Anything
                # less is not.
                fully_read = (not windowed_run
                              and finding.repository not in partial_history
                              and "secrets" in (passes_done.get(
                                  finding.repository) or {"secrets"}))
                if not fully_read:
                    counts["held_open"] = counts.get("held_open", 0) + 1
                    counts["verified_held"] = counts.get("verified_held", 0) + 1
                    continue
                # Closing anyway, and never quietly.  Twenty of these were
                # retired in one night by runs that had not looked, and the
                # only reason anybody found out is that somebody read a
                # dashboard and disbelieved it.  One line each, by name, so
                # the next time it is in the log before it is on a screen.
                log.warning("a credential that was verified live is being "
                            "closed: %s in %s, rule %s, last seen %s",
                            finding.vuln_id or finding.fingerprint,
                            finding.repository, finding.rule or "?",
                            finding.last_found_at)
            # The pass that would have found this one has to have finished.
            #
            # Absence from a report only means "fixed" if somebody looked.  A
            # pass that did not run, or ran and was cut off, reports nothing,
            # which on the way in is indistinguishable from a repository that
            # was cleaned up.  Two kinds were already guarded here by hand and
            # the other two were not, so a run whose dependency pass produced
            # nothing closed every dependency finding in the repository: 81 in
            # one repository in one second, and 329 in a night across an
            # estate.  Reading the scanner's own account of which passes
            # finished covers all four kinds by the same rule.
            #
            # A pass switched off in the settings never reports itself
            # finished, so its findings stay as they are.  That is the
            # intended reading.  Turning a pass off is not evidence that
            # anything was remediated.
            done = passes_done.get(finding.repository)
            if done is not None:
                need = KIND_PASS.get(finding.kind)
                if need is not None and need not in done:
                    counts["held_open"] = counts.get("held_open", 0) + 1
                    continue
            if (finding.kind == FindingKind.CODE
                    and finding.repository in partial_code):
                counts["held_open"] = counts.get("held_open", 0) + 1
                continue
            # The rule that found it was not in this run's semgrep packs.
            #
            # The packs come from semgrep's registry on every scan, and a rule
            # withdrawn there stops reporting everything it found, with nothing
            # changed in the code.  The JWT rule left p/secrets on 2026-10-04
            # and its findings began closing as fixed while the tokens were
            # still in the files.  Nothing looked, so nothing is closed.
            seen_by_engines = {e.strip().lower() for e in
                               str(finding.engines or "").split(",") if e.strip()}
            loaded = rules_loaded.get(finding.repository)
            if (loaded and seen_by_engines == {"semgrep"}
                    and finding.kind in (FindingKind.CODE, FindingKind.CREDENTIAL)
                    and (finding.rule or "") not in loaded):
                counts["held_open"] = counts.get("held_open", 0) + 1
                counts["rule_withdrawn_held"] = counts.get("rule_withdrawn_held", 0) + 1
                withdrawn.add(finding.rule or "?")
                continue
            # A credential only semgrep saw comes from the code pass, so it is
            # silent whenever semgrep did not finish, whatever the credential
            # pass did.
            seen_by = {e.strip().lower() for e in str(finding.engines or "").split(",") if e.strip()}
            if (finding.kind == FindingKind.CREDENTIAL and seen_by == {"semgrep"}):
                done = passes_done.get(finding.repository)
                if (finding.repository in partial_code
                        or (done is not None and "code" not in done)):
                    counts["held_open"] = counts.get("held_open", 0) + 1
                    continue
            # CodeQL alerts nobody could fetch this time.  Either the code
            # finding they became, or one still filed the old way as a
            # dependency with no package, which only CodeQL ever produced.
            from_codeql = "codeql" in str(finding.engines or "").lower()
            legacy_codeql = (finding.kind == FindingKind.DEPENDENCY
                             and (finding.ecosystem or "") == "source")
            if (from_codeql or legacy_codeql) and \
                    finding.repository in codeql_unread:
                counts["held_open"] = counts.get("held_open", 0) + 1
                continue
            # The old dependency rows are retired by the code pass now, so they
            # wait for it rather than for the vulnerability pass, which no
            # longer reads CodeQL at all and would otherwise close every one.
            if legacy_codeql:
                done = passes_done.get(finding.repository)
                if (finding.repository in partial_code
                        or (done is not None and "code" not in done)):
                    counts["held_open"] = counts.get("held_open", 0) + 1
                    continue
            # The same argument for credentials.  With a history window a run
            # walks one slice and reports that slice, so a credential sitting
            # in a commit nobody read this time is absent from the report and
            # looks exactly like one that was cleaned up.  Closing it and
            # opening it again on the run that reaches that slice is a finding
            # that flaps, and a graph that cannot be read.
            if (finding.kind == FindingKind.CREDENTIAL
                    and finding.repository in partial_history):
                counts["held_open"] = counts.get("held_open", 0) + 1
                continue
            finding.state = FindingState.FIXED
            finding.resolved_at = seen_at
            counts["resolved"] += 1
    if withdrawn:
        log.warning("semgrep did not load %d rule(s) that earlier findings came "
                    "from, so %d finding(s) are held open rather than counted as "
                    "fixed: %s", len(withdrawn), counts.get("rule_withdrawn_held", 0),
                    ", ".join(sorted(withdrawn))[:500])
    if partial_code or partial_history:
        log.warning(
            "incomplete coverage: code pass on %d repository(ies), credential "
            "history on %d; %d finding(s) held open rather than counted as "
            "fixed",
            len(partial_code), len(partial_history), counts.get("held_open", 0))

    # Who can reach what.  The scanner has always collected this and it was
    # always thrown away here, which meant every scan worked out the blast
    # radius and then forgot it.
    try:
        from app.core import access as access_store
        counts["access"] = access_store.record_access(session, document, connection)
    except Exception:
        log.exception("could not record access, carrying on with the findings")
        counts["access"] = 0

    # Anything on branches that do not ship gets flagged the same way.  New
    # findings arrive unflagged, and a finding that moved onto a branch that
    # ships has to come back.
    try:
        from app.core import scan_scope
        with session.begin_nested():
            counts["scope_changed"] = scan_scope.refresh(session, touched_repos)
    except Exception:
        log.exception("could not apply the scan scope, carrying on")
        counts["scope_changed"] = 0

    # Anything an exclusion covers gets flagged now, so it never reaches the
    # report files in the first place.
    counts["excepted"] = apply_exceptions(session)
    counts["repositories"] = len(touched_repos)
    session.flush()
    # Anything an exception already covers is not news.  Filtered after
    # apply_exceptions so a finding that arrives already waived never becomes
    # a message somebody has to read and dismiss.  Nor is one only on branches
    # that do not ship: the scope refresh above has flagged it already.
    counts["new_findings"] = [f for f in new_findings
                              if not f.excepted and not f.out_of_scope]

    # Branches a completed scan found nothing to read on, signed off without
    # anybody having to click.  Last, because every rule it applies is about
    # what is in the database now: the findings from this report have landed,
    # what an exclusion covers has been marked, and what was really fixed has
    # been closed.
    #
    # Only repositories this run covered end to end are offered.  A pass that
    # did not finish reports nothing and nothing is what a clear branch looks
    # like, so a dead engine would otherwise hand out green badges, which is
    # the exact shape of every finding this file has ever lost.  A repository
    # whose worker died, whose code pass was cut short, or whose credential
    # walk only covered a window is not offered at all.
    #
    # Wrapped for the same reason the trend point below is.  A badge is not
    # worth throwing a scan away for, and the savepoint keeps a failure here
    # from taking down whatever the caller does next.
    try:
        from app.core import certification

        complete = set()
        for full_name in touched_repos:
            if (full_name in failed_repos or full_name in partial_code
                    or full_name in partial_history):
                continue
            done = passes_done.get(full_name)
            # A scanner too old to say which passes finished is not read as
            # having finished them.  Everywhere else that reading protects an
            # upgrade from freezing an estate; here it would be the difference
            # between a badge somebody can rely on and one nobody can.
            if not done or not set(certification.AUTOMATIC_PASSES) <= done:
                continue
            complete.add(full_name)
        with session.begin_nested():
            counts["auto_certified"] = certification.auto_certify(
                session, complete)
    except Exception:
        log.exception("could not certify the clear branches, carrying on")
        counts["auto_certified"] = {}

    # Today's point on the trend, written after everything else has landed so
    # it describes the state a scan left rather than the state halfway through
    # one.  Re-running a scan on the same day replaces the day rather than
    # adding to it.
    #
    # Wrapped, because a chart is not worth failing an ingest for.  A missing
    # trend row is a gap somebody notices later; a failed ingest is a scan
    # thrown away.
    #
    # Inside a savepoint, and that part is not optional.  Catching the
    # exception is not enough on its own: a failed flush leaves the session
    # in a state where every later statement on it fails too, so a swallowed
    # error here quietly takes down whatever the caller does next.  It did
    # exactly that the first time, and the thing it took down was the
    # software inventory being salvaged from an interrupted scan, which is a
    # much more expensive thing to lose than a point on a graph.
    try:
        from app.core import trends
        with session.begin_nested():
            trends.record(session)
    except Exception:
        log.exception("could not write the trend point, carrying on")

    # How often each learned rule answered, so the rules page shows which are
    # earning their keep and which never fire.
    if rule_hits:
        from app.core.models import LearnedRule
        for rule in session.query(LearnedRule).filter(LearnedRule.id.in_(list(rule_hits))):
            rule.hits = (rule.hits or 0) + rule_hits[rule.id]
            rule.last_hit_at = seen_at
        counts["learned_rule_hits"] = sum(rule_hits.values())

    return counts


def apply_exceptions(session, findings=None) -> int:
    """Set the exception flag on anything an exclusion covers.

    The scanner filters what it can on its own, using the CSV we hand it, but
    it cannot match on vuln_id: that id comes from our fingerprint, which is
    worked out here.  So exclusions written against one particular finding get
    applied on this side, after the findings are in.

    Returns how many it changed.
    """
    import fnmatch

    from app.core.exclusions import active_rules

    rules = active_rules(session)
    if not rules:
        return 0

    by_id = {}
    for rule in rules:
        if rule.vuln_id:
            by_id.setdefault(rule.vuln_id.strip().upper(), rule)

    rows = findings if findings is not None else (
        session.query(Finding).filter(Finding.excepted.is_(False)).all())

    def matches(rule, finding) -> bool:
        kind = _exception_kind(finding)
        if rule.kind not in ("any", kind):
            return False
        for pattern, value in ((rule.organization, finding.organization or ""),
                               (rule.repository, finding.repository or ""),
                               (rule.path, finding.file_path or ""),
                               (rule.rule, finding.rule or "")):
            pattern = pattern or "*"
            if pattern == "*":
                continue
            target = value
            if pattern is rule.repository and "/" not in pattern:
                target = value.split("/")[-1]
            if not fnmatch.fnmatch(target.lower(), pattern.lower()):
                return False
        if rule.fingerprint:
            return rule.fingerprint == finding.fingerprint
        return True

    changed = 0
    for finding in rows:
        if finding.excepted:
            continue
        rule = by_id.get((finding.vuln_id or "").upper())
        if rule is None:
            rule = next((r for r in rules if not r.vuln_id and matches(r, finding)),
                        None)
        if rule is None:
            continue
        finding.excepted = True
        finding.exception_reason = rule.reason or ""
        finding.exception_by = rule.reviewed_by or ""
        finding.exception_at = utcnow()
        finding.exception_expires_at = rule.expires_at
        changed += 1
    return changed


def _exception_kind(finding) -> str:
    value = getattr(finding.kind, "value", str(finding.kind or "")).lower()
    if "cred" in value:
        return "secret"
    if "code" in value:
        return "code"
    return "vuln"


# --- the software inventory -------------------------------------------------
#
# Separate from the findings above on purpose.  A finding exists because
# somebody published an advisory.  A component exists because it is in the
# tree.  Keeping both is what lets the Software page answer "is this version
# anywhere" for a package that has no advisory yet, which is every compromised
# release for the first few days.

# How a purl spells each ecosystem, against the many spellings the engines use.
# The purl type is the one that wins, because it is the identifier anything
# outside this will quote at us.
PURL_TYPE = {
    "npm": "npm", "node": "npm", "nodejs": "npm",
    "pypi": "pypi", "python": "pypi", "pip": "pypi",
    "maven": "maven", "java-archive": "maven", "jenkins-plugin": "maven",
    "nuget": "nuget", "dotnet": "nuget",
    "golang": "golang", "go": "golang", "go-module": "golang",
    "gem": "gem", "rubygems": "gem",
    "composer": "composer", "php-composer": "composer",
    "cargo": "cargo", "rust-crate": "cargo",
    "deb": "deb", "rpm": "rpm", "apk": "apk",
    "github": "github", "github-action": "github",
    "conan": "conan", "cocoapods": "cocoapods", "swift": "swift",
    "hex": "hex", "pub": "pub", "cran": "cran", "hackage": "hackage",
}

# Components that are not software somebody chose.  syft catalogs plain files
# when it is asked to, and a page listing forty thousand of those is a page
# nobody can find a package in.
SKIP_COMPONENT_KINDS = {"file", "operating-system"}

# A ceiling per repository.  One repository with a vendored world in it should
# not be able to fill the table on its own.
MAX_COMPONENTS_PER_PLACE = 20000


def _ecosystem_of(purl: str, fallback: str = "") -> str:
    """The purl type, which is the one spelling worth keeping."""
    text = (purl or "").strip()
    if text.startswith("pkg:") and "/" in text:
        kind = text[4:].split("/", 1)[0].split("@", 1)[0]
        if kind:
            return PURL_TYPE.get(kind.lower(), kind.lower())
    return PURL_TYPE.get((fallback or "").strip().lower(),
                         (fallback or "").strip().lower())


def _component_rows(document: dict) -> dict:
    """-> {(repository, branch): [component, ...]}, from the SBOM bundle.

    The default branch comes from the repository's own SBOM; the rest come
    from sbom_by_branch, which a scan only fills in when it was told to walk
    every branch.
    """
    places = {}

    def take(repository, branch, sbom):
        if not repository or not isinstance(sbom, dict):
            return
        rows = sbom.get("components")
        if not isinstance(rows, list) or not rows:
            return
        places[(repository, branch or "")] = rows[:MAX_COMPONENTS_PER_PLACE]

    for entry in document.get("repositories", []) or []:
        if not isinstance(entry, dict):
            continue
        repository = entry.get("repository") or ""
        default_branch = entry.get("default_branch") or ""
        take(repository, default_branch, entry.get("sbom") or {})
        for extra in entry.get("sbom_by_branch") or []:
            if isinstance(extra, dict):
                take(repository, extra.get("branch") or "",
                     extra.get("sbom") or {})
    return places


def ingest_components(session, bundle_path, connection=None) -> dict:
    """Replace the software inventory for every repository in this bundle.

    Replace rather than merge.  A component that is no longer in the tree is
    not "last seen a while ago", it is gone, and a list that keeps it is a list
    that sends somebody to upgrade a package that was removed months back.
    Only the repositories the bundle covers are touched, so a scan of one
    organization leaves another organization's inventory alone.
    """
    from sqlalchemy import and_ as sa_and

    from app.core.models import Component

    path = Path(bundle_path)
    counts = {"repositories": 0, "branches": 0, "components": 0}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.info("no SBOM bundle to read, so the software inventory is "
                 "unchanged: %s", exc)
        return counts
    if not isinstance(document, dict):
        return counts

    places = _component_rows(document)
    if not places:
        return counts

    seen_at = utcnow()
    label = getattr(connection, "name", "") or ""

    # When it was first seen, kept across the replace.  Losing it would make
    # every package look like it arrived with the last scan.
    known = {}
    for repository, branch in places:
        rows = (session.query(Component.purl_key, Component.first_seen_at)
                .filter(sa_and(Component.repository == repository,
                               Component.branch == branch)).all())
        for key, when in rows:
            known[(repository, branch, key)] = when

    for (repository, branch), components in places.items():
        organization = repository.split("/", 1)[0] if "/" in repository else ""
        session.query(Component).filter(
            sa_and(Component.repository == repository,
                   Component.branch == branch)).delete(synchronize_session=False)

        fresh = {}
        for row in components:
            if not isinstance(row, dict):
                continue
            kind = str(row.get("type") or "library").strip().lower()
            if kind in SKIP_COMPONENT_KINDS:
                continue
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            version = str(row.get("version") or "").strip()
            purl = str(row.get("purl") or "").strip()
            group = str(row.get("group") or "").strip()
            if group and not purl and not name.startswith(group):
                name = f"{group}:{name}"
            if not purl:
                # No purl means syft could not name it in the one vocabulary
                # everything else uses.  Build the closest thing, so the row
                # still has a stable identity across scans.
                eco = _ecosystem_of("", row.get("ecosystem") or "")
                purl = f"pkg:{eco or 'generic'}/{name}" + (f"@{version}" if version else "")
            key = hashlib.sha256(purl.encode("utf-8", "replace")).hexdigest()[:64]
            if key in fresh:
                continue

            licenses = row.get("licenses")
            if isinstance(licenses, list):
                spelled = ", ".join(sorted({str(one).strip() for one in licenses
                                            if str(one).strip()}))
            else:
                spelled = str(licenses or "").strip()

            fresh[key] = Component(
                organization=organization, repository=repository,
                branch=branch, connection=label,
                name=name[:512], version=version[:128],
                ecosystem=_ecosystem_of(purl, row.get("ecosystem") or "")[:64],
                purl=purl[:1024], purl_key=key, kind=kind[:32],
                licenses=spelled[:500],
                cpe=str(row.get("cpe") or "")[:500],
                first_seen_at=known.get((repository, branch, key)) or seen_at,
                last_seen_at=seen_at)

        session.add_all(fresh.values())
        counts["branches"] += 1
        counts["components"] += len(fresh)

    counts["repositories"] = len({repository for repository, _ in places})
    session.flush()
    log.info("software inventory: %d component(s) across %d branch(es) in "
             "%d repositor(y/ies)", counts["components"], counts["branches"],
             counts["repositories"])
    return counts
