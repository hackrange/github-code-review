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
from datetime import datetime, timezone
from pathlib import Path

from app.core.models import (
    Finding, FindingKind, FindingState, Repository, Severity, utcnow, vuln_id_for,
)

log = logging.getLogger("gcr.ingest")

# How many branch names to keep per repository.  A repository that has collected
# more than this has a housekeeping problem rather than a list worth reading,
# and the names are kept to offer a choice, not to be an inventory.
MAX_BRANCH_NAMES = 2000


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

    cache = {}
    counts = {"new": 0, "updated": 0, "resolved": 0, "repositories": 0}
    new_findings = []
    touched_repos = set()
    seen_fingerprints = set()
    # Repositories where the credential walk stopped short this run.  A run
    # that only covered part of the history reports only what it covered, and
    # the rest is not gone, it is unread.
    partial_history = set()

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
        dast = entry.get("dast")
        if isinstance(dast, dict) and dast.get("verdict"):
            repo.dast_verdict = str(dast.get("verdict"))[:16]
            repo.dast_reason = str(dast.get("reason") or "")[:500]
        repo.visibility = meta.get("visibility") or repo.visibility
        repo.default_branch = meta.get("default_branch") or repo.default_branch
        repo.archived = bool(meta.get("archived", repo.archived))
        repo.size_kb = int(meta.get("size_kb") or repo.size_kb or 0)
        repo.html_url = meta.get("html_url") or repo.html_url
        repo.last_scanned_at = seen_at
        # What the scan actually walked.  Kept so the branch box on a
        # connection can offer real names, and so there is still a record of
        # the coverage once the report itself has gone.  Capped because one
        # repository with tens of thousands of refs should not write a blob
        # nobody will read to the end of.
        scanned = [str(name).strip()
                   for name in (entry.get("branches_scanned") or [])
                   if str(name).strip()]
        if scanned:
            repo.branch_names = json.dumps(sorted(set(scanned))[:MAX_BRANCH_NAMES])

        # How far the credential engines walked here.  Only ever moved by a
        # run that actually walked something: a repository skipped this time
        # keeps the ground the last one covered.
        history = entry.get("history") or {}
        walked_from = str(history.get("walked_from") or "").strip()
        if walked_from:
            repo.history_from = walked_from[:32]
            repo.history_complete = bool(history.get("complete"))
        # Defaults to complete on purpose.  A scanner too old to say, or a run
        # with the credential pass switched off, reports no history at all, and
        # must go on behaving exactly as it did before this existed.
        if history and not history.get("complete", True):
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
                # stays waived.
                if finding.state == FindingState.FIXED:
                    finding.state = FindingState.OPEN
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
            if (finding.triage == "not_applicable"
                    and finding.severity != Severity.INFO):
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = Severity.INFO

            override = severity_rules.apply(
                overrides, finding.rule, finding.cwe,
                getattr(connection, "sensitivity", "") if connection is not None else "")
            if override is not None and override != finding.severity:
                finding.engine_severity = (finding.engine_severity
                                           or finding.severity.value)
                finding.severity = override

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
        finding.verified = bool(row.get("verified"))
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
        finding.vulnerability_id = row.get("id") or ""
        finding.fixed_in = row.get("fixed_in") or ""
        finding.known_exploited = bool(row.get("known_exploited"))
        finding.base_upgraded = bool(row.get("base_upgraded"))
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
    in_scope = scanned_repos if scanned_repos is not None else touched_repos
    if in_scope:
        stale = (session.query(Finding)
                 .filter(Finding.repository.in_(list(in_scope)))
                 .filter(Finding.state != FindingState.FIXED)
                 .all())
        for finding in stale:
            if finding.fingerprint in seen_fingerprints:
                continue
            if (finding.kind == FindingKind.CODE
                    and finding.repository in partial_code):
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

    # Anything an exclusion covers gets flagged now, so it never reaches the
    # report files in the first place.
    counts["excepted"] = apply_exceptions(session)
    counts["repositories"] = len(touched_repos)
    session.flush()
    # Anything an exception already covers is not news.  Filtered after
    # apply_exceptions so a finding that arrives already waived never becomes
    # a message somebody has to read and dismiss.
    counts["new_findings"] = [f for f in new_findings if not f.excepted]

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
