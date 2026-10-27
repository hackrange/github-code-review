"""Keeping what a scan already found when it does not get to the end.

A scan writes one file per repository as it finishes that repository, and only
assembles them into a report at the very end.  So a run that is interrupted has
done all of the work and recorded none of it: the clones were made, every
engine ran, and the whole lot goes away because the last step never started.

That is not theoretical.  A deploy recreated the container ninety minutes into
a scan of an organization and the run recorded nothing at all: no
repositories, no findings, no log.

This reads those per repository files and builds the same document the
scanner's own report builder would have, from however many of them exist.  A
scan interrupted at repository forty keeps thirty nine.

Two rules it will not break:

  A partial run is never called finished.  What it did not reach must not be
  counted as fixed, which is the same rule the incomplete code pass already
  follows, and the reason `scanned_repos` is passed rather than inferred.

  A file that is half written is skipped, not guessed at.  The scanner writes
  each one in a single shot, but a process killed mid write can still leave a
  truncated file, and a partial JSON object is not something to interpret.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("gcr.salvage")

# The same flattening the scanner's report builder does, and it has to stay the
# same: these are the keys ingest reads.
LISTS = {
    "vulnerabilities": lambda entry: entry.get("vulnerabilities") or [],
    "code_findings": lambda entry: entry.get("code_findings") or [],
    "misconfigurations": lambda entry: entry.get("misconfigurations") or [],
    "secrets": lambda entry: ((entry.get("secrets") or {}).get("reported")
                              if isinstance(entry.get("secrets"), dict)
                              else entry.get("secrets")) or [],
}


def read_entries(results_dir) -> list:
    """Every repository result that is on disk and readable."""
    directory = Path(results_dir)
    if not directory.is_dir():
        return []

    entries = []
    for path in sorted(directory.glob("*.json")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("could not read %s: %s", path.name, exc)
            continue
        if not text.strip():
            continue
        try:
            entry = json.loads(text)
        except ValueError:
            # Killed mid write.  One unreadable repository is not a reason to
            # lose the other thirty nine.
            log.warning("%s is not complete JSON, so it is left out", path.name)
            continue
        if isinstance(entry, dict) and entry.get("repository"):
            entries.append(entry)
    return entries


def build_document(entries: list) -> dict:
    """The report shape, from however many repositories finished."""
    document = {
        "schema_version": "1.0",
        "generated_at": None,
        "partial": True,
        "repositories": [],
        "partial_code_repositories": [],
        "codeql_unread_repositories": [],
        "placeholders_filtered": [],
        "allowlist_suppressed": [],
    }
    for key in LISTS:
        document[key] = []

    for entry in entries:
        document["repositories"].append(entry)
        for key, take in LISTS.items():
            rows = take(entry)
            if isinstance(rows, list):
                document[key].extend(rows)
        # What the scanner read and ruled out, as report.sh collects it.
        #
        # Ingest keeps a credential set aside on this evidence and closes one
        # it cannot find.  Left out here, every set aside credential in a
        # salvaged repository read as gone: fifty six were closed as fixed on
        # one interrupted run and came back on the next scan.
        block = entry.get("secrets")
        if isinstance(block, dict):
            for key, name in (("placeholders_filtered", "filtered"),
                              ("allowlist_suppressed", "suppressed")):
                rows = block.get(name)
                if isinstance(rows, list):
                    document[key].extend(rows)

        # The same guard the full report writes: a repository whose code pass
        # was cut short must not have its old code findings counted as fixed.
        if entry.get("code_complete") is False:
            meta = entry.get("repository") or {}
            named = meta.get("full_name") if isinstance(meta, dict) else None
            if named:
                document["partial_code_repositories"].append({
                    "repository": named,
                    "reason": (entry.get("code_incomplete_reason")
                               or "the code pass did not complete"),
                })
        # And the same for CodeQL on its own.  Left out, an interrupted scan
        # would read every CodeQL alert it never fetched as fixed.
        if entry.get("codeql_unread_reason"):
            meta = entry.get("repository") or {}
            named = meta.get("full_name") if isinstance(meta, dict) else None
            if named:
                document["codeql_unread_repositories"].append({
                    "repository": named,
                    "reason": entry["codeql_unread_reason"]})
    return document


def scanned_names(entries: list) -> set:
    """Which repositories this run actually finished.

    Everything downstream keys resolution off this.  A repository the scan
    never got to must not have its findings closed, and passing the set rather
    than letting ingest infer it is what makes that true.

    Finished, not merely present.  The scanner writes a result file after each
    expensive pass so a repository killed later still reports the work it did,
    and a worker that timed out gets a stub so it does not vanish from the
    report.  Both of those are entries.  Neither is a repository that was read.
    Counting them here told the ingest that a half scanned repository had been
    fully examined, so everything the half it never reached would have reported
    was absent, and absent is closed: one stopped run retired one thousand
    seven hundred and forty four findings that way, most of them critical.

    The run's normal path has always excluded them, with a comment saying that
    calling them fixed would be the scanner inventing good news.  This is the
    same rule, on the path that runs when a scan does not get to the end, which
    is exactly when it matters most.
    """
    out = set()
    for entry in entries:
        meta = entry.get("repository") or {}
        if not isinstance(meta, dict) or not meta.get("full_name"):
            continue
        if str(entry.get("status", "ok")) != "ok":
            continue
        out.add(meta["full_name"])
    return out


def sbom_bundle(entries: list) -> dict:
    """The SBOM bundle shape, from however many repositories finished.

    The same document the scanner writes beside its report, built here from
    the per repository files, because the bundle itself is assembled in the
    last step and an interrupted run never gets there.
    """
    repositories = []
    for entry in entries:
        meta = entry.get("repository") or {}
        full_name = meta.get("full_name") if isinstance(meta, dict) else None
        if not full_name or not isinstance(entry.get("sbom"), dict):
            continue
        repositories.append({
            "repository": full_name,
            "default_branch": meta.get("default_branch") or "",
            "sbom": entry.get("sbom"),
            "sbom_by_branch": entry.get("sbom_by_branch") or [],
        })
    return {"schema_version": "1.0", "partial": True,
            "repositories": repositories}


def salvage(session, results_dir) -> dict:
    """Ingest whatever finished.  -> what was kept, or why nothing was.

    Safe to call on a run that completed normally: there is nothing to add,
    because the same findings are already in by then and they key the same way.
    """
    from app.core.ingest import ingest_components, ingest_report

    entries = read_entries(results_dir)
    if not entries:
        return {"repositories": 0, "reason": "nothing had finished"}

    document = build_document(entries)
    reached = scanned_names(entries)

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "partial.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        counts = ingest_report(session, path, scanned_repos=reached)

        # The software inventory for the repositories that did finish.  Each
        # per repository file holds its own SBOM, so an interrupted scan can
        # still say what it saw, the same way it keeps the findings.  Only the
        # repositories in this bundle are touched, so the ones the scan never
        # reached keep the inventory they had.
        bundle = Path(tmp) / "partial-sbom.json"
        bundle.write_text(json.dumps(sbom_bundle(entries)), encoding="utf-8")
        try:
            counts["components"] = ingest_components(session, bundle)["components"]
        except Exception:            # noqa: BLE001 - never mask the salvage
            log.warning("could not keep the software inventory from the "
                        "interrupted scan", exc_info=True)

    new_ids = [f.id for f in counts.pop("new_findings", None) or []]
    counts["repositories"] = len(entries)
    log.warning("salvaged %d repository(ies) from an interrupted scan: %s",
                len(entries), counts)
    # For the automatic review, which the caller starts once these commit.
    counts["new_finding_ids"] = new_ids
    return counts
