#!/usr/bin/env python3
"""GitHub's CodeQL alerts, as code findings like any other engine's.

They used to come in as dependency findings with no package.  That cost three
things: every alert of one rule collapsed into a single finding, because a
dependency is keyed on package and version and these have neither; none of
them went through code triage; and none carried a CWE or a confidence.

This reads the alerts, the SARIF GitHub keeps for the analysis that produced
them, and the clone, and writes the same rows normalize_semgrep writes.  The
SARIF is where CodeQL's own precision lives, and where the start of each data
flow is, which the alerts feed leaves out.

    codeql.py alerts.json sarif_dir repo_root repository branch web muted link_json
"""

from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import code_blame  # noqa: E402
import code_triage  # noqa: E402

SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "error": "high", "warning": "medium",
            "note": "low", "none": "info"}
PRECISION = {"very-high": "high", "high": "high", "medium": "medium",
             "low": "low"}
CWE_TAG = re.compile(r"external/cwe/cwe-0*(\d+)$", re.I)
TOKENISH = re.compile(r"(?P<t>[A-Za-z0-9_+=-]{20,})")

# GitHub's own reading of the file.  It hides these from its alert list by
# default, so reporting them here would be louder than the tool that found them.
CLASSIFIED = {"test": "test code", "generated": "generated code",
              "library": "library code"}


def _sarif_facts(sarif_dir: str) -> tuple:
    """-> ({rule: precision}, {(rule, path, line): {"path", "line"}})."""
    precision, sources = {}, {}
    if not sarif_dir or not os.path.isdir(sarif_dir):
        return precision, sources
    for name in sorted(os.listdir(sarif_dir)):
        try:
            with open(os.path.join(sarif_dir, name)) as handle:
                doc = json.load(handle)
        except (OSError, ValueError):
            continue
        for run in doc.get("runs") or []:
            tool = run.get("tool") or {}
            rules = list((tool.get("driver") or {}).get("rules") or [])
            for ext in tool.get("extensions") or []:
                rules.extend(ext.get("rules") or [])
            for rule in rules:
                value = str((rule.get("properties") or {}).get("precision") or "")
                if rule.get("id") and value:
                    precision[rule["id"]] = value.lower()
            for result in run.get("results") or []:
                try:
                    where = result["locations"][0]["physicalLocation"]
                    key = (result.get("ruleId"), where["artifactLocation"]["uri"],
                           int(where["region"]["startLine"]))
                except (KeyError, IndexError, TypeError, ValueError):
                    continue
                for flow in result.get("codeFlows") or []:
                    steps = ((flow.get("threadFlows") or [{}])[0]).get("locations") or []
                    if not steps:
                        continue
                    # Every step, not only where it starts: the check that
                    # makes a flow safe is often in the middle of it, in a
                    # file the alert never names.
                    walked = []
                    for step in steps:
                        where = (step.get("location") or {}).get("physicalLocation") or {}
                        try:
                            walked.append({"path": where["artifactLocation"]["uri"],
                                           "line": int(where["region"]["startLine"])})
                        except (KeyError, TypeError, ValueError):
                            continue
                    if walked:
                        sources[key] = dict(walked[0], steps=walked)
                    break
    return precision, sources


def _cwes(tags) -> list:
    out = []
    for tag in tags or []:
        found = CWE_TAG.search(str(tag))
        if found:
            out.append("CWE-%d" % int(found.group(1)))
    return sorted(set(out), key=lambda c: int(c.split("-")[1]))


def convert(alerts: list, sarif_dir: str, repo_root: str, repository: str,
            branch: str, web: str, muted=(), link=None) -> list:
    link = link or {"blob": "blob", "line": "#L", "commit": "commit"}
    precision, sources = _sarif_facts(sarif_dir)

    # Semgrep's shape, so triage and blame read these exactly as they read
    # every other finding.  Columns are one based and the end is exclusive in
    # both, so they carry straight across.
    shaped = []
    for alert in alerts or []:
        rule = alert.get("rule") or {}
        instance = alert.get("most_recent_instance") or {}
        where = instance.get("location") or {}
        path = str(where.get("path") or "")
        start = int(where.get("start_line") or 0)
        if not path or start <= 0 or (alert.get("state") or "open") != "open":
            continue
        shaped.append({
            "check_id": str(rule.get("id") or "unknown"),
            "path": path,
            "start": {"line": start, "col": int(where.get("start_column") or 0)},
            "end": {"line": int(where.get("end_line") or start),
                    "col": int(where.get("end_column") or 0)},
            "flow_source": sources.get((rule.get("id"), path, start)),
            "_alert": alert,
        })

    shaped = code_triage.triage(shaped, repo_root, muted)
    shaped = code_blame.blame(shaped, repo_root)

    rows = []
    for item in shaped:
        alert = item.pop("_alert")
        rule = alert.get("rule") or {}
        instance = alert.get("most_recent_instance") or {}
        verdict = item.get("triage") or {}
        rule_id = item["check_id"]
        path, start = item["path"], item["start"]["line"]

        grade = SEVERITY.get(str(rule.get("security_severity_level")
                                 or rule.get("severity") or "").lower(), "medium")
        confidence = PRECISION.get(precision.get(rule_id, ""), "unknown")
        # The same bargain semgrep findings get: a rule that is unsure has not
        # earned critical.
        if grade == "critical" and confidence in ("low", "medium"):
            grade = "high"
        if (verdict.get("demote") or {}).get("severity"):
            grade = verdict["demote"]["severity"]

        triage_verdict = verdict.get("verdict") or "review"
        triage_reason = verdict.get("reason") or ""
        triage_rule = verdict.get("rule") or ""
        labels = [CLASSIFIED[c] for c in instance.get("classifications") or []
                  if c in CLASSIFIED]
        if labels and triage_verdict == "review":
            triage_verdict = code_triage.NOT_APPLICABLE
            triage_reason = ("GitHub classifies this file as %s, and hides "
                             "alerts there by default" % " and ".join(labels))
            triage_rule = "codeql-classified"

        line_text = code_triage._line(code_triage._read(os.path.join(repo_root, path)), start)
        blame = item.get("blame") or {}
        cwes = _cwes(rule.get("tags"))
        message = str((instance.get("message") or {}).get("text") or "")
        rows.append({
            "organization": repository.split("/")[0],
            "repository": repository,
            "repository_name": repository.split("/")[-1],
            "branch": branch,
            "source": "codeql",
            "engines": ["codeql"],
            "category": "code_vulnerability",
            "finding_type": "static_analysis",
            "rule_id": rule_id,
            "rule_name": rule_id,
            "title": str(rule.get("description") or rule.get("name") or rule_id),
            "message": message.split("\n")[0][:2000],
            "snippet": TOKENISH.sub(lambda m: m.group("t")[:4] + "************"
                                    + m.group("t")[-3:],
                                    line_text.strip())[:400],
            "file": path,
            "start_line": start,
            "end_line": item["end"]["line"],
            "start_column": item["start"]["col"],
            "end_column": item["end"]["col"],
            "severity": grade,
            "engine_severity": rule.get("security_severity_level") or rule.get("severity"),
            "confidence": confidence,
            "impact": "unknown",
            "likelihood": "unknown",
            "cwe": cwes,
            "cwe_ids": cwes,
            "owasp": [],
            "technology": ["codeql"],
            "references": [alert["html_url"]] if alert.get("html_url") else [],
            "fix": None,
            "commit": blame.get("commit", ""),
            "commit_url": ("%s/%s/%s/%s" % (web, repository, link["commit"], blame["commit"])
                           if blame.get("commit") else ""),
            "author_name": blame.get("author_name", ""),
            "author_email": blame.get("author_email", ""),
            "committed_at": blame.get("committed_at", ""),
            "triage": triage_verdict,
            "triage_reason": triage_reason,
            "triage_rule": triage_rule,
            "matched": verdict.get("matched") or "",
            "alert_number": alert.get("number"),
            "url": "%s/%s/%s/%s/%s%s%d" % (web, repository, link["blob"], branch,
                                          path, link["line"], start),
            "state": "open",
        })
    return rows


def corroborate(rows: list, others: list) -> tuple:
    """Mark agreement with the other engines, without folding rows together.

    The same file, within two lines, and a CWE in common.  Each side keeps its
    own row, because each is its own alert somebody can act on, but both say
    which engines saw it and agreement raises confidence the way it does for
    every other pair of engines.
    """
    for row in rows:
        mine = set(row.get("cwe") or [])
        for other in others:
            if other.get("file") != row.get("file"):
                continue
            if abs(int(other.get("start_line") or 0) - int(row.get("start_line") or 0)) > 2:
                continue
            theirs = {str(c).split(":")[0].strip() for c in (other.get("cwe") or [])}
            if not mine or not (mine & theirs):
                continue
            engines = sorted(set((other.get("engines") or [other.get("source") or ""]))
                             | {"codeql"})
            other["engines"] = engines
            other["corroborated"] = True
            other["confidence"] = "high"
            row["engines"] = sorted(set(row["engines"]) | set(engines))
            row["corroborated"] = True
            row["confidence"] = "high"
    for row in rows:
        row.setdefault("corroborated", False)
        row["engine_note"] = ("seen by " + " and ".join(row["engines"])
                              if row["corroborated"] else "seen only by codeql")
    return rows, others


def main() -> int:
    alerts_path, sarif_dir, repo_root, repository, branch, web = sys.argv[1:7]
    muted = [m for m in (sys.argv[7] if len(sys.argv) > 7 else "").split(",") if m.strip()]
    link = json.loads(sys.argv[8]) if len(sys.argv) > 8 and sys.argv[8] else None
    others_path = sys.argv[9] if len(sys.argv) > 9 else ""
    try:
        with open(alerts_path) as handle:
            alerts = json.load(handle)
    except (OSError, ValueError):
        alerts = []
    others = []
    if others_path:
        try:
            with open(others_path) as handle:
                others = json.load(handle) or []
        except (OSError, ValueError):
            others = []
    rows = convert(alerts if isinstance(alerts, list) else [], sarif_dir,
                   repo_root, repository, branch, web, muted, link)
    rows, others = corroborate(rows, others)
    json.dump(others + rows, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
