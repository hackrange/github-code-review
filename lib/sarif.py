"""Findings in the one format everything else already reads.

The report this tool writes is a good shape and it is ours alone.  Anybody
adopting it has to write an importer before they see a single finding, which is
a week of work standing in front of the thing they wanted.  SARIF is what the
rest of this market speaks, and plenty of free things read it: GitHub's
Security tab, GitLab, Azure DevOps, the SARIF viewer in VS Code, and most
vulnerability managers.

The pull request payoff is the part worth understanding.  A pipeline that
uploads this gets its findings annotated inline on the diff, and the posting is
done by the pipeline's own token.  Nothing here ever needs write access to a
repository, which is the promise the rest of this tool is built on.

Two shapes go in.  A full scan becomes one run per repository, because a SARIF
path is relative to a repository root and an estate has hundreds of those;
versionControlProvenance on each run says which one it is.  A review of a
single directory becomes a single run, which is the file a pipeline uploads.

Cleartext never reaches this file.  A secret travels as its mask and its
fingerprint, the same as everywhere else, and every field is copied across by
name.  Nothing is spread in wholesale, because a passthrough is how a value
nobody meant to publish ends up in a build artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://git.failoverlb.net/github-code-review"

# SARIF has four levels and this has six severities, so something has to give.
# An ungraded finding is left at note deliberately: see SECURITY_SEVERITY.
LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "negligible": "note",
    "note": "note",
}

# GitHub reads security-severity as a number and buckets it: 9 and over is
# critical, 7 and over high, 4 and over medium.  These sit in the middle of
# those bands so a rounding argument cannot move one.
#
# Using the real CVSS score on a dependency finding instead is tempting and is
# the wrong call.  Severity here is what the web app shows and what the
# severity rules have already regraded, and two screens disagreeing about how
# bad the same thing is costs more than the precision buys.  The score is in
# properties for anybody who wants it.
SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.5",
    "low": "2.0",
    "info": "1.0",
    "negligible": "1.0",
    "note": "1.0",
}

# GitHub turns a tag in this shape into a CWE chip on the finding.
CWE_TAG = "external/cwe/cwe-{}"


def _digest(*parts) -> str:
    raw = "|".join(str(p or "") for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def fingerprint_for(kind: str, row: dict) -> str:
    """What makes this the same finding as last time.

    This has to agree with fingerprint_for in app/core/ingest.py.  If it drifts,
    a finding in somebody's Security tab and the same finding in the web app
    become two different things with two different ids, and nobody notices until
    they try to reconcile them.  The two cannot import each other, because the
    scanner runs from its own venv and the web app from another one, so it is
    written twice and tests/sarif-test.sh checks the two still agree.
    """
    if kind == "credential":
        existing = row.get("secret_fingerprint")
        if existing:
            return f"cred:{existing}"
        return "cred:" + _digest(row.get("repository"), row.get("file"),
                                 row.get("detector"), row.get("start_line"))
    if kind == "code":
        return "code:" + _digest(row.get("repository"), row.get("file"),
                                 row.get("rule_name") or row.get("rule"),
                                 row.get("start_line"))
    if kind == "misconfiguration":
        return "misc:" + _digest(row.get("repository"), row.get("file"),
                                 row.get("rule_id"),
                                 row.get("resource") or row.get("start_line"))
    package = row.get("package") or {}
    return "dep:" + _digest(row.get("repository"), package.get("name"),
                            package.get("version"),
                            row.get("id") or row.get("vulnerability_id"))


def _severity(value) -> str:
    return str(value or "unknown").strip().lower()


def _as_list(value) -> list:
    """One of these, or several, or none.

    semgrep writes cwe and owasp as a bare string when there is one of them, and
    iterating a string gives you its characters.  code_analysis.sh already
    guards this on the way in; doing it again here costs nothing and means this
    file is safe to point at an older report.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v not in (None, "")]
    return [value]


def _text(*candidates) -> str:
    for c in candidates:
        if c:
            return str(c).strip()
    return ""


def _region(finding: dict, nudge_end: bool):
    """Where in the file, when the file knows.

    The engines do not agree about the end column.  gitleaks counts the last
    character of the match, semgrep counts one past it, and trufflehog does not
    report columns at all.  Rather than guess which convention every future
    engine follows, this only writes an end column when it is clearly past the
    start, and moves it on by one where it would otherwise be inclusive.  An
    underline a character out is a small thing.  A region a viewer rejects is
    not.
    """
    start_line = int(finding.get("start_line") or finding.get("line") or 0)
    if start_line < 1:
        return None

    region = {"startLine": start_line}
    end_line = int(finding.get("end_line") or 0)
    if end_line >= start_line:
        region["endLine"] = end_line

    start_col = int(finding.get("start_column") or 0)
    if start_col < 1:
        return region
    region["startColumn"] = start_col

    end_col = int(finding.get("end_column") or 0)
    if nudge_end and end_col >= start_col:
        end_col += 1
    if end_col > start_col:
        region["endColumn"] = end_col
    return region


def _relative(path: str, root: str) -> str:
    """Repository relative, whatever was handed in.

    gitleaks reports a file the way it was given the directory, so `review .`
    produces relative paths and `review /src` produces absolute ones.  Both have
    to come out the same here.  A viewer resolves these against somebody's
    checkout, and an absolute path from inside a build container resolves
    against nothing at all.
    """
    if not path:
        return ""
    if os.path.isabs(path) and root:
        try:
            rel = os.path.relpath(path, os.path.abspath(root))
        except ValueError:
            return path
        # Something outside the directory that was reviewed is left alone.  It
        # is wrong either way, and a path full of ".." at least says so.
        if not rel.startswith(".."):
            return rel.replace(os.sep, "/")
        return path
    return path[2:] if path.startswith("./") else path


def _location(path: str, region):
    if not path:
        return None
    physical = {"artifactLocation": {"uri": path}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


class Rules:
    """The rule table for one run, built as the results go past.

    SARIF wants every rule declared once and each result pointing at it by
    index.  Collecting them while walking the findings is the only pass that
    knows which rules actually fired, and a rule table full of rules nothing
    matched is noise in every viewer that reads it.
    """

    def __init__(self):
        self._index = {}
        self.rules = []

    def add(self, rule_id: str, **fields) -> int:
        if rule_id in self._index:
            return self._index[rule_id]
        rule = {"id": rule_id}
        name = fields.get("name")
        if name:
            rule["name"] = name
        short = fields.get("short")
        if short:
            rule["shortDescription"] = {"text": short}
        full = fields.get("full")
        if full and full != short:
            rule["fullDescription"] = {"text": full}
        help_text = fields.get("help") or full or short
        if help_text:
            rule["help"] = {"text": help_text}
        uri = fields.get("uri")
        if uri:
            rule["helpUri"] = uri

        # SARIF wants these unique.  A Dockerfile finding whose provider is
        # also "Dockerfile" produced the tag twice, and a code host rejects the
        # whole document over it rather than the one rule.
        seen, tags = set(), []
        for tag in fields.get("tags") or []:
            if tag and tag not in seen:
                seen.add(tag)
                tags.append(tag)
        properties = {"tags": tags}
        severity = fields.get("severity", "unknown")
        score = SECURITY_SEVERITY.get(severity)
        if score:
            properties["security-severity"] = score
        level = LEVELS.get(severity, "note")
        properties["problem.severity"] = (
            "error" if level == "error"
            else "warning" if level == "warning"
            else "recommendation")
        rule["properties"] = properties

        self._index[rule_id] = len(self.rules)
        self.rules.append(rule)
        return self._index[rule_id]


def _result(rule_index, rule_id, level, message, location, fingerprint,
            properties):
    result = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": message or rule_id},
    }
    if location:
        result["locations"] = [location]
    if fingerprint:
        # Versioned, because the day this scheme changes is the day every
        # finding in somebody's Security tab would otherwise reopen at once.
        result["partialFingerprints"] = {"ghscanFingerprint/v1": fingerprint}
    if properties:
        result["properties"] = properties
    return result


def _secret_result(finding: dict, rules: Rules) -> dict:
    detector = _text(finding.get("detector"), finding.get("rule_id"), "secret")
    severity = _severity(finding.get("severity"))
    rule_id = f"ghscan/secret/{detector}"
    index = rules.add(
        rule_id,
        name=detector,
        short=f"Credential detected by {detector}",
        full=_text(finding.get("description"),
                   f"A {detector} credential is committed to this repository."),
        help=("A credential in git history has to be treated as leaked, even "
              "after it is deleted, because anybody with a clone still has it. "
              " Rotate it first, then remove it."),
        tags=["security", "credential", "external/cwe/cwe-798"],
        severity=severity)

    where = _text(finding.get("exposure"))
    verified = finding.get("verified") is True
    message = "{} credential in {}{}{}".format(
        detector,
        _text(finding.get("file"), "this repository"),
        ", verified live against the provider" if verified else "",
        f" ({where.replace('_', ' ')})" if where else "")

    properties = {
        "kind": "credential",
        "severity": severity,
        "detector": detector,
        "verified": verified,
        "confidence": _text(finding.get("confidence")),
        "classification": _text(finding.get("classification")),
        "exposure": where,
        "branches": _as_list(finding.get("branches")),
        "engines": _as_list(finding.get("engines")),
    }
    # The mask, never the value.  secret_redacted is already shaped by the
    # redaction settings and is the only form of it allowed to leave the scan.
    if finding.get("secret_redacted"):
        properties["preview"] = finding["secret_redacted"]
    if finding.get("author_login") or finding.get("author_name"):
        properties["author"] = _text(finding.get("author_login"),
                                     finding.get("author_name"))
    if finding.get("url"):
        properties["url"] = finding["url"]

    return _result(index, rule_id, LEVELS.get(severity, "note"), message,
                   _location(_text(finding.get("file")),
                             _region(finding, nudge_end=True)),
                   fingerprint_for("credential", finding), properties)


def _code_result(finding: dict, rules: Rules) -> dict:
    raw_rule = _text(finding.get("rule_id"), finding.get("rule_name"), "code")
    severity = _severity(finding.get("severity"))
    cwes = [str(c).split(":")[0].replace("CWE-", "").replace("cwe-", "")
            for c in _as_list(finding.get("cwe_ids") or finding.get("cwe"))]
    tags = ["security", "code"]
    tags += [CWE_TAG.format(c) for c in cwes if c.isdigit()]
    tags += [str(o) for o in _as_list(finding.get("owasp"))]

    references = _as_list(finding.get("references"))
    rule_id = f"ghscan/code/{raw_rule}"
    index = rules.add(
        rule_id,
        name=_text(finding.get("rule_name"), raw_rule),
        short=_text(finding.get("title"), raw_rule),
        full=_text(finding.get("message"), finding.get("title")),
        uri=references[0] if references else None,
        tags=tags,
        severity=severity)

    properties = {
        "kind": "code",
        "severity": severity,
        "confidence": _text(finding.get("confidence")),
        "impact": _text(finding.get("impact")),
        "likelihood": _text(finding.get("likelihood")),
        "cwe": _as_list(finding.get("cwe")),
        "owasp": _as_list(finding.get("owasp")),
    }
    # The triage verdict travels with the finding.  A reader who disagrees with
    # it can only do that if they can see it, which is the same reason the
    # report keeps it rather than acting on it silently.
    verdict = _text(finding.get("triage"))
    if verdict:
        properties["triage"] = verdict
        properties["triageReason"] = _text(finding.get("triage_reason"))
    if finding.get("fix"):
        properties["suggestedFix"] = finding["fix"]
    if finding.get("author_name"):
        properties["author"] = finding["author_name"]
    if finding.get("url"):
        properties["url"] = finding["url"]

    return _result(index, rule_id, LEVELS.get(severity, "note"),
                   _text(finding.get("title"), finding.get("message"), raw_rule),
                   _location(_text(finding.get("file")),
                             _region(finding, nudge_end=False)),
                   fingerprint_for("code", finding), properties)


def _misconfiguration_result(finding: dict, rules: Rules) -> dict:
    rule = _text(finding.get("rule_id"), "unknown")
    severity = _severity(finding.get("severity"))
    kind = _text(finding.get("configuration_kind"))

    # A workflow finding and a Terraform finding are the same kind of thing to
    # everything downstream, but they are not the same kind of thing to a person
    # reading a rule id, so the namespace says which pass produced it.
    family = "workflow" if _text(finding.get("finding_type")) == "workflow" else "iac"
    rule_id = f"ghscan/{family}/{rule}"
    tags = ["security", "misconfiguration", family]
    if kind:
        tags.append(kind)
    provider = _text(finding.get("provider"))
    if provider:
        tags.append(provider.lower())

    index = rules.add(
        rule_id,
        name=rule,
        short=_text(finding.get("title"), rule),
        full=_text(finding.get("description"), finding.get("title")),
        # The resolution is the whole point of one of these.  A misconfiguration
        # without the fix beside it is a fact somebody has to go and research.
        help=_text(finding.get("resolution"), finding.get("description")),
        uri=_text(finding.get("help_url")) or None,
        tags=tags,
        severity=severity)

    resource = _text(finding.get("resource"))
    message = "{}{}".format(
        _text(finding.get("message"), finding.get("title"), rule),
        f" ({resource})" if resource else "")

    properties = {
        "kind": "misconfiguration",
        "severity": severity,
        "configurationKind": kind,
        "resource": resource,
        "provider": provider,
        "service": _text(finding.get("service")),
        "resolution": _text(finding.get("resolution")),
    }
    verdict = _text(finding.get("triage"))
    if verdict:
        properties["triage"] = verdict
        properties["triageReason"] = _text(finding.get("triage_reason"))
    # Who could have stopped it.  A workflow an outsider can trigger reads very
    # differently next to the names of the people who own the repository.
    admins = _as_list(finding.get("repository_admins"))
    if admins:
        properties["repositoryAdmins"] = admins
    if finding.get("url"):
        properties["url"] = finding["url"]

    return _result(index, rule_id, LEVELS.get(severity, "note"), message,
                   _location(_text(finding.get("file")),
                             _region(finding, nudge_end=False)),
                   fingerprint_for("misconfiguration", finding), properties)


def _dependency_result(finding: dict, rules: Rules) -> dict:
    package = finding.get("package") or {}
    advisory = _text(finding.get("id"), "UNKNOWN")
    severity = _severity(finding.get("severity"))

    # The advisory id is the rule.  It is not prefixed the way the other two
    # are, because a CVE number already means the same thing everywhere and
    # anything reading this will recognize it.
    rule_id = advisory
    cwes = [str(c).split(":")[0].replace("CWE-", "").replace("cwe-", "")
            for c in _as_list(finding.get("cwe"))]
    tags = ["security", "dependency"]
    tags += [CWE_TAG.format(c) for c in cwes if c.isdigit()]

    urls = _as_list(finding.get("urls"))
    index = rules.add(
        rule_id,
        name=advisory,
        short=_text(finding.get("title"), advisory),
        full=_text(finding.get("title"), advisory),
        uri=_text(finding.get("reference"), urls[0] if urls else None) or None,
        tags=tags,
        severity=severity)

    fixed_in = _text(finding.get("fixed_in"))
    message = "{} in {} {}{}".format(
        advisory,
        _text(package.get("name"), "a dependency"),
        _text(package.get("version"), "(version unknown)"),
        f", fixed in {fixed_in}" if fixed_in else ", no fix published")

    properties = {
        "kind": "dependency",
        "severity": severity,
        "package": _text(package.get("name")),
        "version": _text(package.get("version")),
        "purl": _text(package.get("purl")),
        "fixedIn": fixed_in,
        "sources": _as_list(finding.get("sources") or finding.get("source")),
        "aliases": _as_list(finding.get("aliases")),
    }
    if finding.get("cvss_score") is not None:
        properties["cvssScore"] = finding["cvss_score"]
    if finding.get("cvss_vector"):
        properties["cvssVector"] = finding["cvss_vector"]
    # Exploitation data changes what somebody does first, so it belongs on the
    # finding rather than only in the summary that produced it.
    if finding.get("known_exploited"):
        properties["knownExploited"] = True
        tags.append("cisa-kev")
    if finding.get("epss_score") is not None:
        properties["epssScore"] = finding["epss_score"]
    if finding.get("priority"):
        properties["priority"] = finding["priority"]

    # A dependency finding has no line.  The manifest that pulled the package
    # in is the closest thing to a place, and it is what somebody has to edit.
    locations = _as_list(package.get("locations"))
    manifest = _text(locations[0] if locations else None)

    return _result(index, rule_id, LEVELS.get(severity, "note"), message,
                   _location(manifest, None),
                   fingerprint_for("dependency", finding), properties)


def _driver(tool: dict, rules: Rules) -> dict:
    return {
        "driver": {
            "name": _text(tool.get("name"), "ghscan"),
            "fullName": "Git Code Review",
            "version": _text(tool.get("version"), "unknown"),
            "informationUri": INFORMATION_URI,
            "rules": rules.rules,
        }
    }


def _provenance(repo: dict):
    uri = _text(repo.get("html_url"))
    if not uri:
        return None
    provenance = {"repositoryUri": uri}
    branch = _text(repo.get("default_branch"))
    if branch:
        provenance["branch"] = branch
    return [provenance]


def build_scan(doc: dict) -> dict:
    """A whole scan, one run per repository.

    Grouping by repository is not tidiness.  A SARIF path is relative to a
    repository root, and an estate scan carries findings from hundreds of roots,
    so one flat run would produce paths that resolve against the wrong tree
    everywhere except the first one.
    """
    tool = doc.get("tool") or {}

    # Everything the scan knows about each repository, so a run can say where
    # its files came from.
    repos = {}
    for entry in doc.get("repositories") or []:
        repo = entry.get("repository") or {}
        name = _text(repo.get("full_name"))
        if name:
            repos[name] = repo

    grouped = {}

    def bucket(name):
        return grouped.setdefault(
            name, {"secrets": [], "code": [], "deps": [], "iac": []})

    for finding in doc.get("secrets") or []:
        bucket(_text(finding.get("repository"), "unknown"))["secrets"].append(finding)
    for finding in doc.get("code_findings") or []:
        bucket(_text(finding.get("repository"), "unknown"))["code"].append(finding)
    for finding in doc.get("vulnerabilities") or []:
        bucket(_text(finding.get("repository"), "unknown"))["deps"].append(finding)
    for finding in doc.get("misconfigurations") or []:
        bucket(_text(finding.get("repository"), "unknown"))["iac"].append(finding)

    runs = []
    for name in sorted(grouped):
        found = grouped[name]
        rules = Rules()
        results = [_secret_result(f, rules) for f in found["secrets"]]
        results += [_code_result(f, rules) for f in found["code"]]
        results += [_misconfiguration_result(f, rules) for f in found["iac"]]
        results += [_dependency_result(f, rules) for f in found["deps"]]

        run = {"tool": _driver(tool, rules), "results": results}
        provenance = _provenance(repos.get(name) or {})
        if provenance:
            run["versionControlProvenance"] = provenance
        run["properties"] = {"repository": name}
        runs.append(run)

    # A scan that found nothing still has to produce a valid document, or every
    # pipeline consuming it fails on the good day rather than the bad one.
    if not runs:
        runs = [{"tool": _driver(tool, Rules()), "results": []}]

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}


def build_review(doc: dict, repository: str = "", root: str = "") -> dict:
    """One directory, one run.

    This is the document a pipeline uploads.  Paths are already relative to the
    directory that was reviewed, which is the repository root in every case that
    matters, so they go straight through.
    """
    tool = {"name": "ghscan",
            "version": _text(doc.get("generator")).replace("ghscan ", "")}
    rules = Rules()
    results = []
    root = root or _text(doc.get("reviewed"))

    for finding in doc.get("findings") or []:
        path = _relative(_text(finding.get("file")), root)
        # The review document is already flat and already redacted.  Reshaping
        # it into what the per-kind writers expect keeps one set of rules and
        # one set of fingerprints across both entry points.
        if finding.get("kind") == "credential":
            results.append(_secret_result({
                "repository": repository,
                "detector": finding.get("rule"),
                "description": finding.get("title"),
                "file": path,
                "start_line": finding.get("line"),
                "start_column": finding.get("start_column"),
                "end_column": finding.get("end_column"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "classification": finding.get("message"),
                "secret_redacted": finding.get("preview"),
                "secret_fingerprint": finding.get("fingerprint"),
            }, rules))
        elif finding.get("kind") == "dependency":
            # A gate's dependency findings keep the shape a scan gives them,
            # so they go through the same writer and get the same rule ids.
            results.append(_dependency_result(
                dict(finding, repository=repository), rules))
        elif finding.get("kind") == "misconfiguration":
            results.append(_misconfiguration_result({
                "repository": repository,
                "rule_id": finding.get("rule"),
                "title": finding.get("title"),
                "message": finding.get("message"),
                "description": finding.get("message"),
                "resolution": finding.get("resolution"),
                "configuration_kind": finding.get("configuration_kind"),
                "finding_type": finding.get("finding_type"),
                "resource": finding.get("resource"),
                "provider": finding.get("provider"),
                "help_url": finding.get("help_url"),
                "file": path,
                "start_line": finding.get("line"),
                "severity": finding.get("severity"),
                "triage": finding.get("triage"),
                "triage_reason": finding.get("triage_reason"),
            }, rules))
        else:
            results.append(_code_result({
                "repository": repository,
                "rule_id": finding.get("rule"),
                "rule_name": finding.get("rule"),
                "title": finding.get("title"),
                "message": finding.get("message"),
                "file": path,
                "start_line": finding.get("line"),
                "start_column": finding.get("start_column"),
                "end_column": finding.get("end_column"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "triage": finding.get("triage"),
                "triage_reason": finding.get("triage_reason"),
            }, rules))

    run = {"tool": _driver(tool, rules), "results": results}
    reviewed = _text(doc.get("reviewed"))
    if repository or reviewed:
        run["properties"] = {"repository": repository, "reviewed": reviewed}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Turn a ghscan report into SARIF 2.1.0.")
    parser.add_argument("path", help="the report to read, or - for stdin")
    parser.add_argument("--review", action="store_true",
                        help="the input is a review document, not a scan")
    parser.add_argument("--repository", default="",
                        help="owner/name of the reviewed repository, so its "
                             "fingerprints match the ones a scan produces")
    parser.add_argument("--root", default="",
                        help="the directory the review ran against, so its "
                             "paths come out relative to it")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    raw = sys.stdin.read() if args.path == "-" else open(args.path).read()
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        print(f"not valid json: {exc}", file=sys.stderr)
        return 1

    if args.review or "findings" in doc:
        sarif = build_review(doc, args.repository, args.root)
    else:
        sarif = build_scan(doc)

    json.dump(sarif, sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
