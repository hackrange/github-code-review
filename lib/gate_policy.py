#!/usr/bin/env python3
"""Turn a gate document into a verdict: pass, warn or fail.

The document comes from `ghscan review --base --head`, and only its new
findings count.  The policy is config/gate-policy.yaml.  This file uses the
standard library and nothing else, apart from PyYAML for reading the policy,
so the scanner and the web app can both load it by path even though they run
from different venvs.

A finding that would block but is covered by an exception is not dropped.  It
moves to exceptions_applied, so the record of a run says what was let through
and why, not only what was stopped.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys

SEVERITY = {"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2,
            "negligible": 1, "info": 1, "note": 1}

# Code triage verdicts that mean a person does not need to look.  A gate that
# blocked on these would be blocking on what the nightly scan already set
# aside.  See lib/code_triage.py.
SET_ASIDE = {"third_party", "not_applicable", "advisory"}


def _rank(severity) -> int:
    return SEVERITY.get(str(severity or "").strip().lower(), 0)


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (over or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load(path: str) -> dict:
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        import yaml
    except ImportError:
        # JSON is YAML, so a policy written as JSON still loads without it.
        # Anything else is a missing library, and saying "not valid JSON"
        # about a YAML file sends somebody looking in the wrong place.
        try:
            policy = json.loads(raw)
        except ValueError:
            raise ValueError("%s is YAML, and PyYAML is not installed for %s"
                             % (path, sys.executable))
    else:
        policy = yaml.safe_load(raw) or {}
    if not isinstance(policy, dict) or not isinstance(policy.get("default"), dict):
        raise ValueError("a gate policy needs a default section")
    # The version a person wrote, plus a hash of the file.  A change somebody
    # forgot to bump the version for still shows up as a different policy.
    policy["_version"] = "%s+%s" % (policy.get("version") or "unversioned",
                                    hashlib.sha256(raw).hexdigest()[:8])
    return policy


def for_repo(policy: dict, repository: str = "") -> dict:
    """The default, with this repository's settings merged over it."""
    effective = copy.deepcopy(policy.get("default") or {})
    repos = policy.get("repos") or {}
    wanted = (repository or "").lower()
    for name, over in repos.items():
        if str(name).lower() == wanted and isinstance(over, dict):
            effective = _merge(effective, over)
    effective.setdefault("mode", "monitor")
    return effective


def _rules(policy: dict, names) -> set:
    categories = policy.get("categories") or {}
    out = set()
    for name in names or ():
        out.update(str(r).upper() for r in categories.get(name) or ())
    return out


def why_blocked(finding: dict, block: dict, policy: dict) -> str:
    """The reason this new finding blocks, or "" when it only warns."""
    kind = finding.get("kind")

    if kind == "credential":
        want = str(block.get("secrets", "live")).lower()
        if want == "any":
            return "a new credential"
        if want == "live" and finding.get("verified") is True:
            return "a new credential the provider confirmed is live"
        return ""

    if kind == "code":
        sast = block.get("sast") or {}
        if not sast:
            return ""
        if (finding.get("triage") or "review") in SET_ASIDE:
            return ""
        if _rank(finding.get("severity")) < _rank(sast.get("min_severity", "high")):
            return ""
        engines = finding.get("engines") or []
        two = bool(finding.get("corroborated")) or len(set(engines)) >= 2
        if two or str(sast.get("require", "two_engines")) == "any":
            return "a new %s code finding%s" % (
                str(finding.get("severity")).lower(),
                " two engines agree on" if two else "")
        return ""

    if kind == "dependency":
        malicious = finding.get("malicious") or {}
        wanted = {str(s).lower() for s in block.get("malicious_packages") or ()}
        advisory = str(finding.get("rule") or finding.get("id") or "")
        if advisory.upper().startswith("MAL-") and "known_malicious" in wanted:
            return "a package with a published malicious-package advisory"
        if malicious and str(malicious.get("signal", "")).lower() in wanted:
            return "a supply chain signal: %s" % malicious.get("signal")
        if malicious:
            return ""
        sca = block.get("sca") or {}
        if sca.get("kev") and finding.get("known_exploited"):
            return "a new dependency on the CISA known exploited list"
        reach = (finding.get("reachability") or {}).get("verdict")
        if (sca.get("reachable_critical") and _rank(finding.get("severity")) >= 5
                and reach == "reachable"):
            return "a new critical the code reaches"
        return ""

    if kind == "misconfiguration":
        rule = str(finding.get("rule") or "").upper()
        if rule in _rules(policy, block.get("iac")):
            return "a new misconfiguration (%s)" % rule
        if rule.lower() in {r.lower() for r in _rules(policy, block.get("ci_workflows"))}:
            return "a new workflow problem (%s)" % finding.get("rule")
        return ""

    return ""


def _summary(finding: dict, reason: str = "") -> dict:
    row = {k: finding.get(k) for k in
           ("kind", "rule", "file", "line", "severity", "title", "fingerprint",
            "introduced_in", "commit")
           if finding.get(k) not in (None, "")}
    if finding.get("kind") == "dependency":
        package = finding.get("package") or {}
        row["package"] = package.get("name")
        row["version"] = package.get("version")
    if reason:
        row["reason"] = reason
    return row


def evaluate(doc: dict, policy: dict, repository: str = "",
             excepted=None) -> dict:
    """The verdict for one gate document.

    excepted is a function that takes a finding and returns the id of the
    exception covering it, or nothing.  The web app passes one that reads the
    waivers; the command line has none.
    """
    effective = for_repo(policy, repository)
    block = effective.get("block") or {}
    blocking, warnings, applied = [], [], []
    for finding in doc.get("findings") or []:
        if not finding.get("new"):
            continue
        reason = why_blocked(finding, block, policy)
        if not reason:
            warnings.append(_summary(finding))
            continue
        exception = excepted(finding) if excepted else None
        if exception:
            row = _summary(finding, reason)
            row["exception"] = exception
            applied.append(row)
        else:
            blocking.append(_summary(finding, reason))

    mode = str(effective.get("mode", "monitor")).lower()
    if blocking:
        verdict = "fail" if mode == "enforce" else "warn"
    elif warnings or applied:
        verdict = "warn"
    else:
        verdict = "pass"
    return {
        "verdict": verdict,
        "mode": mode,
        # A monitor run that would have failed.  This is the number the
        # rollout is judged on.
        "would_block": bool(blocking),
        "policy_version": policy.get("_version"),
        "blocking": blocking,
        "warnings": warnings,
        "exceptions_applied": applied,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("doc", help="a gate document, or - for stdin")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--repository", default="")
    args = parser.parse_args()
    raw = sys.stdin.read() if args.doc == "-" else open(args.doc).read()
    try:
        policy = load(args.policy)
    except (OSError, ValueError) as exc:
        print("cannot read the gate policy: %s" % exc, file=sys.stderr)
        return 2
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        print("the gate document is not valid json: %s" % exc, file=sys.stderr)
        return 2
    json.dump(evaluate(doc, policy, args.repository), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
