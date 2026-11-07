"""Risk scoring for dynamic findings: likelihood x breachability.

Deterministic and token free.  Every signal comes from what the scan already
knows: how the finding was reached (a curated rule that confirmed it, the
baseline content check, or a scanning engine's heuristic), what it would yield,
and how exposed the site is (the two vantage exposure check).  No AI.

likelihood  1..5  how sure we are it is real and reachable
breachability 1..5  what a successful exploit yields, weighted by exposure
risk        a cell on the 5x5 matrix: critical / high / medium / low
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

LIKELIHOOD_LABEL = {1: "Rare", 2: "Unlikely", 3: "Possible", 4: "Likely",
                    5: "Confirmed"}
IMPACT_LABEL = {1: "Minimal", 2: "Low", 3: "Moderate", 4: "High", 5: "Severe"}

# A standard risk heatmap: table[likelihood][breachability].
_TABLE = {
    1: {1: "low", 2: "low", 3: "low", 4: "low", 5: "low"},
    2: {1: "low", 2: "low", 3: "medium", 4: "medium", 5: "high"},
    3: {1: "low", 2: "medium", 3: "medium", 4: "high", 5: "high"},
    4: {1: "medium", 2: "medium", 3: "high", 4: "high", 5: "critical"},
    5: {1: "medium", 2: "high", 3: "high", 4: "critical", 5: "critical"},
}

_RCE = re.compile(r"remote code|command inj|\brce\b|deserial|CWE-?(?:78|94|502|77)\b", re.I)
_ACCESS = re.compile(r"auth\w*\s*bypass|\bidor\b|\bbola\b|broken access|privilege|"
                     r"CWE-?(?:285|639|287|863|862|306)\b", re.I)
_INJECT = re.compile(r"sql\s*inj|\bsqli\b|\bssrf\b|\bxxe\b|\bssti\b|template inj|"
                     r"CWE-?(?:89|918|611|1336|90|943)\b", re.I)
_SENSITIVE_URL = re.compile(r"/admin|/api(?:/|$)|/account|/user|/order|/payment|/billing|"
                            r"/invoice|/token|/secret|/internal|/manage|/config", re.I)
_KEV = re.compile(r"\bKEV\b|known.exploit|actively exploited", re.I)

_SEV_IMPACT = {"critical": 4, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 1}


def _tools(f: dict) -> str:
    got = f.get("tools") or [f.get("tool") or f.get("check") or ""]
    return " ".join(str(t) for t in got).lower()


def likelihood(f: dict) -> tuple:
    """1..5 and a short basis, from how the finding was reached."""
    tools = _tools(f)
    answer = f.get("answer")
    if answer == "not_found":
        return 1, "the address answers not found"
    if tools.startswith("rule:") or "rule:" in tools:
        base, why = 5, "confirmed by a curated rule against a control"
    elif "baseline" in tools:
        base, why = 4, "the baseline check matched real content"
    elif answer == "protected":
        base, why = 2, "the path is access controlled"
    else:
        base, why = 3, "reported by a scanning engine, not re-proven"
    text = f"{f.get('title') or ''} {f.get('evidence') or ''} {f.get('cwe') or ''}"
    if _KEV.search(text) and base < 5:
        return min(5, base + 1), why + "; known exploited"
    return base, why


def breachability(f: dict, exposure: str = "") -> tuple:
    """1..5 and a short basis: what a hit yields, weighted by exposure."""
    text = f"{f.get('title') or ''} {f.get('cwe') or ''} {f.get('evidence') or ''}"
    reasons = []
    if _RCE.search(text):
        impact = 5
        reasons.append("remote code or command execution")
    elif _ACCESS.search(text):
        impact = 4
        reasons.append("access control or authentication")
    elif _INJECT.search(text):
        impact = 4
        reasons.append("injection or server side request forgery")
    else:
        impact = _SEV_IMPACT.get(f.get("severity"), 2)
        reasons.append(f"{f.get('severity') or 'low'} severity issue")
    if (exposure or "") == "open":
        impact = min(5, impact + 1)
        reasons.append("open to the world")
    elif (exposure or "") == "whitelisted":
        impact = max(1, impact - 1)
        reasons.append("allow listed, not public")
    if _SENSITIVE_URL.search(str(f.get("url") or "")):
        impact = min(5, impact + 1)
        reasons.append("a sensitive endpoint")
    return impact, "; ".join(reasons)


def cell(lk: int, br: int) -> str:
    """The risk cell for a likelihood and breachability."""
    return _TABLE.get(max(1, min(5, lk)), {}).get(max(1, min(5, br)), "low")


# A code sink type and the dynamic finding it would corroborate.
_SINK_FINDING = {
    "sql-injection": re.compile(r"sql\s*inj|\bsqli\b|CWE-?89\b", re.I),
    "command-injection": re.compile(r"command inj|\brce\b|code exec|os command|CWE-?(?:78|94|77)\b", re.I),
    "deserialization": re.compile(r"deserial|CWE-?502\b", re.I),
    "template-injection": re.compile(r"\bssti\b|template inj|CWE-?1336\b", re.I),
    "xss-sink": re.compile(r"\bxss\b|cross.site.script|CWE-?79\b", re.I),
    "path-traversal": re.compile(r"path travers|directory travers|local file|\blfi\b|CWE-?(?:22|98)\b", re.I),
}


def corroborate(findings: list, reachable_sinks: list) -> int:
    """Raise a finding to confirmed when a reachable code sink of the matching
    kind sits on the same route: the code does the dangerous thing and the scan
    reached it, which is the strongest evidence there is.  -> how many."""
    by_route = {}
    for s in reachable_sinks or []:
        by_route.setdefault(s.get("reached_route") or "", set()).add(s.get("type"))
    raised = 0
    for f in findings:
        types = by_route.get(urlparse(str(f.get("url") or "")).path)
        if not types:
            continue
        text = f"{f.get('title') or ''} {f.get('cwe') or ''} {f.get('evidence') or ''}"
        matched = [t for t in sorted(types)
                   if _SINK_FINDING.get(t) and _SINK_FINDING[t].search(text)]
        if matched and f.get("likelihood", 0) < 5:
            f["likelihood"] = 5
            f["likelihood_label"] = LIKELIHOOD_LABEL[5]
            f["sink_confirmed"] = True
            f["risk"] = cell(5, f.get("breachability", 3))
            f["risk_basis"] = ((f.get("risk_basis") or "")
                               + f"  Corroborated by a code sink ({', '.join(matched)}) "
                               "on the same reachable route.")
            raised += 1
    return raised


# A finding that is neither confirmed nor in a dangerous class is not raised
# above its own severity by exposure alone: a low issue stays low risk.
_RISK_ORDER = ["low", "medium", "high", "critical"]
_SEV_RISK_CAP = {"critical": "critical", "high": "high", "medium": "medium",
                 "low": "low", "info": "low", "none": "low"}


def annotate(findings: list, exposure: str = "") -> list:
    """Add likelihood, breachability, risk and a basis to each finding, in place."""
    for f in findings:
        lk, lk_why = likelihood(f)
        br, br_why = breachability(f, exposure)
        f["likelihood"] = lk
        f["breachability"] = br
        f["likelihood_label"] = LIKELIHOOD_LABEL[lk]
        f["breachability_label"] = IMPACT_LABEL[br]
        risk = cell(lk, br)
        basis = (f"Likelihood {LIKELIHOOD_LABEL[lk]} ({lk_why}).  "
                 f"Impact {IMPACT_LABEL[br]} ({br_why}).")
        text = f"{f.get('title') or ''} {f.get('cwe') or ''} {f.get('evidence') or ''}"
        dangerous = bool(_RCE.search(text) or _ACCESS.search(text) or _INJECT.search(text))
        if lk < 4 and not dangerous:
            cap = _SEV_RISK_CAP.get(f.get("severity"), "medium")
            if _RISK_ORDER.index(risk) > _RISK_ORDER.index(cap):
                basis += (f"  Held at {cap}: a {f.get('severity') or 'low'} finding that "
                          "is not confirmed and not a dangerous class is not raised above "
                          "its severity by exposure alone.")
                risk = cap
        f["risk"] = risk
        f["risk_basis"] = basis
    return findings


def matrix(findings: list) -> dict:
    """The 5x5 heatmap for the report, ready to render: rows run breachability
    5 (severe) down to 1, columns run likelihood 1 to 5.  Each cell carries its
    finding count and its risk color."""
    count = {b: {l: 0 for l in range(1, 6)} for b in range(1, 6)}
    worst, order = "low", ["low", "medium", "high", "critical"]
    for f in findings:
        lk, br = f.get("likelihood"), f.get("breachability")
        if lk and br:
            count[br][lk] += 1
            if order.index(f.get("risk", "low")) > order.index(worst):
                worst = f.get("risk", "low")
    rows = [{"b": b, "label": IMPACT_LABEL[b],
             "cells": [{"l": l, "n": count[b][l], "risk": cell(l, b)}
                       for l in range(1, 6)]}
            for b in range(5, 0, -1)]
    return {"rows": rows, "worst": worst,
            "columns": [LIKELIHOOD_LABEL[l] for l in range(1, 6)],
            "counts": {r: sum(1 for f in findings if f.get("risk") == r)
                       for r in ("critical", "high", "medium", "low")}}
