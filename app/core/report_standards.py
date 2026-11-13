"""The parts of a security report that follow from published standards.

Nothing here asks a model.  A CVSS score is arithmetic on its vector, an OWASP
category follows from the CWE the way OWASP itself files them, and a reference
link is built from an id rather than written by anybody.  That keeps the
numbers and links in a report exact, and costs no tokens however many reports
are written.
"""

from __future__ import annotations

import math
import re

from app.core.dast_report import CWE_OWASP, OWASP_NAMES, OWASP_TOP10, OWASP_URLS

# --- CVSS 3.1 base score (FIRST specification, section 7) ---------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_ALLOWED = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
            "C": "HLN", "I": "HLN", "A": "HLN"}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: the smallest one-decimal number not below value."""
    whole = int(round(value * 100000))
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def parse_vector(text) -> dict | None:
    """-> the eight base metrics, or None when the vector is not a valid 3.1 base."""
    raw = str(text or "").strip().upper()
    raw = re.sub(r"^CVSS:3\.[01]/", "", raw)
    parts = dict(p.split(":", 1) for p in raw.split("/") if ":" in p)
    metrics = {}
    for key in _ORDER:
        value = parts.get(key, "")
        if len(value) != 1 or value not in _ALLOWED[key]:
            return None
        metrics[key] = value
    return metrics


def cvss31(text) -> tuple:
    """-> (vector string, base score) or ("", None) for anything not a valid vector."""
    m = parse_vector(text)
    if m is None:
        return "", None
    iss = 1 - ((1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]]))
    changed = m["S"] == "C"
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else 6.42 * iss
    exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        score = 0.0
    elif changed:
        score = _roundup(min(1.08 * (impact + exploit), 10))
    else:
        score = _roundup(min(impact + exploit, 10))
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _ORDER), score


def cvss_band(score) -> str:
    if score is None:
        return ""
    if score == 0:
        return "None"
    return "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


# --- CWE, OWASP Top 10 and OWASP API Security Top 10 --------------------------

_BY_CWE = {cwe: key for key, cwes in CWE_OWASP.items() for cwe in cwes}

API_TOP10 = [
    ("API1", "Broken Object Level Authorization"),
    ("API2", "Broken Authentication"),
    ("API3", "Broken Object Property Level Authorization"),
    ("API4", "Unrestricted Resource Consumption"),
    ("API5", "Broken Function Level Authorization"),
    ("API6", "Unrestricted Access to Sensitive Business Flows"),
    ("API7", "Server Side Request Forgery"),
    ("API8", "Security Misconfiguration"),
    ("API9", "Improper Inventory Management"),
    ("API10", "Unsafe Consumption of APIs"),
]
API_NAMES = dict(API_TOP10)
API_URLS = {
    "API1": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "API2": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    "API3": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "API4": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    "API5": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    "API6": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
    "API7": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
    "API8": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    "API9": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    "API10": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
}
# Only the CWEs whose API category is not in doubt.  A weakness that could
# sit in more than one is left unmapped rather than guessed.
_API_BY_CWE = {
    **{c: "API1" for c in (639, 566)},
    **{c: "API2" for c in (287, 288, 290, 294, 302, 304, 306, 307, 384, 521, 522, 613,
                           640, 798, 1390, 1391)},
    **{c: "API3" for c in (213, 915)},
    **{c: "API4" for c in (400, 770, 799, 1333)},
    **{c: "API5" for c in (269, 285, 862, 863)},
    **{c: "API6" for c in (837, 840, 841)},
    918: "API7",
    **{c: "API8" for c in (2, 16, 209, 614, 693, 942, 1004, 1021)},
}


def cwe_number(text) -> int | None:
    m = re.search(r"(?:CWE[-_ ]?)?(\d{1,5})", str(text or ""), re.I)
    return int(m.group(1)) if m else None


def standards_for(cwe_text) -> dict:
    """Everything a report can say about one weakness from its CWE alone."""
    number = cwe_number(cwe_text)
    out = {"cwe": f"CWE-{number}" if number else "", "owasp": "", "owasp_name": "",
           "api": "", "api_name": "", "references": []}
    if not number:
        return out
    out["references"].append(f"https://cwe.mitre.org/data/definitions/{number}.html")
    top = _BY_CWE.get(number)
    if top:
        out.update(owasp=top, owasp_name=OWASP_NAMES[top])
        out["references"].append(OWASP_URLS[top])
    api = _API_BY_CWE.get(number)
    if api:
        out.update(api=api, api_name=API_NAMES[api])
        out["references"].append(API_URLS[api])
    return out


def coverage(items: list) -> dict:
    """Both OWASP lists, each category with the issues filed under it."""
    live = [i for i in items if i.get("rating") != "Informational"]

    def table(rows, key):
        out = []
        for code, name in rows:
            ids = [i["id"] for i in live if i.get(key) == code]
            out.append({"code": code, "name": name, "ids": ids})
        return out
    return {"top10": table(OWASP_TOP10, "owasp"), "api": table(API_TOP10, "api")}


def verdict(items: list) -> dict:
    """Whether the branch is fit to release, from the ratings alone."""
    open_ = [i for i in items if i.get("rating") != "Informational" and not i.get("waived")]
    worst = {r: sum(1 for i in open_ if i.get("rating") == r)
             for r in ("Critical", "High", "Medium", "Low")}
    if worst["Critical"] or worst["High"]:
        return {"level": "stop",
                "text": "Not ready to release.  Fix the Critical and High issues first, "
                        "and confirm each fix with the retest steps in this report."}
    if worst["Medium"]:
        return {"level": "caution",
                "text": "Ready to release with a plan.  No Critical or High issues are "
                        "open.  Fix the Medium issues within 30 days."}
    return {"level": "go", "text": "No blocking issues found.  Keep fixing Low issues "
                                   "as part of normal work."}


STANDARDS = [
    "OWASP Top 10, 2021 edition",
    "OWASP API Security Top 10, 2023 edition",
    "OWASP Application Security Verification Standard (ASVS) 4.0.3",
    "MITRE Common Weakness Enumeration (CWE)",
    "FIRST Common Vulnerability Scoring System (CVSS) 3.1",
    "NIST SP 800-115, Technical Guide to Information Security Testing and Assessment",
]
