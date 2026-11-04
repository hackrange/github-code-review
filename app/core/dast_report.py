"""The PDF report on one dynamic scan.

Laid out the way nextgen-dast lays out its penetration test report, so a
reader who has seen one knows where everything is in the other: a cover with
the grade, document control, an executive summary with the OWASP Top 10
grades and a heat map, scope and method, every finding with how to see it
again, the scans underneath, and a disclaimer.  It is typeset in this
product's own report style, beside the security assessment.

The grade follows nextgen-dast's rules.  Each finding costs points by
severity, the second and later findings in the same OWASP category cost
less, and no one category can take more than 25 points off the overall
score, so one bad library cannot fail an otherwise clean site.  nextgen-dast
counts only findings its probes confirmed.  Here the enhanced review plays that
part: when it ran, a finding it called a likely false positive costs nothing
and one it wants reviewed costs half.  When it did not run, every finding
counts in full and the report says they are unconfirmed.

Everything in the fixed text is US English, about a tenth grade reading
level, with two spaces between sentences and no em dashes.
"""

from __future__ import annotations

import json
import math
import re
import shlex
from datetime import datetime, timezone
from urllib.parse import urlparse

OWASP_TOP10 = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server Side Request Forgery"),
]
OWASP_NAMES = dict(OWASP_TOP10)
OWASP_URLS = {
    "A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

# The CWEs scanners name most, by the OWASP 2021 category OWASP itself puts
# them in.
CWE_OWASP = {
    "A01": [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377,
            402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706,
            862, 863, 913, 922, 1275],
    "A02": [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
            331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    "A03": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97,
            98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
    "A04": [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419,
            430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646,
            650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
    "A05": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756,
            776, 942, 1004, 1032, 1174, 693],
    "A06": [937, 1035, 1104],
    "A07": [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346,
            384, 521, 613, 620, 640, 798, 940, 1216],
    "A08": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09": [117, 223, 532, 778],
    "A10": [918],
}
_BY_CWE = {cwe: key for key, cwes in CWE_OWASP.items() for cwe in cwes}

# Where no CWE says, the kind of check does.
_BY_CHECK = [
    (re.compile(r"sql|injection|xss|cross site script|command|xxe|crlf|template", re.I), "A03"),
    (re.compile(r"tls|ssl|certificate|cipher|https|hsts|plain http|unencrypted", re.I), "A02"),
    (re.compile(r"outdated|vulnerable software|cve-|version|jquery|bootstrap|angular|lodash", re.I), "A06"),
    (re.compile(r"ssrf|server side request", re.I), "A10"),
    (re.compile(r"login|password|session|cookie|auth|default credential", re.I), "A07"),
    (re.compile(r"\.git|\.env|exposed|served|directory listing|backup|traversal|redirect|cors", re.I), "A01"),
]

DEMERIT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
CATEGORY_CAP = 25.0
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def owasp_of(f: dict) -> str:
    """The OWASP 2021 category a finding belongs in.  A05 when nothing says."""
    for number in re.findall(r"CWE-?(\d+)", str(f.get("cwe") or ""), re.I):
        key = _BY_CWE.get(int(number))
        if key:
            return key
    text = " ".join(str(f.get(k) or "") for k in ("title", "check", "tool"))
    for pattern, key in _BY_CHECK:
        if pattern.search(text):
            return key
    return "A05"


def weight_of(f: dict, triaged: bool) -> float:
    """How much of its severity's points a finding costs.  A person's decision
    comes first: a false positive or an exception costs nothing."""
    if (f.get("decision") or {}).get("kind") in ("false_positive", "exception"):
        return 0.0
    verdict = f.get("ai_verdict") or ""
    if triaged:
        if verdict == "likely_false_positive":
            return 0.0
        if verdict == "needs_review":
            return 0.5
    return 1.0


def grade_for(score: int) -> str:
    return ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
            else "D" if score >= 60 else "F")


def score(findings: list, triaged: bool, only: str = None) -> dict:
    """0 to 100, the way nextgen-dast scores.  only scores one category,
    uncapped, for its own line on the scorecard."""
    by_cat: dict = {}
    for f in findings:
        cat = f["owasp"]
        if only and cat != only:
            continue
        points = DEMERIT.get(f.get("severity"), 0) * weight_of(f, triaged)
        if points > 0:
            by_cat.setdefault(cat, []).append(points)
    total = 0.0
    for points in by_cat.values():
        points.sort(reverse=True)
        cat_total = sum(p / math.sqrt(rank) for rank, p in enumerate(points, 1))
        total += cat_total if only else min(cat_total, CATEGORY_CAP)
    value = max(0, int(round(100 - total)))
    return {"score": value, "grade": grade_for(value),
            "counted": sum(len(v) for v in by_cat.values())}


def _q(text: str) -> str:
    return shlex.quote(str(text or ""))


def reproduce(f: dict, host: str) -> dict:
    """A command somebody can run to see the finding again, and a hint.

    The command asks the same question the scanner asked.  If the problem is
    fixed the answer is different, which is the point of including it.
    """
    url = f.get("url") or ""
    tool = (f.get("tool") or f.get("check") or "").lower()
    evidence = str(f.get("evidence") or "")
    is_web = url.startswith(("http://", "https://"))
    hint = "Run it from a machine outside the company network, as an attacker would."
    if tool == "testssl":
        test = (f.get("title") or "").replace("TLS: ", "").split(" ")[0]
        return {"command": f"testssl.sh --quiet --color 0 {_q(host)}",
                "hint": f"Look for the line {test} in the output." if test else hint}
    if tool == "nuclei":
        m = re.search(r"template ([A-Za-z0-9_.-]+)", evidence)
        if m:
            return {"command": f"nuclei -u {_q(url or 'https://' + host + '/')} -id {_q(m.group(1))}",
                    "hint": "nuclei prints a line for the template when it still matches."}
    if tool == "ports" or (not is_web and re.search(r":\d+$", url)):
        hostport = url.rsplit(":", 1)
        if len(hostport) == 2:
            return {"command": f"nc -vz -w 5 {_q(hostport[0])} {_q(hostport[1])}",
                    "hint": "A succeeded or open message means the port still answers."}
    if tool == "methods":
        return {"command": f"curl -sk -i -X TRACE {_q(url)} -H 'X-Check: 1'",
                "hint": "A 200 that echoes X-Check back means TRACE is still on."}
    if tool == "cors":
        return {"command": f"curl -sk -i {_q(url)} -H 'Origin: https://example.invalid'",
                "hint": "Look for Access-Control-Allow-Origin naming example.invalid."}
    if is_web:
        method = "GET"
        m = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s", evidence)
        if m:
            method = m.group(1)
        extra = f" -X {method}" if method != "GET" else ""
        return {"command": f"curl -sk -i{extra} {_q(url)}",
                "hint": ("Compare the response with the evidence above.  "
                         "The response headers are at the top.")}
    return {"command": "", "hint": "This finding has no address to request."}


def _sentence(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def narrative(host: str, view: dict, overall: dict, by_sev: dict, triaged: bool,
              profile_words: str) -> list:
    """The executive summary, written from the numbers.  Plain sentences."""
    total = sum(by_sev.values())
    serious = by_sev.get("critical", 0) + by_sev.get("high", 0)
    out = []
    if not total:
        out.append(f"The {profile_words} scan of {host} found no problems.  "
                   f"That is a good sign, but it is only as wide as the checks that ran, "
                   f"which section 3 lists.")
    else:
        out.append(f"The {profile_words} scan of {host} found {_sentence(total, 'issue')}.  "
                   + (f"{serious} of them {'is' if serious == 1 else 'are'} rated critical or "
                      f"high and should be fixed first." if serious else
                      "None of them is rated critical or high."))
    out.append(f"The site scores {overall['score']} out of 100, a grade of {overall['grade']}.  "
               "Each finding takes points off by how serious it is.  Several findings of the "
               "same kind take less off than the first, and no single kind can take off more "
               "than 25 points.")
    if triaged:
        out.append("An enhanced review read every finding after the scan.  Findings it judged to be "
                   "likely false positives do not count toward the grade, and findings it wants "
                   "a person to check count half.  Its verdict is shown on each finding.")
    elif total:
        out.append("No enhanced review was run on this scan, so every finding counts in full and none "
                   "of them has been confirmed.  Scanners report some issues that turn out not "
                   "to be real, so check each one before acting on it.")
    return out


def available(scan) -> bool:
    """Only a scan this server ran has a report here.  A DAST server's scan
    has that server's own report, and a recorded one has only what was
    recorded, which is not enough to stand behind as a report."""
    return scan is not None and scan.source == "builtin" and scan.status == "done"


def build(db, asset, scan, user=None, organization: str = "") -> dict:
    """Everything the template needs for one scan."""
    from app.core import dast_engines, external

    from app.core import external_decisions

    view = external.scan_dict(scan, findings=True)
    # Decisions as they stand today.  A false positive is not in the report
    # at all; a changed severity is the severity.
    view["findings"] = [f for f in external_decisions.apply(
        view.get("findings") or [], external_decisions.for_asset(db, asset.id), scan_id=scan.id)
        if (f.get("decision") or {}).get("kind") != "false_positive"]
    triaged = view["ai"]["status"] == "done" and any(
        f.get("ai_verdict") for f in view.get("findings") or [])
    findings = []
    for number, f in enumerate(sorted(view.get("findings") or [], key=lambda x: (
            SEVERITIES.index(x.get("severity")) if x.get("severity") in SEVERITIES else 9,
            x.get("title") or "")), 1):
        f = dict(f)
        f["owasp"] = owasp_of(f)
        f["owasp_name"] = OWASP_NAMES[f["owasp"]]
        f["owasp_url"] = OWASP_URLS[f["owasp"]]
        f["ref"] = f"F-{number:03d}"
        f["counted"] = weight_of(f, triaged)
        f["repro"] = reproduce(f, asset.host)
        cwe = re.search(r"CWE-?(\d+)", str(f.get("cwe") or ""), re.I)
        f["cwe_url"] = (f"https://cwe.mitre.org/data/definitions/{cwe.group(1)}.html"
                        if cwe else "")
        findings.append(f)
    overall = score(findings, triaged)
    from app.core.external_decisions import counted as _counted

    by_sev = {s: sum(1 for f in findings if f.get("severity") == s and _counted(f))
              for s in SEVERITIES}
    categories = []
    for key, name in OWASP_TOP10:
        in_cat = [f for f in findings if f["owasp"] == key]
        graded = score(findings, triaged, only=key)
        categories.append({"key": key, "name": name, "count": len(in_cat),
                           "grade": graded["grade"], "score": graded["score"],
                           "cells": {s: sum(1 for f in in_cat if f.get("severity") == s)
                                     for s in SEVERITIES}})
    heat_max = max([c for cat in categories for c in cat["cells"].values()] + [1])

    engines = [e for e in view.get("engines") or []]
    ran = [e for e in engines if e.get("status") == "ok"]
    skipped = [e for e in engines if e.get("status") in ("skipped", "failed", "timeout", "stopped")]
    profile = view.get("profile") or ""
    profile_words = profile if profile else "dynamic"
    limitations = []
    if profile == "baseline":
        limitations.append("This was a baseline scan.  It reads headers, cookies, TLS, open "
                           "ports and a list of files that should never be served.  It does "
                           "not crawl the site or send attack payloads.")
    elif profile in ("quick",):
        limitations.append("This was a quick scan.  It ran template checks for known issues "
                           "and the TLS review.  It did not crawl the site or try injection.")
    for e in skipped:
        limitations.append(f"{e.get('name') or e.get('tool')} did not complete: "
                           f"{e.get('detail') or e.get('status')}.")
    if scan.authenticated:
        kinds = {"header": "a header", "cookie": "a session cookie", "form": "a form login"}
        signin = next((e for e in engines if e.get("tool") == "signin"), None)
        limitations.append(f"The engines signed in with {kinds.get(scan.auth_kind, 'a sign in')}, "
                           "so they saw what that user sees.  The baseline checks and testssl "
                           "ran signed out.")
        if signin and signin.get("status") != "ok":
            limitations.append(f"Signing in did not work: {signin.get('detail')}.")
        unsigned = [e.get("name") for e in engines
                    if e.get("signed_in") is False and e.get("status") == "ok"
                    and e.get("tool") not in ("baseline", "testssl")]
        if unsigned:
            limitations.append("These ran signed out: " + ", ".join(unsigned) + ".")
    else:
        limitations.append("The scan did not sign in, so it saw only the public parts of "
                           "the site.")
    if asset.external_auth_needed and not scan.authenticated:
        limitations.append("Signing in to this site goes through an outside service.  A "
                           "session cookie set in the site's sign in settings lets a scan "
                           "get past it.")
    tele_now = external.telemetry_of(asset)
    if tele_now.get("bot_check"):
        limitations.append(f"{tele_now['bot_check']}'s bot check answers in front of the site.  "
                           "Unless this server's address is let through it, the engines saw the "
                           "check instead of the site, and an empty result means little.")
    if tele_now.get("ports_unreliable"):
        limitations.append("Nearly every port answers, because a CDN or firewall in front accepts "
                           "every connection.  Open ports were not reported as findings.")
    if asset.whitelist_needed:
        limitations.append("The site needs the scanner's address let through a firewall.  If "
                           "it was not, parts of the site were blocked from the scan.")
    limitations.append("A dynamic scan tests the site as it was at the time of the scan.  "
                       "It does not prove the absence of other issues.")

    mapper = external.Mapper(db, user)
    links = [l for l in mapper.links(asset) if l["linked"]]
    counts = external.sast_counts(db, [l["full_name"] for l in links], user)
    tele = external.telemetry_of(asset)
    fields = external.field_values(asset)
    started = scan.started_at or scan.scanned_at
    finished = scan.scanned_at
    ai_summary = (view["ai"].get("summary") or {}) if triaged else {}

    return {
        "asset": asset, "scan": scan, "view": view, "findings": findings,
        "overall": overall, "by_sev": by_sev, "categories": categories,
        "heat_max": heat_max, "triaged": triaged, "ai_summary": ai_summary,
        "narrative": narrative(asset.host, view, overall, by_sev, triaged, profile_words),
        "top": [f for f in findings if f.get("severity") in ("critical", "high")
                and f["counted"] > 0][:5] or [f for f in findings if f["counted"] > 0][:5],
        "ran": ran, "skipped": skipped, "engines": engines,
        "profile": profile, "profile_text": dast_engines.PROFILES.get(profile, ""),
        "limitations": limitations, "links": links, "sast": counts,
        "tele": tele, "fields": fields,
        "environment": external.environments(db).get(asset.environment, asset.environment or ""),
        "started": started, "finished": finished,
        "duration": int((finished - started).total_seconds()) if started and finished else None,
        "organization_name": organization,
    }


def filename(asset, scan) -> str:
    when = (scan.scanned_at or scan.started_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    host = re.sub(r"[^A-Za-z0-9.-]+", "-", asset.host)
    return f"dast-report-{host}-{when}-scan-{scan.id}.pdf"


def render_pdf(html: str, logo: str = "", organization: str = "") -> bytes:
    """Typeset the report.  The typesetter may fetch the logo and nothing else."""
    from weasyprint import HTML

    from app.web.routes_pages import report_url_fetcher

    def finisher(_document, pdf):
        import pydyf
        who = organization or "Dynamic Scan Report"
        pdf.info["Producer"] = pydyf.String(who)
        pdf.info["Creator"] = pydyf.String(who)

    return HTML(string=html, base_url="https://report.invalid/",
                url_fetcher=report_url_fetcher(logo or "")).write_pdf(finisher=finisher)


def host_of(url: str) -> str:
    return urlparse(url or "").hostname or ""
