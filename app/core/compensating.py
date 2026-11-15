"""What stands between a weakness and the harm: controls that are there, and
protections to add while a code fix waits.

Both reports use this, the code report and the external site report, so an
executive reading either sees the same three things beside the findings:

  * Strengths: the security controls the evidence shows the application has.
    A report that is only a list of problems misleads in its own way: it
    tells a reader nothing about whether they are looking at a well built
    application with a few gaps or a poor one.
  * Compensating controls: for each finding, the controls already in front of
    it that lower how likely it is to be used, said plainly, never as a
    reason to leave it.  A control is only named when the evidence shows it
    is there: a header the site sends, a firewall that blocked the scanner, a
    site reachable only from allow listed addresses.  A firewall vendor's
    name in a response header is said to be in front of the site, not to be
    blocking anything, because the header says nothing about its rules.
  * Interim protections: what can be put in place in days, while a code fix
    that takes longer is made.  A fixed library per class of weakness, the
    same wherever it applies, so it is never invented for the occasion.

Nothing here asks a model.
"""

from __future__ import annotations

import re

# ---- what kind of weakness a finding is -------------------------------------

_CWE_CLASS = {
    "xss": {79, 80, 83, 87},
    "sqli": {89, 564},
    "cmdi": {77, 78, 94, 95},
    "ssrf": {918},
    "object-authz": {639, 566},
    "function-authz": {862, 863, 285, 284, 425},
    "auth": {287, 288, 290, 294, 306, 307, 384, 521, 613, 620, 640},
    "csrf": {352},
    "secrets": {798, 259, 321, 538, 530, 532, 312, 522, 615},
    "tls": {295, 297, 319, 326, 327, 757},
    "clickjacking": {1021},
    "redirect": {601},
    "disclosure": {200, 209, 497, 548, 215, 497, 540},
    "files": {22, 23, 35, 73, 434},
    "deserialize": {502},
    "component": {1104, 937, 1035, 1395},
    "headers": {693, 614, 1004, 16},
    "privilege": {250, 269, 732, 276},
    "model": {1426, 1427},
    "logic": {840, 841, 602, 639},
    "dos": {400, 770, 1333, 409},
    "cors": {942, 346},
    "rebind": {367},
}
_WORD_CLASS = [
    ("xss", r"cross.?site script|\bxss\b|innerhtml|html injection"),
    ("sqli", r"sql injection|\bsqli\b"),
    ("cmdi", r"command injection|os command|remote code|code execution|\brce\b"),
    ("ssrf", r"\bssrf\b|server.?side request"),
    ("object-authz", r"\bidor\b|\bbola\b|object.level|another user'?s|cross.?(user|tenant|vendor)"),
    ("function-authz", r"\bbfla\b|function.level|privilege escalation|missing (role|permission|authori)"),
    ("auth", r"authenticat|session|login|sign.?in|saml|oidc|password|mfa|totp|brute"),
    ("csrf", r"\bcsrf\b|request forgery"),
    ("secrets", r"secret|credential|api key|token|password in|private key"),
    ("tls", r"\btls\b|\bssl\b|certificate|cipher|hsts"),
    ("clickjacking", r"clickjack|frame-ancestors|x-frame-options"),
    ("redirect", r"open redirect"),
    ("disclosure", r"disclos|stack trace|verbose error|version (banner|header)|exposed|directory listing"),
    ("files", r"path traversal|directory traversal|file upload|local file"),
    ("component", r"outdated|end of life|vulnerable version|\bcve-\d"),
    ("headers", r"header|cookie (flag|attribute)|httponly|samesite|secure flag"),
    ("privilege", r"\broot\b|sudo|privileged|least privilege"),
    ("model", r"prompt injection|\bllm\b|language model|model output"),
    ("cors", r"\bcors\b|cross.?origin"),
    ("dos", r"denial of service|rate limit|resource exhaustion|unbounded"),
]


def classes_of(finding: dict) -> set:
    """The weakness classes one finding belongs to, from its CWE and its words."""
    out = set()
    for raw in re.findall(r"CWE-?(\d+)", " ".join(str(finding.get(k) or "") for k in
                                                   ("cwe", "cwe_ids", "rule", "rule_id"))):
        n = int(raw)
        out |= {name for name, ids in _CWE_CLASS.items() if n in ids}
    text = " ".join(str(finding.get(k) or "") for k in ("title", "name", "description",
                                                       "rule", "rule_id", "what")).lower()
    for name, pattern in _WORD_CLASS:
        if re.search(pattern, text):
            out.add(name)
    return out


# ---- what can be put in place while the code fix waits -----------------------

# Each one a step an operations or platform team can take in days, without
# changing the application's code, that lowers the chance of the weakness being
# used.  Never a substitute for the fix, and the report says so.
INTERIM = {
    "xss": [
        "Send a Content-Security-Policy that allows scripts only from your own origin "
        "with a per page nonce, and no unsafe-inline.",
        "Turn on the web application firewall's cross site scripting rules for the "
        "affected pages.",
        "Set session cookies HttpOnly so a script that does run cannot read them.",
    ],
    "sqli": [
        "Add a web application firewall rule that blocks SQL syntax in the affected "
        "parameter (a virtual patch).",
        "Give the application's database account only the rights it needs, so an "
        "injected statement cannot change permissions or drop tables.",
        "Alert on database errors and on unusual query volume from the application.",
    ],
    "cmdi": [
        "Block the affected route at the proxy or firewall until the fix ships, or "
        "allow it only from administrator addresses.",
        "Run the application as an account with no sudo rights, in a container with "
        "no extra capabilities.",
        "Alert on unexpected child processes started by the web server.",
    ],
    "ssrf": [
        "Block outbound traffic from the application to private ranges, link local "
        "addresses and the cloud metadata address 169.254.169.254 at the network.",
        "Send the application's outbound requests through an egress proxy that "
        "allows only the hosts it needs.",
        "Require the cloud metadata service's session tokens (IMDSv2 or the "
        "equivalent), so a forged request cannot read credentials.",
    ],
    "object-authz": [
        "Log every request for an object along with who asked, and alert when one "
        "account reads many objects it does not own.",
        "Rate limit the affected routes per account, so records cannot be walked "
        "quickly.",
        "Where ids are sequential numbers, expose a random identifier instead "
        "while the ownership check is added.",
    ],
    "function-authz": [
        "Allow the affected route at the proxy or firewall only from "
        "administrator addresses, or switch the feature off, until the role check "
        "ships.",
        "Review who holds the roles that can reach it, and remove accounts that "
        "do not need them.",
        "Alert on use of the affected action by accounts outside the intended role.",
    ],
    "auth": [
        "Require multi factor sign in for every account, starting with "
        "administrators.",
        "Shorten session lifetimes and end every session when an account is "
        "disabled or its role changes.",
        "Rate limit sign in attempts per account and per address, and alert on "
        "repeated failures.",
    ],
    "csrf": [
        "Set session cookies SameSite=Lax or Strict.",
        "Check the Origin header on state changing requests at the proxy.",
    ],
    "secrets": [
        "Rotate the exposed credential now, and review its use since it was "
        "exposed.",
        "Limit where the credential works from (an address allow list or a "
        "narrower scope), so a copy is worth less.",
        "Restrict who can read the place it was exposed (repository, image "
        "registry, logs).",
    ],
    "tls": [
        "Turn on HTTP Strict Transport Security with a long max-age.",
        "Disable old protocol versions and weak ciphers at the load balancer.",
    ],
    "clickjacking": [
        "Send Content-Security-Policy frame-ancestors 'none' (or X-Frame-Options "
        "DENY) from the proxy.",
    ],
    "redirect": [
        "Add a proxy or firewall rule that refuses redirect targets outside your "
        "own domains.",
    ],
    "disclosure": [
        "Block the exposed path at the proxy, and remove version banners from "
        "server headers.",
        "Turn off detailed error pages in production.",
    ],
    "files": [
        "Block traversal sequences and the affected path at the firewall.",
        "Store uploads outside the web root, on a volume where scripts cannot run.",
    ],
    "deserialize": [
        "Block the affected endpoint at the proxy, or allow it only from trusted "
        "addresses, until the fix ships.",
    ],
    "component": [
        "Apply the firewall vendor's virtual patch for the advisory, if one exists.",
        "Restrict who can reach the component, and alert on the advisory's known "
        "attack patterns.",
    ],
    "headers": [
        "Add the missing headers or cookie attributes at the proxy or load "
        "balancer, which needs no code change.",
    ],
    "privilege": [
        "Remove the extra rights from the running container or service account "
        "(sudo rules, privileged mode, write access to code it runs).",
        "Make the application's code read only at run time.",
    ],
    "model": [
        "Have a person confirm any decision a model makes before it is saved.",
        "Mark text from outside the organization clearly as data in prompts, and "
        "alert when model output contradicts stored results.",
    ],
    "logic": [
        "Have a second person approve the affected action until the server "
        "checks the record's state itself.",
        "Alert when the action is used out of its normal order.",
    ],
    "dos": [
        "Rate limit the affected route per account and per address, and cap request "
        "sizes at the proxy.",
    ],
    "cors": [
        "Return Access-Control-Allow-Origin only for your own origins, from the proxy.",
    ],
    "rebind": [
        "Block outbound traffic from the application to private ranges at the "
        "network, so a changed DNS answer cannot reach inside.",
    ],
}
GENERIC_INTERIM = [
    "Restrict who can reach the affected feature (by role, by address, or by turning it "
    "off) until the fix ships, and watch its use in the logs.",
]


def interim_for(finding: dict, limit: int = 3) -> list:
    """Interim protections for one finding, most useful first."""
    out = []
    for name in sorted(classes_of(finding), key=lambda c: list(INTERIM).index(c)
                       if c in INTERIM else 99):
        for step in INTERIM.get(name, []):
            if step not in out:
                out.append(step)
    return (out or GENERIC_INTERIM)[:limit]


# ---- controls a site shows ----------------------------------------------------

def _csp_strength(csp: str) -> str:
    """strong when scripts need a nonce or hash and inline script is off."""
    csp = (csp or "").lower()
    script = re.search(r"script-src([^;]*)", csp) or re.search(r"default-src([^;]*)", csp)
    if not script:
        return "partial"
    src = script.group(1)
    if "'unsafe-inline'" in src and "'nonce-" not in src and "'sha" not in src:
        return "partial"
    if "*" in src.split() or "data:" in src:
        return "partial"
    return "strong"


def site_controls(tele: dict, exposure: str = "") -> list:
    """Controls the external site shows, each {name, detail, lowers, sure}.

    sure is True when the evidence shows the control at work (a header that is
    sent, a block the scanner received), False when it only shows something
    is there whose settings were not seen.
    """
    headers = {str(k).lower(): str(v) for k, v in (tele.get("headers") or {}).items()}
    out = []

    def add(name, detail, lowers, sure=True):
        out.append({"name": name, "detail": detail, "lowers": set(lowers), "sure": sure})

    if (exposure or "") == "whitelisted":
        add("Network allow list", "The site answers only from allow listed addresses; from "
            "the open internet it does not.  An outside attacker cannot reach it without "
            "first getting onto an allowed network.",
            set(_CWE_CLASS) | {"logic"})
    if tele.get("waf_block"):
        add("Web application firewall, seen blocking", "A firewall in front of the site "
            "refused the scanner's requests, so attack payloads are being filtered "
            "before they reach the application.", {"xss", "sqli", "cmdi", "files", "component",
                                                    "redirect"})
    elif tele.get("cdn"):
        add(f"{tele['cdn']} in front of the site", f"The site is served through "
            f"{tele['cdn']}, which can filter attacks and absorb floods.  Whether its "
            "firewall rules are switched on was not seen.", {"dos"}, sure=False)
    if tele.get("bot_check"):
        add(f"{tele['bot_check']} bot protection", "Automated clients are challenged "
            "before they reach the site, which slows password guessing, scraping and "
            "scanning.", {"auth", "dos", "object-authz"})
    csp = headers.get("content-security-policy", "")
    if csp:
        strength = _csp_strength(csp)
        if strength == "strong":
            add("Content-Security-Policy", "Scripts must come from approved sources and "
                "inline script needs a per page nonce, so most injected script will not run.",
                {"xss"})
        else:
            add("Content-Security-Policy (partial)", "A policy is sent, but it still allows "
                "inline script or broad sources, so it does little against injected script.",
                set(), sure=False)
        if "frame-ancestors" in csp.lower():
            add("Framing blocked by policy", "Content-Security-Policy frame-ancestors stops "
                "other sites from framing these pages.", {"clickjacking"})
    if headers.get("strict-transport-security"):
        add("HTTP Strict Transport Security", "Browsers are told to use only HTTPS for this "
            "site, so a network attacker cannot downgrade a visit to plain HTTP.", {"tls"})
    if headers.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        add("X-Frame-Options", "Other sites cannot frame these pages.", {"clickjacking"})
    if headers.get("x-content-type-options", "").lower() == "nosniff":
        add("X-Content-Type-Options nosniff", "Browsers will not treat an uploaded or "
            "returned file as a script because of its contents.", {"xss", "files"})
    cookies = [str(c) for c in (tele.get("set_cookies") or [])]
    if cookies:
        lowered = [c.lower() for c in cookies]
        if all("httponly" in c for c in lowered):
            add("Cookies are HttpOnly", "Scripts in the page cannot read the cookies the "
                "site sets, so injected script cannot steal a session that way.", {"xss"})
        if all("secure" in c for c in lowered):
            add("Cookies are Secure", "Cookies are only sent over HTTPS.", {"tls", "auth"})
        if all(re.search(r"samesite=(lax|strict)", c) for c in lowered):
            add("Cookies are SameSite", "Browsers do not send the cookies with requests "
                "started by other sites, which blocks most request forgery.", {"csrf"})
        if any(c.split("=", 1)[0].strip().startswith("__host-") for c in lowered):
            add("__Host- cookie prefix", "The session cookie is locked to this exact host, "
                "path and HTTPS.", {"auth"})
    if tele.get("http_to_https") is True:
        add("HTTP redirects to HTTPS", "Plain HTTP requests are sent to HTTPS.", {"tls"})
    tls = tele.get("tls") or {}
    supported = tls.get("supported") or {}
    if tls.get("negotiated_version") and not any(
            ok for proto, ok in supported.items()
            if str(proto).upper().replace(".", "").replace("V", "") in ("SSL2", "SSL3", "TLS1",
                                                                         "TLS10", "TLS11")):
        add("Modern TLS only", f"The site negotiates {tls['negotiated_version']} and refuses "
            "the old protocol versions.", {"tls"})
    return out


def controls_for(finding: dict, controls: list) -> list:
    """The controls that lower the likelihood of one finding, as short sentences."""
    classes = classes_of(finding)
    out = []
    for c in controls:
        if c["sure"] and c["lowers"] & classes:
            out.append(f"{c['name']}: {c['detail']}")
    return out


def strengths(controls: list, limit: int = 8) -> list:
    """The controls worth naming to an executive, as sentences."""
    return [f"{c['name']}.  {c['detail']}" for c in controls if c["sure"]][:limit]


def annotate(findings: list, controls: list) -> list:
    """Add compensating controls and interim protections to each finding."""
    for f in findings:
        f["compensating"] = controls_for(f, controls)
        f["interim"] = interim_for(f)
    return findings


def site_controls_for_repository(db, repository: str) -> list:
    """Controls in front of the sites a repository is pinned to, for the code report.

    Only sites somebody linked to the repository on purpose; a guessed match is
    not evidence about where this code runs.  -> [{host, controls}]
    """
    from app.core import external
    from app.core.models import ExternalAsset, ExternalAssetRepo, Repository

    repo = db.query(Repository).filter(Repository.full_name == repository).one_or_none()
    if repo is None:
        return []
    assets = (db.query(ExternalAsset)
              .join(ExternalAssetRepo, ExternalAssetRepo.asset_id == ExternalAsset.id)
              .filter(ExternalAssetRepo.repository_id == repo.id).all())
    out = []
    for asset in assets[:5]:
        controls = site_controls(external.telemetry_of(asset),
                                 getattr(asset, "exposure", "") or "")
        if controls:
            out.append({"host": asset.host, "controls": controls})
    return out


def adjust_risk(findings: list, controls: list) -> list:
    """Lower likelihood one step where a control the scan saw at work covers it.

    Only lowering, only one step, never below rare, and never for a finding the
    scan proved: a control that was in place when the exploit worked did not
    stop it.  The network allow list is left out because the exposure weighting
    already counts it.
    """
    from app.core import dast_risk

    order = ["low", "medium", "high", "critical"]
    for f in findings:
        lk, br = f.get("likelihood"), f.get("breachability")
        if not isinstance(lk, int) or not isinstance(br, int) or lk >= 5 or lk <= 1:
            continue
        classes = classes_of(f)
        covering = [c["name"] for c in controls
                    if c["sure"] and c["name"] != "Network allow list" and c["lowers"] & classes]
        if not covering:
            continue
        new_lk = lk - 1
        new_risk = dast_risk.cell(new_lk, br)
        old_risk = f.get("risk") or "low"
        if old_risk in order and new_risk in order and order.index(new_risk) >= order.index(old_risk):
            continue
        f["likelihood"] = new_lk
        f["likelihood_label"] = dast_risk.LIKELIHOOD_LABEL[new_lk]
        f["risk"] = new_risk
        f["risk_basis"] = ((f.get("risk_basis") or "") + "  Likelihood lowered one step for "
                           + ", ".join(covering[:3]) + ", seen in front of the site.").strip()
    return findings
