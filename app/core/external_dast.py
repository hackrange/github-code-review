"""A basic dynamic scan of one external site.

Not a replacement for a real DAST server.  It is the handful of checks that
can be made with ordinary requests and no state changed on the far side:
what the headers and cookies say, what the TLS pass found, whether files that
should never be served are served, whether the site reflects what it is sent,
and whether a database or remote desktop port is open to the world.

Every check that reads a path compares against a page that cannot exist
first.  Plenty of sites answer 200 with their home page for anything, and a
finding for every path on the list would teach people to ignore the list.  A
path only counts when it answers with content shaped like the thing itself.

Nothing here sends a payload that could change data.  The reflection check
sends a harmless marker in a query string and reads whether it comes back
unescaped.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from urllib.parse import urljoin, urlparse

from app.core import external_probe as probe_mod

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _expiry_severity(days) -> str:
    """Grade a soon to expire certificate by the days it has left.

    Fifteen days or fewer, down to the day it lapses, is high.  Sixteen to
    twenty nine days is medium.  Thirty to forty days is informational, a
    heads up with time to act.  A certificate already past its date is graded
    where the weakness is read, not here.
    """
    if days is None:
        return "medium"
    if days <= 15:
        return "high"
    if days <= 29:
        return "medium"
    return "info"

# path, what it is, severity, a pattern its body must match, and how to fix it.
SENSITIVE_PATHS = [
    ("/.git/HEAD", "Git repository metadata is served", "high",
     r"^ref:\s*refs/|^[0-9a-f]{40}\s*$",
     "Block the .git directory at the web server, or deploy without it.  "
     "Anybody can rebuild the source and its history from it."),
    ("/.git/config", "Git configuration is served", "high",
     r"\[core\]|\[remote \"",
     "Block the .git directory at the web server, or deploy without it."),
    ("/.env", "An environment file is served", "critical",
     r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S",
     "Remove the file from the web root and rotate every secret it held."),
    ("/.svn/entries", "Subversion metadata is served", "high",
     r"^\d+\s*$|<wc-entries|dir\n",
     "Block the .svn directory at the web server, or deploy without it."),
    ("/.DS_Store", "A macOS folder index is served", "low",
     r"Bud1",
     "Remove .DS_Store files from the web root.  They list the folder's files."),
    ("/server-status", "Apache server status is public", "medium",
     r"Apache Server Status for|Server uptime:",
     "Limit mod_status to the addresses that need it."),
    ("/phpinfo.php", "phpinfo() is public", "high",
     r"<title>phpinfo\(\)</title>|PHP Version \d",
     "Delete the page.  It lists the server's paths, modules and settings."),
    ("/actuator/env", "Spring Boot actuator environment is public", "critical",
     r"\"propertySources\"|\"activeProfiles\"",
     "Turn off or protect the actuator endpoints.  This one can hold secrets."),
    ("/actuator/heapdump", "Spring Boot heap dump is public", "critical",
     r"^JAVA PROFILE",
     "Turn off or protect the actuator endpoints.  A heap dump holds secrets "
     "and session data in the clear."),
    ("/actuator", "Spring Boot actuator index is public", "medium",
     r"\"_links\"\s*:\s*\{",
     "Expose only health and info, and put the rest behind authentication."),
    ("/web.config", "IIS web.config is served", "high",
     r"<configuration[\s>]",
     "Block the file at the web server."),
    ("/WEB-INF/web.xml", "A Java web.xml is served", "high",
     r"<web-app[\s>]",
     "Block WEB-INF at the web server or proxy."),
    ("/crossdomain.xml", "Flash cross domain policy allows any site", "medium",
     r"allow-access-from\s+domain=\"\*\"",
     "Remove the file, or name the domains that really need it."),
    ("/elmah.axd", "ELMAH error log is public", "high",
     r"Error Log for|ELMAH",
     "Restrict ELMAH to local requests or remove it."),
    ("/debug/pprof/", "Go pprof debugging is public", "high",
     r"Types of profiles available|/debug/pprof/",
     "Do not register pprof on a public listener."),
    ("/swagger.json", "API description is public", "info",
     r"\"swagger\"\s*:|\"openapi\"\s*:",
     "Fine if the API is meant to be public.  Otherwise put it behind sign in."),
    ("/openapi.json", "API description is public", "info",
     r"\"openapi\"\s*:",
     "Fine if the API is meant to be public.  Otherwise put it behind sign in."),
    ("/v2/api-docs", "API description is public", "info",
     r"\"swagger\"\s*:",
     "Fine if the API is meant to be public.  Otherwise put it behind sign in."),
]

# Body text that should never reach a visitor.  From the nextgen-dast
# information disclosure probe.
DISCLOSURE_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace", "medium"),
    (r"PHP Fatal error|PHP Warning:", "PHP error", "medium"),
    (r"java\.lang\.\w+Exception", "Java exception", "medium"),
    (r"at \w+(?:\.\w+)+\(\w+\.java:\d+\)", "Java stack trace", "medium"),
    (r"You have an error in your SQL syntax", "MySQL error", "high"),
    (r"ORA-\d{5}", "Oracle error", "medium"),
    (r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark",
     "SQL Server error", "high"),
    (r"Werkzeug Debugger", "Flask debugger", "critical"),
    (r"<title>Django[^<]*Debug|DEBUG\s*=\s*True", "Django debug page", "high"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id in the page", "high"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key in the page", "critical"),
    (r"<title>Index of /", "Directory listing", "medium"),
]

# Libraries whose version is in the file name often enough to read it.
# name, pattern on a script address, the first version that is fine, why.
LIBRARIES = [
    ("jQuery", r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", "3.5.0",
     "Versions before 3.5.0 have cross site scripting flaws in their HTML "
     "handling (CVE-2020-11022, CVE-2020-11023)."),
    ("AngularJS", r"angular(?:js)?[/.-](1\.\d+\.\d+)(?:/angular)?(?:\.min)?\.js", "99.0.0",
     "AngularJS 1.x reached end of life in January 2022 and gets no fixes."),
    ("Bootstrap", r"bootstrap[/.-](\d+\.\d+\.\d+)(?:/js)?(?:/bootstrap)?(?:\.bundle)?(?:\.min)?\.js",
     "3.4.1", "Versions before 3.4.1 have cross site scripting flaws in "
     "data attributes (CVE-2019-8331)."),
    ("Lodash", r"lodash[/.-](\d+\.\d+\.\d+)(?:/lodash)?(?:\.min)?\.js", "4.17.21",
     "Versions before 4.17.21 have prototype pollution and command injection "
     "flaws (CVE-2021-23337)."),
]


def _version(text: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def _finding(check, title, severity, url, evidence, fix, cwe=""):
    return {"id": hashlib.sha256(f"{check}|{title}|{url}".encode()).hexdigest()[:12],
            "check": check, "title": title, "severity": severity,
            "url": url, "evidence": (evidence or "")[:500], "remediation": fix,
            "cwe": cwe}


def _base_url(rec: dict, host: str) -> str:
    final = rec.get("final_url") or ""
    parsed = urlparse(final)
    if parsed.scheme in ("http", "https") and parsed.hostname == host:
        return f"{parsed.scheme}://{parsed.netloc}/"
    ports = rec.get("ports") or []
    return f"https://{host}/" if 443 in ports or not ports else f"http://{host}/"


def scan(host: str, allow_private: bool = False) -> dict:
    """Run every check.  -> {findings, telemetry, base_url, requests}"""
    rec = probe_mod.probe(host, screenshots=False, allow_private=allow_private)
    findings = []
    if rec["category"] in ("noresolve", "private", "none"):
        return {"findings": findings, "telemetry": rec, "base_url": "",
                "requests": 0,
                "note": probe_mod.CATEGORY_NAMES.get(rec["category"], rec["category"])}

    base = _base_url(rec, host)
    count = 0

    def get(url, **kw):
        nonlocal count
        count += 1
        return probe_mod.fetch(url, allow_private=allow_private, **kw)

    # ---- ports that should not face the internet.  Not when nearly every
    # port answers: that is a CDN or firewall accepting everything, and a
    # finding for each would be a list of things that are not there.
    for port in ([] if rec.get("ports_unreliable") else rec.get("ports") or []):
        if port in probe_mod.RISKY_PORTS:
            what = probe_mod.RISKY_PORTS[port]
            findings.append(_finding(
                "ports", f"{what} is reachable from the internet (port {port})",
                "high" if port in (2375, 6379, 9200, 11211, 27017, 23) else "medium",
                f"{host}:{port}", f"TCP {port} accepted a connection",
                "Close the port at the firewall, or allow only the addresses "
                "that need it.", "CWE-284"))

    # ---- TLS
    tls = rec.get("tls") or {}
    for weakness in tls.get("weaknesses") or []:
        wl = weakness.lower()
        if "already expired" in wl:
            sev = "high"
        elif "expires soon" in wl:
            sev = _expiry_severity(tls.get("days_left"))
        elif "not trusted" in wl:
            sev = "high"
        else:
            sev = "medium"
        findings.append(_finding("tls", weakness, sev, f"https://{host}/", weakness,
                                 "Fix the TLS configuration or the certificate.",
                                 "CWE-326"))
    if rec.get("http_to_https") is False:
        findings.append(_finding(
            "transport", "Plain HTTP does not redirect to HTTPS", "low",
            f"http://{host}/", "port 80 answered without sending people to https",
            "Redirect every http request to https, and send HSTS.", "CWE-319"))
    if 443 not in (rec.get("ports") or []) and rec.get("status"):
        findings.append(_finding(
            "transport", "The site is only served over plain HTTP", "medium",
            base, "nothing listens on 443", "Serve the site over HTTPS.", "CWE-319"))

    # ---- headers
    headers = rec.get("headers") or {}
    is_html = "html" in headers.get("content-type", "")
    for name, label in (("strict-transport-security", "HSTS"),
                        ("content-security-policy", "Content-Security-Policy"),
                        ("x-content-type-options", "X-Content-Type-Options")):
        if headers and name not in headers and (is_html or name != "content-security-policy"):
            findings.append(_finding(
                "headers", f"{label} header is missing", "low" if name != "x-content-type-options" else "info",
                rec.get("final_url") or base, f"no {name} on the front page",
                f"Send {label} on every response.", "CWE-693"))
    if headers and is_html and "x-frame-options" not in headers and \
            "frame-ancestors" not in headers.get("content-security-policy", ""):
        findings.append(_finding(
            "headers", "The page can be framed by any site (clickjacking)", "low",
            rec.get("final_url") or base, "no X-Frame-Options and no CSP frame-ancestors",
            "Send X-Frame-Options: DENY, or CSP frame-ancestors 'self'.", "CWE-1021"))
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = headers.get(name, "")
        if re.search(r"\d+\.\d+", value):
            findings.append(_finding(
                "headers", f"{name} header gives the software version", "info",
                rec.get("final_url") or base, f"{name}: {value}",
                "Stop the server announcing its version.", "CWE-200"))

    # ---- cookies
    secure_site = (rec.get("final_url") or "").startswith("https://")
    for raw in rec.get("set_cookies") or []:
        cname = raw.split("=", 1)[0].strip()
        flags = raw.lower()
        missing = []
        if secure_site and "; secure" not in flags and not flags.endswith("secure"):
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            looks_session = bool(re.search(r"sess|auth|token|sid|jwt|login", cname, re.I))
            findings.append(_finding(
                "cookies", f"Cookie {cname} is missing {', '.join(missing)}",
                "medium" if looks_session and ("Secure" in missing or "HttpOnly" in missing) else "low",
                rec.get("final_url") or base, raw.split(";", 1)[0][:40] + "; " +
                "; ".join(p.strip() for p in raw.split(";")[1:])[:200],
                "Set Secure, HttpOnly and SameSite on cookies, session cookies first.",
                "CWE-614"))

    # ---- what the front page says
    body = rec.get("body_sample") or ""
    for pattern, label, severity in DISCLOSURE_PATTERNS:
        m = re.search(pattern, body)
        if m:
            findings.append(_finding(
                "disclosure", f"{label} on the front page", severity,
                rec.get("final_url") or base, m.group(0)[:200],
                "Turn off debug output and detailed errors in production.", "CWE-200"))
    for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)", body, re.I)[:80]:
        for name, pattern, fixed, why in LIBRARIES:
            m = re.search(pattern, src, re.I)
            if m and _version(m.group(1)) < _version(fixed):
                findings.append(_finding(
                    "libraries", f"{name} {m.group(1)} is out of date", "medium",
                    urljoin(rec.get("final_url") or base, src), src[:300],
                    f"Upgrade {name}.  {why}", "CWE-1104"))
    if (rec.get("final_url") or "").startswith("http://") and \
            re.search(r"<input[^>]+type=[\"']?password", body, re.I):
        findings.append(_finding(
            "transport", "A password form is served over plain HTTP", "high",
            rec.get("final_url"), "a password input on an http page",
            "Serve every page with a sign in form over HTTPS.", "CWE-319"))

    # ---- CORS
    origin = "https://gcr-cors-check.invalid"
    got = get(base, headers={"Origin": origin}, body_limit=2048)
    allowed = got["headers"].get("access-control-allow-origin", "")
    creds = got["headers"].get("access-control-allow-credentials", "").lower() == "true"
    if allowed == origin and creds:
        findings.append(_finding(
            "cors", "CORS trusts any origin and allows credentials", "high", base,
            f"Origin {origin} was echoed back with Allow-Credentials true",
            "Check the Origin against a list of your own sites.", "CWE-942"))
    elif allowed == origin:
        findings.append(_finding(
            "cors", "CORS echoes back any origin", "low", base,
            f"Origin {origin} was echoed back",
            "Check the Origin against a list of your own sites.", "CWE-942"))

    # ---- TRACE
    got = get(base, method="TRACE", headers={"X-GCR-Trace": "gcr-trace-check"},
              body_limit=4096)
    if got["status"] == 200 and "gcr-trace-check" in got["body"]:
        findings.append(_finding(
            "methods", "HTTP TRACE is enabled", "low", base,
            "TRACE echoed the request headers back",
            "Turn TRACE off at the web server.", "CWE-693"))

    # ---- reflection
    marker = "gcr" + secrets.token_hex(4)
    probe_value = f'{marker}"\'<b{marker}>'
    got = get(base + "?gcrq=" + probe_value.replace('"', "%22").replace("'", "%27")
              .replace("<", "%3C").replace(">", "%3E"), body_limit=BODY_LIMIT_REFLECT)
    if f"<b{marker}>" in got["body"] and "html" in got["headers"].get("content-type", ""):
        findings.append(_finding(
            "reflection", "A query parameter is reflected without encoding (possible XSS)",
            "medium", base + "?gcrq=...",
            f"<b{marker}> came back as markup in the page",
            "Encode output for the context it lands in.  Confirm with a full DAST "
            "scan: this check does not run script.", "CWE-79"))

    # ---- files that should never be served
    control = get(urljoin(base, f"/gcr-{secrets.token_hex(6)}.txt"), body_limit=8192)
    control_hash = hashlib.sha256(control["body"].encode()).hexdigest()
    for path, title, severity, signature, fix in SENSITIVE_PATHS:
        url = urljoin(base, path)
        got = get(url, follow=False, body_limit=8192)
        if got["status"] != 200 or not got["body"]:
            continue
        if hashlib.sha256(got["body"].encode()).hexdigest() == control_hash:
            continue
        if control["status"] == 200 and abs(len(got["body"]) - len(control["body"])) < 32 \
                and "html" in got["headers"].get("content-type", ""):
            continue
        m = re.search(signature, got["body"])
        if not m:
            continue
        findings.append(_finding("exposure", title, severity, url,
                                 _mask(m.group(0)), fix, "CWE-538"))

    # Worst first, and one of each.
    seen, unique = set(), []
    for f in sorted(findings, key=lambda f: SEVERITY_ORDER.index(f["severity"])):
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
    return {"findings": unique, "telemetry": rec, "base_url": base,
            "requests": count}


BODY_LIMIT_REFLECT = 262144


def _mask(text: str) -> str:
    """Evidence without the secret in it.  KEY=VALUE keeps the key."""
    return re.sub(r"(=\s*)(\S{4})\S*", r"\1\2****", text)[:200]


def rollup(findings: list) -> dict:
    """-> {severity, critical, high, medium, low, info}"""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings or []:
        sev = str(f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    worst = next((s for s in SEVERITY_ORDER if counts[s]), "none")
    return {"severity": worst, **counts}
