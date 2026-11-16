"""Client side findings from a rendered page.

A headless browser loads the page, runs its scripts, and hands back the
JavaScript it loaded (bundles and inline), the page HTML, and any source maps.
This reads them for two things that are proof, not a guess:

    a secret hardcoded in the JavaScript, matched on a distinctive vendor
    format, so a match is a real key that every visitor can read

    source code left exposed through a source map that carries it

Deterministic, no AI.  The secret value is redacted in the finding so the
report does not itself carry it.
"""

from __future__ import annotations

import re

# (what it is, severity, pattern).  The patterns carry metacharacters on
# purpose, so this file never holds a literal that looks like a real secret.
_SECRETS = [
    ("an AWS access key id", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("a Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("a Stripe live secret key", "high", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}")),
    ("a GitHub token", "high", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("a GitHub fine grained token", "high", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}")),
    ("a Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("a SendGrid API key", "high", re.compile(r"\bSG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{30,}")),
    ("a Mailgun API key", "medium", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("a private key", "critical", re.compile(r"-----BEGIN [A-Z0-9 ]{0,24}PRIVATE KEY-----")),
    ("a JSON Web Token", "medium", re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{8,}")),
]


def _redact(value: str) -> str:
    value = (value or "").strip()
    if len(value) <= 10:
        return value[:2] + "***"
    return value[:4] + "***" + value[-4:]


def scan(collected: dict, base_url: str) -> list:
    """collected = {scripts: [{url, text}], inline: [text], maps: [{url, text}]}.
    -> a list of findings in the engine shape."""
    from app.core import dast_engines

    sources = []
    for s in collected.get("scripts") or []:
        sources.append((str(s.get("url") or base_url), s.get("text") or ""))
    for i, text in enumerate(collected.get("inline") or []):
        sources.append((f"{base_url}#inline-{i + 1}", text or ""))

    findings, seen = [], set()
    for where, text in sources:
        for label, severity, pattern in _SECRETS:
            m = pattern.search(text)
            if not m:
                continue
            key = (label, where.split("#")[0])
            if key in seen:
                continue
            seen.add(key)
            inline = "#inline-" in where
            place = "an inline script on the page" if inline else f"the script {where}"
            findings.append(dast_engines._finding(
                tool="dom",
                title=f"{label[0].upper()}{label[1:]} is hardcoded in client side JavaScript",
                severity=severity, url=where.split("#")[0],
                evidence=(f"{place} served to every visitor contains {label}: "
                          f"{_redact(m.group(0))} (redacted).  It is readable by anyone in the "
                          "page source, so treat it as public and already compromised."),
                fix="Move the secret to the server side, never ship it in client code, and "
                    "rotate it now.",
                cwe="CWE-615"))

    for s in collected.get("maps") or []:
        if '"sourcesContent"' in (s.get("text") or ""):
            findings.append(dast_engines._finding(
                tool="dom",
                title="The application source is exposed through a source map",
                severity="low", url=str(s.get("url") or base_url),
                evidence=(f"The source map at {s.get('url')} carries the original source in its "
                          "sourcesContent, so the unminified application code can be read."),
                fix="Do not deploy source maps to production, or restrict access to them.",
                cwe="CWE-540"))
    return findings


# ------------------------------------------- the API calls a page's code makes

# A single page app keeps where its API lives in a configuration object, and
# builds each call by adding a name to it.  Minifying renames the objects but
# keeps the property names, so these survive a production build.
_BASE_KEYS = r"(?:base_?url|api_?url|api_?base(?:_?url)?|api_?endpoint|api_?root|service_?url|backend_?url|api_?host)"
_BASE_VALUE = re.compile(r"\b" + _BASE_KEYS + r"""\s*[:=]\s*["'`](https?://[^"'`\s]{4,200})["'`]""", re.I)
_JOINED = re.compile(
    r"\b" + _BASE_KEYS + r"""\s*\}?\s*\+\s*["'`]([^"'`\s]{2,160})["'`]|"""
    r"\$\{[\w.$]*?" + _BASE_KEYS + r"""\}([^`$\s]{2,160})""", re.I)
_ABSOLUTE = re.compile(r"""["'`](https?://([A-Za-z0-9.\-]+)(/[A-Za-z0-9_\-./{}%]*)?(?:\?[^"'`\s]*)?)["'`]""")
MAX_CALLS = 120


def _clean_call(path: str) -> str:
    """A path to ask for: values dropped, parameter names kept with an empty value."""
    from urllib.parse import parse_qsl, urlsplit

    parts = urlsplit(path)
    base = re.sub(r"\{[^}/]*\}|\$\{[^}]*\}", "1", parts.path or "/")
    base = re.sub(r"/{2,}", "/", base if base.startswith("/") else "/" + base)
    if not re.fullmatch(r"/[A-Za-z0-9._~\-/%]*", base):
        return ""
    names = [k for k, _v in parse_qsl(parts.query, keep_blank_values=True)
             if re.fullmatch(r"[A-Za-z_][\w\-]{0,40}", k)]
    query = "&".join(f"{k}=" for k in dict.fromkeys(names))
    return base + (f"?{query}" if query else "")


from app.core.dast_paths import STATIC  # noqa: E402 - pictures and styles are not calls


def api_calls(collected: dict, site_host: str, hosts) -> dict:
    """The calls the page's code makes to other sites on the list.

    hosts are the host names of the sites being scanned; a call to anywhere
    else is never kept, so this can only point a scan at a site already in
    scope.  -> {host: [path, ...]}"""
    from urllib.parse import urljoin, urlsplit

    hosts = {h.lower() for h in hosts or ()} - {(site_host or "").lower()}
    if not hosts:
        return {}
    texts = [s.get("text") or "" for s in collected.get("scripts") or []]
    texts += [t or "" for t in collected.get("inline") or []]
    out: dict = {}

    def keep(url: str):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host not in hosts:
            return
        path = _clean_call(parts.path + (f"?{parts.query}" if parts.query else ""))
        if path and STATIC.search(path.split("?")[0]):
            return
        if path and path != "/":
            bucket = out.setdefault(host, [])
            if path not in bucket and sum(len(v) for v in out.values()) < MAX_CALLS:
                bucket.append(path)

    for text in texts:
        bases = [m.group(1) for m in _BASE_VALUE.finditer(text)]
        bases = [b for b in bases if (urlsplit(b).hostname or "").lower() in hosts]
        for m in _ABSOLUTE.finditer(text):
            if (m.group(2) or "").lower() in hosts and m.group(3) and m.group(3) != "/":
                keep(m.group(1))
        if not bases:
            continue
        for m in _JOINED.finditer(text):
            fragment = m.group(1) or m.group(2) or ""
            if fragment.startswith(("http:", "https:", "//")) or not re.match(r"[A-Za-z0-9_/]", fragment):
                continue
            for base in bases:
                keep(urljoin(base if base.endswith("/") else base + "/", fragment.lstrip("/")))
    return out
