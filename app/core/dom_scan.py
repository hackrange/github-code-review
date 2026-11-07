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
