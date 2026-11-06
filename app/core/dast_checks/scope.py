"""The scope gate: only the company's own domains may ever be probed.

Every enhanced check, and every single request it makes, passes through here
first.  A host is allowed only when it is one of the domains listed in
Settings (the Domains field, web.company_domains), or a subdomain under one of
them.  Anything else is refused before a packet goes out.

This is a hard gate, not a warning.  It runs in two places: the runner refuses
to start a rule against a host that fails, and the HTTP client the rules use
refuses each request whose host fails, so a probe cannot follow a redirect or
a link to some other site.  The product is for scanning assets the company
owns and hosts, and this is what holds that line in code.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def _norm(name: str) -> str:
    """A host or domain in one shape: lower case, no port, no trailing dot."""
    name = (name or "").strip().lower()
    if not name:
        return ""
    # Drop a scheme or path if a whole URL was passed by mistake.
    if "://" in name:
        name = urlparse(name).hostname or ""
    # Strip a port, but leave an IPv6 literal in brackets alone.
    if name.startswith("["):
        name = name.split("]", 1)[0].lstrip("[")
    elif name.count(":") == 1:
        name = name.split(":", 1)[0]
    return name.rstrip(".")


def company_domains(raw) -> list:
    """The listed domains, cleaned.  Accepts a list or a comma or space list."""
    if isinstance(raw, str):
        parts = raw.replace(",", " ").split()
    else:
        parts = list(raw or [])
    out = []
    for item in parts:
        name = _norm(str(item))
        if name and name not in out:
            out.append(name)
    return out


def _under(host: str, domain: str) -> bool:
    """Is host the domain itself, or a subdomain under it?"""
    if not host or not domain:
        return False
    if host == domain:
        return True
    # A real label boundary, so "evilexample.com" is not under "example.com".
    return host.endswith("." + domain)


def allowed(host: str, domains) -> bool:
    """True only when host is one of the listed domains or under one.

    An IP address is allowed only when it is listed in the Domains field
    exactly.  Nothing matches an empty list, so with no domains set, nothing
    is in scope and every check is refused.
    """
    host = _norm(host)
    listed = domains if isinstance(domains, list) else company_domains(domains)
    if not host or not listed:
        return False
    # An IP literal only matches an identical listed entry, never a suffix.
    try:
        ipaddress.ip_address(host)
        return host in listed
    except ValueError:
        pass
    return any(_under(host, d) for d in listed)


def refuse_reason(host: str, domains) -> str:
    """Empty when host is in scope, else a short sentence saying why not.

    Safe to show an administrator.  It names the host and points at the
    Domains field, and never leaks anything else about what is configured.
    """
    if allowed(host, domains):
        return ""
    clean = _norm(host) or "that host"
    listed = domains if isinstance(domains, list) else company_domains(domains)
    if not listed:
        return ("No company domains are set, so nothing is in scope.  Add the "
                "company's domains in Settings (the Domains field) first.")
    return (f"{clean} is not one of the company's domains, so it is out of "
            "scope.  Enhanced checks only run against hosts listed in Settings "
            "(the Domains field), or subdomains under them.")
