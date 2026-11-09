"""A mitmproxy addon for one scan.

The stock engines (ffuf, nikto, nuclei, wapiti, sqlmap, dalfox) are each pointed
at a local mitmproxy for the run.  This addon then does two things to every
request they make:

    stamps the signed in session on it, so every engine sees what a signed in
    user sees, not just the engines that sign in well on their own

    refuses any host the scan is not scoped to, so an engine that follows a
    link or a redirect off the target cannot touch anything but the sites the
    scan is allowed to reach

It also tallies the requests it forwards, so the scan can report how many
requests each tool actually sent (the proxy is the one place that sees them
all).  The count is written to the file named by GCR_MITM_COUNT, which the
parent reads between engines to attribute the count to each tool.

It runs inside the DAST virtual environment's python, which does not have the
app on its path, so it imports only mitmproxy and the standard library, and
takes its settings from the environment the parent set.
"""

import json
import os

from mitmproxy import http

_AUTH = json.loads(os.environ.get("GCR_MITM_AUTH", "{}") or "{}")
_HOSTS = [h.lower().strip().rstrip(".") for h in
          json.loads(os.environ.get("GCR_MITM_HOSTS", "[]") or "[]") if h]
# Where the session goes: the target and its subdomains, never the rest of
# the scope.  A company domain in scope can be another team's site, and a
# redirect or a crawled link there must not carry this site's cookie or token.
# Older callers did not say, so the target (the first scope host) stands in.
_AUTH_HOSTS = [h.lower().strip().rstrip(".") for h in
               json.loads(os.environ.get("GCR_MITM_AUTH_HOSTS", "null") or "null")
               or _HOSTS[:1] if h]
_ENFORCE = os.environ.get("GCR_MITM_SCOPE", "1") == "1"
_COUNT_PATH = os.environ.get("GCR_MITM_COUNT", "")

_sent = 0        # requests forwarded to a target: the attacks the tools sent
_blocked = 0     # requests refused for being out of scope


def _in_scope(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for allowed in _HOSTS:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def _gets_auth(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return bool(host) and any(host == h or host.endswith("." + h) for h in _AUTH_HOSTS)


def _write_count() -> None:
    if not _COUNT_PATH:
        return
    try:
        with open(_COUNT_PATH, "w") as fh:
            json.dump({"sent": _sent, "blocked": _blocked}, fh)
    except OSError:
        pass   # the count is telemetry; never let it affect the scan


def request(flow: http.HTTPFlow) -> None:
    global _sent, _blocked
    host = flow.request.pretty_host
    if _ENFORCE and _HOSTS and not _in_scope(host):
        _blocked += 1
        _write_count()
        flow.response = http.Response.make(
            403, b"blocked: out of the scan's scope\n",
            {"Content-Type": "text/plain"})
        return
    if _gets_auth(host):
        for name, value in _AUTH.items():
            flow.request.headers[str(name)] = str(value)
    _sent += 1
    _write_count()
