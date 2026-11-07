"""A mitmproxy addon for one scan.

The stock engines (ffuf, nikto, nuclei, wapiti, sqlmap, dalfox) are each pointed
at a local mitmproxy for the run.  This addon then does two things to every
request they make:

    stamps the signed in session on it, so every engine sees what a signed in
    user sees, not just the engines that sign in well on their own

    refuses any host the scan is not scoped to, so an engine that follows a
    link or a redirect off the target cannot touch anything but the sites the
    scan is allowed to reach

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
_ENFORCE = os.environ.get("GCR_MITM_SCOPE", "1") == "1"


def _in_scope(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for allowed in _HOSTS:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if _ENFORCE and _HOSTS and not _in_scope(host):
        flow.response = http.Response.make(
            403, b"blocked: out of the scan's scope\n",
            {"Content-Type": "text/plain"})
        return
    for name, value in _AUTH.items():
        flow.request.headers[str(name)] = str(value)
