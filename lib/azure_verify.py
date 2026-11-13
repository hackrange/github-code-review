#!/usr/bin/env python3
"""Decide whether an Azure credential found in code is still live.

Two kinds are handled, because they are the two whose liveness can be read
or checked without touching anything:

  entra_token  a Microsoft Entra (Azure AD) access token, a JWT.  Its own
               payload says when it stops working, so most of the answer is
               there to read with no network at all.  When the live probe is
               on, a single read only call to the issuing resource (Microsoft
               Graph or Azure Resource Manager) says whether the token is
               still accepted.
  sas          an Azure Storage shared access signature.  The query string
               carries its own expiry (se=), read offline.  When the probe is
               on and a full resource URL is in hand, one HEAD says whether
               the signature is still honored.

The offline read is always safe: it sends nothing and leaks nothing, and a
token past its own expiry is dead whatever a server would say.  The live probe
sends the credential to Microsoft, so it is opt in (--probe) and strictly read
only: GET for a token, HEAD for a SAS, no redirects off Azure, and the
destination host must be a Microsoft cloud endpoint whose address resolves to
a public IP.  A live result raises the finding to a confirmed credential; a
definitive dead result (expired, or the provider refused it) is the rare
positive evidence that a credential is not a live one.

Reads one secret from stdin, writes one compact JSON object to stdout.  Never
prints the secret, never fails the scan: on any trouble it prints {} and
exits 0, so the caller merges nothing.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import ipaddress
import json
import socket
import sys
import urllib.error
import urllib.request
from urllib.parse import parse_qs, unquote, urlsplit

# Microsoft cloud endpoints, by role.  Suffixes so a storage account name in
# front of the domain still matches, exact hosts for the fixed service roots.
_GRAPH_HOSTS = {
    "graph.microsoft.com", "graph.microsoft.us", "dod-graph.microsoft.us",
    "microsoftgraph.chinacloudapi.cn",
}
_ARM_HOSTS = {
    "management.azure.com", "management.usgovcloudapi.net",
    "management.chinacloudapi.cn",
}
_STORAGE_SUFFIXES = (
    ".core.windows.net", ".core.usgovcloudapi.net",
    ".core.chinacloudapi.cn", ".core.cloudapi.de",
)
# Audience values that name a resource we know how to probe.  Microsoft Graph
# and ARM each have a stable GUID as well as a URL form.
_GRAPH_AUD = {"https://graph.microsoft.com", "https://graph.microsoft.com/",
              "00000003-0000-0000-c000-000000000000"}
_ARM_AUD = {"https://management.azure.com", "https://management.azure.com/",
            "https://management.core.windows.net",
            "https://management.core.windows.net/",
            "797f4846-ba00-4fd7-ba43-dac1f8f63013"}
_ENTRA_ISSUER_HINTS = ("sts.windows.net", "login.microsoftonline.com",
                       "login.microsoft.com", "login.microsoftonline.us",
                       "login.partner.microsoftonline.cn", "login.windows.net")

_TIMEOUT = 6.0
_UA = "gcr-secret-verifier"  # generic on purpose: never carries who is scanning


def _now() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


def _b64url_json(part: str):
    """Decode one base64url JWT segment to an object, or None."""
    pad = "=" * (-len(part) % 4)
    try:
        raw = base64.urlsafe_b64decode(part + pad)
        obj = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _iso(epoch) -> str | None:
    try:
        return _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


# ---------------------------------------------------------------- classify

def classify(secret: str) -> str:
    """entra_token, sas, or '' for anything this tool does not judge."""
    s = (secret or "").strip()
    if not s:
        return ""
    parts = s.split(".")
    if len(parts) == 3 and all(parts[:2]):
        header = _b64url_json(parts[0])
        body = _b64url_json(parts[1])
        if isinstance(header, dict) and isinstance(body, dict) and "alg" in header:
            if _entra_resource(body) is not None or _is_entra_issuer(body):
                return "entra_token"
            return ""  # a JWT, but not one we can place as Azure
    if "sig=" in s and ("sv=" in s or "se=" in s or "sr=" in s or "sp=" in s):
        return "sas"
    return ""


def _is_entra_issuer(body: dict) -> bool:
    iss = str(body.get("iss") or "").lower()
    return any(h in iss for h in _ENTRA_ISSUER_HINTS)


def _entra_resource(body: dict):
    """Which resource a token is for: 'graph', 'arm', or None (do not probe)."""
    auds = body.get("aud")
    values = auds if isinstance(auds, list) else [auds]
    for aud in values:
        a = str(aud or "").strip().rstrip("/")
        if a in {x.rstrip("/") for x in _GRAPH_AUD} or "graph.microsoft" in a:
            return "graph"
        if a in {x.rstrip("/") for x in _ARM_AUD} or "management.azure" in a \
                or "management.core.windows.net" in a:
            return "arm"
    return None


# ---------------------------------------------------------------- offline

def inspect(secret: str) -> dict:
    """What can be known with no network: kind, expiry, and what to probe."""
    kind = classify(secret)
    out = {"azure_kind": kind, "azure_expired": None, "azure_expires_at": None,
           "azure_resource": "", "_probe_url": "", "_probe_method": "",
           "_bearer": False}
    if kind == "entra_token":
        body = _b64url_json(secret.split(".")[1]) or {}
        exp = body.get("exp")
        if isinstance(exp, (int, float)):
            out["azure_expires_at"] = _iso(exp)
            out["azure_expired"] = exp < _now()
        resource = _entra_resource(body)
        if resource == "graph":
            out["azure_resource"] = "graph.microsoft.com"
            out["_probe_url"] = "https://graph.microsoft.com/v1.0/organization"
            out["_probe_method"], out["_bearer"] = "GET", True
        elif resource == "arm":
            out["azure_resource"] = "management.azure.com"
            out["_probe_url"] = ("https://management.azure.com/subscriptions"
                                 "?api-version=2022-12-01")
            out["_probe_method"], out["_bearer"] = "GET", True
    elif kind == "sas":
        se, host, url = _sas_facts(secret)
        if se is not None:
            out["azure_expires_at"] = _iso(se)
            out["azure_expired"] = se < _now()
        if host:
            out["azure_resource"] = host
        if url:
            out["_probe_url"], out["_probe_method"] = url, "HEAD"
    return out


def _sas_facts(secret: str):
    """(expiry_epoch|None, storage_host|'', full_https_url|'') from a SAS."""
    s = secret.strip()
    split = urlsplit(s if "://" in s else "//" + s.lstrip("/"), scheme="https")
    host = (split.hostname or "").lower()
    query = split.query or (s.split("?", 1)[1] if "?" in s else s)
    params = parse_qs(query, keep_blank_values=True)
    se = None
    if params.get("se"):
        se = _parse_azure_time(unquote(params["se"][0]))
    is_storage = host.endswith(_STORAGE_SUFFIXES)
    url = ""
    if "://" in s and is_storage and split.path:
        # Only a full, path bearing URL on a storage host is probeable.
        url = "https://%s%s?%s" % (host, split.path, split.query)
    return se, (host if is_storage else ""), url


def _parse_azure_time(value: str):
    v = (value or "").strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%MZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d"):
        try:
            dt = _dt.datetime.strptime(v, fmt).replace(tzinfo=_dt.timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------- live probe

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A probe never follows a redirect: the next hop is not where we checked."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _host_is_azure(host: str) -> bool:
    h = (host or "").lower()
    return (h in _GRAPH_HOSTS or h in _ARM_HOSTS or h.endswith(_STORAGE_SUFFIXES))


def _resolves_public(host: str) -> bool:
    """True only if every address the host resolves to is a public one."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    seen = False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
        seen = True
    return seen


def _http(method: str, url: str, token: str, timeout: float):
    """One read only request to a checked Azure host.  (status, headers).

    Isolated so a test can stand in for it without a network.  Refuses any
    URL that is not https to a Microsoft cloud host resolving to a public IP.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not _host_is_azure(parts.hostname or ""):
        raise ValueError("not an Azure https endpoint")
    if not _resolves_public(parts.hostname):
        raise ValueError("host does not resolve to a public address")
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, method=method, headers=headers)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in (err.headers or {}).items()}


def probe(secret: str, facts: dict, timeout: float = _TIMEOUT) -> dict:
    """Ask the provider whether the credential still works.  Read only.

    -> {azure_live: True|False|None, azure_status, azure_detail}.  None means
    the check could not decide, which is not the same as dead.
    """
    out = {"azure_live": None, "azure_status": None, "azure_detail": ""}
    url, method = facts.get("_probe_url") or "", facts.get("_probe_method") or ""
    if not url:
        out["azure_detail"] = "no resource to probe"
        return out
    token = secret if facts.get("_bearer") else ""
    try:
        status, headers = _http(method, url, token, timeout)
    except ValueError as err:
        out["azure_detail"] = str(err)
        return out
    except (urllib.error.URLError, socket.timeout, OSError) as err:
        out["azure_detail"] = "could not reach the provider: %s" % (
            getattr(err, "reason", err),)
        return out
    out["azure_status"] = status
    if facts.get("azure_kind") == "entra_token":
        if status in (200, 403):
            # 403 is a valid token the tenant accepted but without the scope
            # for this read.  Still a live credential.
            out["azure_live"] = True
            out["azure_detail"] = ("accepted by the provider"
                                   if status == 200 else
                                   "accepted, lacks scope for this read")
        elif status == 401:
            out["azure_live"] = False
            out["azure_detail"] = "the provider rejected the token"
        else:
            out["azure_detail"] = "inconclusive status %s" % status
    else:  # sas
        code = (headers.get("x-ms-error-code") or "").strip()
        if status in (200, 206):
            out["azure_live"] = True
            out["azure_detail"] = "the signature was honored"
        elif status == 403 and code in ("AuthenticationFailed",
                                        "AuthorizationFailure",
                                        "AuthenticationFailedSignatureDidNotMatch"):
            out["azure_live"] = False
            out["azure_detail"] = "the signature was refused (%s)" % code
        else:
            out["azure_detail"] = "inconclusive status %s%s" % (
                status, " %s" % code if code else "")
    return out


# ---------------------------------------------------------------- public API

def verify(secret: str, do_probe: bool = False, timeout: float = _TIMEOUT) -> dict:
    """Offline facts, then a live probe when asked, folded into one result.

    Fields the secrets pass merges onto the finding:
      azure_kind, azure_expired, azure_expires_at, azure_resource, azure_live,
      azure_status, azure_detail.
      verification_attempted  true when a live probe actually ran.
      verified                true only when a provider confirmed it live.
      verification_error      the reason it is not a confirmed live credential.
    """
    facts = inspect(secret)
    kind = facts["azure_kind"]
    result = {k: facts[k] for k in ("azure_kind", "azure_expired",
                                    "azure_expires_at", "azure_resource")}
    if not kind:
        return {}  # nothing to say; caller merges nothing
    result["verification_attempted"] = False
    if do_probe and facts.get("_probe_url") and facts.get("azure_expired") is not True:
        # No point spending a request on a token we can already read as expired.
        probed = probe(secret, facts, timeout)
        result.update(azure_live=probed["azure_live"],
                      azure_status=probed["azure_status"],
                      azure_detail=probed["azure_detail"])
        result["verification_attempted"] = True
        if probed["azure_live"] is True:
            result["verified"] = True
        elif probed["azure_live"] is False:
            result["verification_error"] = "Azure verifier: %s" % probed["azure_detail"]
        else:
            result["verification_error"] = "Azure verifier: %s" % (
                probed["azure_detail"] or "could not confirm")
    elif facts.get("azure_expired") is True:
        result["verification_error"] = (
            "Azure verifier: token is past its own expiry (%s)"
            % (facts["azure_expires_at"] or "expired"))
    return result


def main(argv) -> int:
    do_probe = "--probe" in argv
    timeout = _TIMEOUT
    if "--timeout" in argv:
        try:
            timeout = float(argv[argv.index("--timeout") + 1])
        except (ValueError, IndexError):
            timeout = _TIMEOUT
    secret = sys.stdin.read().strip()
    try:
        out = verify(secret, do_probe=do_probe, timeout=timeout)
    except Exception:  # never fail the scan over a verifier
        out = {}
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
