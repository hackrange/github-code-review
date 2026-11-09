"""Whether a site's certificate may carry its credentials.

Scans accept any certificate, because plenty of sites worth testing have a
self signed or internal one, and an unauthenticated scan sends nothing worth
stealing.  A signed in scan is different: it sends the site's password, cookie
or token, and with checking off anybody on the network path could pose as the
site and take them.

Turning checking on would stop every signed in scan of a site whose
certificate this server does not trust.  So it is trust on first use, per site
and host:

  verified   the certificate chains to a trusted authority and names the
             host.  Credentials go, as before.
  pinned     it does not verify, but its fingerprint is the one saved the
             first time.  Credentials go, as before.
  first use  it does not verify and nothing is saved yet.  The fingerprint is
             saved now and credentials go, as before.
  changed    it does not verify and its fingerprint is not the saved one.
             Credentials are withheld and the reason given.  A real renewal
             of a self signed certificate looks like this too, so an
             administrator can clear the saved one on the site's page.

The check is a TLS handshake and nothing else.  No request is sent on it, so a
site posing as the real one learns nothing from it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import socket
import ssl
from urllib.parse import urlparse

from app.core.models import utcnow

log = logging.getLogger("gcr.tls")

TIMEOUT = 10


def _tunnel(host: str, port: int, proxy: str) -> socket.socket:
    """A socket to host:port, through an http proxy when one is set."""
    if not proxy:
        return socket.create_connection((host, port), timeout=TIMEOUT)
    p = urlparse(proxy)
    sock = socket.create_connection((p.hostname, p.port or 80), timeout=TIMEOUT)
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if p.username:
        token = base64.b64encode(f"{p.username}:{p.password or ''}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    reply = b""
    while b"\r\n\r\n" not in reply and len(reply) < 8192:
        chunk = sock.recv(1024)
        if not chunk:
            break
        reply += chunk
    status = reply.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or status[1] != b"200":
        sock.close()
        raise OSError(f"the proxy refused the tunnel: {reply[:60]!r}")
    return sock


def peer(host: str, port: int = 443, proxy: str = "") -> dict:
    """-> {verified: True|False|None, fingerprint, error}.  None means it could not tell."""
    out = {"verified": None, "fingerprint": "", "error": ""}
    try:
        with _tunnel(host, port, proxy) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        out.update(verified=True, fingerprint=hashlib.sha256(der).hexdigest())
        return out
    except ssl.SSLCertVerificationError as exc:
        out["error"] = getattr(exc, "verify_message", "") or str(exc)[:120]
    except (OSError, ssl.SSLError) as exc:
        out["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
        return out
    # It did not verify.  Read the certificate without trusting it, to compare.
    try:
        # Deliberately unverified: nothing is sent on this connection, it only
        # reads the certificate so it can be compared with the saved one.
        loose = ssl.create_default_context()
        loose.check_hostname = False  # nosemgrep: gcr-tls-verify-disabled
        loose.verify_mode = ssl.CERT_NONE  # nosemgrep: gcr-tls-verify-disabled
        with _tunnel(host, port, proxy) as raw:
            with loose.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        out.update(verified=False, fingerprint=hashlib.sha256(der).hexdigest())
    except (OSError, ssl.SSLError) as exc:
        out["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    return out


def pins_of(asset) -> dict:
    try:
        value = json.loads(getattr(asset, "tls_pins", "") or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def allow(asset_id, url: str, allow_private: bool = False, proxy: str = None) -> dict:
    """May credentials go to this https address?  -> {ok, state, detail}

    Plain http and an unknown site are not judged here (ok True): this is
    about certificates.  When the check cannot reach the site it does not
    block either, since the request that follows fails the same way.
    """
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or not asset_id:
        return {"ok": True, "state": "not checked", "detail": ""}
    from app.core import external_probe
    from app.core.db import session_scope
    from app.core.models import ExternalAsset

    if not allow_private and not external_probe._host_is_public(host):
        return {"ok": True, "state": "not checked", "detail": ""}
    if proxy is None:
        proxy = external_probe.current_proxy() or ""
    seen = peer(host, parsed.port or 443, proxy)
    if seen["verified"] is None:
        log.info("could not check the certificate of %s: %s", host, seen["error"])
        return {"ok": True, "state": "unchecked", "detail": ""}
    if seen["verified"]:
        return {"ok": True, "state": "verified", "detail": ""}
    with session_scope() as db:
        asset = db.get(ExternalAsset, int(asset_id))
        if asset is None:
            return {"ok": True, "state": "not checked", "detail": ""}
        pins = pins_of(asset)
        saved = pins.get(host) or {}
        if not saved.get("fingerprint"):
            pins[host] = {"fingerprint": seen["fingerprint"],
                          "at": utcnow().strftime("%Y-%m-%d %H:%M"),
                          "why": seen["error"][:120]}
            asset.tls_pins = json.dumps(pins, sort_keys=True)
            log.warning("saved the untrusted certificate of %s on first use (%s)",
                        host, seen["error"])
            return {"ok": True, "state": "first use", "detail": ""}
        if saved["fingerprint"] == seen["fingerprint"]:
            return {"ok": True, "state": "pinned", "detail": ""}
    log.warning("the certificate of %s changed since it was saved on %s; credentials "
                "withheld", host, saved.get("at"))
    return {"ok": False, "state": "changed",
            "detail": (f"the certificate of {host} is not trusted and is not the one "
                       f"saved on {saved.get('at') or 'first use'}, so the credentials "
                       "were not sent.  If the site renewed it, clear the saved "
                       "certificate on the site's page")}
