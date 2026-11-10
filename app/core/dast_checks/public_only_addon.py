"""A mitmproxy addon that lets a browser reach public addresses only.

The screenshot browser checks each host it loads against the public internet
before the request goes out, but Chromium then looks the name up again on its
own.  A name whose DNS answers with a public address for the check and a
private one for the browser (DNS rebinding) would get the page's script onto
an internal service, with the page then free to send what it read anywhere.

Run as the browser's proxy, this addon decides at the one moment that counts:
when the proxy opens the connection.  It resolves the name itself, refuses it
unless every address is public, and connects to the address it checked, so
nothing can change in between.  HTTPS is passed through without being opened
(the proxy is started with every host ignored), which keeps the browser's own
TLS, and with it how bot checks see it.

It runs inside the DAST virtual environment's python, which does not have the
app on its path, so it imports only the standard library.
"""

import ipaddress
import socket


def _public(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_global
    except ValueError:
        return False


def pinned(host: str):
    """-> (the address to connect to, "") or ("", why it is refused)."""
    host = (host or "").strip().rstrip(".")
    if not host:
        return "", "no host"
    try:
        ipaddress.ip_address(host.split("%")[0])
        return (host, "") if _public(host) else ("", f"{host} is not a public address")
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return "", f"{host} does not resolve"
    addrs = [i[4][0] for i in infos]
    if not addrs:
        return "", f"{host} does not resolve"
    if not all(_public(a) for a in addrs):
        return "", f"{host} resolves to an address that is not public"
    v4 = [a for a in addrs if ":" not in a]
    return (v4 or addrs)[0], ""


def server_connect(data) -> None:
    server = data.server
    if not server.address:
        return
    host, port = server.address[0], server.address[1]
    addr, why = pinned(host)
    if not addr:
        server.error = f"blocked: {why}"
        return
    # The name stays the TLS server name, and HTTP keeps its Host header; only
    # where the socket goes changes, to the address that was checked.
    if not server.sni and not _is_ip(host):
        server.sni = host
    server.address = (addr, port)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%")[0])
        return True
    except ValueError:
        return False
