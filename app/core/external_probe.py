"""What an external site looks like from the outside.

One pass per host: resolve it, knock on the usual ports, read the TLS
certificate and what versions it will still speak, fetch the front page with
a browser's user agent, grade the security headers, notice a firewall block
page, and take a screenshot.  Nothing here sends anything a browser would
not, apart from the port knocks.

The grading, the port list and the blank screenshot check come from a
standalone site report script that was run against real estates for a while,
so the numbers mean what they meant there.

Every function returns something.  A host that does not answer is a result,
not an error.
"""

from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import ipaddress
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import zlib
from pathlib import Path

log = logging.getLogger("gcr.external")

MOZILLA_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# The common services worth knowing about on something facing the internet.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 873, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083,
    2222, 2375, 2376, 3000, 3128, 3306, 3389, 4443, 5000, 5432, 5601,
    5900, 5985, 5986, 6379, 7001, 7777, 8000, 8006, 8008, 8009, 8080,
    8081, 8088, 8089, 8090, 8123, 8161, 8181, 8200, 8222, 8333, 8443,
    8500, 8530, 8531, 8834, 8888, 9000, 9001, 9090, 9091, 9092, 9200,
    9300, 9418, 9443, 10000, 11211, 15672, 27017, 50000,
]

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "Submission", 636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1433: "MS SQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel TLS", 2222: "SSH alt", 2375: "Docker API",
    2376: "Docker TLS", 3000: "Dev server", 3128: "Squid", 3306: "MySQL",
    3389: "RDP", 4443: "HTTPS alt", 5000: "Dev server", 5432: "PostgreSQL",
    5601: "Kibana", 5900: "VNC", 5985: "WinRM", 5986: "WinRM TLS",
    6379: "Redis", 7001: "WebLogic", 8000: "HTTP alt", 8080: "HTTP alt",
    8443: "HTTPS alt", 8888: "HTTP alt", 9000: "HTTP alt", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9418: "git", 11211: "memcached", 15672: "RabbitMQ",
    27017: "MongoDB",
}

# Ports that should never face the internet.  The DAST pass reports them.
RISKY_PORTS = {
    23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 445: "SMB", 1433: "MS SQL",
    1521: "Oracle", 2375: "Docker API without TLS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 9200: "Elasticsearch", 11211: "memcached",
    27017: "MongoDB",
}

PORT_TIMEOUT = 1.5
PORT_THREADS = 64
HTTP_TIMEOUT = 12
SCREENSHOT_TIMEOUT = 35
BODY_LIMIT = 65536

# Header, weight in the grade, short label.
HEADER_WEIGHTS = [
    ("strict-transport-security", 8, "HSTS"),
    ("content-security-policy", 8, "CSP"),
    ("x-frame-options", 5, "X-Frame-Options"),
    ("x-content-type-options", 5, "X-Content-Type-Options"),
    ("referrer-policy", 3, "Referrer-Policy"),
    ("permissions-policy", 3, "Permissions-Policy"),
    ("cross-origin-opener-policy", 3, "COOP"),
    ("cross-origin-resource-policy", 3, "CORP"),
]

WAF_BLOCK_SIGNATURES = [
    "Sorry, you have been blocked",
    "Attention Required! | Cloudflare",
    "cf-error-details",
    "Please enable cookies",
    "needs to review the security of your connection",
    "Access denied | ",
    "Your IP address has been blocked",
    "Akamai Reference",
    "The requested URL was rejected",
]

WEB_PORTS = (80, 443, 8080, 8443, 8000, 8888, 8081)
WEB_CATEGORIES = {"live", "redir", "gated", "err4", "err5"}

CATEGORY_NAMES = {
    "live": "Live", "redir": "Redirects", "gated": "Sign in or blocked",
    "err4": "Client error", "err5": "Server error", "none": "No web service",
    "noresolve": "Does not resolve", "private": "Private address",
}


# ------------------------------------------------------------------ hosts

HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


def clean_host(value) -> str:
    """One host name as somebody typed or pasted it, or empty.

    A scheme, a path, a port and a leading wildcard are taken off, since people
    paste whole addresses.  What is left has to be a real DNS name.
    """
    text = str(value or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:
        return ""
    text = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    text = text.lstrip("*.").rstrip(".")
    if len(text) > 253 or not HOST_RE.fullmatch(text):
        return ""
    return text


def is_public(ip: str) -> bool:
    """Whether an address is somewhere on the internet rather than inside."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def resolve(host: str) -> list:
    """Every IPv4 address the host resolves to, in order.  Empty when it does not."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    out = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


# ------------------------------------------------------------------ ports

def _knock(ip: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(PORT_TIMEOUT)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_ports(ip: str, ports=None) -> list:
    ports = ports or DEFAULT_PORTS
    found = []
    with cf.ThreadPoolExecutor(max_workers=PORT_THREADS) as pool:
        futures = {pool.submit(_knock, ip, p): p for p in ports}
        for fut in cf.as_completed(futures):
            if fut.result():
                found.append(futures[fut])
    return sorted(found)


# ------------------------------------------------------------------ TLS

def analyze_tls(host: str, ip: str, port: int = 443, legacy: bool = True) -> dict:
    """The certificate, what was negotiated, and which old versions still work."""
    info = {"negotiated_version": None, "negotiated_cipher": None,
            "subject": None, "issuer": None, "not_before": None,
            "not_after": None, "days_left": None, "signature_algorithm": None,
            "key_type": None, "key_bits": None, "san": [], "supported": {},
            "weaknesses": [], "error": None}
    der = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                info["negotiated_version"] = s.version()
                cipher = s.cipher()
                if cipher:
                    info["negotiated_cipher"] = f"{cipher[0]} ({cipher[1]}, {cipher[2]}-bit)"
                der = s.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001 - a failed handshake is a result
        info["error"] = f"{type(exc).__name__}: {exc}"[:300]
        return info

    if der:
        _read_cert(info, der)
    # Whether the trusted chain checks out, which the grade above ignores.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                info["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        info["trusted"] = False
        info["trust_error"] = (exc.verify_message or str(exc))[:200]
    except Exception:  # noqa: BLE001
        info["trusted"] = None

    for label, version in (("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
                           ("TLSv1_1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if legacy and version:
            info["supported"][label] = _accepts(host, ip, port, version)

    w = info["weaknesses"]
    nv = (info["negotiated_version"] or "").upper()
    if nv in ("SSLV3", "TLSV1", "TLSV1.1"):
        w.append(f"Negotiated weak protocol: {info['negotiated_version']}")
    for label, ok in info["supported"].items():
        if ok:
            w.append(f"Legacy protocol enabled: {label.replace('_', '.')}")
    days = info["days_left"]
    if days is not None and days < 0:
        w.append("Certificate already expired")
    elif days is not None and days < 30:
        w.append(f"Certificate expires soon ({days} days)")
    kt = (info.get("key_type") or "").upper()
    kb = info["key_bits"] or 0
    if kt.startswith("RSA") and kb and kb < 2048:
        w.append(f"Weak RSA key size: {kb}-bit")
    elif kt.startswith("EC") and kb and kb < 224:
        w.append(f"Weak EC key size: {kb}-bit")
    sa = (info["signature_algorithm"] or "").lower()
    if "sha1" in sa or "md5" in sa:
        w.append(f"Weak certificate signature: {info['signature_algorithm']}")
    name = (info["negotiated_cipher"] or "").lower()
    if any(bad in name for bad in ("rc4", "3des", "des-cbc", "null", "export", "md5")):
        w.append(f"Weak cipher negotiated: {info['negotiated_cipher']}")
    if info.get("trusted") is False:
        w.append(f"Certificate not trusted: {info.get('trust_error') or 'chain did not verify'}")
    return info


def _accepts(host: str, ip: str, port: int, version) -> bool:
    """Whether the server still finishes a handshake at exactly this version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((ip, port), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except Exception:  # noqa: BLE001 - refused is the answer we want
        return False


def _read_cert(info: dict, der: bytes) -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    except ImportError:  # pragma: no cover - it is in requirements.txt
        return
    try:
        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        info["not_before"] = nb.isoformat()
        info["not_after"] = na.isoformat()
        info["days_left"] = (na - dt.datetime.now(dt.timezone.utc)).days
        info["signature_algorithm"] = (cert.signature_hash_algorithm.name
                                       if cert.signature_hash_algorithm else None)
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            info["key_type"], info["key_bits"] = "RSA", key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            info["key_type"], info["key_bits"] = f"EC ({key.curve.name})", key.key_size
        elif isinstance(key, dsa.DSAPublicKey):
            info["key_type"], info["key_bits"] = "DSA", key.key_size
        else:
            info["key_type"] = type(key).__name__.replace("PublicKey", "")
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info["san"] = ext.value.get_values_for_type(x509.DNSName)[:100]
        except x509.ExtensionNotFound:
            pass
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"certificate could not be read: {type(exc).__name__}"


# ------------------------------------------------------------------ HTTP

def fetch(url: str, method: str = "GET", headers: dict = None,
          follow: bool = True, allow_private: bool = False,
          body_limit: int = BODY_LIMIT, timeout: float = HTTP_TIMEOUT) -> dict:
    """One request, the way a browser would make it.

    -> {status, url, final_url, headers, set_cookies, body, redirects, error}

    Redirects are followed by hand, at most five, and every hop is checked
    against private addresses unless those are allowed, so a site cannot
    bounce this server into the network it sits in.
    """
    import httpx
    from urllib.parse import urljoin, urlparse

    out = {"status": 0, "url": url, "final_url": url, "headers": {},
           "set_cookies": [], "body": "", "redirects": [], "error": ""}
    current = url
    sent = dict(headers or {})
    sent.setdefault("User-Agent", MOZILLA_UA)
    sent.setdefault("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=False,
                          trust_env=True) as client:
            for _hop in range(6):
                host = urlparse(current).hostname or ""
                if not allow_private and not _host_is_public(host):
                    out["error"] = f"{host} resolves to a private address, not followed"
                    return out
                with client.stream(method, current, headers=sent) as resp:
                    body = b""
                    if method != "HEAD":
                        for chunk in resp.iter_bytes():
                            body += chunk
                            if len(body) >= body_limit:
                                break
                    out["status"] = resp.status_code
                    out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
                    out["set_cookies"] = resp.headers.get_list("set-cookie")
                    out["body"] = body[:body_limit].decode(resp.encoding or "utf-8",
                                                           "replace")
                    out["final_url"] = current
                    location = resp.headers.get("location")
                    if follow and location and 300 <= resp.status_code < 400:
                        current = urljoin(current, location)
                        out["redirects"].append(current)
                        if method == "POST":
                            method = "GET"
                        continue
                return out
    except Exception as exc:  # noqa: BLE001 - no answer is a result
        out["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return out


_PUBLIC_CACHE: dict = {}


def _host_is_public(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return is_public(host)
    except ValueError:
        pass
    ips = resolve(host)
    return bool(ips) and all(is_public(ip) for ip in ips)


def probe_http(host: str, ports: list, allow_private: bool = False) -> dict:
    """The front page, over https first when 443 is open."""
    candidates = []
    if 443 in ports:
        candidates.append(f"https://{host}/")
    if 80 in ports:
        candidates.append(f"http://{host}/")
    for port, scheme in ((8443, "https"), (8080, "http"), (8000, "http"),
                         (8888, "http"), (8081, "http")):
        if port in ports:
            candidates.append(f"{scheme}://{host}:{port}/")
    last = {"status": 0, "headers": {}, "final_url": f"https://{host}/",
            "body": "", "redirects": [], "set_cookies": [], "error": ""}
    for url in candidates:
        got = fetch(url, allow_private=allow_private)
        if got["status"] > 0:
            return got
        last = got
    return last


def http_redirects_to_https(host: str, allow_private: bool = False) -> bool | None:
    """Whether plain http on port 80 sends people to https.  None when 80 is shut."""
    got = fetch(f"http://{host}/", follow=False, allow_private=allow_private,
                body_limit=1024)
    if not got["status"]:
        return None
    location = got["headers"].get("location", "")
    return 300 <= got["status"] < 400 and location.lower().startswith("https://")


def detect_waf_block(body: str) -> bool:
    lowered = (body or "").lower()
    return any(sig.lower() in lowered for sig in WAF_BLOCK_SIGNATURES)


def classify(status: int, has_web: bool) -> str:
    if not has_web or not status:
        return "none"
    if status in (401, 403):
        return "gated"
    if 200 <= status < 300:
        return "live"
    if 300 <= status < 400:
        return "redir"
    if 400 <= status < 500:
        return "err4"
    if 500 <= status < 600:
        return "err5"
    return "none"


def title_of(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not m:
        return ""
    import html

    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:200]


# ------------------------------------------------------------------ grade

def compute_score(rec: dict) -> dict:
    """A to F, from missing headers and TLS problems.  N/A when nothing serves."""
    if rec["category"] in ("noresolve", "none", "private"):
        return {"grade": "N/A", "score": 0, "notes": []}
    score, notes = 100, []
    headers = rec.get("headers") or {}
    if headers:
        for name, weight, label in HEADER_WEIGHTS:
            if name not in headers:
                score -= weight
                notes.append(f"Missing {label} (-{weight})")
    tls = rec.get("tls") or {}
    ports = rec.get("ports") or []
    if 443 not in ports:
        if rec.get("status"):
            score -= 30
            notes.append("No TLS on 443, an HTTP only service (-30)")
    else:
        nv = (tls.get("negotiated_version") or "").upper().replace(".", "")
        if nv in ("TLSV1", "TLSV10", "TLSV11"):
            score -= 25
            notes.append(f"Negotiated {tls.get('negotiated_version')} (-25)")
        elif not nv:
            score -= 10
            notes.append("TLS handshake failed on 443 (-10)")
        for proto, ok in (tls.get("supported") or {}).items():
            if ok:
                score -= 8
                notes.append(f"Legacy {proto.replace('_', '.')} accepted (-8)")
        days = tls.get("days_left")
        if days is not None:
            if days < 0:
                score -= 25
                notes.append("Certificate already expired (-25)")
            elif days < 14:
                score -= 10
                notes.append(f"Certificate expires in {days} days (-10)")
            elif days < 30:
                score -= 5
                notes.append(f"Certificate expires in {days} days (-5)")
        kt = (tls.get("key_type") or "").upper()
        kb = tls.get("key_bits") or 0
        if (kt.startswith("RSA") or kt.startswith("DSA")) and kb and kb < 2048:
            score -= 15
            notes.append(f"Weak {kt.split()[0]} key, {kb}-bit (-15)")
        elif kt.startswith("EC") and kb and kb < 224:
            score -= 15
            notes.append(f"Weak EC key, {kb}-bit (-15)")
        sa = (tls.get("signature_algorithm") or "").lower()
        if "sha1" in sa or "md5" in sa:
            score -= 15
            notes.append(f"Weak certificate signature, {tls['signature_algorithm']} (-15)")
        cipher = (tls.get("negotiated_cipher") or "").lower()
        if any(bad in cipher for bad in ("rc4", "3des", "des-cbc", "null", "export", "_md5")):
            score -= 15
            notes.append("Weak cipher negotiated (-15)")
    score = max(0, score)
    grade = ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
             else "D" if score >= 60 else "F")
    return {"grade": grade, "score": score, "notes": notes}


# ------------------------------------------------------------------ whois

_ISP_PATTERNS = [re.compile(p, re.I | re.M) for p in (
    r"^\s*OrgName\s*:\s*(.+)$", r"^\s*org-name\s*:\s*(.+)$",
    r"^\s*Organi[sz]ation\s*:\s*(.+)$",
    r"^\s*owner\s*:\s*(.+)$", r"^\s*netname\s*:\s*(.+)$", r"^\s*descr\s*:\s*(.+)$")]
_ISP_CACHE: dict = {}


def lookup_isp(ip: str) -> str:
    """Who owns the netblock, from whois.  Empty when whois is not installed."""
    if not ip or not shutil.which("whois"):
        return ""
    if ip in _ISP_CACHE:
        return _ISP_CACHE[ip]
    isp = ""
    try:
        proc = subprocess.run(["whois", ip], capture_output=True, text=True,
                              timeout=20, errors="replace")
        for pattern in _ISP_PATTERNS:
            m = pattern.search(proc.stdout or "")
            if m and m.group(1).strip().lower() not in ("private", "n/a",
                                                         "redacted for privacy"):
                isp = m.group(1).strip()[:200]
                break
    except Exception:  # noqa: BLE001
        pass
    _ISP_CACHE[ip] = isp
    return isp


# ------------------------------------------------------------------ screenshots

CHROMIUM_PATHS = (
    "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
    "/usr/lib/chromium/chromium", "/opt/google/chrome/chrome",
)
SHOT_GATE = threading.Semaphore(int(os.environ.get("GCR_SHOT_CONCURRENCY", "2")))


def find_browser() -> str:
    """A headless Chromium to take screenshots with, or empty.

    GCR_CHROMIUM wins.  Then the build the image ships under
    PLAYWRIGHT_BROWSERS_PATH, then the usual install paths.  A snap build is
    skipped: its sandbox stops it writing the image anywhere useful.
    """
    wanted = os.environ.get("GCR_CHROMIUM", "").strip()
    if wanted and os.access(wanted, os.X_OK):
        return wanted
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""),
             "/opt/gcr/browsers", str(Path.home() / ".cache" / "ms-playwright")]
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for pattern in ("chromium_headless_shell-*/chrome-*/chrome-headless-shell",
                        "chromium_headless_shell-*/chrome-*/headless_shell",
                        "chromium-*/chrome-linux*/chrome"):
            found = sorted(Path(root).glob(pattern), reverse=True)
            for cand in found:
                if os.access(cand, os.X_OK):
                    return str(cand)
    for path in CHROMIUM_PATHS:
        real = os.path.realpath(path)
        if os.access(path, os.X_OK) and "/snap/" not in real:
            return path
    return ""


def _png_flat_color(path: Path, max_rows: int = 320) -> str | None:
    """The one color of a PNG with nothing on it, else None.

    File size cannot tell: a plain white 1280x800 PNG is under 5 KB, which
    passes any size check while showing nobody anything.
    """
    try:
        data = path.read_bytes()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return "not-a-png"
        pos, idat, width, height, depth, color = 8, bytearray(), 0, 0, 0, 0
        while pos + 8 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "big")
            chunk = data[pos + 4:pos + 8]
            if chunk == b"IHDR":
                body = data[pos + 8:pos + 8 + length]
                width = int.from_bytes(body[0:4], "big")
                height = int.from_bytes(body[4:8], "big")
                depth, color = body[8], body[9]
            elif chunk == b"IDAT":
                idat += data[pos + 8:pos + 8 + length]
            elif chunk == b"IEND":
                break
            pos += 12 + length
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color)
        if not (width and height and channels) or depth != 8:
            return None
        raw = zlib.decompress(bytes(idat))
        stride = width * channels
        prev = bytearray(stride)
        seen: set = set()
        offset = 0
        for _ in range(min(height, max_rows)):
            if offset + 1 + stride > len(raw):
                break
            ftype = raw[offset]
            line = bytearray(raw[offset + 1:offset + 1 + stride])
            offset += 1 + stride
            # Undo the per row filter, PNG spec section 9.2.
            if ftype == 1:
                for x in range(channels, stride):
                    line[x] = (line[x] + line[x - channels]) & 0xFF
            elif ftype == 2:
                for x in range(stride):
                    line[x] = (line[x] + prev[x]) & 0xFF
            elif ftype == 3:
                for x in range(stride):
                    a = line[x - channels] if x >= channels else 0
                    line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
            elif ftype == 4:
                for x in range(stride):
                    a = line[x - channels] if x >= channels else 0
                    c = prev[x - channels] if x >= channels else 0
                    b = prev[x]
                    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                    pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                    line[x] = (line[x] + pred) & 0xFF
            for x in range(0, stride, channels * 8):
                seen.add(bytes(line[x:x + channels]))
                if len(seen) > 4:
                    return None
            prev = line
        if len(seen) > 4 or not seen:
            return None
        px = sorted(seen)[0][:3]
        return "#" + "".join(f"{b:02x}" for b in px.ljust(3, px[:1] or b"\x00"))
    except Exception:  # noqa: BLE001 - never throw away a picture over this
        return None


def _proxy_flags() -> list:
    proxy = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
             or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY"))
    if not proxy:
        return []
    flags = [f"--proxy-server={proxy}"]
    bypass = os.environ.get("no_proxy") or os.environ.get("NO_PROXY")
    if bypass:
        flags.append(f"--proxy-bypass-list={bypass}")
    return flags


def take_screenshot(browser: str, urls: list, out_path: Path) -> tuple:
    """-> (status, detail).  ok, blank, or blocked when no image came back.

    Two tries per address, the second with twice the time, because under load
    the first launch often just runs out of clock.  A blank page moves on to
    the next address rather than retrying, since blank is the page's doing.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    result, detail = "blocked", "no address to capture"
    scratch = Path(tempfile.mkdtemp(prefix="gcr-shot-"))
    headless = [] if "headless" in Path(browser).name else ["--headless=new"]
    try:
        for url in urls[:2]:
            for attempt in (1, 2):
                timeout = SCREENSHOT_TIMEOUT * attempt
                tmp = scratch / "shot.png"
                tmp.unlink(missing_ok=True)
                with SHOT_GATE:
                    try:
                        proc = subprocess.run(
                            [browser, *headless, *_proxy_flags(),
                             "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
                             "--disable-dev-shm-usage", "--ignore-certificate-errors",
                             "--no-first-run", "--no-default-browser-check",
                             "--disable-background-networking",
                             "--run-all-compositor-stages-before-draw",
                             "--force-device-scale-factor=1",
                             f"--user-data-dir={scratch / 'profile'}",
                             f"--user-agent={MOZILLA_UA}", "--window-size=1280,800",
                             f"--screenshot={tmp}", "--virtual-time-budget=10000", url],
                            capture_output=True, timeout=timeout, cwd=scratch,
                            env={**os.environ, "TMPDIR": str(scratch),
                                 "HOME": str(scratch)})
                    except subprocess.TimeoutExpired:
                        detail = f"timed out after {timeout} seconds"
                        continue
                    except Exception as exc:  # noqa: BLE001
                        detail = f"{type(exc).__name__}: {exc}"[:200]
                        continue
                size = tmp.stat().st_size if tmp.exists() else 0
                if size == 0:
                    err = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
                    killed = " (killed, likely out of memory)" if proc.returncode and proc.returncode < 0 else ""
                    detail = (f"exit {proc.returncode}{killed}, no image written"
                              + (f": {re.sub(r'^\[[^\]]*\]\s*', '', err[-1])[:160]}" if err else ""))
                    continue
                flat = _png_flat_color(tmp)
                if flat is not None:
                    result, detail = "blank", f"rendered a flat {flat} page"
                    break
                shutil.move(str(tmp), str(out_path))
                return "ok", f"{size} bytes from {url}"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return result, detail


def screenshot_urls(host: str, rec: dict) -> list:
    urls = []
    final = rec.get("final_url") or ""
    if final.startswith(("http://", "https://")):
        urls.append(final)
    ports = rec.get("ports") or []
    if 443 in ports or not ports:
        urls.append(f"https://{host}/")
    if 80 in ports:
        urls.append(f"http://{host}/")
    seen: set = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


# ------------------------------------------------------------------ one host

def probe(host: str, shot_path: Path = None, screenshots: bool = True,
          allow_private: bool = False, ports=None, passive: bool = False) -> dict:
    """Everything above, for one host.  -> the telemetry record.

    passive is for a host marked not to be scanned.  Only 443 and 80 are
    tried, no old TLS versions are offered, and the front page is asked for
    once.  The site sees what one browser visit looks like and nothing more.
    """
    started = time.monotonic()
    rec = {"host": host, "ips": [], "ip": "", "isp": "", "ports": [],
           "tls": {}, "status": 0, "headers": {}, "set_cookies": [],
           "redirects": [], "final_url": f"https://{host}/", "title": "",
           "category": "none", "waf_block": False, "http_to_https": None,
           "missing_headers": [], "shot": "", "shot_detail": "",
           "server": "", "powered_by": "", "body_sample": "",
           "probed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    ips = resolve(host)
    if not ips:
        rec["category"] = "noresolve"
        rec["score"] = compute_score(rec)
        return rec
    rec["ips"], rec["ip"] = ips[:8], ips[0]
    if not allow_private and not all(is_public(ip) for ip in ips):
        rec["category"] = "private"
        rec["score"] = compute_score(rec)
        return rec
    rec["isp"] = lookup_isp(rec["ip"])
    rec["passive"] = passive
    if passive:
        # No knocking.  Whichever of 443 and 80 answers a plain request is
        # what counts as open, and nothing else is tried.
        rec["ports"] = [p for p in (443, 80) if _knock(rec["ip"], p)]
    else:
        rec["ports"] = scan_ports(rec["ip"], ports)
    has_web = any(p in rec["ports"] for p in WEB_PORTS)
    if 443 in rec["ports"]:
        rec["tls"] = analyze_tls(host, rec["ip"], legacy=not passive)
    if has_web:
        got = probe_http(host, rec["ports"], allow_private=allow_private)
        rec["status"] = got["status"]
        rec["headers"] = got["headers"]
        rec["set_cookies"] = got.get("set_cookies") or []
        rec["redirects"] = got.get("redirects") or []
        rec["final_url"] = got.get("final_url") or rec["final_url"]
        rec["body_sample"] = (got.get("body") or "")[:BODY_LIMIT]
        rec["title"] = title_of(got.get("body") or "")
        rec["server"] = got["headers"].get("server", "")[:200]
        rec["powered_by"] = got["headers"].get("x-powered-by", "")[:200]
        rec["missing_headers"] = [label for name, _w, label in HEADER_WEIGHTS
                                  if got["headers"] and name not in got["headers"]]
        if 80 in rec["ports"] and not passive:
            rec["http_to_https"] = http_redirects_to_https(host, allow_private)
    rec["category"] = classify(rec["status"], has_web)
    rec["waf_block"] = rec["category"] in WEB_CATEGORIES and detect_waf_block(rec["body_sample"])

    if rec["category"] in WEB_CATEGORIES and screenshots and shot_path is not None:
        browser = find_browser()
        if not browser:
            rec["shot"], rec["shot_detail"] = "nobrowser", "no headless Chromium on this server"
        elif rec["waf_block"]:
            rec["shot"], rec["shot_detail"] = "waf", "a firewall block page answered"
        else:
            rec["shot"], rec["shot_detail"] = take_screenshot(
                browser, screenshot_urls(host, rec), shot_path)
    rec["score"] = compute_score(rec)
    rec["seconds"] = round(time.monotonic() - started, 1)
    return rec
