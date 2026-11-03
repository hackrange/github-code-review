"""The dynamic scanning engines, and turning what each one says into findings.

The same engine set and the same profiles as nextgen-dast, so a scan run here
and a scan run there can be read side by side:

    baseline   the read only checks in external_dast, nothing else
    quick      baseline, testssl, nuclei (exposure, misconfig, cve, logins)
    standard   quick, a wider nuclei, nikto, wapiti
    thorough   standard, ffuf content discovery first, nuclei wider again
    premium    thorough, sqlmap and dalfox

From standard up the engines send attack payloads: SQL, script and command
injection strings.  That is what a DAST scan is, and it is why a host marked
not to be scanned never gets here, and why the page asks before it starts.

An engine that is not installed is skipped and the scan says so.  A scan
that quietly ran three engines out of six reads exactly like a clean one,
which is the one thing a scan must never do.

Each engine writes its own report file into a scratch directory, the parser
reads it, and the directory goes when the scan ends.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

log = logging.getLogger("gcr.dast")

PROFILES = {
    "baseline": "A light, read only check: headers, cookies, TLS, open ports and "
                "files that should never be served.  About 20 requests, done in "
                "seconds.  Runs none of the scanning engines.",
    "quick": "Baseline, then testssl and nuclei for exposures, misconfigurations, "
             "known CVEs and default logins.  Usually 10 to 30 minutes.",
    "standard": "Quick, then nikto and wapiti, which crawl the site and try attack "
                "payloads.  An hour or more.",
    "thorough": "Standard, with ffuf content discovery first and a wider nuclei "
                "pass.  Sends attack payloads.  Several hours on a large site.",
    "premium": "Thorough, then sqlmap and dalfox.  The most invasive.  Can run for "
               "many hours.",
}
DEFAULT_PROFILE = "quick"
ACTIVE_PROFILES = {"standard", "thorough", "premium"}

PLANS = {
    "baseline": [],
    "quick": ["testssl", "nuclei"],
    "standard": ["testssl", "nuclei", "nikto", "wapiti"],
    "thorough": ["ffuf", "testssl", "nuclei", "nikto", "wapiti"],
    "premium": ["ffuf", "testssl", "nuclei", "nikto", "wapiti", "sqlmap", "dalfox"],
}

ENGINE_NAMES = {
    "testssl": "testssl.sh", "nuclei": "nuclei", "nikto": "Nikto",
    "wapiti": "Wapiti", "sqlmap": "sqlmap", "dalfox": "Dalfox", "ffuf": "ffuf",
}

# Wall clock per engine.  Long enough for a real site, short enough that a
# hung engine cannot hold the slot all day.
TIMEOUTS = {
    "testssl": 900, "nuclei": 3600, "nikto": 3600, "wapiti": 4 * 3600,
    "sqlmap": 2 * 3600, "dalfox": 1800, "ffuf": 300,
}

SEVERITIES = ["critical", "high", "medium", "low", "info"]

ENGINE_HOME = Path(os.environ.get("GCR_DAST_HOME", "/opt/gcr/engines"))
WORDLIST = Path(__file__).resolve().parents[2] / "config" / "dast" / "web-content.txt"
TEMPLATES = Path(os.environ.get("GCR_NUCLEI_TEMPLATES",
                                str(Path.home() / ".cache" / "nuclei-templates")))

def _ua() -> str:
    """The one user agent every engine sends, from Settings."""
    from app.core.external_probe import user_agent

    return user_agent()


def binary(tool: str) -> str:
    """Where an engine is, or empty when it is not installed."""
    name = {"testssl": "testssl.sh"}.get(tool, tool)
    found = shutil.which(name)
    if found:
        return found
    for cand in (ENGINE_HOME / "bin" / name, ENGINE_HOME / tool / name):
        if os.access(cand, os.X_OK):
            return str(cand)
    return ""


def installed() -> dict:
    """-> {tool: path or ""} for every engine."""
    return {tool: binary(tool) for tool in ENGINE_NAMES}


def _finding(tool, title, severity, url, evidence="", fix="", cwe="", ref=""):
    severity = (severity or "info").lower()
    if severity not in SEVERITIES:
        severity = "info"
    key = f"{tool}|{title}|{url}"
    return {"id": hashlib.sha256(key.encode()).hexdigest()[:12], "check": tool,
            "tool": tool, "title": str(title)[:300], "severity": severity,
            "url": str(url or "")[:1000], "evidence": str(evidence or "")[:800],
            "remediation": str(fix or "")[:1500], "cwe": str(cwe or "")[:40],
            "reference": str(ref or "")[:500]}


# ------------------------------------------------------------------ running

_running: dict = {}
_running_lock = threading.Lock()


def stop(scan_id: int) -> bool:
    """Kill whatever engine a scan has running.  -> whether there was one."""
    with _running_lock:
        proc = _running.get(scan_id)
    if proc is None:
        return False
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    return True


def _run(cmd: list, timeout: int, workdir: Path, scan_id: int, env=None) -> tuple:
    """-> (exit code or None on timeout, last lines of output)."""
    log_path = workdir / "engine.log"
    with open(log_path, "ab") as out:
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT,
                                cwd=workdir, start_new_session=True,
                                env={**os.environ, "HOME": str(Path.home()),
                                     **(env or {})})
        with _running_lock:
            _running[scan_id] = proc
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            code = None
        finally:
            with _running_lock:
                _running.pop(scan_id, None)
    try:
        tail = log_path.read_text(errors="replace").strip().splitlines()[-3:]
    except OSError:
        tail = []
    return code, " | ".join(t.strip() for t in tail)[-300:]


def _nuclei_templates(workdir: Path, scan_id: int) -> str:
    """The template folder, fetched once into the cache volume."""
    if TEMPLATES.is_dir() and any(TEMPLATES.iterdir()):
        return str(TEMPLATES)
    TEMPLATES.parent.mkdir(parents=True, exist_ok=True)
    _run([binary("nuclei"), "-update-templates", "-ud", str(TEMPLATES),
          "-silent", "-no-color"], 900, workdir, scan_id)
    return str(TEMPLATES) if TEMPLATES.is_dir() else ""


def command(tool: str, url: str, host: str, profile: str, workdir: Path,
            paths: list = None) -> tuple:
    """-> (argv, report file) for one engine.  Ported from nextgen-dast."""
    exe = binary(tool)
    if tool == "testssl":
        report = workdir / "testssl.json"
        return ([exe, "--jsonfile", str(report), "--quiet", "--color", "0",
                 "--warnings", "off", "--user-agent", _ua(), host], report)
    if tool == "nuclei":
        tags = {"quick": "exposure,misconfig,cve,default-login",
                "thorough": "exposure,misconfig,cve,default-login,token-spray,"
                            "ssrf,lfi,sqli,xss,xxe,redirect,fileupload,tech",
                "premium": "exposure,misconfig,cve,default-login,token-spray,"
                           "ssrf,lfi,sqli,xss,xxe,redirect,fileupload,tech",
                }.get(profile, "exposure,misconfig,cve,default-login,token-spray,ssrf,tech")
        report = workdir / "nuclei.jsonl"
        targets = workdir / "nuclei-targets.txt"
        targets.write_text("\n".join([url] + _same_site(url, paths)[:50]) + "\n")
        argv = [exe, "-list", str(targets), "-jsonl-export", str(report),
                "-disable-update-check", "-no-color", "-silent",
                "-severity", "info,low,medium,high,critical", "-tags", tags,
                "-rl", "50", "-c", "25", "-timeout", "10", "-retries", "1",
                "-H", f"User-Agent: {_ua()}"]
        templates = _nuclei_templates(workdir, -1)
        if templates:
            argv += ["-t", templates]
        return argv, report
    if tool == "nikto":
        report = workdir / "nikto.json"
        flags = "x6" if profile == "quick" else ("x6789ab" if profile in ("thorough", "premium") else "x69")
        return ([exe, "-h", url, "-output", str(report), "-Format", "json",
                 "-ask", "no", "-nointeractive", "-Tuning", flags,
                 "-maxtime", "3000s", "-useragent", _ua()], report)
    if tool == "wapiti":
        report = workdir / "wapiti.json"
        modules = ("sql,timesql,xss,permanentxss,ssrf,xxe,exec,file,csrf,"
                   "redirect,upload,crlf,htaccess,htp,backup,cookieflags,"
                   "csp,http_headers,https_redirect,methods,wapp,wp_enum,"
                   "log4shell,shellshock,spring4shell,takeover")
        argv = [exe, "-u", url, "-f", "json", "-o", str(report),
                "--flush-session", "--verbose", "0", "--scope", "subdomain",
                "-m", modules, "--max-attack-time", "1800",
                "--max-scan-time", str(TIMEOUTS["wapiti"] - 300), "-A", _ua(),
                "--store-session", str(workdir / "wapiti-session"),
                "--store-config", str(workdir / "wapiti-config")]
        # Routes from the code and paths found by ffuf, as extra places to
        # start crawling from.  The crawler cannot reach an unlinked route.
        for extra in _same_site(url, paths)[:60]:
            argv += ["-s", extra]
        return argv, report
    if tool == "sqlmap":
        out = workdir / "sqlmap"
        return ([exe, "-u", url, "--batch", "-A", _ua(), "--crawl", "2",
                 "--forms", "--smart", "--level", "2", "--risk", "2",
                 "--output-dir", str(out), "--disable-coloring"], out)
    if tool == "dalfox":
        report = workdir / "dalfox.json"
        # Every address with a query string is a parameter to try.  Without
        # them dalfox only has the front page, which usually has none.
        targets = workdir / "dalfox-targets.txt"
        with_params = [u for u in _same_site(url, paths) if "?" in u]
        targets.write_text("\n".join([url] + with_params[:200]) + "\n")
        return ([exe, "scan", str(targets), "-f", "json", "-o", str(report), "-S",
                 "--workers", "10", "--timeout", "10", "--scan-timeout", "1500",
                 "--skip-mining-dom", "--user-agent", _ua()], report)
    if tool == "ffuf":
        report = workdir / "ffuf.json"
        return ([exe, "-u", url.rstrip("/") + "/FUZZ", "-w", str(WORDLIST),
                 "-of", "json", "-o", str(report), "-mc", "200,301,302,401,403",
                 "-fs", "0", "-ac", "-t", "20", "-rate", "40", "-timeout", "10",
                 "-maxtime", "240", "-s", "-H", f"User-Agent: {_ua()}"], report)
    raise ValueError(f"unknown engine {tool}")


def _same_site(url: str, paths) -> list:
    """Only addresses on the site being scanned, whatever was handed in."""
    from urllib.parse import urlparse

    base = urlparse(url)
    out = []
    for item in paths or []:
        parsed = urlparse(item)
        if parsed.scheme == base.scheme and parsed.netloc == base.netloc and item not in out:
            out.append(item)
    return out


def links_in(url: str, body: str) -> list:
    """Same site links in a page, the ones with a query string first."""
    from urllib.parse import urljoin

    found = []
    for href in re.findall(r"""(?:href|action|src)\s*=\s*["']([^"'#]+)""", body or "", re.I):
        full = urljoin(url, href.strip())
        if full.startswith(("http://", "https://")) and full not in found:
            found.append(full)
    keep = _same_site(url, found)
    return sorted(keep, key=lambda u: "?" not in u)[:100]


def proxy_args(tool: str, proxy: str) -> list:
    """Send an engine through the site's proxy.  testssl talks TLS straight to
    the host and is left alone, the same as the telemetry's TLS read."""
    if not proxy:
        return []
    return {"nuclei": ["-proxy", proxy], "ffuf": ["-x", proxy],
            "nikto": ["-useproxy", proxy], "wapiti": ["-p", proxy],
            "sqlmap": ["--proxy", proxy], "dalfox": ["--proxy", proxy]}.get(tool, [])


def run_engine(tool: str, url: str, host: str, profile: str, workdir: Path,
               scan_id: int, paths: list = None, auth_args: list = None,
               proxy: str = "") -> dict:
    """Run one engine and read its report.

    -> {tool, status, seconds, findings, detail, paths}
    status is ok, failed, timeout, skipped or stopped.
    """
    started = time.monotonic()
    out = {"tool": tool, "name": ENGINE_NAMES[tool], "status": "skipped",
           "seconds": 0, "findings": [], "detail": "", "paths": []}
    if not binary(tool):
        out["detail"] = "not installed on this server"
        return out
    if tool == "ffuf" and not WORDLIST.is_file():
        out["detail"] = "the content discovery word list is missing"
        return out
    engine_dir = workdir / tool
    engine_dir.mkdir(parents=True, exist_ok=True)
    try:
        argv, report = command(tool, url, host, profile, engine_dir, paths)
        argv = list(argv) + list(auth_args or []) + proxy_args(tool, proxy)
    except Exception as exc:  # noqa: BLE001
        out.update(status="failed", detail=f"{type(exc).__name__}: {exc}"[:300])
        return out
    code, tail = _run(argv, TIMEOUTS[tool], engine_dir, scan_id)
    out["seconds"] = int(time.monotonic() - started)
    try:
        parsed = PARSERS[tool](report, url)
    except Exception as exc:  # noqa: BLE001 - a bad report is a failed engine
        log.warning("%s report could not be read: %s", tool, exc)
        parsed = None
    if isinstance(parsed, tuple):
        parsed, out["paths"] = parsed
    if code is None:
        out["status"] = "timeout"
        out["detail"] = f"stopped after {TIMEOUTS[tool] // 60} minutes"
    elif code < 0 or code == -15 or code == 143:
        out["status"] = "stopped"
        out["detail"] = "stopped"
    elif parsed is None:
        out["status"] = "failed"
        out["detail"] = f"exit {code}, no report" + (f": {tail}" if tail else "")
    else:
        out["status"] = "ok"
        out["detail"] = f"{len(parsed)} finding{'s' if len(parsed) != 1 else ''}"
    out["findings"] = parsed or []
    return out


# ------------------------------------------------------------------ parsers

def _read_json(path: Path):
    if not path.is_file() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text(errors="replace"))


def parse_testssl(report: Path, url: str):
    data = _read_json(report)
    if data is None:
        return None
    rows = data if isinstance(data, list) else data.get("scanResult") or []
    out = []
    for row in rows:
        sev = str(row.get("severity") or "").upper()
        if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            continue
        out.append(_finding(
            "testssl", f"TLS: {row.get('id')} {str(row.get('finding') or '')[:160]}",
            sev.lower(), f"https://{str(row.get('ip') or '').split('/')[0]}:{row.get('port') or 443}"
            if not url.startswith("https") else url,
            row.get("finding"), "Fix the TLS configuration.",
            row.get("cwe") or "CWE-326", row.get("cve") or ""))
    return out


def parse_nuclei(report: Path, url: str):
    if not report.is_file():
        return None
    out = []
    for line in report.read_text(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        info = row.get("info") or {}
        cls = info.get("classification") or {}
        cwe = ", ".join((cls.get("cwe-id") or [])[:3]).upper()
        cve = ", ".join((cls.get("cve-id") or [])[:3]).upper()
        extracted = ", ".join(str(x) for x in (row.get("extracted-results") or [])[:5])
        out.append(_finding(
            "nuclei", info.get("name") or row.get("template-id"),
            info.get("severity"), row.get("matched-at") or url,
            "; ".join(x for x in (f"template {row.get('template-id')}",
                                  row.get("matcher-name") or "", extracted) if x),
            info.get("remediation") or info.get("description") or "",
            cwe, cve or ", ".join((info.get("reference") or [])[:2])
            if isinstance(info.get("reference"), list) else cve))
    return out


# Nikto has no severity.  These words in its message move it up from low.
_NIKTO_UP = [
    (re.compile(r"remote code|command execution|sql injection|shell", re.I), "high"),
    (re.compile(r"directory indexing|backup|\.git|password|credential|"
                r"default (account|login)|phpinfo|config", re.I), "medium"),
    (re.compile(r"header is not (set|present|defined)|uncommon header|"
                r"x-powered-by|server banner|retrieved .* header|"
                r"allowed http methods|robots\.txt", re.I), "info"),
]


def parse_nikto(report: Path, url: str):
    data = _read_json(report)
    if data is None:
        return None
    hosts = data if isinstance(data, list) else [data]
    out = []
    for host in hosts:
        for item in (host or {}).get("vulnerabilities") or []:
            msg = str(item.get("msg") or "")
            sev = "low"
            for pattern, level in _NIKTO_UP:
                if pattern.search(msg):
                    sev = level
                    break
            path = str(item.get("url") or "")
            full = path if path.startswith("http") else url.rstrip("/") + "/" + path.lstrip("/")
            out.append(_finding("nikto", msg[:200] or f"Nikto {item.get('id')}", sev,
                                full, f"{item.get('method') or 'GET'} {path}",
                                "", "", str(item.get("references") or "")[:300]))
    return out


_WAPITI_LEVEL = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def parse_wapiti(report: Path, url: str):
    data = _read_json(report)
    if data is None:
        return None
    classes = data.get("classifications") or {}
    out = []
    for section, default in (("vulnerabilities", "medium"), ("anomalies", "low"),
                             ("additionals", "info")):
        for category, items in (data.get(section) or {}).items():
            meta = classes.get(category) or {}
            for item in items or []:
                level = _WAPITI_LEVEL.get(item.get("level"), default)
                param = item.get("parameter") or ""
                path = item.get("path") or "/"
                full = path if path.startswith("http") else url.rstrip("/") + path
                out.append(_finding(
                    "wapiti", f"{category}" + (f" in {param}" if param else ""), level,
                    full, f"{item.get('method') or 'GET'} {path}: {item.get('info') or ''}",
                    meta.get("sol") or "", "",
                    ", ".join(str(r) for r in list((meta.get("ref") or {}).values())[:2])
                    if isinstance(meta.get("ref"), dict) else ""))
    return out


def parse_sqlmap(report: Path, url: str):
    if not report.is_dir():
        return None
    out = []
    for log_file in report.glob("*/log"):
        text = log_file.read_text(errors="replace")
        for block in re.split(r"\n---\n", text):
            m = re.search(r"Parameter: (.+?) \((\w+)\)", block)
            if not m:
                continue
            kinds = re.findall(r"Type: (.+)", block)
            out.append(_finding(
                "sqlmap", f"SQL injection in {m.group(1)} ({m.group(2)})", "critical",
                f"https://{log_file.parent.name}/", "; ".join(kinds)[:400],
                "Use parameterized queries for every database call that takes input.",
                "CWE-89"))
    return out


def parse_dalfox(report: Path, url: str):
    data = _read_json(report)
    if data is None:
        return None
    rows = data.get("findings") if isinstance(data, dict) else data
    out = []
    for row in rows or []:
        kind = row.get("type")
        if kind == "I":
            continue
        sev = str(row.get("severity") or "").lower()
        if kind == "R":
            sev = "low"  # reflected but not shown to run: a signal, not a claim
        out.append(_finding(
            "dalfox", f"Cross site scripting in {row.get('param') or 'a parameter'}"
            + (" (reflected, not confirmed)" if kind == "R" else ""),
            sev or "medium", row.get("data") or url,
            f"{row.get('inject_type') or ''}: {row.get('evidence') or row.get('message_str') or ''}",
            "Encode output for the context it lands in.", row.get("cwe") or "CWE-79"))
    return out


_FFUF_INTERESTING = re.compile(
    r"admin|backup|\.bak|\.old|\.sql|\.zip|\.tar|\.git|\.env|config|debug|"
    r"console|phpmyadmin|actuator|swagger|graphql|jenkins|manager|"
    r"server-status|\.svn|\.htpasswd|wp-admin|dump|private", re.I)


def parse_ffuf(report: Path, url: str):
    """Paths it found.  Only the ones whose names mean something become
    findings, and as info: a path existing is a lead, not a problem.  Every
    path is handed on to nuclei."""
    data = _read_json(report)
    if data is None:
        return None
    out, paths = [], []
    for row in data.get("results") or []:
        found = row.get("url") or ""
        paths.append(found)
        word = (row.get("input") or {}).get("FUZZ", "")
        if _FFUF_INTERESTING.search(word):
            out.append(_finding("ffuf", f"Found {word}", "info", found,
                                f"HTTP {row.get('status')}, {row.get('length')} bytes",
                                "Check this path is meant to be public."))
    return out, paths


PARSERS = {"testssl": parse_testssl, "nuclei": parse_nuclei,
           "nikto": parse_nikto, "wapiti": parse_wapiti,
           "sqlmap": parse_sqlmap, "dalfox": parse_dalfox, "ffuf": parse_ffuf}
