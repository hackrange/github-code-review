"""Record a scan's sign in in a real browser, and replay it before a scan.

Some sites cannot be signed into by a form post: a bot check asks "are you
human?", or single sign on walks through several pages and a one time code.
Here an administrator drives a real browser on this server from the site page.
They see the page as a picture, click and type into it, pass whatever a person
has to pass, and save.  What is saved, encrypted in the site's sign in slot:

    the cookies the site set, which a scan sends as its session
    the browser's user agent, which the scan then uses too, because a bot
        check ties its pass to the client it cleared
    the steps taken, so a scan can sign in again on its own when the session
        has expired, as long as no step needed a person

The browser runs on this server, so the site sees the scanner's own address,
which is what a pass that is tied to an address needs.  It can open pages only
on the site, its subdomains, the company's domains and the sign in providers in
IDP_HOSTS, and everything it loads goes through the proxy that refuses private
addresses (unless the site's own settings allow them).

One process serves the app, so the running recorders are kept in memory here.
Each belongs to the person and site that started it, stops after IDLE_SECONDS
without a command and after MAX_SECONDS in all, and at most MAX_RUNNING run at
once.
"""

from __future__ import annotations

import json
import logging
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("gcr.session_recorder")

SCRIPT = Path(__file__).with_name("session_recorder_browser.py")
IDLE_SECONDS = 10 * 60
MAX_SECONDS = 30 * 60
MAX_RUNNING = 2
REPLAY_SECONDS = 120

# Sign in providers a recording may walk through, beside the site itself and
# the company's own domains.  A page anywhere else is refused.
IDP_HOSTS = ["okta.com", "oktapreview.com", "okta-emea.com", "okta-gov.com",
             "microsoftonline.com", "login.microsoft.com", "login.live.com",
             "duosecurity.com", "pingidentity.com", "pingone.com", "auth0.com",
             "onelogin.com", "accounts.google.com"]

_running: dict = {}
_lock = threading.Lock()


class Busy(Exception):
    """Too many recordings are running, or this one is gone."""


class Recorder:
    def __init__(self, rid, asset_id, slot, owner, host, proc, workdir, guard):
        self.id = rid
        self.asset_id = asset_id
        self.slot = slot
        self.owner = owner
        self.host = host
        self.proc = proc
        self.workdir = workdir
        self.guard = guard
        self.started = time.monotonic()
        self.touched = time.monotonic()
        self.io = threading.Lock()
        self.totp_secret = ""
        self.last = {}

    @property
    def frame(self) -> Path:
        return self.workdir / "frame.jpg"

    def alive(self) -> bool:
        return self.proc.poll() is None

    def send(self, cmd: dict, timeout: float = 45) -> dict:
        """One command to the browser and its answer."""
        with self.io:
            if not self.alive():
                raise Busy("The recording browser has stopped.  Start a new recording.")
            self.touched = time.monotonic()
            self.proc.stdin.write(json.dumps(cmd) + "\n")
            self.proc.stdin.flush()
            reply = _read_line(self.proc, timeout)
        self.last = {k: v for k, v in reply.items() if k not in ("cookies", "steps")}
        return reply

    def stop(self) -> None:
        try:
            if self.alive():
                self.proc.stdin.write(json.dumps({"op": "quit"}) + "\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - make sure it is gone
            pass
        if self.alive():
            self.proc.kill()
        if self.guard:
            self.guard.stop()
        shutil.rmtree(self.workdir, ignore_errors=True)


def _read_line(proc, timeout: float) -> dict:
    """The next JSON answer from the browser, or a sentence when there is none."""
    import select

    end = time.monotonic() + timeout
    while time.monotonic() < end:
        ready, _w, _x = select.select([proc.stdout], [], [], max(0.1, end - time.monotonic()))
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            return {"ok": False, "error": "the recording browser stopped"}
        try:
            return json.loads(line)
        except ValueError:
            continue   # a library printing a warning is not an answer
    return {"ok": False, "error": "the browser did not answer in time"}


def allowed_hosts(host: str, company_domains: list) -> list:
    """The hosts a recording may open pages on."""
    out = [host.lower()] + [d.lower().lstrip(".") for d in company_domains or [] if d]
    return list(dict.fromkeys(out + IDP_HOSTS))


def _python() -> str:
    from app.core import external_probe

    return external_probe.playwright_python()


def available() -> bool:
    return bool(_python()) and SCRIPT.is_file()


def _reap() -> None:
    """Stop recordings left idle or running too long."""
    now = time.monotonic()
    with _lock:
        gone = [r for r in _running.values()
                if not r.alive() or now - r.touched > IDLE_SECONDS or now - r.started > MAX_SECONDS]
        for r in gone:
            _running.pop(r.id, None)
    for r in gone:
        r.stop()


def _guard_for(workdir: Path, allow_private: bool, site_proxy: str):
    """The proxy the browser goes through, as (url for the browser, handle)."""
    if site_proxy:
        return site_proxy, None
    if allow_private:
        return "", None
    from app.core import dast_proxy

    handle = dast_proxy.start_public_only(workdir)
    if handle is None:
        raise Busy("The address guard did not start, so the recording browser was not opened.")
    return handle.url, handle


def start(asset_id: int, host: str, slot: str, owner: str, start_url: str,
          company_domains: list, allow_private: bool = False, site_proxy: str = "") -> Recorder:
    """Open a recording browser on start_url.  Raises Busy or ValueError."""
    from app.core import external_probe

    _reap()
    if not available():
        raise Busy("Playwright is not installed on this server, so a browser cannot be opened.")
    parsed = urlparse(start_url or "")
    allowed = allowed_hosts(host, company_domains)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Start from an http or https address on the site.")
    if not any(parsed.hostname.lower() == a or parsed.hostname.lower().endswith("." + a)
               for a in allowed):
        raise ValueError(f"Start from a page on {host} or its sign in provider.")
    with _lock:
        mine = [r for r in _running.values() if r.asset_id == asset_id and r.owner == owner]
        others = len(_running) - len(mine)
    for r in mine:   # one at a time per person and site: a new one replaces it
        _forget(r.id)
    if others >= MAX_RUNNING:
        raise Busy(f"{MAX_RUNNING} recordings are already running.  Try again when one ends.")
    workdir = Path(tempfile.mkdtemp(prefix="gcr-rec-"))
    proxy_url, guard = _guard_for(workdir, allow_private, site_proxy)
    argv = [_python(), str(SCRIPT), "record", "--url", start_url, "--host", host,
            "--allowed", json.dumps(allowed), "--user-agent", external_probe.user_agent(),
            "--workdir", str(workdir), "--max-seconds", str(MAX_SECONDS)]
    if proxy_url:
        argv += ["--proxy", proxy_url]
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, cwd=workdir, bufsize=1)
    except Exception as exc:  # noqa: BLE001
        if guard:
            guard.stop()
        shutil.rmtree(workdir, ignore_errors=True)
        raise Busy(f"The browser did not start: {type(exc).__name__}") from exc
    rec = Recorder(secrets.token_urlsafe(18), asset_id, slot, owner, host, proc, workdir, guard)
    first = _read_line(proc, 60)
    rec.last = first
    if not rec.alive():
        rec.stop()
        raise Busy("The browser closed as it opened.  "
                   + (first.get("error") or "Check that Playwright works on this server."))
    with _lock:
        _running[rec.id] = rec
    return rec


def get(rid: str, asset_id: int, owner: str) -> Recorder:
    """A running recording, only for the person and site that started it."""
    _reap()
    with _lock:
        rec = _running.get(rid or "")
    if not rec or rec.asset_id != asset_id or rec.owner != owner:
        raise Busy("That recording has ended.  Start a new one.")
    return rec


def _forget(rid: str) -> None:
    with _lock:
        rec = _running.pop(rid, None)
    if rec:
        rec.stop()


def finish(rec: Recorder) -> dict:
    """Ask the browser for what it holds, then close it.  -> the recording."""
    reply = rec.send({"op": "save"}, timeout=30)
    _forget(rec.id)
    if not reply.get("ok"):
        raise ValueError(reply.get("error") or "The browser did not hand back its session.")
    cookies = reply.get("cookies") or []
    if not cookies:
        raise ValueError(f"The browser holds no cookie for {rec.host} yet.  Sign in, or pass "
                         "the check, until the site itself shows, then save.")
    steps = reply.get("steps") or []
    return {"cookies": cookies, "steps": steps, "user_agent": reply.get("user_agent", ""),
            "final_url": reply.get("url", ""), "totp_secret": rec.totp_secret}


def cancel(rec: Recorder) -> None:
    _forget(rec.id)


def public_steps(steps: list) -> list:
    """The steps as the page may show them: what was typed into a password
    field is never shown."""
    out = []
    for s in steps or []:
        view = {"action": s.get("action"), "human": bool(s.get("human"))}
        if s.get("action") == "goto":
            view["what"] = s.get("url", "")
        elif s.get("action") == "click":
            view["what"] = s.get("selector") or f"the point {s.get('x')}, {s.get('y')}"
        elif s.get("action") == "type":
            view["what"] = (f"{s.get('selector')}: "
                            + ("a password" if s.get("secret") else repr(s.get("text", ""))[:80]))
        elif s.get("action") == "totp":
            view["what"] = f"{s.get('selector')}: an authenticator code"
        elif s.get("action") == "key":
            view["what"] = s.get("key", "")
        out.append(view)
    return out


def replay(data: dict, allow_private: bool = False, site_proxy: str = "",
           company_domains: list = None) -> dict:
    """Sign in again by playing the recorded steps.  -> {ok, cookie, detail}"""
    from app.core import external_probe

    out = {"ok": False, "cookie": "", "detail": ""}
    host = data.get("_host", "")
    if not available():
        out["detail"] = "Playwright is not installed"
        return out
    workdir = Path(tempfile.mkdtemp(prefix="gcr-replay-"))
    guard = None
    try:
        proxy_url, guard = _guard_for(workdir, allow_private, site_proxy)
        argv = [_python(), str(SCRIPT), "replay", "--host", host,
                "--allowed", json.dumps(allowed_hosts(host, company_domains or [])),
                "--user-agent", data.get("user_agent") or external_probe.user_agent(),
                "--workdir", str(workdir), "--max-seconds", str(REPLAY_SECONDS)]
        if proxy_url:
            argv += ["--proxy", proxy_url]
        plan = json.dumps({"steps": data.get("steps") or [],
                           "totp_secret": data.get("totp_secret", "")})
        proc = subprocess.run(argv, input=plan, capture_output=True, text=True,
                              timeout=REPLAY_SECONDS + 30, cwd=workdir)
        lines = [ln for ln in (proc.stdout or "").splitlines() if ln.startswith("{")]
        got = json.loads(lines[-1]) if lines else {}
        if got.get("ok") and got.get("cookies"):
            out.update(ok=True, cookie=cookie_header(got["cookies"]), detail=got.get("detail", ""))
        else:
            out["detail"] = got.get("detail") or "the replay gave no session"
    except subprocess.TimeoutExpired:
        out["detail"] = "the replay took too long"
    except Busy as exc:
        out["detail"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - a failed replay is a result
        out["detail"] = f"{type(exc).__name__}"
    finally:
        if guard:
            guard.stop()
        shutil.rmtree(workdir, ignore_errors=True)
    return out


def cookie_header(cookies: list) -> str:
    """Cookies as one Cookie header value, the most specific path first."""
    ordered = sorted(cookies, key=lambda c: -len(c.get("path") or "/"))
    seen, parts = set(), []
    for c in ordered:
        if c["name"] in seen:
            continue
        seen.add(c["name"])
        parts.append(f"{c['name']}={c['value']}")
    return "; ".join(parts)
