"""The browser behind a recorded scan sign in.

Run by app.core.session_recorder under the DAST virtual environment's python,
which has Playwright and does not have the app, so this imports only the
standard library and Playwright.

Two modes:

    record   a browser a person drives from the site page.  Commands arrive
             one JSON object per line on stdin (click, type, key, goto, back,
             reload, scroll, totp, save, quit) and each answer is one JSON
             object per line on stdout.  The page is photographed into
             frame.jpg after every command and every half second between, so
             the person sees redirects and scripts as they happen.  Every
             command is also kept as a step, so the sign in can be replayed.

    replay   the steps a recording kept, played again in a headless browser
             before a scan, so the scan starts with a fresh session.  The
             steps, which hold the password, come in on stdin, never on the
             command line.  A step a person had to do (a CAPTCHA inside a
             frame) cannot be replayed, and the recorder marks it so.

Either way only the site, its subdomains and the hosts the caller allows may
be opened as a page.  Anything the pages load beside that goes through the
caller's proxy, which refuses private addresses.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import select
import struct
import sys
import time
from urllib.parse import urlparse

VIEWPORT = {"width": 1280, "height": 800}
MAX_STEPS = 80
STEP_TIMEOUT_MS = 15_000

HIDE_AUTOMATION = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
"""

# What a click landed on, named so a replay can find it again without the
# coordinates: an id, a name, a test id, an aria label, or a short path.
SELECTOR_JS = r"""
(arg) => {
  const pick = (e) => {
    if (!e || e.nodeType !== 1) return '';
    const q = (s) => s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    if (e.id && /^[A-Za-z][\w-]*$/.test(e.id)) return '#' + e.id;
    const tag = e.tagName.toLowerCase();
    for (const a of ['name', 'data-testid', 'data-se', 'aria-label', 'placeholder']) {
      const v = e.getAttribute(a);
      if (v && v.length < 120) return tag + '[' + a + '="' + q(v) + '"]';
    }
    if ((tag === 'button' || tag === 'a') && (e.innerText || '').trim().length
        && (e.innerText || '').trim().length < 60) {
      return tag + ':has-text("' + q((e.innerText || '').trim()) + '")';
    }
    const parts = [];
    let c = e;
    while (c && c.nodeType === 1 && parts.length < 7) {
      if (c.id && /^[A-Za-z][\w-]*$/.test(c.id)) { parts.unshift('#' + c.id); break; }
      let p = c.tagName.toLowerCase();
      const same = c.parentElement
        ? Array.from(c.parentElement.children).filter(x => x.tagName === c.tagName) : [];
      if (same.length > 1) p += ':nth-of-type(' + (same.indexOf(c) + 1) + ')';
      parts.unshift(p);
      c = c.parentElement;
    }
    return parts.join(' > ');
  };
  let el = arg.focused ? document.activeElement
                       : document.elementFromPoint(arg.x, arg.y);
  if (!el) return null;
  const tag = el.tagName.toLowerCase();
  const frame = tag === 'iframe' || tag === 'frame';
  if (!arg.focused) {
    el = el.closest('a,button,input,select,textarea,label,[role=button],[onclick]') || el;
  }
  return {selector: pick(el), tag: el.tagName.toLowerCase(), frame: frame,
          type: (el.getAttribute('type') || '').toLowerCase(),
          editable: ['input', 'textarea'].includes(el.tagName.toLowerCase())
                    || el.isContentEditable === true};
}
"""


def totp(secret: str, when: float = None) -> str:
    """The six digit code an authenticator app shows now (RFC 6238)."""
    key = base64.b32decode(secret.replace(" ", "").upper() + "=" * (-len(secret) % 8))
    counter = int((when or time.time()) // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def _allowed(host: str, allowed: list) -> bool:
    host = (host or "").lower().rstrip(".")
    return bool(host) and any(host == a or host.endswith("." + a) for a in allowed)


def _launch(p, args):
    launch = {"args": ["--disable-blink-features=AutomationControlled", "--no-sandbox",
                       "--disable-dev-shm-usage", "--disable-gpu"]}
    if args.proxy:
        site = urlparse(args.proxy)
        launch["proxy"] = {"server": f"{site.scheme}://{site.hostname}:{site.port or 80}"}
        if site.username:
            launch["proxy"].update(username=site.username, password=site.password or "")
    try:
        return p.chromium.launch(channel="chromium", **launch)
    except Exception:  # noqa: BLE001 - only the headless shell is installed
        return p.chromium.launch(**launch)


def _context(browser, args, allowed):
    ctx = browser.new_context(user_agent=args.user_agent, viewport=VIEWPORT,
                              locale="en-US", timezone_id="America/New_York",
                              ignore_https_errors=True)
    ctx.add_init_script(HIDE_AUTOMATION)

    def route(r):
        req = r.request
        # Only a page itself is held to the list: a sign in page loads its
        # scripts, fonts and challenge widgets from elsewhere, and the proxy
        # already refuses private addresses for those.
        if req.is_navigation_request() and req.frame == req.frame.page.main_frame:
            host = urlparse(req.url).hostname or ""
            if urlparse(req.url).scheme not in ("http", "https") or not _allowed(host, allowed):
                r.abort("blockedbyclient")
                return
        r.continue_()

    ctx.route("**/*", route)
    return ctx


def _settle(page, ms: int = 4000) -> None:
    try:
        page.wait_for_load_state("domcontentloaded", timeout=ms)
    except Exception:  # noqa: BLE001 - a page still loading is fine to show
        pass


def _cookies_for(ctx, host: str) -> list:
    """The cookies the browser holds for the site and its parent domains."""
    host = host.lower()
    out = []
    for c in ctx.cookies():
        domain = (c.get("domain") or "").lstrip(".").lower()
        if domain and (host == domain or host.endswith("." + domain)):
            out.append({"name": c["name"], "value": c["value"], "domain": c.get("domain", ""),
                        "path": c.get("path", "/"), "expires": c.get("expires", -1)})
    return out


# ------------------------------------------------------------------ record

def record(args) -> int:
    from playwright.sync_api import sync_playwright

    allowed = json.loads(args.allowed)
    frame_path = os.path.join(args.workdir, "frame.jpg")
    steps = []

    def say(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def shoot(page):
        tmp = frame_path + ".tmp"
        try:
            page.screenshot(path=tmp, type="jpeg", quality=60, full_page=False, timeout=5000)
            os.replace(tmp, frame_path)
        except Exception:  # noqa: BLE001 - a page mid navigation cannot be photographed
            pass

    def keep(step):
        if len(steps) < MAX_STEPS:
            steps.append(step)

    def where(page):
        try:
            return {"url": page.url, "title": (page.title() or "")[:200]}
        except Exception:  # noqa: BLE001
            return {"url": "", "title": ""}

    with sync_playwright() as p:
        browser = _launch(p, args)
        ctx = _context(browser, args, allowed)
        page = ctx.new_page()
        try:
            page.goto(args.url, wait_until="domcontentloaded", timeout=30_000)
        except Exception as exc:  # noqa: BLE001 - show what happened, keep going
            say({"ok": False, "error": f"the page did not open: {type(exc).__name__}"})
        keep({"action": "goto", "url": args.url})
        shoot(page)
        say({"ok": True, "ready": True, **where(page)})
        deadline = time.monotonic() + args.max_seconds
        while time.monotonic() < deadline:
            ready, _w, _x = select.select([sys.stdin], [], [], 0.5)
            if not ready:
                shoot(page)
                continue
            line = sys.stdin.readline()
            if not line:
                break
            try:
                cmd = json.loads(line)
            except ValueError:
                say({"ok": False, "error": "not JSON"})
                continue
            op = cmd.get("op")
            reply = {"ok": True}
            try:
                if op == "click":
                    x = max(0, min(VIEWPORT["width"] - 1, int(cmd.get("x", 0))))
                    y = max(0, min(VIEWPORT["height"] - 1, int(cmd.get("y", 0))))
                    hit = page.evaluate(SELECTOR_JS, {"x": x, "y": y, "focused": False}) or {}
                    page.mouse.click(x, y)
                    keep({"action": "click", "selector": hit.get("selector", ""), "x": x, "y": y,
                          "human": bool(hit.get("frame")) or not hit.get("selector")})
                elif op == "type":
                    text = str(cmd.get("text", ""))[:500]
                    hit = page.evaluate(SELECTOR_JS, {"focused": True}) or {}
                    page.keyboard.type(text, delay=20)
                    secret = hit.get("type") == "password"
                    last = steps[-1] if steps else {}
                    if (last.get("action") == "type" and last.get("selector") == hit.get("selector")
                            and hit.get("selector")):
                        last["text"] += text
                    else:
                        keep({"action": "type", "selector": hit.get("selector", ""), "text": text,
                              "secret": secret, "human": not hit.get("selector")
                              or not hit.get("editable")})
                elif op == "key":
                    key = str(cmd.get("key", ""))
                    if key not in ("Enter", "Tab", "Backspace", "Escape", "ArrowDown",
                                   "ArrowUp", "Space", "Delete"):
                        raise ValueError("that key is not offered")
                    page.keyboard.press(key)
                    if key == "Backspace" and steps and steps[-1].get("action") == "type":
                        steps[-1]["text"] = steps[-1]["text"][:-1]
                    else:
                        keep({"action": "key", "key": key})
                elif op == "totp":
                    code = totp(str(cmd.get("secret", "")))
                    hit = page.evaluate(SELECTOR_JS, {"focused": True}) or {}
                    page.keyboard.type(code, delay=20)
                    keep({"action": "totp", "selector": hit.get("selector", ""),
                          "human": not hit.get("selector")})
                elif op == "goto":
                    url = str(cmd.get("url", ""))
                    if not _allowed(urlparse(url).hostname or "", allowed) \
                            or urlparse(url).scheme not in ("http", "https"):
                        raise ValueError("that address is not the site or its sign in")
                    page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                    keep({"action": "goto", "url": url})
                elif op == "back":
                    page.go_back(timeout=15_000)
                    keep({"action": "back"})
                elif op == "reload":
                    page.reload(timeout=15_000)
                    keep({"action": "reload"})
                elif op == "scroll":
                    page.mouse.wheel(0, max(-2000, min(2000, int(cmd.get("dy", 0)))))
                elif op == "human":
                    if steps:
                        steps[-1]["human"] = True
                elif op == "save":
                    _settle(page)
                    reply.update(cookies=_cookies_for(ctx, args.host), steps=steps,
                                 user_agent=args.user_agent)
                elif op == "quit":
                    break
                elif op != "shot":
                    raise ValueError("unknown command")
            except Exception as exc:  # noqa: BLE001 - a failed click is an answer, not a crash
                reply = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
            if op in ("click", "key", "totp"):
                # A click or Enter that submits a form starts navigating a
                # moment later; give it that moment so the answer describes
                # the page it leads to, not the one it left.
                page.wait_for_timeout(350)
            _settle(page, 3000)
            shoot(page)
            reply.update(where(page))
            reply["steps_kept"] = len(steps)
            reply["human_steps"] = sum(1 for s in steps if s.get("human"))
            say(reply)
        try:
            browser.close()
        except Exception:  # noqa: BLE001
            pass
    return 0


# ------------------------------------------------------------------ replay

def replay(args) -> int:
    """Play the recorded steps again and print the cookies it ends with."""
    from playwright.sync_api import sync_playwright

    allowed = json.loads(args.allowed)
    plan = json.loads(sys.stdin.read() or "{}")
    steps = plan.get("steps") or []
    out = {"ok": False, "cookies": [], "detail": "", "url": ""}
    if any(s.get("human") for s in steps):
        out["detail"] = "a recorded step needs a person, such as a CAPTCHA"
        print(json.dumps(out))
        return 0
    deadline = time.monotonic() + args.max_seconds
    with sync_playwright() as p:
        browser = _launch(p, args)
        ctx = _context(browser, args, allowed)
        page = ctx.new_page()
        done = 0
        try:
            for step in steps:
                if time.monotonic() > deadline:
                    raise TimeoutError("the sign in took too long")
                action = step.get("action")
                if action == "goto":
                    page.goto(step["url"], wait_until="domcontentloaded", timeout=30_000)
                elif action == "click":
                    try:
                        page.locator(step["selector"]).first.click(timeout=STEP_TIMEOUT_MS)
                    except Exception:  # noqa: BLE001 - the same place, if the name moved
                        page.mouse.click(step["x"], step["y"])
                elif action == "type":
                    page.locator(step["selector"]).first.fill(step.get("text", ""),
                                                              timeout=STEP_TIMEOUT_MS)
                elif action == "totp":
                    page.locator(step["selector"]).first.fill(totp(plan.get("totp_secret", "")),
                                                              timeout=STEP_TIMEOUT_MS)
                elif action == "key":
                    page.keyboard.press(step["key"])
                elif action == "back":
                    page.go_back(timeout=STEP_TIMEOUT_MS)
                elif action == "reload":
                    page.reload(timeout=STEP_TIMEOUT_MS)
                _settle(page, 8000)
                page.wait_for_timeout(400)
                done += 1
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:  # noqa: BLE001 - a page that keeps polling never idles
                pass
            out.update(ok=True, cookies=_cookies_for(ctx, args.host), url=page.url,
                       detail=f"replayed {done} step{'s' if done != 1 else ''}")
        except Exception as exc:  # noqa: BLE001 - which step failed is the answer
            out["detail"] = (f"step {done + 1} of {len(steps)} ({steps[done].get('action')}) "
                             f"failed: {type(exc).__name__}"
                             if done < len(steps) else f"{type(exc).__name__}")
        try:
            browser.close()
        except Exception:  # noqa: BLE001
            pass
    print(json.dumps(out))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("record", "replay"))
    ap.add_argument("--url", default="")
    ap.add_argument("--host", required=True)
    ap.add_argument("--allowed", required=True, help="JSON list of hosts a page may be on")
    ap.add_argument("--user-agent", required=True)
    ap.add_argument("--proxy", default="")
    ap.add_argument("--workdir", default=".")
    ap.add_argument("--max-seconds", type=int, default=900)
    args = ap.parse_args()
    return record(args) if args.mode == "record" else replay(args)


if __name__ == "__main__":
    sys.exit(main())
