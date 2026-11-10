#!/usr/bin/env python3
"""Load one page in a real browser engine and photograph it.

Run as its own process with the DAST environment's Python, where Playwright
lives; nothing from the app is imported.  The answer is one line of JSON on
standard output.

Why a real browser and not a single request: many sites sit behind a bot
check (Imperva, Cloudflare and others) that answers the first request with a
small page whose script sets a cookie and reloads into the real site.  curl
sees that small page and stops.  A stripped down headless browser is stopped
by it and paints nothing.  Full Chromium in its newer headless mode, with the
automation flag hidden and an ordinary window, language and time zone, gets
through most of them, so this waits for the page to replace itself before
taking the picture.

Every request the page makes is checked against private addresses unless
they are allowed, so a page cannot steer the browser into the network this
server sits in.

    browser_shot.py URL OUT.png --user-agent UA [--timeout 45] [--allow-private]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
from urllib.parse import urlparse

BOT_CHECKS = [
    ("Imperva", r"_Incapsula_Resource|Incapsula incident ID"),
    ("Cloudflare", r"/cdn-cgi/challenge-platform|<title>Just a moment\.\.\.</title>|cf-chl-"),
    ("Akamai", r"bm-verify|akamai-bot"),
    ("PerimeterX", r"px-captcha|_pxAppId"),
    ("DataDome", r"captcha-delivery\.com"),
    # Oracle's Zenedge: a 200 titled "Are you human?" served from /__zenedge/.
    ("Zenedge", r"/__zenedge/|zenedge&#x2F;c\?src="),
]
HIDE_AUTOMATION = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
window.chrome = window.chrome || {runtime: {}};
"""

# Many marketing and login templates hide the page behind a full screen
# preloader and reveal the content with scroll animations (WOW, AOS and the
# like).  A single non scrolling capture then photographs a flat loading
# screen, which reads as blank.  Before the picture, switch the animations
# off, show whatever they were holding back, and drop the preloader curtain.
UNVEIL_CSS = """
*, *::before, *::after {
  animation-duration: 0s !important;
  animation-delay: 0s !important;
  transition-duration: 0s !important;
  transition-delay: 0s !important;
}
.wow, .animated, [data-wow-delay], [data-wow-duration], [data-animate],
[data-aos], .aos-init, .fadeIn, .fadeInUp, .fadeInDown, .fadeInLeft,
.fadeInRight {
  visibility: visible !important;
  opacity: 1 !important;
  transform: none !important;
}
.preloader, #preloader, .page-preloader, .page-loader, #page-loader,
.pageloader, .pageload, .loader-wrapper, .loading-overlay, .spinner-wrapper,
.preloader-wrap, .site-preloader, .preloader-overlay, .page-loading {
  display: none !important;
}
"""


def settle_for_shot(page, deadline) -> None:
    """Make a page that hides behind a preloader and scroll animations show
    itself, so the picture is the page and not a flat loading screen.  Every
    step is optional: a strict style policy may refuse the stylesheet, and a
    page mid navigation may refuse the scroll.  None of it must stop the shot.
    """
    if time.monotonic() > deadline - 2:
        return
    try:
        page.add_style_tag(content=UNVEIL_CSS)
    except Exception:  # noqa: BLE001 - a strict style CSP may refuse it
        pass
    try:
        page.evaluate("() => { const d = document.documentElement;"
                      " window.scrollTo(0, Math.max(d.scrollHeight,"
                      " (document.body || d).scrollHeight)); }")
        page.wait_for_timeout(min(400, max(0, int((deadline - time.monotonic() - 2) * 1000))))
        page.evaluate("() => window.scrollTo(0, 0)")
    except Exception:  # noqa: BLE001 - scrolling is a help, not a requirement
        pass
    try:
        page.wait_for_timeout(min(400, max(0, int((deadline - time.monotonic() - 1) * 1000))))
    except Exception:  # noqa: BLE001
        pass


def bot_check(html: str) -> str:
    if len(html or "") > 30000:
        return ""
    for name, pattern in BOT_CHECKS:
        if re.search(pattern, html or "", re.I):
            return name
    return ""


_public: dict = {}


def public(host: str) -> bool:
    if not host:
        return False
    if host in _public:
        return _public[host]
    try:
        addrs = {i[4][0] for i in socket.getaddrinfo(host, None)}
        ok = bool(addrs) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs)
    except (OSError, ValueError):
        ok = False
    _public[host] = ok
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("out")
    ap.add_argument("--user-agent", required=True)
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--allow-private", action="store_true")
    ap.add_argument("--proxy", default="")
    args = ap.parse_args()
    out = {"ok": False, "title": "", "url": args.url, "status": 0, "bot_check": "",
           "bot_check_seen": "", "engine": "", "error": ""}
    deadline = time.monotonic() + args.timeout
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        out["error"] = "playwright is not installed"
        print(json.dumps(out))
        return 0

    proxy = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
             or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY"))
    launch = {"args": ["--disable-blink-features=AutomationControlled", "--no-sandbox",
                       "--disable-dev-shm-usage", "--disable-gpu"]}
    if args.proxy:
        # The site's own proxy, which may carry a user name and password.
        site = urlparse(args.proxy)
        launch["proxy"] = {"server": f"{site.scheme}://{site.hostname}:{site.port or 80}"}
        if site.username:
            launch["proxy"].update(username=site.username, password=site.password or "")
    elif proxy:
        launch["proxy"] = {"server": proxy}
    try:
        with sync_playwright() as p:
            try:
                # Full Chromium in the new headless mode looks like a browser.
                browser = p.chromium.launch(channel="chromium", **launch)
                out["engine"] = "chromium"
            except Exception:  # noqa: BLE001 - only the headless shell is there
                browser = p.chromium.launch(**launch)
                out["engine"] = "headless shell"
            ctx = browser.new_context(user_agent=args.user_agent,
                                      viewport={"width": 1280, "height": 800},
                                      locale="en-US", timezone_id="America/New_York",
                                      reduced_motion="reduce",
                                      ignore_https_errors=True)
            # A session to photograph the page as, read from the environment, not
            # the command line, so the cookie or token never shows in the process
            # list.  It signs the browser in as one account for a proof picture.
            #
            # Added per request, only for the target and its subdomains.  Set on
            # the whole context it went with every image, script and redirect the
            # page asked for, to whatever host, so a page could hand the session
            # to any collector it named.
            try:
                extra = json.loads(os.environ.get("GCR_SHOT_HEADERS", "{}") or "{}")
                extra = ({str(k): str(v) for k, v in extra.items()}
                         if isinstance(extra, dict) else {})
            except Exception:  # noqa: BLE001 - a bad header set just means no session
                extra = {}
            ctx.add_init_script(HIDE_AUTOMATION)
            target = (urlparse(args.url).hostname or "").lower().rstrip(".")
            # A cookie goes in the browser's own jar, for the target's domain,
            # which is what sends it to the target and its subdomains and
            # nowhere else.  A Cookie header set per request is dropped.
            cookie = next((v for k, v in extra.items() if k.lower() == "cookie"), "")
            extra = {k: v for k, v in extra.items() if k.lower() != "cookie"}
            if cookie and target:
                try:
                    ipaddress.ip_address(target)
                    where = {"url": f"{urlparse(args.url).scheme}://{target}/"}
                except ValueError:
                    # A leading dot is what takes it to the subdomains too.
                    where = {"domain": "." + target, "path": "/"}
                jar = []
                for part in cookie.split(";"):
                    name, sep, value = part.strip().partition("=")
                    if sep and name:
                        jar.append({"name": name, "value": value, **where})
                if jar:
                    ctx.add_cookies(jar)
            if extra or not args.allow_private:
                def _route(route):
                    host = (urlparse(route.request.url).hostname or "").lower().rstrip(".")
                    if not args.allow_private and not public(host):
                        route.abort("addressunreachable")
                    elif extra and target and (host == target
                                               or host.endswith("." + target)):
                        route.continue_(headers={**route.request.headers, **extra})
                    else:
                        route.continue_()
                ctx.route("**/*", _route)
            page = ctx.new_page()
            # A check that passes reloads or redirects into the site.  Imperva
            # also puts its script on the real pages, so the script being on
            # the final page says nothing; the page having moved on does.
            moves = {"n": 0}
            page.on("framenavigated",
                    lambda frame: moves.__setitem__("n", moves["n"] + 1)
                    if frame == page.main_frame else None)
            resp = page.goto(args.url, wait_until="domcontentloaded",
                             timeout=max(5000, int((deadline - time.monotonic()) * 1000)))
            out["status"] = resp.status if resp else 0
            # A bot check replaces itself with the site.  Wait for that, then
            # for the site to settle, but never past the deadline.
            while time.monotonic() < deadline - 5:
                try:
                    name = bot_check(page.content())
                except Exception:  # noqa: BLE001 - mid navigation
                    name = "?"
                if not name or moves["n"] >= 2:
                    break
                if name != "?":
                    out["bot_check_seen"] = name
                page.wait_for_timeout(1500)
            try:
                page.wait_for_load_state("networkidle",
                                         timeout=max(1000, int(min(10, deadline - time.monotonic() - 4) * 1000)))
            except Exception:  # noqa: BLE001 - a page that keeps polling never idles
                pass
            html = page.content()
            out["bot_check"] = bot_check(html)
            if out["bot_check"]:
                out["bot_check_seen"] = out["bot_check"]
                if moves["n"] >= 2:
                    out["bot_check"] = ""
            out["navigations"] = moves["n"]
            out["title"] = (page.title() or "")[:200]
            out["url"] = page.url
            settle_for_shot(page, deadline)
            page.screenshot(path=args.out, full_page=False)
            out["ok"] = True
            browser.close()
    except Exception as exc:  # noqa: BLE001 - every failure is an answer
        out["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
