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
]
HIDE_AUTOMATION = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
window.chrome = window.chrome || {runtime: {}};
"""


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
    if proxy:
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
                                      ignore_https_errors=True)
            ctx.add_init_script(HIDE_AUTOMATION)
            if not args.allow_private:
                ctx.route("**/*", lambda route: route.continue_()
                          if public(urlparse(route.request.url).hostname or "")
                          else route.abort("addressunreachable"))
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
            page.screenshot(path=args.out, full_page=False)
            out["ok"] = True
            browser.close()
    except Exception as exc:  # noqa: BLE001 - every failure is an answer
        out["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
