#!/usr/bin/env python3
"""Load one page in a real browser and hand back the JavaScript it ran.

Run as its own process with the DAST environment's Python, where Playwright
lives; nothing from the app is imported.  The answer is one line of JSON on
standard output: the scripts the page loaded (bundles and inline), and any
source maps those bundles point at that actually carry the source.

Why a real browser and not a plain fetch: a modern app loads most of its code
with more JavaScript after the first response, so a single request sees almost
none of it.  A headless browser runs the page and sees it all.

Every request the page makes is checked against private addresses unless they
are allowed, so a page cannot steer the browser into this server's network.

    browser_dom.py URL --user-agent UA [--timeout 45] [--allow-private]
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
from urllib.parse import urljoin, urlparse

HIDE_AUTOMATION = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
window.chrome = window.chrome || {runtime: {}};
"""

MAX_ONE = 512 * 1024          # one script
MAX_TOTAL = 4 * 1024 * 1024   # all scripts
MAX_SCRIPTS = 60
MAX_MAPS = 12
_SMAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"]+)")

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
    ap.add_argument("--user-agent", required=True)
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--allow-private", action="store_true")
    ap.add_argument("--proxy", default="")
    args = ap.parse_args()
    out = {"ok": False, "url": args.url, "scripts": [], "inline": [], "maps": [], "error": ""}
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
        site = urlparse(args.proxy)
        launch["proxy"] = {"server": f"{site.scheme}://{site.hostname}:{site.port or 80}"}
        if site.username:
            launch["proxy"].update(username=site.username, password=site.password or "")
    elif proxy:
        launch["proxy"] = {"server": proxy}

    scripts, total = [], [0]

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(channel="chromium", **launch)
            except Exception:  # noqa: BLE001 - only the headless shell is there
                browser = p.chromium.launch(**launch)
            ctx = browser.new_context(user_agent=args.user_agent,
                                      viewport={"width": 1280, "height": 800},
                                      ignore_https_errors=True)
            ctx.add_init_script(HIDE_AUTOMATION)
            if not args.allow_private:
                ctx.route("**/*", lambda route: route.continue_()
                          if public(urlparse(route.request.url).hostname or "")
                          else route.abort("addressunreachable"))

            def on_response(resp):
                try:
                    if len(scripts) >= MAX_SCRIPTS or total[0] >= MAX_TOTAL:
                        return
                    rtype = resp.request.resource_type
                    ctype = (resp.headers.get("content-type") or "").lower()
                    if rtype != "script" and "javascript" not in ctype:
                        return
                    body = resp.text()
                    if not body:
                        return
                    body = body[:MAX_ONE]
                    total[0] += len(body)
                    scripts.append({"url": resp.url, "text": body})
                except Exception:  # noqa: BLE001 - a body we cannot read is skipped
                    pass

            page = ctx.new_page()
            page.on("response", on_response)
            page.goto(args.url, wait_until="domcontentloaded",
                      timeout=max(5000, int((deadline - time.monotonic()) * 1000)))
            try:
                page.wait_for_load_state("networkidle",
                                         timeout=max(1000, int(min(12, deadline - time.monotonic() - 4) * 1000)))
            except Exception:  # noqa: BLE001 - a page that keeps polling never idles
                pass
            out["url"] = page.url
            try:
                out["inline"] = page.eval_on_selector_all(
                    "script:not([src])", "els => els.map(e => e.textContent).filter(Boolean)")[:40]
            except Exception:  # noqa: BLE001
                out["inline"] = []

            # Source maps the bundles point at, fetched to see if they carry source.
            maps_seen = set()
            for s in scripts:
                if len(out["maps"]) >= MAX_MAPS or time.monotonic() > deadline - 3:
                    break
                m = _SMAP.search(s["text"][-2000:])
                if not m or m.group(1).startswith("data:"):
                    continue
                map_url = urljoin(s["url"], m.group(1))
                if map_url in maps_seen or not public(urlparse(map_url).hostname or ""):
                    continue
                maps_seen.add(map_url)
                try:
                    r = ctx.request.get(map_url, timeout=8000)
                    if r.ok:
                        out["maps"].append({"url": map_url, "text": r.text()[:MAX_ONE]})
                except Exception:  # noqa: BLE001
                    pass

            out["scripts"] = scripts
            out["ok"] = True
            browser.close()
    except Exception as exc:  # noqa: BLE001 - every failure is an answer
        out["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
