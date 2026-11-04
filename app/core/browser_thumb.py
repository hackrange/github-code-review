#!/usr/bin/env python3
"""Shrink site screenshots into the small pictures the External sites list shows.

Run as its own process with the DAST environment's Python, where Playwright
lives; nothing from the app is imported.  The web app has no image library,
and a screenshot is a 1280x800 PNG of several hundred KB or more.  The list
shows it at 128x80, so sending the whole PNG makes every row wait on a full
image.  This draws each PNG into a 256x160 page (twice the box, so it stays
sharp on a high density screen) and saves that as a small JPEG.

One browser does every pair it is given.  The page loads nothing from the
network: the image goes in as a data URL.  The answer is one line of JSON on
standard output with how many were written.

    browser_thumb.py SRC.png DST.jpg [SRC.png DST.jpg ...]
"""

from __future__ import annotations

import base64
import json
import os
import sys

WIDTH, HEIGHT = 256, 160
PAGE = ("<!doctype html><html><head><style>html,body{margin:0;background:#fff}"
        "img{display:block;width:%dpx;height:%dpx;object-fit:cover;object-position:top}"
        "</style></head><body><img src=\"data:image/png;base64,%%s\"></body></html>"
        % (WIDTH, HEIGHT))


def main() -> int:
    pairs = list(zip(sys.argv[1::2], sys.argv[2::2]))
    out = {"written": 0, "error": ""}
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        out["error"] = "playwright is not installed"
        print(json.dumps(out))
        return 0
    launch = {"args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(**launch)
            page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT})
            # Nothing on this page should reach out; the image is inline.
            page.route("**/*", lambda route: route.abort())
            for src, dst in pairs:
                try:
                    with open(src, "rb") as fh:
                        data = base64.b64encode(fh.read()).decode()
                    page.set_content(PAGE % data, wait_until="load", timeout=15000)
                    tmp = dst + ".tmp"
                    page.screenshot(path=tmp, type="jpeg", quality=75)
                    os.replace(tmp, dst)
                    out["written"] += 1
                except Exception as exc:  # noqa: BLE001 - one bad file is not the batch
                    out["error"] = f"{os.path.basename(src)}: {type(exc).__name__}"
            browser.close()
    except Exception as exc:  # noqa: BLE001 - every failure is an answer
        out["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
