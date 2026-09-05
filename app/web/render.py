"""Templates.

One place that knows where they live and what every page gets for free.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import APP_NAME, VERSION, settings

_TEMPLATES = Path(__file__).resolve().parent / "templates"

# Autoescape on, always.  Everything on these pages came from a repository we
# did not write, including file names and commit messages.
env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


# Fingerprints for the static files, so a changed stylesheet actually reaches
# a browser.
#
# These were linked as ?v=VERSION, and VERSION is a constant in the source.  It
# does not change when the CSS does, so the URL never changed, and with
# max-age=3600 on the response a browser kept serving yesterday's stylesheet
# for an hour after a deploy.  Fixes went out and nobody saw them.  The token
# is the file's own size and mtime now, so it changes exactly when the file
# does and never when it does not.
_ASSET_TOKENS: dict = {}


def asset_v(name: str) -> str:
    """A short token for a static file, from its size and modification time."""
    token = _ASSET_TOKENS.get(name)
    if token is not None:
        return token
    path = _TEMPLATES.parent / "static" / name
    try:
        stat = path.stat()
        raw = f"{stat.st_size}-{int(stat.st_mtime)}"
        token = hashlib.sha256(raw.encode()).hexdigest()[:10]
    except OSError:
        # Never fail a page over a cache token.
        token = VERSION
    _ASSET_TOKENS[name] = token
    return token


env.globals["asset_v"] = asset_v


def _zone():
    """The zone from the Settings page, or GMT if it cannot be read."""
    from zoneinfo import ZoneInfo

    try:
        from app.core import live
        return ZoneInfo(live.timezone_name())
    except Exception:
        return ZoneInfo("GMT")


def local_dt(value):
    """A stored timestamp, moved into the configured zone.

    Everything is written as UTC.  MariaDB hands it back with no zone attached,
    so a naive value is UTC rather than anything to do with the machine's clock.
    """
    if value is None:
        return None
    if not isinstance(value, datetime):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_zone())


def fmt_dt(value, fmt: str = "%Y-%m-%d %H:%M"):
    """Format a stored timestamp in the configured zone.

    Templates used to call .strftime() straight on the value, which printed UTC
    and gave somebody in Miami a time four hours out.
    """
    moved = local_dt(value)
    if moved is None:
        return ""
    if not isinstance(moved, datetime):
        return moved
    return moved.strftime(fmt)


def tz_label() -> str:
    """The short name for right now, so a column can say EDT rather than -0400."""
    try:
        return datetime.now(_zone()).strftime("%Z")
    except Exception:
        return "GMT"


def web_url(value) -> str:
    """A link the page will follow, or nothing.

    These come out of advisory data rather than out of a person, so this is
    not the place a hostile URL was expected to arrive from.  It is one line
    to make that structural rather than a matter of trust: a href beginning
    javascript: runs when somebody clicks it, and every one of these is
    rendered into an anchor a reader is being invited to click.

    Scheme only.  Nothing here tries to decide whether a host is reputable,
    because the useful advisory sources are many and change, and a list of
    approved ones would go stale into a page that silently stops linking.
    """
    text = str(value or "").strip()
    lowered = text.lower()
    if lowered.startswith("https://") or lowered.startswith("http://"):
        return text
    return ""


def sentence_spaced(value) -> str:
    """Keep the gap between sentences that HTML would otherwise swallow.

    The generated reports are written with two spaces after a full stop, which
    is the house style for documents that leave the building.  HTML collapses
    runs of whitespace to one, so that rule survives in the source and
    disappears in the rendered page, which is the worst of both: the style is
    followed and the reader never sees it.

    A non breaking space followed by an ordinary one keeps the width and still
    lets the line break where it should, because the break can happen at the
    second space.  Doing it here rather than in the text means the sentences
    stay ordinary strings that a test can read.
    """
    text = str(value or "")
    for stop in (". ", "? ", "! "):
        text = text.replace(stop + " ", stop[0] + "\u00a0 ")
    return text


env.filters["sentence_spaced"] = sentence_spaced
env.filters["local_dt"] = local_dt
env.filters["dt"] = fmt_dt
env.filters["web_url"] = web_url


def render_partial(template: str, **context) -> str:
    """A fragment, with none of the page furniture around it.

    For the places a page replaces one piece of itself rather than reloading:
    the same template the page includes, so a row cannot end up looking one way
    on load and another way after a search.
    """
    return env.get_template(template).render(**context)


# What a redirect's ?kind= is called in the stylesheet.
#
# These are not the same vocabulary and were being used as though they were.
# A redirect says error, warn or ok; the stylesheet has bad, warn, ok and info.
# Passed straight through, kind=error produced class="notice error", which
# matches nothing, so the one banner that most needed to be red rendered with
# no styling at all.
#
# Mapped in one place because it was previously mapped in several, each
# slightly differently, and the finding page collapsed warn into ok: a recheck
# reporting that a secret is still there came out green, which is the opposite
# of what it found.
NOTICE_CLASSES = {"error": "bad", "bad": "bad",
                  "warn": "warn", "warning": "warn",
                  "ok": "ok", "success": "ok",
                  "info": "info"}


def notice_class(kind: str) -> str:
    """The stylesheet's name for a banner of this kind.  Unknown reads info."""
    return NOTICE_CLASSES.get((kind or "").strip().lower(), "info")


def page(request: Request, template: str, **context) -> HTMLResponse:
    """Render a page with the bits every template expects."""
    from app.web.security import CSRF_COOKIE, issue_csrf, new_csrf_token

    token = request.cookies.get(CSRF_COOKIE) or new_csrf_token()
    # Templates that want the current URL should be able to have it.  A page
    # that renders fine until somebody has enough data to need a second page is
    # a bad way to find out this was missing.
    context.setdefault("request", request)
    context.setdefault("base", settings.base_path)
    context.setdefault("version", VERSION)
    context.setdefault("app_name", APP_NAME)
    context.setdefault("csrf_token", token)
    context.setdefault("flash", request.query_params.get("msg", ""))
    context.setdefault("flash_kind",
                       notice_class(request.query_params.get("kind", "")))
    context.setdefault("tz_label", tz_label())
    # How people sign in decides what half the controls on a page are for.
    # It is cached for a few seconds, so asking here costs nothing and saves
    # every route that renders a page from remembering to pass it.
    if "auth" not in context:
        from app.core import live
        context["auth"] = live.auth_config()

    html = env.get_template(template).render(**context)
    response = HTMLResponse(html)
    issue_csrf(response, token)
    return response
