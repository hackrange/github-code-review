"""Re-test what a scanning engine only guessed, with a safe request of our own.

An engine's heuristic is a lead.  For the few kinds of lead where a safe,
exact test exists, the scan runs that test and the finding then says what the
test showed: proven, or not reproduced.  A person is no longer asked to judge a
claim the scanner itself could settle.

Every request here is a GET.  Nothing is sent that writes, uploads, or changes
a setting, and nothing is sent to a host other than the one being scanned.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Spring4Shell (CVE-2022-22965) is the data binder letting a request parameter
# walk class.module.classLoader.  The published exploits use that walk to
# rewrite Tomcat's access log settings and drop a JSP web shell, which is never
# done here.  The safe test only asks the binder to convert "nonsense" to a
# boolean on the class loader's DefaultAssertionStatus property:
#
#   vulnerable: the binder reaches the property, the conversion fails before any
#               setter runs, and Spring answers 400 Bad Request.
#   patched:    class.module.classLoader is refused, the parameter is ignored,
#               and the page answers as it does without it.
#
# Nothing is set either way: the value cannot be converted, so the setter is
# never called.  Two look alikes rule out the usual false alarms.  One differs
# only in the property name, so a vulnerable binder ignores it; a 400 there too
# means the endpoint rejects odd parameters, not Spring4Shell.  The other keeps
# the "class.module.classLoader" text behind a prefix the binder cannot follow,
# so a firewall that blocks on that text blocks it too; a firewall answer then
# matches it, and is not read as the bug.
_S4S_PROBE = ("class.module.classLoader.DefaultAssertionStatus", "nonsense")
_S4S_NAME_LOOKALIKE = ("class.module.classLoaderGcr.DefaultAssertionStatus", "nonsense")
_S4S_TEXT_LOOKALIKE = ("gcrx.class.module.classLoader.DefaultAssertionStatus", "nonsense")
SPRING4SHELL = re.compile(r"spring4shell|CVE-2022-22965", re.I)
MAX_S4S_URLS = 6

# Our scan proxy answers for itself when it refuses an out of scope host or
# the target drops a connection.  An engine that sees our proxy's banner saw
# the proxy, not the site.
_OWN_PROXY = re.compile(r"\bmitmproxy\b", re.I)
_SECRET = re.compile(r"api.?key|secret|passw|token|private.key|credential|access.key", re.I)


def _with_param(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    q = parse_qsl(u.query, keep_blank_values=True) + [(name, value)]
    return urlunparse(u._replace(query=urlencode(q)))


def spring4shell_test(url: str, fetch, allow_private: bool = False) -> tuple:
    """-> (proven, detail).  Four GETs to the same address, twice for a hit."""
    def get(u):
        return fetch(u, allow_private=allow_private, follow=False, body_limit=4096)

    for attempt in range(2):
        base = get(url)
        name_like = get(_with_param(url, *_S4S_NAME_LOOKALIKE))
        text_like = get(_with_param(url, *_S4S_TEXT_LOOKALIKE))
        probe = get(_with_param(url, *_S4S_PROBE))
        b, n, t, p = (base.get("status"), name_like.get("status"),
                      text_like.get("status"), probe.get("status"))
        if not (p == 400 and b and b != 400 and n == b and t == b):
            return False, (f"a safe re-test did not reproduce it: the address answered "
                           f"{b} plain, {p} with the class loader parameter, {n} and {t} "
                           f"for the two look alikes; a vulnerable Spring answers 400 to "
                           f"the class loader parameter only")
    return True, (f"proven by a safe re-test, twice: the address answered {b} plain and for "
                  f"two look alike parameters, and 400 only when the parameter reached the "
                  f"class loader (class.module.classLoader.DefaultAssertionStatus=nonsense, "
                  f"a value that cannot be set, so nothing changed)")


def _site_domain(host: str) -> str:
    """The last two labels, or three under a two letter country second level
    (example.co.uk).  Close enough to tell a vendor's CDN from the company."""
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org",
                                                                  "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _third_party(f: dict, host: str) -> bool:
    got = (urlparse(f.get("url") or "").hostname or "").lower()
    if not got or not host:
        return False
    dom = _site_domain(host)
    return not (got == dom or got.endswith("." + dom))


def verify(findings: list, base_url: str, allow_private: bool = False,
           fetch=None, stats: dict = None) -> tuple:
    """-> (findings, dropped).  Re-tests the leads a safe test can settle."""
    if fetch is None:
        from app.core import external_probe
        fetch = external_probe.fetch
    host = (urlparse(base_url).hostname or "").lower()
    out, dropped = [], 0
    for f in findings:
        title = str(f.get("title") or "")
        text = f"{title} {f.get('evidence') or ''}"
        if f.get("tool") == "nikto" and re.search(r"server banner changed", title, re.I) \
                and _OWN_PROXY.search(text):
            dropped += 1
            if stats is not None:
                stats["own_proxy"] = stats.get("own_proxy", 0) + 1
            continue
        if f.get("tool") == "dom" and not f.get("decision") and _third_party(f, host) \
                and not _SECRET.search(text):
            # Never a key or token: one in a vendor's file may still be this
            # company's own credential, and only proof it is dead lowers one.
            # A file another company serves (a login widget's CDN, a video
            # embed).  True of their file, and theirs to fix, not this site's.
            f = dict(f, severity="info", answer="third_party",
                     verified="the file is served by another company's host",
                     title=f"Third-party file: {title}"[:300],
                     evidence=(f"{f.get('evidence') or ''}  The file is on "
                               f"{urlparse(f.get('url') or '').hostname}, another company's "
                               "host, so this site cannot change it.  Report it to that "
                               "vendor if it matters.")[:800])
            if stats is not None:
                stats["third_party"] = stats.get("third_party", 0) + 1
            out.append(f)
            continue
        if f.get("tool") == "wapiti" and SPRING4SHELL.search(text) and not f.get("decision"):
            urls = [u for u in (f.get("urls") or [f.get("url")]) if u]
            urls = [u for u in urls if (urlparse(u).hostname or "").lower() == host][:MAX_S4S_URLS]
            proven, detail = False, "no address on the scanned host to re-test"
            for u in urls:
                proven, detail = spring4shell_test(u, fetch, allow_private)
                if proven:
                    f = dict(f, url=u)
                    break
            if proven:
                f = dict(f, severity="critical", answer="confirmed", verified=detail,
                         evidence=(f"{detail}.  {f.get('evidence') or ''}")[:800])
            else:
                f = dict(f, severity="info", answer="not_reproduced", verified=detail,
                         title="Spring4Shell (not reproduced by a safe re-test)",
                         evidence=(f"Wapiti's heuristic flagged it, but {detail}.  "
                                   f"{f.get('evidence') or ''}")[:800])
            if stats is not None:
                key = "s4s_proven" if proven else "s4s_refuted"
                stats[key] = stats.get(key, 0) + 1
        out.append(f)
    return out, dropped
