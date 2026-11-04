"""What a dynamic scan reached, and which code likely answers it.

Two questions, one set of data.

How much of the site did the scan cover?  Every engine that writes down what
it fetched is read for the paths it got an answer for, with the status: the
wapiti crawler keeps every page in its session, ffuf lists the words that
answered, and the other engines name the addresses of their findings.

Which repository is behind the site?  The scanner reads the routes each
repository declares on its default branch.  A path the site really serves
that a repository also declares is evidence that repository is behind it.
A rare, specific path like /api/claims/1/attachments says a lot.  A path
every repository has, like /login or /health, says nothing and is left out.

"Really serves" is the hard part.  Plenty of sites answer every address the
same way: a single page app sends its index page for anything, a gateway
sends 401 for everything under /api, a sign in wall redirects everything.
Only a 200 is a path.  A redirect, a sign in prompt or a refusal is
something standing in front of a page, not the page.  And a 200 only counts
when the site answers an address that cannot exist some other way: that
answer is asked for first, at the root and under each prefix, and a 200
beside a 200 is fetched again and only counts when its page differs.  What
could not be checked does not count.  A wrong repository here would get scanned and reported as the code
behind a site it has nothing to do with, so the rule is to under claim.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets as _secrets
from urllib.parse import urlparse

MAX_PATHS = 3000
MAX_CONTROLS = 30
MAX_VERIFY = 150
MAX_CANDIDATES = 15
SHOW_AT = 20
CAP = 95

# Only a 200 is a path the site serves.  A redirect, a sign in prompt or a
# refusal is something in front of the page, and the same answer comes back
# for paths that are not there at all.
def exists(status) -> bool:
    return status == 200


# Routes so common they point at no repository in particular.
GENERIC = {
    "/", "/1", "/login", "/logout", "/signin", "/signout", "/register", "/signup",
    "/health", "/healthz", "/healthcheck", "/health/1", "/ready", "/readyz", "/live",
    "/livez", "/status", "/ping", "/metrics", "/version", "/info", "/error", "/home",
    "/index", "/index.html", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/api",
    "/admin", "/auth", "/callback", "/static", "/assets", "/public", "/about",
    "/contact", "/search", "/test", "/hello", "/swagger", "/docs", "/openapi.json",
    "/swagger.json", "/actuator", "/actuator/health", "/actuator/info", "/me", "/user",
    "/users", "/users/1", "/profile", "/settings", "/dashboard", "/oauth/callback",
    "/auth/callback", "/token", "/refresh", "/upload", "/download", "/webhook",
}


# ---------------------------------------------------------------- inventory

def clean_path(url: str, host: str = "") -> str:
    """The path of an address on this host, without its query, or ""."""
    try:
        parts = urlparse(url if "://" in url else "http://x" + (url if url.startswith("/") else "/" + url))
    except ValueError:
        return ""
    if host and "://" in url and (parts.hostname or "").lower() != host.lower():
        return ""
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    if len(path) > 300 or any(c in path for c in " \"'<>\\"):
        return ""
    return path


RANK = lambda s: (-1 if s == 200 else 0 if isinstance(s, int) and 200 <= s < 300 else
                  1 if isinstance(s, int) and 300 <= s < 400 else
                  2 if s in (401, 403, 405) else
                  4 if s in (404, 410) else
                  5 if not s else 3)


def inventory(base_url: str, seen: dict, findings: list, from_code=()) -> list:
    """One record per path, from every engine.

    seen is {tool: [{"url", "status", "method"}]}; findings carry a url and
    a tool.  -> [{"p": path, "s": best status or None, "e": [engines],
    "m": [methods], "c": True when the code declared it}]
    """
    host = (urlparse(base_url).hostname or "").lower()
    by_path = {}
    code = set(from_code or ())

    def add(url, status, tool, method="GET"):
        path = clean_path(url, host)
        if not path:
            return
        rec = by_path.get(path)
        if rec is None:
            if len(by_path) >= MAX_PATHS:
                return
            rec = by_path[path] = {"p": path, "s": None, "e": [], "m": []}
        if status and (rec["s"] is None or RANK(status) < RANK(rec["s"])):
            rec["s"] = int(status)
        if tool and tool not in rec["e"]:
            rec["e"].append(tool)
        method = (method or "GET").upper()[:10]
        if method not in rec["m"]:
            rec["m"].append(method)

    for tool, rows in (seen or {}).items():
        for row in rows or []:
            add(row.get("url") or "", row.get("status"), tool, row.get("method"))
    for f in findings or []:
        tool = f.get("tool") or f.get("check") or ""
        if f.get("url"):
            add(f["url"], None, tool)
    for rec in by_path.values():
        if rec["p"] in code:
            rec["c"] = True
    return sorted(by_path.values(), key=lambda r: r["p"])


# ----------------------------------------------------- real or not found page

def fingerprint(body: str) -> str:
    """A page, minus white space and the random part of our own addresses,
    so a not found page that echoes the address back still compares equal."""
    return hashlib.sha256(re.sub(r"\s+", " ", re.sub(r"gcr-[0-9a-f]+", "", body or ""))
                          .encode()).hexdigest()


def _prefixes(path: str) -> list:
    """The prefixes a control is asked for, longest first: /a/b, /a, and /."""
    segs = [s for s in path.split("/") if s]
    out = []
    for n in (2, 1):
        if len(segs) > n:
            out.append("/" + "/".join(segs[:n]))
    return out + ["/"]


def classify(records: list, fetch) -> dict:
    """Mark each record reachable (True), not (False), or unchecked (None).

    fetch(path) -> {"status", "body"} for a path on the site, without
    following redirects.  A 200 beside a 200 control, and a path only named
    in a finding, are left unchecked and marked "v" for verify() to fetch.
    -> the controls, by prefix
    """
    # Controls: the root, and each prefix that holds a 200.
    busy = {}
    for rec in records:
        if rec.get("s") in (200, None):
            for pre in _prefixes(rec["p"])[:-1]:
                busy[pre] = busy.get(pre, 0) + 1
    # Every prefix gets one, busiest first: a gateway that answers 200 for
    # anything under /api/v1 does it for the one path the crawler saw too.
    wanted = ["/"] + [p for p, _n in sorted(busy.items(), key=lambda kv: (-kv[1], kv[0]))
                      ][:MAX_CONTROLS - 1]
    controls = {}
    for pre in wanted:
        probe = pre.rstrip("/") + f"/gcr-{_secrets.token_hex(6)}/{_secrets.token_hex(4)}.html"
        got = fetch(probe) or {}
        controls[pre] = {"status": int(got.get("status") or 0),
                         "fp": fingerprint(got.get("body") or "") if got.get("body") else ""}
    for rec in records:
        rec.pop("v", None)
        status = rec.get("s")
        cs = _control(controls, rec["p"])["status"]
        if status is not None and status != 200:
            rec["r"] = False
        elif cs == 0:
            # No answer for nonsense: nothing to compare against.
            rec["r"] = None
        elif status == 200 and cs != 200:
            rec["r"] = True
        else:
            # A 200 where nonsense gets a 200 too, or a path only named in a
            # finding, whose status nobody wrote down.
            rec["r"] = None
            rec["v"] = True
    return controls


def _control(controls: dict, path: str) -> dict:
    return controls[next(p for p in _prefixes(path) if p in controls)]


def verify(records: list, controls: dict, fetch, first=()) -> int:
    """Fetch the unchecked paths again, the ones in first before the rest, and
    keep those that answer 200 with a page that is not the not found page.
    -> how many were fetched"""
    first = set(first or ())
    todo = sorted((r for r in records if r.get("v")), key=lambda r: r["p"] not in first)
    done = 0
    for rec in todo[:MAX_VERIFY]:
        done += 1
        control = _control(controls, rec["p"])
        got = fetch(rec["p"]) or {}
        status = int(got.get("status") or 0)
        if rec.get("s") is None and status:
            rec["s"] = status
        rec["r"] = (status == 200 and bool(got.get("body")) and
                    (control["status"] != 200 or fingerprint(got["body"]) != control["fp"]))
        rec.pop("v", None)
    return done


def counts(records: list) -> dict:
    """What the scan reached, for the page and the report."""
    out = {"answered": len(records), "reachable": 0, "unchecked": 0, "from_code": 0,
           "by_status": {"200": 0, "2xx": 0, "3xx": 0, "401/403": 0, "404": 0, "other": 0, "none": 0},
           "by_engine": {}}
    for rec in records:
        s = rec.get("s")
        key = ("none" if s is None else "200" if s == 200 else "2xx" if 200 <= s < 300 else "3xx" if 300 <= s < 400
               else "401/403" if s in (401, 403) else "404" if s in (404, 410) else "other")
        out["by_status"][key] += 1
        if rec.get("r") is True:
            out["reachable"] += 1
            if rec.get("c"):
                out["from_code"] += 1
        elif rec.get("r") is None:
            out["unchecked"] += 1
        for tool in rec.get("e") or []:
            out["by_engine"][tool] = out["by_engine"].get(tool, 0) + 1
    return out


# ------------------------------------------------------------------ matching

def _segs(path: str) -> list:
    return [s for s in path.lower().split("/") if s]


class Index:
    """The declared routes of many repositories, looked up by path.

    A route's parameters were written as 1 when it was read, so a 1 in a
    route matches any one segment.  A route also matches the end of a longer
    path when it has two or more fixed segments, since code mounted under a
    prefix (a servlet context, a gateway path, a router mounted at /api)
    declares the part after the prefix.
    """

    def __init__(self, routes_by_repo: dict, skip_generic: bool = True):
        self.routes = {}
        holders = {}
        for repo_id, routes in routes_by_repo.items():
            clean = []
            for r in routes or []:
                if not isinstance(r, str):
                    continue
                key = "/" + "/".join(_segs(r))
                if key not in clean:
                    clean.append(key)
            self.routes[repo_id] = clean
            for key in clean:
                holders.setdefault(key, set()).add(repo_id)
        # A route many repositories declare is somebody's framework, not
        # this site's code.
        limit = max(5, math.ceil(0.05 * len(self.routes)))
        self.generic = ({k for k, ids in holders.items() if len(ids) > limit} | GENERIC
                        if skip_generic else set())
        self.buckets = {}
        for repo_id, routes in self.routes.items():
            for key in routes:
                segs = _segs(key)
                literal = [i for i, s in enumerate(segs) if s != "1"]
                if key in self.generic or not literal:
                    continue
                k = len(segs) - 1 - literal[-1]
                self.buckets.setdefault((len(segs), k, segs[literal[-1]]), []).append(
                    (repo_id, key, segs, len(literal)))

    def lookup(self, path: str) -> list:
        """-> [(repo_id, route, literal segments, exact)]"""
        ps = _segs(path)
        out = []
        for n in range(1, len(ps) + 1):
            tail = ps[len(ps) - n:]
            for k in range(n):
                for repo_id, key, segs, lit in self.buckets.get((n, k, tail[n - 1 - k]), ()):
                    exact = n == len(ps)
                    if not exact and lit < 2:
                        continue
                    if all(r == "1" or r == t for r, t in zip(segs, tail)):
                        out.append((repo_id, key, lit, exact))
        return out

    def any_match(self, path: str) -> bool:
        return bool(self.lookup(path))


def weight(literal: int, exact: bool) -> float:
    w = 0.25 if literal == 1 else 0.45 if literal == 2 else 0.6
    return w if exact else w * 0.7


def match(records: list, index: Index, names: dict) -> list:
    """Repositories whose routes the site really serves, best first.

    Each real path counts once per repository, by its best matching route,
    and a path several repositories declare is split between them.
    -> [{repo_id, full_name, confidence, matched: [{path, route, exact,
    status}], matched_count, routes_total}]
    """
    per_repo = {}
    for rec in records:
        if rec.get("r") is not True:
            continue
        hits = index.lookup(rec["p"])
        if not hits:
            continue
        best = {}
        for repo_id, key, lit, exact in hits:
            w = weight(lit, exact)
            if repo_id not in best or w > best[repo_id][0]:
                best[repo_id] = (w, key, exact)
        share = len(best)
        for repo_id, (w, key, exact) in best.items():
            entry = per_repo.setdefault(repo_id, {"miss": 1.0, "matched": []})
            entry["miss"] *= 1 - w / share
            entry["matched"].append({"path": rec["p"], "route": key, "exact": exact,
                                     "status": rec.get("s")})
    out = []
    for repo_id, entry in per_repo.items():
        confidence = min(CAP, round(100 * (1 - entry["miss"])))
        out.append({"repo_id": repo_id, "full_name": names.get(repo_id, ""),
                    "confidence": confidence,
                    "matched": sorted(entry["matched"], key=lambda m: m["path"])[:40],
                    "matched_count": len(entry["matched"]),
                    "routes_total": len(index.routes.get(repo_id) or [])})
    out.sort(key=lambda c: (-c["confidence"], -c["matched_count"], c["full_name"]))
    return out


def reached(records: list, index: Index, repo_id) -> dict:
    """How many of one repository's routes the scan reached with a real answer."""
    real = [r["p"] for r in records if r.get("r") is True]
    routes = index.routes.get(repo_id) or []
    # Every route counts here, the common ones too: this is coverage, not
    # evidence.
    single = Index({repo_id: routes}, skip_generic=False)
    got = set()
    for path in real:
        for _, key, _, _ in single.lookup(path):
            got.add(key)
    return {"routes_total": len(routes), "routes_reached": len(got)}


# ------------------------------------------------------------------ storage

def load(raw) -> dict:
    try:
        value = json.loads(raw or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}
