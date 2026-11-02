#!/usr/bin/env python3
"""Git Code Review API client for pipelines.

Standard library only, so it runs on any GitHub Actions runner without a
pip install.

Settings come from the environment first, then from a .env file:

  GCR_URL            API base, https, ending in /api/v1
  GCR_TOKEN          a token with the "reports" scope (in CI, from a secret)
  GCR_TOKEN_COMMAND  or a command that prints the token, for a token kept
                     encrypted or in a keychain, such as
                     gpg --quiet --decrypt ~/.config/gcr/token.gpg
  GCR_TOKEN_FILE     or a file holding only the token, mode 600
  GCR_CA_BUNDLE      optional: a CA file for a server with an internal cert
  GCR_ALLOW_HTTP     set to 1 to allow plain http, for local testing only

The .env file is looked for in the current folder and in the kit folder.  It
must not be readable by other users when it holds a token (chmod 600 .env),
and it must never be committed: the kit's .gitignore already lists it.

Inside GitHub Actions the repository and branch default to GITHUB_REPOSITORY
and GITHUB_REF_NAME, and results are added to the job summary.

Exit codes:
  0  pass, or the command worked
  1  fail: there is something to fix
  2  unknown: the branch was never scanned (check only)
  3  the call itself failed: bad token, no network, bad input

Examples:
  gcr_api.py ping
  gcr_api.py fix-plan --repo acme/payments --branch main
  gcr_api.py check --repo acme/payments --branch main --fail-on high
  gcr_api.py findings --repo acme/payments --severity critical --format table
  gcr_api.py sbom --repo acme/payments --format cdx --out sbom.cdx.json
  gcr_api.py trends --repo acme/payments --days 30 --fail-if-rising critical
  gcr_api.py token-expiry --warn-days 14
  gcr_api.py request-exception --finding 4182 --expires 2027-01-31 \\
      --reason "Only reachable from the admin network, fix planned in Q1."
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

TIMEOUT = 60

EXIT_OK, EXIT_FAIL, EXIT_UNKNOWN, EXIT_ERROR = 0, 1, 2, 3
SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}" if status else detail)
        self.status = status
        self.detail = detail


class Client:
    """A thin wrapper over the token API.  One method per endpoint."""

    def __init__(self, base_url: str = "", token: str = ""):
        _load_settings()
        self.base = (base_url or os.environ.get("GCR_URL") or "").rstrip("/")
        if not self.base:
            raise ApiError(0, "No server address.  Set GCR_URL, or copy "
                              ".env.example to .env.")
        parsed = urllib.parse.urlparse(self.base)
        local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme != "https" and not local and os.environ.get("GCR_ALLOW_HTTP") != "1":
            raise ApiError(0, "GCR_URL must start with https://.  A token sent over "
                              "plain http can be read by anybody on the network.")
        import ssl
        cafile = os.path.expanduser(os.environ.get("GCR_CA_BUNDLE") or "") or None
        # Certificates are always checked.  There is deliberately no switch to
        # turn that off; point GCR_CA_BUNDLE at your company CA instead.
        self.tls = ssl.create_default_context(cafile=cafile)
        self.token = token or _token_from_env()
        if not self.token:
            raise ApiError(0, "No token.  Set GCR_TOKEN or GCR_TOKEN_FILE.")

    # -- transport ---------------------------------------------------------

    def _call(self, method: str, path: str, params: dict = None,
              body: dict = None, raw: bool = False):
        query = {k: v for k, v in (params or {}).items()
                 if v is not None and v != ""}
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self.token)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        # A GET is retried a few times when the server is busy or restarting.
        # A POST is never retried, so a request is never sent twice.
        attempts = 3 if method == "GET" else 1
        for attempt in range(1, attempts + 1):
            try:
                return self._send(request, raw)
            except ApiError as err:
                if attempt == attempts or err.status not in (429, 502, 503, 504):
                    raise
                import time
                time.sleep(5 * attempt)

    def _send(self, request, raw: bool):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT,
                                        context=self.tls) as response:
                payload = response.read()
        except urllib.error.HTTPError as err:
            text = err.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(text)
                detail = parsed.get("detail", "") if isinstance(parsed, dict) else ""
            except ValueError:
                detail = ""
            if not detail and text.strip() and "<html" not in text.lower():
                # Some errors come back as plain text, which is the reason.
                detail = text.strip()[:500]
            if not detail:
                # The load balancer swaps some answers for its own HTML page,
                # so the API's own reason is lost.  Say what the code means.
                detail = {
                    401: "the token was refused.  It may be wrong, expired, "
                         "revoked, or missing the scope this call needs.",
                    403: "refused before it reached the API.  The runner's IP "
                         "is probably not allowed through the load balancer.",
                    404: "not found, or not visible to the token's owner.",
                    429: "too many calls.  Wait a minute and try again.",
                }.get(err.code, "the server sent a web page instead of JSON.")
            raise ApiError(err.code, str(detail)) from None
        except urllib.error.URLError as err:
            raise ApiError(0, f"could not reach {self.base}: {err.reason}") from None
        if raw:
            return payload
        try:
            return json.loads(payload)
        except ValueError:
            raise ApiError(200, "the answer was not JSON.  Check GCR_URL ends "
                                "in /api/v1.") from None

    def _pages(self, path: str, key: str, params: dict, limit: int = 1000):
        """Every row of a paged list, one page at a time."""
        offset = 0
        while True:
            page = self._call("GET", path, dict(params, limit=limit, offset=offset))
            rows = page.get(key, [])
            yield from rows
            offset += len(rows)
            if not rows or offset >= page.get("total", 0):
                return

    # -- endpoints ---------------------------------------------------------

    def ping(self) -> dict:
        return self._call("GET", "/ping")

    def check(self, repo: str, branch: str = "", fail_on: str = "high",
              include: str = "", block_exploited: bool = True,
              reach: str = "") -> dict:
        return self._call("GET", "/check", {
            "repo": repo, "branch": branch, "fail_on": fail_on,
            "include": include, "block_exploited": "1" if block_exploited else "0",
            "reach": reach})

    def findings(self, **filters) -> list:
        return list(self._pages("/findings", "findings", filters))

    def finding(self, finding_id: int) -> dict:
        return self._call("GET", f"/findings/{int(finding_id)}")

    def repositories(self, org: str = "") -> list:
        return list(self._pages("/repositories", "repositories", {"org": org}))

    def sboms(self) -> list:
        return self._call("GET", "/sbom").get("sboms", [])

    def sbom(self, repo: str, fmt: str = "cdx") -> bytes:
        path = "/sbom/" + "/".join(urllib.parse.quote(p, safe="") for p in repo.split("/"))
        return self._call("GET", path, {"format": fmt}, raw=True)

    def trends(self, days: int = 30, basis: str = "actions", **filters) -> dict:
        return self._call("GET", "/trends", dict(filters, days=days, basis=basis))

    def exceptions(self, status: str = "") -> list:
        return list(self._pages("/exceptions", "exceptions", {"status": status}))

    def request_exception(self, finding_id: int, reason: str, expires: str,
                          ticket: str = "", category: str = "") -> dict:
        return self._call("POST", f"/findings/{int(finding_id)}/exceptions", body={
            "reason": reason, "expires": expires, "ticket": ticket,
            "category": category})


# -- helpers ---------------------------------------------------------------

SECRET_KEYS = ("GCR_TOKEN",)


def _private(path: str) -> bool:
    """True when no other user can read the file.  Always true on Windows,
    where files are protected by ACLs rather than mode bits."""
    if os.name != "posix":
        return True
    return (os.stat(path).st_mode & 0o077) == 0


def _load_settings() -> None:
    """Fill in GCR_* settings from a .env file, without overriding any.

    The file is plain KEY=value lines.  Lines starting with # are notes.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for folder in (os.getcwd(), os.path.dirname(here), here):
        path = os.path.join(folder, ".env")
        if not os.path.isfile(path):
            continue
        values = {}
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("export "):
                    line = line[len("export "):]
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key, value = key.strip(), value.strip().strip('"').strip("'")
                if key.startswith("GCR_") and value:
                    values[key] = value
        if any(k in values for k in SECRET_KEYS) and not _private(path):
            raise ApiError(0, f"{path} holds a token but other users can read it.  "
                              f"Run: chmod 600 {path}")
        for key, value in values.items():
            if not os.environ.get(key):
                os.environ[key] = value
        return


def _token_from_env() -> str:
    """The token, from the first place that has one.

    GCR_TOKEN, then GCR_TOKEN_COMMAND, then GCR_TOKEN_FILE.  The token is
    never printed, logged or put on a command line.
    """
    token = (os.environ.get("GCR_TOKEN") or "").strip()
    if token:
        return token

    command = (os.environ.get("GCR_TOKEN_COMMAND") or "").strip()
    if command:
        import shlex
        import subprocess
        try:
            argv = [os.path.expanduser(part) for part in shlex.split(command)]
            done = subprocess.run(argv, capture_output=True,
                                  text=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as err:
            raise ApiError(0, f"GCR_TOKEN_COMMAND could not run: {err}") from None
        if done.returncode != 0 or not done.stdout.strip():
            raise ApiError(0, "GCR_TOKEN_COMMAND did not print a token "
                              f"(exit {done.returncode}).")
        return done.stdout.strip().splitlines()[0].strip()

    path = os.path.expanduser(os.environ.get("GCR_TOKEN_FILE") or "")
    if path:
        if not os.path.isfile(path):
            raise ApiError(0, f"GCR_TOKEN_FILE {path} does not exist.")
        if not _private(path):
            raise ApiError(0, f"{path} can be read by other users.  "
                              f"Run: chmod 600 {path}")
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    return ""


def _in_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _summary(markdown: str) -> None:
    """Add to the GitHub Actions job summary, when there is one."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(markdown.rstrip() + "\n\n")


def _annotate(level: str, title: str, message: str, file: str = "", line: int = 0):
    """A GitHub annotation, so the problem shows on the run and the file."""
    if not _in_actions():
        return

    def data(text):
        return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def prop(text):
        # Property values also have to escape the two characters that
        # separate properties.
        return data(text).replace(":", "%3A").replace(",", "%2C")

    # Some manifest paths are stored with a leading slash.  GitHub matches an
    # annotation to a file by its path from the repository root, without one.
    file = (file or "").lstrip("/")
    props = []
    if file:
        props.append("file=" + prop(file))
        if line:
            props.append(f"line={int(line)}")
    props.append("title=" + prop(title))
    print(f"::{level} {','.join(props)}::{data(message)}")


def _default_repo(given: str) -> str:
    return given or os.environ.get("GITHUB_REPOSITORY", "")


def _default_branch(given: str) -> str:
    if given:
        return given
    # On a pull request GITHUB_REF_NAME is "123/merge", which is never scanned.
    # The branch being merged into is the one with a scan behind it.
    if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        return os.environ.get("GITHUB_BASE_REF", "")
    return os.environ.get("GITHUB_REF_NAME", "")


def _table(rows: list, columns: list) -> str:
    widths = [max(len(c), *(len(str(r.get(c, ""))) for r in rows)) if rows else len(c)
              for c in columns]
    line = "  ".join(c.upper().ljust(w) for c, w in zip(columns, widths))
    out = [line, "  ".join("-" * w for w in widths)]
    for r in rows:
        out.append("  ".join(str(r.get(c, "")).ljust(w) for c, w in zip(columns, widths)))
    return "\n".join(out)


# -- commands --------------------------------------------------------------

def cmd_ping(client: Client, args) -> int:
    answer = client.ping()
    print(f"Token works.  User {answer['user']}, scopes {', '.join(answer['scopes'])}, "
          f"expires {answer.get('expires_at') or 'never'}.")
    return EXIT_OK


def cmd_token_expiry(client: Client, args) -> int:
    answer = client.ping()
    if "reports" not in answer.get("scopes", []):
        print("This token does not have the reports scope.", file=sys.stderr)
        return EXIT_FAIL
    expires = answer.get("expires_at")
    if not expires:
        print("The token does not expire.")
        return EXIT_OK
    when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    if when.tzinfo is None:
        # The server stores it in UTC and sometimes leaves the zone off.
        when = when.replace(tzinfo=timezone.utc)
    left = (when - datetime.now(timezone.utc)).days
    print(f"The token expires on {when:%Y-%m-%d}, in {left} day(s).")
    if left <= args.warn_days:
        _annotate("warning", "GCR token expiring",
                  f"The Git Code Review token expires in {left} day(s).  Make a new "
                  "one on the IDE tokens page and update the GCR_TOKEN secret.")
        return EXIT_FAIL if args.strict else EXIT_OK
    return EXIT_OK


def cmd_check(client: Client, args) -> int:
    repo = _default_repo(args.repo)
    if not repo:
        print("Give --repo org/name, or run inside GitHub Actions.", file=sys.stderr)
        return EXIT_ERROR
    answer = client.check(repo, _default_branch(args.branch), args.fail_on,
                          args.include, not args.no_block_exploited, args.reach)
    verdict = answer["verdict"]

    if args.json:
        print(json.dumps(answer, indent=2))
    else:
        print(f"{verdict.upper()}: {answer['message']}")
        print(f"  {answer['repository']} @ {answer['branch']}, last scanned "
              f"{answer.get('last_scanned_at') or 'never'}")
        for f in answer["blocking"]:
            print(f"  [{f['severity']}] {f['area']}: {f['title']}  {f['file']}")
            print(f"      {f.get('fix') or f['why']}")
            print(f"      {f['link']}")

    for f in answer["blocking"]:
        _annotate("error", f"{f['severity']} {f['area']}: {f['title']}",
                  (f.get("fix") or f["why"]) + "  " + f["link"], f["file"], f["line"])

    rows = "\n".join(
        f"| {f['severity']} | {f['area']} | {f['title']} | `{f['file']}` | "
        f"{f.get('fix') or f['why']} | [open]({f['link']}) |"
        for f in answer["blocking"])
    icon = {"pass": "PASS", "fail": "FAIL", "unknown": "UNKNOWN"}[verdict]
    _summary(f"### Git Code Review deploy check: {icon}\n\n{answer['message']}\n\n"
             f"`{answer['repository']}` on `{answer['branch']}`, last scanned "
             f"{answer.get('last_scanned_at') or 'never'}, failing on "
             f"{answer['fail_on']} and above.\n\n"
             + (f"| Severity | Area | Finding | File | Fix | Link |\n|---|---|---|---|---|---|\n{rows}"
                if rows else ""))

    if verdict == "pass":
        return EXIT_OK
    if verdict == "unknown":
        return EXIT_OK if args.allow_unknown else EXIT_UNKNOWN
    return EXIT_OK if args.warn_only else EXIT_FAIL


def cmd_findings(client: Client, args) -> int:
    filters = {"repo": _default_repo(args.repo), "branch": args.branch,
               "severity": args.severity, "kind": args.kind, "state": args.state,
               "since": args.since, "exploited": "1" if args.exploited else ""}
    rows = client.findings(**filters)
    for r in rows:
        # A package has no line of code; where it is declared is its location.
        if not r.get("file"):
            r["file"] = ((r.get("package") or {}).get("declared_in") or "").lstrip("/")
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    elif args.format == "csv":
        import csv
        writer = csv.writer(sys.stdout)
        writer.writerow(["id", "vuln_id", "severity", "kind", "repository", "branch",
                         "file", "line", "title", "package", "version", "fixed_in"])
        for r in rows:
            p = r.get("package") or {}
            writer.writerow([r["id"], r["vuln_id"], r["severity"], r["kind"],
                             r["repository"], r["branch"], r["file"], r["line"],
                             r["title"], p.get("name", ""), p.get("version", ""),
                             p.get("fixed_in", "")])
    else:
        print(_table([{"id": r["id"], "severity": r["severity"], "kind": r["kind"],
                       "repository": r["repository"], "file": r["file"][:50],
                       "title": r["title"][:60]} for r in rows],
                     ["id", "severity", "kind", "repository", "file", "title"]))
        print(f"\n{len(rows)} finding(s).")
    counts = {s: 0 for s in SEVERITIES}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    _summary("### Git Code Review findings\n\n| " + " | ".join(SEVERITIES) + " |\n|"
             + "---|" * len(SEVERITIES) + "\n| "
             + " | ".join(str(counts[s]) for s in SEVERITIES) + " |")
    if args.max is not None and len(rows) > args.max:
        print(f"{len(rows)} finding(s) is more than the {args.max} allowed.", file=sys.stderr)
        return EXIT_FAIL
    return EXIT_OK


def cmd_sbom(client: Client, args) -> int:
    repo = _default_repo(args.repo)
    if not repo:
        print("Give --repo org/name, or run inside GitHub Actions.", file=sys.stderr)
        return EXIT_ERROR
    body = client.sbom(repo, args.format)
    out = args.out or f"{repo.replace('/', '__')}.{args.format}.json"
    with open(out, "wb") as handle:
        handle.write(body)
    doc = json.loads(body)
    count = len(doc.get("components") or doc.get("packages") or [])
    print(f"Wrote {out}, {len(body)} bytes, {count} component(s).")
    return EXIT_OK


def cmd_trends(client: Client, args) -> int:
    answer = client.trends(days=args.days, basis=args.basis,
                           org=args.org, repo=_default_repo(args.repo),
                           branch=args.branch)
    series = answer["series"]
    if not series:
        print("No trend data for that filter yet.")
        return EXIT_OK
    first, last = series[0], series[-1]
    print(f"{'day':<12}" + "".join(f"{s:>10}" for s in SEVERITIES[:4]) + f"{'total':>10}")
    for point in series:
        print(f"{point['day']:<12}" + "".join(f"{point[s]:>10}" for s in SEVERITIES[:4])
              + f"{point['total']:>10}")
    change = {s: last[s] - first[s] for s in SEVERITIES[:4] + ["total"]}
    words = ", ".join(f"{s} {'+' if v > 0 else ''}{v}" for s, v in change.items())
    print(f"\nChange over {args.days} day(s): {words}")
    _summary(f"### Git Code Review trend, last {args.days} day(s)\n\n"
             "| | critical | high | medium | low | total |\n|---|---|---|---|---|---|\n"
             f"| {first['day']} | {first['critical']} | {first['high']} | {first['medium']} | "
             f"{first['low']} | {first['total']} |\n"
             f"| {last['day']} | {last['critical']} | {last['high']} | {last['medium']} | "
             f"{last['low']} | {last['total']} |")
    for level in args.fail_if_rising or []:
        if change.get(level, 0) > 0:
            _annotate("error", "Findings are rising",
                      f"{level} went from {first[level]} to {last[level]}.")
            print(f"{level} is rising: {first[level]} to {last[level]}.", file=sys.stderr)
            return EXIT_FAIL
    return EXIT_OK


def cmd_request_exception(client: Client, args) -> int:
    answer = client.request_exception(args.finding, args.reason, args.expires,
                                      args.ticket, args.category)
    print(f"Exception {answer['id']} on finding {answer['finding']} is "
          f"{answer['status']}.  An administrator approves it in the web app.")
    return EXIT_OK


def cmd_exceptions(client: Client, args) -> int:
    rows = client.exceptions(args.status)
    print(_table([{"id": r["id"], "finding": r["finding"], "status": r["status"],
                   "expires": (r.get("expires_at") or "")[:10],
                   "repository": r.get("repository", ""),
                   "reason": r["reason"][:50]} for r in rows],
                 ["id", "finding", "status", "expires", "repository", "reason"]))
    return EXIT_OK


# -- the fix plan ----------------------------------------------------------

BUILD_HINTS = (".github/workflows/", ".github/actions/", "dockerfile", "containerfile",
               "jenkinsfile", ".gitlab-ci", "azure-pipelines", "bitbucket-pipelines",
               "buildspec", "cloudbuild", ".circleci/", "makefile", "compose.y")
RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}


def _version_key(text: str):
    """Sort 1.10.0 after 1.9.2.  Good enough for picking the highest fix."""
    parts = []
    for piece in str(text).replace("-", ".").replace("+", ".").split("."):
        parts.append((0, int(piece), "") if piece.isdigit() else (1, 0, piece))
    return parts


def _is_build_file(path: str) -> bool:
    low = (path or "").lower()
    return any(hint in low for hint in BUILD_HINTS)


def fix_plan(client: Client, repo: str, branch: str = "") -> dict:
    """Turn a repository's open findings into a list of things to do.

    secrets   credentials found in the code, worst first
    upgrades  one row per package: the version to move to, and why
    images    container base images with vulnerable packages inside
    build     problems in CI workflows, Dockerfiles and build scripts
    code      code problems, only those an AI review has read
    """
    rows = client.findings(repo=repo, branch=branch)
    plan = {"repository": repo, "branch": branch, "secrets": [], "upgrades": [],
            "images": [], "build": [], "code": [], "code_not_reviewed": 0}
    packages, images = {}, {}

    for r in rows:
        kind = r["kind"]
        review = r.get("ai_review") or {}
        if kind == "credential":
            cred = r.get("credential") or {}
            plan["secrets"].append({
                "id": r["id"], "severity": r["severity"], "title": r["title"],
                "file": r["file"], "line": r["line"], "commit": r.get("commit", ""),
                "preview": cred.get("preview", ""), "live": bool(cred.get("verified")),
            })
        elif kind == "dependency":
            pkg = r.get("package") or {}
            vuln = r.get("vulnerability") or {}
            image = pkg.get("image", "")
            if image:
                entry = images.setdefault(image, {"image": image, "packages": set(),
                                                  "worst": "info", "ids": []})
                entry["packages"].add(f"{pkg.get('name')} {pkg.get('version')}")
                entry["ids"].append(r["id"])
                if RANK[r["severity"]] > RANK[entry["worst"]]:
                    entry["worst"] = r["severity"]
                continue
            where = (pkg.get("declared_in") or "").lstrip("/")
            key = (pkg.get("ecosystem", ""), pkg.get("name", ""), where)
            entry = packages.setdefault(key, {
                "package": pkg.get("name", ""), "ecosystem": pkg.get("ecosystem", ""),
                "declared_in": where, "current": set(), "fixed_in": [],
                "advisories": [], "worst": "info", "exploited": False,
                "build_only": True, "ids": []})
            entry["current"].add(pkg.get("version", ""))
            if pkg.get("fixed_in"):
                # An advisory can list several fixed versions, one per line.
                entry["fixed_in"].extend(v.strip() for v in
                                         str(pkg["fixed_in"]).replace(",", " ").split() if v.strip())
            if vuln.get("id"):
                entry["advisories"].append(vuln["id"])
            entry["exploited"] = entry["exploited"] or bool(vuln.get("known_exploited"))
            if (r.get("reachability") or {}).get("scope") != "development":
                entry["build_only"] = False
            entry["ids"].append(r["id"])
            if RANK[r["severity"]] > RANK[entry["worst"]]:
                entry["worst"] = r["severity"]
        elif kind == "misconfiguration" and _is_build_file(r["file"]):
            plan["build"].append({
                "id": r["id"], "severity": r["severity"], "title": r["title"],
                "file": r["file"], "line": r["line"], "rule": r.get("rule", ""),
                "fix": review.get("fix", ""), "ai_reviewed": bool(review)})
        elif kind in ("code", "misconfiguration"):
            if review.get("fix"):
                plan["code"].append({
                    "id": r["id"], "severity": review.get("severity") or r["severity"],
                    "title": r["title"], "file": r["file"], "line": r["line"],
                    "summary": review.get("summary", ""), "fix": review["fix"],
                    "check": review.get("what_to_check", ""),
                    "meanwhile": review.get("compensating_controls", "")})
            else:
                plan["code_not_reviewed"] += 1

    for entry in packages.values():
        fixes = sorted(set(entry["fixed_in"]), key=_version_key)
        entry["upgrade_to"] = fixes[-1] if fixes else ""
        entry["current"] = sorted(v for v in entry["current"] if v)
        entry["advisories"] = sorted(set(entry["advisories"]))
        del entry["fixed_in"]
        plan["upgrades"].append(entry)
    for entry in images.values():
        entry["packages"] = sorted(entry["packages"])
        plan["images"].append(entry)

    order = lambda e: (-RANK[e.get("worst") or e.get("severity", "info")],
                       e.get("package") or e.get("image") or e.get("file", ""))
    for part in ("secrets", "upgrades", "images", "build", "code"):
        plan[part].sort(key=order)
    return plan


def plan_markdown(plan: dict, site: str = "") -> str:
    """The plan as Markdown, which GitHub shows nicely in a job summary."""
    def link(item_id):
        return f" [details]({site}/findings/{item_id})" if site else ""

    out = [f"## Fix plan for `{plan['repository']}`"
           + (f" on `{plan['branch']}`" if plan["branch"] else "")]
    step = 0

    def heading(title):
        nonlocal step
        step += 1
        out.append(f"\n### {step}. {title}\n")

    if plan["secrets"]:
        heading("Secrets in the code: do these first")
        out.append("Rotate each one at its provider (make a new key and turn the old one "
                   "off), then move it out of the code into a secret store.  Deleting "
                   "the line is not enough, because the old value stays in the git history.\n")
        out.append("| Severity | What | Where | Live? |\n|---|---|---|---|")
        for x in plan["secrets"]:
            out.append(f"| {x['severity']} | {x['title']} `{x['preview']}`{link(x['id'])} | "
                       f"`{x['file']}:{x['line']}` | "
                       f"{'YES, confirmed working' if x['live'] else 'not confirmed'} |")
    if plan["upgrades"]:
        heading("Packages to upgrade")
        out.append("Change each package to the version in **Upgrade to**, or newer, in the "
                   "file named under **Declared in**.  Then rebuild so the lock file updates.\n")
        out.append("| Package | Now | Upgrade to | Worst | Declared in | Advisories |\n"
                   "|---|---|---|---|---|---|")
        for u in plan["upgrades"]:
            worst = u["worst"] + (" (known exploited)" if u["exploited"] else "")
            if u["build_only"]:
                worst += ", build only"
            now = ", ".join(u["current"]) or "a range"
            more = " ..." if len(u["advisories"]) > 4 else ""
            eco = f" ({u['ecosystem']})" if u["ecosystem"] else ""
            out.append(f"| {u['package']}{eco} | {now} | "
                       f"**{u['upgrade_to'] or 'no fix yet'}** | {worst} | "
                       f"`{u['declared_in']}` | {', '.join(u['advisories'][:4])}{more} |")
    if plan["images"]:
        heading("Container images to rebuild")
        out.append("Move to a newer tag of the base image, or rebuild it so the operating "
                   "system packages update.\n")
        for i in plan["images"]:
            out.append(f"- `{i['image']}` ({i['worst']}): {', '.join(i['packages'][:6])}")
    if plan["build"]:
        heading("Problems in the build and CI files")
        for b in plan["build"]:
            tip = f"  Fix: {b['fix']}" if b["fix"] else ""
            out.append(f"- **{b['severity']}** `{b['file']}:{b['line']}` "
                       f"{b['title']}.{tip}{link(b['id'])}")
    if plan["code"]:
        heading("Code fixes reviewed by AI")
        for c in plan["code"]:
            out.append(f"- **{c['severity']}** `{c['file']}:{c['line']}` {c['title']}"
                       f"{link(c['id'])}\n"
                       f"  - What it is: {c['summary']}\n  - Fix: {c['fix']}"
                       + (f"\n  - Check: {c['check']}" if c["check"] else "")
                       + (f"\n  - Until then: {c['meanwhile']}" if c["meanwhile"] else ""))
    if plan["code_not_reviewed"]:
        out.append(f"\n{plan['code_not_reviewed']} other code or configuration "
                   "finding(s) have not been reviewed by AI yet, so no fix is suggested for them.  They are on the "
                   "Findings page.")
    if step == 0 and not plan["code_not_reviewed"]:
        out.append("\nNothing to fix.  No open findings on this repository.")
    return "\n".join(out)


def cmd_fix_plan(client: Client, args) -> int:
    repo = _default_repo(args.repo)
    if not repo:
        print("Give --repo org/name, or run inside GitHub Actions.", file=sys.stderr)
        return EXIT_ERROR
    plan = fix_plan(client, repo, _default_branch(args.branch))
    site = client.base[:-len("/api/v1")] if client.base.endswith("/api/v1") else ""
    text = plan_markdown(plan, site)
    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        print(text)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    _summary(text)
    for s in plan["secrets"]:
        _annotate("error", "Secret in the code: rotate it",
                  f"{s['title']} {s['preview']}.  Rotate it first, then remove it.",
                  s["file"], s["line"])
    for u in plan["upgrades"]:
        if RANK[u["worst"]] >= RANK["high"] and u["upgrade_to"]:
            _annotate("warning", f"Upgrade {u['package']}",
                      f"Move {u['package']} to {u['upgrade_to']} or later "
                      f"({u['worst']}).", u["declared_in"])
    if args.fail_on_secrets and plan["secrets"]:
        return EXIT_FAIL
    return EXIT_OK


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ping", help="check the token works")

    p = sub.add_parser("token-expiry", help="warn before the token runs out")
    p.add_argument("--warn-days", type=int, default=14)
    p.add_argument("--strict", action="store_true", help="exit 1 inside the warning window")

    p = sub.add_parser("check", help="pass or fail a deploy")
    p.add_argument("--repo", default="", help="org/name (default GITHUB_REPOSITORY)")
    p.add_argument("--branch", default="", help="default GITHUB_REF_NAME, or the base branch on a PR")
    p.add_argument("--fail-on", default="high", choices=SEVERITIES[:5])
    p.add_argument("--include", default="", help="package,image,build,config,credential,code or all")
    p.add_argument("--reach", default="", help="any counts packages unlikely to be reached")
    p.add_argument("--no-block-exploited", action="store_true")
    p.add_argument("--allow-unknown", action="store_true", help="pass a branch nobody scanned")
    p.add_argument("--warn-only", action="store_true", help="report but never fail")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("fix-plan", help="what to fix, grouped and in order")
    p.add_argument("--repo", default="")
    p.add_argument("--branch", default="")
    p.add_argument("--markdown", default="", help="also write the plan to this file")
    p.add_argument("--json", action="store_true")
    p.add_argument("--fail-on-secrets", action="store_true",
                   help="exit 1 when any secret is found")

    p = sub.add_parser("findings", help="list findings")
    p.add_argument("--repo", default="")
    p.add_argument("--branch", default="")
    p.add_argument("--severity", default="", choices=[""] + SEVERITIES)
    p.add_argument("--kind", default="", choices=["", "credential", "code", "dependency",
                                                  "misconfiguration"])
    p.add_argument("--state", default="open", choices=["open", "waived", "fixed"])
    p.add_argument("--since", default="", choices=["", "1", "7", "14", "30"])
    p.add_argument("--exploited", action="store_true", help="known exploited only")
    p.add_argument("--format", default="table", choices=["table", "json", "csv"])
    p.add_argument("--max", type=int, default=None, help="exit 1 when there are more than this")

    p = sub.add_parser("sbom", help="download a repository's SBOM")
    p.add_argument("--repo", default="")
    p.add_argument("--format", default="cdx", choices=["cdx", "spdx"])
    p.add_argument("--out", default="")

    p = sub.add_parser("trends", help="how the numbers moved")
    p.add_argument("--days", type=int, default=30, choices=[1, 7, 30, 90, 365])
    p.add_argument("--basis", default="actions", choices=["actions", "advisories"])
    p.add_argument("--org", default="")
    p.add_argument("--repo", default="")
    p.add_argument("--branch", default="")
    p.add_argument("--fail-if-rising", nargs="*", choices=SEVERITIES[:4] + ["total"])

    p = sub.add_parser("exceptions", help="list your exceptions")
    p.add_argument("--status", default="", choices=["", "requested", "approved",
                                                    "rejected", "revoked", "expired"])

    p = sub.add_parser("request-exception", help="ask for an exception on a finding")
    p.add_argument("--finding", type=int, required=True)
    p.add_argument("--reason", required=True, help="at least 20 characters")
    p.add_argument("--expires", required=True, help="YYYY-MM-DD, within a year")
    p.add_argument("--ticket", default="")
    p.add_argument("--category", default="", choices=["", "not_deployed"])

    args = parser.parse_args(argv)
    handlers = {"ping": cmd_ping, "token-expiry": cmd_token_expiry, "check": cmd_check,
                "findings": cmd_findings, "fix-plan": cmd_fix_plan, "sbom": cmd_sbom, "trends": cmd_trends,
                "exceptions": cmd_exceptions, "request-exception": cmd_request_exception}
    try:
        return handlers[args.command](Client(), args)
    except ApiError as err:
        print(f"Git Code Review API: {err}", file=sys.stderr)
        _annotate("error", "Git Code Review API", str(err))
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
