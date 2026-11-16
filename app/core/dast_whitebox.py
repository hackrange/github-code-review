"""What the code behind a site says about the site, for a dynamic scan.

A dynamic scanner on its own only finds the pages it can reach by following
links.  An API with no front page, an admin route nobody links to and the
handler behind a form that only appears after sign in are all invisible to
it.  The repository knows every one of them.

So before the engines run, each repository mapped to the site is checked out
at its default branch, and two things are read from it:

    the routes it declares, in the common frameworks and in any OpenAPI file,
    which are handed to the engines as extra starting points

    whether the site's host name is written anywhere in it, which is the best
    evidence there is that the mapping is right

Nothing from the checkout is sent anywhere.  The paths become requests to the
site, which is where they were going to be served anyway.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

MAX_FILES = 6000
MAX_BYTES = 400_000
MAX_ROUTES = 300

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target",
             "__pycache__", ".venv", "venv", "bower_components", "coverage",
             ".next", ".nuxt", "out", "bin", "obj", "test", "tests", "spec",
             "__tests__", "fixtures", "examples", "docs"}
CODE_EXT = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".java",
            ".kt", ".cs", ".go", ".rb", ".php", ".xml", ".yaml", ".yml",
            ".json", ".scala", ".groovy", ".dwl"}

# One pattern per way of declaring a route.  The path is group "p".
ROUTE_PATTERNS = [
    # Express, Koa, Fastify, Hono: app.get('/x'), router.post("/x")
    re.compile(r"\b(?:app|router|server|api|route[rs]?)\.(?:get|post|put|patch|delete|all|use|route)\(\s*['\"`](?P<p>/[^'\"`\s]*)"),
    # Flask, FastAPI, Starlette: @app.route("/x"), @router.get("/x")
    re.compile(r"@\w+\.(?:route|get|post|put|patch|delete|api_route|websocket)\(\s*['\"](?P<p>/[^'\"\s]*)"),
    # Django: path("x/", re_path(r"^x/$"
    re.compile(r"\b(?:path|re_path)\(\s*r?['\"]\^?(?P<p>[A-Za-z0-9_\-/<>:.]*)\$?['\"]"),
    # Spring: @GetMapping("/x"), @RequestMapping(value = "/x")
    re.compile(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*['\"](?P<p>/?[^'\"\s]*)"),
    # JAX-RS: @Path("/x")
    re.compile(r"@Path\(\s*['\"](?P<p>/?[^'\"\s]*)"),
    # ASP.NET: [Route("x")], [HttpGet("x")]
    re.compile(r"\[(?:Route|Http(?:Get|Post|Put|Patch|Delete))\(\s*['\"](?P<p>[^'\"\s]*)"),
    # Go: http.HandleFunc("/x", r.GET("/x", mux.Handle("/x"
    re.compile(r"\.(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Delete)\(\s*['\"`](?P<p>/[^'\"`\s]*)"),
    # Rails routes.rb: get '/x', resources :things
    re.compile(r"^\s*(?:get|post|put|patch|delete|match)\s+['\"](?P<p>/?[^'\"\s]*)", re.M),
    # Mule: <http:listener ... path="/x"
    re.compile(r"<http:listener\b[^>]*\bpath=\"(?P<p>/[^\"]*)\""),
    # Laravel: Route::get('/x'
    re.compile(r"Route::(?:get|post|put|patch|delete|any|match)\(\s*['\"](?P<p>/?[^'\"\s]*)"),
]

_PARAM = re.compile(r"\{[^}/]*\}|<[^>/]*>|:[A-Za-z_]\w*|\*\*?|\(\?[^)]*\)")

MAX_SINKS = 200
# High signal dangerous patterns, tagged by type.  These are not a SAST engine:
# they mark where code does something a dynamic test wants aimed at it.  The
# reachability of the route in the same file decides whether a sink matters or
# is only context, so a loose match that is not reachable costs nothing.
SINK_PATTERNS = [
    ("sql-injection", re.compile(
        r"\b(?:execute|executeQuery|query|rawQuery|prepare|mysqli_query|pg_query)\s*\("
        r"[^)\n]{0,160}?(?:\+|%[sd]?|\$\{|\bf[\"']|\.format\(|\|\|)", re.I)),
    ("command-injection", re.compile(
        r"\b(?:os\.system|subprocess\.(?:call|run|Popen)|child_process\.exec(?:Sync)?|"
        r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|shell_exec|passthru|\bpopen|"
        r"\bsystem|\beval|\bexec)\s*\(", re.I)),
    ("deserialization", re.compile(
        r"\b(?:pickle\.loads|yaml\.load\s*\((?![^)\n]*Safe)|unserialize|"
        r"ObjectInputStream|readObject|Marshal\.load|cPickle\.loads)\b", re.I)),
    ("template-injection", re.compile(
        r"\b(?:render_template_string|Template\s*\([^)\n]*\)\.render|Handlebars\.compile)\b", re.I)),
    ("xss-sink", re.compile(
        r"\b(?:innerHTML\s*=|outerHTML\s*=|document\.write|insertAdjacentHTML|"
        r"dangerouslySetInnerHTML|v-html)\b", re.I)),
    ("path-traversal", re.compile(
        r"\b(?:open|readFile(?:Sync)?|sendFile|include(?:_once)?|require(?:_once)?|"
        r"file_get_contents|fopen)\s*\([^)\n]{0,120}?(?:\+|\$\{|\breq\.|request\.|params|\binput|\.\.\/)", re.I)),
]


def _clean_route(raw: str) -> str:
    """A route as a path that can be requested.  Parameters become 1."""
    path = (raw or "").strip()
    if not path or len(path) > 200 or any(c in path for c in " \"'$`\\"):
        return ""
    if not path.startswith("/"):
        path = "/" + path
    path = _PARAM.sub("1", path).replace("^", "").replace("$", "")
    path = re.sub(r"/{2,}", "/", path)
    if not re.fullmatch(r"/[A-Za-z0-9._~\-/%]*", path):
        return ""
    return path


MAX_WRITES = 200
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# Routes that change something, with their method.  The method is group "m"
# and the path group "p".  A dynamic scan of this product is read only by
# design, so these are the routes it never tests; listing them says where a
# code review or a test with a person has to look instead.
WRITE_PATTERNS = [
    # Express, Koa, Fastify, Hono: app.post('/x')
    re.compile(r"\b(?:app|router|server|api|route[rs]?)\.(?P<m>post|put|patch|delete)\(\s*['\"`](?P<p>/[^'\"`\s]*)"),
    # Flask, FastAPI: @router.post("/x")
    re.compile(r"@\w+\.(?P<m>post|put|patch|delete)\(\s*['\"](?P<p>/[^'\"\s]*)"),
    # Spring: @PostMapping("/x")
    re.compile(r"@(?P<m>Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*['\"](?P<p>/?[^'\"\s]*)"),
    # Go: r.POST("/x"), e.Post("/x")
    re.compile(r"\.(?P<m>POST|PUT|PATCH|DELETE|Post|Put|Patch|Delete)\(\s*['\"`](?P<p>/[^'\"`\s]*)"),
    # Rails routes.rb: post '/x'
    re.compile(r"^\s*(?P<m>post|put|patch|delete)\s+['\"](?P<p>/?[^'\"\s]*)", re.M),
    # Laravel: Route::post('/x'
    re.compile(r"Route::(?P<m>post|put|patch|delete)\(\s*['\"](?P<p>/?[^'\"\s]*)"),
]
# ASP.NET: [HttpPost], [HttpPost("x")], joined with the controller's [Route].
_CS_CLASS_ROUTE = re.compile(
    r"\[Route\(\s*\"(?P<p>[^\"]*)\"\s*\)\][^{;]*?\bclass\s+(?P<c>\w+)", re.S)
_CS_CLASS = re.compile(r"\bclass\s+(?P<c>\w+)")
_CS_WRITE = re.compile(r"\[Http(?P<m>Post|Put|Patch|Delete)(?:\(\s*\"(?P<p>[^\"]*)\"[^)]*\))?\]")


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _aspnet_writes(text: str) -> list:
    """[(method, path, line)] for ASP.NET actions that change something."""
    if "[Http" not in text:
        return []
    classes = [(m.start(), m.group("c")) for m in _CS_CLASS.finditer(text)]
    routes = {m.group("c"): m.group("p") for m in _CS_CLASS_ROUTE.finditer(text)}
    out = []
    for m in _CS_WRITE.finditer(text):
        owner = ""
        for start, name in classes:
            if start < m.start():
                owner = name
        template = m.group("p")
        if template is not None and template.startswith(("/", "~/")):
            raw = template.lstrip("~")
        else:
            base = routes.get(owner, "")
            if not base and template is None:
                continue
            raw = "/" + "/".join(x.strip("/") for x in (base, template or "") if x.strip("/"))
        controller = owner[:-len("Controller")] if owner.endswith("Controller") else owner
        raw = re.sub(r"\[controller\]", controller, raw, flags=re.I)
        if "[action]" in raw.lower():
            continue
        out.append((m.group("m").upper(), raw, _line_of(text, m.start())))
    return out


def writes_in(text: str, rel: str) -> list:
    """Routes in one file that change something.  -> [{method, route, file, line}]"""
    found = []
    if rel.endswith(".cs"):
        found = _aspnet_writes(text)
    else:
        for pattern in WRITE_PATTERNS:
            for m in pattern.finditer(text):
                found.append((m.group("m").upper(), m.group("p"), _line_of(text, m.start())))
    out, seen = [], set()
    for method, raw, line in found:
        route = _clean_route(raw)
        if not route or route == "/" or (method, route) in seen:
            continue
        seen.add((method, route))
        out.append({"method": method, "route": route, "file": rel, "line": line})
    return out


def _openapi_paths(text: str, name: str) -> list:
    """Paths from an OpenAPI or Swagger file, JSON or YAML."""
    out = []
    if name.endswith(".json"):
        try:
            doc = json.loads(text)
        except ValueError:
            return out
        if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc):
            base = str(doc.get("basePath") or "")
            out = [base.rstrip("/") + p for p in (doc.get("paths") or {})]
        return out
    if not re.search(r"^(?:openapi|swagger)\s*:", text, re.M):
        return out
    in_paths = False
    for line in text.splitlines():
        if re.match(r"^paths\s*:", line):
            in_paths = True
            continue
        if in_paths:
            if re.match(r"^\S", line):
                break
            m = re.match(r"^  ['\"]?(/[^'\":]*)['\"]?\s*:", line)
            if m:
                out.append(m.group(1))
    return out


def _sinks_in(text: str, rel: str, file_routes: list) -> list:
    """Dangerous patterns in one file, each tagged with the routes that file
    declares (its reachability decides later whether the sink matters)."""
    out = []
    for kind, pattern in SINK_PATTERNS:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            out.append({"file": rel, "line": line, "type": kind,
                        "routes": file_routes[:8]})
    return out


def read(root: Path, host: str = "") -> dict:
    """-> {routes: [path], sinks: [...], host_files: [file], files: read,
    writes: [{method, route, file, line}]}"""
    routes, sinks, host_files, read_count, writes = [], [], [], 0, []
    host_re = re.compile(r"(?<![A-Za-z0-9.-])" + re.escape(host.lower()) + r"(?![A-Za-z0-9-])",
                         re.I) if host else None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and not d.startswith("."))
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if path.suffix.lower() not in CODE_EXT and filename != "routes.rb" \
                    and not filename.endswith((".env", ".properties", ".conf", ".ini")):
                continue
            if path.is_symlink():
                continue
            read_count += 1
            if read_count > MAX_FILES:
                break
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                text = path.read_text("utf-8", "replace")
            except OSError:
                continue
            rel = str(path.relative_to(root)).replace(os.sep, "/")
            if host_re is not None and len(host_files) < 10 and host_re.search(text):
                host_files.append(rel)
            file_routes = []
            if path.suffix.lower() in (".json", ".yaml", ".yml"):
                for p in _openapi_paths(text, filename):
                    cleaned = _clean_route(p)
                    if cleaned:
                        file_routes.append(cleaned)
                        if cleaned not in routes:
                            routes.append(cleaned)
                if path.suffix.lower() == ".json":
                    continue
            for pattern in ROUTE_PATTERNS:
                for m in pattern.finditer(text):
                    cleaned = _clean_route(m.group("p"))
                    if cleaned and cleaned != "/":
                        if cleaned not in file_routes:
                            file_routes.append(cleaned)
                        if cleaned not in routes:
                            routes.append(cleaned)
            if len(sinks) < MAX_SINKS:
                sinks += _sinks_in(text, rel, file_routes)
            if len(writes) < MAX_WRITES:
                writes += writes_in(text, rel)
            if len(routes) >= MAX_ROUTES * 2 and len(sinks) >= MAX_SINKS:
                break
    return {"routes": routes[:MAX_ROUTES], "sinks": sinks[:MAX_SINKS],
            "host_files": host_files, "files": read_count, "writes": writes[:MAX_WRITES]}
