#!/usr/bin/env python3
"""Which dependency findings can actually be reached.

A scan of a real estate produces a vulnerability count nobody can act on.  Most
of that count sits in packages the application never calls: something eleven
levels down that got pulled in by a build tool, or a test framework that does
not ship.  Ranking honestly is most of what somebody wants from the list.

A full call graph is the wrong first step.  Three cheaper questions get most of
the way, and they are facts about the tree rather than guesses:

  Is the package a direct dependency, or is it a long way down.
  Is it a development dependency that never reaches production.
  Is it imported anywhere in the source at all.

The rule `code_triage.py` follows applies here without change: a verdict, the
reason for it, and nothing removed.  When unsure, keep.  A finding this cannot
work out is `unknown`, never `unlikely`, because a wrong `unlikely` is somebody
not looking at the one that mattered.

Reads the merged vulnerability JSON on argv[1] and the checkout on argv[2],
writes the same list with a `reachability` object added to each row.
"""

from __future__ import annotations

import json
import os
import re
import sys

# Verdicts, in the order a person cares about them.
REACHABLE = "reachable"    # the code imports it
UNLIKELY = "unlikely"      # it does not ship, or nothing refers to it
UNKNOWN = "unknown"        # not enough of the tree was readable to say

# Directories that are never the application's own source.  Walking them is
# slow and what is in them is somebody else's code, which is what the vendored
# pass is for rather than this one.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party",
    "bower_components", ".venv", "venv", "site-packages", "dist", "build",
    "target", ".tox", ".mypy_cache", ".pytest_cache", "__pycache__",
    ".gradle", ".idea", ".next", ".nuxt", "coverage", ".terraform",
}

# A tree with more source than this is one where the walk costs more than the
# answer is worth.  Stopping early makes the verdict unknown, not unlikely.
MAX_FILES = 20000
MAX_FILE_BYTES = 2 * 1024 * 1024

# Paths that are the test suite rather than the application.  A package only
# imported from here does not ship either.
# Configuration for build, test and lint tools.  They import packages, and none
# of what they import is in what gets deployed.
TOOL_PATH = re.compile(
    r"(^|/)[^/]*\.(?:config|conf)\.[cm]?[jt]s$"
    r"|(^|/)(?:karma|protractor|gulpfile|gruntfile|webpack|rollup|babel|jest|vite|vitest|"
    r"postcss|tailwind|craco|nuxt|next|svelte|astro|metro|commitlint|stylelint|lint-staged)"
    r"[^/]*\.[cm]?[jt]s$"
    r"|(^|/)\.[a-z]+rc\.[cm]?[jt]s$"
    r"|(^|/)(e2e|tools|\.storybook|\.husky)/", re.I)

TEST_PATH = re.compile(
    r"(^|/)(tests?|specs?|__tests__|testdata|e2e|cypress|features)(/|$)"
    r"|(^|/)[^/]*[._-](test|spec)\.[^/]+$"
    r"|(^|/)test_[^/]+\.py$", re.I)


# --- what the ecosystem is called, once ------------------------------------
#
# grype says "npm" and "python" and "go-module"; osv says "npm" and "PyPI" and
# "Go"; dependabot says something else again.  One name each here, and every
# comparison below is against that.
def ecosystem_of(raw: str) -> str:
    text = (raw or "").strip().lower()
    if text in ("npm", "node", "nodejs", "javascript", "yarn", "pnpm"):
        return "npm"
    if text in ("python", "pypi", "pip", "poetry", "wheel", "egg"):
        return "python"
    if text in ("go", "golang", "go-module", "gomodule"):
        return "go"
    return text or "unknown"


SUPPORTED = ("npm", "python", "go")


# --- python package names are not python module names ----------------------
#
# The distribution on the index and the thing you type after `import` are
# different strings often enough that guessing from the name alone is wrong.
# The ones below are the cases common enough to matter; anything else falls
# through to the normalized forms, and a miss makes the verdict unknown.
PY_MODULES = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"],
    "python-dateutil": ["dateutil"], "protobuf": ["google"],
    "msgpack-python": ["msgpack"], "attrs": ["attr", "attrs"],
    "setuptools": ["setuptools", "pkg_resources"],
    "typing-extensions": ["typing_extensions"],
    "scikit-learn": ["sklearn"], "opencv-python": ["cv2"],
    "python-jose": ["jose"], "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"], "djangorestframework": ["rest_framework"],
    "google-api-python-client": ["googleapiclient"],
    "python-magic": ["magic"], "python-memcached": ["memcache"],
    "mysqlclient": ["MySQLdb"], "psycopg2-binary": ["psycopg2"],
    "pyjwt": ["jwt"], "python-multipart": ["multipart"],
    "python-docx": ["docx"], "python-pptx": ["pptx"],
    "faker": ["faker"], "grpcio": ["grpc"], "pyzmq": ["zmq"],
    "pysocks": ["socks"], "paho-mqtt": ["paho"],
    "azure-storage-blob": ["azure"], "google-cloud-storage": ["google"],
    "ruamel-yaml": ["ruamel"], "pytest-cov": ["pytest_cov"],
    "importlib-metadata": ["importlib_metadata"],
    "backports-zoneinfo": ["backports"],
}


def python_candidates(name: str) -> list:
    low = (name or "").strip().lower()
    if low in PY_MODULES:
        return PY_MODULES[low]
    return [low.replace("-", "_"), low.replace("-", ""), low]


def npm_root(specifier: str) -> str:
    """The package a bare import specifier belongs to.

    `@scope/pkg/sub/path` is the `@scope/pkg` package and `pkg/sub` is `pkg`.
    """
    parts = specifier.split("/")
    if specifier.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


# --- reading the tree -------------------------------------------------------
def _read(path: str) -> str:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _walk(root: str):
    """Every source file worth reading, with the vendored trees left out."""
    seen = 0
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            seen += 1
            if seen > MAX_FILES:
                return
            yield os.path.join(base, name), os.path.relpath(os.path.join(base, name), root)


JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
JS_IMPORT = re.compile(
    r"""(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    r"""|from\s+['"]([^'"]+)['"]"""
    r"""|import\s+['"]([^'"]+)['"]""")

PY_IMPORT = re.compile(
    r"""^[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)|import[ \t]+([A-Za-z_][\w.]*(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*)*))""",
    re.M)

GO_IMPORT = re.compile(r"""["`]([a-z0-9][\w.\-]*\.[a-z]{2,}/[^"`\s]+|[a-z][\w./\-]*)["`]""")


def scan_imports(root: str) -> dict:
    """What the source refers to, by ecosystem.

    Returns {ecosystem: {name: {"files": n, "first": path, "ships": bool}}}.
    `ships` is false when every reference is from the test suite, which is the
    difference between a package the application uses and one only its tests
    do.
    """
    found = {"npm": {}, "python": {}, "go": {}}

    def note(eco: str, name: str, rel: str):
        if not name:
            return
        entry = found[eco].setdefault(name, {"files": 0, "first": rel,
                                             "ships": False})
        entry["files"] += 1
        if not TEST_PATH.search(rel) and not TOOL_PATH.search(rel):
            entry["ships"] = True

    for full, rel in _walk(root):
        ext = os.path.splitext(full)[1].lower()
        if ext in JS_EXT:
            for match in JS_IMPORT.finditer(_read(full)):
                spec = match.group(1) or match.group(2) or match.group(3) or ""
                if not spec or spec.startswith((".", "/")) or spec.startswith("node:"):
                    continue
                note("npm", npm_root(spec), rel)
        elif ext == ".py":
            for match in PY_IMPORT.finditer(_read(full)):
                names = match.group(1) or match.group(2) or ""
                for one in names.split(","):
                    top = one.strip().split(".")[0]
                    if top and top != "__future__":
                        note("python", top, rel)
        elif ext == ".go":
            for match in GO_IMPORT.finditer(_read(full)):
                path = match.group(1)
                if "." in path.split("/")[0]:
                    note("go", path, rel)
    return found


# --- reading the manifests --------------------------------------------------
def _json(path: str):
    try:
        return json.loads(_read(path) or "null")
    except ValueError:
        return None


REQ_NAME = re.compile(r"^\s*([A-Za-z0-9._-]+)")
DEV_REQ_FILE = re.compile(r"(dev|test|lint|doc|ci)", re.I)


def read_manifests(root: str) -> dict:
    """Which packages this repository asks for directly, and in which scope.

    Returns {ecosystem: {name: "runtime" | "development"}}.  A name that is in
    both is runtime: shipping once is enough.
    """
    direct = {"npm": {}, "python": {}, "go": {}}

    def put(eco, name, scope):
        name = (name or "").strip()
        if not name:
            return
        if eco == "python":
            name = name.lower()
        if direct[eco].get(name) == "runtime":
            return
        direct[eco][name] = scope

    for full, rel in _walk(root):
        base = os.path.basename(full).lower()

        if base == "package.json":
            document = _json(full)
            if not isinstance(document, dict):
                continue
            for key in ("dependencies", "peerDependencies", "optionalDependencies"):
                for name in (document.get(key) or {}):
                    put("npm", name, "runtime")
            for name in (document.get("devDependencies") or {}):
                put("npm", name, "development")

        elif base.startswith("requirements") and base.endswith(".txt"):
            scope = "development" if DEV_REQ_FILE.search(base) else "runtime"
            for line in (_read(full) or "").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-", "http", "git+")):
                    continue
                match = REQ_NAME.match(line)
                if match:
                    put("python", match.group(1), scope)

        elif base == "pyproject.toml":
            text = _read(full)
            # Deliberately not a TOML parse.  The two blocks that matter are
            # findable with a scan, and this has to run where tomllib may not
            # be there and a dependency of our own would be one more thing to
            # install into the scanner image.
            for block, scope in (("[project]", "runtime"),
                                 ("[tool.poetry.dependencies]", "runtime"),
                                 ("[project.optional-dependencies]", "development"),
                                 ("[tool.poetry.group.dev.dependencies]", "development"),
                                 ("[tool.poetry.dev-dependencies]", "development")):
                start = text.find(block)
                if start < 0:
                    continue
                chunk = text[start:start + 8000]
                for match in re.finditer(r'^\s*["\']?([A-Za-z0-9._-]+)["\']?\s*[=<>~^]', chunk, re.M):
                    put("python", match.group(1), scope)
                for match in re.finditer(r'^\s*["\']([A-Za-z0-9._-]+)[^"\']*["\']\s*,?\s*$', chunk, re.M):
                    put("python", match.group(1), scope)

        elif base == "pipfile":
            text = _read(full)
            for block, scope in (("[packages]", "runtime"),
                                 ("[dev-packages]", "development")):
                start = text.find(block)
                if start < 0:
                    continue
                chunk = text[start + len(block):]
                chunk = chunk.split("\n[", 1)[0]
                for match in re.finditer(r'^\s*["\']?([A-Za-z0-9._-]+)["\']?\s*=', chunk, re.M):
                    put("python", match.group(1), scope)

        elif base == "go.mod":
            for line in (_read(full) or "").splitlines():
                stripped = line.strip()
                if stripped.startswith(("module ", "go ", "//", ")", "replace ")):
                    continue
                stripped = stripped[len("require "):].strip() if stripped.startswith("require ") else stripped
                if not stripped or stripped == "(":
                    continue
                parts = stripped.split()
                if len(parts) >= 2 and "/" in parts[0]:
                    # `// indirect` is go saying this came in through something
                    # else, which is exactly the transitive question.
                    put("go", parts[0],
                        "runtime" if "// indirect" not in line else "transitive")
    return direct


# --- who pulls in whom ------------------------------------------------------
#
# The absence of an import is not evidence on its own.  An application never
# imports qs, and express parses every query string with it.  What the lockfile
# says is evidence: npm marks every package needed only for development
# `"dev": true`, and records which package requires which, so a transitive
# package can be followed up to the direct dependency that brought it in.

def _npm_name(key: str) -> str:
    """node_modules/a/node_modules/@s/b -> @s/b"""
    tail = key.rsplit("node_modules/", 1)[-1]
    return tail


def read_npm_locks(root: str) -> dict:
    """-> {name: {"dev": bool, "parents": set, "roots": {name: scope}}}

    Every package-lock.json in the tree, merged.  A package is development only
    when every copy of it, in every lockfile, is marked dev.
    """
    info: dict = {}
    roots: dict = {}

    def entry(name):
        return info.setdefault(name, {"dev": True, "parents": set()})

    for full, _rel in _walk(root):
        if os.path.basename(full) not in ("package-lock.json", "npm-shrinkwrap.json"):
            continue
        doc = _json(full)
        if not isinstance(doc, dict):
            continue
        packages = doc.get("packages")
        if isinstance(packages, dict):
            top = packages.get("") or {}
            for key, scope in (("dependencies", "runtime"), ("optionalDependencies", "runtime"),
                               ("peerDependencies", "runtime"), ("devDependencies", "development")):
                for dep in (top.get(key) or {}):
                    if roots.get(dep) != "runtime":
                        roots[dep] = scope
            for key, pkg in packages.items():
                if not key or not isinstance(pkg, dict) or "node_modules/" not in key:
                    continue
                name = _npm_name(key)
                node = entry(name)
                if not pkg.get("dev"):
                    node["dev"] = False
                for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                    for dep in (pkg.get(field) or {}):
                        entry(dep)["parents"].add(name)
            continue
        # Lockfile version 1: a nested tree, with dev on each node and the
        # edges under `requires`.  It has no root entry, so the direct
        # dependencies come from the package.json beside it.
        beside = _json(os.path.join(os.path.dirname(full), "package.json"))
        if isinstance(beside, dict):
            for key, scope in (("dependencies", "runtime"), ("optionalDependencies", "runtime"),
                               ("peerDependencies", "runtime"), ("devDependencies", "development")):
                for dep in (beside.get(key) or {}):
                    if roots.get(dep) != "runtime":
                        roots[dep] = scope
        def walk_v1(tree):
            for name, pkg in (tree or {}).items():
                if not isinstance(pkg, dict):
                    continue
                node = entry(name)
                if not pkg.get("dev"):
                    node["dev"] = False
                for dep in (pkg.get("requires") or {}):
                    entry(dep)["parents"].add(name)
                walk_v1(pkg.get("dependencies"))
        walk_v1(doc.get("dependencies"))
    for name, node in info.items():
        node["roots"] = roots
    return {"packages": info, "roots": roots}


def npm_chains(name: str, locks: dict, limit: int = 12) -> list:
    """Shortest chains from a direct dependency down to this package."""
    packages, roots = locks.get("packages") or {}, locks.get("roots") or {}
    if name not in packages:
        return []
    chains, frontier, seen = [], [[name]], {name}
    while frontier and len(chains) < limit:
        nxt = []
        for path in frontier:
            head = path[0]
            if head in roots and len(path) > 1:
                chains.append(path)
                continue
            for parent in sorted(packages.get(head, {}).get("parents") or ()):
                if parent not in seen:
                    seen.add(parent)
                    nxt.append([parent] + path)
        frontier = nxt[:500]
    return chains


def _py_norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def read_poetry_locks(root: str, direct: dict) -> dict:
    """The same shape as read_npm_locks, from poetry.lock.

    Poetry 2 records `groups = ["main"]` or `["dev"]` on every package, and
    older versions `category = "dev"`.  Either is the lockfile saying whether
    the package ships.  The edges are each package's dependency table, and the
    direct dependencies are what pyproject.toml asked for.
    """
    info: dict = {}
    for full, _rel in _walk(root):
        if os.path.basename(full) != "poetry.lock":
            continue
        text = _read(full)
        for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
            named = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
            if not named:
                continue
            name = _py_norm(named.group(1))
            node = info.setdefault(name, {"dev": True, "parents": set()})
            groups = re.search(r"^groups\s*=\s*\[([^\]]*)\]", block, re.M)
            category = re.search(r'^category\s*=\s*"([^"]+)"', block, re.M)
            if groups:
                if '"main"' in groups.group(1):
                    node["dev"] = False
            elif not category or category.group(1) != "dev":
                node["dev"] = False
            deps = re.search(r"^\[package\.dependencies\]\s*$(.*?)(?=^\[|\Z)", block, re.M | re.S)
            for dep in re.findall(r"^([A-Za-z0-9._-]+)\s*=", deps.group(1) if deps else "", re.M):
                info.setdefault(_py_norm(dep), {"dev": True, "parents": set()})["parents"].add(name)
    roots = {_py_norm(n): scope for n, scope in (direct.get("python") or {}).items()}
    return {"packages": info, "roots": roots}


def judge_from_lock(name: str, eco: str, imports: dict, locks: dict) -> tuple:
    """For a package nothing imports directly: what the lockfile says.
    None when the lockfile does not know it."""
    packages = (locks or {}).get("packages") or {}
    key = _py_norm(name) if eco == "python" else name
    if key not in packages:
        return None
    seen = imports.get(eco) or {}

    def imported(package):
        if eco == "python":
            for candidate in python_candidates(package):
                if candidate in seen:
                    return seen[candidate]
            return None
        return seen.get(package)

    chains = npm_chains(key, locks)
    # A chain is never proof the code runs.  It is shown, and stays unknown.
    for chain in chains:
        hit = imported(chain[0])
        if hit and hit["ships"]:
            files = "1 file" if hit["files"] == 1 else f"{hit['files']} files"
            return UNKNOWN, (f"pulled in through {' -> '.join(chain)}, and {chain[0]} "
                             f"is imported in {files}, first at {hit['first']}; whether "
                             f"this code runs depends on what {chain[0]} does with it")
    if packages[key]["dev"]:
        return UNLIKELY, ("installed only for development (the lockfile marks it "
                          "dev) and nothing the application ships imports what "
                          "pulls it in, so it is not in what gets deployed")
    if chains:
        return UNKNOWN, (f"pulled in through {' -> '.join(chains[0])}, but nothing the "
                         f"application ships imports {chains[0][0]}, which may be a "
                         f"tool rather than a library")
    return UNKNOWN, "in the lockfile, but nothing found leads to it from a direct dependency"


# Pages that load a library with a script tag rather than an import.
PAGE_EXT = {".html", ".htm", ".cshtml", ".vbhtml", ".aspx", ".ascx", ".master",
            ".jsp", ".php", ".erb", ".hbs", ".ejs", ".vue", ".twig", ".jinja", ".j2"}
SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
# ASP.NET loads scripts without a script tag: a ScriptManager reference by name
# or path, and MVC bundles that include a file pattern.
ASP_SCRIPT = re.compile(r"""<asp:ScriptReference[^>]*?\b(?:Name|Path)\s*=\s*["']([^"']+)["']""", re.I)
BUNDLE_INCLUDE = re.compile(r"""\.Include\(\s*((?:@?"[^"]+"\s*,?\s*)+)\)""")


def scan_script_tags(root: str) -> dict:
    """-> {basename stem: first page that loads it}."""
    loaded: dict = {}

    def note(src: str, rel: str):
        stem = os.path.basename(src.split("?")[0].strip().lower())
        # A ScriptManager reference by name, jquery, is the library itself.
        if stem and not stem.endswith(".js"):
            stem += ".js"
        # MVC writes {version} where the number goes.
        stem = stem.replace("-{version}", "")
        if stem:
            loaded.setdefault(stem, rel)

    for full, rel in _walk(root):
        ext = os.path.splitext(full)[1].lower()
        if TEST_PATH.search(rel):
            continue
        if ext in PAGE_EXT:
            text = _read(full)
            for match in SCRIPT_SRC.finditer(text):
                note(match.group(1), rel)
            for match in ASP_SCRIPT.finditer(text):
                note(match.group(1), rel)
        elif ext in (".cs", ".vb"):
            text = _read(full)
            if "ScriptBundle" not in text:
                continue
            for match in BUNDLE_INCLUDE.finditer(text):
                for src in re.findall(r'"([^"]+)"', match.group(1)):
                    note(src, rel)
    return loaded


def _script_loads(name: str, scripts: dict) -> str:
    """The page that loads this library by file name, if one does."""
    low = (name or "").lower()
    if not low or not scripts:
        return ""
    pattern = re.compile(r"^%s(?:[-.][\w.]*)?\.js$" % re.escape(low))
    for stem, page in scripts.items():
        if pattern.match(stem):
            return page
    return ""


# --- the verdict ------------------------------------------------------------
def judge_npm_transitive(name: str, direct: dict, imports: dict, locks: dict,
                         scripts: dict) -> tuple:
    """For an npm package nothing imports directly.  None when there is no
    lockfile evidence either way."""
    page = _script_loads(name, scripts)
    if page:
        return REACHABLE, f"a page loads it with a script tag, first at {page}"
    packages = (locks or {}).get("packages") or {}
    if name not in packages:
        return None
    seen = imports.get("npm") or {}
    chains = npm_chains(name, locks)
    # Being somewhere under a package the application uses does not mean this
    # code runs: a bundle carries only what is imported, and a dependency of a
    # dependency is often an install script or a build step.  So a chain is
    # never proof of reachable.  It is shown, and the verdict stays unknown.
    shipping = [c for c in chains if (seen.get(c[0]) or {}).get("ships")]
    if shipping:
        chain = shipping[0]
        hit = seen[chain[0]]
        files = "1 file" if hit["files"] == 1 else f"{hit['files']} files"
        return UNKNOWN, (f"pulled in through {' -> '.join(chain)}, and {chain[0]} "
                         f"is imported in {files}, first at {hit['first']}; whether "
                         f"this code runs depends on what {chain[0]} does with it")
    # Development only, and nothing the application ships leads to it: the
    # lockfile and the source agree that it is not deployed.
    if packages[name]["dev"]:
        return UNLIKELY, ("installed only for development (the lockfile marks it "
                          "dev) and nothing the application ships imports what "
                          "pulls it in, so it is not in what gets deployed")
    if chains:
        chain = chains[0]
        return UNKNOWN, (f"pulled in through {' -> '.join(chain)}, but nothing the "
                         f"application ships imports {chain[0]}, which may be a "
                         f"tool rather than a library")
    return UNKNOWN, "in the lockfile, but nothing found leads to it from a direct dependency"


def judge(name: str, eco: str, direct: dict, imports: dict,
          locks: dict = None, scripts: dict = None) -> tuple:
    """-> (verdict, reason).  Conservative by construction."""
    # A page loading the library is evidence whatever ecosystem reported it:
    # jQuery arrives as an npm file, a NuGet package and a dotnet component,
    # and all three are the same script on the same page.
    page = _script_loads(name, scripts or {})
    if page:
        return REACHABLE, f"a page loads it with a script tag, first at {page}"
    if eco not in SUPPORTED:
        return UNKNOWN, (f"reachability is not worked out for {eco} packages yet, "
                         "so this keeps its place in the list")

    known = direct.get(eco) or {}
    seen = imports.get(eco) or {}

    if eco == "python":
        candidates = python_candidates(name)
        declared = known.get((name or "").lower())
        hit = next((seen[c] for c in candidates if c in seen), None)
        mapped = (name or "").lower() in PY_MODULES
    elif eco == "go":
        declared = known.get(name)
        # A go module path is a prefix of the import paths inside it.
        hit = seen.get(name)
        if hit is None:
            for path, entry in seen.items():
                if path == name or path.startswith(name + "/"):
                    hit = entry
                    break
        mapped = True
    else:
        declared = known.get(name)
        hit = seen.get(name)
        mapped = True

    # The source importing it outranks what the manifest calls it.  A front
    # end often lists everything under devDependencies and a bundler ships it
    # all to the browser regardless.
    if hit is not None:
        where = hit["first"]
        count = hit["files"]
        files = "1 file" if count == 1 else f"{count} files"
        if not hit["ships"]:
            if declared == "development":
                return UNLIKELY, (f"a development dependency, only imported from "
                                  f"the test suite, in {files}, first at {where}")
            return UNLIKELY, (f"only imported from the test suite, in {files}, "
                              f"first at {where}")
        return REACHABLE, f"imported in {files}, first at {where}"

    if declared == "development":
        return UNLIKELY, ("a development dependency that nothing the "
                          "application ships imports, so it is not in what "
                          "gets deployed")

    if eco == "npm" and declared in (None, "transitive"):
        decided = judge_npm_transitive(name, direct, imports, (locks or {}).get("npm") or {},
                                       scripts or {})
        if decided:
            return decided
    if eco == "python" and declared in (None, "transitive"):
        decided = judge_from_lock(name, "python", imports, (locks or {}).get("python") or {})
        if decided:
            return decided

    if not known and not seen:
        return UNKNOWN, ("no manifest or source for this ecosystem was readable "
                         "in the checkout")

    if declared in ("runtime", "transitive") or declared is None:
        transitive = declared in (None, "transitive")
        if transitive:
            # Not an import is not evidence.  A framework calls what it pulls
            # in on every request, and without a lockfile to say this package
            # is development only, nobody can say it does not ship.
            return UNKNOWN, ("not a direct dependency, and nothing here says "
                             "whether it ships: the application may reach it "
                             "through the package that pulled it in")
        if not mapped:
            return UNKNOWN, ("a direct dependency, but no import of it was "
                             "found and its module name may differ from the "
                             "package name")
        return UNKNOWN, ("a direct dependency that nothing appears to import, "
                         "which may be a tool rather than a library")

    return UNKNOWN, "not enough of the tree was readable to say"


def apply(findings: list, root: str) -> list:
    """Add a reachability verdict to every dependency finding."""
    imports = scan_imports(root)
    direct = read_manifests(root)
    # Only read when there is an npm finding to answer, because both walk the
    # whole tree again.
    wants_npm = any(ecosystem_of((f.get("package") or {}).get("type")
                                 or (f.get("package") or {}).get("ecosystem") or "") == "npm"
                    for f in findings)
    wants_python = any(ecosystem_of((f.get("package") or {}).get("type")
                                    or (f.get("package") or {}).get("ecosystem") or "") == "python"
                       for f in findings)
    locks = {"npm": read_npm_locks(root) if wants_npm else {},
             "python": read_poetry_locks(root, direct) if wants_python else {}}
    scripts = scan_script_tags(root) if findings else {}

    for finding in findings:
        package = finding.get("package") or {}
        name = package.get("name") or ""
        eco = ecosystem_of(package.get("type") or package.get("ecosystem") or "")
        if not name:
            finding["reachability"] = {
                "verdict": UNKNOWN, "reason": "the finding does not name a package",
                "ecosystem": eco, "direct": "unknown", "scope": "unknown"}
            continue

        verdict, reason = judge(name, eco, direct, imports, locks, scripts)
        known = (direct.get(eco) or {})
        declared = known.get(name.lower() if eco == "python" else name)
        finding["reachability"] = {
            "verdict": verdict,
            "reason": reason,
            "ecosystem": eco,
            "direct": ("direct" if declared in ("runtime", "development")
                       else "transitive" if declared == "transitive"
                       else "unknown"),
            "scope": ("development" if declared == "development"
                      else "runtime" if declared == "runtime"
                      else "unknown"),
        }
    return findings


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("usage: reachability.py <vulns.json> <repo_root>\n")
        return 2
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as handle:
            findings = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"could not read the findings: {exc}\n")
        return 1
    if not isinstance(findings, list):
        sys.stderr.write("the findings are not a list\n")
        return 1

    json.dump(apply(findings, sys.argv[2]), sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
