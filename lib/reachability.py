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
        if not TEST_PATH.search(rel):
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


# --- the verdict ------------------------------------------------------------
def judge(name: str, eco: str, direct: dict, imports: dict) -> tuple:
    """-> (verdict, reason).  Conservative by construction."""
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

    if declared == "development":
        return UNLIKELY, ("a development dependency, which is not in what "
                          "gets deployed")

    if hit is not None:
        where = hit["first"]
        count = hit["files"]
        files = "1 file" if count == 1 else f"{count} files"
        if not hit["ships"]:
            return UNLIKELY, (f"only imported from the test suite, in {files}, "
                              f"first at {where}")
        return REACHABLE, f"imported in {files}, first at {where}"

    if not known and not seen:
        return UNKNOWN, ("no manifest or source for this ecosystem was readable "
                         "in the checkout")

    if declared in ("runtime", "transitive") or declared is None:
        transitive = declared in (None, "transitive")
        if transitive:
            return UNLIKELY, ("not a direct dependency and nothing in the "
                              "source imports it")
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

    for finding in findings:
        package = finding.get("package") or {}
        name = package.get("name") or ""
        eco = ecosystem_of(package.get("type") or package.get("ecosystem") or "")
        if not name:
            finding["reachability"] = {
                "verdict": UNKNOWN, "reason": "the finding does not name a package",
                "ecosystem": eco, "direct": "unknown", "scope": "unknown"}
            continue

        verdict, reason = judge(name, eco, direct, imports)
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
