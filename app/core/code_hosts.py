"""The host names a repository's own files say it serves, or name.

Read on every scan of the default branch, from the checkout already on disk,
so a site can be tied to its code without anybody typing a web address into
the repository first.  Two kinds, kept apart because they mean different
things:

    serves   a file that decides where the code answers: an ingress or route,
             a web server's server_name, a CNAME file, a CDN alias or
             certificate, a deploy environment's url, an OpenAPI server, a
             framework's allowed hosts, or an app/site url setting.  This is
             evidence the code is behind that host.

    names    an http(s) address written anywhere else in the code.  The code
             may only call that host, so this is a hint, never a link.

Standard library only: lib/code_hosts.py loads this file by path in the
scanner, the way lib/routes.py loads dast_whitebox.py.  Nothing is fetched and
nothing in the checkout is run.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

MAX_FILES = 8000
MAX_BYTES = 400_000
MAX_HOSTS = 300
MAX_FILES_PER_HOST = 3

# Test and generated trees name made up hosts, and dependencies name
# everybody's.  Dot directories are skipped too, except the CI ones.
SKIP_DIRS = {"node_modules", "vendor", "dist", "build", "target", "__pycache__",
             "venv", "bower_components", "coverage", "out", "bin", "obj", "test",
             "tests", "spec", "__tests__", "fixtures", "examples", "docs", "mocks",
             "testdata", "third_party", "site-packages"}
KEEP_DOT_DIRS = {".github", ".gitlab", ".circleci", ".azure", ".deploy", ".platform",
                 ".ebextensions", ".do", ".helm"}
TEXT_EXT = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".java", ".kt",
            ".cs", ".go", ".rb", ".php", ".xml", ".yaml", ".yml", ".json", ".scala",
            ".groovy", ".dwl", ".tf", ".tfvars", ".hcl", ".toml", ".conf", ".ini",
            ".properties", ".env", ".config", ".vue", ".svelte", ".html", ".bicep",
            ".template", ".tpl"}
NAMED_FILES = {"CNAME", "Caddyfile", "Dockerfile", "Procfile", "nginx.conf",
               "httpd.conf", ".htaccess"}

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = rf"(?:\*\.)?(?:{_LABEL}\.)+[a-z]{{2,24}}"
HOST_RE = re.compile(rf"^{_HOST}$")
# A host as written: optionally a scheme, then the host, then the end of the
# value, a port or a path.
_IN_VALUE = re.compile(rf"(?:[a-z][a-z0-9+.-]*://)?(?P<h>{_HOST})(?=$|[:/\s\"'`,;)\]}}>?#])", re.I)
_URL = re.compile(rf"\b(?:https?|wss?)://(?P<h>{_HOST})(?=$|[:/\s\"'`,;)\]}}>?#\\])", re.I)

# Not anybody's site: documentation, loopback and reserved names.
_IGNORE_SUFFIX = (".example", ".invalid", ".localhost", ".local", ".test",
                  ".example.com", ".example.org", ".example.net", ".svc",
                  ".cluster.local", ".internal", ".arpa", ".lan", ".home")
_IGNORE_EXACT = {"example.com", "example.org", "example.net", "localhost"}
# Placeholders people leave in templates and samples.
_PLACEHOLDER = re.compile(r"(^|[.-])(your|my)-?(domain|site|company|app|host|server)\b|"
                          r"(^|\.)(domain|company|website|placeholder)\.(com|org|net)$")
_CONFIG_EXT = {".conf", ".yaml", ".yml", ".toml", ".tf", ".tfvars", ".hcl", ".env",
               ".ini", ".tpl", ".template", ".vhost", ".properties", ".config", ".bicep"}
_SOURCE_EXT = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".java", ".kt",
               ".cs", ".go", ".rb", ".php", ".scala", ".groovy", ".vue", ".svelte"}
# A file extension is not a top level domain.  These turn up as "file.js".
_NOT_TLD = {"js", "ts", "py", "rb", "go", "java", "json", "yaml", "yml", "xml",
            "html", "htm", "css", "scss", "md", "txt", "php", "cs", "kt", "jsx",
            "tsx", "vue", "png", "jpg", "jpeg", "gif", "svg", "ico", "map", "lock",
            "log", "sh", "bat", "cfg", "conf", "ini", "env", "properties", "jar",
            "war", "zip", "gz", "tar", "pem", "crt", "key", "sql", "csv", "tf",
            "toml", "dwl", "raml", "wsdl", "xsd", "dll", "exe", "so", "class",
            "min", "test", "spec", "config", "local", "internal", "svc", "id",
            "name", "value", "type", "data", "get", "set", "prototype", "length"}

# Settings whose value is the address the code itself answers on.  Exact
# names only: API_URL, FRONTEND_URL, SERVER_URL, SERVICE_URL and the like are
# usually somebody else's host, the one this code calls.
_SERVE_KEYS = re.compile(
    r"""(?ix)^["']?(
        (?:app|site|public|external|canonical)[_.-]?(?:url|host|hostname|domain|origin)
      | (?:next_public_)?site[_.-]?url | nextauth[_.-]?url | virtual[_.-]?host
      | letsencrypt[_.-]?host | allowed[_.-]?hosts | csrf[_.-]?trusted[_.-]?origins
      | server[_.-]?name | servername | serveralias | domain[_.-]?name | domainname
      | custom[_.-]?domain | customdomain | homepage | aliases | subject[_.-]?alternative[_.-]?names
      | dns[_.-]?names | allowedhosts | hosts?
    )["']?$""")
# Of those, the ones that only mean "serves" inside the right kind of file.
_SCOPED_KEYS = {"host", "hosts", "aliases", "homepage"}

# In Helm values, the sections whose host: is where the chart answers.
_ROUTE_PARENTS = {"ingress", "ingresses", "ingressroute", "route", "routes", "httproute",
                  "virtualservice", "gateway", "istio", "openshift_route"}
_ROUTE_KINDS = re.compile(
    r"(?im)^\s*kind:\s*[\"']?(Ingress|IngressRoute|Route|HTTPRoute|GRPCRoute|TLSRoute|"
    r"Gateway|VirtualService|Certificate|ManagedCertificate|BackendConfig)\b")
_OPENAPI = re.compile(r"(?im)^\s*[\"']?(openapi|swagger)[\"']?\s*:")
_KV = re.compile(r"""^\s*(?:-\s*)?(?:export\s+)?(?P<k>["']?[A-Za-z_][\w.-]*["']?)\s*(?:=|:)\s*(?P<v>.*)$""")
_LIST_ITEM = re.compile(r"""^\s*-\s*(?P<v>.+)$""")
# Traefik writes hosts in backticks: Host(`a.example.com`, `b.example.com`).
_TRAEFIK = re.compile(r"Host(?:SNI)?\(\s*(?P<v>`[^`)]+`(?:\s*,\s*`[^`)]+`)*)\s*\)")
_NGINX = re.compile(r"(?im)^\s*(server_name|ServerName|ServerAlias)\s+(?P<v>[^;{\n]+)")
_RAILS = re.compile(r"""config\.hosts\s*(?:<<|\+=|=)\s*(?P<v>[^\n]+)""")
_CADDY = re.compile(r"(?m)^(?P<v>(?:https?://)?[a-z0-9*][^\s{]*(?:\s*,\s*[^\s{]+)*)\s*\{\s*$", re.I)
_ENV_BLOCK = re.compile(r"^\s*environment:\s*$")
_ENV_URL = re.compile(r"^\s*url:\s*(?P<v>.+)$")
_SERVERS = re.compile(r"^\s*[\"']?servers[\"']?\s*:")


def clean(raw: str) -> str:
    """A host from a value, or "".  Templated values are refused."""
    value = (raw or "").strip().strip("\"'`,;[]()").strip()
    if not value or any(c in value for c in "{}$%<>|"):
        return ""
    m = _IN_VALUE.match(value.lower())
    if not m:
        return ""
    host = m.group("h").rstrip(".").lower()
    if not HOST_RE.match(host) or host in _IGNORE_EXACT or host.endswith(_IGNORE_SUFFIX):
        return ""
    if _PLACEHOLDER.search(host):
        return ""
    if host.rsplit(".", 1)[-1] in _NOT_TLD:
        return ""
    if re.fullmatch(r"[\d.]+", host.replace("*.", "")):
        return ""
    return host


def _values(raw: str) -> list:
    """Every host in a value that may be a list: "a b", "a,b", ["a","b"], a;b."""
    out = []
    for part in re.split(r"[\s,;\[\]]+", raw or ""):
        host = clean(part)
        if host and host not in out:
            out.append(host)
    return out


def _wanted(dirpath: str, filename: str) -> bool:
    if filename in NAMED_FILES or filename.startswith(".env"):
        return True
    return Path(filename).suffix.lower() in TEXT_EXT


def site_config_name(low: str) -> bool:
    return low in ("docusaurus.config.js", "gatsby-config.js", "astro.config.mjs",
                   "nuxt.config.js", "nuxt.config.ts")


def _serves_in(text: str, rel: str, filename: str) -> list:
    """-> [(host, how)] that this file says the code answers on."""
    out = []
    low = filename.lower()
    is_yaml = low.endswith((".yaml", ".yml"))
    route_file = bool(_ROUTE_KINDS.search(text)) if is_yaml else False
    helm_values = is_yaml and (low.startswith("values") or "/charts/" in f"/{rel}"
                               or "/helm/" in f"/{rel}")
    openapi = bool(_OPENAPI.search(text[:4000])) if low.endswith((".yaml", ".yml", ".json")) else False
    ci_file = rel.startswith((".github/workflows/", ".gitlab")) or low == ".gitlab-ci.yml"
    source = Path(low).suffix in _SOURCE_EXT and not site_config_name(low)
    site_config = low in ("_config.yml", "config.toml", "hugo.toml", "hugo.yaml",
                          "config.yaml", "docusaurus.config.js", "gatsby-config.js",
                          "astro.config.mjs", "nuxt.config.js", "nuxt.config.ts")

    def add(values, how):
        for host in values:
            if (host, how) not in out:
                out.append((host, how))

    if filename == "CNAME":
        add(_values(text.splitlines()[0] if text.strip() else ""), "CNAME file")
        return out
    # Server and proxy rules live in config files.  The same words in source
    # or in a data file (a vulnerability database, say) are about something else.
    config_file = (Path(low).suffix in _CONFIG_EXT or filename in NAMED_FILES
                   or low.startswith(".env"))
    if config_file:
        for m in _NGINX.finditer(text):
            add(_values(m.group("v")), "web server config")
        for m in _TRAEFIK.finditer(text):
            add(_values(" ".join(re.findall(r"`([^`]+)`", m.group("v")))), "Traefik rule")
    if filename == "Caddyfile":
        for m in _CADDY.finditer(text):
            add(_values(m.group("v")), "Caddyfile")
    if low.endswith((".rb",)):
        for m in _RAILS.finditer(text):
            add(_values(m.group("v")), "Rails config.hosts")
    if low == "package.json":
        for m in re.finditer(r'"homepage"\s*:\s*"([^"]+)"', text):
            add(_values(m.group(1)), "package homepage")
    lines = text.splitlines()
    list_key, list_indent, env_line = "", -1, -10
    # The keys above this line, by indent, so a host: under ingress: in Helm
    # values counts and a host: under database: does not.
    parents = []
    for n, line in enumerate(lines):
        indent = len(line) - len(line.lstrip())
        eff = indent + (2 if line.lstrip().startswith("- ") else 0)
        if line.strip() and not line.lstrip().startswith("#"):
            while parents and parents[-1][0] >= eff:
                parents.pop()
        # A deploy environment's url, in GitHub Actions or GitLab CI.
        if ci_file:
            if _ENV_BLOCK.match(line):
                env_line = n
            elif n - env_line <= 4:
                m = _ENV_URL.match(line)
                if m:
                    add(_values(m.group("v")), "deploy environment url")
        # YAML lists under a key that names hosts.
        if list_key:
            item = _LIST_ITEM.match(line)
            if item and indent >= list_indent:
                value = item.group("v")
                kv = _KV.match(line)
                if kv and kv.group("k").strip("\"'").lower() in ("url", "host"):
                    value = kv.group("v")
                elif kv and ":" in value and not value.lower().startswith(("http", "*")):
                    list_key = "" if indent <= list_indent else list_key
                    continue
                add(_values(value), list_key)
                continue
            if line.strip() and indent <= list_indent:
                list_key = ""
        kv = _KV.match(line)
        if not kv:
            continue
        key = kv.group("k").strip("\"'")
        value = kv.group("v").strip()
        lk = key.lower().replace("-", "_")
        under = {k for _i, k in parents}
        parents.append((eff, lk))
        if openapi and lk == "servers":
            list_key, list_indent = "OpenAPI servers", indent
            if value.startswith("["):
                for url in re.findall(r"""["']url["']\s*:\s*["']([^"']+)""", text):
                    add(_values(url), "OpenAPI servers")
            continue
        if openapi and lk == "host" and value:
            add(_values(value), "OpenAPI host")
            continue
        if site_config and lk in ("url", "baseurl", "base_url", "siteurl", "site_url") and value:
            add(_values(value), "site generator url")
            continue
        if not _SERVE_KEYS.match(key):
            continue
        # In source code a setting is only read when it is written out as a
        # string.  publicUrl: config.publicUrl is a variable, not a host.
        if source and not value.startswith(("'", '"', "`", "[", "(")):
            continue
        in_route = route_file or (helm_values and bool(under & _ROUTE_PARENTS))
        if lk in _SCOPED_KEYS and not in_route:
            if lk == "aliases" and low.endswith((".tf", ".tfvars", ".json")) and value:
                add(_values(value), "CDN aliases")
            continue
        how = "ingress or route" if in_route and lk in ("host", "hosts") else f"{key} setting"
        if value in ("", "|", ">") or value.endswith(":"):
            list_key, list_indent = how, indent
            continue
        add(_values(value), how)
    return out


def read(root: Path) -> dict:
    """-> {hosts: [{host, kind, how, files}], files: read}

    serves come first, then names by how many files name them."""
    root = Path(root)
    found, read_count = {}, 0

    def note(host, kind, how, rel):
        key = (host, kind)
        entry = found.setdefault(key, {"host": host, "kind": kind, "how": how, "files": []})
        if rel not in entry["files"] and len(entry["files"]) < MAX_FILES_PER_HOST:
            entry["files"].append(rel)
        entry.setdefault("_n", 0)
        entry["_n"] += 1

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and (not d.startswith(".") or d in KEEP_DOT_DIRS))
        for filename in sorted(filenames):
            if not _wanted(dirpath, filename):
                continue
            path = Path(dirpath) / filename
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
            served = set()
            for host, how in _serves_in(text, rel, filename):
                served.add(host)
                note(host, "serves", how, rel)
            for m in _URL.finditer(text):
                host = clean(m.group("h"))
                if host and host not in served:
                    note(host, "names", "named in the code", rel)
        if read_count > MAX_FILES:
            break
    serves = sorted((e for e in found.values() if e["kind"] == "serves"),
                    key=lambda e: e["host"])
    serving = {e["host"] for e in serves}
    names = sorted((e for e in found.values()
                    if e["kind"] == "names" and e["host"] not in serving),
                   key=lambda e: (-e["_n"], e["host"]))
    out = []
    for e in serves + names:
        e.pop("_n", None)
        out.append(e)
    return {"hosts": out[:MAX_HOSTS], "files": read_count}


def load(raw) -> list:
    """The stored list, checked.  -> [{host, kind, how, files}]"""
    try:
        value = json.loads(raw or "[]") if isinstance(raw, str) else raw
    except ValueError:
        return []
    out = []
    for e in value if isinstance(value, list) else []:
        if not isinstance(e, dict):
            continue
        host = clean(str(e.get("host") or ""))
        kind = e.get("kind")
        if not host or kind not in ("serves", "names"):
            continue
        files = [str(f)[:300] for f in (e.get("files") or []) if isinstance(f, str)]
        out.append({"host": host, "kind": kind, "how": str(e.get("how") or "")[:60],
                    "files": files[:MAX_FILES_PER_HOST]})
    return out[:MAX_HOSTS]
