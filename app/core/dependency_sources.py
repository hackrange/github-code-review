"""Where a codebase gets its code from, read straight out of the files.

Every package manager can be pointed at a registry other than the public one,
and every one of them can pull another repository in directly: a git URL in a
manifest, a submodule, a shared CI template, a Go module that happens to live
in the same organization.  Both are worth knowing.  A private registry is a
host the build trusts with everything it installs, and a repository pulled in
from elsewhere in the estate is shared code: a finding in it is a finding in
everything that uses it.

No model is asked.  These are regular expressions over known file names, so
the answer is the same every time and every row says which file and line it
came from.  Credentials in a URL (user:token@host) are dropped before anything
is stored, and files that hold nothing but credentials are read for hosts only.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

# Big enough for any real manifest.  A lock file past this is read for its
# first part only, which still names every registry it uses.
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 4000
MAX_ROWS = 2000

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
             "dist", "build", "target", ".gradle", ".idea", ".terraform"}

# Hosts everybody uses.  Anything else is somebody's own, which is the part
# that needs reading.
PUBLIC_HOSTS = {
    "registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com",
    "pypi.org", "pypi.python.org", "files.pythonhosted.org",
    "repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com",
    "plugins.gradle.org", "jcenter.bintray.com", "maven.google.com",
    "dl.google.com", "api.nuget.org", "www.nuget.org", "proxy.golang.org",
    "sum.golang.org", "rubygems.org", "index.rubygems.org", "crates.io",
    "index.crates.io", "static.crates.io", "repo.packagist.org",
    "packagist.org", "docker.io", "index.docker.io", "registry-1.docker.io",
    "ghcr.io", "quay.io", "gcr.io", "mcr.microsoft.com", "public.ecr.aws",
    "registry.k8s.io", "github.com", "gitlab.com", "bitbucket.org",
    "registry.terraform.io", "charts.helm.sh", "golang.org", "go.googlesource.com",
    "gopkg.in", "google.golang.org", "k8s.io", "sigs.k8s.io", "cloud.google.com",
}

KINDS = ("package registry", "repository", "container registry", "ci template",
         "module source", "download")

_URL = re.compile(r"""(?:git\+)?(?:https?|ssh|git)://[^\s"'<>(){}\[\],;]+""")
_SCP = re.compile(r"""\bgit@([A-Za-z0-9.\-]+):([A-Za-z0-9_.\-/]+)""")


def _clean_url(raw: str) -> str:
    """A URL with any user and password taken out, and the trailing junk off."""
    text = raw.strip().rstrip(".,;)'\"").removeprefix("git+")
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    host = parts.hostname or ""
    if not host:
        return ""
    port = f":{parts.port}" if parts.port else ""
    # A ref after the repository, as pip writes it: repo.git@v1.
    path = re.sub(r"\.git@.*$", ".git", parts.path)
    return f"{parts.scheme}://{host}{port}{path}"


def host_of(value: str) -> str:
    try:
        return (urlsplit(value).hostname or "").lower()
    except ValueError:
        return ""


def repo_path(url: str) -> str:
    """org/repo out of a repository URL, or "" when it does not look like one."""
    try:
        path = urlsplit(url).path
    except ValueError:
        return ""
    path = path.strip("/").removesuffix(".git")
    bits = [b for b in path.split("/") if b]
    if len(bits) < 2:
        return ""
    # GitLab nests groups, so keep everything up to a - separator.
    if "-" in bits:
        bits = bits[:bits.index("-")]
    return "/".join(bits[:6])


def image_host(image: str) -> str:
    """The registry an image reference pulls from.  Docker Hub when unnamed."""
    ref = image.strip().split("@")[0]
    first = ref.split("/")[0]
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        return first.split(":")[0].lower()
    return "docker.io"


class _Rows:
    def __init__(self):
        self.rows = []
        self._seen = set()

    def add(self, kind, value, rel, line, ecosystem="", host=""):
        if len(self.rows) >= MAX_ROWS:
            return
        host = (host or host_of(value)).lower()
        if not host:
            return
        key = (kind, value, rel)
        if key in self._seen:
            return
        self._seen.add(key)
        self.rows.append({"kind": kind, "host": host, "value": value[:500],
                          "file": rel, "line": line, "ecosystem": ecosystem,
                          "public": host in PUBLIC_HOSTS})


def _lines(path: Path):
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES)
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


def _urls_in(text: str) -> list:
    found = [_clean_url(m.group(0)) for m in _URL.finditer(text)]
    for m in _SCP.finditer(text):
        found.append(f"ssh://{m.group(1)}/{m.group(2).removesuffix('.git')}.git")
    return [u for u in found if u]


def _registry_line(rows, rel, number, line, ecosystem):
    for url in _urls_in(line):
        rows.add("package registry", url, rel, number, ecosystem)


def _scan_file(root: Path, path: Path, rows: _Rows) -> None:
    rel = str(path.relative_to(root))
    name = path.name.lower()
    lines = None

    def each():
        nonlocal lines
        if lines is None:
            lines = _lines(path)
        return enumerate(lines, 1)

    # Package registries in configuration made for exactly that.
    if name in (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini",
                ".pypirc", "nuget.config", "settings.xml", ".bowerrc"):
        eco = {".npmrc": "npm", ".yarnrc": "npm", ".yarnrc.yml": "npm",
               "pip.conf": "pypi", "pip.ini": "pypi", ".pypirc": "pypi",
               "nuget.config": "nuget", "settings.xml": "maven",
               ".bowerrc": "npm"}[name]
        for n, line in each():
            # Credentials files: the hosts only.  _clean_url already drops
            # anything in the user part, and nothing else on the line is kept.
            if "_auth" in line or "password" in line.lower():
                for url in _urls_in(line):
                    rows.add("package registry", url, rel, n, eco)
                continue
            _registry_line(rows, rel, n, line, eco)
        return

    if name.startswith("requirements") and name.endswith((".txt", ".in")) \
            or name == "constraints.txt":
        for n, line in each():
            text = line.strip()
            if text.startswith(("-i", "--index-url", "--extra-index-url",
                                "--find-links", "-f", "--trusted-host")):
                _registry_line(rows, rel, n, text, "pypi")
            elif "git+" in text or " @ http" in text:
                for url in _urls_in(text):
                    rows.add("repository" if "git+" in text or url.endswith(".git")
                             else "download", url, rel, n, "pypi")
        return

    if name in ("pyproject.toml", "pipfile", "cargo.toml", "gemfile",
                "composer.json", "chart.yaml", "requirements.yaml"):
        eco = {"pyproject.toml": "pypi", "pipfile": "pypi", "cargo.toml": "cargo",
               "gemfile": "gem", "composer.json": "composer",
               "chart.yaml": "helm", "requirements.yaml": "helm"}[name]
        for n, line in each():
            low = line.lower()
            for url in _urls_in(line):
                if "git" in low.split("=")[0] or ":git" in low or "git:" in low \
                        or url.endswith(".git"):
                    rows.add("repository", url, rel, n, eco)
                else:
                    rows.add("package registry", url, rel, n, eco)
            if eco == "gem":
                m = re.search(r"""github:\s*["']([\w.\-]+/[\w.\-]+)["']""", line)
                if m:
                    rows.add("repository", f"https://github.com/{m.group(1)}",
                             rel, n, eco)
        return

    if name == "package.json":
        import json as _json
        try:
            data = _json.loads(path.read_bytes()[:MAX_FILE_BYTES].decode("utf-8", "replace"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        text = path.read_text("utf-8", "replace")

        def line_of(needle):
            at = text.find(needle)
            return text.count("\n", 0, at) + 1 if at >= 0 else 0

        for section in ("dependencies", "devDependencies", "optionalDependencies",
                        "peerDependencies"):
            for dep, spec in (data.get(section) or {}).items():
                spec = str(spec or "")
                if spec.startswith("github:") or re.match(
                        r"^[\w.\-]+/[\w.\-]+(#.*)?$", spec):
                    url = "https://github.com/" + spec.removeprefix("github:").split("#")[0]
                elif "://" in spec or spec.startswith(("git+", "git@")):
                    found = _urls_in(spec)
                    url = found[0] if found else ""
                else:
                    continue
                if not url:
                    continue
                kind = "download" if url.endswith((".tgz", ".tar.gz", ".zip")) \
                    else "repository"
                rows.add(kind, url, rel, line_of(spec), "npm")
        registry = (data.get("publishConfig") or {}).get("registry")
        if registry:
            for url in _urls_in(str(registry)):
                rows.add("package registry", url, rel, line_of(str(registry)), "npm")
        return

    if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                "npm-shrinkwrap.json", "poetry.lock", "pipfile.lock",
                "gemfile.lock", "composer.lock", "packages.lock.json",
                "cargo.lock", "uv.lock"):
        # Lock files name a host per package.  One row per host, not per
        # package: the question is which registries, not which packages.
        hosts = {}
        for n, line in each():
            for url in _urls_in(line):
                host = host_of(url)
                if host and host not in hosts:
                    hosts[host] = (url, n)
        for host, (url, n) in hosts.items():
            parts = urlsplit(url)
            kind = "repository" if url.endswith(".git") or "git" in parts.scheme \
                else "package registry"
            rows.add(kind, f"{parts.scheme}://{host}", rel, n, "lock", host)
        return

    if name in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
                "settings.gradle.kts", "init.gradle", "gradle.properties"):
        in_scm = False
        for n, line in each():
            low = line.lower()
            if "<scm>" in low:
                in_scm = True
            if "</scm>" in low:
                in_scm = False
            if in_scm or "xmlns" in low or "schemalocation" in low \
                    or "maven.apache.org/pom" in low or "<license" in low:
                continue
            if "<url>" in low or "url" in low or "maven" in low:
                for url in _urls_in(line):
                    if "apache.org/licenses" in url or url.endswith(".xsd"):
                        continue
                    rows.add("package registry", url, rel, n, "maven")
        return

    if name == "go.mod":
        for n, line in each():
            text = line.strip()
            if text.startswith(("module ", "go ", "toolchain ", "//")) or not text:
                continue
            text = text.removeprefix("require").strip(" (")
            m = re.match(r"^([a-z0-9.\-]+\.[a-z]{2,}(?:/[\w.\-~]+)+)\s+v", text)
            if m:
                path = m.group(1)
                host = path.split("/")[0]
                if host in PUBLIC_HOSTS and host not in ("github.com", "gitlab.com",
                                                          "bitbucket.org"):
                    continue
                rows.add("module source", "https://" + "/".join(path.split("/")[:3]),
                         rel, n, "go", host)
            if "=>" in text:
                target = text.split("=>", 1)[1].strip().split()[0]
                if "." in target.split("/")[0]:
                    rows.add("module source", "https://" + target, rel, n, "go")
        return

    if name == ".gitmodules":
        for n, line in each():
            if line.strip().startswith("url"):
                for url in _urls_in(line):
                    rows.add("repository", url, rel, n, "git")
        return

    if name.startswith("dockerfile") or name.endswith(".dockerfile") \
            or name.startswith("containerfile"):
        for n, line in each():
            m = re.match(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line)
            if m and not m.group(1).startswith("$") and m.group(1).lower() != "scratch":
                image = m.group(1)
                rows.add("container registry", image, rel, n, "docker",
                         image_host(image))
        return

    if name.endswith((".yml", ".yaml")):
        workflow = ".github/workflows/" in rel.replace(os.sep, "/") \
            or ".github/actions/" in rel.replace(os.sep, "/")
        gitlab = name == ".gitlab-ci.yml"
        compose = "compose" in name
        for n, line in each():
            text = line.strip()
            if workflow:
                m = re.match(r"-?\s*uses:\s*['\"]?([\w.\-]+/[\w.\-/]+)@", text)
                if m and not m.group(1).startswith("./"):
                    repo = "/".join(m.group(1).split("/")[:2])
                    rows.add("ci template", f"https://github.com/{repo}", rel, n,
                             "actions")
                m = re.match(r"-?\s*uses:\s*['\"]?docker://(\S+)", text)
                if m:
                    rows.add("container registry", m.group(1), rel, n, "docker",
                             image_host(m.group(1)))
            if gitlab:
                m = re.match(r"-?\s*project:\s*['\"]?([\w.\-/]+)", text)
                if m:
                    rows.add("ci template", f"gitlab://{m.group(1)}", rel, n,
                             "gitlab", "gitlab")
                if text.startswith(("- remote:", "remote:")):
                    for url in _urls_in(text):
                        rows.add("ci template", url, rel, n, "gitlab")
            if (compose or gitlab or "k8s" in rel or "kube" in rel
                    or "helm" in rel or "deploy" in rel) and \
                    re.match(r"-?\s*image:\s*['\"]?([^\s'\"$]+)", text):
                image = re.match(r"-?\s*image:\s*['\"]?([^\s'\"$]+)", text).group(1)
                if image and not image.startswith("{"):
                    rows.add("container registry", image, rel, n, "docker",
                             image_host(image))
            if name in ("chart.yaml", "requirements.yaml") and "repository:" in text:
                for url in _urls_in(text):
                    rows.add("package registry", url, rel, n, "helm")
        return

    if name.endswith(".tf"):
        for n, line in each():
            m = re.match(r'\s*source\s*=\s*"([^"]+)"', line)
            if not m:
                continue
            value = m.group(1)
            if value.startswith(("./", "../")):
                continue
            if value.startswith("git::") or "github.com" in value or value.endswith(".git"):
                for url in _urls_in(value.removeprefix("git::")) or \
                        ["https://" + value.split("?")[0].removeprefix("git::")]:
                    rows.add("repository", _clean_url(url) or url, rel, n,
                             "terraform")
            elif value.count("/") >= 3 and "." in value.split("/")[0]:
                rows.add("module source", "https://" + value.split("/")[0], rel, n,
                         "terraform", value.split("/")[0])
        return


def scan(root: Path) -> list:
    """Every source this checkout names, one row per thing per file."""
    root = Path(root)
    rows = _Rows()
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            seen += 1
            if seen > MAX_FILES * 10:
                return rows.rows
            path = Path(dirpath) / filename
            if path.is_symlink():
                continue
            try:
                _scan_file(root, path, rows)
            except Exception:  # one odd file never stops the rest
                continue
    return rows.rows


def match_estate(rows: list, estate: dict) -> list:
    """Mark rows that point at a repository this installation also scans.

    estate is {"org/repo" lowercased: "Org/Repo" as stored}.  Matched on the
    path alone, because the same repository is reached by https, ssh and
    shorthand, and a self hosted git under another name is still the same
    organization's code.
    """
    for row in rows:
        row["in_estate"] = ""
        if row["kind"] not in ("repository", "ci template", "module source"):
            continue
        value = row["value"]
        path = (value.split("://", 1)[1].split("/", 1)[1]
                if "://" in value and "/" in value.split("://", 1)[1] else "")
        path = path.removesuffix(".git").strip("/").lower()
        bits = path.split("/")
        for size in range(len(bits), 1, -1):
            hit = estate.get("/".join(bits[:size]))
            if hit:
                row["in_estate"] = hit
                break
    return rows


def summarize(rows: list) -> dict:
    """Hosts with what they are used for, and repositories pulled in."""
    hosts = {}
    repos = {}
    for row in rows:
        entry = hosts.setdefault(row["host"], {"host": row["host"],
                                               "public": row["public"],
                                               "kinds": set(), "files": set(),
                                               "count": 0})
        entry["kinds"].add(row["kind"])
        entry["files"].add(row["file"])
        entry["count"] += 1
        if row["kind"] in ("repository", "ci template", "module source"):
            key = repo_path(row["value"]) or row["value"]
            r = repos.setdefault(key, {"repository": key, "host": row["host"],
                                       "kind": row["kind"],
                                       "in_estate": row.get("in_estate", ""),
                                       "files": set()})
            r["files"].add(f"{row['file']}:{row['line']}")
    out_hosts = sorted(hosts.values(), key=lambda h: (h["public"], h["host"]))
    for h in out_hosts:
        h["kinds"] = sorted(h["kinds"])
        h["files"] = sorted(h["files"])[:20]
    out_repos = sorted(repos.values(),
                       key=lambda r: (not r["in_estate"], r["repository"]))
    for r in out_repos:
        r["files"] = sorted(r["files"])[:20]
    return {"hosts": out_hosts, "repositories": out_repos,
            "private_hosts": sum(1 for h in out_hosts if not h["public"]),
            "shared": sum(1 for r in out_repos if r["in_estate"])}
