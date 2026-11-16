"""Pull a published image from its registry and lay out what ships, in memory.

The base image a Dockerfile names is read elsewhere, for vulnerable packages.
This is the image the repository itself builds and publishes: the artifact a
server actually runs.  It differs from the checkout in ways nothing that reads
the checkout can see.  The build copies files from outside the repository, a
layer adds a sudoers rule, a hidden backup rides along in a directory nobody
looks at, a credential is written in one layer and deleted in the next and is
still in the first.

Nothing is built, run or extracted with tar.  Every layer is read as a stream
and only regular files are written, each under a path this script built
itself, so a crafted layer cannot write outside the output directory, plant a
symlink or a device, or fill the disk past the caps.  The caller points the
output at memory (the scan root is on /dev/shm) and deletes it afterwards.

Registries are reached over HTTPS only, and only at public addresses unless
the caller allows private ones.  Every connection, redirects included, goes to
the address that was checked, so a name that answers differently the second
time cannot steer the request inside the network.  An image reference comes
from a file in a repository, which is to say from whoever can push to it.

Usage: image_fetch.py <ref> <outdir> [--allow-private] [--max-mb N]

Writes into <outdir>:
  scan/fs/<path>         files of the final image the checks read
  scan/deleted/<n>/<path> files a later layer deleted or replaced, still in layer n
  scan/env               the image configuration's environment, one per line
  meta.json              the reference, digest, run configuration and, for
                         every file in the final image, its owner and mode

Exit 0 on success, 2 when the image could not be read (the reason on stderr).
"""

from __future__ import annotations

import gzip
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import tarfile
import time
import urllib.parse

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")

TIMEOUT = 60
MAX_REDIRECTS = 5
MAX_JSON = 8 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024          # a text file bigger than this is not config
MAX_ARCHIVE = 20 * 1024 * 1024      # archives are kept to list what is inside
MAX_META_FILES = 400_000
DEADLINE_SEC = 1500

# Where an operating system and its packages live.  Their files are the
# distribution's, are read for vulnerable versions by the package scanners, and
# are full of test keys and sample configs that would read as credentials.
SKIP_PREFIXES = (
    "usr/lib/", "usr/lib64/", "usr/lib32/", "usr/libexec/", "usr/share/",
    "usr/include/", "usr/bin/", "usr/sbin/", "usr/games/", "usr/src/",
    "usr/local/include/", "usr/local/share/", "usr/local/go/",
    "lib/", "lib64/", "lib32/", "libx32/", "bin/", "sbin/", "boot/", "dev/",
    "proc/", "sys/", "run/", "var/lib/dpkg/", "var/lib/apt/", "var/lib/rpm/",
    "var/lib/yum/", "var/lib/dnf/", "var/lib/apk/", "var/cache/", "var/log/",
    "etc/ssl/", "etc/pki/", "etc/ca-certificates/", "etc/ssh/",
    "etc/apt/", "etc/yum.repos.d/", "etc/alternatives/", "etc/fonts/",
    "opt/conda/pkgs/", "root/.cache/", "home/linuxbrew/",
)
# Directory names that hold somebody else's code wherever they appear.
SKIP_DIRS = {"node_modules", "site-packages", "dist-packages", "__pycache__", "vendor",
             ".npm", ".git", "bower_components", ".gradle", ".m2"}
# Package directories under /usr/local, which hold a language's own library.
SKIP_LOCAL = re.compile(r"^(usr/local/lib/(python|node|ruby|perl|php/extensions)|home/[^/]+/\.cache/)")
ARCHIVE = re.compile(r"\.(zip|tar|tgz|tar\.gz|tar\.bz2|tar\.xz|7z|rar)$", re.I)

# The records a vulnerability scanner reads to know what is installed: the
# distribution's own package database and release file, and the metadata a
# language's package manager leaves beside each installed package.  The checks
# above skip all of these on purpose, so they are kept in a tree of their own,
# pkgs/, outside scan/, where no credential engine and no structural check
# looks.  Only the final image counts here: a record a later layer replaced or
# deleted leaves this tree rather than being kept aside.
PACKAGE_RECORD = re.compile(
    r"^(?:"
    r"etc/(?:os-release|lsb-release|alpine-release|debian_version|redhat-release|"
    r"centos-release|system-release|rocky-release|almalinux-release)"
    r"|usr/lib/os-release"
    r"|var/lib/dpkg/status|var/lib/dpkg/status\.d/[^/]+"
    r"|lib/apk/db/installed"
    r"|(?:var/lib/rpm|usr/lib/sysimage/rpm)/(?:Packages|Packages\.db|rpmdb\.sqlite)"
    r")$"
    r"|(?:^|/)(?:site|dist)-packages/[^/]+\.dist-info/METADATA$"
    r"|(?:^|/)(?:site|dist)-packages/[^/]+\.egg-info/PKG-INFO$"
    r"|(?:^|/)node_modules/(?:@[^/]+/)?[^/]+/package\.json$"
    r"|(?:^|/)vendor/composer/installed\.json$"
    r"|(?:^|/)specifications/[^/]+\.gemspec$"
    r"|\.deps\.json$"
    r"|\.(?:jar|war|ear)$")
MAX_PACKAGE_RECORD = 64 * 1024 * 1024   # an rpm database or a large jar


class FetchError(Exception):
    pass


# --- the network ----------------------------------------------------------

def _blocked(ip: ipaddress._BaseAddress) -> bool:
    """True for anything that is not an ordinary public address.

    is_global alone lets through two ranges that are internal in practice:
    the carrier NAT block, which cloud providers hand out inside a network,
    and the NAT64 prefix, which reaches IPv4 addresses behind it.  Multicast
    is global by that test and is never a registry.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return ip in ipaddress.ip_network("100.64.0.0/10")
    return ip in ipaddress.ip_network("64:ff9b::/96") or \
        ip in ipaddress.ip_network("64:ff9b:1::/48")


def _resolve(host: str, port: int, allow_private: bool) -> str:
    """One address for host, checked.  Fails closed."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchError(f"cannot resolve {host}: {exc}") from None
    addrs = []
    for info in infos:
        try:
            addrs.append(ipaddress.ip_address(info[4][0].split("%", 1)[0]))
        except ValueError:
            continue
    if not addrs:
        raise FetchError(f"{host} has no address")
    if not allow_private:
        # Every answer, not just the one used: a name that returns a public
        # and a private address is a name somebody is playing with.
        bad = [str(a) for a in addrs if _blocked(a)]
        if bad:
            raise FetchError(f"{host} resolves to a non-public address ({bad[0]}); "
                             "private registries are not allowed by the settings")
    return str(addrs[0])


class _PinnedHTTPS(http.client.HTTPSConnection):
    """An HTTPS connection to one address, with the name kept for TLS."""

    def __init__(self, host, port, address, context):
        super().__init__(host, port, timeout=TIMEOUT, context=context)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class Client:
    def __init__(self, allow_private: bool):
        self.allow_private = allow_private
        self.context = ssl.create_default_context()
        self.tokens = {}
        self.deadline = time.monotonic() + DEADLINE_SEC

    def _open(self, url: str, headers: dict):
        """GET url, following redirects one checked hop at a time.

        Returns the live response; the caller reads and closes it.  The
        registry's Authorization never follows a redirect to another host:
        blob storage is handed a signed URL and needs nothing else.
        """
        origin = urllib.parse.urlsplit(url).hostname
        for _ in range(MAX_REDIRECTS + 1):
            if time.monotonic() > self.deadline:
                raise FetchError("took too long")
            parts = urllib.parse.urlsplit(url)
            if parts.scheme != "https" or not parts.hostname:
                raise FetchError(f"refusing a non-HTTPS address: {parts.scheme}://{parts.hostname}")
            if parts.username or parts.password:
                raise FetchError("refusing an address with credentials in it")
            port = parts.port or 443
            address = _resolve(parts.hostname, port, self.allow_private)
            conn = _PinnedHTTPS(parts.hostname, port, address, self.context)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            send = dict(headers)
            if parts.hostname != origin:
                send.pop("Authorization", None)
            conn.request("GET", path, headers=send)
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                where = resp.getheader("Location") or ""
                resp.read(); conn.close()
                if not where:
                    raise FetchError("a redirect with no location")
                url = urllib.parse.urljoin(url, where)
                continue
            return resp, conn
        raise FetchError("too many redirects")

    def _token(self, challenge: str) -> str:
        """A bearer token for an anonymous pull, from the challenge."""
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields.pop("realm", "")
        if not realm:
            raise FetchError("the registry asked for credentials it did not describe")
        key = realm + "|" + fields.get("scope", "")
        if key in self.tokens:
            return self.tokens[key]
        query = urllib.parse.urlencode({k: v for k, v in fields.items() if k in ("service", "scope")})
        resp, conn = self._open(realm + ("&" if "?" in realm else "?") + query, {})
        try:
            if resp.status != 200:
                raise FetchError(f"the registry refused an anonymous pull ({resp.status}); "
                                 "a private image needs credentials this scanner does not have")
            body = json.loads(resp.read(MAX_JSON) or b"{}")
        finally:
            conn.close()
        token = body.get("token") or body.get("access_token") or ""
        if not token:
            raise FetchError("the registry gave no token")
        self.tokens[key] = token
        return token

    def get(self, url: str, accept: str = ""):
        """GET a registry URL, answering a bearer challenge once."""
        headers = {"User-Agent": "gcr-image-reader/1"}
        if accept:
            headers["Accept"] = accept
        resp, conn = self._open(url, headers)
        if resp.status == 401:
            challenge = resp.getheader("WWW-Authenticate") or ""
            resp.read(); conn.close()
            if not challenge.lower().startswith("bearer"):
                raise FetchError("the registry wants credentials for this image")
            headers["Authorization"] = "Bearer " + self._token(challenge)
            resp, conn = self._open(url, headers)
        if resp.status != 200:
            resp.read(); conn.close()
            raise FetchError(f"{urllib.parse.urlsplit(url).path} answered {resp.status}")
        return resp, conn

    def get_json(self, url: str, accept: str = ""):
        resp, conn = self.get(url, accept)
        try:
            data = resp.read(MAX_JSON + 1)
            if len(data) > MAX_JSON:
                raise FetchError("a manifest larger than any real one")
            try:
                value = json.loads(data)
            except ValueError:
                raise FetchError(f"{urllib.parse.urlsplit(url).hostname} did not answer "
                                 "as an image registry") from None
            return value, (resp.getheader("Content-Type") or "").split(";")[0].strip(), \
                resp.getheader("Docker-Content-Digest") or ""
        finally:
            conn.close()


# --- the reference --------------------------------------------------------

_NAME = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$")


def parse_ref(ref: str):
    """-> (registry host[:port], repository, tag or digest)."""
    ref = ref.strip()
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise FetchError("not a valid digest")
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "registry-1.docker.io", ref
    # docker.io is how people write Docker Hub, and docker itself maps it to
    # the registry; the host of that name serves the website, not the API.
    if registry in ("docker.io", "index.docker.io"):
        registry = "registry-1.docker.io"
    tag = "latest"
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path, tag = path.rsplit(":", 1)
    if registry == "registry-1.docker.io" and "/" not in path:
        path = "library/" + path
    if not _NAME.match(path) or not re.fullmatch(r"[\w][\w.-]{0,127}", tag):
        raise FetchError("not an image reference")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(:\d{1,5})?", registry):
        raise FetchError("not a registry host")
    return registry, path, digest or tag


# --- the layers -----------------------------------------------------------

def _clean(name: str) -> str:
    """A layer path as a relative path with no way out, or "" to skip it."""
    name = name.replace("\\", "/")
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return ""
        parts.append(part)
    return "/".join(parts)


def wanted(path: str) -> bool:
    """Whether the checks read this file's content."""
    if any(path.startswith(p) for p in SKIP_PREFIXES) or SKIP_LOCAL.match(path):
        return False
    return not any(part in SKIP_DIRS for part in path.split("/")[:-1])


class Layout:
    """The final image, built up one layer at a time."""

    def __init__(self, outdir: str, max_bytes: int):
        self.out = outdir
        self.fs = os.path.join(outdir, "scan", "fs")
        self.pkgs = os.path.join(outdir, "pkgs")
        self.pkg_saved = set()    # package records in pkgs/, final image only
        self.pkg_kept = 0
        self.max_bytes = max_bytes
        self.kept = 0
        self.meta = {}            # path -> [uid, gid, mode, size, layer, type]
        self.saved = {}           # path -> layer it was saved from
        self.truncated = False

    def _target(self, root: str, path: str) -> str:
        full = os.path.normpath(os.path.join(root, path))
        if not full.startswith(os.path.normpath(root) + os.sep):
            raise FetchError("a path escaped the output")
        return full

    def _retire(self, path: str, layer: int):
        """A later layer removed or replaced path: keep the old copy aside."""
        if path in self.pkg_saved:
            # What a vulnerability scan reads is the final image, so a removed
            # package record goes rather than being kept.
            try:
                os.remove(self._target(self.pkgs, path))
            except OSError:
                pass
            self.pkg_saved.discard(path)
        if path in self.saved:
            src = self._target(self.fs, path)
            dst = self._target(os.path.join(self.out, "scan", "deleted", str(self.saved[path])), path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                os.replace(src, dst)
            except OSError:
                pass
            del self.saved[path]
        self.meta.pop(path, None)

    def remove(self, path: str, layer: int):
        """A whiteout: path and everything under it are gone."""
        prefix = path + "/"
        for p in [p for p in set(self.meta) | self.pkg_saved
                  if p == path or p.startswith(prefix)]:
            self._retire(p, layer)

    def opaque(self, directory: str, layer: int):
        prefix = directory + "/" if directory else ""
        for p in [p for p in set(self.meta) | self.pkg_saved if p.startswith(prefix)]:
            self._retire(p, layer)

    def add(self, member: tarfile.TarInfo, path: str, stream, layer: int):
        if path in self.meta:
            self._retire(path, layer)
        kind = "f" if member.isreg() else "l" if member.issym() else \
            "d" if member.isdir() else "o"
        if len(self.meta) < MAX_META_FILES:
            self.meta[path] = [member.uid, member.gid, member.mode, member.size, layer, kind]
        else:
            self.truncated = True
        if kind != "f":
            return
        # A layer is a stream, so each entry can be read once: one read
        # serves both the package record and the checks.
        data = None
        if PACKAGE_RECORD.search(path):
            data = self._keep_package_record(member, path, stream)
        if not wanted(path):
            return
        limit = MAX_ARCHIVE if ARCHIVE.search(path) else MAX_FILE
        if member.size > limit or self.kept + member.size > self.max_bytes:
            if self.kept + member.size > self.max_bytes:
                self.truncated = True
            return
        if data is None:
            handle = stream.extractfile(member)
            if handle is None:
                return
            data = handle.read(limit + 1)
        if len(data) > limit:
            return
        # Binary files are not config and not source; archives are listed.
        if not ARCHIVE.search(path) and b"\x00" in data[:8192]:
            return
        target = self._target(self.fs, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as out:
            out.write(data)
        self.kept += len(data)
        self.saved[path] = layer


    def _keep_package_record(self, member, path: str, stream):
        """A package record into pkgs/, within its own share of the budget.
        -> the bytes read, for the checks to reuse, or None."""
        if member.size > MAX_PACKAGE_RECORD or self.pkg_kept + member.size > self.max_bytes:
            # A vulnerability scan of part of the installed packages would
            # report the rest as absent, which reads as clean.
            self.truncated = True
            return None
        handle = stream.extractfile(member)
        if handle is None:
            return None
        data = handle.read(MAX_PACKAGE_RECORD + 1)
        if len(data) > MAX_PACKAGE_RECORD:
            self.truncated = True
            return None
        target = self._target(self.pkgs, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as out:
            out.write(data)
        self.pkg_kept += len(data)
        self.pkg_saved.add(path)
        return data


def _layer_stream(resp, media_type: str):
    if "zstd" in media_type:
        try:
            from compression import zstd       # Python 3.14
        except ImportError:
            raise FetchError("a zstd layer and no zstd reader") from None
        return zstd.ZstdFile(resp)
    if "gzip" in media_type or media_type.endswith(".tar.gzip") or \
            media_type == "application/vnd.docker.image.rootfs.diff.tar.gzip":
        return gzip.GzipFile(fileobj=resp)
    return resp


def read_layer(client: Client, base: str, layer: dict, index: int, layout: Layout):
    digest = layer.get("digest") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise FetchError("a layer with no valid digest")
    resp, conn = client.get(f"{base}/blobs/{digest}")
    try:
        stream = _layer_stream(resp, layer.get("mediaType") or "")
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            apply_layer(tar, index, layout)
    finally:
        conn.close()


def apply_layer(tar, index: int, layout: Layout):
    """One layer's entries onto the layout, whiteouts included."""
    for member in tar:
        path = _clean(member.name)
        if not path:
            continue
        head, _, name = path.rpartition("/")
        if name == ".wh..wh..opq":
            layout.opaque(head, index)
            continue
        if name.startswith(".wh."):
            layout.remove((head + "/" if head else "") + name[4:], index)
            continue
        layout.add(member, path, tar, index)


def pick_manifest(client: Client, base: str, ref: str):
    manifest, ctype, digest = client.get_json(f"{base}/manifests/{ref}", ACCEPT)
    if ctype in INDEX_TYPES or "manifests" in manifest:
        choices = [m for m in manifest.get("manifests") or []
                   if (m.get("platform") or {}).get("os", "linux") == "linux"
                   and (m.get("platform") or {}).get("architecture") not in ("unknown",)]
        pref = [m for m in choices if (m.get("platform") or {}).get("architecture") == "amd64"]
        chosen = (pref or choices or [None])[0]
        if not chosen:
            raise FetchError("no linux image in the index")
        manifest, ctype, _ = client.get_json(f"{base}/manifests/{chosen['digest']}", ACCEPT)
        digest = chosen["digest"]
    if not manifest.get("layers") and manifest.get("fsLayers"):
        raise FetchError("a schema 1 manifest, which this reader does not handle")
    return manifest, digest


def fetch(ref: str, outdir: str, allow_private: bool, max_bytes: int) -> dict:
    registry, repo, tag = parse_ref(ref)
    client = Client(allow_private)
    base = f"https://{registry}/v2/{repo}"
    manifest, digest = pick_manifest(client, base, tag)

    config = {}
    cfg_desc = manifest.get("config") or {}
    if re.fullmatch(r"sha256:[0-9a-f]{64}", cfg_desc.get("digest") or ""):
        config, _, _ = client.get_json(f"{base}/blobs/{cfg_desc['digest']}")
    run = (config.get("config") or {}) if isinstance(config, dict) else {}

    os.makedirs(os.path.join(outdir, "scan", "fs"), exist_ok=True)
    layout = Layout(outdir, max_bytes)
    for index, layer in enumerate(manifest.get("layers") or []):
        read_layer(client, base, layer, index, layout)

    env = [e for e in (run.get("Env") or []) if isinstance(e, str)]
    with open(os.path.join(outdir, "scan", "env"), "w", encoding="utf-8") as out:
        out.write("\n".join(env) + ("\n" if env else ""))
    meta = {
        "ref": ref, "digest": digest,
        "user": run.get("User") or "",
        "entrypoint": run.get("Entrypoint") or [],
        "cmd": run.get("Cmd") or [],
        "workdir": run.get("WorkingDir") or "",
        "env_names": [e.split("=", 1)[0] for e in env],
        "layers": len(manifest.get("layers") or []),
        "truncated": layout.truncated,
        "files": layout.meta,
    }
    with open(os.path.join(outdir, "meta.json"), "w", encoding="utf-8") as out:
        json.dump(meta, out)
    return meta


def main(argv) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = [a for a in argv[1:] if a.startswith("--")]
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    allow_private = "--allow-private" in flags
    max_mb = 512
    for flag in flags:
        if flag.startswith("--max-mb="):
            max_mb = max(16, min(4096, int(flag.split("=", 1)[1])))
    try:
        meta = fetch(args[0], args[1], allow_private, max_mb * 1024 * 1024)
    except (FetchError, OSError, tarfile.TarError, EOFError, ValueError,
            http.client.HTTPException, ssl.SSLError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"ref": meta["ref"], "digest": meta["digest"],
                      "layers": meta["layers"], "files": len(meta["files"]),
                      "truncated": meta["truncated"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
