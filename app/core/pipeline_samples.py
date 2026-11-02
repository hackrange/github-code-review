"""The pipeline sample kit, as one zip.

The files live in samples/pipeline.  Each download gets this server's address
written into .env.example, so the scripts work without editing, and a
SHA256SUMS file listing every other file.

The zip is built the same way every time for the same address and files:
fixed timestamps, fixed order.  The page can then show its checksum, and
somebody can check the file they downloaded is the one the page described.

Nothing that looks like a credential may leave in it.  The kit only ever holds
placeholders, and a token or a private key appearing in it would be a mistake
somebody made while testing, so the build refuses rather than ships it.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "samples" / "pipeline"
FOLDER = "gcr-pipeline-samples"
FILENAME = "gcr-pipeline-samples.zip"

# What goes in, by pattern.  A list rather than "everything in the folder",
# so a stray .env or a test token dropped in it can never be picked up.
INCLUDE = ("README.md", ".env.example", ".gitignore", "python/*.py", "bash/*.sh",
           "github-actions/*.yml", "docs/*.docx", "docs/*.pdf")
EXECUTABLE = ("bash/*.sh", "python/*.py")

# Shapes that must never be in the kit: this product's tokens, GitHub tokens,
# AWS keys and private keys.
FORBIDDEN = re.compile(
    rb"gcr_[A-Za-z0-9_-]{40,}"
    rb"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}"
    rb"|AKIA[0-9A-Z]{16}"
    rb"|-----BEGIN [A-Z ]*PRIVATE KEY-----")

# A fixed date for every entry, so the same input gives the same bytes.
STAMP = (2026, 1, 1, 0, 0, 0)

_cache = {}


class UnsafeKit(RuntimeError):
    """A file in the kit looks like it holds a real credential."""


def files() -> list:
    """-> [(path inside the kit, Path on disk)], sorted."""
    found = {}
    for pattern in INCLUDE:
        for path in KIT.glob(pattern):
            if path.is_file() and not path.is_symlink():
                found[path.relative_to(KIT).as_posix()] = path
    return sorted(found.items())


def available() -> bool:
    return bool(files())


def _with_address(text: bytes, api_url: str) -> bytes:
    """.env.example with this server's address in place of the placeholder."""
    line = f"GCR_URL={api_url}".encode()
    return re.sub(rb"(?m)^GCR_URL=.*$", line, text, count=1)


def build(api_url: str) -> tuple:
    """-> (zip bytes, sha256 hex of the zip, [(name, bytes)])."""
    listing = files()
    key = (api_url, tuple((name, p.stat().st_mtime_ns, p.stat().st_size)
                          for name, p in listing))
    if key in _cache:
        return _cache[key]

    contents = []
    for name, path in listing:
        data = path.read_bytes()
        if name == ".env.example":
            data = _with_address(data, api_url)
        if FORBIDDEN.search(data):
            raise UnsafeKit(f"{name} looks like it holds a real credential.  "
                            "The kit was not built.")
        contents.append((name, data))

    sums = "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in contents)
    contents.append(("SHA256SUMS", sums.encode()))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in contents:
            info = zipfile.ZipInfo(f"{FOLDER}/{name}", date_time=STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            runnable = any(Path(name).match(p) for p in EXECUTABLE)
            info.external_attr = ((0o755 if runnable else 0o644) | 0o100000) << 16
            bundle.writestr(info, data)
    body = buffer.getvalue()
    result = (body, hashlib.sha256(body).hexdigest(),
              [(n, len(d)) for n, d in contents])
    _cache.clear()
    _cache[key] = result
    return result
