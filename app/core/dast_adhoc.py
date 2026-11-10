"""An ad-hoc code source for the whitebox read.

When the code behind a site is not one of the scanned repositories, a person can
point the scan at the code directly: a public git URL to clone, or an uploaded
zip or tar.gz.  The routes and sinks read from it then guide the dynamic scan
the same way a mapped repository's would.

Both are read only and handled with care.  The clone is refused unless it is a
plain https URL to a public host, so it cannot be turned into a request against
the network the scanner sits in, and it never prompts for or stores a
credential.  The archive is unpacked with hard limits on size and count, and
every entry is checked so nothing can be written outside its own folder.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

MAX_ARCHIVE_BYTES = 200 * 1024 * 1024      # the stored upload
MAX_UNCOMPRESSED = 1024 * 1024 * 1024      # what it unpacks to
MAX_ENTRIES = 50000
CLONE_TIMEOUT = 180
_EXT = {"zip": ".zip", "tgz": ".tar.gz"}


def _adhoc_dir() -> Path:
    from app.core.external import data_dir

    d = data_dir() / "adhoc"
    d.mkdir(parents=True, exist_ok=True)
    return d


def archive_path(asset_id, kind: str) -> Path:
    return _adhoc_dir() / f"{int(asset_id)}{_EXT.get(kind, '.bin')}"


def clear_archive(asset_id) -> None:
    for ext in _EXT.values():
        (_adhoc_dir() / f"{int(asset_id)}{ext}").unlink(missing_ok=True)


def kind_of(filename: str) -> str:
    n = (filename or "").lower()
    if n.endswith(".zip"):
        return "zip"
    if n.endswith(".tar.gz") or n.endswith(".tgz"):
        return "tgz"
    return ""


async def save_upload(asset_id, upload) -> str:
    """Store an uploaded zip or tar.gz for a site.  -> its kind, or raises
    ValueError with a sentence to show.  Streamed, with a size cap, so a huge
    upload cannot fill the disk."""
    kind = kind_of(getattr(upload, "filename", ""))
    if not kind:
        raise ValueError("The code archive has to be a .zip or a .tar.gz file.")
    clear_archive(asset_id)
    dest = archive_path(asset_id, kind)
    size = 0
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise ValueError("The code archive is too large (over 200 MB).")
                out.write(chunk)
    except ValueError:
        dest.unlink(missing_ok=True)
        raise
    if size == 0:
        dest.unlink(missing_ok=True)
        raise ValueError("The code archive was empty.")
    return kind


def validate_git_url(url: str) -> str:
    """-> a clean https git URL, or raises ValueError.  Refuses anything that is
    not https to a public host, and any URL carrying a credential."""
    from urllib.parse import urlparse

    from app.core import external_probe

    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("The git URL has to be an https address with no user name "
                         "or password in it.  For private code, upload an archive.")
    if not external_probe._host_is_public(parsed.hostname):
        raise ValueError("The git URL has to be a public host, not a private "
                         "address.  For internal code, upload an archive.")
    return url


def describe(asset) -> dict:
    """What the page may show about the ad-hoc source.  {} when there is none."""
    git = getattr(asset, "adhoc_git_url", "") or ""
    kind = getattr(asset, "adhoc_archive", "") or ""
    if not git and not kind:
        return {}
    return {"git_url": git, "archive_kind": kind,
            "label": git or (f"uploaded {kind} archive" if kind else "")}


def _safe_clone(url: str, dest: Path) -> str:
    """Shallow clone url into dest.  -> "" on success, else a short reason."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/true",
               GCM_INTERACTIVE="never")
    cmd = ["git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
           "-c", "core.askpass=/bin/true",
           # The address was checked as typed.  A redirect would take the clone
           # somewhere unchecked, an internal address included, so none is followed.
           "-c", "http.followRedirects=false", "clone", "--depth", "1",
           "--single-branch", "--no-tags", url, str(dest)]
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                           timeout=CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return "the clone took too long and was stopped."
    if r.returncode != 0:
        return f"git clone failed: {(r.stderr or '').strip().splitlines()[-1][:200] if r.stderr else 'unknown error'}"
    return ""


def _safe_zip(path: Path, dest: Path) -> str:
    dest_root = str(dest.resolve())
    total = 0
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            return "the archive has too many files in it."
        for info in infos:
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if target != dest and not str(target).startswith(dest_root + os.sep):
                return "the archive tries to write outside its own folder."
            total += info.file_size
            if total > MAX_UNCOMPRESSED:
                return "the archive is too large when it is unpacked."
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)
    return ""


def _safe_tar(path: Path, dest: Path) -> str:
    with tarfile.open(path, "r:gz") as t:
        members = t.getmembers()
        if len(members) > MAX_ENTRIES:
            return "the archive has too many files in it."
        if sum(m.size for m in members if m.isreg()) > MAX_UNCOMPRESSED:
            return "the archive is too large when it is unpacked."
        # The data filter (Python 3.12+) blocks absolute paths, traversal and
        # links that point outside the destination.
        t.extractall(dest, filter="data")
    return ""


@contextlib.contextmanager
def checkout(adhoc: dict):
    """Materialise the ad-hoc source into a temporary folder, cleaned up on exit.

    adhoc is {git, archive, asset_id}.  Yields (root, why): root is the folder
    to read, or None with a short reason when there is nothing set or it failed.
    """
    from app.core import recheck

    git = (adhoc.get("git") or "").strip()
    kind = (adhoc.get("archive") or "").strip()
    asset_id = adhoc.get("asset_id")
    if not git and not kind:
        yield None, ""
        return
    base = recheck.memory_dir() or None
    tmp = tempfile.mkdtemp(prefix="gcr-adhoc-", dir=base)
    try:
        dest = Path(tmp) / "src"
        if git:
            try:
                url = validate_git_url(git)
            except ValueError as exc:
                yield None, str(exc)
                return
            why = _safe_clone(url, dest)
        else:
            dest.mkdir(parents=True, exist_ok=True)
            archive = archive_path(asset_id, kind)
            if not archive.exists():
                yield None, "the uploaded archive is missing."
                return
            why = _safe_zip(archive, dest) if kind == "zip" else _safe_tar(archive, dest)
        if why:
            yield None, why
            return
        yield str(dest), ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
