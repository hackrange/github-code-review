"""Backups nobody has to remember to take.

Two kinds, both the same encrypted file the Backup and restore page makes, so
either one goes back through that page:

  nightly        taken once a night by the scheduler
  before-delete  taken just before a bulk delete of findings, which does not
                 undo any other way

The five newest of each kind are kept.  The two kinds are counted apart, so a
run of deletes cannot push the nightly copies out, and five quiet nights cannot
push out the copy taken before a delete.

The password comes from GCR_BACKUP_PASSWORD, which install.sh writes into .env.
It is never kept in the database, because a backup whose password went down
with the database could never be opened.  With no password set, nothing is
written and the reason is given; a backup under a made up password nobody
knows would be worse than none, because it looks like protection.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("gcr.autobackup")

KEEP = 5
KINDS = ("nightly", "before-delete")

# The only names this module writes, and so the only names it will hand back
# out.  Anything else in the folder is somebody else's and is left alone.
NAME = re.compile(r"^gcr-(nightly|before-delete)-(\d{8}-\d{6})\.zip$")

_lock = threading.Lock()


class NotConfigured(Exception):
    """No password, so no backup can be written."""


def folder() -> Path:
    """Where the files go.  A host folder in production, so they outlive the
    container and the database volume both."""
    raw = os.environ.get("GCR_BACKUP_DIR", "").strip()
    if raw:
        return Path(raw)
    from app.config import settings
    return settings.data_dir / "backups"


def _password() -> str:
    from app.core import backup
    value = os.environ.get("GCR_BACKUP_PASSWORD", "")
    if not value:
        raise NotConfigured(
            "No backup password is set.  Put GCR_BACKUP_PASSWORD in .env "
            "(install.sh writes one) and recreate the container.")
    if len(value) < backup.MIN_PASSWORD:
        raise NotConfigured(
            f"GCR_BACKUP_PASSWORD is shorter than {backup.MIN_PASSWORD} "
            "characters, so it is not used.")
    return value


def configured() -> bool:
    try:
        _password()
    except NotConfigured:
        return False
    return True


def listing() -> list[dict]:
    """The backups on disk, newest first."""
    where = folder()
    if not where.is_dir():
        return []
    found = []
    for entry in where.iterdir():
        match = NAME.match(entry.name)
        if not match or not entry.is_file():
            continue
        stat = entry.stat()
        found.append({
            "name": entry.name,
            "kind": match.group(1),
            "taken_at": datetime.strptime(match.group(2), "%Y%m%d-%H%M%S")
                                .replace(tzinfo=timezone.utc),
            "bytes": stat.st_size,
        })
    found.sort(key=lambda item: item["taken_at"], reverse=True)
    return found


def path_of(name: str) -> Path | None:
    """The file behind a name from the listing, or None.

    The name has to be one this module writes and has to be in the folder
    right now.  Nothing from a request is ever joined onto a path unchecked.
    """
    if not isinstance(name, str) or not NAME.match(name):
        return None
    for item in listing():
        if item["name"] == name:
            return folder() / item["name"]
    return None


def _prune(kind: str) -> int:
    mine = [item for item in listing() if item["kind"] == kind]
    removed = 0
    for item in mine[KEEP:]:
        try:
            (folder() / item["name"]).unlink()
            removed += 1
        except OSError:
            log.warning("could not remove old backup %s", item["name"], exc_info=True)
    return removed


def take(kind: str, actor: str = "system") -> dict:
    """Write one backup and trim that kind back to the newest five.

    Raises NotConfigured when there is no password, and lets anything else
    through, because a caller about to delete findings must know it failed.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown backup kind {kind!r}")
    password = _password()

    from app.core import backup
    from app.core.audit import record
    from app.core.db import session_scope

    with _lock:
        where = folder()
        where.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        name = f"gcr-{kind}-{stamp}.zip"
        final = where / name
        partial = where / f".{name}.partial"

        with session_scope() as db:
            blob = backup.create(db, password, actor=actor)

        # Written beside the real name and moved into place, so a half written
        # file never carries a name the listing would offer for a restore.
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(partial, final)
        except BaseException:
            try:
                partial.unlink()
            except OSError:
                pass
            raise

        removed = _prune(kind)
        with session_scope() as db:
            record(db, "backup.created", actor=actor or "system", target=name,
                   detail=f"{kind}, {len(blob)} bytes"
                          + (f", {removed} older removed" if removed else ""))

    log.info("%s backup written: %s (%d bytes)", kind, name, len(blob))
    return {"name": name, "bytes": len(blob), "removed": removed}


def nightly() -> None:
    """The scheduler's job.  Never raises: a failed night is logged and the
    next night tries again."""
    try:
        take("nightly", actor="system")
    except NotConfigured as exc:
        log.warning("nightly backup skipped: %s", exc)
    except Exception:  # noqa: BLE001 - logged, and tomorrow is another go
        log.exception("nightly backup failed")
