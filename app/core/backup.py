"""Backup and restore, as one encrypted file.

What this is for: moving an installation to another machine, or getting it back
after losing one.  Everything that cannot be worked out again goes in.  The
findings can always be found again by scanning; the decisions people made about
them cannot, and those are the point.

Three things shape the format.

It has to restore onto a machine that shares nothing with this one, so the
export is logical rather than a database dump.  Rows go out as JSON, which
loads back into MariaDB or SQLite, any version, either direction.

It carries credentials, so it is encrypted with a password somebody types
rather than with anything stored here.  scrypt turns the password into a key
and AES-256-GCM does the rest, which also means a file somebody tampered with
fails to open rather than restoring quietly wrong.

The installation key never travels.  Secrets are decrypted on the way out and
encrypted again on the way in, with the key belonging to whichever machine is
restoring.  So a backup opens on a machine that has never seen this one's key,
and a stolen backup is worth nothing without the password.

Sessions are left out.  They are short lived, and restoring somebody's signed
in browser onto another machine is not a feature.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import zipfile
from datetime import date, datetime
from decimal import Decimal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

log = logging.getLogger("gcr.backup")

FORMAT = "gcr-backup-1"

# Left out on purpose.  Sessions are short lived and restoring one is not a
# feature anybody asked for.  Utilization is how busy this machine was, which
# means nothing on the machine a backup is restored to.  The finding summaries
# are worked out from the findings, and rebuilt after a restore on their own.
SKIP_TABLES = {"sessions", "utilization_minute", "utilization_2min",
               "utilization_10min", "finding_counts", "finding_groups",
               "finding_branches"}

# Columns holding something encrypted with this installation's key.  They come
# out in the clear inside the encrypted archive and go back in encrypted with
# the key of whatever machine is restoring.
SECRET_COLUMNS = {
    "connections": ("token", "app_key"),
}

# scrypt, sized so a guess costs real time and memory on a machine built for
# guessing, while one open on a laptop takes under a second.
KDF_N = 1 << 15
KDF_R = 8
KDF_P = 1
KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12

MIN_PASSWORD = 12

# Enough for a large estate, small enough that nobody can hand the importer a
# file that eats the machine.
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


def _derive(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_BYTES, n=KDF_N, r=KDF_R, p=KDF_P)
    return kdf.derive(password.encode("utf-8"))


def _plain(value):
    """A row value as something json can write."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if hasattr(value, "value"):          # an Enum column
        return value.value
    return value


def _coerce(column, value):
    """A json value back into what the column expects.

    Everything goes out as text so the file reads the same on any machine, and
    a database will not take a date back as a string.  This is where it turns
    into the right kind of thing again, decided by the column rather than by
    guessing at the value.
    """
    import sqlalchemy as sa

    if value is None:
        return None
    kind = column.type

    if isinstance(kind, sa.Enum) and getattr(kind, "enum_class", None):
        try:
            return kind.enum_class(value)
        except ValueError:
            return kind.enum_class[str(value)]
    if isinstance(kind, sa.DateTime):
        if isinstance(value, datetime):
            return value
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    if isinstance(kind, sa.Date):
        return value if isinstance(value, date) else date.fromisoformat(str(value)[:10])
    if isinstance(kind, sa.Boolean):
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)
    return value


def _tables():
    from app.core.models import Base
    return [t for t in Base.metadata.sorted_tables if t.name not in SKIP_TABLES]


def export_rows(session) -> dict:
    """Every table worth keeping, as plain rows.

    Secrets are decrypted here.  They are only ever written inside the
    encrypted part of the archive.
    """
    from app.core import settings_store as store

    data, counts = {}, {}
    for table in _tables():
        rows = []
        for row in session.execute(table.select()).mappings():
            item = {k: _plain(v) for k, v in dict(row).items()}

            for column in SECRET_COLUMNS.get(table.name, ()):
                if item.get(column):
                    item[column] = store._decrypt(item[column])

            # The settings table says which of its own rows are secret.
            if table.name == "settings" and item.get("is_secret"):
                item["value"] = store._decrypt(item.get("value") or "")

            rows.append(item)
        data[table.name] = rows
        counts[table.name] = len(rows)
    return {"tables": data, "counts": counts}


def create(session, password: str, actor: str = "") -> bytes:
    """-> the archive, as bytes.  Raises ValueError on a password that will not do."""
    from app.config import VERSION

    if len(password or "") < MIN_PASSWORD:
        raise ValueError(
            f"Use a password of at least {MIN_PASSWORD} characters. "
            "This file holds every credential the installation has.")

    payload = export_rows(session)
    payload["format"] = FORMAT
    payload["app_version"] = VERSION
    payload["created_at"] = datetime.utcnow().isoformat() + "Z"
    payload["created_by"] = actor or ""

    raw = gzip.compress(json.dumps(payload, default=str).encode("utf-8"), 6)

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive(password, salt)

    manifest = {
        "format": FORMAT,
        "app_version": VERSION,
        "created_at": payload["created_at"],
        "counts": payload["counts"],
        "kdf": {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P,
                "salt": salt.hex(), "length": KEY_BYTES},
        "cipher": {"name": "AES-256-GCM", "nonce": nonce.hex()},
        "plaintext_sha256": hashlib.sha256(raw).hexdigest(),
    }
    # The manifest is authenticated as well as the data, so somebody editing
    # the counts or the version in it breaks the open rather than lying.
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    blob = AESGCM(key).encrypt(nonce, raw, manifest_bytes)

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest_bytes)
        archive.writestr("data.enc", blob)
        archive.writestr("RESTORE.txt", RESTORE_NOTE)
    log.info("backup written: %s rows across %s tables",
             sum(payload["counts"].values()), len(payload["counts"]))
    return out.getvalue()


def read(blob: bytes, password: str) -> dict:
    """Open an archive.  Raises ValueError if the password is wrong or it was edited."""
    if len(blob) > MAX_ARCHIVE_BYTES:
        raise ValueError("That file is too large to be one of ours.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
        manifest_bytes = archive.read("manifest.json")
        data = archive.read("data.enc")
    except (zipfile.BadZipFile, KeyError):
        raise ValueError("That is not a backup file.")

    try:
        manifest = json.loads(manifest_bytes)
    except ValueError:
        raise ValueError("That backup's manifest is unreadable.")
    if manifest.get("format") != FORMAT:
        raise ValueError(f"That backup is in {manifest.get('format')!r}, "
                         f"and this reads {FORMAT!r}.")

    kdf = manifest.get("kdf") or {}
    try:
        key = Scrypt(salt=bytes.fromhex(kdf["salt"]), length=kdf["length"],
                     n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(
                         (password or "").encode("utf-8"))
        nonce = bytes.fromhex(manifest["cipher"]["nonce"])
    except (KeyError, ValueError):
        raise ValueError("That backup's manifest is missing something.")

    try:
        raw = AESGCM(key).decrypt(nonce, data, manifest_bytes)
    except Exception:
        # One message for both, because telling somebody which of the two it
        # was helps a guesser more than it helps them.
        raise ValueError("Wrong password, or the file has been altered.")

    if hashlib.sha256(raw).hexdigest() != manifest.get("plaintext_sha256"):
        raise ValueError("That backup did not survive the trip intact.")

    return {"manifest": manifest, "payload": json.loads(gzip.decompress(raw))}


def restore(session, blob: bytes, password: str) -> dict:
    """Replace what is here with what is in the archive.

    Replace, not merge.  A half restored installation where some decisions are
    the old machine's and some are this one's is worse than either.
    """
    from app.core import settings_store as store

    opened = read(blob, password)
    payload = opened["payload"]
    tables = payload.get("tables") or {}

    written = {}
    ordered = _tables()

    # Children first on the way out, parents first on the way in.
    for table in reversed(ordered):
        session.execute(table.delete())

    for table in ordered:
        rows = tables.get(table.name)
        if not rows:
            continue
        prepared = []
        for row in rows:
            item = {c.name: _coerce(c, row.get(c.name))
                    for c in table.columns if c.name in row}

            for column in SECRET_COLUMNS.get(table.name, ()):
                if item.get(column):
                    item[column] = store._encrypt(item[column])

            if table.name == "settings" and item.get("is_secret"):
                item["value"] = store._encrypt(item.get("value") or "")

            prepared.append(item)
        if prepared:
            session.execute(table.insert(), prepared)
        written[table.name] = len(prepared)

    session.flush()
    log.info("restored %s rows across %s tables",
             sum(written.values()), len(written))
    return {"manifest": opened["manifest"], "written": written}


RESTORE_NOTE = """Git Code Review backup
=======================

This archive holds one installation: its findings, the decisions people made
about them, the accounts, the settings and the credentials.

data.enc is encrypted with the password chosen when it was made.  Without that
password nothing here can be read, and there is no way to recover it.

To restore onto a fresh machine:

  1. Install Git Code Review and sign in as the first administrator.
  2. Sign in, then open Backup and restore under Administration.
  3. Upload this file and give the password.

Restoring replaces everything on the destination, including the account you
signed in with.  Sign in again afterward with an account from the backup.

manifest.json is not encrypted.  It says when the archive was made, which
version made it and how many rows of each kind it holds.  It carries nothing
secret, and it is signed along with the data, so an edited manifest stops the
archive opening rather than making it lie.
"""
