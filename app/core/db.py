"""The database, and the session helper everything else uses.

SQLite is the default.  One file in a volume, WAL on so the scanner can write
while somebody reads a page, and a compose down leaves it alone.  Point
GCR_DATABASE_URL at MariaDB instead when you want a server, and everything
here works the same way.

Schema changes are applied on boot.  create_all makes tables that are missing,
_add_missing_columns adds columns the models grew since the last release, and
_widen_columns gives more room to the ones that outgrew what they were first
declared as, so an upgrade is a pull and a restart.
"""

from __future__ import annotations

import contextlib
import logging
import re
import time
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.core.models import Base

log = logging.getLogger("gcr.db")

_engine = None
_Session = None


def engine():
    global _engine
    if _engine is not None:
        return _engine

    url = settings.database_url

    if settings.uses_sqlite:
        path = Path(settings.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(
            url,
            connect_args={"check_same_thread": False, "timeout": 30},
            future=True,
            pool_pre_ping=True,
        )

        @event.listens_for(_engine, "connect")
        def _pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            # WAL lets a reader and a writer work at the same time.
            cur.execute("PRAGMA journal_mode=WAL")
            # Foreign keys are off by default in SQLite, which is a trap.
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

        return _engine

    # MariaDB or MySQL.  Recycle connections well inside the server's own idle
    # timeout, otherwise the first request after a quiet night gets a closed
    # socket.
    _engine = create_engine(
        url,
        future=True,
        pool_pre_ping=True,
        pool_recycle=1800,
        pool_size=10,
        max_overflow=5,
    )
    return _engine


def session_factory():
    global _Session
    if _Session is None:
        _Session = sessionmaker(bind=engine(), expire_on_commit=False,
                                future=True)
    return _Session


@contextlib.contextmanager
def session_scope():
    """Open a session, commit if it worked, roll back if it did not."""
    session = session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def wait_for_database(attempts: int = 30, delay: float = 2.0) -> None:
    """Give the database server time to come up.

    Compose starts both containers at once and MariaDB takes a few seconds to
    be ready for connections.  Nothing to wait for with SQLite.
    """
    if settings.uses_sqlite:
        return

    from sqlalchemy import text

    last = None
    for attempt in range(1, attempts + 1):
        try:
            with engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            if attempt > 1:
                log.info("database answered after %d tries", attempt)
            return
        except OperationalError as exc:
            last = exc
            log.info("waiting for the database (%d/%d)", attempt, attempts)
            time.sleep(delay)
    raise RuntimeError(f"database never came up: {last}")


def init_db() -> None:
    """Make the schema if it is not there, then bring it up to date.

    Safe to call on every boot, and safe on an empty volume, which is the
    normal case the first time somebody starts the container.
    """
    wait_for_database()

    from sqlalchemy import inspect

    with engine().connect() as conn:
        existing = set(inspect(conn).get_table_names())
    fresh = not existing

    Base.metadata.create_all(engine())

    if fresh:
        log.info("made a new database")
    else:
        made = {t.name for t in Base.metadata.sorted_tables} - existing
        if made:
            log.info("added table(s): %s", ", ".join(sorted(made)))
        added = _add_missing_columns()
        if added:
            log.info("added %d new column(s) to the existing database", added)
        widened = _widen_columns()
        if widened:
            log.info("gave %d column(s) more room", widened)
        extended = _extend_enums()
        if extended:
            log.info("taught %d column(s) a new value", extended)

    if settings.uses_sqlite:
        try:
            Path(settings.db_path).chmod(0o600)
        except OSError:
            pass


def _add_missing_columns() -> int:
    """Add columns the models have that the database does not.

    create_all makes tables that are missing but never touches one that is
    already there, so a release that adds a column would otherwise fail on
    every existing install with a confusing error about no such column.

    Only ever adds.  Nothing here drops or rewrites anything, so the worst case
    is a column nobody uses.
    """
    from sqlalchemy import inspect, text

    engine_ = engine()
    dialect = engine_.dialect
    quote = dialect.identifier_preparer.quote
    added = 0

    with engine_.begin() as conn:
        # Inspect on this connection, not on the engine.  An inspector built
        # from the engine caches what it saw, and then we try to add a column
        # that is already there and log a scary error about nothing.
        inspector = inspect(conn)
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            have = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in have:
                    continue

                # SQLite will not add a unique column to a table that already
                # exists.  Say so rather than half applying a change.
                if column.unique and settings.uses_sqlite:
                    log.warning("cannot add unique column %s.%s to an existing "
                                "SQLite database, do it by hand", table.name,
                                column.name)
                    continue

                spec = column.type.compile(dialect)
                clause = (f"ALTER TABLE {quote(table.name)} ADD COLUMN "
                          f"{quote(column.name)} {spec}")
                default = column.default
                if default is not None and getattr(default, "is_scalar", False):
                    value = default.arg
                    if isinstance(value, bool):
                        clause += f" DEFAULT {1 if value else 0}"
                    elif isinstance(value, (int, float)):
                        clause += f" DEFAULT {value}"
                    elif isinstance(value, str):
                        escaped = value.replace("'", "''")
                        clause += f" DEFAULT '{escaped}'"

                try:
                    conn.execute(text(clause))
                    log.info("added column %s.%s", table.name, column.name)
                    added += 1
                except Exception as exc:
                    log.error("could not add %s.%s: %s", table.name,
                              column.name, exc)
    return added


# What each MySQL string type holds, in bytes.  There is no portable way to ask
# "is this column big enough now", so the sizes are written down.
_MYSQL_WIDTHS = (
    ("TINYTEXT", 255),
    ("MEDIUMTEXT", 16777215),
    ("LONGTEXT", 4294967295),
    ("TEXT", 65535),
)


def _capacity(spec: str) -> int:
    """Bytes a compiled column type holds, or 0 if it is not a string type.

    MEDIUMTEXT has to be checked before TEXT, or a prefix match calls it a TEXT
    and decides a perfectly good column needs widening every single boot.
    """
    spec = spec.strip().upper()
    match = re.match(r"^(?:VAR)?CHAR\((\d+)\)", spec)
    if match:
        return int(match.group(1))
    for name, size in _MYSQL_WIDTHS:
        if spec.startswith(name):
            return size
    return 0


def _extend_enums() -> int:
    """Let a column hold a value the models learned about after it was made.

    An enum column is created with exactly the values the models had that day,
    and nothing has ever revisited it.  _widen_columns cannot: it compares
    capacities, and an enum has no width to compare, so it skips them and says
    nothing.

    The first sign is a scan finishing and then dying on the way into the
    database with "Data truncated for column 'kind'", which is the worst place
    for it.  Every repository has already been cloned and read by then, and the
    findings are thrown away because a column could not hold a word.  That is
    how the misconfiguration kind landed: added to the models, shipped, and the
    first real scan on an existing install lost everything it found.

    Only ever adds.  A value in the database that the models no longer declare
    is left alone, because dropping it would rewrite rows that already use it.

    SQLite is skipped.  It stores an enum as free text and never truncates, so
    there is nothing to do and nothing that would have caught this either.
    """
    if settings.uses_sqlite:
        return 0

    from sqlalchemy import inspect, text

    engine_ = engine()
    dialect = engine_.dialect
    quote = dialect.identifier_preparer.quote
    extended = 0

    with engine_.begin() as conn:
        inspector = inspect(conn)
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            have = {c["name"]: c for c in inspector.get_columns(table.name)}
            for column in table.columns:
                current = have.get(column.name)
                if current is None:
                    continue

                wanted_values = getattr(column.type, "enums", None)
                if not wanted_values:
                    continue
                now_values = getattr(current["type"], "enums", None)
                if now_values is None:
                    continue

                # The database reports what it stores.  SQLAlchemy's Enum built
                # from a python Enum stores the member names, so compare on the
                # same footing rather than on how each side spells them.
                missing = [v for v in wanted_values if v not in set(now_values)]
                if not missing:
                    continue

                try:
                    wanted_spec = column.type.compile(dialect)
                except Exception:
                    continue

                # MODIFY replaces the whole definition, so nullability and the
                # default are copied back from what is already there.  Taking
                # them from the models would let a column go NOT NULL over rows
                # that are already null, which fails halfway through.
                clause = (f"ALTER TABLE {quote(table.name)} MODIFY "
                          f"{quote(column.name)} {wanted_spec}")
                if not current.get("nullable", True):
                    clause += " NOT NULL"
                server_default = current.get("default")
                if server_default not in (None, ""):
                    clause += f" DEFAULT {server_default}"

                try:
                    conn.execute(text(clause))
                    log.info("%s.%s can now hold: %s", table.name, column.name,
                             ", ".join(missing))
                    extended += 1
                except Exception as exc:
                    log.error("could not extend %s.%s: %s", table.name,
                              column.name, exc)
    return extended


def _widen_columns() -> int:
    """Give more room to columns the models outgrew.

    _add_missing_columns only ever adds, so a column declared narrow in an
    earlier release stays narrow for the life of the install.  Nothing warns
    about it.  The first sign is a scan dying on "data too long", which is how
    findings.branches went: TEXT holds 65,535 bytes, and one secret sitting in
    an old commit of a repository with a few thousand branches is reachable
    from all of them, so the branch list on that one row goes straight past it.

    Only ever grows.  A column already big enough is left alone, and one bigger
    than the models ask for is never cut back, because shrinking a column is
    how an upgrade quietly loses somebody's data.

    SQLite is skipped.  Its TEXT has no length at all, so there is nothing
    there to widen.
    """
    if settings.uses_sqlite:
        return 0

    from sqlalchemy import inspect, text

    engine_ = engine()
    dialect = engine_.dialect
    quote = dialect.identifier_preparer.quote
    widened = 0

    with engine_.begin() as conn:
        inspector = inspect(conn)
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            have = {c["name"]: c for c in inspector.get_columns(table.name)}
            for column in table.columns:
                current = have.get(column.name)
                if current is None:
                    continue

                try:
                    wanted_spec = column.type.compile(dialect)
                    now_spec = current["type"].compile(dialect)
                except Exception:
                    continue

                wanted = _capacity(wanted_spec)
                now = _capacity(now_spec)
                if not wanted or not now or wanted <= now:
                    continue

                # MODIFY wants the whole definition back and quietly drops
                # anything left out, so the rest of it is copied from what is
                # already there rather than from the models.  The width is the
                # only thing being changed here.  Taking nullability from the
                # models instead would let a column silently go NOT NULL on
                # rows that are already null, which fails halfway through.
                clause = (f"ALTER TABLE {quote(table.name)} MODIFY "
                          f"{quote(column.name)} {wanted_spec}")
                if not current.get("nullable", True):
                    clause += " NOT NULL"
                server_default = current.get("default")
                if server_default not in (None, ""):
                    clause += f" DEFAULT {server_default}"

                try:
                    conn.execute(text(clause))
                    log.info("widened %s.%s from %s to %s", table.name,
                             column.name, now_spec, wanted_spec)
                    widened += 1
                except Exception as exc:
                    log.error("could not widen %s.%s: %s", table.name,
                              column.name, exc)
    return widened
