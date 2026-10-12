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

        _watch(_engine)
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
    _watch(_engine)
    return _engine


def _watch(eng) -> None:
    """Mark the finding summaries stale whenever a write to findings commits."""
    from app.core import summary

    summary.watch(eng)


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
        if "ai_usage" in made:
            # The token counts kept before there was a usage table, so the
            # cost page has some history to forecast from on the first day.
            from app.core.ai_cost import backfill

            with session_scope() as session:
                copied = backfill(session)
            if copied:
                log.info("copied %d earlier AI call(s) into the usage table", copied)
        # Widen first, then add.  The order is not arbitrary.
        #
        # MariaDB caps a row at 65,535 bytes counting every varchar in full,
        # and a wide table can reach it.  When it does, adding a column fails
        # with a message about row size that names no column, while the change
        # that makes room, moving a long varchar to TEXT, is a widening.  With
        # the add running first, a release that does both would fail its add,
        # succeed its widen, and then need a second restart before the column
        # appeared: an upgrade that half works and looks finished.
        #
        # Nothing is lost by going the other way round.  A column that does
        # not exist yet cannot need widening.
        widened = _widen_columns()
        if widened:
            log.info("gave %d column(s) more room", widened)
        added = _add_missing_columns()
        if added:
            log.info("added %d new column(s) to the existing database", added)
        extended = _extend_enums()
        if extended:
            log.info("taught %d column(s) a new value", extended)
        # Nothing credits a history walk on the reader's side any more.
        #
        # There was a backfill here that set the "walked to its first commit"
        # marker on every repository, on an install where not one carried it,
        # reasoning that a marker can only come from a windowed run so their
        # absence proved every completed scan had been a full walk.  The
        # reasoning was wrong in the one way that mattered: the reports it read
        # said "complete" about the run, not about the walk.
        #
        # It credited two hundred and sixty one repositories.  The next
        # windowed run then read only new commits, found nothing older, and the
        # silence was taken for remediation: two thousand nine hundred and
        # seventy six findings closed, including every one of the twenty
        # credentials that had been proved live against the provider that
        # issued them.
        #
        # The marker is written by the scanner, which is the only thing that
        # knows where a walk actually reached.  A reader that infers it is
        # guessing, and this is not a thing worth guessing about.

        # Paths an engine reported with the scan's clone folder in front.
        # Cheap once done: the query finds nothing to change.
        from app.core.ingest import repair_clone_paths

        with session_scope() as session:
            repair_clone_paths(session)

    if settings.uses_sqlite:
        try:
            Path(settings.db_path).chmod(0o600)
        except OSError:
            pass


def _safe_default(value) -> bool:
    """Whether a reflected default can go back into a statement as it stands."""
    text_value = str(value)
    return ";" not in text_value and "--" not in text_value and "/*" not in text_value


def _literal(column_type, value, dialect):
    """A default value written the way this database writes literals, or None.

    Handing the job to the type keeps the quoting rules with the driver that
    owns them.  Booleans and numbers are rendered here because their spelling
    is a property of the statement rather than of the value, and because a
    boolean column whose type declines to render True is common enough to be
    worth answering directly.

    None means there is no safe rendering, and the caller adds the column with
    no default rather than inventing one.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    try:
        processor = column_type.literal_processor(dialect=dialect)
    except Exception:
        processor = None
    if processor is None:
        return None
    try:
        rendered = processor(value)
    except Exception:
        return None
    # A processor that hands back something with a statement terminator or a
    # comment in it has not quoted the value, whatever it thinks it did.
    if rendered is None or ";" in rendered or "--" in rendered:
        return None

    # And a backslash is refused outright, because nothing here escapes one.
    #
    # This was the whole reason for moving the job to the driver, and the
    # driver does not do it either: literal_processor doubles quotes and
    # leaves a backslash alone, on MySQL as much as anywhere else.  MySQL
    # treats a backslash as an escape character by default, so a value holding
    # one can end its own string early no matter which of the two wrote it.
    #
    # There is no correct escaping to reach for here that is worth writing,
    # because a default holding a backslash is not a thing this application
    # has or needs.  So the column is added without a default and a line says
    # so, which is a visible gap rather than a statement that might not mean
    # what it reads.
    if "\\" in str(value):
        return None
    return rendered


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
                # The default, rendered by the driver rather than by hand.
                #
                # This used to double any apostrophe and wrap the result in
                # quotes, which is the standard SQL answer and not the whole
                # answer: MySQL and MariaDB also treat a backslash as an
                # escape character, so doubling quotes alone does not make a
                # string safe to paste into a statement there.
                #
                # It was never reachable.  Every default here is a literal
                # written in models.py, so nothing an outsider controls has
                # ever reached it.  That is an argument about where the values
                # come from rather than a property of the code, and it stops
                # holding the moment somebody feeds this from anywhere else.
                # The type knows how to render its own literal for the dialect
                # in hand, so it does that instead, and a type that cannot is
                # left without a default rather than guessed at.
                default = column.default
                if default is not None and getattr(default, "is_scalar", False):
                    rendered = _literal(column.type, default.arg, dialect)
                    if rendered is not None:
                        clause += f" DEFAULT {rendered}"
                    else:
                        log.debug("no safe way to render the default for "
                                  "%s.%s, adding the column without one",
                                  table.name, column.name)

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
                # The default the database just reported, handed back to the
                # database that reported it.  Already a literal in that
                # dialect, so it is not re-quoted, and checked rather than
                # trusted: anything carrying a terminator or a comment is not
                # a default, whatever the inspector called it.
                #
                # Nothing an outsider controls reaches this.  Writing a column
                # default takes rights over the schema, and somebody holding
                # those does not need this statement.  It is checked anyway
                # because the check costs one line and the argument for
                # skipping it is one nobody should have to re-derive.
                server_default = current.get("default")
                if server_default not in (None, "") and _safe_default(server_default):
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
                # The default the database just reported, handed back to the
                # database that reported it.  Already a literal in that
                # dialect, so it is not re-quoted, and checked rather than
                # trusted: anything carrying a terminator or a comment is not
                # a default, whatever the inspector called it.
                #
                # Nothing an outsider controls reaches this.  Writing a column
                # default takes rights over the schema, and somebody holding
                # those does not need this statement.  It is checked anyway
                # because the check costs one line and the argument for
                # skipping it is one nobody should have to re-derive.
                server_default = current.get("default")
                if server_default not in (None, "") and _safe_default(server_default):
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
