"""What each repository is, who answers for it, and what it holds.

The connection answers this for a whole account, and that is right most of the
time.  It stops being right the moment one organization holds a cardholder
system and a brochure site, which is most organizations.  A finding in the
first is an incident and the same finding in the second is a chore, and nothing
in a scanner can tell them apart without somebody saying so.

So a repository can carry its own answers, and anything it does not carry falls
back to the connection.  Tagging is then only needed where the account level
answer is wrong, rather than 258 times.
"""

from __future__ import annotations

import logging
import re

from app.core.models import Repository, utcnow

log = logging.getLogger("gcr.tagging")

FIELDS = ("application_name", "application_owner", "technical_owner", "sensitivity")

# Who hears about one repository.  Kept apart from FIELDS because nothing falls
# back here: a connection that mails its owners already does that for every
# repository in it, so these only ever add people.
NOTIFY_FLAGS = ("notify_application_owner", "notify_technical_owner")

# What an owner has to look like.  The forms check it through clean_email, and
# the import checks it here, so a spreadsheet cannot put a name where every
# form insists on an address.
OWNERS = ("application_owner", "technical_owner")
ADDRESS = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[a-z]{2,}$", re.I)


def bad_address(value: str) -> str:
    """The first part of an owner cell that is not an address, or ""."""
    for part in str(value or "").replace(";", ",").split(","):
        part = part.strip()
        if part and not ADDRESS.match(part):
            return part
    return ""


def labels(session) -> list:
    """The sensitivity labels this installation uses."""
    from app.core import settings_store as store
    return store.sensitivity_labels(session)


def effective(session, repo) -> dict:
    """What applies to this repository, and where each answer came from.

    The source matters as much as the value.  "Nobody has said" and "somebody
    said, for the whole account" are different states, and an audit that cannot
    tell them apart is not much of an audit.
    """
    from app.core import connections as connection_store

    source = None
    if getattr(repo, "connection", None):
        source = connection_store.by_name(session, repo.connection)
    if source is None:
        source = _connection_for_org(session, repo.organization)
    return _applies(repo, source)


def _applies(repo, source) -> dict:
    """The fallback itself, once the connection to fall back to is in hand."""
    out = {}
    for field in FIELDS:
        own = (getattr(repo, field, "") or "").strip()
        if own:
            out[field] = {"value": own, "from": "repository"}
            continue
        inherited = (getattr(source, field, "") or "").strip() if source else ""
        out[field] = {"value": inherited,
                      "from": "connection" if inherited else "nobody"}
    return out


def effective_many(session, repos) -> dict:
    """The same answers for a list of repositories, keyed by repository id.

    `effective` asks the database for a connection every time it is called,
    which is fine for the one repository a page is showing.  A report covering
    an estate would run that query a few hundred times to read a string
    somebody typed once, so the connections are read here in a single go and
    the fallback is done from memory.
    """
    from app.core.models import Connection

    by_name, by_org = {}, {}
    for row in session.query(Connection).all():
        by_name[(row.name or "").strip()] = row
        orgs = (row.scope_orgs() if hasattr(row, "scope_orgs")
                else [o.strip() for o in (row.organizations or "").split(",")])
        for org in orgs:
            # First match wins, the same as _connection_for_org does.
            by_org.setdefault(org, row)

    out = {}
    for repo in repos:
        source = by_name.get((getattr(repo, "connection", "") or "").strip())
        if source is None:
            source = by_org.get(getattr(repo, "organization", "") or "")
        out[repo.id] = _applies(repo, source)
    return out


def _connection_for_org(session, organization: str):
    from app.core.models import Connection

    if not organization:
        return None
    for row in session.query(Connection).all():
        orgs = (row.scope_orgs() if hasattr(row, "scope_orgs")
                else [o.strip() for o in (row.organizations or "").split(",")])
        if organization in orgs:
            return row
    return None


def tag(session, repo_ids, values: dict, actor: str = "") -> int:
    """Set what was given on every repository named.  Empty fields are left alone.

    Left alone rather than cleared, because tagging thirty repositories with a
    data type should not quietly wipe the owner somebody set on one of them
    last month.  Clearing is done with the word "-", which is explicit.
    """
    wanted = {}
    for field in FIELDS:
        given = (values.get(field) or "").strip()
        if given == "-":
            wanted[field] = ""
        elif given:
            wanted[field] = given
    if not wanted:
        return 0

    rows = session.query(Repository).filter(Repository.id.in_(list(repo_ids))).all()
    for row in rows:
        for field, value in wanted.items():
            setattr(row, field, value)
        row.tagged_by = actor or row.tagged_by or ""
        row.tagged_at = utcnow()
    session.flush()
    log.info("tagged %d repositories with %s", len(rows), ", ".join(wanted))
    return len(rows)


def set_own(session, repo, values: dict, actor: str = "") -> list:
    """One repository's own answers, exactly as given.  -> the fields that moved.

    Not the same as tag().  This is a form that shows what is already there, so
    an empty box means somebody emptied it, and the field goes back to whatever
    the connection says.
    """
    moved = []
    for field in FIELDS + ("notify_extra",):
        if field not in values:
            continue
        given = (values.get(field) or "").strip()
        if given == "-":
            given = ""
        if given != (getattr(repo, field, "") or "").strip():
            setattr(repo, field, given)
            moved.append(field)
    for field in NOTIFY_FLAGS:
        if field not in values:
            continue
        given = bool(values.get(field))
        if given != bool(getattr(repo, field, False)):
            setattr(repo, field, given)
            moved.append(field)
    if moved:
        repo.tagged_by = actor or repo.tagged_by or ""
        repo.tagged_at = utcnow()
        session.flush()
    return moved


def notify_addresses(repo, applies: dict) -> list:
    """Who hears about this repository, beyond the installation and its account.

    `applies` is what effective() said, so a ticked owner is whichever owner
    actually applies here, set on the repository or inherited.  Only things
    that look like addresses, once each, for the reason the connection's
    version gives: a dash or a name handed to a mail server loses the whole
    message.
    """
    wanted = []
    if getattr(repo, "notify_application_owner", False):
        wanted.append((applies.get("application_owner") or {}).get("value", ""))
    if getattr(repo, "notify_technical_owner", False):
        wanted.append((applies.get("technical_owner") or {}).get("value", ""))
    wanted.append(getattr(repo, "notify_extra", "") or "")

    out = []
    for entry in wanted:
        for part in str(entry).replace(";", ",").split(","):
            address = part.strip()
            if "@" in address and address not in out:
                out.append(address)
    return out


def untagged(session, organization: str = "", base=None):
    """Repositories nobody has said anything about.

    `base` is the query to start from, rbac.visible_repositories for anybody
    who does not see the whole estate.
    """
    query = (base if base is not None else session.query(Repository)).filter(
        (Repository.technical_owner == "") | (Repository.technical_owner.is_(None)),
        (Repository.sensitivity == "") | (Repository.sensitivity.is_(None)))
    if organization:
        query = query.filter(Repository.organization == organization)
    return query


# The columns of the CSV, in the order they are written.  repository first
# because that is what somebody sorts and matches on in a spreadsheet.
CSV_COLUMNS = ["repository", "application_name", "application_owner",
               "technical_owner", "sensitivity", "description",
               "tagged_by", "tagged_date"]

# Enough for an estate several times the size of any this has met, and small
# enough that a pasted spreadsheet cannot exhaust memory.
MAX_IMPORT_ROWS = 20000


def to_csv(session, organization: str = "", base=None) -> str:
    """Every repository and what is said about it, as a spreadsheet.

    Exported with what is set on the repository itself, not what it inherits.
    A round trip has to be lossless: writing the connection's answer into every
    row and reading it back would turn one inherited value into two hundred
    explicit ones, and nobody could tell afterwards which had been meant.
    """
    import csv
    import io

    # Only the repositories the caller may see, when the caller passes them.
    # The file names every owner, contact and data label it covers.
    query = base if base is not None else session.query(Repository)
    if organization:
        query = query.filter(Repository.organization == organization)

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in query.order_by(Repository.full_name).all():
        writer.writerow([
            row.full_name,
            row.application_name or "",
            row.application_owner or "",
            row.technical_owner or "",
            # Pipe rather than comma.  A comma inside a CSV cell is legal and
            # quoted, and then somebody opens it in a spreadsheet, edits it,
            # and the quoting is gone.  A pipe survives that.
            " | ".join(part.strip() for part in
                       (row.sensitivity or "").split(",") if part.strip()),
            (row.note or "").replace("\r", " ").replace("\n", " "),
            row.tagged_by or "",
            row.tagged_at.strftime("%Y-%m-%d") if row.tagged_at else "",
        ])
    return buffer.getvalue()


def split_labels(value: str) -> list:
    """The labels in a cell, however somebody separated them.

    Pipes are what this exports, because a comma inside a CSV cell is legal,
    quoted, and gone the moment a spreadsheet round trips it.  Commas are
    accepted anyway: it is what the value looks like everywhere else in this
    product, and refusing it would be a rule with no purpose behind it.
    """
    parts = []
    for chunk in str(value or "").replace("|", ",").split(","):
        one = chunk.strip()
        if one and one not in parts:
            parts.append(one)
    return parts


def from_csv(session, text: str, actor: str = "") -> dict:
    """Read the same shape back.  -> what changed, and what did not.

    This only ever updates.  A repository is a thing a scan found; one typed
    into a spreadsheet is a row nothing will ever scan, so a name nobody
    recognizes is reported back as a line to fix rather than created.

    Nothing here stops on an error.  A file edited by hand has a bad row in it
    somewhere, and refusing the other four hundred because of it helps nobody:
    every row is taken on its own, and what could not be used is counted and
    named.

    An empty cell leaves that value alone.  Somebody who deletes a column, or
    exports one organization and pastes it over another, must not silently
    clear what they did not touch.  A single "-" clears it, which is the word
    the tagging page already uses.
    """
    import csv
    import io

    counts = {"changed": 0, "unchanged": 0, "unknown": 0, "skipped": 0,
              "rows": 0}
    problems = []

    try:
        reader = csv.DictReader(io.StringIO(text))
        fields = [(name or "").strip().lower() for name in (reader.fieldnames or [])]
    except (csv.Error, ValueError) as exc:
        return {**counts, "problems": [f"could not read the file: {exc}"]}

    if "repository" not in fields:
        return {**counts,
                "problems": ["that file needs a repository column; export one "
                             "first to see the shape"]}

    known = {row.full_name: row for row in session.query(Repository).all()}

    for raw in reader:
        counts["rows"] += 1
        if counts["rows"] > MAX_IMPORT_ROWS:
            problems.append(f"stopped after {MAX_IMPORT_ROWS} rows")
            break

        # One bad row is one bad row.  Whatever is wrong with it, the rest of
        # the file still gets read.
        try:
            row = {(k or "").strip().lower(): (str(v) if v is not None else "").strip()
                   for k, v in raw.items() if k}
        except Exception:            # noqa: BLE001
            counts["skipped"] += 1
            continue

        name = row.get("repository", "")
        if not name:
            counts["skipped"] += 1
            continue

        repo = known.get(name)
        if repo is None:
            counts["unknown"] += 1
            if len(problems) < 10:
                problems.append(f"no repository called {name}")
            continue

        # Checked before anything is set, so a row with a bad owner changes
        # nothing at all rather than half of itself.
        wrong = [(field, bad_address(row[field])) for field in OWNERS
                 if row.get(field) and row[field] != "-"
                 and bad_address(row[field])]
        if wrong:
            counts["skipped"] += 1
            if len(problems) < 10:
                field, part = wrong[0]
                problems.append(f"{name}: {field.replace('_', ' ')} has to be "
                                f"an email address, and {part!r} is not one")
            continue

        try:
            touched = False
            for field in FIELDS:
                if field not in row:
                    continue
                given = row[field]
                if not given:
                    continue                  # left alone, deliberately
                if given == "-":
                    new = ""
                elif field == "sensitivity":
                    # However it was separated, stored the way the rest of the
                    # product writes it.
                    new = ", ".join(split_labels(given))
                else:
                    new = given
                if (getattr(repo, field, "") or "") != new:
                    setattr(repo, field, new)
                    touched = True

            if row.get("description"):
                new = "" if row["description"] == "-" else row["description"]
                if (repo.note or "") != new:
                    repo.note = new
                    repo.note_by = actor or repo.note_by or ""
                    repo.note_at = utcnow()
                    touched = True

            if touched:
                repo.tagged_by = actor or repo.tagged_by or ""
                repo.tagged_at = utcnow()
                counts["changed"] += 1
            else:
                counts["unchanged"] += 1
        except Exception as exc:            # noqa: BLE001
            counts["skipped"] += 1
            if len(problems) < 10:
                problems.append(f"{name} could not be read: {str(exc)[:80]}")

    session.flush()
    log.info("tagging import: %s", counts)
    return {**counts, "problems": problems}
