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


# Enough for production, staging and a few regions, and few enough that the
# box is still a list of places rather than an inventory.
MAX_WEB_URLS = 20


def web_urls(value: str) -> tuple:
    """Where a web application answers, cleaned.  -> (urls, problem).

    For identifying the application, mostly to whatever runs dynamic scans,
    which is another system.  Nothing here fetches them.  Comma or space
    separated, each http or https with a host, and no user name or password
    in it: the list gets exported and handed on, and a credential in a scope
    list ends up in every copy of it.
    """
    from urllib.parse import urlparse

    out = []
    for part in str(value or "").replace(",", " ").split():
        parsed = urlparse(part)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return [], f"{part!r} is not an http or https address"
        if parsed.username or parsed.password:
            return [], f"{part!r} has a user name or password in it"
        if part not in out:
            out.append(part)
    if len(out) > MAX_WEB_URLS:
        return [], f"more than {MAX_WEB_URLS} addresses"
    return out, ""


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
    for field in FIELDS + ("notify_extra", "web_app_urls"):
        if field not in values:
            continue
        given = (values.get(field) or "").strip()
        if given == "-":
            given = ""
        if given != (getattr(repo, field, "") or "").strip():
            setattr(repo, field, given)
            moved.append(field)
    for field in NOTIFY_FLAGS + ("web_app",):
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
               "notify_application_owner", "notify_technical_owner",
               "notify_extra", "web_application", "web_urls",
               "tagged_by", "tagged_date"]

# What a yes or no cell may say.
YES = ("yes", "y", "true", "1")
NO = ("no", "n", "false", "0")

# Enough for an estate several times the size of any this has met, and small
# enough that a pasted spreadsheet cannot exhaust memory.
MAX_IMPORT_ROWS = 20000


# How long each cell may be, the same as the columns it lands in.  Too long
# for MariaDB fails the whole import at the end rather than the one row.
LIMITS = {"application_name": 200, "application_owner": 200,
          "technical_owner": 200, "sensitivity": 400, "notify_extra": 2000,
          "web_app_urls": 4000}

# The CSV's name for each column that is not called what the model calls it.
CSV_NAMES = {"web_app": "web_application", "web_app_urls": "web_urls"}


def _owners(value: str) -> str:
    """Addresses as the forms store them, one comma and a space apart.

    Pipes too, which is how the export separates them.
    """
    return ", ".join(part.strip() for part in
                     str(value).replace(";", ",").replace("|", ",").split(",")
                     if part.strip())


def _unquote(value: str) -> str:
    """A cell without the apostrophe the export put in front of a formula."""
    from app.core.reports import SPREADSHEET_TRIGGERS

    if value[:1] == "'" and value[1:2] and value[1:2] in SPREADSHEET_TRIGGERS:
        return value[1:]
    return value


def _read_row(row: dict, repo, offered: list, inherited: dict) -> tuple:
    """One import row, checked.  -> ({field: value}, "") or ({}, why).

    Only what the row says.  An empty cell is left out, so it leaves that value
    alone, and a "-" is an empty value, which clears it.
    """
    wanted = {}

    for field in FIELDS + ("notify_extra",):
        given = row.get(field, "")
        if not given:
            continue
        if given == "-":
            wanted[field] = ""
            continue
        if field in OWNERS + ("notify_extra",):
            bad = bad_address(given.replace("|", ","))
            if bad:
                return {}, (f"{field.replace('_', ' ')} has to be an email "
                            f"address, and {bad!r} is not one")
            given = _owners(given)
        elif field == "sensitivity":
            # Matched without case, and stored the way the list spells it, so
            # "customer data" and "Customer Data" are one label, not two.
            by_case = {label.casefold(): label for label in offered}
            held = []
            for one in split_labels(given):
                label = by_case.get(one.casefold())
                if label is None:
                    return {}, (f"{one!r} is not one of the labels on the "
                                f"Settings page ({', '.join(offered)})")
                if label not in held:
                    held.append(label)
            given = ", ".join(held)
        wanted[field] = given

    for field in NOTIFY_FLAGS + ("web_app",):
        given = row.get(CSV_NAMES.get(field, field), "").lower()
        if not given:
            continue
        if given not in YES + NO:
            return {}, (f"{CSV_NAMES.get(field, field).replace('_', ' ')} "
                        f"has to be yes or no, and {given!r} is neither")
        wanted[field] = given in YES

    given = row.get("web_urls", "")
    if given:
        urls, why = ([], "") if given == "-" else web_urls(given.replace("|", ","))
        if why:
            return {}, f"web urls: {why}"
        wanted["web_app_urls"] = ", ".join(urls)

    for field, limit in LIMITS.items():
        if len(wanted.get(field) or "") > limit:
            return {}, f"{CSV_NAMES.get(field, field).replace('_', ' ')} is longer than {limit}"

    # The same two rules the repository's page holds to.  What the row leaves
    # alone counts as what the repository already has.
    def after(field):
        return wanted[field] if field in wanted else getattr(repo, field, None)

    if after("web_app") and not (after("web_app_urls") or "").strip():
        return {}, "a web application needs its web urls"
    for flag, field in (("notify_application_owner", "application_owner"),
                        ("notify_technical_owner", "technical_owner")):
        if (after(flag) and not (after(field) or "").strip()
                and (inherited.get(field) or {}).get("from") != "connection"):
            return {}, (f"{flag.replace('_', ' ')} is yes, but there is no "
                        f"{field.replace('_', ' ')} to send it to")
    return wanted, ""


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

    from app.core.reports import _quote_formula

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in query.order_by(Repository.full_name).all():
        # Every cell quoted against formulas, since this file is opened in a
        # spreadsheet by design.  from_csv takes the quote off again.
        writer.writerow([_quote_formula(cell) for cell in [
            row.full_name,
            row.application_name or "",
            # Pipes between addresses for the same reason as the labels below.
            " | ".join(_owners(row.application_owner or "").split(", "))
            if row.application_owner else "",
            " | ".join(_owners(row.technical_owner or "").split(", "))
            if row.technical_owner else "",
            # Pipe rather than comma.  A comma inside a CSV cell is legal and
            # quoted, and then somebody opens it in a spreadsheet, edits it,
            # and the quoting is gone.  A pipe survives that.
            " | ".join(part.strip() for part in
                       (row.sensitivity or "").split(",") if part.strip()),
            (row.note or "").replace("\r", " ").replace("\n", " "),
            "yes" if row.notify_application_owner else "no",
            "yes" if row.notify_technical_owner else "no",
            " | ".join(_owners(row.notify_extra or "").split(", "))
            if row.notify_extra else "",
            "yes" if row.web_app else "no",
            " | ".join(web_urls(row.web_app_urls)[0]),
            row.tagged_by or "",
            row.tagged_at.strftime("%Y-%m-%d") if row.tagged_at else "",
        ]])
    return buffer.getvalue()


WEB_COLUMNS = ["repository", "application_name", "web_urls",
               "application_owner", "technical_owner", "sensitivity",
               "visibility", "default_branch", "code_last_changed",
               "changed_from", "days_since_change", "commits_90d",
               "last_scanned"]


def web_apps_csv(session, base=None) -> str:
    """Every repository marked as part of a web application, and where it is.

    For the system that runs dynamic scans, to know what is out there and who
    to ask before testing it.  What applies rather than what is set here,
    unlike to_csv: this is not read back, so the owner is the one that
    actually answers, wherever it came from.  Every cell
    is quoted against formulas, since this one goes to another team.
    """
    import csv
    import io

    from app.core.reports import spreadsheet_row

    query = base if base is not None else session.query(Repository)
    rows = (query.filter(Repository.web_app.is_(True))
            .order_by(Repository.full_name).all())
    applies = effective_many(session, rows)
    from app.core import webapps

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=WEB_COLUMNS,
                            lineterminator="\n")
    writer.writeheader()
    for row in rows:
        said = applies.get(row.id, {})
        moved = webapps.changed(row)
        writer.writerow(spreadsheet_row({
            "repository": row.full_name,
            "application_name": said.get("application_name", {}).get("value", ""),
            "web_urls": " | ".join(web_urls(row.web_app_urls)[0]),
            "application_owner": said.get("application_owner", {}).get("value", ""),
            "technical_owner": said.get("technical_owner", {}).get("value", ""),
            "sensitivity": " | ".join(split_labels(
                said.get("sensitivity", {}).get("value", ""))),
            "visibility": row.visibility or "",
            "default_branch": row.default_branch or "",
            # A commit on the default branch, or the host's last push to any
            # branch until a scan has read it.  Never a deployment.
            "code_last_changed": (moved["at"].strftime("%Y-%m-%d")
                                  if moved["at"] else ""),
            "changed_from": {"commit": "default branch commit",
                             "push": "host push, any branch"}.get(
                                 moved["source"], ""),
            "days_since_change": ("" if moved["days"] is None
                                  else moved["days"]),
            "commits_90d": ("" if row.default_commits_90d is None
                            else row.default_commits_90d),
            "last_scanned": (row.last_scanned_at.strftime("%Y-%m-%d")
                             if row.last_scanned_at else ""),
        }))
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
    # The labels anybody can tick, so a spreadsheet cannot invent one.  Plus
    # what repositories already carry, so a file exported before a label was
    # dropped still goes back in.
    offered = labels(session)
    for repo in known.values():
        offered += [x for x in split_labels(repo.sensitivity or "")
                    if x not in offered]
    # What each would inherit, for a notify tick on an owner the row leaves
    # to the connection.
    inherited = effective_many(session, list(known.values()))

    for raw in reader:
        counts["rows"] += 1
        if counts["rows"] > MAX_IMPORT_ROWS:
            problems.append(f"stopped after {MAX_IMPORT_ROWS} rows")
            break

        # One bad row is one bad row.  Whatever is wrong with it, the rest of
        # the file still gets read.
        try:
            row = {(k or "").strip().lower():
                   _unquote((str(v) if v is not None else "").strip())
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

        # Everything is checked before anything is set, so a bad row changes
        # nothing at all rather than half of itself.
        wanted, why = _read_row(row, repo, offered, inherited.get(repo.id, {}))
        if why:
            counts["skipped"] += 1
            if len(problems) < 10:
                problems.append(f"{name}: {why}")
            continue

        try:
            touched = False
            for field, new in wanted.items():
                if field in NOTIFY_FLAGS + ("web_app",):
                    if bool(getattr(repo, field, False)) != new:
                        setattr(repo, field, new)
                        touched = True
                elif (getattr(repo, field, "") or "") != new:
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
