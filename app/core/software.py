"""What software is in the estate, and where.

The findings tables answer "what is wrong".  This one answers "what is there",
which is a different question and the one that gets asked in a hurry.  When a
package is announced as compromised, nobody wants to know whether it has a CVE
yet.  They want to know whether that exact version is anywhere in the code, in
which repositories, on which branches, and who to tell.

Built from the SBOM a scan writes, so it lists everything, not only the
packages an advisory happens to name.  Vulnerability is joined on afterwards
rather than being the reason a row exists.

The branch is part of the answer, not a detail.  A release branch routinely
pins a version the default branch has already moved past, so "we upgraded" is
only ever true of a branch somebody checked.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import distinct, func, or_

from app.core.models import Component, Finding, FindingKind, FindingState

# How the severities rank when a package has more than one advisory against
# it.  The worst one is what the row shows, because that is the one that
# decides whether somebody looks today.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                 "info": 4, "unknown": 5}

PAGE_SIZE = 100

# The ecosystems worth naming in plain words.  Anything else shows the purl
# type it came with, which is still the right answer, just less friendly.
ECOSYSTEM_NAMES = {
    "npm": "Node", "pypi": "Python", "maven": "Java", "nuget": ".NET",
    "golang": "Go", "gem": "Ruby", "composer": "PHP", "cargo": "Rust",
    "github": "GitHub Actions", "deb": "Debian", "rpm": "RPM", "apk": "Alpine",
    "conan": "C/C++", "cocoapods": "CocoaPods", "swift": "Swift",
    "hex": "Erlang", "pub": "Dart", "cran": "R", "hackage": "Haskell",
    "generic": "Unrecognized",
}


def pretty_ecosystem(value: str) -> str:
    key = (value or "").strip().lower()
    return ECOSYSTEM_NAMES.get(key, key or "unknown")


def vulnerability_index(session) -> dict:
    """-> {(repository, package name lowered, version): {...}}.

    One pass over the dependency findings rather than a join, because the two
    sides spell an ecosystem differently often enough that joining on it would
    quietly drop rows, and because a package with no advisory has to end up
    with an empty entry rather than no row at all.

    Only what is still open and not set aside.  A finding somebody excepted is
    a decision, and showing the package as vulnerable after that decision would
    be arguing with it.
    """
    index = {}
    rows = (session.query(Finding.repository, Finding.package_name,
                          Finding.package_version, Finding.severity,
                          Finding.vulnerability_id, Finding.known_exploited,
                          Finding.malicious)
            .filter(Finding.kind == FindingKind.DEPENDENCY)
            .filter(Finding.state != FindingState.FIXED)
            .filter(Finding.excepted.is_(False))
            .all())
    for repository, name, version, severity, advisory, exploited, malicious in rows:
        if not name:
            continue
        key = (repository or "", name.strip().lower(), (version or "").strip())
        entry = index.setdefault(key, {"count": 0, "worst": "", "advisories": [],
                                       "known_exploited": False,
                                       "malicious": False})
        entry["count"] += 1
        grade = getattr(severity, "value", severity) or "unknown"
        if (not entry["worst"]
                or SEVERITY_RANK.get(grade, 9) < SEVERITY_RANK.get(entry["worst"], 9)):
            entry["worst"] = grade
        if advisory and advisory not in entry["advisories"]:
            entry["advisories"].append(advisory)
        entry["known_exploited"] = entry["known_exploited"] or bool(exploited)
        entry["malicious"] = entry["malicious"] or bool(malicious)
    return index


def conditions(session, user, *, search="", ecosystem="", organization="",
               repository="", branch="", license_text="",
               unlicensed=False) -> list:
    """Everything the filter row can ask for, as SQL conditions.

    Conditions rather than a query, because the page asks the same narrowed
    question several ways at once and each one wants the columns, not a
    subquery wrapped around them.

    Whether a package is vulnerable is not in here.  That lives in the
    findings, so it is applied to the rows after they come back.
    """
    from app.core import rbac

    clauses = []
    scope = rbac.component_scope(session, user)
    if scope is not None:
        clauses.append(scope)

    if search:
        like = f"%{search.strip()}%"
        clauses.append(or_(Component.name.ilike(like),
                           Component.purl.ilike(like)))
    if ecosystem:
        clauses.append(Component.ecosystem == ecosystem)
    if organization:
        clauses.append(Component.organization == organization)
    if repository:
        clauses.append(Component.repository == repository)
    if branch:
        clauses.append(Component.branch == branch)
    if license_text:
        clauses.append(Component.licenses.ilike(f"%{license_text.strip()}%"))
    if unlicensed:
        clauses.append(or_(Component.licenses == "", Component.licenses.is_(None)))
    return clauses


def summary(session, clauses) -> dict:
    """The numbers across the top, and the ecosystem mix underneath them.

    The mix is counted over distinct packages rather than over rows.  Counting
    rows would say more about which repositories were scanned than about what
    the estate is written in: one monorepo with a large lockfile would drown
    everything else out.
    """
    def count(column, *extra):
        return (session.query(func.count(column))
                .filter(*clauses).filter(*extra).scalar()) or 0

    rows = (session.query(Component.ecosystem,
                          func.count(distinct(func.lower(Component.name))))
            .filter(*clauses).group_by(Component.ecosystem).all())
    total = sum(number for _, number in rows) or 1
    mix = [{"ecosystem": eco or "", "name": pretty_ecosystem(eco),
            "packages": number, "share": round(100.0 * number / total, 1)}
           for eco, number in sorted(rows, key=lambda row: -row[1])]

    return {
        "places": count(Component.id),
        "packages": count(distinct(func.lower(Component.name))),
        "versions": count(distinct(Component.purl_key)),
        "repositories": count(distinct(Component.repository)),
        "unlicensed": count(Component.id,
                            or_(Component.licenses == "",
                                Component.licenses.is_(None))),
        "ecosystems": mix,
    }


def _risk_by_package(index: dict) -> dict:
    """The vulnerability index again, with the repository dropped.

    The list page groups a package across the whole estate, so it wants one
    answer per (name, version) rather than one per place.
    """
    out = {}
    for (_repository, name, version), entry in index.items():
        seen = out.setdefault((name, version),
                              {"count": 0, "worst": "", "advisories": [],
                               "known_exploited": False, "malicious": False})
        seen["count"] += entry["count"]
        if (not seen["worst"]
                or SEVERITY_RANK.get(entry["worst"], 9)
                < SEVERITY_RANK.get(seen["worst"], 9)):
            seen["worst"] = entry["worst"]
        for advisory in entry["advisories"]:
            if advisory not in seen["advisories"]:
                seen["advisories"].append(advisory)
        seen["known_exploited"] = seen["known_exploited"] or entry["known_exploited"]
        seen["malicious"] = seen["malicious"] or entry["malicious"]
    return out


def inventory(session, user, *, page=1, vulnerable=False, **filters) -> dict:
    """One row per package and version, with everywhere it appears.

    Grouped rather than listed flat: an estate has the same version of the
    same library in fifty repositories, and fifty rows of it is not a list
    somebody can read.  The count is the link into the detail.
    """
    clauses = conditions(session, user, **filters)

    grouped = (session.query(
                   Component.name, Component.version, Component.ecosystem,
                   func.count(Component.id).label("places"),
                   func.count(distinct(Component.repository)).label("repositories"),
                   func.min(Component.licenses).label("licenses"),
                   func.min(Component.purl).label("purl"))
               .filter(*clauses)
               .group_by(Component.name, Component.version, Component.ecosystem)
               .order_by(func.lower(Component.name), Component.version))

    risk = _risk_by_package(vulnerability_index(session))

    def decorate(name, version, ecosystem, places, repositories, licenses, purl):
        found = risk.get(((name or "").strip().lower(), (version or "").strip()))
        return {
            "name": name, "version": version, "ecosystem": ecosystem,
            "ecosystem_name": pretty_ecosystem(ecosystem),
            "places": places, "repositories": repositories,
            "licenses": licenses or "", "purl": purl or "",
            "vulnerable": bool(found),
            "worst": (found or {}).get("worst", ""),
            "advisories": (found or {}).get("advisories", [])[:6],
            "known_exploited": (found or {}).get("known_exploited", False),
            "malicious": (found or {}).get("malicious", False),
        }

    if vulnerable:
        # The one filter the database cannot answer, so the paging happens
        # after it.  Bounded by how many advisories there are rather than by
        # how many packages, which is the smaller number by a long way.
        rows = [decorate(*row) for row in grouped.all()]
        rows = [row for row in rows if row["vulnerable"]]
        total = len(rows)
        pages = max(1, -(-total // PAGE_SIZE))
        page = min(max(1, int(page or 1)), pages)
        shown = rows[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]
    else:
        # The total rides along as a window count, so the grouping runs once
        # rather than once to count and again to page.
        def fetch(number):
            return (grouped.add_columns(func.count().over())
                    .limit(PAGE_SIZE).offset((number - 1) * PAGE_SIZE).all())

        page = max(1, int(page or 1))
        found = fetch(page)
        if not found and page > 1:
            # Past the last page there is no row to carry the total.
            total = grouped.count()
            page = max(1, -(-total // PAGE_SIZE))
            found = fetch(page)
        total = found[0][-1] if found else 0
        pages = max(1, -(-total // PAGE_SIZE))
        shown = [decorate(*row[:-1]) for row in found]

    return {"rows": shown, "total": total, "page": page, "pages": pages,
            "summary": summary(session, clauses)}


def where(session, user, name: str, version: str = "", ecosystem: str = "") -> list:
    """Every repository and branch one package sits on.

    This is the screen somebody opens with a package name a vendor has just
    emailed them.  A blank version means every version, because "which
    versions do we have" is the question that comes before "does it matter".
    """
    from app.core import rbac

    clauses = [func.lower(Component.name) == (name or "").strip().lower()]
    scope = rbac.component_scope(session, user)
    if scope is not None:
        clauses.append(scope)
    if version:
        clauses.append(Component.version == version.strip())
    if ecosystem:
        clauses.append(Component.ecosystem == ecosystem.strip())

    index = vulnerability_index(session)
    out = []
    for row in (session.query(Component).filter(*clauses)
                .order_by(Component.organization, Component.repository,
                          Component.branch, Component.version).all()):
        found = index.get((row.repository, (row.name or "").strip().lower(),
                           (row.version or "").strip())) or {}
        out.append({
            "organization": row.organization, "repository": row.repository,
            "branch": row.branch, "name": row.name, "version": row.version,
            "ecosystem": row.ecosystem,
            "ecosystem_name": pretty_ecosystem(row.ecosystem),
            "licenses": row.licenses or "", "purl": row.purl or "",
            "kind": row.kind or "", "connection": row.connection or "",
            "first_seen": row.first_seen_at, "last_seen": row.last_seen_at,
            "vulnerable": bool(found),
            "worst": found.get("worst", ""),
            "advisories": found.get("advisories", []),
            "known_exploited": found.get("known_exploited", False),
            "malicious": found.get("malicious", False),
        })
    return out


EXPORT_COLUMNS = [
    "organization", "repository", "branch", "package", "version", "ecosystem",
    "license", "purl", "kind", "connection", "vulnerable", "worst_severity",
    "advisories", "known_exploited", "malicious", "first_seen", "last_seen",
]


def rows_for_export(session, user, *, vulnerable=False, **filters) -> list:
    """The inventory flat, one row per package per place.

    Flat rather than grouped: a file gets read by something that wants to join
    it to its own list of repositories, and a count of fifty is no use to that.

    Columns rather than whole rows.  An unfiltered export of a real estate is
    a few hundred thousand components, and building an object for each one
    costs far more than the file does.
    """
    clauses = conditions(session, user, **filters)
    index = vulnerability_index(session)

    out = []
    for row in (session.query(
                    Component.organization, Component.repository,
                    Component.branch, Component.name, Component.version,
                    Component.ecosystem, Component.licenses, Component.purl,
                    Component.kind, Component.connection,
                    Component.first_seen_at, Component.last_seen_at)
                .filter(*clauses)
                .order_by(Component.organization, Component.repository,
                          Component.branch, func.lower(Component.name))
                .yield_per(2000)):
        (organization, repository, branch, name, version, ecosystem, licenses,
         purl, kind, connection, first_seen, last_seen) = row
        found = index.get((repository, (name or "").strip().lower(),
                           (version or "").strip())) or {}
        if vulnerable and not found:
            continue
        out.append({
            "organization": organization or "",
            "repository": repository or "",
            "branch": branch or "",
            "package": name or "",
            "version": version or "",
            "ecosystem": ecosystem or "",
            "license": licenses or "",
            "purl": purl or "",
            "kind": kind or "",
            "connection": connection or "",
            "vulnerable": "true" if found else "false",
            "worst_severity": found.get("worst", ""),
            "advisories": " ".join(found.get("advisories", [])),
            "known_exploited": "true" if found.get("known_exploited") else "false",
            "malicious": "true" if found.get("malicious") else "false",
            "first_seen": first_seen.isoformat() if first_seen else "",
            "last_seen": last_seen.isoformat() if last_seen else "",
        })
    return out


def choices(session, user) -> dict:
    """What to offer in the filter row, from what is actually there.

    Built from the inventory rather than written down, so an ecosystem nobody
    uses is not offered and one nobody expected still is.
    """
    from app.core import rbac

    clauses = []
    scope = rbac.component_scope(session, user)
    if scope is not None:
        clauses.append(scope)

    ecosystems = [
        {"value": value or "", "name": pretty_ecosystem(value), "count": number}
        for value, number in (session.query(Component.ecosystem,
                                            func.count(Component.id))
                              .filter(*clauses)
                              .group_by(Component.ecosystem)
                              .order_by(func.count(Component.id).desc()).all())]

    organizations = [value for (value,) in (
        session.query(Component.organization).filter(*clauses)
        .filter(Component.organization != "")
        .group_by(Component.organization)
        .order_by(Component.organization).all())]

    licenses = {}
    for value, number in (session.query(Component.licenses,
                                        func.count(Component.id))
                          .filter(*clauses)
                          .group_by(Component.licenses).all()):
        for one in [part.strip() for part in (value or "").split(",")]:
            if one:
                licenses[one] = licenses.get(one, 0) + number

    return {
        "ecosystems": ecosystems,
        "organizations": organizations,
        "licenses": sorted(licenses.items(), key=lambda pair: -pair[1])[:40],
    }


# The severities CycloneDX will accept in a rating.  The same words this uses
# everywhere else, which is not a coincidence worth relying on, so anything
# unexpected is left off rather than guessed at.
CDX_SEVERITIES = {"critical", "high", "medium", "low", "info", "none", "unknown"}

# The component types the schema allows.  An SBOM arrives with whatever the
# engine that wrote it called a thing, and one unrecognized word in here fails
# validation for the whole document, so anything unfamiliar becomes a library.
CDX_TYPES = {"application", "framework", "library", "container", "platform",
             "operating-system", "device", "device-driver", "firmware", "file",
             "machine-learning-model", "data", "cryptographic-asset"}

# A license identifier is only allowed to be one from the SPDX list, and a
# document offering one that is not on it is rejected outright rather than
# read with the license ignored.  These are the ones an estate is actually
# licensed under; everything else goes in as a name, which is always valid and
# says exactly as much to anybody reading it.
SPDX_IDS = {
    value.lower(): value for value in (
        "MIT", "MIT-0", "Apache-2.0", "Apache-1.1", "BSD-2-Clause",
        "BSD-3-Clause", "0BSD", "ISC", "MPL-2.0", "EPL-1.0", "EPL-2.0",
        "CDDL-1.0", "CDDL-1.1", "GPL-2.0-only", "GPL-2.0-or-later",
        "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1-only",
        "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
        "AGPL-3.0-only", "AGPL-3.0-or-later", "Artistic-2.0", "BSL-1.0",
        "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0", "OFL-1.1", "PostgreSQL",
        "Python-2.0", "PSF-2.0", "Ruby", "Unlicense", "WTFPL", "Zlib",
        "MS-PL", "OpenSSL", "BlueOak-1.0.0",
    )
}


def advisory_severities(session) -> dict:
    """-> {advisory id: the severity this graded it}.

    Read on its own rather than taken from the row a package sits on.  A
    package with a critical advisory and a low one has "critical" against it,
    and copying that onto both would put a severity on an advisory that nobody
    here ever gave it.  Whoever loads the document would have no way to tell
    the two apart, and the wrong one is the one that gets escalated.
    """
    out = {}
    rows = (session.query(Finding.vulnerability_id, Finding.severity)
            .filter(Finding.kind == FindingKind.DEPENDENCY)
            .filter(Finding.state != FindingState.FIXED)
            .filter(Finding.excepted.is_(False))
            .filter(Finding.vulnerability_id != "")
            .all())
    for advisory, severity in rows:
        if not advisory:
            continue
        grade = getattr(severity, "value", severity) or "unknown"
        if grade not in CDX_SEVERITIES:
            grade = "unknown"
        known = out.get(advisory)
        if not known or SEVERITY_RANK.get(grade, 9) < SEVERITY_RANK.get(known, 9):
            out[advisory] = grade
    return out


def _cdx_licenses(text: str) -> list:
    """A comma separated license field as CycloneDX license entries.

    A license somebody can act on is half of what a bill of materials is for,
    so what an SBOM stated is carried through here rather than summarized
    away: the identifier where SPDX has one, the expression where the package
    is licensed under a combination, and the plain name where it is neither.

    An expression goes in on its own, because that is what the format says a
    licenses array holding one may contain, and because "MIT OR Apache-2.0"
    listed as two licenses reads as a package licensed under both.
    """
    parts = [one.strip() for one in (text or "").split(",") if one.strip()]
    if len(parts) == 1 and any(word in f" {parts[0]} "
                               for word in (" OR ", " AND ", " WITH ")):
        return [{"expression": parts[0]}]

    out, seen = [], set()
    for one in parts:
        if one.lower() in seen:
            continue
        seen.add(one.lower())
        identifier = SPDX_IDS.get(one.lower())
        out.append({"license": {"id": identifier}} if identifier
                   else {"license": {"name": one}})
    return out


def _package_ref(row) -> str:
    """What the dependency graph calls one package version.

    The purl when there is one, because that is the identifier every other
    tool will use for the same package and a document that invents its own
    cannot be joined to anything.  Only the rows an SBOM gave no purl need a
    made up reference, and those are named so it is obvious which they are.
    """
    purl = (row.get("purl") or "").strip()
    if purl:
        return purl
    name = (row.get("package") or "").strip()
    version = (row.get("version") or "").strip()
    ecosystem = (row.get("ecosystem") or "generic").strip() or "generic"
    return f"gcr:package/{ecosystem}/{name}" + (f"@{version}" if version else "")


def _place_ref(row) -> str:
    """What the graph calls one branch of one repository."""
    repository = (row.get("repository") or "").strip() or "unknown"
    branch = (row.get("branch") or "").strip()
    return f"gcr:repository/{repository}" + (f"@{branch}" if branch else "")


def cyclonedx(rows, *, scope="", filters=None, severities=None) -> dict:
    """The filtered inventory as a CycloneDX document.  -> the document.

    Built from the same flat rows the CSV is, so a file and a document of the
    same search describe the same software.

    The point of it is the `dependencies` array.  A list of components with no
    graph is a document plenty of tools will accept and then show as nothing:
    they read the graph, not the list.  There is a real graph to write here
    even though the SBOMs this reads never carried edges between packages,
    because the estate has a shape of its own.  The export is one thing, it
    holds repositories on branches, and each of those holds packages.  Saying
    that is honest and it is what makes the document useful, where a single
    root depending on eleven thousand packages at once would not be.

    What it does not do is invent edges between packages.  Nothing in the
    inventory records which package pulled in which, so every package version
    is a leaf with an empty `dependsOn`.  That is the difference between
    "nothing was recorded" and "nothing depends on it", and an empty array
    with the reference still present says the first one.
    """
    import uuid

    from app.config import APP_NAME, VERSION

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    severities = severities or {}

    root = "gcr:inventory"
    places, packages, edges = {}, {}, {}
    advisories = {}

    for row in rows:
        name = (row.get("package") or "").strip()
        if not name:
            continue
        ref = _package_ref(row)
        component = packages.get(ref)
        if component is None:
            kind = (row.get("kind") or "").strip().lower()
            component = {
                "bom-ref": ref,
                "type": kind if kind in CDX_TYPES else "library",
                "name": name,
            }
            version = (row.get("version") or "").strip()
            if version:
                component["version"] = version
            if row.get("purl"):
                component["purl"] = row["purl"]
            packages[ref] = component

        # A package is one component here however many repositories hold it,
        # and the SBOMs behind those places do not all state a license.  One
        # that did is the answer for all of them: dropping it because the
        # first place read happened to be silent would lose a license this
        # already knows, on the document people ask for precisely to find
        # out what they are shipping under.
        stated = _cdx_licenses(row.get("license", ""))
        if stated:
            known = component.setdefault("licenses", [])
            for one in stated:
                if one not in known:
                    known.append(one)

        # The two things somebody is on this page to find out, kept on the
        # component rather than only in the vulnerabilities below, because a
        # compromised release usually has no advisory to hang them off yet.
        for field, label in (("malicious", "gcr:malicious"),
                             ("known_exploited", "gcr:known-exploited")):
            if str(row.get(field, "")).lower() == "true":
                marks = component.setdefault("properties", [])
                if not any(mark["name"] == label for mark in marks):
                    marks.append({"name": label, "value": "true"})

        place = _place_ref(row)
        if place not in places:
            entry = {
                "bom-ref": place,
                "type": "application",
                "name": (row.get("repository") or "").strip() or "unknown",
            }
            branch = (row.get("branch") or "").strip()
            if branch:
                entry["version"] = branch
            marks = [{"name": "gcr:repository", "value": entry["name"]}]
            if branch:
                marks.append({"name": "gcr:branch", "value": branch})
            if row.get("organization"):
                marks.append({"name": "gcr:organization",
                              "value": row["organization"]})
            if row.get("connection"):
                marks.append({"name": "gcr:connection", "value": row["connection"]})
            entry["properties"] = marks
            places[place] = entry
            edges[place] = {}
        edges[place][ref] = True

        for advisory in (row.get("advisories") or "").split():
            advisories.setdefault(advisory, {})[ref] = True

    # An expression covers the whole package on its own, so a package that
    # arrived with one and a bare license from somewhere else keeps the
    # expression.  "MIT OR Apache-2.0" alongside "MIT" would read as a package
    # licensed under both, which is the opposite of what an OR says.
    for component in packages.values():
        licenses = component.get("licenses") or []
        expressions = [one for one in licenses if "expression" in one]
        if expressions and len(licenses) > 1:
            component["licenses"] = expressions[:1]

    metadata_properties = [{"name": f"gcr:filter:{key}", "value": str(value)}
                           for key, value in sorted((filters or {}).items())
                           if value not in ("", None, False)]
    metadata_properties.append({"name": "gcr:packages",
                                "value": str(len(packages))})
    metadata_properties.append({"name": "gcr:places", "value": str(len(places))})
    # Said out loud rather than left to be counted.  How much of a bill of
    # materials has no license on it is the first thing anybody using it for
    # license work needs to know, and a document that does not say invites
    # the reader to assume the answer is none.
    metadata_properties.append(
        {"name": "gcr:packages-with-no-license",
         "value": str(sum(1 for one in packages.values()
                          if not one.get("licenses")))})

    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {"components": [{"type": "application", "name": APP_NAME,
                                      "version": VERSION}]},
            "component": {
                "bom-ref": root,
                "type": "application",
                "name": f"{APP_NAME} software inventory",
                "version": scope or "all",
                "description": (
                    "Every package in the searched estate, and the repository "
                    "and branch each one sits on."),
                "properties": metadata_properties,
            },
        },
        "components": (sorted(places.values(), key=lambda one: one["bom-ref"])
                       + sorted(packages.values(),
                                key=lambda one: one["bom-ref"])),
        # Every reference in the document appears here exactly once, including
        # the leaves.  A tool reading the graph walks it by looking each
        # reference up, and one that is missing reads as a broken document
        # rather than as a package with nothing under it.
        "dependencies": (
            [{"ref": root, "dependsOn": sorted(places)}]
            + [{"ref": place, "dependsOn": sorted(edges[place])}
               for place in sorted(places)]
            + [{"ref": ref, "dependsOn": []} for ref in sorted(packages)]),
    }

    if advisories:
        document["vulnerabilities"] = [
            {
                "id": advisory,
                **({"ratings": [{"severity": severities[advisory]}]}
                   if severities.get(advisory) in CDX_SEVERITIES else {}),
                "affects": [{"ref": ref} for ref in sorted(affected)],
            }
            for advisory, affected in sorted(advisories.items())
        ]
    return document
