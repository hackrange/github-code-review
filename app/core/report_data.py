"""What a security assessment is actually about, assembled from the findings.

The first version of the report drew the trends page onto paper.  It was
accurate and it was worth very little: a reader learned that a number had
moved and nothing about what the number was made of, which repository was in
trouble, or what to do on Monday.

So this reads the findings themselves.  Everything here is scoped and filtered
exactly as the page was, and everything is a fact already in the database.
Nothing is estimated, nothing is rounded up for effect, and where a number is
not known it says so rather than leaving a zero to be read as good news.

The ordering is the argument.  A credential somebody has proved still works
outranks a thousand advisories nobody can reach, because one of those is a way
in today and the others are a queue.  So the report opens with what is
provably live, then what is exploitable, then the largest pieces of work, and
only then the totals.  A report that opens with totals teaches the reader that
the totals are the point.
"""

from __future__ import annotations

from sqlalchemy import func

from app.core.models import Finding, FindingKind, FindingState, Severity

# How many rows a section prints before it stops being a list somebody reads
# and becomes an appendix nobody does.
TOP_N = 12

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO, Severity.UNKNOWN]


def _scoped(query, organization="", repository="", branch="", connection=""):
    """The same narrowing the page did, applied to findings."""
    query = query.filter(Finding.state == FindingState.OPEN)
    if connection:
        query = query.filter(Finding.connection == connection)
    if organization:
        query = query.filter(Finding.organization == organization)
    if repository:
        query = query.filter(Finding.repository == repository)
    if branch:
        query = query.filter(Finding.branch == branch)
    return query


def coverage(query) -> dict:
    """What this report is actually about, in repositories and branches."""
    return {
        "repositories": query.with_entities(
            func.count(func.distinct(Finding.repository))).scalar() or 0,
        "organizations": query.with_entities(
            func.count(func.distinct(Finding.organization))).scalar() or 0,
        "branches": query.with_entities(
            func.count(func.distinct(Finding.branch))).scalar() or 0,
        "findings": query.count(),
        "last_seen": query.with_entities(
            func.max(Finding.last_found_at)).scalar(),
    }


def by_severity(query) -> dict:
    """Advisory counts per severity, in a fixed order so a table never moves."""
    counts = {level.value: 0 for level in SEVERITY_ORDER}
    for severity, total in (query.with_entities(
            Finding.severity, func.count(Finding.id))
            .group_by(Finding.severity).all()):
        counts[getattr(severity, "value", str(severity))] = total
    return counts


def by_kind(query) -> list:
    """Where the problems are, by the kind of thing they are.

    Four different jobs live under one word.  A leaked credential is revoked,
    a weak line of code is rewritten, a vulnerable package is upgraded and an
    unsafe setting is changed, and the people who do those are often not the
    same people.  A report that does not separate them gives everybody a
    number that is mostly somebody else's work.
    """
    labels = {
        FindingKind.CREDENTIAL: ("Credentials in the code",
                                 "Revoke and rotate.  A committed credential "
                                 "is exposed to everyone who can read the "
                                 "repository and to its whole history."),
        FindingKind.DEPENDENCY: ("Vulnerable dependencies",
                                 "Upgrade the package.  One upgrade usually "
                                 "answers several advisories at once."),
        FindingKind.CODE: ("Weaknesses in the code",
                           "Fix in the source.  These need a developer who "
                           "knows the code, not a version bump."),
        FindingKind.MISCONFIGURATION: ("Unsafe settings",
                                       "Change the setting in the "
                                       "infrastructure files and redeploy."),
    }
    out = []
    for kind, total in (query.with_entities(Finding.kind, func.count(Finding.id))
                        .group_by(Finding.kind).all()):
        name, advice = labels.get(kind, (str(kind), ""))
        serious = (query.filter(Finding.kind == kind)
                   .filter(Finding.severity.in_(
                       [Severity.CRITICAL, Severity.HIGH])).count())
        out.append({"kind": getattr(kind, "value", str(kind)), "name": name,
                    "advice": advice, "total": total, "serious": serious})
    out.sort(key=lambda row: row["serious"], reverse=True)
    return out


def urgent(query) -> dict:
    """The things that are not a queue.

    Each of these is a fact somebody established rather than a rule firing.  A
    credential the provider confirmed still works is a way in that exists now.
    A package that is itself an attack is not a version to bump.  A
    vulnerability on the exploited list is being used somewhere in the world
    today.

    They are counted separately from everything else because mixing them into
    a severity total is how they get lost: thirty five malicious packages
    inside twelve thousand criticals is a rounding error on the page and a
    breach in the estate.
    """
    live = query.filter(Finding.verified.is_(True))
    bad = query.filter(Finding.malicious.is_(True))
    hot = query.filter(Finding.known_exploited.is_(True))

    def sample(rows, limit=TOP_N):
        return rows.order_by(Finding.severity.asc(),
                             Finding.last_found_at.desc()).limit(limit).all()

    return {
        "live_credentials": {"count": live.count(), "rows": sample(live)},
        "malicious_packages": {"count": bad.count(), "rows": sample(bad)},
        "known_exploited": {"count": hot.count(), "rows": sample(hot)},
    }


def top_actions(db, query, limit=TOP_N) -> list:
    """The largest single pieces of work, and what each one clears.

    Grouped the way the findings list groups them, so the number here is the
    number somebody sees when they click through.  Sorted by how much one
    action removes, because that is the question this section answers: if we
    do one thing this week, which one.
    """
    from app.core import grouping

    head, alone = grouping._key_columns()
    rank = grouping._rank_column()
    keys = (Finding.repository, Finding.branch, head,
            Finding.package_version, Finding.fixed_in, Finding.image_ref, alone)

    rows = (query.filter(Finding.kind == FindingKind.DEPENDENCY)
            .with_entities(*keys,
                           func.max(rank).label("worst"),
                           func.count(Finding.id).label("advisories"))
            .group_by(*keys)
            .order_by(func.max(rank).desc(), func.count(Finding.id).desc())
            .limit(limit).all())

    out = []
    for repo, branch, package, version, fixed, image, _alone, worst, advisories in rows:
        level = grouping.BY_RANK.get(int(worst or 0))
        out.append({
            "repository": repo, "branch": branch, "package": package or "",
            "version": version or "", "fixed_in": fixed or "",
            "image": image or "", "advisories": advisories,
            "severity": level.value if level else "unknown",
        })
    return out


def worst_findings(query, limit=TOP_N) -> list:
    """The individual findings at the top of the queue.

    Ordered by the risk score where there is one, because that is the only
    total order this product produces, and by severity where there is not.  A
    score of zero means nothing has been worked out for it yet, which is not
    the same as a low score, so those sort last rather than first.
    """
    scored = (query.filter(Finding.risk_score > 0)
              .order_by(Finding.risk_score.desc())
              .limit(limit).all())
    if len(scored) >= limit:
        return scored
    seen = {row.id for row in scored}
    rest = (query.filter(Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]))
            .order_by(Finding.severity.asc(), Finding.last_found_at.desc())
            .limit(limit * 2).all())
    for row in rest:
        if row.id not in seen:
            scored.append(row)
        if len(scored) >= limit:
            break
    return scored


def hotspots(query, axis="repository", limit=TOP_N) -> list:
    """The heatmap, from the findings rather than from the daily rollup.

    Built here rather than read from the trend table because a report drills
    to a branch and the rollup only goes that far by day.  Same shape either
    way, so the page and the report show the same picture.
    """
    column = {"organization": Finding.organization,
              "repository": Finding.repository,
              "branch": Finding.branch}.get(axis, Finding.repository)

    counts = {}
    for name, severity, total in (query.with_entities(
            column, Finding.severity, func.count(Finding.id))
            .group_by(column, Finding.severity).all()):
        entry = counts.setdefault(name or "(none)",
                                  {level.value: 0 for level in SEVERITY_ORDER})
        entry[getattr(severity, "value", str(severity))] = total

    rows = []
    for name, entry in counts.items():
        row = dict(entry)
        row["name"] = name
        row["total"] = sum(entry.values())
        # Worst first within a row, so the sort below is about seriousness
        # rather than about volume: two hundred informational findings should
        # not outrank three criticals.
        row["weight"] = (entry["critical"] * 1000 + entry["high"] * 100
                         + entry["medium"] * 10 + entry["low"])
        rows.append(row)
    rows.sort(key=lambda r: r["weight"], reverse=True)
    return rows[:limit]


def themes(query) -> list:
    """Observations that hold across the whole set, each with its number.

    These are the sentences somebody would write after reading the list, and
    every one of them is checked against the data before it is included.  A
    theme that does not apply is left out rather than printed with a zero,
    because a report full of "0 of these" reads as a form nobody filled in.
    """
    total = query.count()
    if not total:
        return []

    found = []

    patched = query.filter(Finding.base_upgraded.is_(True)).count()
    if patched:
        found.append({
            "title": "Some of this is already handled by the build",
            "count": patched,
            "detail": "%d finding%s %s reported against a base container image "
                      "that the build patches after pulling it.  The version "
                      "that ships is probably not the one reported.  These stay "
                      "on the list because an image is only as current as the "
                      "day it was last built, so rebuilding regularly is what "
                      "keeps that true."
                      % (patched, "" if patched == 1 else "s",
                         "is" if patched == 1 else "are"),
        })

    set_aside = query.filter(Finding.triage.in_(
        ["not_applicable", "advisory", "third_party"])).count()
    if set_aside:
        found.append({
            "title": "Some of it does not apply here",
            "count": set_aside,
            "detail": "%d finding%s been set aside automatically, for example "
                      "a rule written for one framework firing on an "
                      "application that does not use it.  They are kept and "
                      "counted, not deleted, so the decision can be reviewed."
                      % (set_aside, " has" if set_aside == 1 else "s have"),
        })

    unreachable = query.filter(Finding.reachability == "unlikely").count()
    if unreachable:
        found.append({
            "title": "Some of it is in code that never runs",
            "count": unreachable,
            "detail": "%d %s in a package that nothing in the source imports.  "
                      "The vulnerability is real and the path to it is not, so "
                      "these are lower priority than their rating suggests."
                      % (unreachable, "is" if unreachable == 1 else "are"),
        })

    creds = query.filter(Finding.kind == FindingKind.CREDENTIAL).count()
    if creds:
        live = query.filter(Finding.verified.is_(True)).count()
        found.append({
            "title": "Credentials committed to source control",
            "count": creds,
            "detail": ("%d credential%s found in the code or its history.  %s  "
                       "A credential in a repository has to be treated as "
                       "exposed and rotated, whether or not it still works: "
                       "removing it from the current files does not remove it "
                       "from the history."
                       % (creds, "" if creds == 1 else "s",
                          ("%d of them %s confirmed still working."
                           % (live, "was" if live == 1 else "were"))
                          if live else
                          "None has been confirmed as still working, which is "
                          "not the same as none working.")),
        })

    return found


def assemble(db, base_query, organization="", repository="", branch="",
             connection="", axis="repository") -> dict:
    """Everything the document needs, from one scoped query."""
    query = _scoped(base_query, organization, repository, branch, connection)
    return {
        "coverage": coverage(query),
        "severity": by_severity(query),
        "kinds": by_kind(query),
        "urgent": urgent(query),
        "actions": top_actions(db, query),
        "worst": worst_findings(query),
        "hotspots": hotspots(query, axis=axis),
        "themes": themes(query),
    }
