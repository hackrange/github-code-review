"""One row per thing somebody would actually do about it.

A distribution ships one source package as many binary ones, and a flaw in the
source is reported once against each binary that came out of it.  One problem
in util-linux arrives as eight package names times seven advisories: fifty six
rows, one `apt upgrade`.  Multiply that across an estate and the findings list
stops being a list of problems and becomes a list of facts about problems,
which is not the same thing and is much harder to work through.

So the list groups on the action.  The action is "move this package from the
version that is here to the version that fixes it", and every advisory that
one move answers belongs on one row.

Three rules this keeps, because without them a shorter list is a worse one:

Nothing is merged away.  Every advisory stays its own row in the database with
its own state, its own waiver and its own severity override.  This is a way of
looking at them, not a way of storing them, and the difference is that a
grouped view can be got wrong and fixed, while a grouped ingest loses the
per advisory decisions people have already made and cannot get them back
without a rescan.

The group takes the worst of what is in it, never an average.  One entry on
the exploited list among thirty quiet ones makes the whole row urgent, and a
mean would bury exactly the thing the row exists to surface.

A partial fix is visible.  A version that answers six advisories out of seven
is a different situation from one that answers all seven, and a group that
only shows a count hides which one it is.

Grouping on severity was the other candidate and it is the wrong axis in both
directions at once: it merges two unrelated packages that happen to share a
word, and it splits one package into several rows the moment one of its
advisories is rescored.  The list would get less stable exactly when a finding
got more serious.
"""

from __future__ import annotations

from sqlalchemy import case, func, literal

from app.core.models import Finding, FindingKind, Severity

# Worst first.  Unknown sits at the bottom rather than the top: a grade nobody
# supplied is not a reason to shout, and the confidence and reachability
# columns are where genuine uncertainty is expressed.
RANK = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
        Severity.LOW: 2, Severity.INFO: 1, Severity.UNKNOWN: 0}

BY_RANK = {v: k for k, v in RANK.items()}

# Only these group.  A credential and a code finding are each their own piece
# of work and collapsing two of them would hide a real second thing to fix.
GROUPABLE = (FindingKind.DEPENDENCY,)


def _rank_column():
    """Severity as a number the database can take a maximum of."""
    return case(*[(Finding.severity == level, score)
                  for level, score in RANK.items()], else_=0)


def _key_columns():
    """What makes two findings the same job, as columns to group on.

    The source package rather than the binary one, because that is the thing
    an upgrade names.  It falls back to the package name, filled in at ingest
    for everything with no separate source, so this is never null and an
    ecosystem like npm groups by the name people would type.

    Two columns rather than one string, and no concatenation anywhere: the two
    databases this runs on spell that differently and a view that works on one
    and quietly returns nonsense on the other is worse than not having it.
    The second column is the id for anything not groupable, which puts each of
    those in a group of its own and lets one query serve both kinds.
    """
    head = case((Finding.kind.in_(GROUPABLE),
                 func.coalesce(Finding.package_source, Finding.package_name)),
                else_=literal(""))
    alone = case((Finding.kind.in_(GROUPABLE), literal(0)), else_=Finding.id)
    return head, alone


def group_key(finding) -> tuple:
    """The same key, in Python, for a finding already loaded."""
    if finding.kind in GROUPABLE:
        head = (getattr(finding, "package_source", "")
                or getattr(finding, "package_name", "") or "")
    else:
        head = "id:%s" % finding.id
    return (finding.repository or "", finding.branch or "", head,
            getattr(finding, "package_version", "") or "",
            getattr(finding, "fixed_in", "") or "",
            getattr(finding, "image_ref", "") or "")


def summarize(members: list) -> dict:
    """What a group row says, worked out from the findings in it.

    `members` is every finding in the group, worst first is not assumed.
    """
    if not members:
        return {}

    worst = max(members, key=lambda f: RANK.get(f.severity, 0))
    advisories = []
    for f in members:
        name = (f.vulnerability_id or f.rule or "").strip()
        if name and name not in advisories:
            advisories.append(name)

    # A fix that does not answer everything in the group.  Worth saying out
    # loud: "upgrade and you are done" and "upgrade and five of these remain"
    # are different instructions.
    unfixed = [f for f in members if not (f.fixed_in or "").strip()]

    scores = [f.cvss_score for f in members if f.cvss_score is not None]
    epss = [f.epss_score for f in members if f.epss_score is not None]

    return {
        "lead": worst,
        "count": len(members),
        "severity": worst.severity,
        "advisories": advisories,
        "exploited": [f for f in members if getattr(f, "known_exploited", False)],
        "unfixed": len(unfixed),
        "partial": bool(unfixed) and len(unfixed) != len(members),
        "worst_cvss": max(scores) if scores else None,
        "worst_epss": max(epss) if epss else None,
        # The ids behind the row, so a tick box on a group can act on all of
        # them without the page having to ask again.
        "ids": [f.id for f in members],
    }


def group(findings: list) -> list:
    """-> [summary], in the order the findings arrived.

    Order is preserved deliberately: the caller has already sorted, and a
    group takes the position of its first member, so a grouped list is the
    ungrouped list with the repeats folded up rather than a different ordering
    somebody has to relearn.
    """
    order = []
    buckets = {}
    for f in findings:
        key = group_key(f)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(f)
    return [summarize(buckets[k]) for k in order]


def count_groups(query) -> int:
    """How many rows the grouped view has, without loading any of them.

    The page needs this for paging and for saying how many there are, and
    counting in Python would mean fetching everything first, which is the
    thing paging exists to avoid.
    """
    key = _key_column()
    grouped = (query.with_entities(
        Finding.repository, Finding.branch, key,
        Finding.package_version, Finding.fixed_in, Finding.image_ref)
        .group_by(Finding.repository, Finding.branch, key,
                  Finding.package_version, Finding.fixed_in, Finding.image_ref))
    return grouped.count()


def page_of_groups(db, query, offset: int, limit: int) -> tuple:
    """-> (summaries, total groups) for one page, grouped in the database.

    Grouping a page after fetching it is the obvious implementation and it is
    wrong: a group whose members straddle a page boundary comes out as two
    half groups, one at the bottom of one page and one at the top of the next,
    each carrying a count that is not true.  So the grouping and the paging
    happen in the same statement, and the findings are fetched afterwards for
    the groups that page actually holds.
    """
    head, alone = _key_columns()
    rank = _rank_column()
    keys = (Finding.repository, Finding.branch, head,
            Finding.package_version, Finding.fixed_in, Finding.image_ref, alone)

    grouped = query.with_entities(
        *keys,
        func.max(rank).label("worst"),
        func.max(Finding.risk_score).label("score"),
    ).group_by(*keys)

    total = grouped.count()

    rows = (grouped.order_by(func.max(rank).desc(),
                             func.max(Finding.risk_score).desc(),
                             Finding.repository.asc())
            .offset(offset).limit(limit).all())
    if not rows:
        return [], total

    # Everything in those groups, in one statement.  An OR of the key tuples
    # rather than a fetch per group, which on a page of a hundred would be a
    # hundred round trips.
    from sqlalchemy import and_, or_
    clauses = []
    for r in rows:
        repo, branch, name, version, fixed, image, one = r[0:7]
        parts = [Finding.repository == repo, Finding.branch == branch,
                 Finding.package_version == version,
                 Finding.fixed_in == fixed, Finding.image_ref == image]
        if one:                      # a finding that groups with nothing
            parts.append(Finding.id == one)
        else:
            parts.append(func.coalesce(Finding.package_source,
                                       Finding.package_name) == name)
            parts.append(Finding.kind.in_(GROUPABLE))
        clauses.append(and_(*parts))

    members = query.filter(or_(*clauses)).all()

    # Back into the page order the group query decided.
    order = {tuple(r[0:7]): i for i, r in enumerate(rows)}
    buckets = {}
    for f in members:
        k = (f.repository or "", f.branch or "",
             ((f.package_source or f.package_name or "")
              if f.kind in GROUPABLE else ""),
             f.package_version or "", f.fixed_in or "", f.image_ref or "",
             0 if f.kind in GROUPABLE else f.id)
        buckets.setdefault(k, []).append(f)

    out = []
    for key in sorted(buckets, key=lambda k: order.get(k, 10 ** 9)):
        out.append(summarize(buckets[key]))
    return out, total


def counts_by_severity(query) -> tuple:
    """-> (by action, by advisory).  Two dictionaries keyed on severity value.

    Both, always, and never one presented as the other.  They answer two
    questions that both get asked and have different right answers:

    How much work is there.  That is actions, and it is the number a team
    plans against.  Forty six thousand findings is not a backlog anybody can
    reason about; it is a number that makes people stop looking.

    Are we affected by CVE-2026-13595.  That is advisories, and an auditor
    asking it will not accept "it is inside a group somewhere".  It is also
    the figure that goes outside the building.

    They do not reconcile column by column and are not meant to.  A group
    takes the worst severity in it, so a group counted critical can hold six
    mediums, and neither table is a subset of the other.  That is the correct
    behavior, because one entry on the exploited list among thirty quiet ones
    has to make the row urgent, and it is the reason both numbers are shown
    rather than one being derived from the other on the page.
    """
    from app.core.models import Severity as _Severity

    advisories = {s.value: 0 for s in _Severity}
    for severity, total in (query.with_entities(
            Finding.severity, func.count(Finding.id))
            .group_by(Finding.severity).all()):
        advisories[getattr(severity, "value", str(severity))] = total

    head, alone = _key_columns()
    rank = _rank_column()
    keys = (Finding.repository, Finding.branch, head,
            Finding.package_version, Finding.fixed_in, Finding.image_ref, alone)

    actions = {s.value: 0 for s in _Severity}
    grouped = (query.with_entities(func.max(rank).label("worst"))
               .group_by(*keys).subquery())
    for worst, total in (query.session.query(
            grouped.c.worst, func.count()).group_by(grouped.c.worst).all()):
        level = BY_RANK.get(int(worst or 0))
        if level is not None:
            actions[level.value] = total
    return actions, advisories
