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

import json

from sqlalchemy import func, select

from app.core import branch_scope
from app.core.models import (Finding, FindingKind, FindingState, Repository,
                             Severity)

# How many rows a section prints before it stops being a list somebody reads
# and becomes an appendix nobody does.
TOP_N = 12

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO, Severity.UNKNOWN]


def _archived_names():
    """The repositories the host has retired, as something to filter against.

    A select rather than a list of names, so this needs no session of its own
    and the database does the work in one statement instead of shipping a few
    thousand names back to be sent straight out again.
    """
    return select(Repository.full_name).where(
        Repository.archived.is_(True),
        Repository.full_name.isnot(None))


def _tally(model):
    """How many findings a row stands for: one on Finding, a count on a summary."""
    if model is None or model is Finding:
        return func.count(Finding.id)
    return func.sum(model.findings)


def _scoped(query, organization="", repository="", branch="", connection="",
            include_archived=False, model=None):
    """The same narrowing the page did, applied to findings.

    Archived repositories are set aside here, the same way the dashboard sets
    them aside.  Code that can no longer be changed is not work anybody can
    do, and a risk matrix that counts it is a picture of a problem nobody is
    allowed to solve.  Left in, those cells never empty however much gets
    fixed, which is how a chart stops being read.

    Set aside is not hidden.  The findings stay open, stay in the findings
    list, stay in both report files and stay in the export, and every caller
    of this can ask for the count that was left out through `archived_aside`
    so that the page can say so out loud.  Pass include_archived to get the
    unfiltered set, which is what that count is worked out from.
    """
    model = model or Finding
    query = query.filter(model.state == FindingState.OPEN)
    # Only on branches that do not ship is off every number, not set aside
    # and counted the way archived is.  See app.core.scan_scope.  The branch
    # name summary has no such column; it only lists names for a picker.
    if hasattr(model, "out_of_scope"):
        query = query.filter(model.out_of_scope.is_(False))
    if not include_archived:
        query = query.filter(model.repository.notin_(_archived_names()))
    if connection:
        query = query.filter(model.connection == connection)
    if organization:
        query = query.filter(model.organization == organization)
    if repository:
        query = query.filter(model.repository == repository)
    if branch:
        # Matching the branch list needs the findings themselves.
        assert model is Finding, "a branch filter needs the findings table"
        # Both readings of what branch a finding is on.  See branch_scope.
        query = query.filter(branch_scope.matches(branch))
    return query


def archived_aside(query, organization="", repository="", branch="",
                   connection="", model=None) -> int:
    """How many open findings this scope left out because the host retired them.

    Shown wherever the scoped figures are, because a number that quietly got
    smaller is the thing nobody notices and later cannot explain.
    """
    model = model or Finding
    scoped = _scoped(query, organization, repository, branch, connection,
                     include_archived=True, model=model)
    return int(scoped.filter(model.repository.in_(_archived_names()))
               .with_entities(_tally(model)).scalar() or 0)


def resolved_since(base_query, organization="", repository="", branch="",
                   connection="") -> int:
    """How many findings in this scope have been closed rather than are open.

    Without this a scope where everything was fixed produces a report full of
    zeroes, which reads as a blank form or a broken filter.  It is neither: it
    is the best outcome this product can report, and it should say so.
    """
    from app.core.models import FindingState as _State

    query = base_query.filter(Finding.state == _State.FIXED)
    if connection:
        query = query.filter(Finding.connection == connection)
    if organization:
        query = query.filter(Finding.organization == organization)
    if repository:
        query = query.filter(Finding.repository == repository)
    if branch:
        query = query.filter(branch_scope.matches(branch))
    return query.count()


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


def _by_branch(query) -> dict:
    """Severity counts per branch, with a finding counted on every branch.

    The one stamped branch is only the first name git handed back, so counting
    by it alone leaves master reading zero while develop carries the lot, and
    the developer looking at master concludes there is nothing to fix there.
    There is: it is the same code on both.

    Counted row by row rather than grouped in the database.  The branch list is
    a text column, and grouping on a long one truncates it, which would quietly
    fold two different sets of branches into a single row.  The branch axis
    only ever covers one repository, so this reads a few hundred rows.
    """
    counts = {}
    for listed, primary, severity in query.with_entities(
            Finding.branches, Finding.branch, Finding.severity).all():
        try:
            names = [str(name) for name in (json.loads(listed or "[]") or [])
                     if name]
        except (TypeError, ValueError):
            names = []
        level = getattr(severity, "value", str(severity))
        for name in (names or [primary or ""]):
            entry = counts.setdefault(
                name or "(none)",
                {grade.value: 0 for grade in SEVERITY_ORDER})
            entry[level] = entry.get(level, 0) + 1
    return counts


def hotspots(query, axis="repository", limit=TOP_N, model=None) -> list:
    """The heatmap, from the findings rather than from the daily rollup.

    Built here rather than read from the trend table because a report drills
    to a branch and the rollup only goes that far by day.  Same shape either
    way, so the page and the report show the same picture.

    `limit` of None returns every row.  A report shows the busiest handful
    because a document has a page size; a screen that sorts and pages has to
    be given the whole set or it would be paging over a truncation.
    """
    model = model or Finding
    if axis == "branch":
        counts = _by_branch(query)
    else:
        column = {"organization": model.organization,
                  "repository": model.repository}.get(axis, model.repository)
        counts = {}
        for name, severity, total in (query.with_entities(
                column, model.severity, _tally(model))
                .group_by(column, model.severity).all()):
            total = int(total or 0)
            entry = counts.setdefault(
                name or "(none)",
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
    return rows if limit is None else rows[:limit]


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
        "resolved": resolved_since(base_query, organization, repository,
                                   branch, connection),
        "posture": posture(query),
        "matrix": risk_matrix(query),
        "detail": by_class(query, levels=("critical", "high")),
        "medium_detail": by_class(query, levels=("medium",), limit=6, examples=1),
        "coverage": coverage(query),
        "severity": by_severity(query),
        "kinds": by_kind(query),
        "urgent": urgent(query),
        "actions": top_actions(db, query),
        "worst": worst_findings(query),
        "hotspots": hotspots(query, axis=axis),
        "themes": themes(query),
    }


# --- the risk matrix ---------------------------------------------------------
#
# The grid a security team actually recognizes: what it would cost against how
# likely it is, with the cell colored by what those two together mean.
#
# A shaded table of counts is decoration.  It shows where the numbers are
# large, which is usually where the codebase is large.  This is different
# because the two axes are asked separately and answered from different
# evidence: impact from what the system holds, likelihood from what anybody
# has actually established.  A critical in a package nothing imports and a
# medium somebody proved live land in different cells, which is the entire
# point and is invisible in a severity total.
#
# The cell color is not chosen here.  It comes from the same matrix that
# decides the grade, so the picture and the number can never disagree.

IMPACT_ROWS = ("high", "medium", "low")
LIKELIHOOD_COLUMNS = ("unlikely", "possible", "likely", "happening now")


def risk_matrix(query, model=None) -> dict:
    """-> the grid, its coverage, and what is not on it.

    Only findings carrying both axes in the risk vocabulary are placed.  Rows
    from before the model existed carry the engine's own words and are counted
    as unplaced rather than guessed into a cell, because putting them
    somewhere plausible is how a picture starts lying.
    """
    from app.core.models import Severity as _Severity
    from app.core.risk import MATRIX

    # Both the count and the worst grade actually carried by what is in each
    # cell.
    #
    # The color used to come from the matrix, on the reasoning that the
    # picture then cannot disagree with the number.  It can, and it did: a
    # cell reading high impact and unlikely was colored medium because that
    # is what the model says the pair means, while every one of the hundred
    # and thirty six findings in it was graded info.  The pair is a
    # recommendation and the grade is what stands after triage and after
    # anybody has had their say, and presenting the first as though it were
    # the second is the picture telling a story the list does not.
    #
    # So the color is what the findings are.  The model's own answer is kept
    # beside it, because where the two differ that is worth seeing rather than
    # smoothing over.
    from app.core.grouping import RANK

    counts = {}
    worst_at = {}
    model = model or Finding
    for impact, likelihood, severity, total in (query.with_entities(
            model.impact, model.likelihood, model.severity, _tally(model))
            .group_by(model.impact, model.likelihood, model.severity).all()):
        total = int(total or 0)
        key = ((impact or "").lower(), (likelihood or "").lower())
        counts[key] = counts.get(key, 0) + total
        if RANK.get(severity, 0) > RANK.get(worst_at.get(key), -1):
            worst_at[key] = severity

    placed = 0
    grid = []
    for impact in IMPACT_ROWS:
        row = {"impact": impact, "cells": []}
        for likelihood in LIKELIHOOD_COLUMNS:
            key = (impact, likelihood)
            total = counts.get(key, 0)
            placed += total
            proposed = MATRIX.get(impact, {}).get(likelihood, _Severity.UNKNOWN)
            actual = worst_at.get(key)
            row["cells"].append({
                "impact": impact, "likelihood": likelihood, "count": total,
                # What the findings in here are graded, which is what the
                # color follows and what the list will show.
                "severity": (getattr(actual, "value", str(actual))
                             if actual is not None
                             else getattr(proposed, "value", str(proposed))),
                # What the model says this pair means, kept so the two can be
                # compared rather than conflated.
                "proposed": getattr(proposed, "value", str(proposed)),
                "differs": (actual is not None
                            and getattr(actual, "value", "") !=
                            getattr(proposed, "value", "")),
            })
        row["total"] = sum(cell["count"] for cell in row["cells"])
        grid.append(row)

    everything = int(query.with_entities(_tally(model)).scalar() or 0)
    return {
        "rows": grid,
        "columns": LIKELIHOOD_COLUMNS,
        "placed": placed,
        "total": everything,
        "unplaced": everything - placed,
        # The busiest cell, so the page can say what the picture shows rather
        # than leaving the reader to find it.
        "worst": max(
            (cell for row in grid for cell in row["cells"] if cell["count"]),
            key=lambda c: (["info", "low", "medium", "high", "critical"]
                           .index(c["severity"])
                           if c["severity"] in ("info", "low", "medium", "high",
                                                "critical") else 0,
                           c["count"]),
            default=None),
    }


def by_class(query, levels=("critical", "high"), limit=8, examples=3) -> list:
    """-> the findings at these severities, grouped by what they are examples of.

    A list of rule names is a list of the tool's vocabulary.  Three rules that
    are all SQL injection read as three problems to somebody who does not
    already know they are one, and the count of distinct things to understand
    is what makes a report feel unmanageable.

    So each section is a weakness, with how many, where, a sentence on what it
    is and a sentence on what to do.  Ordered by count, because within one
    severity the size of the pile is what decides where to start.
    """
    from app.core.models import Severity as _Severity
    from app.core.weakness import classify

    out = []
    for level in levels:
        try:
            wanted = _Severity(level)
        except ValueError:
            continue
        rows = query.filter(Finding.severity == wanted).all()
        if not rows:
            continue

        buckets = {}
        for row in rows:
            key, name, what, todo = classify(
                getattr(row, "cwe", ""), getattr(row, "rule", ""),
                str(getattr(row, "kind", "")))
            entry = buckets.setdefault(key, {
                "key": key, "name": name, "what": what, "todo": todo,
                "count": 0, "repositories": set(), "rows": []})
            entry["count"] += 1
            if row.repository:
                entry["repositories"].add(row.repository)
            if len(entry["rows"]) < examples:
                entry["rows"].append(row)

        classes = sorted(buckets.values(), key=lambda e: e["count"], reverse=True)
        for entry in classes:
            entry["repositories"] = sorted(entry["repositories"])
        shown = classes[:limit]
        out.append({
            "severity": level,
            "total": len(rows),
            "classes": shown,
            # What did not fit, said rather than dropped.
            "other_classes": len(classes) - len(shown),
            "other_findings": sum(e["count"] for e in classes[limit:]),
        })
    return out


def posture(query) -> dict:
    """The few facts an executive summary should be built from.

    Not a score.  A score compresses everything into one number and the
    compression is where the argument goes: two estates with the same score
    can need completely different things done.  These are the handful of
    questions somebody senior actually asks, each answered with a number that
    can be checked.
    """
    from app.core.models import Severity as _Severity

    total = query.count()
    if not total:
        return {"total": 0}

    serious = query.filter(Finding.severity.in_(
        [_Severity.CRITICAL, _Severity.HIGH])).count()
    proven = query.filter(Finding.verified.is_(True)).count()
    exploited = query.filter(Finding.known_exploited.is_(True)).count()
    hostile = query.filter(Finding.malicious.is_(True)).count()
    reachable = query.filter(Finding.reachability == "reachable").count()
    set_aside = query.filter(Finding.triage.in_(
        ["not_applicable", "advisory", "third_party"])).count()
    patched = query.filter(Finding.base_upgraded.is_(True)).count()
    fixable = query.filter(Finding.fixed_in != "").count()

    return {
        "total": total,
        "serious": serious,
        "serious_share": round(100.0 * serious / total),
        "proven": proven,
        "exploited": exploited,
        "hostile": hostile,
        "reachable": reachable,
        "set_aside": set_aside,
        "patched": patched,
        "fixable": fixable,
        "fixable_share": round(100.0 * fixable / total),
        # The one number that is a judgement rather than a count, and it is
        # deliberately coarse: three words, not a score out of a hundred.
        "standing": ("needs attention now" if (proven or hostile)
                     else "work to do" if serious
                     else "routine"),
    }
