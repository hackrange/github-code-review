"""Which rules are producing the work list, and what to do about them.

Tuning is a rule level job and the product only ever offered a finding level
view of it.  On a twenty repository corpus 190 distinct rules produced 1,291
code findings and the top ten produced 597 of them, 46%: ten decisions move
nearly half the list, and there was no page that said which ten.

Everything here is a count of findings nobody has set aside, because that is
the list a person is actually being asked to work through.
"""

from __future__ import annotations

from sqlalchemy import case, func

from app.core.models import Finding, FindingKind, FindingState, Severity

# Below this a rule is not making noise, it is just present.  A page of two
# hundred rules with one finding each is the problem this page exists to
# solve, restated.
FLOOR = 3

# The grades that put a finding in front of somebody.
LOUD = (Severity.CRITICAL, Severity.HIGH)


def _scope(session, query, user):
    """The same scoping every other list uses, so the counts agree with them.

    rbac.visible_findings builds its own query, and this page needs aggregates
    rather than rows, so the condition is taken and applied here.  Using a
    different scoping rule from the Findings page is how a developer ends up
    being told to mute a rule they cannot see.
    """
    from app.core import rbac
    condition = rbac._scope_filter(user, session)
    return query if condition is None else query.filter(condition)


def ranked(session, user, kind: str = "", limit: int = 50) -> list:
    """-> rules ordered by how many open findings they produce.

    One row per rule, with what it is costing: the total, how much of it is
    high or critical, how much the engine itself is unsure about, and how many
    repositories it turns up in.  A rule in one repository is a fix; the same
    rule in forty is a policy.
    """
    query = session.query(
        Finding.rule.label("rule"),
        func.count(Finding.id).label("total"),
        func.count(func.distinct(Finding.repository)).label("repositories"),
        func.sum(case((Finding.severity.in_(LOUD), 1), else_=0)).label("loud"),
        func.sum(case((Finding.confidence == "low", 1), else_=0)).label("unsure"),
    ).filter(
        Finding.state == FindingState.OPEN,
        # Only on branches that do not ship is not on anybody's work list.
        Finding.out_of_scope.is_(False),
        Finding.rule.isnot(None),
        Finding.rule != "",
    )
    query = _scope(session, query, user)

    # The work list, not everything ever found.  A rule already set aside is
    # not making noise, and showing it here as if it were would send somebody
    # to mute a rule that is already muted.
    query = query.filter(~Finding.triage.in_(
        ["third_party", "advisory", "not_applicable"]))

    if kind in {k.value for k in FindingKind}:
        query = query.filter(Finding.kind == FindingKind(kind))

    rows = (query.group_by(Finding.rule)
            .having(func.count(Finding.id) >= FLOOR)
            .order_by(func.count(Finding.id).desc())
            .limit(limit).all())

    # What kind of finding each rule produces, for the label on the row.
    kinds = {}
    for rule, k in (_scope(session, session.query(Finding.rule, Finding.kind), user)
                    .filter(Finding.state == FindingState.OPEN)
                    .group_by(Finding.rule, Finding.kind).all()):
        kinds.setdefault(rule, set()).add(getattr(k, "value", k))

    out = []
    for row in rows:
        total = int(row.total or 0)
        out.append({
            "rule": row.rule,
            "total": total,
            "repositories": int(row.repositories or 0),
            "loud": int(row.loud or 0),
            "unsure": int(row.unsure or 0),
            "kinds": sorted(kinds.get(row.rule, [])),
        })
    return out


def summary(session, user, rows: list) -> dict:
    """The one number worth putting at the top: how concentrated this is."""
    total = (_scope(session, session.query(func.count(Finding.id)), user)
             .filter(Finding.state == FindingState.OPEN)
             .filter(~Finding.triage.in_(
                 ["third_party", "advisory", "not_applicable"])).scalar() or 0)
    distinct = (_scope(session, session.query(func.count(func.distinct(Finding.rule))), user)
                .filter(Finding.state == FindingState.OPEN)
                .filter(~Finding.triage.in_(
                    ["third_party", "advisory", "not_applicable"])).scalar() or 0)
    top_ten = sum(r["total"] for r in rows[:10])
    return {
        "open": int(total),
        "rules": int(distinct),
        "top_ten": top_ten,
        "top_ten_share": round(100 * top_ten / total) if total else 0,
    }
