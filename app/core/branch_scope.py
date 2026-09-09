"""Which findings belong to a branch.

A finding carries one primary branch and, beside it, every branch the scan
saw it on.  The primary is only whichever name git handed back first, and
`git for-each-ref --contains` sorts by ref name, so a commit sitting on both
develop and master is filed under develop for no reason but the alphabet.
Filtering on that column alone then answers "nothing on master" for a
repository whose master carries every one of those findings, and the branch
box does not even offer master, because no row is stamped with it.

Both readings are followed here, the same way the sign off coverage in
`certification.blocking_branches` already does: a finding is on a branch when
it is stamped with it or when it remembers it.

The cost of that is a substring match against a text column, which no index
helps with.  It is paid on the branch filter only, which is the one place
where the wrong answer is a repository that looks clean.
"""
from __future__ import annotations

import json

from sqlalchemy import or_

from app.core.models import Finding

# LIKE has no escape character of its own until one is named.  A branch name
# may legally hold % or _, and unescaped those are wildcards.
_ESC = "\\"


def _needle(branch: str) -> str:
    """The branch name as it appears inside the stored list, as a LIKE pattern.

    Built with json.dumps rather than by quoting by hand, so a name the
    encoder escapes is looked for in its escaped form, which is the only form
    the column holds.  The quotes are part of the needle: they are what stops
    master from matching master-2.
    """
    text = json.dumps(branch)
    for char in (_ESC, "%", "_"):
        text = text.replace(char, _ESC + char)
    return f"%{text}%"


def matches(branch: str):
    """A clause selecting every finding on this branch, under either reading."""
    return or_(Finding.branch == branch,
               Finding.branches.like(_needle(branch), escape=_ESC))


def names(query) -> list:
    """Every branch the findings in this query mention, sorted.

    Distinct pairs rather than distinct findings, so this costs the number of
    branch combinations in scope and not the number of findings: on an estate
    of sixty thousand findings that is a few hundred rows.
    """
    found = set()
    rows = (query.with_entities(Finding.branch, Finding.branches)
            .distinct().all())
    for primary, listed in rows:
        if primary:
            found.add(str(primary))
        try:
            listed = json.loads(listed or "[]") or []
        except (TypeError, ValueError):
            continue
        for name in listed:
            if name:
                found.add(str(name))
    return sorted(found)
