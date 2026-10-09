"""Which branches ship, and so which ones get more than a credential scan.

A repository has one of three settings:

  all          every branch gets every pass.  The default, and what a
               repository with no row here has.
  chosen       only the branches on a list get every pass.  Names or globs,
               master or release/*.  Everything else, new branches included,
               gets credentials only.
  credentials  the whole repository gets credentials only.

A branch can override that either way, and the override wins.

Credentials are read on every branch whatever this says.  A key pushed to a
branch nobody deploys still works, so "does not ship" is no reason to stop
looking for one.

Nothing is deleted.  A finding whose every branch is out of scope gets
`out_of_scope` set, which takes it off the work list and out of the report
files.  Put the branch back and the flag comes off on the spot.  A finding on
two branches, one in and one out, stays: it ships from the first one.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import or_

from app.core.models import (BranchScope, BranchScopeChange, Finding,
                             FindingKind, FindingState, Repository, Severity,
                             utcnow)

log = logging.getLogger("gcr.scope")

REPO_MODES = ("all", "chosen", "credentials")
BRANCH_MODES = ("full", "credentials")

# How the page says each one.
REPO_LABELS = {"all": "Full scan, all branches",
               "chosen": "Full scan, chosen branches only",
               "credentials": "Credentials only"}


class Rule:
    """One repository's setting with its branch overrides, ready to match."""

    def __init__(self, mode="all", full=None, overrides=None):
        self.mode = mode if mode in REPO_MODES else "all"
        self.full = list(full or [])
        self.overrides = dict(overrides or {})

    def full_scan(self, branch: str) -> tuple:
        """Whether this branch gets every pass.  -> (yes, where that came from).

        Where is "branch" for an override and "repository" otherwise, which is
        what lets the page say "inherited from repository".
        """
        branch = branch or ""
        if branch in self.overrides:
            return self.overrides[branch] == "full", "branch"
        if self.mode == "credentials":
            return False, "repository"
        if self.mode == "chosen":
            return any(fnmatch.fnmatchcase(branch, p) for p in self.full), "repository"
        return True, "repository"

    def as_scanner(self) -> dict:
        return {"mode": self.mode, "full": self.full,
                "branches": self.overrides}


def patterns_of(text) -> list:
    """Branch names and globs from a box, one per line or comma, in order."""
    if isinstance(text, (list, tuple)):
        items = text
    else:
        items = str(text or "").replace("\r", "\n").replace(",", "\n").split("\n")
    out = []
    for item in items:
        item = str(item).strip()
        if item and item not in out:
            out.append(item[:255])
    return out


def rules(session, repositories=None) -> dict:
    """repository name -> Rule, for every repository with anything set."""
    query = session.query(BranchScope)
    if repositories is not None:
        names = list(repositories)
        if not names:
            return {}
        query = query.filter(BranchScope.repository.in_(names))
    out = {}
    for row in query.all():
        rule = out.setdefault(row.repository, Rule())
        if row.branch:
            if row.mode in BRANCH_MODES:
                rule.overrides[row.branch] = row.mode
        else:
            rule.mode = row.mode if row.mode in REPO_MODES else "all"
            rule.full = patterns_of(row.patterns)
    return out


def rule_for(session, repository: str) -> Rule:
    return rules(session, [repository]).get(repository) or Rule()


def branches_of(primary, listed) -> list:
    """Every branch a finding is on, the same reading branch_scope uses."""
    names = []
    if primary:
        names.append(str(primary))
    try:
        for name in (json.loads(listed or "[]") or []):
            if name and str(name) not in names:
                names.append(str(name))
    except (TypeError, ValueError):
        pass
    return names


def out_of_scope(rule, kind, primary, listed) -> bool:
    """Whether a finding is only on branches that do not ship.

    A credential never is.  Neither is a finding that names no branch at all:
    there is nothing to say it is somewhere that does not ship, and hiding it
    on no evidence is the wrong way round.
    """
    if rule is None:
        return False
    if kind == FindingKind.CREDENTIAL or getattr(kind, "value", kind) == "credential":
        return False
    names = branches_of(primary, listed)
    if not names:
        return False
    return not any(rule.full_scan(name)[0] for name in names)


def refresh(session, repositories=None) -> int:
    """Set out_of_scope on findings to match the rules now.  -> rows changed.

    With repositories, only those.  Without, every repository that has a rule
    plus every finding flagged already, which covers a rule that was removed.
    """
    session.flush()
    all_rules = rules(session)
    query = session.query(Finding.id, Finding.repository, Finding.kind,
                          Finding.branch, Finding.branches,
                          Finding.out_of_scope)
    if repositories is not None:
        names = sorted({r for r in repositories if r})
        if not names:
            return 0
        query = query.filter(Finding.repository.in_(names))
    else:
        clauses = [Finding.out_of_scope.is_(True)]
        if all_rules:
            clauses.append(Finding.repository.in_(sorted(all_rules)))
        query = query.filter(or_(*clauses))

    flip_on, flip_off = [], []
    for fid, repo, kind, primary, listed, flagged in query.all():
        want = out_of_scope(all_rules.get(repo), kind, primary, listed)
        if want and not flagged:
            flip_on.append(fid)
        elif flagged and not want:
            flip_off.append(fid)

    for ids, value in ((flip_on, True), (flip_off, False)):
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            (session.query(Finding).filter(Finding.id.in_(chunk))
             .update({Finding.out_of_scope: value},
                     synchronize_session="evaluate"))
    if flip_on or flip_off:
        log.info("scan scope: %d finding(s) now not deployed, %d back in scope",
                 len(flip_on), len(flip_off))
    return len(flip_on) + len(flip_off)


def for_scanner(session) -> dict:
    """What the scanner needs: repository -> mode, full list and overrides."""
    return {name: rule.as_scanner() for name, rule in rules(session).items()}


# ---- reading a repository's setting -----------------------------------------

def describe(rule, default_branch: str = "") -> str:
    """Short text for the Scope column.  "Full: master, release/*" and so on."""
    rule = rule or Rule()
    if rule.mode == "credentials":
        text = "Credentials only"
    elif rule.mode == "chosen":
        text = "Full: " + ", ".join(rule.full)
    else:
        text = "Full scan, all branches"
    if rule.overrides:
        n = len(rule.overrides)
        text += f" ({n} branch override{'' if n == 1 else 's'})"
    return text


def default_left_out(rule, default_branch: str) -> bool:
    """True when the default branch only gets credentials.  Worth a warning."""
    if rule is None or not default_branch:
        return False
    return not rule.full_scan(default_branch)[0]


def _snapshot(row) -> dict | None:
    if row is None:
        return None
    return {"mode": row.mode, "patterns": row.patterns or "",
            "reason": row.reason or "",
            "review_at": row.review_at.strftime("%Y-%m-%d") if row.review_at else "",
            "set_by": row.set_by or "",
            "set_at": row.set_at.isoformat() if row.set_at else ""}


def _row(session, repository: str, branch: str):
    return (session.query(BranchScope)
            .filter(BranchScope.repository == repository)
            .filter(BranchScope.branch == (branch or "")).one_or_none())


def _proposed(current: Rule, branch: str, mode: str, patterns) -> Rule:
    """The rule as it would be after this change."""
    rule = Rule(current.mode, list(current.full), dict(current.overrides))
    if branch:
        if mode in BRANCH_MODES:
            rule.overrides[branch] = mode
        else:
            rule.overrides.pop(branch, None)
    else:
        rule.mode = mode if mode in REPO_MODES else "all"
        rule.full = patterns_of(patterns) if rule.mode == "chosen" else []
    return rule


def validate(repository: str, branch: str, mode: str, patterns) -> str:
    """-> what is wrong with this change, or "" when nothing is."""
    if not repository:
        return "There is no repository to change."
    if branch:
        if mode not in BRANCH_MODES + ("inherit",):
            return "A branch is either full scan, credentials only or inherited."
        return ""
    if mode not in REPO_MODES:
        return "Pick one of the three repository settings."
    if mode == "chosen" and not patterns_of(patterns):
        # An empty list means nothing gets a full scan, which is what
        # "Credentials only" already says, and says honestly.
        return ("The full scan list is empty.  Name at least one branch, or "
                "pick Credentials only.")
    return ""


def known_branches(session, repository: str) -> list:
    """Every branch the last scan saw, falling back on the walked list."""
    repo = (session.query(Repository)
            .filter(Repository.full_name == repository).first())
    if repo is None:
        return []
    for column in (repo.branch_names_present, repo.branch_names):
        try:
            names = json.loads(column or "[]") or []
        except (TypeError, ValueError):
            names = []
        if names:
            return [str(n) for n in names if n]
    return [repo.default_branch] if repo.default_branch else []


def preview(session, repository: str, branch: str, mode: str, patterns,
            findings=None, changes=None) -> dict:
    """What a change would do, before anybody commits to it.

    Counts open findings that would leave the work list or come back to it, by
    severity, and the branches that would change between full and credentials
    only.  `findings` narrows the count to what the reader may see.  `changes`
    is a list of (branch, mode, patterns) for several at once, in place of the
    single one.
    """
    current = rule_for(session, repository)
    changes = list(changes or [(branch, mode, patterns)])
    after = current
    for one_branch, one_mode, one_patterns in changes:
        after = _proposed(after, one_branch, one_mode, one_patterns)

    hide = {s.value: 0 for s in Severity}
    show = {s.value: 0 for s in Severity}
    query = (findings if findings is not None else session.query(Finding))
    query = (query.filter(Finding.repository == repository)
             .filter(Finding.state == FindingState.OPEN)
             .filter(Finding.kind != FindingKind.CREDENTIAL)
             .with_entities(Finding.kind, Finding.severity, Finding.branch,
                            Finding.branches))
    seen = set(known_branches(session, repository))
    for kind, severity, primary, listed in query.all():
        seen.update(branches_of(primary, listed))
        was = out_of_scope(current, kind, primary, listed)
        will = out_of_scope(after, kind, primary, listed)
        level = getattr(severity, "value", str(severity))
        if will and not was:
            hide[level] = hide.get(level, 0) + 1
        elif was and not will:
            show[level] = show.get(level, 0) + 1
    seen.update(b for b, _, _ in changes if b)

    to_credentials, to_full = [], []
    for name in sorted(seen):
        before_full = current.full_scan(name)[0]
        after_full = after.full_scan(name)[0]
        if before_full and not after_full:
            to_credentials.append(name)
        elif after_full and not before_full:
            to_full.append(name)

    repo = (session.query(Repository)
            .filter(Repository.full_name == repository).first())
    default_branch = (repo.default_branch if repo else "") or ""
    return {"hide": hide, "show": show,
            "hide_total": sum(hide.values()), "show_total": sum(show.values()),
            "to_credentials": to_credentials, "to_full": to_full,
            "default_branch": default_branch,
            "default_protected": bool(repo and repo.default_branch_protected),
            # The one change that needs a second look: the branch that ships
            # by definition stops getting a full scan.
            "default_leaves": bool(default_branch
                                   and default_branch in to_credentials),
            "describe_before": describe(current, default_branch),
            "describe_after": describe(after, default_branch)}


def _parse_review(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def apply(session, repository: str, branch: str, mode: str, patterns,
          reason: str, review_at, actor: str, reverts: int = None,
          refresh_after: bool = True) -> tuple:
    """Make the change, record it, and refresh the findings.  -> (change, problem).

    "all" on the repository and "inherit" on a branch are the defaults, so the
    row goes rather than staying behind saying the default.  The change record
    keeps what it was.
    """
    branch = (branch or "").strip()
    problem = validate(repository, branch, mode, patterns)
    if problem:
        return None, problem
    reason = (reason or "").strip()
    if len(reason) < 10:
        return None, "Say why, in a sentence.  Somebody will read this later."

    row = _row(session, repository, branch)
    before = _snapshot(row)
    dropping = (branch and mode == "inherit") or (not branch and mode == "all")
    if dropping:
        if row is not None:
            session.delete(row)
        after = None
    else:
        if row is None:
            row = BranchScope(repository=repository, branch=branch)
            session.add(row)
        row.mode = mode
        row.patterns = ("\n".join(patterns_of(patterns))
                        if not branch and mode == "chosen" else "")
        row.reason = reason[:4000]
        row.review_at = _parse_review(review_at)
        row.set_by = (actor or "")[:120]
        row.set_at = utcnow()
        session.flush()
        after = _snapshot(row)

    change = BranchScopeChange(repository=repository, branch=branch,
                               before=json.dumps(before), after=json.dumps(after),
                               reason=reason[:4000], changed_by=(actor or "")[:120],
                               reverts=reverts)
    session.add(change)
    session.flush()
    # Off for a batch of branches in one repository, which refreshes once at
    # the end rather than once a branch.
    if refresh_after:
        refresh(session, [repository])
    log.info("%s set the scan scope of %s%s to %s", actor, repository,
             f" on {branch}" if branch else "", mode)
    return change, ""


def revert(session, change_id: int, actor: str) -> tuple:
    """Put a scope back the way it was before one change.  -> (change, problem).

    Refused when the scope has moved again since, because undoing an old
    change on top of a newer one would quietly throw the newer one away.
    """
    change = session.get(BranchScopeChange, change_id)
    if change is None:
        return None, "There is no such change."
    current = _snapshot(_row(session, change.repository, change.branch))
    recorded = json.loads(change.after or "null")
    if (current or {}).get("mode") != (recorded or {}).get("mode") or \
            (current or {}).get("patterns", "") != (recorded or {}).get("patterns", ""):
        return None, ("The scope has changed again since then.  Change it "
                      "directly rather than undoing an older step.")
    before = json.loads(change.before or "null")
    if before is None:
        mode = "inherit" if change.branch else "all"
        patterns, review = "", None
    else:
        mode, patterns = before.get("mode", "all"), before.get("patterns", "")
        review = before.get("review_at") or None
    return apply(session, change.repository, change.branch, mode, patterns,
                 f"Reverted change {change.id}: {change.reason}"[:4000],
                 review, actor, reverts=change.id)


def history(session, repository: str, limit: int = 20) -> list:
    """Recent changes to one repository's scope, newest first, for the page."""
    rows = (session.query(BranchScopeChange)
            .filter(BranchScopeChange.repository == repository)
            .order_by(BranchScopeChange.id.desc()).limit(limit).all())
    out, latest = [], set()
    for row in rows:
        # Only the newest change to each setting can be undone.  revert()
        # checks that too; this keeps the page from offering it.
        newest = row.branch not in latest
        latest.add(row.branch)
        out.append({"id": row.id, "branch": row.branch, "newest": newest,
                    "before": json.loads(row.before or "null"),
                    "after": json.loads(row.after or "null"),
                    "reason": row.reason, "by": row.changed_by,
                    "at": row.changed_at, "reverts": row.reverts})
    return out


def settings_of(session, repository: str) -> dict:
    """The repository row and its branch rows, as the scope page shows them."""
    rows = (session.query(BranchScope)
            .filter(BranchScope.repository == repository)
            .order_by(BranchScope.branch).all())
    repo_row = next((r for r in rows if not r.branch), None)
    return {"repository": repo_row,
            "branches": [r for r in rows if r.branch]}


# ---- many at once, from a connection's page ----------------------------------

ACTIONS = ("credentials", "full", "inherit")


def batch(repositories, pairs, action: str) -> dict:
    """Ticked repositories and (repository, branch) pairs, as changes per repository.

    -> {repository: [(branch, mode, patterns), ...]}.  A ticked repository
    takes the whole repository to credentials only, or back to every branch.
    A ticked branch gets an override, or loses one for "inherit".
    """
    out = {}
    if action not in ACTIONS:
        return out
    for repository in repositories:
        out.setdefault(repository, []).append(
            ("", "credentials" if action == "credentials" else "all", ""))
    for repository, branch in pairs:
        if branch:
            out.setdefault(repository, []).append((branch, action, ""))
    return out


def apply_batch(session, repository: str, changes: list, reason: str,
                review_at, actor: str) -> tuple:
    """Every change for one repository, refreshed once.  -> (change ids, problem)."""
    ids = []
    for branch, mode, patterns in changes:
        change, problem = apply(session, repository, branch, mode, patterns,
                                reason, review_at, actor, refresh_after=False)
        if problem:
            return ids, problem
        ids.append(change.id)
    refresh(session, [repository])
    return ids, ""
