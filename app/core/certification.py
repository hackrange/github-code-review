"""Whether somebody in security has signed off a branch, and whether that still
describes the code.

The badge is the easy part.  What makes this safe to show is the two ways it
stops being true, because a green mark that outlives what it was based on is
worse than no mark at all: it does not merely fail to help, it actively tells
somebody not to look.

  It expires.  A date is required when it is written, and past that date it
  reads as lapsed rather than quietly carrying on.

  It goes stale the moment anybody pushes.  The commit that was reviewed is
  recorded and compared against where the branch is now, so any new commit at
  all turns the badge amber, whether or not it produced a finding.  Waiting for
  a finding would be the wrong test: a reviewer read some code, and different
  code has not been read.  "Our engines found nothing in it" is not the claim a
  sign off makes.

Most of these are written by a person.  Some are written by a scan: a branch
a completed scan found nothing worth reading on gets one on its own, because
asking somebody to click a button on every empty branch in an estate is asking
for a queue nobody works through, and an unreviewed branch that nobody could
ever have anything to say about is not the branch anyone wants attention on.

An automatic one is marked as automatic and says so wherever it is shown.  It
claims a great deal less than a person's, and the wording is deliberately
about the search rather than about the code: our engines looked and came back
with nothing anybody has to read.  Three rules keep that honest.

  It waits for the passes to finish.  A pass that did not run reports nothing,
  and nothing is exactly what a clear branch looks like from here, so silence
  from a dead engine would otherwise be handed a green badge.

  It never touches a person's.  A scan may refresh or leave behind a badge it
  wrote itself, and may not overwrite, revive or re-date one somebody signed,
  including one they withdrew.

  It holds to the same grades a reader would.  Anything above low is a finding
  somebody has to look at, and a branch holding one is not signed off by a
  machine.

Both of those are shown rather than enforced.  Nothing in this file removes a
finding, changes a grade, or keeps anything out of a report.  A certified
repository that starts producing criticals shows every one of them, beside a
badge saying the review no longer covers what is there.  The moment a
certification can hide a finding it stops being one person's opinion and
becomes everybody else's blind spot.
"""

from __future__ import annotations

import logging

from sqlalchemy import or_

from datetime import timezone

from app.core.models import (Certification, Finding, FindingState,
                            Severity, utcnow)

log = logging.getLogger("gcr.certification")

# The states a badge can be in, worst last so a caller can sort on it.
ACTIVE = "active"        # reviewed, in date, and nothing has changed since
STALE = "stale"          # in date, but the code has moved on
# The same fact about a badge a scan wrote, which asks nobody for anything.
#
# Almost every sign off on a large install is automatic: a scan looked, found
# nothing, and said so.  When somebody pushes to such a branch the old code
# turned it amber and asked a person to re-check something no person ever
# checked, for work the next scan is already going to do.  On one estate that
# was ninety nine point six percent of the badges, so the one amber that meant
# "a human vouched for this and the code has changed since" was lost among them.
RESCANNING = "rescanning"  # a scan signed it, and the code moved since
LAPSED = "lapsed"        # the date has passed
# A sign off on a branch nobody can go and look at.
#
# The amber state exists to ask a person to read a diff.  When the branch it
# names is not one the last scan found, there is no diff to hand them: the
# compare link points at commits the host has since collected, and clicking it
# returns a 404.  Asking for a review that cannot be done is worse than asking
# for nothing, because the reader spends the trip finding that out and trusts
# the next amber badge less.
#
# So it is neither.  Not certified, because nothing here has been read against
# code that is present.  Not amber, because there is no work to do.  Unknown,
# which is what it is, and which says out loud that the answer is missing
# rather than guessing at one.
UNKNOWN = "unknown"      # the branch is not one this install can reach
REVOKED = "revoked"      # somebody took it back
NOT_APPLICABLE = "not_applicable"   # nobody is expected to review this
NONE = "none"            # nobody has reviewed this

# An automatic sign off, in the words it has to say it in.
AUTOMATIC_NOTE = ("This branch is automatically certified because there were "
                  "no observable findings or credentials in our discovery.")

# The name one is written under.  Not a person's name, and it is shown as the
# author everywhere a certification is listed, so a scan finding nothing is
# never read as somebody having looked.
AUTOMATIC_ACTOR = "automatic"

# How long one lasts.  The same ninety days the sign off form offers, so an
# automatic badge never outlives what a person would have been given.
AUTOMATIC_DAYS = 90

# The grades that leave a branch clear.  Anything above these is a finding
# somebody has to read, and a branch holding one is not signed off by a scan.
AUTOMATIC_CLEAR = (Severity.LOW, Severity.INFO)

# How many branches a "not certified" note names before it stops naming them.
# Enough to act on a repository, short enough that a whole organization does
# not turn the line into a wall nobody reads.
MAX_NAMED = 12

# The passes that have to have finished first.  This is the rule the whole
# feature rests on: a pass that did not run reports nothing, and nothing is
# exactly what a clear branch looks like from here.  Without this an engine
# that died would hand out green badges, which is the one failure this file
# was written to prevent.
AUTOMATIC_PASSES = ("code", "secrets", "vulnerabilities", "misconfigurations")


def _aware(value):
    """A timestamp that can be compared with utcnow().

    SQLite hands back naive datetimes whatever the column says, so a stored
    expiry compared straight against an aware now raises rather than
    answering.  On a single file install that meant the finding page did not
    render at all, which is a strange way to find out a badge had expired.
    """
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def for_branch(session, repository: str, branch: str):
    """The certification covering this branch, whatever state it is in."""
    if not repository:
        return None
    return (session.query(Certification)
            .filter(Certification.repository == repository)
            .filter(Certification.branch == (branch or ""))
            .one_or_none())


def _on_day(value) -> str:
    """A date somebody can hold in their head, or a phrase that admits it."""
    value = _aware(value)
    return value.strftime("%d %b %Y") if value is not None else "an unknown date"


def _repo_row(session, repository: str):
    """The repository a sign off is about, read once.

    Every question a badge asks -- where the branch is now, when it was last
    pushed, what the default branch is called, whether the branch is still
    there -- is answered out of the same row.  Four of them each going and
    fetching it turned a page of two thousand badges into eight thousand
    queries.
    """
    from app.core.models import Repository

    return (session.query(Repository)
            .filter(Repository.full_name == repository).one_or_none())


def _pushed_phrase(session, repository: str, repo=None) -> str:
    """" on 12 Mar", or nothing at all when the host never said.

    Said where it is useful rather than left to be worked out.  "The branch has
    moved" is a fact nobody can act on; "the branch moved on Tuesday" is the
    start of finding out who and why.
    """
    if repo is None:
        repo = _repo_row(session, repository)
    when = _aware(getattr(repo, "pushed_at", None)) if repo else None
    return (" on %s" % when.strftime("%d %b %Y")) if when is not None else ""


def _default_branch_of(session, repository: str, repo=None) -> str:
    """The branch a sign off with no branch on it is about."""
    if repo is None:
        repo = _repo_row(session, repository)
    return (getattr(repo, "default_branch", "") or "") if repo else ""


def _out_of_reach(session, row, repo=None) -> str:
    """Why this sign off cannot be reviewed, or "" when it can.

    Said when the branch is not among the branches the last scan found in this
    repository.  A merged pull request whose branch was then deleted leaves
    exactly this: a sign off naming a ref that is gone, against a commit the
    host squashed away with it.  Ingest removes those when a scan reports what
    it found, so this is the gap in between, and the gap can be long when the
    scan that would have reported it failed, or never got to the repository at
    all.

    Against the full list of branches, not the ones the run walked.  Those are
    two different lists: the quiet branch filter and the per repository cap
    both narrow what a run walks, so a branch nobody has touched for a year is
    missing from the walked list while being perfectly present.  A sign off on
    one of those still stands.  It is out of the coverage figure, because the
    figure counts what this install looked at, but nobody is being told the
    code has gone.

    Only ever said on the evidence of a scan that looked.  A repository whose
    scanner never sent a full list says nothing either way: a missing list is
    not proof that a branch is missing.  The default branch counts as found
    whatever it is called, the same rule ingest uses, because a sign off
    written against "" means whichever branch the repository deploys from.
    """
    import json

    if repo is None:
        repo = _repo_row(session, row.repository)
    if repo is None:
        return "this repository is no longer in the scan"
    default = (getattr(repo, "default_branch", "") or "")
    named = row.branch or default
    if not named:
        return ""
    try:
        there = {str(name) for name in
                 (json.loads(getattr(repo, "branch_names_present", "")
                             or "[]") or []) if name}
    except (TypeError, ValueError):
        there = set()
    if not there:
        return ""
    if named == default or named in there:
        return ""
    return ("the last scan of this repository found %d branch%s and %s was "
            "not one of them, so there is nothing here to read.  The sign off "
            "is removed once a scan confirms the branch has gone"
            % (len(there), "" if len(there) == 1 else "es", named))


def head_of(session, repository: str, branch: str, repo=None) -> str:
    """Where that branch was at the last scan, as a commit."""
    import json

    if repo is None:
        repo = _repo_row(session, repository)
    if repo is None:
        return ""
    try:
        heads = json.loads(repo.branch_heads or "{}") or {}
    except (TypeError, ValueError):
        return ""
    if branch:
        return str(heads.get(branch, "") or "")
    return str(heads.get(repo.default_branch or "", "") or "")


class _Lookups:
    """What status() reads, fetched once for a whole list of sign offs.

    One badge asks for its repository row and a count of findings since the
    review.  Two thousand badges asked two thousand times each, and the
    dashboard sent four thousand queries to draw one tile.  This reads the
    same things in a few queries and answers from memory.

    Names are matched without case, the way MariaDB compares them, so a badge
    reads the same here as it does one at a time.
    """

    CHUNK = 500

    def __init__(self, session, rows):
        import bisect
        from collections import defaultdict

        from app.core.models import Repository

        self._bisect = bisect
        rows = [row for row in rows if row is not None]
        names = sorted({row.repository for row in rows if row.repository})

        self.repos = {}
        for chunk in _chunks(names, self.CHUNK):
            for repo in (session.query(Repository)
                         .filter(Repository.full_name.in_(chunk)).all()):
                self.repos.setdefault(_fold(repo.full_name), repo)

        # Only the three columns the count needs, and only findings newer
        # than the oldest review, which is the most any badge can look at.
        oldest = min((_aware(row.certified_at) for row in rows
                      if row.certified_at is not None), default=None)
        found = defaultdict(list)
        if oldest is not None:
            for chunk in _chunks(names, self.CHUNK):
                query = (session.query(Finding.repository, Finding.branch,
                                       Finding.first_found_at)
                         .filter(Finding.repository.in_(chunk))
                         .filter(Finding.state == FindingState.OPEN)
                         .filter(Finding.excepted.is_(False))
                         .filter(Finding.first_found_at > oldest))
                for repository, branch, first in query.all():
                    found[(_fold(repository), _fold(branch or ""))].append(
                        _aware(first))
        for times in found.values():
            times.sort()
        self.found = found

    def repo(self, repository):
        return self.repos.get(_fold(repository))

    def since(self, repository, named, certified_at) -> int:
        """Open findings first seen after the review, on this branch or on
        none.  The same count the single badge query makes."""
        after = _aware(certified_at)
        if after is None:
            return 0
        repository = _fold(repository)
        if named:
            places = {"", _fold(named)}
        else:
            # No branch to narrow by, so every branch counts.
            places = {branch for (repo, branch) in self.found
                      if repo == repository}
        total = 0
        for branch in places:
            times = self.found.get((repository, branch), ())
            total += len(times) - self._bisect.bisect_right(times, after)
        return total


def _fold(value) -> str:
    return (value or "").casefold()


def _chunks(items, size):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def statuses(session, rows) -> list:
    """status() for every row, in order, in a few queries instead of two each."""
    rows = list(rows)
    lookups = _Lookups(session, rows)
    return [status(session, row, lookups=lookups) for row in rows]


def status(session, row, head_sha: str = "", lookups=None) -> dict:
    """-> {state, why, ...}.  What this badge should say today.

    Answers with a sentence rather than a color, because the interesting cases
    are the ones where it is no longer true and the reader needs to know which
    kind of no longer true it is.

    Pass `lookups` from statuses() when asking about a lot of them at once.
    """
    if row is None:
        return {"state": NONE, "why": "", "certification": None}

    now = utcnow()
    if row.revoked_at is not None:
        return {"state": REVOKED, "certification": row,
                "why": ("withdrawn by %s%s" % (
                    row.revoked_by or "somebody",
                    ": " + row.revoked_reason if row.revoked_reason else ""))}

    # Before the date and before the commits, because both of those are
    # questions about a branch, and this is the question of whether the branch
    # is there to ask them about.
    repo = (lookups.repo(row.repository) if lookups is not None
            else _repo_row(session, row.repository))
    gone = _out_of_reach(session, row, repo)
    if gone:
        return {"state": UNKNOWN, "certification": row, "why": gone}

    expires = _aware(row.expires_at)
    if not expires or expires <= now:
        return {"state": LAPSED, "certification": row,
                "why": "the review has passed its expiry date and needs doing again"}

    # Has anybody pushed since the review.
    #
    # This is the first question and not the second, and the order is the
    # point.  Waiting for a finding to arrive would mean a badge stays green
    # across any amount of new code the scanner happened to have nothing to
    # say about, and "our engines found nothing in it" is not what a sign off
    # claims.  A reviewer read some code.  Different code has not been read.
    #
    # Only ever decided on two known commits.  A missing sha proves nothing,
    # and guessing towards still-fine is the one direction that would make
    # this badge a liability.
    if not head_sha:
        head_sha = head_of(session, row.repository, row.branch, repo)
    if row.commit_sha and head_sha and head_sha != row.commit_sha:
        # A scan's own sign off, overtaken by a push.  Nobody is being asked
        # for anything: the next scan reads the new commit and either signs it
        # again or produces a finding that speaks for itself.  Saying "needs
        # re-checking" here invents work and buries the badges that mean it.
        if getattr(row, "automatic", False):
            return {"state": RESCANNING, "certification": row, "moved": True,
                    "why": ("the branch moved%s, from %s to %s, after the scan "
                            "signed it off on %s.  The next scan reads the new "
                            "commits and signs it again if it still finds "
                            "nothing"
                            % (_pushed_phrase(session, row.repository, repo),
                               row.commit_sha[:12], head_sha[:12],
                               _on_day(row.certified_at)))}
        return {"state": STALE, "certification": row, "moved": True,
                "why": ("the branch moved%s, from %s to %s, after it was "
                        "reviewed on %s, so there is code here nobody has "
                        "looked at"
                        % (_pushed_phrase(session, row.repository, repo),
                           row.commit_sha[:12], head_sha[:12],
                           _on_day(row.certified_at)))}

    # And whether anything has been found since, which catches the case the
    # commit check cannot: a repository certified before it was ever scanned,
    # or one whose head this install has not recorded yet.
    #
    # On this branch, which is the whole point and was missing.  A sign off
    # covers one branch and this counted the repository, so a single finding
    # arriving on main turned every signed off branch in that repository amber
    # at once.  Eight hundred and eighty one of nine hundred badges went that
    # way, and the ones a person then opened to see what had changed showed
    # nothing, because there was nothing on the branch they were told about.
    # A badge that cries wolf about somebody else's branch is worse than no
    # badge: it costs a review that finds nothing and teaches people to ignore
    # the next one.
    #
    # A finding filed under no branch counts wherever it is, because it
    # predates the branch being recorded and there is no way to place it.  That
    # errs towards amber, which is the safe direction for a claim that
    # something has been read.
    named = row.branch or _default_branch_of(session, row.repository, repo)
    if lookups is not None:
        since = lookups.since(row.repository, named, row.certified_at)
    else:
        since_q = (session.query(Finding)
                   .filter(Finding.repository == row.repository)
                   .filter(Finding.state == FindingState.OPEN)
                   .filter(Finding.excepted.is_(False))
                   .filter(Finding.first_found_at > _aware(row.certified_at)))
        if named:
            since_q = since_q.filter(or_(Finding.branch == named,
                                         Finding.branch.is_(None),
                                         Finding.branch == ""))
        since = since_q.count()
    if since:
        return {"state": STALE, "certification": row, "new_findings": since,
                "why": ("%d finding%s has arrived since the review, so it no "
                        "longer covers what is there"
                        % (since, "" if since == 1 else "s"))}

    return {"state": ACTIVE, "certification": row,
            "why": "reviewed and nothing has changed since"}


def certify(session, repository: str, branch: str, note: str, expires_at,
            actor: str, commit_sha: str = "", automatic: bool = False) -> tuple:
    """Record a review, or replace the one that is there.  -> (row, why not).

    `automatic` says a scan wrote this rather than a person.  It is stored
    rather than guessed at from the author, because every later decision about
    the row turns on it: what a scan may overwrite, and what the pages showing
    the badge tell a reader it means.
    """
    repository = (repository or "").strip()
    if not repository:
        return None, "Which repository."
    if expires_at is None:
        return None, ("Give it an expiry date.  A review with no end date is a "
                      "claim that nothing will ever change.")
    if _aware(expires_at) <= utcnow():
        return None, "That date has already passed."
    note = (note or "").strip()
    if len(note) < 20:
        return None, ("Say what you reviewed and what you concluded.  Somebody "
                      "is going to rely on this without being able to ask you.")

    # Nothing to read, nothing to sign.  A branch the last scan did not find is
    # one the host no longer has, and a sign off is a statement that somebody
    # read some code.  Checked here rather than only on the form, because the
    # form is not the only way in and a claim that cannot be true should not be
    # storable by any route.
    #
    # An automatic sign off skips the check: it is written while walking the
    # branch list itself, so the branch is in reach by construction, and the
    # recorded list is the one the run in progress is about to replace.
    row = for_branch(session, repository, branch)
    if not automatic:
        gone = _out_of_reach(
            session, row if row is not None
            else Certification(repository=repository, branch=(branch or "")))
        if gone:
            return None, ("That branch is not one the last scan of this "
                          "repository found, so there is no code here to "
                          "review: " + gone)
    if row is None:
        row = Certification(repository=repository, branch=(branch or ""))
        session.add(row)

    row.note = note[:4000]
    row.automatic = bool(automatic)
    row.commit_sha = (commit_sha or "")[:64]
    row.certified_by = actor or ""
    row.certified_at = utcnow()
    row.expires_at = expires_at
    # Recertifying clears a previous withdrawal: this is a fresh review, and
    # the audit log keeps the fact that the old one was taken back.
    row.revoked_at = None
    row.revoked_by = ""
    row.revoked_reason = ""
    session.flush()
    log.info("%s certified %s on %s until %s", actor, repository,
             branch or "(default)", expires_at)
    return row, ""


def blocking_branches(session, repository: str, default_branch: str = "") -> set:
    """Which branches of this repository hold a finding somebody has to read.

    Only the grades that stop a sign off are fetched, so a repository carrying
    thousands of low findings costs the same here as an empty one.

    A finding remembers every branch it was seen on, and one on the default
    branch may name no branch at all, so both readings are followed.  Guessing
    the other way would sign off a branch because the finding on it was filed
    under a name this loop did not recognize.
    """
    import json

    blocked = set()
    rows = (session.query(Finding.branch, Finding.branches)
            .filter(Finding.repository == repository)
            .filter(Finding.state == FindingState.OPEN)
            .filter(Finding.excepted.is_(False))
            .filter(Finding.severity.notin_(AUTOMATIC_CLEAR))
            .all())
    for branch, listed in rows:
        try:
            names = [str(name) for name in (json.loads(listed or "[]") or [])
                     if name]
        except (TypeError, ValueError):
            names = []
        for name in (names or [branch or default_branch]):
            blocked.add(name or default_branch)
    return blocked


def _written_by_a_scan(session, repository: str, branch: str,
                       default_branch: str):
    """The certification a scan may write over here, if there is one.

    -> (row, whether to leave the branch alone).

    The default branch can be certified under its name or under no name at
    all, because a certification written from a finding uses the branch the
    finding named and a finding on the default branch often names none.  Both
    are the same branch, so both are looked at.  Missing that would put a
    second badge on a branch a person had already signed, and coverage counts
    badges.
    """
    row = for_branch(session, repository, branch)
    if row is None and branch and branch == default_branch:
        row = for_branch(session, repository, "")
    if row is None:
        return None, False
    # A person's sign off is never touched by a scan, in any state.  Not
    # refreshed, not re-dated, and least of all revived after they withdrew it.
    if not row.automatic:
        return row, True
    if row.revoked_at is not None:
        return row, True
    return row, False


def auto_certify(session, repositories, actor: str = AUTOMATIC_ACTOR) -> dict:
    """Sign off the branches a completed scan found nothing to read on.

    -> {certified, refreshed, considered, blocked}.

    Callers pass only repositories whose passes all finished this run.  That
    check belongs with whoever read the scan, because the report is the only
    thing that knows it, and it is not optional: without it the badge means
    "our engines said nothing", which is what a dead engine says too.

    What it will not do, in order of how much damage each would be:

      Overwrite a person.  Their note, their date and their withdrawal all
      stand, and the branch is left alone.

      Sign off a branch holding a finding above low.  Low and informational
      are the grades a reader would pass over, and they are the only ones
      passed over here.

      Sign off a branch somebody marked as not applicable.  They said no
      review was expected there; a green badge is not a way of agreeing.

      Repeat itself.  A badge that is already current is left where it is, so
      an estate that has settled writes nothing on every scan.
    """
    import json

    from datetime import timedelta

    from app.core.models import Repository

    named = sorted({str(name) for name in (repositories or []) if name})
    out = {"certified": 0, "refreshed": 0, "considered": 0, "blocked": 0}
    if not named:
        return out

    expires_at = utcnow() + timedelta(days=AUTOMATIC_DAYS)
    for repo in (session.query(Repository)
                 .filter(Repository.full_name.in_(named)).all()):
        # Archived code cannot be changed, so a badge on it is not coverage
        # anybody wanted.  The coverage figure leaves these out entirely and
        # this follows it rather than inventing a second rule.
        if repo.archived:
            continue
        default_branch = repo.default_branch or ""
        try:
            walked = [str(name) for name in
                      (json.loads(repo.branch_names or "[]") or []) if name]
        except (TypeError, ValueError):
            walked = []
        # A scan that recorded no branch names still walked the default one.
        if not walked and default_branch:
            walked = [default_branch]
        try:
            heads = json.loads(repo.branch_heads or "{}") or {}
        except (TypeError, ValueError):
            heads = {}

        blocked = blocking_branches(session, repo.full_name, default_branch)
        for branch in walked:
            out["considered"] += 1
            if branch in blocked:
                out["blocked"] += 1
                continue
            if exemption(session, repo.full_name, branch) is not None:
                continue

            row, leave_alone = _written_by_a_scan(
                session, repo.full_name, branch, default_branch)
            if leave_alone:
                continue
            head = str(heads.get(branch, "") or "")
            if row is not None and status(session, row, head).get("state") == ACTIVE:
                continue

            # Refreshing writes back under the name the row already has, so a
            # branch ends up with one badge rather than one per spelling.
            where = row.branch if row is not None else branch
            fresh, problem = certify(session, repo.full_name, where,
                                     AUTOMATIC_NOTE, expires_at, actor, head,
                                     automatic=True)
            if problem:
                log.warning("could not certify %s on %s automatically: %s",
                            repo.full_name, branch or "(default)", problem)
                continue
            out["refreshed" if row is not None else "certified"] += 1

    if out["certified"] or out["refreshed"]:
        log.info("automatically certified %d branch(es) and refreshed %d, "
                 "out of %d looked at",
                 out["certified"], out["refreshed"], out["considered"])
    return out


def revoke(session, repository: str, branch: str, actor: str,
           reason: str = "") -> tuple:
    """Take one back.  Kept rather than deleted.  -> (row, why not)."""
    row = for_branch(session, repository, branch)
    if row is None:
        return None, "There is no certification on that branch."
    if row.revoked_at is not None:
        return None, "That one has already been withdrawn."
    row.revoked_at = utcnow()
    row.revoked_by = actor or ""
    row.revoked_reason = (reason or "")[:2000]
    session.flush()
    return row, ""


def exemption(session, repository: str, branch: str):
    """The record saying this branch is not expected to be signed off."""
    from app.core.models import CertificationExemption

    if not repository:
        return None
    return (session.query(CertificationExemption)
            .filter(CertificationExemption.repository == repository)
            .filter(CertificationExemption.branch == (branch or ""))
            .one_or_none())


def mark_not_applicable(session, repository: str, branch: str, reason: str,
                        actor: str) -> tuple:
    """Say no sign off is expected on this branch.  -> (row, why not).

    A reason is required and held to the same length as a certification note.
    This one removes work from somebody's list permanently, so it has to be
    reviewable by whoever finds it later and wonders why the branch was never
    looked at.
    """
    from app.core.models import CertificationExemption

    if not repository:
        return None, "There is no repository to mark."
    reason = (reason or "").strip()
    if len(reason) < 20:
        return None, ("Say why no review is expected here.  Somebody is going "
                      "to find this later and have to take it on trust.")

    row = exemption(session, repository, branch)
    if row is None:
        row = CertificationExemption(repository=repository,
                                     branch=(branch or ""))
        session.add(row)
    row.reason = reason[:4000]
    row.marked_by = actor or ""
    row.marked_at = utcnow()
    session.flush()
    log.info("%s marked %s on %s as not applicable for certification",
             actor, repository, branch or "(default)")
    return row, ""


def clear_not_applicable(session, repository: str, branch: str,
                         actor: str) -> tuple:
    """Put the branch back among the ones a sign off is expected on."""
    row = exemption(session, repository, branch)
    if row is None:
        return None, "That branch is not marked as not applicable."
    session.delete(row)
    session.flush()
    log.info("%s put %s on %s back among the branches expecting a review",
             actor, repository, branch or "(default)")
    return row, ""


def all_certifications(session, base=None) -> list:
    """Every sign off on record, newest first.

    The state is not stored: a branch that has moved since it was reviewed is
    amber whether or not anybody has looked at it since, so it is worked out
    when it is asked for rather than written down and left to go stale.
    """
    from app.core.models import Certification

    query = base if base is not None else session.query(Certification)
    return query.order_by(Certification.certified_at.desc()).all()


def coverage(session, repos, certifications=None, exemptions=None) -> dict:
    """How much of what could be signed off has been.  -> a dict of counts.

    The denominator is branches, not repositories and not certifications.  A
    count of certifications answers "how many reviews exist", which is a number
    that only ever goes up and tells nobody how much is left.  Branches answer
    "how much of this has been read", which is the question somebody looking at
    a coverage figure is actually asking.

    Branches come from what the scanner recorded walking each repository, so
    the denominator is the branches this product has actually looked at rather
    than every ref that has ever existed on the host.  A repository nobody has
    scanned yet contributes nothing to either side, which is right: it is not
    coverage somebody owes, it is a scan somebody owes.

    Exempted branches come out of the denominator entirely.  They are not
    counted as done and they are not counted as outstanding, because a total
    that includes branches nobody intends to review measures the wrong thing,
    and a percentage nobody believes gets ignored rather than argued with.

    Every argument is a query so the caller can narrow all three the same way.
    Narrowing one and not the others is how a reader ends up being shown a
    percentage of somebody else's estate.
    """
    import json as _json

    from app.core.models import Certification, CertificationExemption, Repository

    # Archived repositories are left out entirely.  A branch on code that can
    # no longer be changed is not coverage anybody owes, and counting it means
    # the figure gets worse every time a repository is retired, which is the
    # opposite of what retiring one should do.
    rows = (repos if repos is not None else session.query(Repository))
    rows = rows.filter(Repository.archived.is_(False))
    population = set()
    default_branch = {}
    for full_name, default, names in rows.with_entities(
            Repository.full_name, Repository.default_branch,
            Repository.branch_names).all():
        default_branch[full_name] = default or ""
        try:
            walked = _json.loads(names or "[]")
        except (ValueError, TypeError):
            walked = []
        for branch in walked:
            if branch:
                population.add((full_name, branch))

    def _resolve(repository, branch):
        """A certification names the branch a finding was on, and a finding on
        the default branch may carry no branch at all."""
        return (repository, branch or default_branch.get(repository, ""))

    exempt = set()
    marks = (exemptions if exemptions is not None
             else session.query(CertificationExemption))
    for repository, branch in marks.with_entities(
            CertificationExemption.repository,
            CertificationExemption.branch).all():
        key = _resolve(repository, branch)
        # Only counted when the branch is one this install has walked.  An
        # exemption on something outside the population would otherwise shrink
        # the denominator below the branches it is made of.
        if key in population:
            exempt.add(key)

    certified = 0
    wanted = [row for row in (certifications if certifications is not None
                              else session.query(Certification)).all()
              if _resolve(row.repository, row.branch) in population
              and _resolve(row.repository, row.branch) not in exempt]
    for state in statuses(session, wanted):
        if state.get("state") == ACTIVE:
            certified += 1

    certifiable = len(population) - len(exempt)
    return {
        "certified": certified,
        "certifiable": certifiable,
        "exempt": len(exempt),
        "branches": len(population),
        "percent": (round(100 * certified / certifiable)
                    if certifiable else 0),
    }


def scope_seal(session, repos, certifications=None, exemptions=None,
               organization="", repository="", branch="") -> dict:
    """-> what a seal on this scope may claim, or {"show": False}.

    A seal is only honest when everything in the scope carries one.  Signed
    off on eleven branches of twelve is not a certified repository, and a
    green mark that means "mostly" is worth less than no mark, because the
    reader cannot tell which kind of mostly they are looking at.

    So this counts the same population `coverage` does, narrowed to what is on
    screen, and shows nothing unless the two numbers meet.  An empty scope
    shows nothing either: no branches signed off is not the same claim as no
    branches, and a seal on an empty set is the easiest way to be wrong.

    A sign off a scan wrote is marked as one, here as everywhere else.  The
    difference between "somebody read this" and "the engines had nothing to
    say about it" is the whole reason the automatic flag exists, and a seal
    that blurred the two would be the worst place to blur it.
    """
    import json as _json

    from app.core.models import Certification, CertificationExemption, Repository

    rows = (repos if repos is not None else session.query(Repository))
    rows = rows.filter(Repository.archived.is_(False))
    if repository:
        rows = rows.filter(Repository.full_name == repository)
    elif organization:
        rows = rows.filter(Repository.organization == organization)

    population, default_branch = set(), {}
    for full_name, default, names in rows.with_entities(
            Repository.full_name, Repository.default_branch,
            Repository.branch_names).all():
        default_branch[full_name] = default or ""
        try:
            walked = _json.loads(names or "[]")
        except (ValueError, TypeError):
            walked = []
        for name in walked:
            if name and (not branch or name == branch):
                population.add((full_name, name))

    if not population:
        return {"show": False}

    def _resolve(repo_name, name):
        return (repo_name, name or default_branch.get(repo_name, ""))

    marks = (exemptions if exemptions is not None
             else session.query(CertificationExemption))
    exempt = {key for key in (
        _resolve(repo_name, name) for repo_name, name in
        marks.with_entities(CertificationExemption.repository,
                            CertificationExemption.branch).all())
        if key in population}

    certifiable = len(population) - len(exempt)
    if certifiable <= 0:
        return {"show": False}

    signed, automatic, newest, who = 0, 0, None, ""
    done = set()
    wanted = [row for row in (certifications if certifications is not None
                              else session.query(Certification)).all()
              if _resolve(row.repository, row.branch) in population
              and _resolve(row.repository, row.branch) not in exempt]
    for row, state in zip(wanted, statuses(session, wanted)):
        if state.get("state") != ACTIVE:
            continue
        key = _resolve(row.repository, row.branch)
        signed += 1
        done.add(key)
        if row.automatic:
            automatic += 1
        when = _aware(row.certified_at)
        if when is not None and (newest is None or when > newest):
            newest, who = when, row.certified_by or ""

    if signed != certifiable:
        # The counts come back even though the seal does not.  A scope that is
        # nearly signed off and a scope nobody has touched both showed nothing
        # here, and the difference is the whole question the reader has: the
        # branch box on this page can only offer branches that carry findings,
        # so a repository whose other branches are clean looks like a
        # repository of one branch and the missing seal reads as a bug.
        #
        # And the names of the ones that are short, because the number on its
        # own cannot be acted on.  "One of three signed off" on a page whose
        # branch box offers one branch is a reader being told they are missing
        # two of something they cannot find: the other two are clean, so they
        # carry no findings, so nothing on the page mentions them.  Named, the
        # sentence becomes a list of what to go and do.
        missing = sorted(population - exempt - done)
        return {"show": False, "signed": signed, "certifiable": certifiable,
                "exempt": len(exempt),
                "outstanding": [{"repository": repo_name, "branch": name}
                                for repo_name, name in missing[:MAX_NAMED]],
                "outstanding_total": len(missing)}

    return {
        "show": True,
        "branches": signed,
        "exempt": len(exempt),
        "automatic": automatic,
        # Three ways to say who, because a mixed set is neither of the other
        # two and reading it as either would be a claim nobody made.
        "by_a_person": automatic == 0,
        "by_a_scan": automatic == signed,
        "who": who,
        "at": newest,
    }


def sealed_repositories(session, repos, certifications=None,
                        exemptions=None) -> set:
    """Every repository where each branch walked carries an active sign off.

    -> {"org/name", ...}

    The same population and the same rules scope_seal applies to one scope,
    asked once for a whole list of them.  A table row cannot afford a query
    each, and a mark worked out by a different rule than the seal beside it is
    two marks that disagree the first time somebody checks them against each
    other.

    So the rules are repeated deliberately rather than approximated: a branch
    marked not applicable is left out of the count instead of counted as done,
    a sign off only counts while it is active, and a repository with nothing
    certifiable gets no mark, because a seal on an empty set is the easiest
    way to be wrong.
    """
    import json as _json

    from app.core.models import Certification, CertificationExemption, Repository

    rows = (repos if repos is not None else session.query(Repository))
    rows = rows.filter(Repository.archived.is_(False))

    population, default_branch = set(), {}
    for full_name, default, names in rows.with_entities(
            Repository.full_name, Repository.default_branch,
            Repository.branch_names).all():
        default_branch[full_name] = default or ""
        try:
            walked = _json.loads(names or "[]")
        except (ValueError, TypeError):
            walked = []
        for name in walked:
            if name:
                population.add((full_name, name))
    if not population:
        return set()

    def _resolve(repo_name, name):
        return (repo_name, name or default_branch.get(repo_name, ""))

    marks = (exemptions if exemptions is not None
             else session.query(CertificationExemption))
    exempt = {key for key in (
        _resolve(repo_name, name) for repo_name, name in
        marks.with_entities(CertificationExemption.repository,
                            CertificationExemption.branch).all())
        if key in population}

    done = set()
    wanted = [row for row in (certifications if certifications is not None
                              else session.query(Certification)).all()
              if _resolve(row.repository, row.branch) in population
              and _resolve(row.repository, row.branch) not in exempt]
    for row, state in zip(wanted, statuses(session, wanted)):
        if state.get("state") == ACTIVE:
            done.add(_resolve(row.repository, row.branch))

    owed, signed = {}, {}
    for key in population - exempt:
        owed[key[0]] = owed.get(key[0], 0) + 1
        if key in done:
            signed[key[0]] = signed.get(key[0], 0) + 1
    return {name for name, total in owed.items()
            if total and signed.get(name, 0) == total}


def all_exemptions(session, base=None) -> list:
    """Every branch marked as not expecting a sign off, newest first."""
    from app.core.models import CertificationExemption

    query = base if base is not None else session.query(CertificationExemption)
    return query.order_by(CertificationExemption.marked_at.desc()).all()


def counts(session, base=None) -> dict:
    """-> {active, stale, lapsed, revoked, total}.  Where the sign offs stand.

    Stale is reported separately from active rather than folded into it,
    because a badge that has gone amber is the one that needs somebody.  A
    single "certified" number would count a review that no longer describes
    the code as though it still did, which is the exact failure the amber
    state was added to prevent.

    `base` narrows this to what a reader may see, the same as everywhere else.

    "automatic" counts how many of the current ones were written by a scan
    rather than by a person.  It is a subset of active, not another state, and
    it is here because the sentence a report writes about these numbers has to
    be able to tell the two apart.  "Reviewed by the security team" is not a
    thing to say about a badge nobody read anything for.
    """
    from app.core.models import Certification

    rows = (base if base is not None else session.query(Certification)).all()
    out = {ACTIVE: 0, STALE: 0, RESCANNING: 0, UNKNOWN: 0, LAPSED: 0,
           REVOKED: 0, "automatic": 0}
    for row, found in zip(rows, statuses(session, rows)):
        state = found.get("state", "")
        if state in out:
            out[state] += 1
        if state == ACTIVE and row.automatic:
            out["automatic"] += 1
    out["total"] = len(rows)
    return out
