"""Severity, as this organization means it.

A scanner grades a rule once, for everybody who will ever run it.  That grade
is a reasonable default and a poor answer: a plain HTTP link to an image on a
marketing page and a plain HTTP link carrying a session are the same rule and
very different risks, and only the people who own the system can say which one
they have.

So an override is a first class thing here, matched on any of the fields a
person can read off a finding: the rule that fired, a CWE it carries, the kind
of thing it is, the state it is in, the value a credential leaked, how it was
exposed, how sure the engine was, which engine said so, and the line of code
itself.  The engine's own grade is not thrown away: what changes is what the
number means to the people reading it.

A rule can also ask about more than one of those at once, and that is usually
what somebody means.  "A credential that only ever existed in git history is a
medium" is three conditions and one decision.  Written as three separate
overrides it would be a different thing entirely, because each one would fire
on its own and regrade findings nobody meant to touch.  So conditions are
joined, either all of them or any of them, and the whole set is one rule with
one reason attached to it.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re

from app.core.models import Severity, SeverityRule

log = logging.getLogger("gcr.severity_rules")

# The fields a condition can read, and what they are called on a finding page.
# The labels are the labels: somebody writing a rule is looking at a finding
# and typing what they see, so the words have to be the same words.
FIELDS = (
    ("rule", "What", "The rule that fired, by name"),
    ("path", "Where", "The file, or the package for a dependency. * matches "
                      "any part, such as src/legacy/* or */test/*"),
    ("repository", "Repository", "owner/name, as the findings list shows it. * "
                                 "matches any part, such as team/* or */*-demo"),
    ("cwe", "CWE", "A CWE the finding carries"),
    ("kind", "Kind", "credential, code, dependency or misconfiguration"),
    ("state", "State", "open, waived or fixed"),
    ("value", "Value", "The masked value of a leaked credential"),
    ("exposure", "Exposure", "current_and_history or git_history_only"),
    ("author", "Committed by", "The name, login or email on the commit"),
    ("confidence", "Confidence", "How sure the engine was: low, medium, high, "
                                 "or unrated where it did not say"),
    ("engine", "Found by", "The engine that reported it, such as semgrep or trivy"),
    ("snippet", "Code", "Text in the line the engine matched"),
    ("fingerprint", "Fingerprint", "The finding's own fingerprint, which names "
                                   "one finding and nothing else"),
)

MATCH_TYPES = tuple(name for name, _label, _help in FIELDS)

FIELD_LABELS = {name: label for name, label, _help in FIELDS}

# How specific a field is, when two rules both match and only one grade can
# win.  A rule name names one thing somebody wrote; a kind names a quarter of
# the database.
# A line of code ranks with a credential value: both name a particular thing
# somebody wrote.  An engine names a third of the database and confidence names
# most of it, so both sit at the bottom with kind and state.
# A fingerprint names one finding and no other, so it is the most specific
# thing anybody can write and it outranks even a rule name.
# A path names a place somebody wrote; a repository names a whole codebase,
# narrower than a CWE and wider than a line.
FIELD_RANK = {"fingerprint": 6, "rule": 5, "value": 4, "author": 4,
              "snippet": 4, "path": 4, "repository": 3, "cwe": 3,
              "exposure": 2, "engine": 2, "kind": 1, "state": 1, "confidence": 1}

# What a fingerprint looks like, with the kind in front or without it.  Checked
# when a rule is saved: a fingerprint is copied off a page, and a value that
# could never match one is a typo rather than an unusual choice.
FINGERPRINT = re.compile(r"(?:[a-z]+:)?[0-9a-f]{8,64}$")

# The values that are not free text.  A typo in one of these is a rule that
# silently never fires, which is worse than an error message.
ALLOWED = {
    "kind": ("credential", "code", "dependency", "misconfiguration"),
    "state": ("open", "waived", "fixed"),
    # unrated is a value somebody can ask for, not one an engine writes.  It
    # stands for the empty field: a CVE match, a Trivy check, or a rule that
    # never said how sure it was.
    "confidence": ("low", "medium", "high", "unrated"),
}

COMBINE = ("all", "any")

# What this tool thinks some rules are worth, before anybody says otherwise.
#
# These are the tool's opinion rather than somebody's decision, which is why
# they live here as a constant instead of as rows: a row in the table names a
# person who made a call, and seeding one would have to invent that person.
# An install that disagrees writes a real row, and that row wins.
#
# The three below came out of putting this side by side with a commercial
# scanner on the same repository.  It graded all three low; this graded all
# three high, on infrastructure that was doing what it was designed to do.
# Being louder than the alternative is not the same as being better than it,
# and on these the other tool was right.
#
# Each carries the sensitivity labels that take the exception away again,
# because these are downgrades of exposure and encryption findings, and the
# argument for calling them minor stops holding on a system that holds
# regulated data.
SHIPPED = {
    "aws-0053": (
        "low",
        "A load balancer being reachable from the internet is what a public "
        "application is for. Graded high it fires on every public service in "
        "an estate and teaches people that this rule means nothing, which "
        "costs more than it finds. It stays reportable because an internal "
        "service that became internet facing by accident looks exactly the "
        "same in the file.",
        "PCI, HIPAA, CUI"),
    "aws-0132": (
        "low",
        "Storage encrypted with a provider managed key rather than a customer "
        "managed one. The data is encrypted either way: this is a statement "
        "about who holds the key, which is a compliance preference in most "
        "places and a requirement in a few.",
        "PCI, HIPAA, CUI"),
    "aws-0033": (
        "low",
        "The same question about a container registry rather than a bucket, "
        "and the same answer.",
        "PCI, HIPAA, CUI"),
    "aws-0031": (
        "medium",
        "A mutable image tag can be moved under you by anybody who can write "
        "to the registry, which is a real supply chain problem and not a high "
        "one: it needs push access to the registry first, and that is a much "
        "larger thing to have already lost.",
        ""),
}


def all_rules(session) -> list:
    return (session.query(SeverityRule)
            .order_by(SeverityRule.match_type, SeverityRule.pattern).all())


def _clean_condition(field: str, value: str) -> tuple:
    """One condition, checked.  -> ((field, value), why not)."""
    field = (field or "").strip().lower()
    value = (value or "").strip()
    if field not in MATCH_TYPES:
        return None, "Match on one of: %s." % ", ".join(
            FIELD_LABELS[name] for name in MATCH_TYPES)
    if not value:
        return None, "Give %s something to match." % FIELD_LABELS[field]
    if field == "fingerprint" and not FINGERPRINT.match(value.lower()):
        # The same reasoning as the list below.  Somebody typing a rule name
        # or a file path in here would get a rule that never fires and no
        # word about why, which is the failure this module exists to avoid.
        return None, ("A fingerprint is the one printed on the finding, a "
                      "kind and then hex. Copy it from the finding rather "
                      "than typing it.")
    allowed = ALLOWED.get(field)
    if allowed and value.lower() not in allowed:
        # Named rather than hinted at.  A rule that quietly never fires is
        # worse than one that would not save, because nobody goes back to
        # check whether the grade they wrote ever applied to anything.
        return None, "%s is one of: %s." % (FIELD_LABELS[field],
                                            ", ".join(allowed))
    return (field, value[:200]), ""


def add(session, match_type: str, pattern: str, severity, actor: str = "",
        reason: str = "", unless_sensitivity: str = "",
        conditions=None, combine: str = "all") -> tuple:
    """-> (row, why not).  One override per set of conditions.

    `conditions` are the ones after the first, as (field, value) pairs or as
    {"field": ..., "value": ...}.  `combine` is "all" or "any" and decides
    whether a finding has to satisfy every one of them or just one.
    """
    first, why = _clean_condition(match_type, pattern)
    if first is None:
        return None, why
    match_type, pattern = first

    combine = (combine or "all").strip().lower()
    if combine not in COMBINE:
        combine = "all"

    extra = []
    for item in (conditions or []):
        if isinstance(item, dict):
            field, value = item.get("field"), item.get("value")
        else:
            field, value = item
        # An empty row in the form is somebody not using it, not an error.
        if not str(field or "").strip() and not str(value or "").strip():
            continue
        pair, why = _clean_condition(field, value)
        if pair is None:
            return None, why
        if pair == (match_type, pattern) or pair in extra:
            continue
        extra.append(pair)

    try:
        severity = severity if isinstance(severity, Severity) else Severity(str(severity).lower())
    except ValueError:
        return None, "That is not a severity."

    # One override per set of conditions, so saving the same set again edits
    # it rather than leaving two rules disagreeing about the same findings.
    encoded = json.dumps([{"field": f, "value": v} for f, v in extra])
    row = None
    for candidate in (session.query(SeverityRule)
                      .filter(SeverityRule.match_type == match_type,
                              SeverityRule.pattern == pattern).all()):
        if _conditions_of(candidate) == extra:
            row = candidate
            break
    if row is None:
        row = SeverityRule(match_type=match_type, pattern=pattern)
        session.add(row)
    row.conditions = encoded
    row.combine = combine
    row.severity = severity
    row.reason = (reason or "")[:2000]
    row.unless_sensitivity = (unless_sensitivity or "")[:400]
    row.created_by = actor or ""
    session.flush()
    return row, ""


def _conditions_of(row) -> list:
    """Everything after the first condition, as (field, value) pairs."""
    try:
        listed = json.loads(getattr(row, "conditions", "") or "[]") or []
    except (TypeError, ValueError):
        log.warning("severity rule %s has conditions that are not readable",
                    getattr(row, "id", "?"))
        return []
    out = []
    for item in listed:
        if not isinstance(item, dict):
            continue
        field = str(item.get("field") or "").strip().lower()
        value = str(item.get("value") or "").strip()
        if field in MATCH_TYPES and value:
            out.append((field, value))
    return out


def conditions_of(row) -> list:
    """Every condition on this rule, first one included."""
    return [(row.match_type, row.pattern)] + _conditions_of(row)


def describe(row) -> str:
    """The rule as a sentence, for a table somebody has to read quickly."""
    joiner = " and " if (row.combine or "all") == "all" else " or "
    return joiner.join("%s = %s" % (FIELD_LABELS.get(field, field), value)
                       for field, value in conditions_of(row))


def remove(session, rule_id: int) -> bool:
    row = session.query(SeverityRule).filter(SeverityRule.id == rule_id).one_or_none()
    if row is None:
        return False
    session.delete(row)
    return True


def _tags(value) -> set:
    return {t.strip().lower() for t in str(value or "").split(",") if t.strip()}


def as_map(session) -> dict:
    """Loaded once per ingest rather than queried per finding.

    Two things in one, because they answer two different questions.  The
    "rule" and "cwe" maps are the old lookup, kept because a rule name or a
    CWE is all most overrides are about and a dictionary answers that in one
    step.  "rows" is every override compiled into conditions, which is the
    only way to answer a rule about the kind, the state, the value or the
    exposure, and the only way to answer one about several at once.
    """
    out = {"rule": {}, "cwe": {}, "rows": []}
    # The tool's own opinion first, so a decision somebody actually made
    # overwrites it below rather than the other way round.
    for pattern, (level, _why, unless) in SHIPPED.items():
        try:
            out["rule"][pattern] = (Severity(level), _tags(unless))
            out["rows"].append({"conditions": [("rule", pattern)],
                                "combine": "all", "severity": Severity(level),
                                "unless": _tags(unless), "shipped": True})
        except ValueError:          # a typo here must not take a scan down
            log.warning("shipped severity for %s is not a severity", pattern)
    for row in all_rules(session):
        if row.match_type in ("rule", "cwe") and not _conditions_of(row):
            out.setdefault(row.match_type, {})[row.pattern.strip().lower()] = (
                row.severity, _tags(row.unless_sensitivity))
        out["rows"].append({"conditions": conditions_of(row),
                            "combine": (row.combine or "all"),
                            "severity": row.severity,
                            "unless": _tags(row.unless_sensitivity),
                            "shipped": False})
    return out


def _field_of(finding, field: str) -> str:
    """What this finding says in that field, as plain lowercase text."""
    if field == "rule":
        return str(getattr(finding, "rule", "") or "").strip().lower()
    if field == "cwe":
        return str(getattr(finding, "cwe", "") or "").strip().lower()
    if field == "value":
        return str(getattr(finding, "secret_preview", "") or "").strip().lower()
    if field == "exposure":
        return str(getattr(finding, "exposure", "") or "").strip().lower()
    if field == "confidence":
        return str(getattr(finding, "confidence", "") or "").strip().lower()
    if field == "engine":
        # A comma joined list, because two engines landing on the same line is
        # kept rather than blended into one name.
        return str(getattr(finding, "engines", "") or "").strip().lower()
    if field == "snippet":
        return str(getattr(finding, "snippet", "") or "").strip().lower()
    if field == "fingerprint":
        return str(getattr(finding, "fingerprint", "") or "").strip().lower()
    if field == "repository":
        return str(getattr(finding, "repository", "") or "").strip().lower()
    if field == "path":
        # What the Where column shows: the file, or the package where a
        # dependency has no file of its own.
        return str(getattr(finding, "file_path", "") or getattr(finding, "package_name", "")
                   or "").strip().lower()
    if field in ("kind", "state"):
        raw = getattr(finding, field, "")
        return str(getattr(raw, "value", raw) or "").strip().lower()
    return ""


def _author_of(finding) -> list:
    """The three ways the blame pass can name whoever wrote the line.

    All three are checked, because somebody writing a rule types the one they
    happen to know.  A login is what the host shows, a name is what the commit
    carries, and an email is the only one of the three that is reliably there
    on a repository whose commits were never linked to an account.
    """
    return [str(getattr(finding, name, "") or "").strip().lower()
            for name in ("author_login", "author_name", "author_email")]


def _one_matches(field: str, pattern: str, finding) -> bool:
    """Does this finding satisfy one condition."""
    pattern = (pattern or "").strip().lower()
    if not pattern:
        return False
    if field == "cwe":
        # A finding can carry several, and CWE-79 and 79 are the same thing to
        # a person.
        bare = pattern.replace("cwe-", "")
        for item in _field_of(finding, "cwe").split(","):
            item = item.strip()
            if item and (item == pattern or item.replace("cwe-", "") == bare):
                return True
        return False
    if field == "engine":
        # The same reading as a CWE: a list, and satisfying it means any one
        # of them matches.
        for actual in _field_of(finding, "engine").split(","):
            actual = actual.strip()
            if not actual:
                continue
            if ("*" in pattern or "?" in pattern):
                if fnmatch.fnmatch(actual, pattern):
                    return True
            elif actual == pattern:
                return True
        return False
    if field == "snippet":
        # Contains, not equals, and no wildcards.
        #
        # Nobody writing a rule about code types a whole line back, so this
        # matches anywhere in the line.  A star is a star here rather than a
        # wildcard, because "SELECT * FROM orders" is exactly the sort of
        # thing somebody pastes in, and reading that star as "anything" turns
        # a rule about one query into a rule that matches nothing at all.
        actual = _field_of(finding, "snippet")
        if not actual:
            return False
        return pattern in actual
    if field == "fingerprint":
        # Written with the kind in front or without it.  The page prints
        # code:c9379 and so on, and somebody copying it takes either the whole
        # thing or the hash on the end, and both name the same finding.
        actual = _field_of(finding, "fingerprint")
        if not actual:
            return False
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(actual, pattern)
        bare = pattern.split(":", 1)[-1]
        return actual == pattern or actual.split(":", 1)[-1] == bare
    if field == "author":
        for actual in _author_of(finding):
            if not actual:
                continue
            if ("*" in pattern or "?" in pattern):
                if fnmatch.fnmatch(actual, pattern):
                    return True
            elif actual == pattern:
                return True
        return False
    actual = _field_of(finding, field)
    if field == "confidence" and pattern == "unrated":
        return not actual
    if not actual:
        return False
    # A star is what somebody reaches for when they mean "any of these", and a
    # masked credential is unreadable without one.
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(actual, pattern)
    return actual == pattern


def matches(compiled: dict, finding) -> bool:
    """Does this finding satisfy the whole rule."""
    conditions = compiled.get("conditions") or []
    if not conditions:
        return False
    results = (_one_matches(field, value, finding)
               for field, value in conditions)
    return all(results) if compiled.get("combine", "all") == "all" \
        else any(results)


def _specificity(compiled: dict) -> tuple:
    """How much of a claim this rule is, so the narrower one wins.

    More conditions first, because a rule naming three things was written
    about a smaller set than one naming a single thing.  Then by the narrowest
    field it names: a rule name is one thing somebody wrote, a kind is a
    quarter of the database.  "all" beats "any" on a tie for the same reason.

    Ties beyond that go to whichever came out of the query first, which is by
    match type and pattern.  A tie here means two rules that cover exactly the
    same ground disagree, and that is a thing to decide in the page rather
    than to resolve by silently preferring one.
    """
    conditions = compiled.get("conditions") or []
    return (len(conditions),
            max((FIELD_RANK.get(field, 0) for field, _v in conditions),
                default=0),
            1 if compiled.get("combine", "all") == "all" else 0,
            0 if compiled.get("shipped") else 1)


def _sql_for(field: str, pattern: str):
    """One condition as something the database can count.  -> a filter clause.

    The same reading as `_one_matches` above, in the other language.  The two
    have to agree: a count that disagrees with what the rule actually does is
    worse than no count, because it is the number somebody decides on.
    """
    from sqlalchemy import func, literal, or_

    from app.core.models import Finding, FindingKind, FindingState

    pattern = (pattern or "").strip().lower()
    wild = "*" in pattern or "?" in pattern

    def text_clause(column):
        actual = func.lower(func.coalesce(column, ""))
        if wild:
            return (actual != "") & actual.like(
                pattern.replace("*", "%").replace("?", "_"))
        return actual == pattern

    if field == "kind":
        try:
            return Finding.kind == FindingKind(pattern)
        except ValueError:
            return literal(False)
    if field == "state":
        try:
            return Finding.state == FindingState(pattern)
        except ValueError:
            return literal(False)
    if field == "cwe":
        # A finding carries a list.  Wrapped in separators and stripped of
        # spaces so that cwe-79 cannot match cwe-798, which is a different
        # weakness and would quietly inflate the count.
        listed = (literal(",")
                  + func.replace(func.lower(func.coalesce(Finding.cwe, "")),
                                 " ", "")
                  + literal(","))
        bare = pattern.replace("cwe-", "")
        return or_(listed.like("%,{},%".format(pattern)),
                   listed.like("%,cwe-{},%".format(bare)),
                   listed.like("%,{},%".format(bare)))
    if field == "author":
        return or_(text_clause(Finding.author_login),
                   text_clause(Finding.author_name),
                   text_clause(Finding.author_email))
    if field == "engine":
        # Wrapped in separators the same way a CWE list is, so semgrep cannot
        # match a hypothetical semgrep-pro and inflate the count.
        listed = (literal(",")
                  + func.replace(func.lower(func.coalesce(Finding.engines, "")),
                                 " ", "")
                  + literal(","))
        return listed.like("%,{},%".format(
            pattern.replace("*", "%").replace("?", "_") if wild else pattern))
    if field == "fingerprint":
        # The same reading as `_one_matches`: the whole thing, or the hash on
        # the end of it.  endswith rather than a string built by hand, so the
        # value is escaped rather than read as a pattern.
        actual = func.lower(func.coalesce(Finding.fingerprint, ""))
        if wild:
            return (actual != "") & actual.like(
                pattern.replace("*", "%").replace("?", "_"))
        bare = pattern.split(":", 1)[-1]
        return or_(actual == pattern,
                   actual.endswith(":" + bare, autoescape=True))
    if field == "snippet":
        # Contains and nothing else, matching `_one_matches` above.  The two
        # have to agree or the number beside the rule is not the rule.
        #
        # autoescape, because a percent sign is ordinary punctuation in code
        # and a wildcard in SQL, and "%s" is exactly the kind of line somebody
        # writes a rule about.
        actual = func.lower(func.coalesce(Finding.snippet, ""))
        return (actual != "") & actual.contains(pattern, autoescape=True)
    if field == "confidence" and pattern == "unrated":
        # The same reading as `_one_matches`: nothing recorded at all.
        return func.coalesce(Finding.confidence, "") == ""
    if field == "path":
        # The file, or the package where there is no file, as `_field_of` reads it.
        return text_clause(func.coalesce(func.nullif(Finding.file_path, ""),
                                         Finding.package_name))
    column = {"rule": Finding.rule, "value": Finding.secret_preview,
              "repository": Finding.repository,
              "exposure": Finding.exposure,
              "confidence": Finding.confidence}.get(field)
    if column is None:
        return literal(False)
    return text_clause(column)


def matching_count(session, row, base=None) -> int:
    """How many findings this rule would grade.  -> a number.

    Somebody writing "kind = credential and state = open is a medium" is
    making a decision about a set they cannot see.  Two hundred findings and
    two are the same sentence and very different decisions, so the page says
    which one it is before they save it and after.

    It counts what is in the database now, which is what the next scan will
    regrade.  `base` narrows it to what the reader may see, so nobody is told
    a number made of somebody else's repositories.
    """
    from sqlalchemy import and_, or_

    from app.core.models import Finding

    clauses = [_sql_for(field, value) for field, value in conditions_of(row)]
    if not clauses:
        return 0
    joined = (and_(*clauses) if (getattr(row, "combine", "all") or "all") == "all"
              else or_(*clauses))
    query = base if base is not None else session.query(Finding)
    try:
        return query.filter(joined).count()
    except Exception:      # a count is not worth failing the page for
        log.exception("could not count what severity rule %s covers",
                      getattr(row, "id", "?"))
        return 0


def findings_query(row) -> str:
    """The findings list holding exactly what this rule covers, or "".

    A number somebody can see and cannot reach is a number they have to take
    on trust, so the count is a link where it can be.  It is empty rather than
    approximate everywhere else: the findings list can filter on the kind and
    the state and not on the exposure, the value or who committed the line, so
    a link for those rules would open a longer list than the number beside it
    and the reader would be right to stop believing both.
    """
    if (getattr(row, "combine", "all") or "all") != "all":
        return ""      # a list cannot say "or"
    kind = ""
    state = "any"
    for field, value in conditions_of(row):
        if field == "kind" and not kind:
            kind = value.lower()
        elif field == "state" and state == "any":
            state = value.lower()
        else:
            return ""
    # The same extra filters the heatmap cells carry.  The count is every
    # finding the rule covers, so the list it opens has to hold every one of
    # them rather than the ones on somebody's work list.
    return ("state=%s&kind=%s&exception=any&triage=any&baseline=any&group=none"
            % (state, kind))


def counts_for(session, rows, base=None) -> dict:
    """-> {rule id: how many findings it covers}."""
    return {row.id: matching_count(session, row, base=base) for row in rows}


def apply(overrides: dict, rule: str, cwe: str, sensitivity: str = "",
          finding=None):
    """The severity this organization gives it, or None to leave it alone.

    Given a finding, every override is checked against it and the narrowest
    one that matches wins: more conditions beat fewer, and among equals a rule
    name beats a kind.  Without one this falls back to the rule name and CWE
    it was handed, which is all the older callers ever had.

    A rule name is the more specific statement, so it wins over a CWE.  A
    finding can carry several CWEs; the first one anybody wrote a rule for
    decides, and the order is the order they came in.

    An override stops applying where the system holds something it was not
    written for.  "A plain HTTP link is low" is a fair statement about a
    brochure site and a careless one about the system holding cardholder data,
    so the tags on the connection can take the exception away again.
    """
    if not overrides:
        return None
    carried = _tags(sensitivity)

    if finding is not None:
        best = None
        for compiled in overrides.get("rows") or []:
            if not matches(compiled, finding):
                continue
            if compiled["unless"] and (carried & compiled["unless"]):
                # Not this system.  Nothing less specific gets to stand in for
                # it either: the exception was taken away here, and falling
                # through to a broader rule would put it back by another name.
                continue
            rank = _specificity(compiled)
            if best is None or rank > best[0]:
                best = (rank, compiled["severity"])
        return best[1] if best is not None else None

    def usable(entry):
        severity, unless = entry
        if unless and (carried & unless):
            return None      # this system is one the exception was not meant for
        return severity

    by_rule = overrides.get("rule") or {}
    entry = by_rule.get((rule or "").strip().lower())
    if entry is not None:
        return usable(entry)

    by_cwe = overrides.get("cwe") or {}
    if by_cwe and cwe:
        for item in str(cwe).split(","):
            item = item.strip().lower()
            if not item:
                continue
            if item in by_cwe:
                return usable(by_cwe[item])
            # CWE-79 and 79 are the same thing to a person.
            bare = item.replace("cwe-", "")
            for key, value in by_cwe.items():
                if key.replace("cwe-", "") == bare:
                    return usable(value)
    return None
