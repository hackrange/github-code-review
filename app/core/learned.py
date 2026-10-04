"""What AI validation decides, and what the scanner learns from it.

Three things live here, and they share one rule: a decision about the same
code is not made twice.

Grades from a model.  A validation that reads a finding as lower than the
scanner graded it lowers it.  Never higher: raising is a person's call.  Never
on a credential, a known exploited package or a malicious one: a model cannot
show a secret is dead or that an exploit does not apply, and the grading
policy says only that evidence lowers those.

Learned rules.  The model is asked which other findings of the same kind in
the repository deserve the same grade for the same reason, and the answer is
kept as a deterministic matcher with a synthetic test beside it.  The next
finding it covers, in a bulk run or a later scan, is answered from the rule
for nothing.  A rule is scoped to the repository it was learned in until a
person accepts it everywhere.

Grade basis.  Every grading decision, a person's or a model's, records what
code it was made against.  The same code on a later scan keeps the decision.
Different code lifts it, says why on the finding, and leaves it for review.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import re

from app.core.models import (AIGrade, Finding, FindingKind, FindingState,  # noqa: F401
                             GradeBasis, LearnedRule, Severity, utcnow)

log = logging.getLogger("gcr.learned")

RANK = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

# A model's rating, as a severity.  "Not exploitable" is info rather than gone:
# the finding stays readable and searchable with the reason on it.
RATING_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
    "INFO": Severity.INFO, "NOT EXPLOITABLE": Severity.INFO,
}

# Shortest text a learned rule may match a line on.  Anything shorter matches
# half the codebase by accident.
MIN_CONTAINS = 6


def _value(thing) -> str:
    return str(getattr(thing, "value", thing) or "")


# ------------------------------------------------------------------ policy

def protected(finding) -> str:
    """Why AI may not lower this finding, or "" when it may."""
    if finding.kind == FindingKind.CREDENTIAL:
        return ("a credential stays critical until something shows it is dead, "
                "and a model reading the code cannot show that")
    if finding.kind == FindingKind.DEPENDENCY and getattr(finding, "known_exploited", False):
        return ("it is known to be exploited, and only evidence that it does "
                "not ship lowers that")
    if getattr(finding, "malicious", None):
        return "a malicious package does its harm at install time"
    return ""


def lower(current, target) -> bool:
    """Is target strictly below current."""
    return RANK.get(_value(target), 0) < RANK.get(_value(current), 0) \
        and RANK.get(_value(target), 0) > 0


def severity_for(rating: str):
    return RATING_SEVERITY.get((rating or "").strip().upper())


# ------------------------------------------------------------------- basis

def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def basis_of(finding) -> str:
    """A digest of what a grade decision on this finding is about.

    The flagged lines for code and configuration, so an edit to them lifts
    the decision and an edit elsewhere in the file does not.  The version and
    advisory for a package.  Empty for a credential, whose identity is the
    secret itself, and for a finding with no lines to read.
    """
    if finding.kind == FindingKind.CREDENTIAL:
        return ""
    if finding.kind == FindingKind.DEPENDENCY:
        raw = "|".join([finding.package_name or "", finding.package_version or "",
                        finding.vulnerability_id or ""])
    else:
        raw = _norm(finding.snippet)
        if not raw:
            return ""
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:40]


def record_basis(session, finding, source: str):
    """Remember the code a decision was made against, replacing an older one."""
    if finding.id is None:
        session.flush()
    row = (session.query(GradeBasis)
           .filter(GradeBasis.finding_id == finding.id, GradeBasis.source == source)
           .one_or_none())
    if row is None:
        row = GradeBasis(finding_id=finding.id, source=source)
        session.add(row)
    row.basis = basis_of(finding)
    row.recorded_at = utcnow()
    row.lifted_at = None
    row.lifted_severity = ""
    row.lifted_reason = ""
    row.lifted_by = ""
    return row


def load_bases(session) -> dict:
    """{(finding_id, source): GradeBasis} for every decision still standing."""
    return {(row.finding_id, row.source): row
            for row in session.query(GradeBasis).filter(GradeBasis.lifted_at.is_(None))}


def code_changed(bases: dict, finding, source: str) -> bool:
    """Did the code under a standing decision change since it was made.

    A decision recorded before bases existed, or against a finding that had no
    lines then, takes the code as it is now as its basis: nothing says it
    changed, and assuming it did would undo a thousand decisions at once.
    """
    if finding.id is None:
        return False
    row = bases.get((finding.id, source))
    now = basis_of(finding)
    if row is None:
        return False
    if not row.basis or not now:
        row.basis = row.basis or now
        return False
    return row.basis != now


def lift(bases: dict, finding, source: str, severity: str, reason: str, by: str) -> None:
    row = bases.get((finding.id, source))
    if row is None:
        return
    row.lifted_at = utcnow()
    row.lifted_severity = severity or ""
    row.lifted_reason = (reason or "")[:2000]
    row.lifted_by = by or ""
    bases.pop((finding.id, source), None)


# ------------------------------------------------------------------- facts

def facts(finding) -> dict:
    """The parts of a finding a learned rule can read, as plain data.

    This is also what a synthetic test case stores, so a rule can be checked
    long after the finding it came from has been fixed.
    """
    return {
        "repository": finding.repository or "",
        "kind": _value(finding.kind),
        "rule": finding.rule or "",
        "file": finding.file_path or "",
        "snippet": (finding.snippet or "")[:1000],
        "package": finding.package_name or "",
        "version": finding.package_version or "",
        "advisory": finding.vulnerability_id or "",
        "severity": _value(finding.severity),
    }


# ---------------------------------------------------------------- patterns

PATTERN_LINE = re.compile(r"(?im)^\s*\**\s*learned pattern\s*\**\s*:\s*(\{.*\})\s*$")


def parse_pattern(text: str) -> dict:
    """The model's learned pattern line, or {} when it gave none."""
    match = None
    for match in PATTERN_LINE.finditer(text or ""):
        pass
    if match is None:
        return {}
    try:
        data = json.loads(match.group(1))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def strip_pattern(text: str) -> str:
    """The answer without the machine readable line, for the page."""
    return PATTERN_LINE.sub("", text or "").rstrip()


def _bad_glob(glob: str) -> bool:
    return len(glob) > 400 or ".." in glob or glob.startswith("/")


def proposal(finding, severity, pattern: dict) -> tuple:
    """-> (fields for a LearnedRule, "") or (None, why not).

    Everything the model proposes is checked against the finding it came
    from.  A pattern that would not match its own finding is a pattern about
    something else, and one too loose to say anything is refused.
    """
    if not pattern or not pattern.get("applies"):
        return None, "the model said its reasoning is about this one finding"
    kind = _value(finding.kind)
    fields = {"repository": finding.repository or "", "kind": kind,
              "severity": severity, "reason": str(pattern.get("why") or "")[:2000]}
    if kind == "dependency":
        if not finding.package_name:
            return None, "the finding names no package"
        advisory = str(pattern.get("advisory") or "").strip()
        if advisory not in ("*", (finding.vulnerability_id or "")):
            advisory = finding.vulnerability_id or ""
        fields.update(package=finding.package_name, advisory=advisory or "*")
        return fields, ""
    if kind not in ("code", "misconfiguration") or not finding.rule:
        return None, "only code, configuration and package findings are learned"
    glob = str(pattern.get("path_glob") or "").strip()
    contains = _norm(str(pattern.get("code_contains") or ""))
    if glob and (_bad_glob(glob) or not fnmatch.fnmatch(finding.file_path or "", glob)):
        glob = ""
    snippet = _norm(finding.snippet)
    if contains and (len(contains) < MIN_CONTAINS or contains not in snippet):
        contains = ""
    if not glob:
        glob = finding.file_path or ""
    if not contains and snippet:
        # Nothing narrower that still matches: the line itself.  Then the rule
        # covers this code wherever it appears in that path, and nothing else.
        contains = snippet[:500]
    if not contains and glob in ("", "*", "**"):
        return None, "the pattern would match every finding of that rule"
    fields.update(rule=finding.rule, path_glob=glob, code_contains=contains)
    return fields, ""


# ------------------------------------------------------------------ matching

def _matches(rule, f: dict) -> bool:
    """Does one learned rule cover these finding facts."""
    if (rule.kind or "") != f.get("kind"):
        return False
    if rule.kind == "dependency":
        if (rule.package or "") != f.get("package"):
            return False
        return (rule.advisory or "*") in ("*", f.get("advisory") or "")
    if (rule.rule or "").lower() != (f.get("rule") or "").lower():
        return False
    if rule.path_glob and not fnmatch.fnmatch(f.get("file") or "", rule.path_glob):
        return False
    if rule.code_contains and rule.code_contains not in _norm(f.get("snippet")):
        return False
    return True


def in_scope(rule, repository: str) -> bool:
    if rule.retired_at is not None:
        return False
    return bool(rule.global_accepted_by) or \
        (rule.repository or "").lower() == (repository or "").lower()


def load_rules(session) -> dict:
    """Live rules, indexed by what they key on, loaded once per run."""
    index = {}
    for rule in session.query(LearnedRule).filter(LearnedRule.retired_at.is_(None)):
        key = (rule.kind, (rule.package if rule.kind == "dependency" else rule.rule or "").lower())
        index.setdefault(key, []).append(rule)
    return index


def match(index: dict, finding):
    """The narrowest live rule in scope that covers this finding, or None."""
    f = facts(finding)
    key = (f["kind"], (f["package"] if f["kind"] == "dependency" else f["rule"]).lower())
    best = None
    for rule in index.get(key, ()):
        if not in_scope(rule, f["repository"]) or not _matches(rule, f):
            continue
        rank = (rule.repository.lower() == f["repository"].lower(),
                len(rule.code_contains or ""), len(rule.path_glob or ""),
                (rule.advisory or "*") != "*")
        if best is None or rank > best[0]:
            best = (rank, rule)
    return best[1] if best else None


# --------------------------------------------------------- synthetic tests

def fixture_of(rule) -> dict:
    try:
        data = json.loads(rule.fixture or "{}")
    except ValueError:
        data = {}
    data.setdefault("positive", [])
    data.setdefault("negative", [])
    return data


def self_test(rule) -> list:
    """What the rule's synthetic test says is wrong with it, empty when sound.

    Every positive case must match and every negative one must not.  Run when
    the rule is made, when a negative is added, and from the admin page.
    """
    data = fixture_of(rule)
    problems = []
    if not data["positive"]:
        problems.append("it has no case it was learned from")
    for case in data["positive"]:
        if not _matches(rule, case):
            problems.append("it no longer matches %s %s" % (case.get("file") or case.get("package"),
                                                           case.get("rule") or case.get("advisory")))
    for case in data["negative"]:
        if _matches(rule, case):
            problems.append("it matches %s, which a model refused to lower"
                            % (case.get("file") or case.get("package")))
    return problems


def create(session, finding, severity, fields: dict, analysis_id, model: str,
           by: str):
    """Keep a learned rule, unless an identical one is already live."""
    for rule in session.query(LearnedRule).filter(
            LearnedRule.retired_at.is_(None), LearnedRule.kind == fields["kind"],
            LearnedRule.repository == fields["repository"]):
        same = all((getattr(rule, name) or "") == (fields.get(name) or "")
                   for name in ("rule", "package", "advisory", "path_glob", "code_contains"))
        if same and rule.severity == severity:
            return rule
    rule = LearnedRule(created_by=by, model=(model or "")[:120],
                       source_finding_id=finding.id, source_analysis_id=analysis_id,
                       **{k: v for k, v in fields.items()})
    rule.fixture = json.dumps({"expect": _value(severity), "positive": [facts(finding)],
                               "negative": []})
    if self_test(rule):
        return None
    session.add(rule)
    session.flush()
    return rule


def add_negative(session, rule, finding, by: str, why: str) -> None:
    """A model refused to lower something this rule covers: the rule is wrong.

    The finding becomes a negative case, and the rule is retired, because a
    rule that matches what a model just said should stay graded is broader
    than the reason it was learned from.  Every grade it gave is taken back.
    """
    data = fixture_of(rule)
    data["negative"].append(facts(finding))
    rule.fixture = json.dumps(data)
    retire(session, rule, by, why)


def retire(session, rule, by: str, why: str) -> int:
    """Stop a rule and take back every grade it gave.  -> findings restored."""
    rule.retired_at = utcnow()
    rule.retired_by = by or ""
    rule.retired_reason = (why or "")[:2000]
    restored = 0
    for grade in session.query(AIGrade).filter(AIGrade.rule_id == rule.id).all():
        finding = session.get(Finding, grade.finding_id)
        if finding is not None and finding.custom_severity is None and grade.was:
            try:
                finding.severity = Severity(grade.was)
                restored += 1
            except ValueError:
                pass
        session.delete(grade)
    return restored


# ----------------------------------------------------------------- applying

def give(session, finding, severity, *, source: str, reason: str, by: str,
         analysis_id=None, rule_id=None, model: str = "") -> bool:
    """Grade a finding lower on a model's word.  -> True when the grade moved.

    The AI grade is kept even under a person's regrade, so it is there if the
    regrade is cleared, but the severity only moves when nobody has spoken.
    """
    if protected(finding) or not lower(finding.severity, severity):
        return False
    if finding.id is None:
        session.flush()
    grade = session.query(AIGrade).filter(AIGrade.finding_id == finding.id).one_or_none()
    if grade is None:
        grade = AIGrade(finding_id=finding.id)
        session.add(grade)
    grade.was = grade.was or _value(finding.severity)
    grade.severity = severity
    grade.reason = (reason or "")[:4000]
    grade.source = source
    grade.analysis_id = analysis_id
    grade.rule_id = rule_id
    grade.model = (model or "")[:120]
    grade.created_by = by or ""
    grade.created_at = utcnow()
    record_basis(session, finding, "ai")
    if finding.custom_severity is not None:
        return False
    finding.engine_severity = finding.engine_severity or _value(finding.severity)
    finding.severity = severity
    return True


def apply_rule_now(session, rule, by: str) -> int:
    """Grade every open finding the new rule covers, without asking anybody.

    The point of learning: one answer about renderMarkdown settles all seven
    v-html bindings that call it, in the same run.
    """
    query = session.query(Finding).filter(Finding.state == FindingState.OPEN)
    if not rule.global_accepted_by:
        query = query.filter(Finding.repository == rule.repository)
    if rule.kind == "dependency":
        query = query.filter(Finding.kind == FindingKind.DEPENDENCY,
                             Finding.package_name == rule.package)
    else:
        query = query.filter(Finding.kind == FindingKind(rule.kind),
                             Finding.rule == rule.rule)
    moved = 0
    for finding in query.limit(5000):
        if not _matches(rule, facts(finding)):
            continue
        existing = session.query(AIGrade).filter(AIGrade.finding_id == finding.id).one_or_none()
        if existing is not None and existing.source == "analysis":
            continue        # a model answered for this one itself
        if give(session, finding, rule.severity, source="rule",
                reason="learned rule #%d: %s" % (rule.id, rule.reason), by=by,
                rule_id=rule.id, model=rule.model):
            moved += 1
            rule.hits = (rule.hits or 0) + 1
            rule.last_hit_at = utcnow()
    return moved


def load_grades(session) -> dict:
    """{finding_id: AIGrade} for applying at ingest."""
    return {row.finding_id: row for row in session.query(AIGrade)}


def describe(rule) -> str:
    """The rule in a sentence, for pages and audit lines."""
    scope = "every repository" if rule.global_accepted_by else rule.repository
    if rule.kind == "dependency":
        what = "%s, %s" % (rule.package, "any advisory" if rule.advisory == "*" else rule.advisory)
    else:
        what = rule.rule
        if rule.path_glob:
            what += " in %s" % rule.path_glob
        if rule.code_contains:
            what += " where the line contains “%s”" % rule.code_contains[:80]
    return "%s graded %s, in %s" % (what, _value(rule.severity), scope)
