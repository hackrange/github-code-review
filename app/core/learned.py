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
        return ("it is on the CISA known exploited list, and only evidence "
                "that it does not ship lowers that")
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
        "reachability": finding.reachability or "",
        "image": getattr(finding, "image_ref", "") or "",
    }


# How exposed a package is, for comparing two repositories.  Reachable is the
# most: the code imports it.  Unknown and unrated sit in the middle, because
# nothing says either way.  Unlikely is the least: it does not ship.
EXPOSURE = {"reachable": 3, "unknown": 2, "": 2, "unrated": 2, "unlikely": 1}


def _exposure(value) -> int:
    return EXPOSURE.get((value or "").strip().lower(), 2)


def source_facts(session, rule) -> dict:
    """What was true of the package where a dependency rule was learned.

    Its reachability, its version and the base image it came from.  Read from
    the rule's own test case, which records all three from now on, and for a
    rule learned before that, from the finding it came from.
    """
    cases = fixture_of(rule).get("positive") or []
    case = cases[0] if cases else {}
    out = {"reachability": case.get("reachability"), "version": case.get("version"),
           "image": case.get("image")}
    if any(value is None for value in out.values()) and rule.source_finding_id:
        row = session.get(Finding, rule.source_finding_id)
        if row is not None:
            for key, value in (("reachability", row.reachability),
                               ("version", row.package_version),
                               ("image", getattr(row, "image_ref", ""))):
                if out[key] is None:
                    out[key] = value or ""
    return {key: (value or "") for key, value in out.items()}


def _prepare(session, rule):
    """Attach what matching needs and the row does not carry."""
    if rule.kind == "dependency" and not hasattr(rule, "_source"):
        rule._source = source_facts(session, rule)
    return rule


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
    if not contains:
        # No code to match on, which is how a workflow finding arrives.  Then
        # the reason can only be about the one file that was read, and a glob
        # would carry it to files nobody looked at.
        glob = finding.file_path or ""
    if not contains and glob in ("", "*", "**"):
        return None, "the pattern would match every finding of that rule"
    fields.update(rule=finding.rule, path_glob=glob, code_contains=contains)
    return fields, ""


# ------------------------------------------------------------------ matching

def local_only(rule) -> bool:
    """A code or configuration rule with no code to match on.

    All it knows is a file path, and .github/workflows/ci.yml is in half the
    repositories there are.  Another repository's file of the same name is
    different code, so a rule like this answers only where it was learned.
    """
    return rule.kind != "dependency" and not (rule.code_contains or "")


def _read_files(rule) -> set:
    """The files a path-only rule was actually learned from.

    A rule kept before globs were narrowed can say .github/**/* when the
    model read one workflow.  Only what was read is covered.
    """
    files = getattr(rule, "_files", None)
    if files is None:
        files = {case.get("file") or "" for case in fixture_of(rule)["positive"]}
        try:
            rule._files = files
        except AttributeError:
            pass
    return files


def _matches(rule, f: dict) -> bool:
    """Does one learned rule cover these finding facts."""
    if (rule.kind or "") != f.get("kind"):
        return False
    if rule.kind == "dependency":
        if (rule.package or "") != f.get("package"):
            return False
        if (rule.advisory or "*") not in ("*", f.get("advisory") or ""):
            return False
        # Outside the repository it was learned in, a rule about a package only
        # holds where what it was learned on is still true: the same version,
        # from the same base image when it came from one, and no more exposed.
        # A reason like "a ^4.21.2 range cannot resolve into the affected
        # range" or "this copy comes from the node base image" is about one
        # copy, and says nothing about a service pinned to an older release
        # that imports the package on every request.
        if (f.get("repository") or "").lower() != (rule.repository or "").lower():
            learned_on = getattr(rule, "_source", None)
            if learned_on is None:
                return False
            if (f.get("version") or "") != learned_on["version"]:
                return False
            if learned_on["image"] and (f.get("image") or "") != learned_on["image"]:
                return False
            if _exposure(f.get("reachability")) > _exposure(learned_on["reachability"]):
                return False
        return True
    if (rule.rule or "").lower() != (f.get("rule") or "").lower():
        return False
    if local_only(rule):
        if (f.get("repository") or "").lower() != (rule.repository or "").lower():
            return False
        if any(ch in (rule.path_glob or "") for ch in "*?[") and \
                (f.get("file") or "") not in _read_files(rule):
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
        _prepare(session, rule)
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
        # Narrowest first, and the newest of two equally narrow ones, since it
        # was learned from a later reading.
        rank = (rule.repository.lower() == f["repository"].lower(),
                len(rule.code_contains or ""), len(rule.path_glob or ""),
                (rule.advisory or "*") != "*", rule.id or 0)
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
            problems.append("it matches %s, which a model read differently"
                            % (case.get("file") or case.get("package")))
    return problems


def contradiction(session, fields: dict, severity) -> str:
    """Why an earlier reading says a proposed rule is wrong, or "".

    A retired rule keeps the findings a model read differently from it.  A new
    rule that would cover one of them at a grade the model did not give is the
    same mistake learned again, so it is refused.  A case kept before readings
    were recorded only says the old rule's grade was wrong.
    """
    probe = LearnedRule(**fields)
    _prepare(session, probe)
    for old in session.query(LearnedRule).filter(
            LearnedRule.retired_at.isnot(None), LearnedRule.kind == fields["kind"],
            LearnedRule.repository == fields["repository"]):
        for case in fixture_of(old)["negative"]:
            reading = case.get("reading") or ""
            if reading:
                wrong = reading != _value(severity)
            else:
                wrong = _value(old.severity) == _value(severity)
            if wrong and _matches(probe, case):
                return ("it would grade %s %s, and a model read that one as %s"
                        % (case.get("file") or case.get("package"), _value(severity),
                           reading or "something else"))
    return ""


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
    if self_test(rule) or contradiction(session, fields, severity):
        return None
    session.add(rule)
    session.flush()
    return rule


def add_negative(session, rule, finding, by: str, why: str, reading=None) -> None:
    """A model read something this rule covers differently: the rule is wrong.

    Higher or lower makes no difference.  The rule claims everything it covers
    deserves its grade for the same reason, and one reading that does not
    agree shows the reason does not hold across all of it.  The finding
    becomes a negative case with the reading on it, the rule is retired, and
    every grade it gave is taken back.
    """
    data = fixture_of(rule)
    case = facts(finding)
    if reading is not None:
        case["reading"] = _value(reading)
    data["negative"].append(case)
    rule.fixture = json.dumps(data)
    retire(session, rule, by, why)


def retire(session, rule, by: str, why: str) -> int:
    """Stop a rule and take back every grade it gave.  -> findings restored."""
    rule.retired_at = utcnow()
    rule.retired_by = by or ""
    rule.retired_reason = (why or "")[:2000]
    restored = 0
    for grade in session.query(AIGrade).filter(AIGrade.rule_id == rule.id).all():
        restored += _restore(session, grade)
    return restored


def _restore(session, grade) -> bool:
    """Put a finding back to what stood before an AI grade, and drop the grade."""
    finding = session.get(Finding, grade.finding_id)
    restored = False
    if finding is not None and finding.custom_severity is None and grade.was:
        try:
            finding.severity = Severity(grade.was)
            restored = True
        except ValueError:
            pass
    session.delete(grade)
    return restored


def unaccept(session, rule, by: str) -> int:
    """Take a rule back to its own repository.  -> findings restored.

    What it graded elsewhere goes back; what it graded at home stays.
    """
    rule.global_accepted_by = ""
    rule.global_accepted_at = None
    home = (rule.repository or "").lower()
    restored = 0
    for grade in session.query(AIGrade).filter(AIGrade.rule_id == rule.id).all():
        finding = session.get(Finding, grade.finding_id)
        if finding is not None and (finding.repository or "").lower() == home:
            continue
        restored += _restore(session, grade)
    return restored


def delete(session, rule, by: str) -> int:
    """Remove a rule for good, after taking back what it gave.  -> restored.

    A retired rule's negative cases go with it, so a pattern it was retired
    for can be learned again.
    """
    restored = 0
    if rule.retired_at is None:
        restored = retire(session, rule, by, "deleted")
    session.delete(rule)
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
    _prepare(session, rule)
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


def still_covers(index: dict, grade, finding) -> bool:
    """Does the rule behind a grade it gave still cover this finding.

    A grade a rule gave is re-checked on every scan rather than kept for good,
    so narrowing a rule, or retiring it, takes back what it no longer covers.
    """
    if grade.source != "rule" or not grade.rule_id:
        return True
    for rules in index.values():
        for rule in rules:
            if rule.id == grade.rule_id:
                f = facts(finding)
                return in_scope(rule, f["repository"]) and _matches(rule, f)
    return False


def load_grades(session) -> dict:
    """{finding_id: AIGrade} for applying at ingest."""
    return {row.finding_id: row for row in session.query(AIGrade)}


def describe(rule) -> str:
    """The rule in a sentence, for pages and audit lines."""
    everywhere = rule.global_accepted_by and not local_only(rule)
    scope = "every repository" if everywhere else rule.repository
    if rule.kind == "dependency":
        what = "%s, %s" % (rule.package, "any advisory" if rule.advisory == "*" else rule.advisory)
    else:
        what = rule.rule
        if rule.path_glob:
            what += " in %s" % rule.path_glob
        if rule.code_contains:
            what += " where the line contains “%s”" % rule.code_contains[:80]
    return "%s graded %s, in %s" % (what, _value(rule.severity), scope)
