r"""Triage rules: what counts as an example rather than a credential.

The scanner finds candidates, then decides which are real.  A value reading
`changeme`, or a token that trails off because somebody shortened it for a
README, is not a leak, and reporting it teaches people to skim the list.

Two kinds.  A value rule matches the credential itself, so nothing here can
show you which findings it would hide: cleartext lives only inside a scan and
the database keeps a hash.  A path rule matches the file, which is stored, so
that one can be tried against what is already here.

The rules the tool ships stay in scanner_defaults.  A row in this table is a
decision somebody made, either a rule of their own or a shipped one they turned
off, which is what makes restoring the defaults a matter of deleting rows.

Patterns are never compiled here.  The scanner is jq, and jq's engine is not
python's: \x{2026} is valid there and a syntax error in re.  check() asks jq.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from app.core.models import TriageRule, utcnow

log = logging.getLogger("gcr.triage_rules")

TARGETS = ("value", "path")

# Where each kind lands in the scanner's config.
FIELD = {"value": "placeholder_patterns", "path": "placeholder_paths"}

# How long jq gets to answer.  A pattern that takes longer than this against
# one short string is one that would hold a scan up, so refusing it is the
# right answer rather than a nuisance.
CHECK_TIMEOUT = 5


def shipped() -> dict:
    """The rules this tool ships, straight out of the scanner's defaults.

    Read rather than copied, so there is one list and the page cannot drift
    from what the scanner is actually given.
    """
    from app.core.scanner_defaults import TEMPLATE

    triage = TEMPLATE["scan"]["secrets"]["triage"]
    return {target: list(triage.get(FIELD[target], []) or [])
            for target in TARGETS}


def _jq() -> str:
    return shutil.which("jq") or ""


def check(pattern: str) -> str:
    """-> why it will not do, or "" if it is fine.

    Asks jq, because jq is what reads it.  If jq is not on this machine the
    pattern is taken on trust: refusing to save one because the checker is
    missing would be worse than saving one the scanner then complains about.
    """
    pattern = (pattern or "").strip()
    if not pattern:
        return "Give it a pattern to match."
    if len(pattern) > 500:
        return "That pattern is too long, keep it under 500 characters."

    binary = _jq()
    if not binary:
        log.warning("no jq here, so %r goes in unchecked", pattern[:80])
        return ""

    # Run it against something, not against nothing.  Checking an empty string
    # only proves the pattern parses; a rule like (a+)+$ parses fine and then
    # takes forever on the first real value it sees, which would hang a scan
    # rather than fail it.  These samples are the shapes that set that off.
    try:
        done = subprocess.run(
            [binary, "-n", "--arg", "p", pattern, "--argjson", "s",
             json.dumps(["", "a" * 48 + "!", "x" * 48 + "!",
                         "ab" * 24 + "!", "x/" * 24 + "y.md",
                         "AKIA" + "Q" * 32]),
             '$s | map(test($p)) | any'],
            capture_output=True, text=True, timeout=CHECK_TIMEOUT)
    except subprocess.TimeoutExpired:
        return ("That pattern takes too long to run.  It backtracks, so on a "
                "real value it would hold the scan up instead of failing it.  "
                "Nested repeats like (a+)+ are the usual cause.")
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not check %r: %s", pattern[:80], exc)
        return ""

    if done.returncode != 0:
        detail = (done.stderr or "").strip().splitlines()
        note = detail[-1] if detail else "it is not a valid regular expression"
        # jq says "jq: error (at <unknown>): ..." which is noise to read.
        note = note.split("): ", 1)[-1].strip()
        return f"The scanner will not read that pattern: {note}"
    return ""


def matches(patterns, sample: str) -> list:
    """Which of these patterns match this sample, according to jq.

    The point of the test box.  One call for the lot rather than one each, so
    trying a sample against forty rules is one process.
    """
    patterns = [p for p in patterns if p]
    if not patterns or not sample:
        return []
    binary = _jq()
    if not binary:
        return []

    program = '$p | map(select(. as $r | $s | test($r)))'
    try:
        done = subprocess.run(
            [binary, "-n", "-c", "--argjson", "p", json.dumps(patterns),
             "--arg", "s", sample, program],
            capture_output=True, text=True, timeout=CHECK_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not try that sample: %s", exc)
        return []
    if done.returncode != 0:
        return []
    try:
        return json.loads(done.stdout or "[]")
    except ValueError:
        return []


def _rows(session) -> list:
    return session.query(TriageRule).order_by(TriageRule.id.asc()).all()


def effective(session) -> dict:
    """What the scanner is given: {"value": [...], "path": [...]}.

    Shipped rules, minus the ones somebody turned off, plus the ones somebody
    wrote.  Shipped first, so the order the tool was tested with is the order
    it still runs in.
    """
    rows = _rows(session)
    off = {(row.target, row.pattern) for row in rows if not row.enabled}
    out = {}
    for target in TARGETS:
        out[target] = [p for p in shipped()[target] if (target, p) not in off]
        out[target] += [row.pattern for row in rows
                        if row.target == target and row.enabled
                        and not row.shipped]
    return out


def listing(session) -> list:
    """Every rule, shipped and otherwise, in the order the page shows them."""
    rows = {(row.target, row.pattern): row for row in _rows(session)}
    out = []
    for target in TARGETS:
        for pattern in shipped()[target]:
            row = rows.get((target, pattern))
            out.append({
                "target": target, "pattern": pattern, "source": "shipped",
                "enabled": row.enabled if row is not None else True,
                "reason": (row.reason if row is not None else "") or "",
                "created_by": (row.created_by if row is not None else "") or "",
                "id": row.id if row is not None else None,
            })
        for (row_target, pattern), row in rows.items():
            if row_target != target or row.shipped:
                continue
            out.append({
                "target": target, "pattern": pattern, "source": "custom",
                "enabled": row.enabled, "reason": row.reason or "",
                "created_by": row.created_by or "", "id": row.id,
            })
    return out


def add(session, target: str, pattern: str, reason: str = "",
        actor: str = "") -> tuple:
    """-> (row, why not).  One rule per pattern, so adding the same one twice
    edits it rather than growing the list."""
    target = (target or "value").strip().lower()
    if target not in TARGETS:
        return None, "A rule matches the value or the path."

    pattern = (pattern or "").strip()
    why = check(pattern)
    if why:
        return None, why

    if pattern in shipped()[target]:
        return None, ("That is already one of the rules this tool ships. "
                      "It is in the list below.")

    row = (session.query(TriageRule)
           .filter(TriageRule.target == target,
                   TriageRule.pattern == pattern).one_or_none())
    if row is None:
        row = TriageRule(target=target, pattern=pattern)
        session.add(row)
    row.reason = reason or ""
    row.enabled = True
    row.shipped = False
    row.created_by = actor or row.created_by or ""
    row.created_at = utcnow()
    session.flush()
    return row, ""


def set_enabled(session, target: str, pattern: str, on: bool,
                actor: str = "") -> tuple:
    """Turn one rule on or off, shipped or not.

    A shipped rule has no row until somebody turns it off, at which point one
    is written to say who did and when.  Turning it back on removes the row
    again rather than leaving a disabled record of a rule that is running.
    """
    target = (target or "").strip().lower()
    pattern = (pattern or "").strip()
    if target not in TARGETS or not pattern:
        return False, "No such rule."

    is_shipped = pattern in shipped()[target]
    row = (session.query(TriageRule)
           .filter(TriageRule.target == target,
                   TriageRule.pattern == pattern).one_or_none())

    if row is None:
        if not is_shipped:
            return False, "No such rule."
        if on:
            return True, ""          # already running
        row = TriageRule(target=target, pattern=pattern, shipped=True,
                         created_by=actor or "", created_at=utcnow())
        session.add(row)

    if is_shipped and on:
        session.delete(row)
        session.flush()
        return True, ""

    row.enabled = bool(on)
    session.flush()
    return True, ""


def remove(session, rule_id: int) -> bool:
    """Delete a rule somebody wrote.  A shipped one is turned off, not deleted."""
    row = (session.query(TriageRule)
           .filter(TriageRule.id == rule_id).one_or_none())
    if row is None or row.shipped:
        return False
    session.delete(row)
    session.flush()
    return True


def restore_defaults(session) -> int:
    """Back to what the tool ships.

    Every row goes: the custom rules and the records of shipped ones being
    turned off.  What is left is the defaults, because the defaults were never
    in the table to begin with.
    """
    rows = _rows(session)
    for row in rows:
        session.delete(row)
    session.flush()
    return len(rows)
