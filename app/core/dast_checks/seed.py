"""Load the shipped curated rules into the database.

The curated rules live as JSON files next to this module, one per rule, so an
upgrade can add or improve a rule by shipping a file, with no migration.  The
sync is careful with what an administrator has done:

    a rule that is not in the database yet is added, disabled, so turning on
    premium never quietly runs a pile of new checks; the admin enables them

    a shipped rule the admin has edited (its version moved past 1) or disabled
    is left exactly as it is; only an untouched curated rule is refreshed from
    its file, and even then its enabled state is kept

So the shipped set improves over time without ever undoing a local change.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.dast_checks import spec as spec_mod

CURATED = Path(__file__).resolve().parent / "curated"


def load() -> list:
    """Every shipped rule that still meets the standard."""
    out = []
    for path in sorted(CURATED.glob("*.json")):
        try:
            out.append(spec_mod.validate(json.loads(path.read_text())))
        except (ValueError, spec_mod.SpecError):
            continue
    return out


def sync(db) -> dict:
    """Add new curated rules and refresh untouched ones.  -> counts."""
    from app.core.models import DastRule

    have = {r.rule_id: r for r in db.query(DastRule).all()}
    added = refreshed = 0
    for s in load():
        body = json.dumps(s, ensure_ascii=False)
        rulesets = json.dumps(s.get("rulesets") or [], ensure_ascii=False)
        row = have.get(s["id"])
        if row is None:
            db.add(DastRule(rule_id=s["id"], rule_class=s["class"],
                            title=s["title"][:300], safety=s["safety"],
                            severity_floor=s["severity_floor"], enabled=False,
                            origin="curated", spec=body, rulesets=rulesets))
            added += 1
        elif row.origin == "curated" and (row.version or 1) == 1 and row.spec != body:
            # Untouched shipped rule: improve it, but keep the admin's on/off.
            row.rule_class = s["class"]
            row.title = s["title"][:300]
            row.safety = s["safety"]
            row.severity_floor = s["severity_floor"]
            row.spec = body
            row.rulesets = rulesets
            refreshed += 1
    return {"added": added, "refreshed": refreshed}
