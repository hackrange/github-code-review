"""Saved scan profiles, and which rules a profile runs.

A scan profile is a saved name for a scan: a depth (the engine profile, from
baseline to premium) plus the curated rulesets to run.  A profile named PHP,
premium depth with the php ruleset, is applied to the PHP sites and runs only
the php rules on top of the stock engines.

A rule belongs to the ruleset named after its class, plus any extra rulesets
on the rule itself.  A profile that lists ["*"] runs every curated rule, which
is what the plain premium depth does so nothing regressed when profiles landed.
"""

from __future__ import annotations

import json

# The engine depths, lowest to highest.  Kept here so this module does not
# have to import the engine layer.
DEPTHS = ["baseline", "quick", "standard", "thorough", "premium"]


def _list(raw) -> list:
    if isinstance(raw, list):
        return [str(x) for x in raw]
    try:
        value = json.loads(raw or "[]")
        return [str(x) for x in value] if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def membership(rule_class: str, rulesets_raw) -> set:
    """Every ruleset a rule is in: its class, plus its own extra rulesets."""
    names = {rule_class} if rule_class else set()
    names.update(_list(rulesets_raw))
    return names


def selected(rule_class: str, rulesets_raw, chosen) -> bool:
    """Whether a rule runs under a profile that chose these ruleset names."""
    chosen = chosen if isinstance(chosen, (list, set)) else _list(chosen)
    if "*" in chosen:
        return True
    return bool(membership(rule_class, rulesets_raw) & set(chosen))


def resolve(db, profile_value: str) -> tuple:
    """A scan's profile value to (depth, ruleset names).

    A saved profile name gives its depth and its rulesets.  A plain depth
    string gives that depth, and runs all curated rules only at premium (the
    behavior before saved profiles existed).  Anything unknown is quick with
    no curated rules.
    """
    from app.core.models import DastScanProfile

    value = (profile_value or "").strip()
    prof = db.query(DastScanProfile).filter(DastScanProfile.name == value).first()
    if prof is not None:
        names = _list(prof.rulesets)
        depth = prof.depth if prof.depth in DEPTHS else "premium"
        return depth, names
    if value in DEPTHS:
        return value, (["*"] if value == "premium" else [])
    return "quick", []
