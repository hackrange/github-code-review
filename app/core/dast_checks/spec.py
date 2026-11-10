"""The rule standard: one shape every enhanced check follows.

A rule is data, not code.  It says what to send, how to tell a real finding
from nothing, how a person can reproduce it by hand, and how to fix it.  The
engine reads this and runs it, so the safety contract is enforced here, by the
validator and the engine, not by trusting whoever wrote the rule.

A rule only passes validation when it can lead to a provable finding:

    it carries a control and a differential, so a plain 200 is never a finding
    it re-tests, so a fluke is not a finding
    it says how to reproduce the result by hand
    it says how to fix it

and when it is safe:

    a read rule may only send GET, HEAD or OPTIONS
    a neutral rule may not send a method or a payload that changes data
    an out of band rule proves contact through the callback, nothing more

A rule that cannot meet both is rejected with a plain reason, so a new rule,
whether a person writes it or the model drafts it from a prompt, has to meet
the standard before it can be saved or run.
"""

from __future__ import annotations

import re

# The classes a rule is filed under, one per area of the plan.
CLASSES = {
    "access-control": "Access control and authorization",
    "authentication": "Authentication, session and identity",
    "injection": "Injection and input handling",
    "misconfiguration": "Security misconfiguration and exposure",
    "business-logic": "Business logic and request handling",
    "client-side": "Client-side and sensitive data exposure",
}

# What a rule may do, strongest guarantee first.
SAFETY = {
    "read": "Read only.  Sends GET, HEAD or OPTIONS, changes nothing.",
    "neutral": "Sends a request that changes nothing lasting, such as a failed "
               "login for a user that does not exist.",
    "oob": "Confirms the server can be made to make a request, through a "
           "callback this product runs.  Proves contact, nothing more.",
}

SEVERITIES = ["info", "low", "medium", "high", "critical"]

# Methods a read rule may use.  Nothing else may be read only.
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
# Methods no rule may ever use, whatever its class: they change or remove data.
FORBIDDEN_METHODS = {"PUT", "DELETE", "PATCH"}
ALL_METHODS = READ_METHODS | {"POST", "TRACE"}

# Things that must never appear in a probe, in any field.  These change or
# destroy data or knock a service over, which this product never does.  The
# list is a backstop: the method and safety rules already block most of it,
# and this catches a dangerous string hidden in a query or a body.
DESTRUCTIVE = [
    r"\bdrop\s+table\b", r"\btruncate\s+table\b", r"\bdelete\s+from\b",
    r"\binsert\s+into\b", r"\bupdate\s+\w+\s+set\b", r"\balter\s+table\b",
    r"\bshutdown\b", r"\bxp_cmdshell\b", r";\s*drop\b",
    r"\brm\s+-rf\b", r"\bmkfs\b", r"\bdd\s+if=", r":\(\)\s*\{", r"\bfork\b\s*bomb",
    r"\bformat\s+c:", r"\bshutdown\b|/s\b", r"\breboot\b", r"\bhalt\b",
    r"\bsleep\s+(\d{2,})\b",   # a long sleep is a denial of service, not a probe
]
_DESTRUCTIVE = [re.compile(p, re.I) for p in DESTRUCTIVE]

# The longest time delay a timing probe may ask for, in seconds.  A real
# oracle needs only a couple of seconds, and a long one is a denial of service.
MAX_DELAY_SECONDS = 5

_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_NEEDS = {"session", "two_accounts", "code_routes", "openapi", "oob", "headless"}


class SpecError(ValueError):
    """A rule that does not meet the standard.  The message is safe to show."""


def _flatten(value) -> str:
    """Every string anywhere in a nested probe, joined, for the deny scan."""
    out = []

    def walk(node):
        if isinstance(node, dict):
            for key, item in node.items():
                out.append(str(key))
                walk(item)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)
        elif node is not None:
            out.append(str(node))

    walk(value)
    return "  ".join(out)


def _methods_in(probe) -> list:
    """Every HTTP method the probe uses, upper cased."""
    methods = []
    for step in probe or []:
        req = step.get("request") if isinstance(step, dict) else None
        if isinstance(req, dict):
            methods.append(str(req.get("method") or "GET").upper())
    return methods


def _check_destructive(spec: dict) -> None:
    text = _flatten(spec.get("probe"))
    for pattern in _DESTRUCTIVE:
        if pattern.search(text):
            raise SpecError("A probe contains something that could change data "
                            "or knock a service over, which is never allowed.  "
                            f"Remove: {pattern.pattern}")


def _require(spec: dict, field: str, what: str) -> str:
    value = spec.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SpecError(f"{what} is required and must be text.")
    return value.strip()


def validate(spec: dict) -> dict:
    """Check a rule against the standard.  -> the cleaned spec, or raises.

    This is the one gate.  The admin page runs it before a save, the AI draft
    runs it before it is offered, and the engine runs it before it runs a
    rule, so nothing unsafe or unprovable gets through any door.
    """
    if not isinstance(spec, dict):
        raise SpecError("A rule must be a mapping of fields.")

    rid = str(spec.get("id") or "").strip().lower()
    if not _ID.match(rid) or len(rid) > 80:
        raise SpecError("id must be a short slug like injection-php-cgi-arg, "
                        "lower case, digits and single dashes, up to 80 "
                        "characters.")

    cls = str(spec.get("class") or "").strip().lower()
    if cls not in CLASSES:
        raise SpecError("class must be one of: " + ", ".join(sorted(CLASSES)))

    safety = str(spec.get("safety") or "").strip().lower()
    if safety not in SAFETY:
        raise SpecError("safety must be read, neutral or oob.")

    floor = str(spec.get("severity_floor") or "").strip().lower()
    if floor not in SEVERITIES:
        raise SpecError("severity_floor must be one of: " + ", ".join(SEVERITIES))

    title = _require(spec, "title", "title")
    summary = _require(spec, "summary", "summary")
    reproduce = _require(spec, "reproduce", "reproduce (how a person repeats "
                         "the result by hand)")
    remediate = _require(spec, "remediate", "remediate (how to fix it)")

    needs = spec.get("needs") or []
    if not isinstance(needs, list) or any(n not in _NEEDS for n in needs):
        raise SpecError("needs must be a list from: " + ", ".join(sorted(_NEEDS)))

    probe = spec.get("probe")
    if not isinstance(probe, list) or not probe:
        raise SpecError("probe must be a non-empty list of steps.")

    methods = _methods_in(probe)
    for method in methods:
        if method not in ALL_METHODS:
            raise SpecError(f"{method} is not a method a rule may use.")
        if method in FORBIDDEN_METHODS:
            raise SpecError(f"{method} changes or removes data and is never "
                            "allowed.")
    if safety == "read" and any(m not in READ_METHODS for m in methods):
        raise SpecError("A read rule may only send GET, HEAD or OPTIONS.  Use "
                        "safety: neutral if it must POST, and say why it is "
                        "non-destructive.")
    if safety == "neutral" and "POST" in methods and not str(
            spec.get("neutral_justification") or "").strip():
        raise SpecError("A neutral rule that sends POST needs "
                        "neutral_justification saying why the request changes "
                        "nothing lasting.")

    has_oob_step = any(isinstance(s, dict) and s.get("oob_token") for s in probe)
    if safety == "oob":
        if not has_oob_step:
            raise SpecError("An out of band rule must have a probe step with an "
                            "oob_token (dns or http), which is how contact is "
                            "proved.")
        if "oob" not in needs:
            raise SpecError("An out of band rule must list 'oob' in needs.")

    confirm = spec.get("confirm")
    if not isinstance(confirm, dict):
        raise SpecError("confirm is required: it is how a real finding is told "
                        "from nothing.")
    differential = str(confirm.get("differential") or "").strip()
    if not differential:
        raise SpecError("confirm.differential is required.  A finding must "
                        "stand on a difference, never on a bare 200.")
    retest = confirm.get("retest", 1)
    if not isinstance(retest, int) or retest < 1 or retest > 10:
        raise SpecError("confirm.retest must be a whole number from 1 to 10.")
    if safety != "oob" and not str(confirm.get("control") or "").strip():
        raise SpecError("confirm.control is required: the request that cannot "
                        "succeed, so the normal answer is known.")

    delay = confirm.get("max_delay_seconds")
    if delay is not None and (not isinstance(delay, (int, float))
                              or delay > MAX_DELAY_SECONDS or delay < 0):
        raise SpecError(f"A timing probe may wait at most {MAX_DELAY_SECONDS} "
                        "seconds.")

    # A rule about what anybody can see has to look as anybody.  In a signed
    # in scan the session would otherwise ride along, and a page that is only
    # open to the signed in user would read as open to the world.
    if "anonymous" in spec and not isinstance(spec["anonymous"], bool):
        raise SpecError("anonymous must be true or false.")

    _check_destructive(spec)

    cleaned = dict(spec)
    cleaned.update(id=rid, **{"class": cls}, safety=safety, severity_floor=floor,
                   title=title, summary=summary, reproduce=reproduce,
                   remediate=remediate, needs=list(needs))
    return cleaned


def summary_line(spec: dict) -> str:
    """One line for a log or a flash message.  Assumes spec validated."""
    return f"{spec['id']} [{spec['class']}, {spec['safety']}] {spec['title']}"
