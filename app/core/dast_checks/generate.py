"""Draft a rule from a prompt, with the built in AI.

An administrator types what they want to find, for example "a detection rule
for a PHP-CGI argument injection flaw", and the model drafts a rule spec.  The
draft is never trusted on the model's word.  It is held to the same standard
as a hand written rule:

    the model is told the standard and told, firmly, to stay non-destructive
    and in scope (the system prompt below)

    whatever comes back is parsed as JSON and run through spec.validate, which
    is what actually enforces read/neutral/oob, blocks the dangerous verbs and
    payloads, and requires a control, a differential, a reproduction and a fix

    a draft that does not validate is not offered; the admin sees why

So the guard rails do not rest on the prompt.  The prompt asks for a safe
rule; the validator is what guarantees one.  A draft is always saved disabled
and marked as an AI draft, so a person reviews it before it ever runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.dast_checks import spec as spec_mod

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schema" / "dast_rule.schema.json"

MAX_PROMPT = 2000


def _schema_text() -> str:
    try:
        return _SCHEMA_PATH.read_text()
    except OSError:
        return "{}"


SYSTEM = """You write one detection rule for a defensive web security scanner.

The scanner checks only web sites the company owns and hosts, with the owner's
permission.  It must never be destructive.  Your rule must find a real,
provable weakness that has an impact, and tell a security admin how to
reproduce it by hand and how to fix it.  No theories, no "best practice"
findings with no path to impact, no false positives.

You must obey these hard rules, and the rule you write is checked against them
and thrown away if it breaks any:

1. Non-destructive only.  Never create, change or delete data.  Never cause a
   denial of service.  Never lock an account out.  Never upload a file.  Pick
   a safety class and stay in it:
     read    only GET, HEAD or OPTIONS.
     neutral a request that changes nothing lasting, such as a failed login
             for a user that does not exist.  If it sends POST, set
             neutral_justification.
     oob     prove the server can be made to make a request, through a callback
             token ({oob}); prove contact and nothing more.
   PUT, DELETE and PATCH are never allowed.  No payload may drop, delete,
   update or insert data, run a command, or ask for a delay longer than 5
   seconds.
2. Prove it.  confirm must have a control (a request that cannot succeed) and
   a differential (the difference a finding stands on), and retest at least
   once.  A bare 200 is never a finding.
3. Fact based.  reproduce must be a concrete step a person can run by hand
   (for example a curl command).  remediate must say how to fix it.
4. In scope.  Do not put a host name or an absolute URL to a specific site in
   the rule.  Use a path, and the placeholder {route} for a discovered route.
   The scanner supplies the host, and refuses any host that is not the
   company's own.

Output only one JSON object, no prose, no code fence, that validates against
this JSON Schema:

%s
"""


def _extract_json(text: str) -> dict:
    """The first JSON object in the model's reply, fence or no fence."""
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1] if raw.count("```") >= 2 else raw
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("The model did not return a JSON object.")
    return json.loads(raw[start:end + 1])


def _host_free(spec: dict) -> None:
    """Refuse a draft that names a specific host or an absolute URL.

    A rule never names where to scan; the scanner supplies the in-scope host.
    A draft that hard codes one is a scope mistake, so it is rejected rather
    than quietly stripped.
    """
    text = spec_mod._flatten(spec.get("probe"))
    if "://" in text:
        raise spec_mod.SpecError("A rule must not contain an absolute URL.  Use "
                                 "a path, and {route} for a discovered route.")


def generate(cfg: dict, prompt: str, actor: str = "") -> dict:
    """Draft one rule from a prompt.  -> {ok, spec, error, model, usage}.

    Never raises.  A model that is off, a reply that is not JSON, and a draft
    that fails the standard all come back as ok False with a plain reason.
    """
    from app.core import ai

    out = {"ok": False, "spec": None, "error": "", "model": "", "usage": {}}
    want = (prompt or "").strip()
    if not want:
        out["error"] = "Say what the rule should detect."
        return out
    if len(want) > MAX_PROMPT:
        want = want[:MAX_PROMPT]

    system = SYSTEM % _schema_text()
    ask = ("Write one rule for this request, as JSON only:\n\n" + want
           + "\n\nRemember: non-destructive, provable, in scope, and it must "
           "validate against the schema.")
    answer = ai.complete(cfg, system, ask, purpose="dast_rule")
    out["model"] = answer.get("model", "")
    out["usage"] = {k: answer.get(k) for k in
                    ("input_tokens", "output_tokens", "duration_ms")}
    if not answer.get("ok"):
        out["error"] = answer.get("error") or "The model did not answer."
        return out
    try:
        draft = _extract_json(answer.get("text", ""))
    except (ValueError, json.JSONDecodeError) as exc:
        out["error"] = f"The reply was not usable JSON: {exc}"
        return out
    try:
        _host_free(draft)
        clean = spec_mod.validate(draft)
    except spec_mod.SpecError as exc:
        out["error"] = f"The draft did not meet the standard: {exc}"
        out["spec"] = draft  # show it so the admin can see what came back
        return out
    out["ok"] = True
    out["spec"] = clean
    return out


def start_draft(cfg: dict, prompt: str, actor: str) -> int:
    """Begin drafting a rule in the background.  -> the draft row id.

    Returns at once; the model runs in its own thread, so a slow answer never
    holds the page.  The draft row moves from working to ready or failed, and
    the admin page shows it when it is done.
    """
    import json
    import threading

    from app.core.db import session_scope
    from app.core.models import DastRuleDraft

    with session_scope() as db:
        row = DastRuleDraft(prompt=(prompt or "")[:2000], status="working",
                            created_by=(actor or "")[:120])
        db.add(row)
        db.flush()
        draft_id = row.id

    def run():
        result = generate(cfg, prompt, actor)
        with session_scope() as db:
            row = db.get(DastRuleDraft, draft_id)
            if row is None:
                return
            if result["ok"]:
                row.status = "ready"
                row.spec = json.dumps(result["spec"], ensure_ascii=False)
            else:
                row.status = "failed"
                row.error = (result.get("error") or "")[:500]
                if result.get("spec"):
                    row.spec = json.dumps(result["spec"], ensure_ascii=False)
            row.model = (result.get("model") or "")[:120]

    threading.Thread(target=run, daemon=True, name=f"dast-draft-{draft_id}").start()
    return draft_id
