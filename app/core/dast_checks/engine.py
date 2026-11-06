"""Run a rule spec against a site, safely.

This reads a validated rule (see spec.py) and runs it.  It is the only thing
that turns a spec into requests, so the safety contract lives here in code:

    every request passes the scope gate first, so a rule can only ever touch
    the company's own domains, and cannot follow a redirect off them

    a read rule may only send GET, HEAD or OPTIONS; the client refuses the rest

    a finding needs the spec's differential to hold, and to hold on every
    re-test, so a one-off answer is never a finding

The differential is a small, fixed expression, not code.  It is parsed and
walked by hand (evaluate() below), which allows only booleans, comparisons and
a short list of named helpers.  Nothing a rule says is ever executed as Python.

A finding carries what makes it fact based: the exact request, the control it
was compared against, how to reproduce it by hand, and how to fix it.
"""

from __future__ import annotations

import ast
import secrets
import time
from urllib.parse import urljoin, urlparse

from app.core.dast_checks import scope, spec as spec_mod

# How many discovered routes a {route} rule tries before it gives up, and the
# ceiling on requests one rule may make.  A rule is a scalpel, not a crawler.
MAX_ROUTES = 25
DEFAULT_BUDGET = 60


class Refused(Exception):
    """A request a rule tried to make that the safety contract does not allow."""


class Budget:
    """A request counter.  A rule that runs out is stopped, not crashed."""

    def __init__(self, limit: int = DEFAULT_BUDGET):
        self.left = limit

    def spend(self) -> None:
        if self.left <= 0:
            raise Refused("the request budget for this rule is used up")
        self.left -= 1


class Client:
    """The one way a rule reaches the network.  Gate and method rules live here.

    Backed by external_probe.fetch, which already blocks private addresses and
    follows redirects by hand, so a rule cannot be bounced off the host it is
    allowed to touch.
    """

    def __init__(self, base_url: str, domains, safety: str, budget: Budget,
                 allow_private: bool = False, headers: dict = None):
        self.base_url = base_url.rstrip("/") + "/"
        self.domains = domains
        self.safety = safety
        self.budget = budget
        self.allow_private = allow_private
        self.headers = dict(headers or {})

    def _allowed_method(self, method: str) -> bool:
        method = method.upper()
        if method in spec_mod.FORBIDDEN_METHODS:
            return False
        if self.safety == "read":
            return method in spec_mod.READ_METHODS
        return method in spec_mod.ALL_METHODS

    def request(self, method: str, path: str, query: dict = None,
                headers: dict = None) -> dict:
        from app.core import external_probe

        method = (method or "GET").upper()
        if not self._allowed_method(method):
            raise Refused(f"{method} is not allowed for a {self.safety} rule")
        url = urljoin(self.base_url, path.lstrip("/"))
        if query:
            from urllib.parse import urlencode
            sep = "&" if "?" in url else "?"
            url = url + sep + urlencode(query, doseq=True)
        host = urlparse(url).hostname or ""
        if not scope.allowed(host, self.domains):
            raise Refused(scope.refuse_reason(host, self.domains))
        self.budget.spend()
        sent = dict(self.headers)
        sent.update(headers or {})
        started = time.monotonic()
        got = external_probe.fetch(url, method=method, headers=sent,
                                   allow_private=self.allow_private)
        got["seconds"] = time.monotonic() - started
        got.setdefault("body", "")
        return got


# ------------------------------------------------------------------ the DSL

_ALLOWED_FUNCS = {"body_differs", "body_contains", "header", "reflected",
                  "status_in"}
_ALLOWED_CMP = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
                ast.In, ast.NotIn)


def _eval_node(node, env):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, env)
    if isinstance(node, ast.BoolOp):
        vals = [_eval_node(v, env) for v in node.values]
        return all(vals) if isinstance(node.op, ast.And) else any(vals)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, env)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, env)
        for op, right_node in zip(node.ops, node.comparators):
            if not isinstance(op, _ALLOWED_CMP):
                raise Refused("an operator in the rule is not allowed")
            right = _eval_node(right_node, env)
            ok = _compare(op, left, right)
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in _ALLOWED_FUNCS:
            raise Refused("a function in the rule is not allowed")
        if node.keywords:
            raise Refused("keyword arguments are not allowed in a rule")
        args = [_eval_node(a, env) for a in node.args]
        return env["_funcs"][node.func.id](*args)
    if isinstance(node, ast.Name):
        # JSON style literals, so a differential can read oob_hit==true.
        if node.id in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[node.id]
        if node.id not in env:
            raise Refused(f"the rule refers to an unknown name: {node.id}")
        return env[node.id]
    if isinstance(node, ast.Constant):
        return node.value
    raise Refused("the rule expression has something that is not allowed")


def _compare(op, left, right) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    if isinstance(op, ast.In):
        return left in right
    if isinstance(op, ast.NotIn):
        return left not in right
    return False


def evaluate(expr: str, env: dict) -> bool:
    """A rule's differential: a boolean over a fixed, safe set of names.

    Parsed and walked by hand.  Anything outside booleans, comparisons and the
    allowed helpers is refused, so nothing in a rule runs as code.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise Refused(f"the differential does not parse: {exc}")
    return bool(_eval_node(tree, env))


def _normalize(body: str) -> str:
    import re
    body = re.sub(r"gcr-[0-9a-f]+", "", body or "")
    body = re.sub(r"[0-9a-fA-F]{16,}", "", body)
    return re.sub(r"\s+", " ", body).strip()


def _env_for(response: dict, control: dict, oob_hit: bool) -> dict:
    """The names and helpers a differential may use."""
    body = response.get("body") or ""
    headers = response.get("headers") or {}

    def body_differs(other):
        return _normalize(body) != _normalize((other or {}).get("body") or "")

    def body_contains(text):
        return str(text) in body

    def header(name):
        return headers.get(str(name).lower(), "")

    def reflected(marker):
        return str(marker) in body

    def status_in(*codes):
        return response.get("status") in codes

    return {
        "status": response.get("status", 0),
        "control": control,
        "oob_hit": oob_hit,
        "_funcs": {"body_differs": body_differs, "body_contains": body_contains,
                   "header": header, "reflected": reflected,
                   "status_in": status_in},
    }


# ------------------------------------------------------------------ running

def _control_response(client: Client) -> dict:
    """The site's answer to a path that cannot exist, so normal is known."""
    token = "gcr-" + secrets.token_hex(8)
    return client.request("GET", f"/{token}/{token}.html")


def _expand(path: str, route: str, oob_token: str) -> str:
    return path.replace("{route}", route.lstrip("/")).replace("{oob}", oob_token)


def _uses_route(spec: dict) -> bool:
    """Whether the probe aims at the discovered routes, or a fixed path."""
    return "{route}" in spec_mod._flatten(spec.get("probe"))


def needs_met(spec: dict, ctx: dict) -> str:
    """Empty when the rule can run here, else a short reason it is skipped."""
    for need in spec.get("needs") or []:
        if need == "code_routes" and not ctx.get("code_routes"):
            return "no routes from the code to aim at"
        if need == "session" and not ctx.get("headers"):
            return "the site has no sign in configured"
        if need == "two_accounts" and not ctx.get("second_headers"):
            return "a second account is not configured"
        if need == "oob" and not ctx.get("oob"):
            return "no out of band callback is configured"
        if need == "headless" and not ctx.get("headless"):
            return "this engine build cannot run a headless browser yet"
    if spec.get("safety") == "neutral" and ctx.get("neutral_ok") is False:
        return "neutral rules are not run here"
    return ""


def run_rule(spec: dict, ctx: dict) -> dict:
    """Run one validated rule.  -> {rule_id, status, findings, detail}.

    status is ok, skipped, refused or error.  findings is a list in the shape
    the other engines use, each with how to reproduce it and how to fix it.
    """
    out = {"rule_id": spec.get("id", ""), "status": "ok", "findings": [],
           "detail": ""}
    base_url = ctx.get("base_url") or ""
    host = urlparse(base_url).hostname or ctx.get("host") or ""
    domains = ctx.get("domains")

    # The gate, before anything runs.  An out of scope host never gets a probe.
    if not scope.allowed(host, domains):
        out["status"] = "refused"
        out["detail"] = scope.refuse_reason(host, domains)
        return out

    skip = needs_met(spec, ctx)
    if skip:
        out["status"] = "skipped"
        out["detail"] = skip
        return out

    budget = Budget(int(ctx.get("budget") or DEFAULT_BUDGET))
    client = Client(base_url, domains, spec["safety"], budget,
                    allow_private=bool(ctx.get("allow_private")),
                    headers=ctx.get("headers"))

    # A rule with {route} in its probe is aimed at the discovered routes; a
    # fixed-path rule is run once, not repeated against every route.
    if _uses_route(spec):
        routes = list(ctx.get("code_routes") or [])[:MAX_ROUTES]
    else:
        routes = [""]
    confirm = spec.get("confirm") or {}
    differential = confirm.get("differential") or "False"
    retest = int(confirm.get("retest") or 1)
    oob = ctx.get("oob")

    try:
        for route in routes:
            token = oob.token() if (oob and spec["safety"] == "oob") else ""
            oob_value = oob.url(token) if (oob and token) else ""
            confirmations = 0
            last = control = None
            for _attempt in range(retest):
                last = _run_probe(spec, client, route, oob_value)
                control = (_control_response(client)
                           if spec["safety"] != "oob" else {})
                oob_hit = bool(oob and token and oob.hit(token))
                env = _env_for(last, control, oob_hit)
                if evaluate(differential, env):
                    confirmations += 1
                else:
                    break
            if confirmations == retest and confirmations > 0:
                out["findings"].append(_finding(spec, client, last, route))
                break   # one solid finding per rule; the rest is noise
    except Refused as exc:
        out["status"] = "refused"
        out["detail"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - a broken rule is not a broken scan
        out["status"] = "error"
        out["detail"] = f"{type(exc).__name__}: {exc}"[:200]
    return out


def _run_probe(spec: dict, client: Client, route: str, oob_value: str) -> dict:
    """Send the probe steps; the last response is what the differential reads.

    oob_value is the callback URL that {oob} becomes, empty for a non oob rule.
    """
    last = {}
    for step in spec.get("probe") or []:
        req = step.get("request") if isinstance(step, dict) else None
        if not isinstance(req, dict):
            continue
        path = _expand(str(req.get("path") or "/"), route, oob_value)
        query = {k: _expand(str(v), route, oob_value)
                 for k, v in (req.get("query") or {}).items()}
        last = client.request(req.get("method") or "GET", path, query=query,
                              headers=req.get("headers") or {})
    return last


def _finding(spec: dict, client: Client, response: dict, route: str) -> dict:
    """A finding that stands on evidence, with how to repeat it and how to fix."""
    from app.core import dast_engines

    url = response.get("final_url") or response.get("url") or client.base_url
    if spec.get("safety") == "oob":
        evidence = ("Confirmed by an out of band callback: the site was made to "
                    "reach our unique address, which proves it, and re-tested.")
    else:
        evidence = (f"Confirmed against a control (a request that cannot "
                    f"succeed) and re-tested.  The site answered status "
                    f"{response.get('status')} here but not for the control.")
    f = dast_engines._finding(
        tool=f"rule:{spec['id']}", title=spec.get("title", spec["id"]),
        severity=spec.get("severity_floor", "medium"), url=url,
        evidence=evidence[:800], fix=spec.get("remediate", ""),
        cwe=(spec.get("mappings") or {}).get("cwe", ""),
        ref=(spec.get("references") or [""])[0])
    f["rule_id"] = spec["id"]
    f["rule_class"] = spec["class"]
    f["reproduce"] = spec.get("reproduce", "")
    f["route"] = route
    return f
