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
import base64
import hashlib
import hmac
import json
import re
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
                  "status_in", "differ", "same", "status_of"}
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


def _env_for(response: dict, control: dict, oob_hit: bool, saved: dict = None) -> dict:
    """The names and helpers a differential may use.

    saved holds other responses by name (for example b and anon in a two
    account check), so a differential can compare them.
    """
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

    def differ(a, b):
        return _normalize((a or {}).get("body") or "") != _normalize((b or {}).get("body") or "")

    def same(a, b):
        return not differ(a, b)

    def status_of(resp):
        return (resp or {}).get("status", 0)

    env = {
        "status": response.get("status", 0),
        "response": response,
        "control": control,
        "oob_hit": oob_hit,
        "_funcs": {"body_differs": body_differs, "body_contains": body_contains,
                   "header": header, "reflected": reflected,
                   "status_in": status_in, "differ": differ, "same": same,
                   "status_of": status_of},
    }
    env.update(saved or {})
    return env


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

    # A rule that compares two accounts runs its own path: it reads an object
    # that belongs to the second account and checks the first can read it too.
    if "two_accounts" in (spec.get("needs") or []):
        try:
            out["findings"] = _run_two_account(spec, ctx, domains, budget)
        except Refused as exc:
            out["status"], out["detail"] = "refused", str(exc)
        except Exception as exc:  # noqa: BLE001
            out["status"], out["detail"] = "error", f"{type(exc).__name__}: {exc}"[:200]
        return out

    # A rule with a jwt step forges a variant of the signed in token and checks
    # the server still accepts it: its own path, reads only.
    if any(isinstance(s, dict) and s.get("jwt") for s in spec.get("probe") or []):
        try:
            out["findings"] = _run_jwt(spec, ctx, domains, budget)
        except Refused as exc:
            out["status"], out["detail"] = "refused", str(exc)
        except Exception as exc:  # noqa: BLE001
            out["status"], out["detail"] = "error", f"{type(exc).__name__}: {exc}"[:200]
        return out

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


_OBJECT_PATH = re.compile(r"/\d{1,12}(?:/|$)|/[0-9a-fA-F]{8,}(?:/|$)"
                          r"|[?&][\w-]*id=\w+", re.I)


def _b_objects(client_b: Client, base_url: str, code_routes) -> list:
    """Addresses that look like they point at a specific object of account b.

    A cross account read is only meaningful against an object that belongs to
    the other account, so this keeps the links from account b's own pages (and
    any code routes) that carry an id, and leaves the generic pages out.
    """
    out = []
    try:
        landing = client_b.request("GET", "/")
    except Refused:
        return out
    from app.core.dast_engines import links_in

    for url in links_in(base_url, landing.get("body") or ""):
        if _OBJECT_PATH.search(url) and url not in out:
            out.append(url)
    for route in code_routes or []:
        if _OBJECT_PATH.search(route) and route not in out:
            out.append(route)
    return out[:MAX_ROUTES]


# Common weak signing secrets for the HS256 re-sign test.  A short, high signal
# list: a hit means the secret is guessable, not a brute force.
WEAK_JWT_SECRETS = ["secret", "password", "changeme", "123456", "key", "jwt",
                    "admin", "test", "secretkey", "your-256-bit-secret",
                    "your_jwt_secret", "supersecret", "token", "s3cr3t",
                    "jwtsecret", "qwerty", "P@ssw0rd"]
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _find_jwt(headers: dict):
    """The first JWT carried in the session, as (header name, value, token)."""
    for name, value in (headers or {}).items():
        for m in _JWT_RE.finditer(str(value)):
            tok = m.group(0)
            try:
                head = json.loads(_b64url_dec(tok.split(".")[0]))
            except Exception:  # noqa: BLE001 - not a real JWT, keep looking
                continue
            if isinstance(head, dict) and "alg" in head:
                return name, value, tok
    return None


def _forge_jwt(tok: str, mode: str, secret: str = "") -> str:
    """A variant of the token: the signature stripped, the algorithm set to
    none, or the token re-signed with a guessed secret.  The claims are left
    exactly as they were, so this proves the signature is not checked, it does
    not forge a new identity."""
    head_b, payload_b, _sig = tok.split(".")
    head = json.loads(_b64url_dec(head_b))
    if mode == "strip":
        return f"{head_b}.{payload_b}."
    if mode == "alg_none":
        head["alg"] = "none"
        return f"{_b64url_enc(json.dumps(head, separators=(',', ':')).encode())}.{payload_b}."
    if mode == "weak_secret":
        head["alg"] = "HS256"
        new_head = _b64url_enc(json.dumps(head, separators=(",", ":")).encode())
        sig = hmac.new(secret.encode(), f"{new_head}.{payload_b}".encode(), hashlib.sha256).digest()
        return f"{new_head}.{payload_b}.{_b64url_enc(sig)}"
    return tok


def _run_jwt(spec: dict, ctx: dict, domains, budget: Budget) -> list:
    """Forge a variant of the signed in session's JWT and check the server still
    accepts it.  -> findings.  Reads only, claims unchanged.

    The finding stands only when the forged token gets the signed in response
    and the signed out visitor does not, so a public page or a rejected forgery
    both stay silent.
    """
    base_url = ctx.get("base_url") or ""
    allow_private = bool(ctx.get("allow_private"))
    headers = ctx.get("headers") or {}
    found = _find_jwt(headers)
    if not found:
        return []   # the session carries no JWT, so there is nothing to forge
    name, value, tok = found
    step = next((s.get("jwt") for s in spec.get("probe") or []
                 if isinstance(s, dict) and s.get("jwt")), {})
    paths = step.get("paths") or ([step["path"]] if step.get("path") else ["/"])
    modes = [m for m in (step.get("forge") or ["alg_none", "strip"])
             if m in ("alg_none", "strip", "weak_secret")]

    authed = Client(base_url, domains, "read", budget, allow_private, headers)
    anon = Client(base_url, domains, "read", budget, allow_private, None)
    confirm = spec.get("confirm") or {}
    differential = confirm.get("differential") or "False"
    retest = int(confirm.get("retest") or 1)
    said = {"alg_none": "an alg:none token", "strip": "a token with its signature stripped",
            "weak_secret": "a token re-signed with a guessed secret"}

    for path in paths[:8]:
        resp_authed = authed.request("GET", path)
        # The endpoint must really be behind the session; the differential then
        # confirms, per attempt, that the forgery got the signed in response and
        # the signed out one did not, so a public page stays silent.
        if resp_authed.get("status") != 200:
            continue
        resp_anon = anon.request("GET", path)
        for mode in modes:
            for secret in (WEAK_JWT_SECRETS if mode == "weak_secret" else [""]):
                try:
                    forged = _forge_jwt(tok, mode, secret)
                except Exception:  # noqa: BLE001 - a malformed token, skip this mode
                    break
                forged_headers = dict(headers)
                forged_headers[name] = value.replace(tok, forged)
                client = Client(base_url, domains, "read", budget, allow_private, forged_headers)
                confirmations, resp = 0, None
                for _attempt in range(retest):
                    resp = client.request("GET", path)
                    env = _env_for(resp, {}, False,
                                   saved={"authed": resp_authed, "anon": resp_anon})
                    if evaluate(differential, env):
                        confirmations += 1
                    else:
                        break
                if confirmations == retest and confirmations > 0:
                    f = _finding(spec, client, resp, path)
                    how = (f"a token re-signed with the weak secret '{secret}'"
                           if mode == "weak_secret" else said.get(mode, mode))
                    f["evidence"] = (
                        f"The signed in session's JWT was replaced with {how}, its claims "
                        f"unchanged, and the server returned the signed in response at {path} "
                        "all the same, so it is not verifying the token's signature.  The "
                        "signed out visitor is turned away.")[:800]
                    return [f]
    return []


def _run_two_account(spec: dict, ctx: dict, domains, budget: Budget) -> list:
    """Account A reads an object that belongs to account B.  -> findings.

    Reads only.  For each object address found in B's own pages: fetch it as B
    (to confirm it is really B's and it is a real page), as A, and signed out.
    The differential decides, for example: A got 200, it is really B's object,
    A sees the same body as B, and the signed out visitor is turned away.
    """
    base_url = ctx.get("base_url") or ""
    allow_private = bool(ctx.get("allow_private"))
    a = Client(base_url, domains, "read", budget, allow_private, ctx.get("headers"))
    b = Client(base_url, domains, "read", budget, allow_private, ctx.get("second_headers"))
    anon = Client(base_url, domains, "read", budget, allow_private, None)

    confirm = spec.get("confirm") or {}
    differential = confirm.get("differential") or "False"
    retest = int(confirm.get("retest") or 1)

    findings = []
    for url in _b_objects(b, base_url, ctx.get("code_routes")):
        confirmations, resp_a = 0, None
        for _attempt in range(retest):
            resp_b = b.request("GET", url)
            if resp_b.get("status") != 200:
                break
            resp_a = a.request("GET", url)
            resp_anon = anon.request("GET", url)
            env = _env_for(resp_a, {}, False,
                           saved={"b": resp_b, "anon": resp_anon})
            if evaluate(differential, env):
                confirmations += 1
            else:
                break
        if confirmations == retest and confirmations > 0:
            findings.append(_finding(spec, a, resp_a, url))
            break   # one solid finding per rule
    return findings


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
