"""Testing an API from its OpenAPI or Swagger description.

A crawler finds the pages a site links to.  An API links to nothing, so a
scan that is not told what the API is tests almost none of it.  An uploaded
description lists every operation, its parameters and which ones need a sign
in, and this turns that list into checks for the weaknesses that matter most
in APIs (OWASP API Security Top 10):

  API1  object level authorization: an object of one account, read by another.
        Ids come from the second account's own list operations, then each
        object is read as that account, as the first account and signed out.
  API2  authentication: an operation the description says needs a sign in
        that answers with data to a request with none.
  API3  property level exposure: a response that carries a password hash, a
        key, a token or a secret question in a field.
  API5  function level authorization: an administrative operation (by its
        path, tag or name) that answers with data to the account described as
        the lower privilege one.
  API7  server side request forgery: a parameter that takes an address, given
        the out of band callback's address, proven only when the callback is
        reached.

Every request is a read: GET only, through the engine's client, which holds
the scope gate and refuses any other method.  Nothing is created, changed or
deleted, so these run against production as safely as the rest of a scan.
The description's own servers are never used: every request goes to the
site being scanned, so an uploaded file cannot point the scanner anywhere
else.

Findings come with the three responses side by side, how to repeat them, and
how to fix them, the same as every other check.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

MAX_BYTES = 5 * 1024 * 1024
MAX_OPERATIONS = 600
MAX_IDS = 4               # objects tried per item operation
MAX_ITEM_OPS = 40
MAX_SSRF = 10

_ADMINISH = re.compile(r"(?i)(^|[/_.-])(admin|administrat\w*|internal|manage\w*|config\w*|"
                       r"settings?|system|users?|roles?|permissions?|groups?|audit\w*|"
                       r"logs?|exports?|debug|metrics|tenants?|billing|keys?|tokens?|"
                       r"secrets?|backup\w*|impersonat\w*)($|[/_.-])")
_LOWER = re.compile(r"(?i)(read.?only|viewer|lower|limited|basic|auditor|guest|standard|"
                    r"regular|no admin|non.?admin|ordinary|least)")
_ADDRESS_PARAM = re.compile(r"(?i)^(url|uri|link|href|callback|callback_?url|webhook\w*|"
                            r"redirect\w*|return_?url|next|target|dest\w*|image_?url|"
                            r"feed|endpoint|host|server|proxy|fetch|src|source_?url)$")
_SENSITIVE_KEY = re.compile(r"(?i)^(password|passwd|password_?hash|pass_?hash|pwd|"
                            r"secret|client_?secret|api_?key|apikey|private_?key|"
                            r"access_?token|refresh_?token|session_?token|auth_?token|"
                            r"totp_?secret|mfa_?secret|otp_?secret|salt|ssn|"
                            r"social_?security\w*|security_?answer|card_?number|cvv)$")
_ID_KEY = re.compile(r"(?i)^(id|uuid|guid|key|slug|\w+_id|\w+Id|\w+_uuid)$")


class SpecError(ValueError):
    pass


# ---- reading the description ---------------------------------------------------

def _load(text: str):
    text = (text or "").strip()
    if not text:
        raise SpecError("the file is empty")
    if text[0] in "{[":
        try:
            return json.loads(text)
        except ValueError as exc:
            raise SpecError(f"not valid JSON: {exc}") from None
    try:
        import yaml
    except ImportError:
        raise SpecError("YAML is not supported here; upload the JSON form") from None

    class NoAliases(yaml.SafeLoader):
        """Anchors and aliases refused: they are how a small file expands into a
        huge one, and a real API description does not need them."""

        def compose_node(self, parent, index):
            if self.check_event(yaml.events.AliasEvent):
                raise SpecError("anchors and aliases are not accepted")
            return super().compose_node(parent, index)

    try:
        return yaml.load(text, Loader=NoAliases)    # noqa: S506 - a safe loader
    except yaml.YAMLError as exc:
        raise SpecError(f"not valid YAML: {str(exc)[:200]}") from None


def parse(text: str) -> dict:
    """An uploaded description as the operations to test.  Raises SpecError.

    -> {title, version, kind, base, operations: [{method, path, params,
        secured, admin, op_id, summary, tags}]}
    """
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise SpecError("the file is larger than 5 MB")
    doc = _load(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        raise SpecError("this is not an OpenAPI or Swagger description: it has no paths")
    kind = "swagger 2" if str(doc.get("swagger") or "").startswith("2") else \
        "openapi " + str(doc.get("openapi") or "3")
    # Only the path part of where the API lives.  The host is always the site.
    base = ""
    if kind == "swagger 2":
        base = str(doc.get("basePath") or "")
    else:
        servers = doc.get("servers") or []
        if servers and isinstance(servers[0], dict):
            base = urlparse(str(servers[0].get("url") or "")).path or ""
    base = "/" + base.strip("/") if base.strip("/") else ""
    global_secured = bool(doc.get("security"))
    ops = []
    for path, item in doc["paths"].items():
        if not isinstance(item, dict) or not str(path).startswith("/"):
            continue
        shared = [p for p in item.get("parameters") or [] if isinstance(p, dict)]
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            if not isinstance(op, dict):
                continue
            params = []
            for p in shared + [p for p in op.get("parameters") or [] if isinstance(p, dict)]:
                if "$ref" in p:
                    continue
                schema = p.get("schema") if isinstance(p.get("schema"), dict) else {}
                params.append({"name": str(p.get("name") or "")[:80],
                               "in": str(p.get("in") or "")[:20],
                               "required": bool(p.get("required")),
                               "type": str(p.get("type") or schema.get("type") or "")[:20],
                               "format": str(p.get("format") or schema.get("format") or "")[:20]})
            secured = op.get("security")
            secured = global_secured if secured is None else bool(secured)
            words = " ".join([path, str(op.get("operationId") or ""),
                              " ".join(str(t) for t in op.get("tags") or [])])
            ops.append({"method": method.upper(), "path": base + str(path),
                        "params": params, "secured": secured,
                        "admin": bool(_ADMINISH.search(words)),
                        "op_id": str(op.get("operationId") or "")[:120],
                        "summary": str(op.get("summary") or "")[:200],
                        "tags": [str(t)[:40] for t in (op.get("tags") or [])][:5]})
            if len(ops) >= MAX_OPERATIONS:
                break
        if len(ops) >= MAX_OPERATIONS:
            break
    if not ops:
        raise SpecError("the description lists no operations")
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    return {"title": str(info.get("title") or "")[:200],
            "version": str(info.get("version") or "")[:40],
            "kind": kind, "base": base, "operations": ops}


def summary(parsed: dict) -> dict:
    ops = parsed.get("operations") or []
    return {"title": parsed.get("title", ""), "version": parsed.get("version", ""),
            "kind": parsed.get("kind", ""), "operations": len(ops),
            "reads": sum(1 for o in ops if o["method"] == "GET"),
            "secured": sum(1 for o in ops if o["secured"]),
            "admin": sum(1 for o in ops if o["admin"])}


# ---- running it ------------------------------------------------------------------

_PATH_PARAM = re.compile(r"\{([^}/]+)\}")


def _json(resp: dict):
    ctype = str((resp.get("headers") or {}).get("content-type", "")).lower()
    body = resp.get("body") or ""
    if "json" not in ctype and not body.lstrip().startswith(("{", "[")):
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def _has_data(value) -> bool:
    """A body that carries records, not an error or an empty shell."""
    if isinstance(value, list):
        return any(isinstance(x, (dict, list)) or x not in (None, "") for x in value)
    if isinstance(value, dict):
        keys = {str(k).lower() for k in value}
        if keys and keys <= {"error", "errors", "message", "detail", "status", "code",
                             "success", "ok", "title", "type"}:
            return False
        return bool(value)
    return False


def _records(value) -> list:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        for key in ("data", "items", "results", "records", "rows", "content", "value"):
            inner = value.get(key)
            if isinstance(inner, list):
                return [x for x in inner if isinstance(x, dict)]
    return []


def _ids(value) -> list:
    out = []
    for rec in _records(value)[:20]:
        for key, v in rec.items():
            if _ID_KEY.match(str(key)) and isinstance(v, (int, str)) and str(v).strip():
                out.append((str(key), str(v)))
                break
    return out


def _sensitive(value, path="") -> list:
    """Fields that carry a secret, with a non empty value.  -> [field path]"""
    hits = []
    if isinstance(value, dict):
        for k, v in list(value.items())[:200]:
            here = f"{path}.{k}" if path else str(k)
            if _SENSITIVE_KEY.match(str(k)) and isinstance(v, str) and len(v.strip()) >= 4:
                hits.append(here)
            elif isinstance(v, (dict, list)):
                hits += _sensitive(v, here)
    elif isinstance(value, list):
        for item in value[:20]:
            hits += _sensitive(item, path + "[]")
    return hits[:10]


def _same_object(a, b) -> bool:
    if a == b:
        return True
    if isinstance(a, dict) and isinstance(b, dict):
        ids = [k for k in a if _ID_KEY.match(str(k))]
        return bool(ids) and all(a.get(k) == b.get(k) for k in ids)
    return False


def _denied(resp: dict) -> bool:
    from app.core.dast_checks.engine import _looks_authless

    return resp.get("status") in (401, 403, 404) or _looks_authless(resp)


def _fill(path: str, value: str = "") -> str:
    return _PATH_PARAM.sub(lambda m: value or "1", path)


def _finding(title, severity, url, evidence, fix, cwe, owasp, reproduce):
    from app.core import dast_engines

    f = dast_engines._finding(tool="api-spec", title=title, severity=severity, url=url,
                              evidence=evidence[:800], fix=fix, cwe=cwe,
                              ref="https://owasp.org/API-Security/editions/2023/en/0x11-t10/")
    f["rule_id"] = "api-spec/" + owasp.lower()
    f["rule_class"] = "access-control" if owasp in ("API1", "API2", "API5") else "misconfiguration"
    f["reproduce"] = reproduce
    f["owasp_api"] = owasp
    return f


def _evidence(url, resp_a, resp_b, resp_anon, ctx, where: str) -> str:
    from app.core.dast_checks import engine

    text = engine._two_account_evidence(url, resp_a, resp_b, resp_anon,
                                        ctx.get("intent_a", ""), ctx.get("intent_b", ""))
    return text.replace(f"The address {url} was found in the second account's own pages.",
                        f"{where}  Address: {url}.", 1)


# ---- keeping the upload ----------------------------------------------------------

def _path(asset_id: int):
    from app.core import external

    return external.data_dir() / "api-specs" / f"{int(asset_id)}.json"


def save(asset_id: int, text: str, name: str, by: str) -> dict:
    """Parse and keep an uploaded description.  Raises SpecError.  -> summary"""
    from datetime import datetime, timezone

    parsed = parse(text)
    path = _path(asset_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"name": re.sub(r"[^\w. -]", "_", str(name or "api"))[:120], "by": str(by)[:120],
              "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "parsed": parsed}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record), encoding="utf-8")
    tmp.replace(path)
    return summary(parsed)


def load(asset_id: int) -> dict | None:
    """-> {name, by, at, parsed} or None."""
    path = _path(asset_id)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and record.get("parsed") else None


def clear(asset_id: int) -> None:
    try:
        _path(asset_id).unlink()
    except OSError:
        pass


def describe(asset_id: int) -> dict | None:
    record = load(asset_id)
    if not record:
        return None
    return {"name": record.get("name", ""), "by": record.get("by", ""),
            "at": record.get("at", ""), **summary(record["parsed"])}


def run(parsed: dict, ctx: dict, budget_requests: int = 300) -> tuple:
    """Run every check the description allows.  -> (findings, detail)."""
    from app.core.dast_checks import engine
    from app.core.dast_checks.engine import Budget, Client, Refused

    base_url = ctx.get("base_url") or ""
    domains = ctx.get("domains")
    budget = Budget(budget_requests)
    allow_private = bool(ctx.get("allow_private"))
    a = Client(base_url, domains, "read", budget, allow_private, ctx.get("headers"))
    b = Client(base_url, domains, "read", budget, allow_private, ctx.get("second_headers")) \
        if ctx.get("second_headers") else None
    anon = Client(base_url, domains, "read", budget, allow_private, None)
    ops = [o for o in parsed.get("operations") or [] if o["method"] == "GET"]
    findings, notes = [], []

    def get(client, path, query=None):
        try:
            return client.request("GET", path, query=query)
        except Refused:
            return {"status": 0, "body": "", "headers": {}}

    def url_of(path):
        return base_url.rstrip("/") + path

    collections = [o for o in ops if not _PATH_PARAM.search(o["path"])]
    items = [o for o in ops if _PATH_PARAM.search(o["path"])][:MAX_ITEM_OPS]
    seen_exposure = set()

    try:
        # API2: secured operations that answer signed out.  Collections only:
        # an item needs an id, and that is the next check's job.
        for op in collections:
            if not op["secured"]:
                continue
            signed_out = get(anon, op["path"])
            data = _json(signed_out)
            if signed_out.get("status") == 200 and not _denied(signed_out) and _has_data(data):
                signed_in = get(a, op["path"]) if ctx.get("headers") else {}
                if ctx.get("headers") and _json(signed_in) is None:
                    continue
                findings.append(_finding(
                    f"API operation answers without signing in: GET {op['path']}",
                    "high", url_of(op["path"]),
                    f"The API description says GET {op['path']} needs a sign in.  Asked "
                    f"with no credentials, it answered {signed_out.get('status')} with "
                    f"{len(_records(data)) or 'a body of'} record(s) of data.",
                    "Require authentication on this operation in the API itself, not only "
                    "in its documentation, and deny by default.",
                    "CWE-306", "API2",
                    f"curl -i '{url_of(op['path'])}'   (no cookie, no Authorization header)"))
            for client in (a, b):
                if client is None:
                    continue
                resp = get(client, op["path"])
                hits = _sensitive(_json(resp))
                if hits and op["path"] not in seen_exposure:
                    seen_exposure.add(op["path"])
                    findings.append(_finding(
                        f"API response carries secret fields: GET {op['path']}",
                        "medium", url_of(op["path"]),
                        "The response includes fields that hold secrets: "
                        + ", ".join(hits) + ".  Their values are not shown here.",
                        "Return only the fields a caller needs.  Never return password "
                        "hashes, keys or tokens; build responses from an allow list of fields.",
                        "CWE-213", "API3", f"GET {url_of(op['path'])} signed in, and read "
                        "the named fields."))

        # API1: the second account's objects, read by the first.
        if b is not None and ctx.get("headers"):
            ids = []
            for op in collections:
                ids += _ids(_json(get(b, op["path"])))
                if len(ids) >= 30:
                    break
            for op in items:
                tried = 0
                for _key, value in ids:
                    if tried >= MAX_IDS:
                        break
                    path = _fill(op["path"], value)
                    resp_b = get(b, path)
                    data_b = _json(resp_b)
                    if resp_b.get("status") != 200 or not _has_data(data_b):
                        continue
                    tried += 1
                    resp_a = get(a, path)
                    resp_anon = get(anon, path)
                    data_a = _json(resp_a)
                    if (resp_a.get("status") == 200 and _has_data(data_a)
                            and _same_object(data_a, data_b) and _denied(resp_anon)):
                        f = _finding(
                            f"One account reads another account's object: GET {op['path']}",
                            "high", url_of(path),
                            _evidence(url_of(path), resp_a, resp_b, resp_anon, ctx,
                                      f"The id came from the second account's own "
                                      f"answer to a list operation."),
                            "Check, on every request, that the object belongs to the "
                            "caller or is shared with them, using the signed in identity, "
                            "never an id from the request alone.",
                            "CWE-639", "API1", engine._two_account_reproduce(url_of(path)))
                        f["proof_kind"] = "two_account"
                        f["proof_url"] = url_of(path)
                        findings.append(f)
                        break

        # API5: administrative reads for the account described as lower privilege.
        if b is not None and ctx.get("headers") and _LOWER.search(ctx.get("intent_a") or ""):
            for op in collections:
                if not op["admin"]:
                    continue
                resp_b = get(b, op["path"])
                if resp_b.get("status") != 200 or not _has_data(_json(resp_b)):
                    continue
                resp_a = get(a, op["path"])
                resp_anon = get(anon, op["path"])
                if (resp_a.get("status") == 200 and _has_data(_json(resp_a))
                        and _denied(resp_anon)):
                    findings.append(_finding(
                        f"Lower privilege account reaches an administrative API: GET {op['path']}",
                        "high", url_of(op["path"]),
                        _evidence(url_of(op["path"]), resp_a, resp_b, resp_anon, ctx,
                                  f"The description marks this operation as "
                                  f"administrative ({op['op_id'] or op['path']})."),
                        "Check the caller's role on the server for every administrative "
                        "operation.  Hiding it from the interface is not a check.",
                        "CWE-285", "API5", engine._two_account_reproduce(url_of(op["path"]))))
        elif b is not None:
            notes.append("function level checks need the first account described as the "
                         "lower privilege one")

        # API7: parameters that take an address, proven only by the callback.
        oob = ctx.get("oob")
        if oob:
            tried = 0
            for op in ops:
                if tried >= MAX_SSRF:
                    break
                for p in op["params"]:
                    if p["in"] != "query" or not _ADDRESS_PARAM.match(p["name"]):
                        continue
                    token = oob.token()
                    target = oob.url(token)
                    get(a, _fill(op["path"]), {p["name"]: target})
                    tried += 1
                    if oob.hit(token):
                        findings.append(_finding(
                            f"Server fetches an address the caller gives: {p['name']} on "
                            f"GET {op['path']}",
                            "high", url_of(_fill(op["path"])),
                            "Confirmed by an out of band callback: given our unique address "
                            f"in {p['name']}, the server made a request to it.",
                            "Allow only the hosts this feature needs, resolve and check the "
                            "address, block private and metadata ranges, and connect to the "
                            "address that was checked.",
                            "CWE-918", "API7",
                            f"GET {url_of(_fill(op['path']))}?{p['name']}=<your listener URL>"))
                    break
    except Exception as exc:  # noqa: BLE001 - a broken description is not a broken scan
        notes.append(f"stopped early: {type(exc).__name__}")
    detail = (f"{len(parsed.get('operations') or [])} operations described, "
              f"{budget_requests - max(0, budget.left)} requests, "
              f"{len(findings)} finding(s)")
    if notes:
        detail += ".  " + "; ".join(notes)
    return findings, detail
