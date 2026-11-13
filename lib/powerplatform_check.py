"""Read Microsoft Power Platform exports for the problems no other engine sees.

A Power Platform solution checked into git is YAML and JSON: Power Pages site
metadata (web roles, table permissions, site settings), canvas app source
(.pa.yaml, or the older .fx.yaml), and Power Automate flow definitions.
Semgrep has no idea what any of it means, and the code pass came back empty on
every one of these repositories.  One of them gave the Anonymous Users web
role read access to every row of two tables, with the Web API switched on for
both, and nothing in the scan said so.

Every rule is a fact about Microsoft's export format, not about any one
repository: the web role flags, the table permission scope and privileges,
the Webapi/<table>/enabled site setting, the flow trigger and action shapes,
the HtmlText property.  Nothing here names a table, a role id or a site.

  powerplatform.pages-anonymous-global-access
      A table permission with Global access (every row) held by a web role
      marked Anonymous Users Role.  Read, write or delete with the Web API on
      for that table is high: anybody can list or change every row with no
      sign in.  Without the Web API it is medium, since the permission still
      governs every list, form and Liquid query an anonymous visitor reaches.

  powerplatform.pages-anonymous-global-create
      The same for create only.  Anybody can add rows, and every column the
      Web API exposes is theirs to fill, including ones that say who the row
      belongs to.  Medium with the Web API on, low without.

  powerplatform.pages-authenticated-global-write
      Global write or delete held by the Authenticated Users role: any signed
      in visitor can change or remove every other visitor's rows.  Medium.
      Global read for that role is only reported when open registration is on
      and the Web API is enabled, because then signing in proves nothing.

  powerplatform.flow-http-trigger-anyone
      A flow started by "When an HTTP request is received" whose "Who can
      trigger the flow" is Anyone (Microsoft: "open access without any
      additional authentication"), that writes data or sends mail, and never
      looks at the request headers.  Medium.

  powerplatform.flow-html-email-unencoded
      An email action whose HTML body has record or caller values put straight
      into the markup.  Power Automate does not encode them.  Low.

  powerplatform.flow-recipients-from-caller
      A flow started by a caller (a Power App, Power Pages or an HTTP request)
      that sends mail to addresses the caller passed in.  Low.

  powerplatform.flow-csv-formula
      A Create CSV table action, with nothing in the flow neutralizing cells
      that begin with = + - @.  Low.

  powerplatform.flow-odata-filter-injection
      A $filter that pastes a record or caller value between single quotes
      without doubling quotes in it.  Low.

  powerplatform.flow-owner-reads-caller-key
      A caller started flow that reads rows or files with its owner's
      connection by a key (filter, id, file) the caller sent.  Medium when it
      responds with the result, low otherwise.

  powerplatform.flow-file-trigger-bulk-write
      A flow started by a new file that loops over the file and writes each
      row somewhere trusted.  Medium.

  powerplatform.pages-no-content-security-policy
      A Power Pages site with site settings but no Content-Security-Policy.

  A flow marked Draft (StateCode 0) in its workflow.yml is graded one level
  lower, and the finding says it is off.

  powerplatform.canvas-htmltext-unencoded
      A canvas app HtmlText formula that joins data values into markup without
      EncodeHTML.  The control renders links and markup.  Low.

Usage: powerplatform_check.py <dir> <repository> <branch> <web base> <link JSON>
Prints a JSON array of code findings in the shape the other engines use.
"""

from __future__ import annotations

import json
import os
import re
import sys

try:                                  # the scanner's venv has it; be safe anyway
    import yaml
    _LOADER = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader
except ImportError:                   # pragma: no cover
    yaml = None
    _LOADER = None

MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv",
             "venv", "__pycache__", "bin", "obj"}

# Dataverse option set for a table permission's scope (adx_scope / mspp_scope).
SCOPE = {756150000: "Global", 756150001: "Contact", 756150002: "Account",
         756150003: "Parent", 756150004: "Self"}
GLOBAL = 756150000

# Power Automate operations that change something or send something.
WRITE_OPS = {
    "postitem", "patchitem", "deleteitem", "createfile", "updatefile", "deletefile",
    "copyfile", "movefile", "createrecord", "updaterecord", "updateonlyrecord",
    "deleterecord", "performboundaction", "performunboundaction", "associateentities",
    "executeprocedure", "executeprocedure_v2", "insertrow", "insertrow_v2", "patchrow",
    "patchrow_v2", "deleterow", "deleterow_v2", "addrowv2", "addrow", "updaterow",
    "postmessagetoconversation", "postmessagetochannel", "postmessagetochannelv3",
    "createtask", "createissue",
}
MAIL_OPS = {"sendemailv2", "sendemail", "sendemailfromsharedmailboxv2",
            "sendemailfromsharedmailbox", "sendemailnotification", "sendmailv3",
            "sendemailwithoptions", "sendanemailv2"}
# Operations that read rows or files by a key.
READ_OPS = {"getitems", "getitem", "listrecords", "getrecord", "getfilecontent",
            "getfilecontentbypath", "getfilemetadata", "getfilemetadatabypath",
            "listrows", "getrow", "getrowv2", "executeprocedure_v2", "getfileitems"}
# Triggers that start when somebody drops a file into a library or folder.
FILE_TRIGGERS = {"getonnewfileitems", "getonupdatedfileitems", "onnewfile", "onnewfilev2",
                 "onnewfiles", "onnewfilesv2", "onupdatedfile", "onupdatedfilev2",
                 "onnewfilev3", "onupdatedfilev3"}
KEY_PARAM = re.compile(r"(^|/)(\$filter|id|itemid|recordid|file|path|fileid)$", re.I)
FILTER_QUOTED = re.compile(r"'\s*@\{([^{}]*)\}\s*'")

# Triggers whose caller supplies the inputs (as opposed to a record or a timer).
CALLER_KINDS = {"powerapp", "powerappv2", "http", "powerpages", "button",
                "virtualagent", "skills"}

# Values that come from a record or a caller, inside @{...} or @expr.
FLOW_DATA = re.compile(r"\b(triggerBody|triggerOutputs|items|item|body|outputs|"
                       r"variables|actions)\s*\(")
INTERP = re.compile(r"@\{([^{}]*)\}")
HEADERS_READ = re.compile(r"triggerOutputs\(\)\s*\??\[\s*'headers'|"
                          r"triggerOutputs\(\)\s*\??\.\s*headers", re.I)
CSV_GUARD = re.compile(r"startsWith\([^)]*'\s*[=+@-]\s*'|"
                       r"(?:concat|replace)\([^)]*'''", re.I)

# Canvas app data references that can carry text somebody else wrote.
FX_DATA = re.compile(
    r"ThisItem\.(?:'[^']+'|\w+)(?:\.(?:'[^']+'|\w+))*|"
    r"\b\w+\.Selected\.(?:'[^']+'|\w+)(?:\.\w+)*|"
    r"\b(?:LookUp|First|Last|Index|Param)\s*\(|"
    r"\b\w+\.Text\b|\bUser\(\)\.(?:FullName|Email)")
FX_JOIN = re.compile(r"&|\bConcatenate\s*\(|\bConcat\s*\(")
HTMLTEXT = re.compile(r"^(\s*)HtmlText\s*:\s*(.*)$")


def _key(doc: dict, name: str):
    """A field by its pac name, or the adx_/mspp_ prefixed one older exports use."""
    for k in (name, "adx_" + name, "mspp_" + name):
        if k in doc:
            return doc[k]
    return None


def _flat_yaml(text: str) -> dict:
    """Enough of YAML for flat pac exports, when PyYAML is missing."""
    out, last = {}, None
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_][\w./-]*):\s*(.*)$", line)
        if m:
            last, value = m.group(1), m.group(2).strip()
            if value == "":
                out[last] = None
            elif value.lower() in ("true", "false"):
                out[last] = value.lower() == "true"
            elif re.fullmatch(r"-?\d+", value):
                out[last] = int(value)
            else:
                out[last] = value.strip("'\"")
        elif last and re.match(r"^\s*-\s+(.+)$", line):
            item = re.match(r"^\s*-\s+(.+)$", line).group(1).strip("'\"")
            out[last] = (out[last] if isinstance(out[last], list) else []) + [item]
    return out


def _read(path: str):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _load_yaml(path: str) -> dict:
    text = _read(path)
    if text is None:
        return {}
    if yaml is not None:
        try:
            doc = yaml.load(text, Loader=_LOADER)
            return doc if isinstance(doc, dict) else {}
        except Exception:             # a hand edited file is not our problem
            return {}
    return _flat_yaml(text)


def _line_of(text: str, needle: str, default: int = 1) -> int:
    at = text.find(needle) if needle else -1
    return text.count("\n", 0, at) + 1 if at >= 0 else default


def _walk(root_dir: str):
    for here, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            path = os.path.join(here, name)
            if not os.path.islink(path):
                yield path


def _rel(root_dir: str, path: str) -> str:
    return os.path.relpath(path, root_dir).replace(os.sep, "/")


def _truthy(value) -> bool:
    return value is True or str(value).strip().lower() in ("true", "1", "yes")


# --- Power Pages -------------------------------------------------------------

def _site_dirs(root_dir: str, paths: list) -> list:
    """Every folder holding a table-permissions folder, which is a site export."""
    sites = set()
    for path in paths:
        parent = os.path.dirname(path)
        if os.path.basename(parent).lower() == "table-permissions" and path.endswith(".yml"):
            sites.add(os.path.dirname(parent))
    return sorted(sites)


def _yml_in(folder: str) -> list:
    try:
        return sorted(os.path.join(folder, n) for n in os.listdir(folder)
                      if n.endswith((".yml", ".yaml")))
    except OSError:
        return []


def check_site(root_dir: str, site: str) -> list:
    roles = {}
    for path in _yml_in(os.path.join(site, "web-roles")):
        doc = _load_yaml(path)
        rid = str(_key(doc, "id") or _key(doc, "webroleid") or "").lower()
        if rid:
            roles[rid] = {"name": str(_key(doc, "name") or rid),
                          "anonymous": _truthy(_key(doc, "anonymoususersrole")),
                          "authenticated": _truthy(_key(doc, "authenticatedusersrole"))}
    settings = {}
    folder = os.path.join(site, "site-settings")
    for path in _yml_in(folder):
        doc = _load_yaml(path)
        name = _key(doc, "name")
        if name:
            settings[str(name).strip().lower()] = _key(doc, "value")
    # Some exports keep every setting in one list.
    for single in ("sitesetting.yml", "site-settings.yml"):
        path = os.path.join(site, single)
        if os.path.isfile(path) and yaml is not None:
            try:
                rows = yaml.load(_read(path) or "", Loader=_LOADER) or []
            except Exception:
                rows = []
            for doc in rows if isinstance(rows, list) else []:
                if isinstance(doc, dict) and _key(doc, "name"):
                    settings[str(_key(doc, "name")).lower()] = _key(doc, "value")

    def webapi(table: str) -> tuple:
        on = _truthy(settings.get(f"webapi/{table}/enabled"))
        fields = str(settings.get(f"webapi/{table}/fields") or "").strip()
        return on, fields

    open_registration = (_truthy(settings.get("authentication/registration/enabled", True))
                         and _truthy(settings.get(
                             "authentication/registration/openregistrationenabled")))

    hits = []
    for path in _yml_in(os.path.join(site, "table-permissions")):
        text = _read(path) or ""
        doc = _load_yaml(path)
        try:
            scope = int(_key(doc, "scope"))
        except (TypeError, ValueError):
            continue
        if scope != GLOBAL:
            continue
        table = str(_key(doc, "entitylogicalname") or "").strip().lower()
        if not table:
            continue
        held = _key(doc, "entitypermission_webrole") or []
        if isinstance(held, str):
            held = [held]
        held = [roles.get(str(r).lower()) for r in held]
        held = [r for r in held if r]
        anon = [r["name"] for r in held if r["anonymous"]]
        authd = [r["name"] for r in held if r["authenticated"]]
        if not (anon or authd):
            continue
        can = {op for op in ("read", "write", "delete", "create")
               if _truthy(_key(doc, op))}
        if not can:
            continue
        filtered = bool(str(_key(doc, "permissionfetchxml") or "").strip())
        api_on, fields = webapi(table)
        perm = str(_key(doc, "entityname") or _key(doc, "name") or os.path.basename(path))
        line = _line_of(text, "scope:", 1)
        rel = _rel(root_dir, path)
        api_note = (f"The Web API is enabled for {table}"
                    + (f" (columns: {fields})" if fields else "") + ", so this works "
                    "from any HTTP client through /_api/." if api_on else
                    f"The Web API is not enabled for {table} in this export, so the "
                    "exposure is through the pages, lists, forms and Liquid that use it.")
        filt_note = (" A FetchXML filter is set on the permission; check that it "
                     "narrows the rows, since that lowers this." if filtered else "")

        def add(rule, severity, cwe, title, message, ops):
            if filtered:
                severity = {"high": "medium", "medium": "low"}.get(severity, severity)
            hits.append({
                "rule": rule, "severity": severity, "cwe": cwe, "file": rel,
                "line": line, "title": title,
                "message": message + " " + api_note + filt_note,
                "matched": f"{table} scope Global {'/'.join(sorted(ops))} for "
                           f"{', '.join(sorted(anon or authd))}"})

        changes = can & {"read", "write", "delete"}
        if anon and changes:
            add("pages-anonymous-global-access",
                "high" if (api_on or changes & {"write", "delete"}) else "medium",
                "284", f"Anonymous visitors can {'/'.join(sorted(changes))} every {table} row",
                f"Table permission '{perm}' grants Global access (every row) to "
                f"{', '.join(anon)}, the web role every visitor who has not signed in "
                f"holds, with {', '.join(sorted(changes))}.  Nothing ties a row to the "
                "visitor.  Use Contact, Account, Parent or Self access, or move it off "
                "the anonymous role.", changes)
        elif anon and "create" in can:
            add("pages-anonymous-global-create", "medium" if api_on else "low", "639",
                f"Anonymous visitors can create {table} rows with any values",
                f"Table permission '{perm}' lets {', '.join(anon)} create {table} rows "
                "with Global access, and nothing binds a new row to a signed in "
                "contact.  Any column the visitor can send, including ones naming who "
                "the row belongs to, is theirs to set.  Require sign in and bind the "
                "row to the contact (Contact access with a relationship), or set the "
                "owner fields server side.", {"create"})
        if authd and not anon:
            if changes & {"write", "delete"}:
                add("pages-authenticated-global-write", "medium", "639",
                    f"Any signed in visitor can change every {table} row",
                    f"Table permission '{perm}' grants Global "
                    f"{'/'.join(sorted(changes & {'write', 'delete'}))} to "
                    f"{', '.join(authd)}, the role every signed in visitor holds, so "
                    "each one can change or remove rows that belong to others"
                    + (", and open registration lets anybody sign up." if
                       open_registration else ".")
                    + "  Use Contact, Account, Parent or Self access.",
                    changes & {"write", "delete"})
            elif "read" in changes and open_registration and api_on:
                add("pages-authenticated-global-write", "medium", "284",
                    f"Anybody who registers can read every {table} row",
                    f"Table permission '{perm}' grants Global read to "
                    f"{', '.join(authd)}, and open registration is on, so signing up "
                    "is all it takes to list every row.", {"read"})

    # No Content-Security-Policy site setting: the browser runs any script a
    # page or a stored value manages to inject.  Only when the export carries
    # site settings at all, so a partial export is not reported.
    if settings and not any(k.startswith("http/content-security-policy") and
                            not k.endswith("report-only") for k in settings):
        anchor = os.path.join(site, "website.yml")
        hits.append({
            "rule": "pages-no-content-security-policy", "severity": "low", "cwe": "693",
            "file": _rel(root_dir, anchor if os.path.isfile(anchor) else folder),
            "line": 1, "title": "Power Pages site sets no Content Security Policy",
            "message": ("None of this site's settings is HTTP/Content-Security-Policy, so "
                        "the browser will run any script that reaches a page, from a "
                        "custom page script, a template or a stored value.  Add the "
                        "setting with script-src limited to the site and the hosts it "
                        "really uses (Power Pages supports a nonce for its own scripts)."),
            "matched": "no HTTP/Content-Security-Policy site setting"})
    return hits


# --- Power Automate ----------------------------------------------------------

def _flow_definition(text: str):
    if "workflowdefinition.json" not in text and '"triggers"' not in text:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    for candidate in (doc.get("properties", {}).get("definition"), doc.get("definition"), doc):
        if isinstance(candidate, dict) and isinstance(candidate.get("triggers"), dict) \
                and isinstance(candidate.get("actions"), dict):
            return candidate
    return None


def _actions(actions: dict):
    """Every action, nested ones (conditions, loops, scopes, switches) too."""
    for name, act in (actions or {}).items():
        if not isinstance(act, dict):
            continue
        yield name, act
        yield from _actions(act.get("actions"))
        if isinstance(act.get("else"), dict):
            yield from _actions(act["else"].get("actions"))
        for case in (act.get("cases") or {}).values():
            if isinstance(case, dict):
                yield from _actions(case.get("actions"))
        if isinstance(act.get("default"), dict):
            yield from _actions(act["default"].get("actions"))


def _op(act: dict) -> str:
    inputs = act.get("inputs") if isinstance(act.get("inputs"), dict) else {}
    host = inputs.get("host") if isinstance(inputs.get("host"), dict) else {}
    return str(host.get("operationId") or act.get("type") or "").lower()


def _params(act: dict) -> dict:
    inputs = act.get("inputs") if isinstance(act.get("inputs"), dict) else {}
    params = inputs.get("parameters")
    return params if isinstance(params, dict) else {}


def _flow_off(path: str) -> bool:
    """A solution export keeps the flow's state in workflow.yml beside it.
    StateCode 0 is Draft (off); 1 is Activated."""
    meta = os.path.join(os.path.dirname(path), "workflow.yml")
    if not os.path.isfile(meta):
        return False
    m = re.search(r"^\s*StateCode\s*:\s*['\"]?(\d+)", _read(meta) or "", re.M)
    return bool(m) and m.group(1) == "0"


def _embedded(doc_text: str) -> dict:
    """connection name -> runtimeSource, from the flow file's connectionReferences."""
    try:
        doc = json.loads(doc_text)
    except ValueError:
        return {}
    refs = (doc.get("properties") or {}).get("connectionReferences") or {}
    return {str(k): str((v or {}).get("runtimeSource") or "").lower()
            for k, v in refs.items() if isinstance(v, dict)}


def check_flow(root_dir: str, path: str, text: str, definition: dict) -> list:
    hits = _check_flow(root_dir, path, text, definition)
    if hits and _flow_off(path):
        for hit in hits:
            hit["severity"] = {"high": "medium", "medium": "low"}.get(hit["severity"],
                                                                        hit["severity"])
            hit["message"] += ("  This flow is turned off (Draft) in this export, so the "
                               "grade is one level lower; it applies in full once the "
                               "flow is turned on.")
    return hits


def _check_flow(root_dir: str, path: str, text: str, definition: dict) -> list:
    rel = _rel(root_dir, path)
    hits = []
    triggers = definition.get("triggers") or {}
    kinds = set()
    anyone = None
    for tname, trig in triggers.items():
        if not isinstance(trig, dict):
            continue
        kind = str(trig.get("kind") or "").lower()
        ttype = str(trig.get("type") or "").lower()
        kinds.add(kind or ttype)
        inputs = trig.get("inputs") if isinstance(trig.get("inputs"), dict) else {}
        if ttype == "request" and kind in ("http", ""):
            auth = str(inputs.get("triggerAuthenticationType") or "All")
            if auth.lower() in ("all", "anyone", ""):
                anyone = tname
    caller = bool(kinds & CALLER_KINDS)
    acts = list(_actions(definition.get("actions")))
    body = json.dumps(definition.get("actions") or {})

    if anyone:
        doing = [(n, _op(a)) for n, a in acts if _op(a) in WRITE_OPS | MAIL_OPS
                 or _op(a) == "http"]
        if doing and not HEADERS_READ.search(body):
            names = ", ".join(sorted({n for n, _ in doing})[:4])
            hits.append({
                "rule": "flow-http-trigger-anyone", "severity": "medium", "cwe": "306",
                "file": rel, "line": _line_of(text, f'"{anyone}"'),
                "title": "Flow anybody with its URL can start writes data or sends mail",
                "message": ("This flow starts on \"When an HTTP request is received\" "
                            "with \"Who can trigger the flow\" set to Anyone, which "
                            "Microsoft describes as open access without any additional "
                            "authentication.  It then acts (" + names + ") and never "
                            "reads the request headers, so no shared secret or token "
                            "is checked here.  A gateway in front may check one, but "
                            "anybody holding the flow's own URL goes around it.  Use "
                            "\"Any user in my tenant\" or \"Specific users\", or "
                            "validate a credential in the flow before acting."),
                "matched": f"http trigger anyone {anyone}"})

    for name, act in acts:
        op = _op(act)
        if op not in MAIL_OPS:
            continue
        params = _params(act)
        line = _line_of(text, f'"{name}"')
        for key, value in params.items():
            low = key.lower()
            if not isinstance(value, str):
                continue
            if low.endswith("/body") or low == "body":
                parts = [m.group(1) for m in INTERP.finditer(value)]
                data = [p for p in parts if FLOW_DATA.search(p)
                        and "encodeuricomponent" not in p.lower()
                        and "replace(" not in p.lower()]
                if data and re.search(r"<\s*[a-zA-Z]", value):
                    hits.append({
                        "rule": "flow-html-email-unencoded", "severity": "low", "cwe": "79",
                        "file": rel, "line": line,
                        "title": "Email HTML built from record or caller values without encoding",
                        "message": (f"Action '{name}' puts {len(data)} value(s) into an HTML "
                                    "email body as they are.  Power Automate does not encode "
                                    "them, so whoever wrote the record (or called the flow) "
                                    "can add links, images or fake instructions to mail sent "
                                    "from a trusted account.  Encode < > & \" before use, "
                                    "for example with replace(), or send plain text."),
                        "matched": f"html body {name}"})
            if caller and re.search(r"(^|/)(to|cc|bcc)$", low) \
                    and re.search(r"triggerBody\s*\(\s*\)", value):
                hits.append({
                    "rule": "flow-recipients-from-caller", "severity": "low", "cwe": "441",
                    "file": rel, "line": line,
                    "title": "Mail sent to whatever addresses the caller passes in",
                    "message": (f"Action '{name}' takes its {key.split('/')[-1]} addresses "
                                "from the trigger input, and this flow is started by a "
                                "caller (a Power App, Power Pages or an HTTP request).  "
                                "Anyone who may run it can send mail, with the flow's "
                                "content, from the connection's mailbox to any address.  "
                                "Look recipients up from the record, or check them "
                                "against an allow list."),
                    "matched": f"recipients {name} {key}"})

    sources = _embedded(text)
    triggered_by_file = any(
        isinstance(t, dict) and str(((t.get("inputs") or {}).get("host") or {})
                                    .get("operationId") or "").lower() in FILE_TRIGGERS
        for t in triggers.values())
    responds = any(str(a.get("type") or "").lower() == "response" for _n, a in acts)
    for name, act in acts:
        op = _op(act)
        params = _params(act)
        line = _line_of(text, f'"{name}"')
        host = (act.get("inputs") or {}).get("host") if isinstance(act.get("inputs"), dict) else {}
        conn = str((host or {}).get("connectionName") or "")
        for key, value in params.items():
            if not isinstance(value, str):
                continue
            # B: a value pasted inside quotes in an OData filter.
            if key.lower().endswith("$filter"):
                pasted = [m.group(1) for m in FILTER_QUOTED.finditer(value)
                          if FLOW_DATA.search(m.group(1))
                          and "replace(" not in m.group(1).lower()]
                if pasted:
                    hits.append({
                        "rule": "flow-odata-filter-injection", "severity": "low",
                        "cwe": "943", "file": rel, "line": line,
                        "title": "OData filter built by pasting a value inside quotes",
                        "message": (f"Action '{name}' builds its $filter by pasting "
                                    f"{pasted[0].strip()[:60]} between single quotes.  A value "
                                    "with a quote in it ends the string and adds its own "
                                    "conditions (for example ' or 1 eq 1 or 'a' eq '), which "
                                    "changes which rows the flow reads.  Double any single "
                                    "quote first: replace(value, , '')."),
                        "matched": f"odata filter {name}"})
            # C: the owner's connection reads by a key the caller chose.
            if (caller and op in READ_OPS and KEY_PARAM.search(key)
                    and re.search(r"triggerBody\s*\(\s*\)", value)
                    and sources.get(conn, "embedded") != "invoker"):
                hits.append({
                    "rule": "flow-owner-reads-caller-key",
                    "severity": "medium" if responds else "low", "cwe": "639",
                    "file": rel, "line": line,
                    "title": "Flow reads data by a key the caller picks, with the owner's rights",
                    "message": (f"Action '{name}' reads with the flow owner's connection, and "
                                f"its {key.split('/')[-1]} comes from the trigger input.  This "
                                "flow is started by a caller (a Power App, Power Pages or an "
                                "HTTP request), and nothing in it checks that the key belongs "
                                "to that caller, so anyone who may run it can read another "
                                "person's rows" + (" and get them back in the response." if
                                responds else ".") + "  Take the key from the caller's own "
                                "identity on the server side (for example the signed in user's "
                                "email from the trigger headers), or run the connection as the "
                                "caller."),
                    "matched": f"owner reads caller key {name} {key}"})
        # D: rows from an uploaded file written somewhere trusted, in a loop.
        if triggered_by_file and op in WRITE_OPS and _in_loop(definition.get("actions"), name):
            hits.append({
                "rule": "flow-file-trigger-bulk-write", "severity": "medium", "cwe": "345",
                "file": rel, "line": line,
                "title": "Any file dropped in the watched folder is written in as trusted data",
                "message": (f"This flow starts when a file is created, loops over what is in "
                            f"it, and writes each row with action '{name}' using the owner's "
                            "connection.  Nothing checks who uploaded the file, validates the "
                            "rows, or limits how many there are, so anyone who can upload to "
                            "that folder decides what is written.  Check the uploader against "
                            "an allow list, validate each row, cap the row count, and keep the "
                            "folder's upload rights to the people who own the data."),
                "matched": f"file trigger bulk write {name}"})

    if not CSV_GUARD.search(body):
        for name, act in acts:
            if str(act.get("type") or "").lower() != "table":
                continue
            inputs = act.get("inputs") if isinstance(act.get("inputs"), dict) else {}
            if str(inputs.get("format") or "").upper() != "CSV":
                continue
            hits.append({
                "rule": "flow-csv-formula", "severity": "low", "cwe": "1236",
                "file": rel, "line": _line_of(text, f'"{name}"'),
                "title": "CSV export does not neutralize spreadsheet formulas",
                "message": (f"Action '{name}' writes a CSV table, and nothing in this flow "
                            "prefixes cells that begin with = + - @ (or tab, return).  A "
                            "value somebody typed into a record runs as a formula when "
                            "the file is opened in Excel.  Prefix those cells with a "
                            "single quote in the Select step."),
                "matched": f"csv {name}"})
    return hits


def _in_loop(actions: dict, target: str, inside: bool = False) -> bool:
    for name, act in (actions or {}).items():
        if not isinstance(act, dict):
            continue
        if name == target:
            return inside
        looping = inside or str(act.get("type") or "").lower() in ("foreach", "until")
        for sub in [act.get("actions"), (act.get("else") or {}).get("actions"),
                    (act.get("default") or {}).get("actions")] + \
                   [c.get("actions") for c in (act.get("cases") or {}).values()
                    if isinstance(c, dict)]:
            if sub and _in_loop(sub, target, looping):
                return True
    return False


# --- Canvas apps -------------------------------------------------------------

def _strip_calls(formula: str, names: tuple) -> str:
    """The formula with every call to one of names removed, arguments and all."""
    out, i = [], 0
    pattern = re.compile(r"\b(" + "|".join(names) + r")\s*\(")
    while True:
        m = pattern.search(formula, i)
        if not m:
            out.append(formula[i:])
            return "".join(out)
        out.append(formula[i:m.start()])
        depth, j, quote = 1, m.end(), None
        while j < len(formula) and depth:
            ch = formula[j]
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            j += 1
        i = j


# Text(value, "format") of a date or number cannot carry markup.
_FORMATTED = re.compile(r"\bText\s*\(\s*([^,()]+(?:\([^()]*\))?)\s*,\s*\"[^\"]*\"\s*\)")


# A column named for a date or time (Due Date, Created, Modified, StartTime)
# holds a date, and a date cannot carry markup.  'Created By' is a person, and
# its .DisplayName is text, so only the last part of the reference counts.
_DATEISH = re.compile(r"\.(?:'[^']*\b(?:date|time)'|\w*(?:Date|Time)|Created|Modified|"
                      r"'Created'|'Modified')$", re.I)


def check_canvas(root_dir: str, path: str, text: str) -> list:
    rel = _rel(root_dir, path)
    lines = text.split("\n")
    hits = []
    for index, line in enumerate(lines):
        m = HTMLTEXT.match(line)
        if not m:
            continue
        indent = len(m.group(1))
        block = [m.group(2)]
        for nxt in lines[index + 1:index + 400]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            block.append(nxt)
        formula = "\n".join(block).strip()
        if formula.startswith("|") or formula.startswith(">"):
            formula = formula[1:].lstrip("-+").strip()
        if not formula.startswith("="):
            continue
        bare = _strip_calls(formula, ("EncodeHTML", "PlainText", "EncodeUrl"))
        bare = _FORMATTED.sub("", bare)
        # Text inside string literals is markup, not data.
        bare = re.sub(r"\"(?:[^\"]|\"\")*\"", "\"\"", bare)
        refs = sorted({r.group(0).rstrip("( ") for r in FX_DATA.finditer(bare)
                       if not _DATEISH.search(r.group(0))})
        if not refs or not FX_JOIN.search(bare):
            continue
        control = ""
        for back in range(index - 1, max(-1, index - 12), -1):
            c = re.match(r"^\s*-?\s*['\"]?([^:'\"]+?)['\"]?\s*:\s*$", lines[back])
            if c and c.group(1) not in ("Properties", "Children"):
                control = c.group(1).strip()
                break
        hits.append({
            "rule": "canvas-htmltext-unencoded", "severity": "low", "cwe": "79",
            "file": rel, "line": index + 1,
            "title": "HTML text control built from data without EncodeHTML",
            "message": (f"HtmlText of {control or 'an HTML text control'} joins "
                        f"{', '.join(refs[:5])} into markup without EncodeHTML.  The "
                        "control renders links and formatting, so a value somebody else "
                        "wrote (a list item, a person's display name, a URL parameter) "
                        "can put a link or image in front of every user.  Wrap each "
                        "value in EncodeHTML()."),
            "matched": f"{control} HtmlText {' '.join(refs[:8])}"})
    return hits


# --- driver ------------------------------------------------------------------

def check(root_dir: str) -> list:
    paths = list(_walk(root_dir))
    hits = []
    for site in _site_dirs(root_dir, paths):
        hits += check_site(root_dir, site)
    for path in paths:
        low = path.lower()
        if low.endswith((".pa.yaml", ".fx.yaml")):
            text = _read(path)
            if text and "HtmlText" in text:
                hits += check_canvas(root_dir, path, text)
        elif low.endswith(".json"):
            text = _read(path)
            if not text or '"triggers"' not in text:
                continue
            definition = _flow_definition(text)
            if definition is not None:
                hits += check_flow(root_dir, path, text, definition)
    return hits


def main(argv) -> int:
    root_dir, repo, branch, web, link = argv[1:6]
    link = json.loads(link or "{}")
    out = []
    for hit in check(root_dir):
        url = ""
        if web and branch:
            url = (f"{web}/{repo}/{link.get('blob', 'blob')}/{branch}/{hit['file']}"
                   f"{link.get('line', '#L')}{hit['line']}")
        org, _, name = repo.partition("/")
        out.append({
            "organization": org, "repository": repo, "repository_name": name,
            "branch": branch, "source": "powerplatform-check",
            "category": "code_vulnerability", "finding_type": "static_analysis",
            "rule_id": "powerplatform." + hit["rule"],
            "rule_name": "powerplatform." + hit["rule"],
            "title": hit["title"], "message": hit["message"],
            "file": hit["file"], "start_line": hit["line"], "end_line": hit["line"],
            "start_column": 0, "end_column": 0, "matched": hit["matched"],
            "severity": hit["severity"], "engine_severity": hit["severity"],
            "confidence": "high", "impact": "unknown", "likelihood": "unknown",
            "cwe": ["CWE-" + hit["cwe"]], "cwe_ids": [hit["cwe"]],
            "owasp": [], "technology": ["power-platform"], "references": [],
            "fix": None, "commit": "", "commit_url": "",
            "author_name": "", "author_email": "", "committed_at": "",
            "triage": "review", "triage_reason": "", "triage_rule": "",
            "url": url, "state": "open"})
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
