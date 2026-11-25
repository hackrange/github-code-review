r"""Read Mule flows for the problems no other engine here can see.

A Mule application is mostly XML: flows, the steps in them, and the connectors
those steps use.  Semgrep has no idea what a flow is and CodeQL does not read
them at all, so on every Mule repository the code pass came back empty.  One
of them had an HTTPS endpoint that let anybody send mail through the company
relay, with the sender and recipient taken from the query string, and nothing
in the scan said so.

Three rules, each a fact about the XML rather than a guess:

  mule.http-listener-unauthenticated-sink
      A flow started by an HTTP listener, with no security filter in it, where
      something the caller sent (query string, URI parameters, headers) reaches
      a step that acts on the world: sending mail, a database statement, an
      outbound request, a file write.  Followed through flow-ref, and through
      variables set from the request.  A listener with nothing behind it, such
      as a health check, is not reported.  One that an API gateway
      autodiscovery names may have a policy in front of it that the code
      cannot show, so it is reported low and says so.

  mule.credential-in-query-string
      A password, secret, token or key read out of the query string.  URLs end
      up in proxy, gateway and access logs.

  mule.smtp-login-without-tls
      A plain smtp-config that logs in with a password and asks for no
      STARTTLS, so the password can cross the network in the clear.

  mule.http-listener-runs-writes-unauthenticated
      A listener flow with no login check and no gateway policy that reaches a
      step which writes or removes data (a database write, a Salesforce bulk
      job, clearing a store), whatever the caller sends.  Anyone who can reach
      the listener starts it.  One report per listener.

  mule.sql-built-from-request
      A database step whose SQL is built by joining in something the caller
      sent (query string, URI parameters, headers, the body, or a variable set
      from one of them).  Reported whether or not the flow asks for a login:
      a signed in caller injects SQL as easily as an anonymous one.

An APIkit application keeps almost all of its logic in the flows its router
dispatches to, named verb:\path:config, not in the flow with the listener.
Each of those is read as its own entry point, at the listener's path plus its
own, inheriting whatever login check and gateway policy the listener's flow has.

Usage: mule_check.py <dir> <repository> <branch> <web base> <link parts JSON>
Prints a JSON array of code findings in the shape the other engines use.
"""

from __future__ import annotations

import json
import os
import re
import sys
import xml.parsers.expat

CORE = "http://www.mulesoft.org/schema/mule/core"
HTTP = "http://www.mulesoft.org/schema/mule/http"
EMAIL = "http://www.mulesoft.org/schema/mule/email"
GATEWAY = "http://www.mulesoft.org/schema/mule/api-gateway"

MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", "target", "vendor", ".mule", ".idea", "bin"}

# Anything the caller controls, read in DataWeave.  queryParams..host is the
# descendant selector, written the same way.
REQUEST = re.compile(r"attributes\s*\.\s*\.?\s*(queryParams|uriParams|headers|"
                     r"queryString|requestUri|requestPath|rawRequestPath)\b")
VAR = re.compile(r"\bvars\s*\.\s*([A-Za-z_][\w]*)")
# A bare "key" is how Object Store, cache and template lookups name theirs, so
# only api_key and the like count.
SECRET_PARAM = re.compile(
    r"attributes\s*\.\s*queryParams\s*\.\s*\.?\s*['\"]?"
    r"(pass(?:word|wd)?|pwd|secret|client_?secret|access_?token|auth_?token|"
    r"api_?key|apikey|private_?key)\b", re.I)
# The request body, read in DataWeave.
PAYLOAD = re.compile(r"(?<![\w.])payload\b")
# APIkit implementation flows: verb:\path[:content type]:config.
APIKIT_FLOW = re.compile(r"^(get|post|put|patch|delete|head|options):(\\[^:]*)(?::[^:]+)?:([^:]+)$",
                         re.I)
# A sub-flow named for checking the caller.  One named for getting a token is
# the application signing itself in to something else, not a check.
AUTH_FLOW = re.compile(
    r"(?i)(introspect|validat\w*[-_]?(token|jwt|access|auth|request|caller|client)|"
    r"verif\w*[-_]?(token|jwt|signature)|(authenticat|authoriz)\w*[-_]?(sub)?flow|"
    r"check[-_]?(token|auth|jwt)|(token|jwt)[-_]?(validat|verif)\w*)")
NOT_AUTH_FLOW = re.compile(r"(?i)(^|[-_])(get|obtain|request|generate|fetch|refresh|issue|mint)[-_]")
# A listener for signing in or getting a token is public by design, and the
# request it makes is the sign in itself.
LOGIN_PATH = re.compile(r"(?i)(^|/)(login|logon|logout|signin|signout|\w*token|oauth\w*|authorize|callback)(/|$)")
# SQL text joined together in an expression.
SQL_JOIN = re.compile(r"#\[.*(\+\+|\$\().*", re.S)
SQL_WORDS = re.compile(r"(?i)\b(select|insert|update|delete|where|order\s+by|call|exec|values)\b")

# Steps that act on something outside the application, by namespace suffix and
# local name.  A missing auth check in front of one of these is the finding.
SINKS = {
    ("email", "send"): "sends mail",
    ("db", "select"): "runs a database query",
    ("db", "insert"): "writes to the database",
    ("db", "update"): "writes to the database",
    ("db", "delete"): "deletes from the database",
    ("db", "bulk-insert"): "writes to the database",
    ("db", "bulk-update"): "writes to the database",
    ("db", "bulk-delete"): "deletes from the database",
    ("db", "execute-ddl"): "changes the database schema",
    ("db", "execute-script"): "runs a database script",
    ("db", "stored-procedure"): "runs a stored procedure",
    ("http", "request"): "makes an outbound request",
    ("file", "write"): "writes a file",
    ("sftp", "write"): "writes a file",
    ("ftp", "write"): "writes a file",
    ("os", "store"): "writes to an object store",
    ("os", "remove"): "removes from an object store",
    ("os", "clear"): "clears an object store",
    ("os", "retrieve-all"): "reads every entry of an object store",
    ("salesforce", "create"): "creates Salesforce records",
    ("salesforce", "update"): "updates Salesforce records",
    ("salesforce", "upsert"): "writes Salesforce records",
    ("salesforce", "delete"): "deletes Salesforce records",
    ("salesforce", "query"): "queries Salesforce",
    ("salesforce", "create-job-bulk-api-v2"): "starts a Salesforce bulk job",
    ("s3", "put-object"): "writes to S3",
    ("s3", "delete-object"): "deletes from S3",
    ("s3", "get-object"): "reads from S3",
    ("sns", "publish"): "publishes a notification",
    ("sqs", "send-message"): "queues a message",
    ("jms", "publish"): "publishes a message",
    ("anypoint-mq", "publish"): "publishes a message",
    ("as400", "program-call-processor"): "calls a host program",
    ("as400", "command-call-processor"): "runs a host command",
}
# Steps that change or remove something.  Started by anybody who can reach a
# listener with no login check, these matter whether or not the caller says
# what to change: a bulk sync or a clear runs all the same.
WRITES = {("db", n) for n in ("insert", "update", "delete", "bulk-insert", "bulk-update",
                              "bulk-delete", "execute-script", "execute-ddl", "stored-procedure")} | {
    ("salesforce", n) for n in ("create", "update", "upsert", "delete", "create-job-bulk-api-v2",
                                "create-job", "create-batch")} | {
    ("os", "clear"), ("os", "remove"), ("s3", "delete-object"), ("s3", "put-object"),
    ("as400", "command-call-processor"), ("as400", "program-call-processor")}
DB_STEPS = {"select", "insert", "update", "delete", "bulk-insert", "bulk-update",
            "bulk-delete", "execute-script", "stored-procedure", "execute-ddl"}

LITERAL_SECRET = re.compile(
    r"""((?:pass(?:word|wd)?|pwd|secret|token|key)\w*\s*=\s*["'])(?!\$\{|!\[)[^"']+(["'])""",
    re.I)

# Local names that put an authentication or authorization step in a flow.
AUTH = re.compile(r"(security-filter|authorization-filter|authentication-filter|"
                  r"validate-token|validate-jwt|jwt-validat|basic-auth|oauth)", re.I)


class Node:
    __slots__ = ("ns", "name", "attrs", "line", "children", "parent", "text")

    def __init__(self, ns, name, attrs, line, parent):
        self.ns, self.name, self.attrs = ns, name, attrs
        self.line, self.children, self.parent = line, [], parent
        self.text = ""

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


def parse(path: str):
    """-> the root Node, or None.  expat keeps line numbers, which etree drops."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_BYTES or b"mulesoft.org/schema/mule/core" not in data:
        return None
    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    # A flow file has no business declaring entities, and expanding them is
    # how a hostile XML file eats memory.
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    root = [None]
    stack = []

    def entity_decl(*_):
        raise ValueError("entity declarations are not read")

    def start(tag, attrs):
        ns, _, name = tag.rpartition(" ")
        node = Node(ns, name, {k.rpartition(" ")[2]: v for k, v in attrs.items()},
                    parser.CurrentLineNumber, stack[-1] if stack else None)
        if stack:
            stack[-1].children.append(node)
        else:
            root[0] = node
        stack.append(node)

    def end(_tag):
        stack.pop()

    # A query lives in the element's text, <db:sql>SELECT ...</db:sql>, not in
    # an attribute.
    def chars(data):
        if stack and len(stack[-1].text) < 20_000:
            stack[-1].text += data

    parser.EntityDeclHandler = entity_decl
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(data, True)
    except (xml.parsers.expat.ExpatError, ValueError, RecursionError):
        return None
    return root[0]


def prefix(node) -> str:
    """The connector a namespace belongs to: .../schema/mule/email -> email."""
    return node.ns.rstrip("/").rpartition("/")[2]


def text_of(node) -> str:
    return " ".join(list(node.attrs.values()) + [node.text])


def mule_files(root_dir: str):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = os.path.relpath(dirpath, root_dir).replace(os.sep, "/")
        # Tests drive the flows on purpose.  They are not the application.
        if re.search(r"(^|/)src/test(/|$)", rel_dir):
            continue
        for filename in sorted(filenames):
            if filename.endswith(".xml"):
                path = os.path.join(dirpath, filename)
                if not os.path.islink(path):
                    yield os.path.relpath(path, root_dir).replace(os.sep, "/"), path


def tainted_vars(flows: list, early: set = frozenset()) -> set:
    """Variables set from the request, directly or from another such variable.

    early is the steps that run while payload is still the request body, where
    a variable set from payload is set from the caller."""
    names = set()
    sets = [n for flow in flows for n in flow.walk()
            if n.name == "set-variable" and n.attrs.get("variableName")]
    changed = True
    while changed:
        changed = False
        for node in sets:
            name = node.attrs["variableName"]
            if name in names:
                continue
            value = text_of(node)
            if (REQUEST.search(value) or any(v in names for v in VAR.findall(value))
                    or (id(node) in early and PAYLOAD.search(value))):
                names.add(name)
                changed = True
    return names


def _replaces_payload(step) -> bool:
    """Whether a step leaves something other than the request in payload."""
    if prefix(step) in ("db", "salesforce", "s3", "os", "sqs", "as400", "ftp", "sftp", "file") \
            or (prefix(step) == "http" and step.name == "request"):
        return True
    if step.name == "set-payload":
        return not PAYLOAD.search(text_of(step))
    if step.name == "transform":
        message = [c for c in step.walk() if c.name == "set-payload"]
        return bool(message) and not any(PAYLOAD.search(text_of(c)) or REQUEST.search(text_of(c))
                                         for c in message)
    return False


def early_steps(flow, by_name: dict, depth: int = 3, tainted: set = frozenset()) -> set:
    """Ids of the steps that run while payload holds what the caller sent.

    payload starts as the request body.  A connector replaces it with its own
    result; a transform or set-payload that builds it from the body, the
    request's attributes or a variable set from them makes it the caller's
    again, which is how a flow carries request values into a payload and then
    into SQL.  Follows flow-ref."""
    out, state = set(), [True]

    def caller_built(node) -> bool:
        text = " ".join(text_of(c) for c in node.walk() if c.name == "set-payload") or text_of(node)
        return bool(REQUEST.search(text) or any(v in tainted for v in VAR.findall(text))
                    or (state[0] and PAYLOAD.search(text)))

    def visit(node, level):
        for child in node.children:
            if child.name == "flow-ref" and level < depth:
                target = by_name.get(child.attrs.get("name", ""))
                if target is not None:
                    visit(target, level + 1)
                continue
            if state[0]:
                for d in child.walk():
                    out.add(id(d))
            sets_payload = child.name == "set-payload" or (
                child.name == "transform" and any(c.name == "set-payload" for c in child.walk()))
            if sets_payload:
                state[0] = caller_built(child)
                if state[0]:
                    for d in child.walk():
                        out.add(id(d))
            elif _replaces_payload(child):
                state[0] = False

    visit(flow, 0)
    return out


def reachable(flow, by_name: dict, depth: int = 4) -> list:
    """The flow and every flow or sub-flow it reaches through flow-ref."""
    seen, out, todo = set(), [], [(flow, 0)]
    while todo:
        node, level = todo.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        out.append(node)
        if level >= depth:
            continue
        for step in node.walk():
            if step.name == "flow-ref":
                target = by_name.get(step.attrs.get("name", ""))
                if target is not None:
                    todo.append((target, level + 1))
    return out


def check(root_dir: str) -> list:
    docs, lines = [], {}
    for rel, path in mule_files(root_dir):
        root = parse(path)
        if root is not None and root.ns == CORE and root.name == "mule":
            docs.append((rel, root))
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines[rel] = handle.read(MAX_BYTES).splitlines()

    by_name, flow_file = {}, {}
    gateway_flows, gateway_any = set(), False
    for rel, root in docs:
        for node in root.walk():
            if node.ns == CORE and node.name in ("flow", "sub-flow") and node.attrs.get("name"):
                by_name[node.attrs["name"]] = node
                flow_file[id(node)] = rel
            if node.ns == GATEWAY and node.name == "autodiscovery":
                gateway_any = True
                if node.attrs.get("flowRef"):
                    gateway_flows.add(node.attrs["flowRef"])

    # APIkit: the router in a listener's flow dispatches to the flows named
    # verb:\path:config.  Each is an entry point of its own.
    apikit = {}
    for name, node in by_name.items():
        m = APIKIT_FLOW.match(name)
        if m and node.name == "flow":
            path = re.sub(r"\(([^)]*)\)", r"{\1}", m.group(2).replace("\\", "/"))
            apikit.setdefault(m.group(3), []).append((m.group(1).upper(), path, node))

    entries = []
    for rel, root in docs:
        for flow in (n for n in root.walk() if n.ns == CORE and n.name == "flow"):
            listener = next((c for c in flow.children
                             if c.ns == HTTP and c.name == "listener"), None)
            if listener is None:
                continue
            base = listener.attrs.get("path") or "/"
            fname = flow.attrs.get("name", "")
            entries.append((flow, base, fname, fname, []))
            routers = [s for s in flow.walk() if s.name == "router" and prefix(s) in ("apikit", "mule-apikit")]
            for router in routers:
                for verb, path, impl in apikit.get(router.attrs.get("config-ref", ""), []):
                    where = (base.rstrip("/*") + path) if base.endswith("*") else base + path
                    # What the listener's flow does before the router runs
                    # (a login check) covers the implementation too.
                    entries.append((impl, f"{verb} {where}", impl.attrs.get("name", ""),
                                    fname, reachable(flow, by_name)))

    hits, reported = [], set()
    for flow, where, fname, gate_name, inherited in entries:
        flows = reachable(flow, by_name)
        steps = [s for f in flows for s in f.walk()]
        guard_steps = steps + [s for f in inherited for s in f.walk()]
        rel = flow_file.get(id(flow), "")

        for step in steps:
            for value in list(step.attrs.values()) + [step.text]:
                m = SECRET_PARAM.search(value)
                if m and ("credential", id(step)) not in reported:
                    reported.add(("credential", id(step)))
                    hits.append(dict(
                        rule="credential-in-query-string", file=flow_file.get(
                            id(_owner(step, flows)), rel), line=step.line,
                        severity="medium", cwe="598",
                        title=f"A {m.group(1).lower()} is read from the query string",
                        message=(f"The flow {fname} reads {m.group(1)} from the query "
                                 f"string of {where}.  Query strings end up in proxy, "
                                 "gateway and access logs.  Credentials belong in a "
                                 "header or the body, or in secure properties.")))
                    break

        # Two rounds: a variable set from payload can make payload the
        # caller's again further down, and that widens what counts as early.
        early = early_steps(flow, by_name)
        tainted = tainted_vars(flows, early)
        early = early_steps(flow, by_name, tainted=tainted)
        tainted = tainted_vars(flows, early)

        def from_caller(step):
            values = text_of(step) + " " + " ".join(
                text_of(c) for c in step.walk() if c is not step)
            return (REQUEST.search(values)
                    or any(v in tainted for v in VAR.findall(values))
                    or (id(step) in early and PAYLOAD.search(values)))

        # SQL joined from what the caller sent, login or not.
        for step in steps:
            if prefix(step) != "db" or step.name not in DB_STEPS:
                continue
            sql_nodes = [c for c in step.walk() if c.name == "sql"]
            sql = " ".join(c.text for c in sql_nodes) or step.attrs.get("sql", "")
            joined = bool(SQL_JOIN.search(sql))
            via = [v for v in VAR.findall(sql) if v in tainted]
            built_at = next((c for c in sql_nodes if SQL_JOIN.search(c.text or "")), step)
            if not joined and re.fullmatch(r"\s*#\[\s*payload\s*\]\s*", sql or ""):
                # #[payload]: the statement was put in payload by a transform
                # before this step, out of what the caller sent.
                built = [n for f in flows for n in f.walk() if n.name == "set-payload"
                         and SQL_WORDS.search(text_of(n))
                         and re.search(r"\+\+|\$\(|\breplace\b", text_of(n))
                         and (REQUEST.search(text_of(n))
                              or any(v in tainted for v in VAR.findall(text_of(n))))]
                if built:
                    joined, via, built_at = True, ["payload"], built[0]
            if not joined and via:
                # #[vars.query]: the SQL was put together where the variable was set.
                built = [n for f in flows for n in f.walk()
                         if n.name == "set-variable" and n.attrs.get("variableName") in via]
                built = [n for n in built if SQL_WORDS.search(text_of(n)) and "++" in text_of(n)]
                joined = bool(built)
                if built:
                    built_at = built[0]
            if not joined or ("sql", id(step)) in reported \
                    or ("sql-at", id(built_at)) in reported:
                continue
            caller = (REQUEST.search(sql) or via
                      or (id(step) in early and PAYLOAD.search(sql)))
            if not caller:
                continue
            reported.add(("sql", id(step)))
            reported.add(("sql-at", id(built_at)))
            run_at = f"{flow_file.get(id(_owner(step, flows)), rel)} line {step.line}"
            hits.append(dict(
                rule="sql-built-from-request",
                file=flow_file.get(id(_owner(built_at, flows)), rel), line=_join_line(built_at),
                severity="high", cwe="89",
                title=f"{where} builds SQL from caller input",
                message=(f"The flow {fname} runs SQL put together by joining in values the "
                         "caller sent (the query string, URI parameters, headers or the "
                         "body, directly or through a variable), and runs it at " + run_at + ".  "
                         "A value with a quote in it "
                         "changes the statement, and anyone who can call the API, signed in "
                         "or not, reads or changes other rows.  Use db:input-parameters with "
                         ":name binds, and allow list any column name that must be in the "
                         "text.")))

        if any(AUTH.search(s.name) for s in guard_steps):
            continue
        if any(s.name == "flow-ref" and AUTH_FLOW.search(s.attrs.get("name", ""))
               and not NOT_AUTH_FLOW.search(s.attrs.get("name", "")) for s in guard_steps):
            continue
        # Signing in and getting a token are public by design, and what they
        # store or call is the sign in itself.  The SQL rule above still reads them.
        if LOGIN_PATH.search(where.split(" ")[-1]):
            continue
        writes = [s for s in steps if (prefix(s), s.name) in WRITES]
        if writes and gate_name not in gateway_flows and not inherited \
                and not any(from_caller(w) for w in writes):
            first = writes[0]
            hits.append(dict(
                rule="http-listener-runs-writes-unauthenticated",
                file=rel, line=next((c.line for c in flow.children
                                     if c.ns == HTTP and c.name == "listener"), flow.line),
                severity="medium", cwe="306",
                title=f"{where} {SINKS.get((prefix(first), first.name), 'writes data')} for anyone who calls it, with no login check",
                message=(f"The flow {fname} is started by an HTTP listener at {where} with no "
                         "security filter, token check or API gateway policy, and it reaches "
                         f"{len(writes)} step(s) that write or remove data (the first in "
                         f"{flow_file.get(id(_owner(first, flows)), rel)} at line {first.line}).  "
                         "Anyone who can reach the listener starts the job, and can start it "
                         "again and again.  Put it behind the API's policy, require a token, "
                         "or move it to a scheduler.")))
        for step in steps:
            verb = SINKS.get((prefix(step), step.name))
            if not verb or ("open", id(step)) in reported:
                continue
            if not from_caller(step):
                continue
            reported.add(("open", id(step)))
            gated = gate_name in gateway_flows
            hits.append(dict(
                rule="http-listener-unauthenticated-sink",
                file=flow_file.get(id(_owner(step, flows)), rel), line=step.line,
                severity="low" if gated else "high", cwe="306",
                title=(f"{where} {verb} using caller input"
                       + (", behind an API gateway policy the code cannot show"
                          if gated else " with no login check")),
                message=(
                    f"The flow {fname} is reached from an HTTP listener at {where} "
                    f"and {verb} with values taken from the request.  No security "
                    "filter or token validation appears in the flow, anything "
                    "it calls, or the listener's flow in front of it" + (
                        ".  An API gateway autodiscovery names this flow, so a policy "
                        "applied in Anypoint may require a login.  Confirm one does."
                        if gated else (
                            ".  This app registers an API gateway autodiscovery, but "
                            "not for this flow." if gateway_any else
                            ", and nothing registers it with an API gateway."))
                    + "  Anyone who can reach the listener can make it act.")))
            break

    for rel, root in docs:
        for config in (n for n in root.walk() if n.ns == EMAIL and n.name == "smtp-config"):
            conn = next((c for c in config.walk() if c.name == "smtp-connection"), None)
            if conn is None or not conn.attrs.get("password"):
                continue
            props = " ".join(text_of(c) for c in config.walk())
            if re.search(r"starttls", props, re.I):
                continue
            hits.append(dict(
                rule="smtp-login-without-tls", file=rel, line=conn.line,
                severity="medium", cwe="319",
                title="The mail connection logs in without TLS",
                message=(f"The SMTP connection in {config.attrs.get('name', 'smtp-config')} "
                         "sends a user name and password and asks for no STARTTLS, so "
                         "the login can cross the network in the clear.  Use smtps-config, "
                         "or set mail.smtp.starttls.enable and require it.")))
    # The line's own text is what ingest keys a code finding on, so a waiver
    # survives the flow being moved down a few lines.  It goes into the report
    # file, so a literal secret in it is masked.  A ${...} reference is not one.
    for hit in hits:
        text = lines.get(hit["file"], [])
        line = text[hit["line"] - 1].strip()[:300] if 0 < hit["line"] <= len(text) else ""
        hit["matched"] = LITERAL_SECRET.sub(r"\1****\2", line)
    return hits


def _join_line(node) -> int:
    """The line inside a node's text where SQL is first joined to a value,
    which is where a pattern engine reports the same thing and where the fix
    goes.  The node's own line when the text gives no better answer."""
    text = node.text or ""
    at = text.find("++")
    if at < 0:
        at = text.find("$(")
    if at < 0:
        return node.line
    # The element's text starts on its own line, after the tag and CDATA.
    return node.line + text[:at].count("\n")


def _owner(step, flows):
    """The flow a step sits in, so a finding names the right file."""
    node = step
    while node is not None and node not in flows:
        node = node.parent
    return node if node is not None else flows[0]


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
            "branch": branch, "source": "mule-check",
            "category": "code_vulnerability", "finding_type": "static_analysis",
            "rule_id": "mule." + hit["rule"], "rule_name": "mule." + hit["rule"],
            "title": hit["title"], "message": hit["message"],
            "file": hit["file"], "start_line": hit["line"], "end_line": hit["line"],
            "start_column": 0, "end_column": 0, "matched": hit["matched"],
            "severity": hit["severity"], "engine_severity": hit["severity"],
            "confidence": "high", "impact": "unknown", "likelihood": "unknown",
            "cwe": ["CWE-" + hit["cwe"]], "cwe_ids": [hit["cwe"]],
            "owasp": [], "technology": ["mule"], "references": [],
            "fix": None, "commit": "", "commit_url": "",
            "author_name": "", "author_email": "", "committed_at": "",
            "triage": "review", "triage_reason": "", "triage_rule": "",
            "url": url, "state": "open"})
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
