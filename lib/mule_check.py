"""Read Mule flows for the problems no other engine here can see.

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
SECRET_PARAM = re.compile(
    r"attributes\s*\.\s*queryParams\s*\.\s*\.?\s*['\"]?"
    r"(pass(?:word|wd)?|pwd|secret|client_?secret|token|access_?token|"
    r"api_?key|apikey|key)\b", re.I)

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
}

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


def tainted_vars(flows: list) -> set:
    """Variables set from the request, directly or from another such variable."""
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
            if REQUEST.search(value) or any(v in names for v in VAR.findall(value)):
                names.add(name)
                changed = True
    return names


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

    hits = []
    for rel, root in docs:
        for flow in (n for n in root.walk() if n.ns == CORE and n.name == "flow"):
            listener = next((c for c in flow.children
                             if c.ns == HTTP and c.name == "listener"), None)
            if listener is None:
                continue
            flows = reachable(flow, by_name)
            steps = [s for f in flows for s in f.walk()]
            where = f"{listener.attrs.get('path') or '/'}"
            fname = flow.attrs.get("name", "")

            for step in steps:
                for value in list(step.attrs.values()) + [step.text]:
                    m = SECRET_PARAM.search(value)
                    if m:
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

            if any(AUTH.search(s.name) for s in steps):
                continue
            tainted = tainted_vars(flows)
            for step in steps:
                verb = SINKS.get((prefix(step), step.name))
                if not verb:
                    continue
                values = text_of(step) + " " + " ".join(
                    text_of(c) for c in step.walk() if c is not step)
                from_request = (REQUEST.search(values)
                                or any(v in tainted for v in VAR.findall(values)))
                if not from_request:
                    continue
                gated = fname in gateway_flows
                hits.append(dict(
                    rule="http-listener-unauthenticated-sink",
                    file=flow_file.get(id(_owner(step, flows)), rel), line=step.line,
                    severity="low" if gated else "high", cwe="306",
                    title=(f"{where} {verb} using caller input"
                           + (", behind an API gateway policy the code cannot show"
                              if gated else " with no login check")),
                    message=(
                        f"The flow {fname} is started by an HTTP listener at {where} "
                        f"and {verb} with values taken from the request.  No security "
                        "filter or token validation appears in the flow or anything "
                        "it calls" + (
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
