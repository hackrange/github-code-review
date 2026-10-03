"""Decide whether a code finding is worth a person's attention.

Semgrep matches a pattern on a line.  It cannot see that the line sits in a
JSON endpoint, or in a theme somebody bought, or that the value was cast to an
integer three characters earlier.  So it reports all of them the same way, and
a developer who opens three false positives in a row stops opening the fourth.

This runs after semgrep, with the clone still on disk, and answers the question
semgrep could not: given where this line lives and what it actually does, is
this a finding?

Two rules it follows:

  Nothing is deleted.  Every finding comes out the other side carrying a
  verdict and the reason for it, so somebody can disagree.  A filter you cannot
  inspect is not trustworthy either.

  When unsure, keep.  A false positive costs a developer a minute.  A missed
  finding costs something else entirely, so every rule here has to be a fact
  about the code rather than a guess about intent.
"""

from __future__ import annotations

import collections
import json
import math
import os
import re
import sys

# Verdicts, worst first.
REVIEW = "review"            # a person should look
THIRD_PARTY = "third_party"  # real, but not in code this team wrote
NOT_APPLICABLE = "not_applicable"   # provably not what the rule is looking for

# --- where the code came from ------------------------------------------------

THIRD_PARTY_PATHS = [
    (r"(^|/)(vendor|node_modules|third_party|bower_components)(/|$)", "a dependency directory"),
    (r"(^|/)(dist|build|out)(/|$)",                                   "a build output directory"),
    (r"(^|/)app/template/",                                           "a bought or generated template kit"),
    (r"phpmailer|swiftmailer|tcpdf|fpdf|jquery|bootstrap",            "a vendored library"),
    (r"\.min\.(js|css)$",                                             "a minified asset"),
    (r"(^|/)(tests?|spec|fixtures?|__tests__)(/|$)",                  "test material"),
    # Python packaging and the Splunk add-on layout.  An add-on built with the
    # Add-on Builder ships its whole runtime inside bin/, so the vendored code
    # outnumbers the written code several times over.
    (r"(^|/)site-packages(/|$)",                                      "an installed dependency"),
    (r"(^|/)aob_py[23](/|$)",                                         "the Splunk Add-on Builder's bundled runtime"),
    (r"(^|/)splunklib(/|$)",                                          "the vendored Splunk SDK"),
    (r"(^|/)bin/(urllib3|requests|certifi|chardet|idna|six|yaml)(/|$)", "a vendored library"),
    # A Splunk lookup backup is captured data, not source.
    (r"(^|/)lookup_file_backups(/|$)",                                "a Splunk lookup backup"),
    (r"[.-](bundle|pack)\.js$",                                       "a bundled asset"),
    (r"-min\.(js|css)$",                                              "a minified asset"),
]

# --- what the matched expression does ----------------------------------------

# Casting to a number destroys markup: there is no XSS in an integer.
NUMERIC = re.compile(r"\(\s*(?:int|integer|float|double|bool)\s*\)|"
                     r"\b(?:intval|floatval|doubleval|boolval|count|number_format)\s*\(")
# Output escaping, including the short helper this codebase uses.
ESCAPED = re.compile(r"\b(?:htmlspecialchars|htmlentities|esc_html|esc_attr|strip_tags)\s*\(|"
                     r"^echo\s+e\s*\(")
# Functions whose return value cannot carry markup.
# date is gone from this list on purpose.  It was cleared whatever its format
# string was, and a format taken from the request emits any character you like,
# because every literal in a format is written by escaping it.  A literal format
# is handled where the rest of the escaping is.  min and max are gone for the
# same kind of reason: given strings they return a string, not a number.
# semgrep reports the whole statement on some matches and only the expression
# on others, so nothing here may require the echo to be present.
OUTPUT_PREFIX = r"^(?:<\?=\s*|<\?php\s+echo\s+|echo\s+|print\s+)?"
SAFE_RETURN = re.compile(OUTPUT_PREFIX + r"(?:strtotime|time|round|abs|strlen|"
                         r"sizeof|number_format|json_last_error)\s*\(")
JSON_OUT = re.compile(OUTPUT_PREFIX + r"json_encode\b")

# --- what the surrounding file is --------------------------------------------

JSON_HEADER = re.compile(r"""header\s*\(\s*['"]\s*Content-Type\s*:\s*application/json""", re.I)
# Content-Type is often built from a variable on a download endpoint, so the
# disposition is the reliable half.
DOWNLOAD_HEADER = re.compile(r"""header\s*\(\s*['"]\s*Content-Disposition\s*:|"""
                             r"""header\s*\(\s*['"]\s*Content-Type\s*:\s*"""
                             r"""(?:application/(?:pdf|octet-stream|zip|vnd)|image/|text/csv)""", re.I)

# Markup anywhere in the file means it can render as a page, whatever headers
# some other branch of it sets.
HTML_MARKUP = re.compile(r"<!DOCTYPE|<html\b|<body\b|<div\b|<table\b|<span\b|<form\b|<a\s+href", re.I)


def _header_before(source: str, pattern, line: int) -> bool:
    """Is that header set before this line, in a file that emits no markup?

    Checking the whole file was wrong in both directions.  One page here has a
    CSV export branch at line 41 and an HTML listing at line 407: the header is
    real, the suppression would not have been.  And a genuine download endpoint
    was missed because its content type came from a variable.

    So: the header has to come first, and the file has to be one that never
    renders a page at all.
    """
    if HTML_MARKUP.search(source):
        return False
    for number, text in enumerate(source.splitlines(), start=1):
        if number >= line:
            break
        if pattern.search(text):
            return True
    return False

# Rules whose whole premise is "this reaches an HTML page".
XSS_FAMILY = {"echoed-request", "var-in-href", "template-and-attributes",
              "explicit-unescape-with-markup", "template-explicit-unescape",
              "html-magic-method", "direct-use-of-superglobal"}

# --- Python ------------------------------------------------------------------

# eval/exec on nothing but a string literal has no input to inject.  The danger
# in eval is the argument, so an argument that cannot vary is not the danger.
PY_LITERAL_CALL = re.compile(
    r"^(?:eval|exec)\s*\(\s*(?P<q>['\"])(?:(?!(?P=q)).)*(?P=q)\s*\)\s*$", re.S)

# --- JavaScript --------------------------------------------------------------

# The rule is called non-literal-regexp.  When the argument is a literal, the
# rule matched the thing it exists to rule out.
JS_LITERAL_REGEXP = re.compile(
    r"(?:new\s+)?RegExp\s*\(\s*(?P<q>['\"])(?:(?!(?P=q)).)*(?P=q)"
    r"\s*(?:,\s*(?P<f>['\"])[gimsuy]*(?P=f)\s*)?\)", re.S)

# --- GitHub Actions ----------------------------------------------------------

ACTIONS_EXPR = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")


def _input_is_choice(source: str, name: str) -> bool:
    """Is that workflow_dispatch input declared `type: choice`?

    GitHub validates a choice input against its options list when the workflow
    is dispatched and rejects anything else, so the value cannot be arbitrary.
    That is a fact about the trigger, not a guess about the caller.
    """
    lines = source.splitlines()
    for index, text in enumerate(lines):
        match = re.match(r"^(\s+)" + re.escape(name) + r"\s*:\s*$", text)
        if not match:
            continue
        indent = len(match.group(1))
        # It has to sit under an inputs: block, not merely share its name with
        # a job or a step somewhere else in the file.
        under_inputs = False
        for above in reversed(lines[:index]):
            if not above.strip():
                continue
            lead = len(above) - len(above.lstrip())
            if lead < indent:
                under_inputs = re.match(r"\s*inputs\s*:\s*$", above) is not None
                break
        if not under_inputs:
            continue
        for follow in lines[index + 1:]:
            if not follow.strip():
                continue
            if len(follow) - len(follow.lstrip()) <= indent:
                break
            if re.match(r"\s*type\s*:\s*choice\s*$", follow):
                return True
    return False


def _env_is_literal(source: str, name: str) -> bool:
    """Is that env name defined, and never from an expression?

    One dynamic definition anywhere is enough to disqualify it: the step we are
    judging cannot know which one it got.
    """
    seen = False
    for text in source.splitlines():
        match = re.match(r"^\s*" + re.escape(name) + r"\s*:\s*(\S.*)$", text)
        if match:
            seen = True
            if "${{" in match.group(1):
                return False
    return seen


def _expression_is_fixed(expression: str, source: str) -> bool:
    """Can this ${{ ... }} carry something an attacker chose?"""
    expression = expression.strip()
    match = re.fullmatch(r"(?:github\.event\.)?inputs\.([A-Za-z0-9_-]+)", expression)
    if match:
        return _input_is_choice(source, match.group(1))
    match = re.fullmatch(r"env\.([A-Za-z0-9_-]+)", expression)
    if match:
        return _env_is_literal(source, match.group(1))
    # steps outputs, github context, secrets, vars: not provable here.
    return False


# Structure, not vocabulary.  A lone keyword catches ordinary prose: the string
# "(Select all that apply, comma-separated: ...)" is a question on a form, and
# it contains SELECT.  A statement has two halves that go together.
SQL_STATEMENT = re.compile(
    r"\bSELECT\b.*?\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b.*?\bSET\b|"
    r"\bDELETE\s+FROM\b|\bUNION\s+(?:ALL\s+)?SELECT\b|\bCREATE\s+TABLE\b|"
    r"\bALTER\s+TABLE\b|\bDROP\s+TABLE\b", re.I | re.S)


def _read(path: str) -> str:
    try:
        with open(path, errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _matched_text(source: str, finding: dict) -> str:
    """The exact expression semgrep matched, using its column offsets.

    Not the line: a line can hold an escaped call and an unescaped one at once,
    and judging the wrong half is how a filter starts lying.
    """
    lines = source.splitlines()
    start, end = finding.get("start", {}), finding.get("end", {})
    first, last = start.get("line", 0), end.get("line", 0)
    if not lines or first < 1 or first > len(lines):
        return ""
    if first == last:
        return lines[first - 1][start.get("col", 1) - 1:end.get("col", 1) - 1]
    parts = [lines[first - 1][start.get("col", 1) - 1:]]
    parts += lines[first:last - 1]
    if 0 < last <= len(lines):
        parts.append(lines[last - 1][:end.get("col", 1) - 1])
    return " ".join(part.strip() for part in parts)


ADVISORY = "advisory"        # the rule reports a pattern, not a problem

# --- credentials semgrep found, which never met the secrets triage -----------
#
# semgrep ships secret detection of its own in p/secrets, and those findings
# come out as code findings.  That means they take a different road out of the
# scan: gitleaks and trufflehog hand their hits to lib/triage.sh, which knows
# about placeholders, and semgrep's hits go nowhere near it.
#
# The result was a critical on this line:
#
#     'sk_live_' followed by thirty two x's
#
# Reported critical.  The secrets pipeline would have dropped it
# on the entropy floor, which is the thing worth copying: the placeholder word
# list alone does not catch it, because that list is anchored and this value has
# a real looking prefix on the front of the padding.
#
# So all three of the cheap tests come across, read from the same file the
# secrets side reads, rather than a second list that drifts from the first.
CREDENTIAL_RULE = re.compile(
    r"(detected[-_].*(key|token|secret|hash|password|credential)"
    r"|(api[-_]?key|access[-_]?token|client[-_]?secret|private[-_]?key))",
    re.I)



def _download_branch(source: str, line: int) -> bool:
    """A download that ends the request, inside a file that also renders a page.

    Refusing to trust a header in a file containing markup is right: one page
    has a CSV branch near the top and an HTML listing four hundred lines below,
    and the header does not cover the listing.  But a branch that sets a
    disposition, writes the bytes and then exits cannot reach that markup at
    all, and those are the real download endpoints in a mixed file.
    """
    lines = (source or "").splitlines()
    if not (1 <= line <= len(lines)):
        return False
    above = lines[max(0, line - 16):line - 1]
    if not any(DOWNLOAD_HEADER.search(text) for text in above):
        return False
    below = lines[line:line + 3]
    return any(re.match(r"\s*(?:exit|die)\s*[;(]", text) for text in below)


# --- a path that cannot leave where it was meant to go -----------------------
#
# Two facts about a line settle most of these, and neither needs to know what
# the deployment allows.  open_basedir looked like the answer and is not: on the
# repository this was worked out against, every path these findings touch is
# already inside the listed roots, so it stops a read reaching /etc and does
# nothing about the directory holding the generated administrator password.

PATH_FAMILY = ("tainted-filename", "path-traversal", "unlink-use",
               "file-inclusion", "tainted-path", "non-literal-fopen")

# A validation is only worth something if it is anchored at both ends and the
# characters it admits cannot walk anywhere.  A pattern without ^ and $ matches
# a substring, which is no restriction at all.
ANCHORED_PATH_CHECK = re.compile(
    r"""preg_match\s*\(\s*(['"])\s*[/#~]\^(?P<body>.*?)\$[/#~][a-zA-Z]*\s*\1\s*,\s*"""
    r"""(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)""", re.S)
# Anything that could step out of a directory, or end the string early.
PATH_ESCAPES = ("/", "\\\\", "..", "%", "\\0")

# [$path, $type] = $map[$key];  and  list($path, $type) = $map[$key];
DESTRUCTURE = re.compile(
    r"^\s*(?:\[|list\s*\()\s*(?P<names>[^\]\)]*?)\s*(?:\]|\))\s*=\s*(?P<rhs>.*)$")


def _regex_admits_no_path(pattern_body: str) -> bool:
    """Does this anchored pattern admit anything that can leave a directory?"""
    if not pattern_body:
        return False
    # A wildcard makes the question unanswerable, so answer no.
    if any(token in pattern_body for token in (".*", ".+", "[^", "\\s", "|")):
        return False
    classes = re.findall(r"\[([^\]]*)\]", pattern_body)
    if not classes:
        return False
    for group in classes:
        for escape in PATH_ESCAPES:
            if escape in group:
                return False
    # A literal separator outside a class is just as bad.
    outside = re.sub(r"\[[^\]]*\]", "", pattern_body)
    return not any(token in outside for token in ("/", "\\\\", ".."))


def _path_checked_before(source: str, variable: str, line: int) -> str:
    """-> the pattern that constrains this variable before the line, or "".

    Backwards from the sink, because a check written after it protects nothing.
    """
    if not source or not variable:
        return ""
    lines = source.splitlines()[:max(0, line - 1)]
    for text in reversed(lines):
        found = ANCHORED_PATH_CHECK.search(text)
        if found and found.group("var") == variable:
            if _regex_admits_no_path(found.group("body")):
                return found.group(0)[:120]
    return ""



def _path_component_safe(source: str, variable: str, line: int, hops: int = 2) -> bool:
    """Can this part of a path carry a separator into the sink?

    A check is written against the value that arrived, and the sink is built
    from it a line or two later.  Following that is the difference between the
    rule working and the rule never firing, but every part of the join has to
    be accounted for: one checked component beside one unchecked one is not a
    safe path.
    """
    if not variable or variable in SUPERGLOBALS:
        return False
    if _path_checked_before(source, variable, line):
        return True
    if hops <= 0:
        return False
    built = (_destructured_from(source, variable, line)
             or _assignment_before(source, variable, line))
    if not built or "$_" in built:
        return False
    inner = set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", built))
    if not inner:
        # Built out of literals only.
        return True
    return all(_path_component_safe(source, name, line, hops - 1)
               for name in inner)



def _from_literal_table(source: str, variable: str, line: int) -> bool:
    """Did this value come out of an array written into the source?

    The request picks which entry.  It never supplies what is in one, so a
    table holding nothing but literals cannot yield a path somebody chose.
    """
    if not variable or variable in SUPERGLOBALS:
        return False
    built = (_destructured_from(source, variable, line)
             or _assignment_before(source, variable, line))
    if not built:
        return False
    base = re.match(r"^(\$[A-Za-z_][A-Za-z0-9_]*)\s*\[", built.strip())
    if not base:
        return False
    table = _assignment_before(source, base.group(1), line)
    if not table or not LITERAL_ARRAY.match(table.strip()):
        return False
    # A table is only a table of literals if nothing in it came from anywhere.
    return "$_" not in table and not re.search(r"\$[A-Za-z_]", table)


def _destructured_from(source: str, variable: str, line: int) -> str:
    """-> what a list assignment took this variable out of, or "".

    [$path, $contentType] = $allowed[$key] is how a lookup out of a table of
    literals actually reaches a sink, and a plain assignment search misses it.
    """
    if not source or not variable:
        return ""
    for text in reversed(source.splitlines()[:max(0, line - 1)]):
        found = DESTRUCTURE.match(text)
        if not found:
            continue
        names = [n.strip() for n in found.group("names").split(",")]
        if variable in names:
            return found.group("rhs").strip().rstrip(";")
    return ""

def _shannon(value: str) -> float:
    """Bits per character.  The same measure lib/secrets.sh takes in jq."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total)
                for n in collections.Counter(value).values())


def _triage_defaults() -> dict:
    """The shipped triage defaults, or nothing if they cannot be read.

    Nothing here is worth failing a scan over.  Without the file this rule
    simply does not fire, and every credential semgrep found is reported, which
    is where it was before.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(os.path.dirname(here), "config", "triage-defaults.json")
    try:
        with open(path) as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        return {"patterns": [], "paths": [], "min_entropy": 0.0, "min_length": 0}
    patterns = []
    for pattern in doc.get("placeholder_patterns", []):
        try:
            patterns.append(re.compile(pattern))
        except re.error:
            continue
    # The same path list the credential pass uses.  Reading it here rather than
    # keeping a second copy means an administrator who adds a documentation
    # directory on the Triage rules page has it apply to both kinds of finding,
    # which is what they will assume they just did.
    paths = []
    for pattern in doc.get("placeholder_paths", []):
        try:
            paths.append(re.compile(pattern))
        except re.error:
            continue
    return {"patterns": patterns, "paths": paths,
            "min_entropy": float(doc.get("min_entropy", 0) or 0),
            "min_length": int(doc.get("min_length", 0) or 0)}


DEFAULTS = _triage_defaults()
PLACEHOLDERS = DEFAULTS["patterns"]
PLACEHOLDER_PATHS = DEFAULTS["paths"]

# The value inside the quotes, which is what the secrets side judges.  semgrep
# matches the whole assignment, and running a placeholder rule over
# "$key = 'sk_live_xxxx'" would be judging the variable name as well.
QUOTED_VALUE = re.compile(r"""['"]([^'"\n]{6,})['"]""")

# --- CodeQL, which arrives as GitHub's alerts rather than from a run here ----
#
# These rules are written against what was actually reported on a real
# repository, alert by alert, and each one only speaks on a fact it can read
# off the code.  CodeQL's own precision for all of them is high, so confidence
# alone would never have separated the wrong ones from the right ones.

# XSS rules that fired on a line writing a text node.  A text node is never
# parsed as markup, whatever is in it.
CODEQL_XSS = frozenset({"js/xss", "js/xss-through-exception",
                        "js/xss-through-dom", "js/reflected-xss",
                        "js/stored-xss"})
TEXT_SINK = re.compile(r"createTextNode\s*\(|\.textContent\s*=|\.innerText\s*=")
HTML_SINK = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write"
                       r"|\.html\s*\(|dangerouslySetInnerHTML|DOMParser")

# A method looked up by name out of a table.  The rule worries about two
# things: a name like constructor or toString reaching the prototype, and a
# value that is not a function.  An own key of an object literal declared in
# the same file answers both.
TABLE_LOOKUP = re.compile(r"(?P<table>[A-Za-z_$][\w$]*)\[(?P<key>[A-Za-z_$][\w$]*)\]")
DYNAMIC_CALL = re.compile(r"(?P<table>[A-Za-z_$][\w$]*)\[(?P<key>[A-Za-z_$][\w$]*)\]\s*\(")
GUARDED_VAR = re.compile(
    r"\b(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*Object\.prototype\."
    r"hasOwnProperty\.call\(\s*(?P<table>[A-Za-z_$][\w$]*)\s*,\s*(?P<key>[A-Za-z_$][\w$]*)\s*\)"
    r"\s*\?\s*(?P=table)\[(?P=key)\]\s*:\s*(?:null|undefined|false)\b")

# Denial of service rules, where who can send the input decides how much it
# matters.  An administrator slowing their own server down is a low.
CODEQL_DOS = frozenset({"js/polynomial-redos", "js/redos", "js/regex-injection",
                        "js/resource-exhaustion", "js/loop-bound-injection",
                        "js/unvalidated-dynamic-method-call"})
PRIVILEGED_GUARD = re.compile(
    r"\b(requirePerm|requirePermission|requireRole|requireAdmin|adminOnly|isAdmin)\s*\(\s*([^)]{0,60})\)")

# What counts as the handler holding back a caller who asks too often.  CodeQL
# only knows the limiter packages by name; an app that counts in its own
# database looks unlimited to it.
#
# A call to something named for it, and nothing weaker.  A bare 429 was tried
# and it was wrong: a registry answers 429 to mean "still scanning, come back",
# which limits nobody, and two pull handlers were set aside on it.
LIMIT_EVIDENCE = re.compile(
    r"\b(rateLimit|rateLimiter|limiter|throttle|slowDown)\w*\s*\(")
REQUIRE_LOCAL = re.compile(
    r"\b(?:const|let|var)\s+(?:(?P<name>[A-Za-z_$][\w$]*)|\{(?P<names>[^}]*)\})\s*=\s*"
    r"require\(\s*['\"](?P<path>\.{1,2}/[^'\"]+)['\"]\s*\)")
MEMBER_CALL = re.compile(r"\b(?P<obj>[A-Za-z_$][\w$]*)\.(?P<fn>[A-Za-z_$][\w$]*)\s*\(")
BARE_CALL = re.compile(r"(?<![\w$.])(?P<fn>[A-Za-z_$][\w$]*)\s*\(")


def _line(source: str, number: int) -> str:
    lines = (source or "").splitlines()
    return lines[number - 1] if 1 <= number <= len(lines) else ""


def _codeql_guarded_call(source: str, line: int) -> str:
    """-> the guard, if the method on this line comes from an own key check."""
    lines = (source or "").splitlines()
    text = _line(source, line)
    window = "\n".join(lines[max(0, line - 9):line - 1])
    for call in DYNAMIC_CALL.finditer(text):
        table, key = call.group("table"), call.group("key")
        if not re.search(r"\b(?:const|let|var)\s+%s\s*=\s*\{" % re.escape(table), source):
            continue
        guard = re.search(
            r"hasOwnProperty\.call\(\s*%s\s*,\s*%s\s*\)" % (re.escape(table), re.escape(key)),
            window)
        if guard:
            return guard.group(0)
    for found in GUARDED_VAR.finditer(window):
        var, table = found.group("var"), found.group("table")
        if re.search(r"(?<![\w$.])%s\s*\(" % re.escape(var), text) and \
                re.search(r"\b(?:const|let|var)\s+%s\s*=\s*\{" % re.escape(table), source):
            return found.group(0)
    return ""


def _resolve_module(base_file: str, spec: str) -> str:
    """A relative require, as a file on disk, or empty."""
    here = os.path.dirname(base_file)
    target = os.path.normpath(os.path.join(here, spec))
    for candidate in (target, target + ".js", os.path.join(target, "index.js")):
        if os.path.isfile(candidate):
            return candidate
    return ""


def _function_text(source: str, name: str) -> str:
    """The body of a named function in this file, or empty."""
    pattern = re.compile(
        r"(?:\bfunction\s+%s\s*\(|\b%s\s*[:=]\s*(?:async\s*)?(?:function\b[^(]*)?\([^)]*\)\s*(?:=>)?\s*\{)"
        % (re.escape(name), re.escape(name)))
    found = pattern.search(source or "")
    if not found:
        return ""
    start = source.find("{", found.end() - 1)
    if start < 0:
        return ""
    depth = 0
    for at in range(start, min(len(source), start + 20000)):
        if source[at] == "{":
            depth += 1
        elif source[at] == "}":
            depth -= 1
            if depth == 0:
                return source[start:at + 1]
    return ""


def _limit_in(text: str, file_path: str, hops: int, seen: set) -> str:
    """-> what holds callers back, found in this text or what it calls."""
    found = LIMIT_EVIDENCE.search(text or "")
    if found:
        return found.group(0).strip(" (,")
    if hops <= 0 or not file_path:
        return ""
    source = _read(file_path)
    modules = {}
    for req in REQUIRE_LOCAL.finditer(source):
        resolved = _resolve_module(file_path, req.group("path"))
        if not resolved:
            continue
        if req.group("name"):
            modules[req.group("name")] = (resolved, None)
        for part in (req.group("names") or "").split(","):
            part = part.strip().split(":")[-1].strip()
            if part:
                modules[part] = (resolved, part)
    targets = []
    for call in MEMBER_CALL.finditer(text or ""):
        hit = modules.get(call.group("obj"))
        if hit and hit[1] is None:
            targets.append((hit[0], call.group("fn")))
    for call in BARE_CALL.finditer(text or ""):
        hit = modules.get(call.group("fn"))
        if hit and hit[1] is not None:
            targets.append((hit[0], hit[1]))
    for target, fn in targets:
        if (target, fn) in seen:
            continue
        seen.add((target, fn))
        body = _function_text(_read(target), fn)
        if not body:
            # Re-exported from somewhere else: the module only names it.
            body = "%s(" % fn if re.search(r"\b%s\b" % re.escape(fn), _read(target)) else ""
        why = _limit_in(body, target, hops - 1, seen)
        if why:
            return why
    return ""


def _codeql_rate_limited(repo_root: str, path: str, source: str,
                         start: int, end: int) -> str:
    """-> what limits this handler, for js/missing-rate-limiting, or empty."""
    lines = (source or "").splitlines()
    text = "\n".join(lines[max(0, start - 1):max(start, end)])
    full = path if os.path.isabs(path) else os.path.join(repo_root, path)
    return _limit_in(text, full, 2, set())


def _codeql_privileged_source(repo_root: str, flow_source: dict) -> str:
    """-> the guard on the route the input comes from, or empty."""
    if not isinstance(flow_source, dict):
        return ""
    path, line = str(flow_source.get("path") or ""), int(flow_source.get("line") or 0)
    if not path or line <= 0:
        return ""
    lines = _read(os.path.join(repo_root, path)).splitlines()
    for text in reversed(lines[max(0, line - 15):line]):
        found = PRIVILEGED_GUARD.search(text)
        if found:
            return found.group(0)
        # The start of this route.  Past it is the previous route, and
        # whatever guards that one does not guard this one.
        if re.search(r"\b(?:router|app)\.(?:get|post|put|patch|delete|all)\s*\(", text):
            break
    return ""


def _codeql_guarded_on_flow(repo_root: str, flow_source: dict) -> str:
    """-> an own key check somewhere along the data flow, or empty.

    The method can be handed in as an argument, so the line that calls it has
    no lookup on it at all.  The lookup, and the check before it, are on the
    way there, which is what the flow steps are for.
    """
    for step in (flow_source or {}).get("steps") or []:
        path, line = str(step.get("path") or ""), int(step.get("line") or 0)
        if not path or line <= 0:
            continue
        source = _read(os.path.join(repo_root, path))
        guard = _codeql_guarded_call(source, line)
        if guard:
            return "%s in %s" % (guard, path)
        # Along the way the lookup is often handed on rather than called,
        # show(name, VIEWS[name]), so a guarded lookup counts here too.
        lines = source.splitlines()
        window = "\n".join(lines[max(0, line - 9):line - 1])
        for lookup in TABLE_LOOKUP.finditer(_line(source, line)):
            table, key = lookup.group("table"), lookup.group("key")
            if not re.search(r"\b(?:const|let|var)\s+%s\s*=\s*\{" % re.escape(table), source):
                continue
            found = re.search(r"hasOwnProperty\.call\(\s*%s\s*,\s*%s\s*\)"
                              % (re.escape(table), re.escape(key)), window)
            if found:
                return "%s in %s" % (found.group(0), path)
    return ""


# What a value capped to a length looks like where it enters.  The function
# is then read to make sure it really refuses or cuts anything longer.
CAPPED_INPUT = re.compile(
    r"\b(?P<fn>[A-Za-z_$][\w$]*)\(\s*req\.[\w$.\[\]'\"]+\s*,\s*(?P<n>\d{1,6})\b")
# Short enough that even a cubic regex is nothing.
CAP_LIMIT = 256


def _codeql_capped_source(repo_root: str, flow_source: dict) -> str:
    """-> how the input is capped where it enters, if it is, or empty."""
    if not isinstance(flow_source, dict):
        return ""
    path, line = str(flow_source.get("path") or ""), int(flow_source.get("line") or 0)
    full = os.path.join(repo_root, path)
    source = _read(full)
    found = CAPPED_INPUT.search(_line(source, line))
    if not found or int(found.group("n")) > CAP_LIMIT:
        return ""
    name = found.group("fn")
    target = ""
    for req in REQUIRE_LOCAL.finditer(source):
        names = [p.strip().split(":")[-1].strip()
                 for p in (req.group("names") or "").split(",")]
        if name in names:
            target = _resolve_module(full, req.group("path"))
    body_source = _read(target) if target else source
    signature = re.search(r"\bfunction\s+%s\s*\(([^)]*)\)" % re.escape(name), body_source)
    if not signature:
        return ""
    params = [p.strip().split("=")[0].strip() for p in signature.group(1).split(",")]
    if len(params) < 2 or not params[1]:
        return ""
    limit = re.escape(params[1])
    body = _function_text(body_source, name)
    refuses = re.search(r"\.length\s*>=?\s*%s\b[^\n]*\b(fail|throw)\b" % limit, body)
    cuts = re.search(r"\.slice\(\s*0\s*,\s*%s\s*\)" % limit, body)
    if refuses or cuts:
        return "%s(..., %s)" % (name, found.group("n"))
    return ""


# The variable a comment or tag strip was written into, and the only things
# its own parser does with it.  None of these can carry it out of the function.
STRIPPED = re.compile(r"\b(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*[^;\n]*\.replace\(")
READ_ONLY_USE = (r"\.(?:exec|test)\(\s*{v}\s*\)", r"\b{v}\.(?:indexOf|lastIndexOf|slice|substring|"
                 r"charAt|charCodeAt|startsWith|endsWith|length)\b")


def _codeql_parser_only(source: str, line: int) -> str:
    """-> the variable, if a stripped string is only read by its own parser."""
    found = STRIPPED.search(_line(source, line))
    if not found:
        return ""
    var = found.group("var")
    lines = (source or "").splitlines()
    rest = []
    for text in lines[line:]:
        if re.match(r"^\}", text):
            break
        rest.append(text)
    uses = [m for m in re.finditer(r"(?<![\w$.])%s(?![\w$])" % re.escape(var), "\n".join(rest))]
    if not uses:
        return ""
    allowed = sum(len(re.findall(p.format(v=re.escape(var)), "\n".join(rest)))
                  for p in READ_ONLY_USE)
    return var if allowed >= len(uses) else ""


# A request whose every connection resolves through a lookup that filters the
# address it is about to connect to.  Checked at connect time, which is the
# one place DNS rebinding cannot get past, and the defense CodeQL does not
# model.
GUARDED_AGENT = re.compile(r"new\s+https?\.Agent\(\s*\{[^}]*\blookup\s*:")
FILTERED_LOOKUP = re.compile(r"dns\.lookup\([^)]*\)[\s\S]{0,400}?\.filter\(")


def _codeql_connect_guard(source: str) -> bool:
    return bool(GUARDED_AGENT.search(source or "")) and \
        bool(FILTERED_LOOKUP.search(source or ""))


# A key as a key file holds it: the armor, then base64.  A detector's own
# regex for the armor has a group or a backslash where the base64 would be.
SERVICE_ACCOUNT_KEY = re.compile(
    r"-----BEGIN (?:RSA )?PRIVATE KEY-----(?:\\n|\s)+[A-Za-z0-9+/]{40}")


# --- running a command, and the two ways PHP makes that safe -----------------
#
# Every critical finding on one real repository was this rule, all six of them,
# and not one was a command injection.  Three passed the command to proc_open as
# an array, which goes to execve with no shell anywhere near it.  The other
# three built a string in which every interpolation was wrapped in
# escapeshellarg or cast to an integer.
#
# Both are facts about the code rather than guesses about intent, which is the
# bar everything in this file has to clear.
EXEC_FAMILY = ("exec-use", "exec-detected", "system-use", "shell-exec-use",
               "proc-open-use", "popen-use", "passthru-use",
               "non-literal-shell-command")

FIRST_ARG_VAR = re.compile(r"\b(?:proc_open|exec|shell_exec|system|passthru|popen)"
                           r"\s*\(\s*(\$[A-Za-z_][A-Za-z0-9_]*)")
ARRAY_ASSIGN = re.compile(r"^\s*\[|^\s*array\s*\(")
SHELL_SAFE = re.compile(r"escapeshellarg\s*\(|escapeshellcmd\s*\(|"
                        r"\(\s*int\s*\)|\bintval\s*\(")
INTERPOLATION = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*|%[sd]")

# implode(',', array_map('intval', ...)) is digits and commas, whatever string
# it is spliced into.  The SQL twin of the numeric cast rule above.
INT_MAPPED = re.compile(r"""array_map\s*\(\s*['"](?:intval|absint)['"]""")
# A generated placeholder list is not a value.  What gets spliced into the
# statement is question marks and commas, and the values arrive separately
# through the bind array, which is the prepared-statement idiom rather than a
# departure from it.
PLACEHOLDER_LIST = re.compile(
    r"""array_fill\s*\([^;]*['"]\?['"]|"""
    r"""str_repeat\s*\(\s*['"]\?\s*,?\s*['"]|"""
    r"""array_map\s*\(\s*(?:function|fn)\s*\([^)]*\)\s*(?:=>|\{\s*return)\s*['"]\?['"]""")


def _assignment_before(source: str, variable: str, line: int) -> str:
    """The last thing assigned to this variable before the line, or "".

    Backwards only, and the nearest one only.  A later assignment says nothing
    about the value here, and an earlier one has been overwritten since.
    """
    if not source or not variable:
        return ""
    upto = source.splitlines()[:max(0, line - 1)]
    pattern = re.compile(r"^\s*" + re.escape(variable) + r"\s*=\s*(.*)$")
    for index in range(len(upto) - 1, -1, -1):
        found = pattern.match(upto[index])
        if not found:
            continue
        collected = found.group(1)
        follow = index + 1
        # A statement can run over several lines; stop at the semicolon or
        # after a dozen, whichever comes first.
        while (not collected.rstrip().endswith(";")
               and follow < len(upto) and follow < index + 12):
            collected += " " + upto[follow].strip()
            follow += 1
        return collected
    return ""


# What to take out before asking whether anything unsafe is left.  Removing the
# safe constructs and looking at the remainder is more honest than counting
# them: a sprintf has a placeholder and an argument for every value, and
# counting both made a properly escaped command look half escaped.
SAFE_CONSTRUCT = re.compile(
    r"escapeshellarg\s*\([^()]*\)"
    r"|escapeshellcmd\s*\([^()]*\)"
    r"|intval\s*\([^()]*\)"
    r"|\(\s*int\s*\)\s*\([^()]*\)"
    r"|\(\s*int\s*\)\s*\$[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?")

BARE_VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")


def _command_expression(text: str) -> str:
    """The first argument of the call, which is the command being run.

    The rest of the line is not the command.  proc_open takes descriptors and a
    pipes array after it, and judging those as though they were part of the
    command is how a properly escaped call reads as unsafe.
    """
    found = re.search(r"\b(?:proc_open|exec|shell_exec|system|passthru|popen)"
                      r"\s*\(", text)
    if not found:
        return ""
    depth, start = 0, found.end()
    for index in range(found.end() - 1, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:index].strip()
        elif char == "," and depth == 1:
            return text[start:index].strip()
    return text[start:].strip()


def _shell_is_safe(text: str) -> tuple:
    """-> (safe, why).  Judged on the command as it is actually built."""
    body = text.strip()
    if ARRAY_ASSIGN.match(body):
        return (True, "passed to the process as an array, which goes to execve: "
                      "there is no shell for anything to be injected into")
    if not BARE_VARIABLE.search(body) and "%" not in body:
        return (True, "a fixed command with nothing interpolated into it")
    # Take out everything that is escaped or made a number, then see what is
    # left holding a value.
    remainder = SAFE_CONSTRUCT.sub("", body)
    if not BARE_VARIABLE.search(remainder):
        return (True, "every value interpolated into the command is escaped for "
                      "the shell or cast to a number")
    return (False, "")



# --- does this output escape every value in it? ------------------------------
#
# The old test asked whether an escaper appeared anywhere on the line.  That is
# the wrong question in both directions: it missed `echo "<td>" . e($x)`, which
# is escaped, and it would have cleared `echo $untrusted . e($safe)`, which is
# not.  A scanner that hides a real one is worse than a noisy scanner, because
# the noise is visible and the miss is not.
#
# So the question here is whether anything is left over once every escaped
# sub-expression is removed.  What remains is what reaches the page raw.

# Cannot return markup: the result is a number, or a count, or a length.
NUMERIC_CALLS = ("intval", "floatval", "doubleval", "boolval", "count",
                 "sizeof", "strlen", "mb_strlen", "round", "abs",
                 "number_format")
# Cannot return markup: the result is escaped for HTML or percent encoded.
# json_encode is deliberately absent.  Its output is safe in a JSON response
# and not in an HTML one, where it can carry </script>, and the caller already
# handles the JSON case separately by looking at the content type.
ESCAPING_CALLS = ("htmlspecialchars", "htmlentities", "esc_html", "esc_attr",
                  "esc_url", "strip_tags", "urlencode", "rawurlencode",
                  "http_build_query")

BASE_ESCAPERS = frozenset(NUMERIC_CALLS + ESCAPING_CALLS)

# Request data, wherever it is found.  No assignment upstream makes these
# safe, because they are the thing being traced back to.
SUPERGLOBALS = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
                "$_FILES", "$_ENV", "$GLOBALS")

# echo, print, or a short open tag, and whatever it is that gets written.
OUTPUT_STATEMENT = re.compile(r"^(?:<\?=|<\?php\s+echo|echo|print)\s+(.*)$", re.S)
# The cast has to swallow what it casts, or the variable it made safe is
# still sitting there looking unescaped.
CAST_TO_NUMBER = re.compile(
    r"\(\s*(?:int|integer|float|double|real|bool|boolean)\s*\)\s*"
    r"\$[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]*\]|->[A-Za-z_][A-Za-z0-9_]*))*")
CAST_BEFORE_GROUP = re.compile(
    r"\(\s*(?:int|integer|float|double|real|bool|boolean)\s*\)\s*\(")


def _strip_literals(expression: str) -> str:
    """Remove quoted strings, keeping any variable a double quoted one names.

    A single quoted string in PHP interpolates nothing, so it is inert.  A
    double quoted one does interpolate, and "$name" is every bit as much a way
    to put a value on the page as concatenating it.
    """
    out = []
    index = 0
    length = len(expression)
    while index < length:
        char = expression[index]
        if char == "'":
            index += 1
            while index < length and expression[index] != "'":
                index += 2 if expression[index] == "\\" else 1
            index += 1
            out.append(" ")
            continue
        if char == '"':
            index += 1
            start = index
            while index < length and expression[index] != '"':
                index += 2 if expression[index] == "\\" else 1
            inner = expression[start:index]
            index += 1
            # Keep the interpolated names, drop the surrounding text.
            out.append(" ".join(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", inner)))
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _drop_ternary_conditions(expression: str) -> str:
    """Remove the test from `condition ? this : that`.

    A condition decides which branch is written.  It is not itself written, so
    counting the variables in it as output reported every correctly escaped
    ternary in a codebase that writes a lot of them.  ?? and ?: are left alone
    on purpose: both of their sides can reach the page.
    """
    out = expression or ""
    for _ in range(8):
        depth = 0
        index = 0
        cut = None
        while index < len(out):
            char = out[index]
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            elif char == "?" and depth == 0:
                pair = out[index:index + 2]
                if pair in ("??", "?>", "?:"):
                    index += 2
                    continue
                cut = index
                break
            index += 1
        if cut is None:
            break
        out = out[cut + 1:]
    return out


def _drop_numeric_casts(expression: str) -> str:
    """Remove `(int)` and friends together with whatever they cast.

    The cast has to swallow its operand or the value it made safe is still
    sitting there looking unescaped.  It reaches a bare variable and also a
    whole parenthesised expression, which is how the idiom is actually
    written: (int)($row['id'] ?? 0).
    """
    out = CAST_TO_NUMBER.sub(" 0 ", expression or "")
    for _ in range(12):
        found = CAST_BEFORE_GROUP.search(out)
        if not found:
            break
        depth = 0
        index = found.end() - 1
        stop = None
        while index < len(out):
            if out[index] == "(":
                depth += 1
            elif out[index] == ")":
                depth -= 1
                if depth == 0:
                    stop = index
                    break
            index += 1
        if stop is None:
            break
        out = out[:found.start()] + " 0 " + out[stop + 1:]
    return out

def _drop_call(expression: str, names) -> tuple:
    """Delete one whole call to any of these names, arguments included.

    Returns (expression, changed).  Deleting the arguments along with the call
    is the point: what a sanitiser wraps is covered by it, however deeply.
    """
    for found in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", expression):
        if found.group(1) not in names:
            continue
        depth = 0
        index = found.end() - 1
        while index < len(expression):
            if expression[index] == "(":
                depth += 1
            elif expression[index] == ")":
                depth -= 1
                if depth == 0:
                    return expression[:found.start()] + " " + expression[index + 1:], True
            index += 1
        # Unbalanced, which means the match is a fragment of a longer line.
        return expression, False
    return expression, False


def _unescaped_values(expression: str, escapers=BASE_ESCAPERS) -> list:
    """The values in this output that nothing escapes.  Empty means all covered.

    Returns None when the expression cannot be read confidently, which the
    caller must treat as "keep the finding" rather than as "nothing left".
    """
    if not expression:
        return None
    # A heredoc body is not on this line, so there is nothing here to judge.
    if "<<<" in expression:
        return None
    body = OUTPUT_STATEMENT.match(expression.strip())
    working = body.group(1) if body else expression
    # These two have to be recognised before the quotes come off, because what
    # makes them safe is that an argument is a literal.
    working = LITERAL_FORMAT_CALL.sub(" 'date' ", working)
    working = JSON_HEX_CALL.sub(" 'json' ", working)
    working = _strip_literals(working)
    working = _drop_ternary_conditions(working)
    working = _drop_numeric_casts(working)
    for _ in range(24):
        working, changed = _drop_call(working, escapers)
        if not changed:
            break
    return re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", working)



# A date built from a literal format cannot carry markup: every character in
# the output came from the format string or from a number.  A format that is
# itself a variable can, so the literal is the whole point.
LITERAL_FORMAT_CALL = re.compile(
    r"""\b(?:date|gmdate|strftime|date_format)\s*\(\s*(['"])[^'"]*\1[^;]*?\)""")
# json_encode is only safe in HTML when it has been told to escape the
# characters that end a script block.  Without the flag it can emit </script>.
JSON_HEX_CALL = re.compile(
    r"""\bjson_encode\s*\([^;]*JSON_HEX_TAG[^;]*\)""")
# An array written out in full, with no variable anywhere in it, holds nothing
# but literals.  Subscripting it returns one of them whatever the key is.
LITERAL_ARRAY = re.compile(r"^\s*(?:\[|array\s*\()")


def _literal_map_variables(source: str, text: str, line: int) -> set:
    """Variables in this line that are subscripts of an all-literal array."""
    found = set()
    for name in set(re.findall(r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*\[", text or "")):
        built = _assignment_before(source or "", name, line)
        if not built:
            continue
        if LITERAL_ARRAY.match(built) and "$" not in built:
            found.add(name)
    return found


def _drop_literal_subscripts(text: str, names) -> str:
    """Replace $map[...] with a literal, for maps proven to hold only literals."""
    out = text
    for name in names:
        out = re.sub(re.escape(name) + r"\s*\[[^\]]*\]", " 'literal' ", out)
    return out


def _all_assignments(body: str, variable: str) -> list:
    """Every value ever put into this variable, by = or by .= appending."""
    if not body or not variable:
        return []
    pattern = re.compile(r"^\s*" + re.escape(variable) + r"\s*\.?=\s*(.*?);?\s*$")
    return [m.group(1) for m in
            (pattern.match(line) for line in body.splitlines()) if m]


def _covered_in_body(expression: str, body: str, known, hops: int = 2) -> bool:
    """Is every value in this expression covered, following local assignments?

    A helper rarely returns the escaper call itself.  It builds a string over
    several lines and returns the variable, which is why reading only the
    return statement found so few of them.
    """
    left = _unescaped_values("echo " + expression, known)
    if left is None:
        return False
    if not left:
        return True
    if hops <= 0:
        return False
    for variable in left:
        if variable in SUPERGLOBALS:
            return False
        pieces = _all_assignments(body, variable)
        if not pieces:
            return False
        if not all(_covered_in_body(piece, body, known, hops - 1)
                   for piece in pieces):
            return False
    return True

# A wrapper is a function whose every return is already covered.  Finding them
# by reading them is the whole point: a project names its escaper whatever it
# likes, and a list of names this tool shipped with would never contain it.
FUNCTION_HEAD = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*\{", re.S)


def _function_body(source: str, start: int) -> str:
    """The text between the braces of the function that opens at start."""
    depth = 0
    for index in range(start, min(len(source), start + 20000)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    return ""


def _escaper_wrappers(sources, rounds: int = 3) -> frozenset:
    """Names that only ever return an escaped value, read out of the source.

    Run to a fixpoint, because wrappers are written on top of wrappers: e()
    wraps htmlspecialchars, and a column helper wraps e().
    """
    known = set(BASE_ESCAPERS)
    bodies = {}
    for source in sources:
        if not source or "function" not in source:
            continue
        for head in FUNCTION_HEAD.finditer(source):
            body = _function_body(source, head.end() - 1)
            if body and head.group(1) not in bodies:
                bodies[head.group(1)] = body
    for _ in range(rounds):
        grew = False
        for name, body in bodies.items():
            if name in known:
                continue
            returns = re.findall(r"\breturn\s+([^;]+);", body)
            if not returns:
                continue
            # Every single one of them, not merely one of them.
            if all(_covered_in_body(value, body, known) for value in returns):
                known.add(name)
                grew = True
        if not grew:
            break
    return frozenset(known)


# Wrappers are declared once, in an include, and used everywhere else, so the
# file a finding sits in is usually not the file that defines the escaper.
SKIP_DIRECTORIES = ("vendor", "node_modules", "third_party", "bower_components",
                    ".git", "dist", "build")
PHP_SUFFIXES = (".php", ".inc", ".phtml")


def _repo_escapers(repo_root: str, limit: int = 4000) -> frozenset:
    """Read the project's own escaping helpers out of its source."""
    if not repo_root or not os.path.isdir(repo_root):
        return BASE_ESCAPERS
    sources = []
    seen = 0
    for folder, directories, files in os.walk(repo_root):
        directories[:] = [d for d in directories if d not in SKIP_DIRECTORIES]
        for name in files:
            if not name.endswith(PHP_SUFFIXES):
                continue
            seen += 1
            if seen > limit:
                break
            full = os.path.join(folder, name)
            try:
                if os.path.getsize(full) > 600000:
                    continue
            except OSError:
                continue
            text = _read(full)
            if "function" in text:
                sources.append(text)
        if seen > limit:
            break
    return _escaper_wrappers(sources)


# --- a credential that ships with the product --------------------------------
#
# Reporting this as "bcrypt hash detected" describes what was matched and not
# what is wrong.  A hash in a schema file is not a leaked secret: it is a
# credential every install created from that file shares, which is a different
# and worse thing.  It was rated the same as the noise around it and sat in the
# middle of a long report where nobody would ever reach it.
#
# The plaintext is not the point and usually cannot be recovered anyway.  A
# seeded administrator row is a default credential whatever the password is.

BCRYPT_HASH = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
OTHER_HASH = re.compile(r"\$(?:argon2(?:id|i|d)|scrypt|pbkdf2[^$]*|5|6)\$[^\s'\"]{16,}")

# Where a credential of this kind gets shipped from.
SEED_FILE = re.compile(
    r"\.sql$|(^|/)(schema|schemas|seeds?|fixtures?|migrations?|sql_updates)(/|$)",
    re.I)
# An account being created, rather than a hash being compared against.
ACCOUNT_CONTEXT = re.compile(
    r"\bis_admin\b|\bis_super_admin\b|\bis_superuser\b|"
    r"\binsert\s+into\s+[`\"']?(users?|accounts?|admins?|members?)\b|"
    r"\brole\s*=\s*[`\"']?(admin|administrator|root|superuser)\b",
    re.I)

# Hashes published somewhere popular enough that the plaintext is common
# knowledge.  Every entry here was checked against the algorithm rather than
# copied from a list, and naming the password is what makes the report
# impossible to wave away.
PUBLISHED_HASHES = {
    "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi": (
        "password", "the example in the PHP password_hash manual"),
}


def _published_hash(text: str):
    """-> (plaintext, where it was published) for a hash anybody can look up."""
    for found in BCRYPT_HASH.finditer(text or ""):
        known = PUBLISHED_HASHES.get(found.group(0))
        if known:
            return known
    return None



# A file that nothing loads seeds nothing.  Escalating a credential in dead
# code spends the grade that makes somebody stop what they are doing on a file
# that never runs, and a repository this happened on had two of them: reference
# copies of a schema, carrying a hash out of the manual, while the live path
# substituted a generated password per install.  Detecting the hash was right.
# Calling it a default credential was not.
LOADER_SUFFIXES = (".php", ".inc", ".phtml", ".sh", ".bash", ".yml", ".yaml",
                   ".json", ".env", ".conf", ".ini", ".py", ".rb", ".go",
                   ".ts", ".js", ".sql", ".tf", ".mk")
LOADER_NAMES = ("dockerfile", "makefile", "entrypoint", "docker-compose")


def _reference_corpus(repo_root: str, limit: int = 6000) -> list:
    """Every file that could name another one, as (relative path, text)."""
    corpus = []
    if not repo_root or not os.path.isdir(repo_root):
        return corpus
    seen = 0
    for folder, directories, files in os.walk(repo_root):
        directories[:] = [d for d in directories if d not in SKIP_DIRECTORIES]
        for name in files:
            lowered = name.lower()
            if not (lowered.endswith(LOADER_SUFFIXES)
                    or any(k in lowered for k in LOADER_NAMES)):
                continue
            seen += 1
            if seen > limit:
                return corpus
            full = os.path.join(folder, name)
            try:
                if os.path.getsize(full) > 2000000:
                    continue
            except OSError:
                continue
            relative = os.path.relpath(full, repo_root)
            corpus.append((relative, _read(full)))
    return corpus


def _anything_loads(path: str, corpus: list) -> bool:
    """Does any other file in the repository name this one?

    A file naming itself does not count.  The reference copies that started
    this carried comments about themselves and nothing else.
    """
    if not path:
        return True     # nothing to go on, so do not act on the absence
    if not corpus:
        return True
    base = os.path.basename(path)
    stem = os.path.splitext(base)[0]
    if not stem:
        return True
    needles = [base.lower()]
    # The stem catches "require_once SCHEMA_DIR . '/master_schema' . $ext".
    if len(stem) >= 6:
        needles.append(stem.lower())
    for other, text in corpus:
        if other == path or os.path.basename(other) == base:
            continue
        lowered = text.lower()
        if any(needle in lowered for needle in needles):
            return True
    return False

def _promotion(rule: str, path: str, matched: str, source: str, line: int = 0,
               corpus: list = ()):
    """-> what this finding should have been reported as, or None.

    Only ever raises severity, and only on a fact about the file: a hash that
    is written into a schema is a credential the product ships with.
    """
    if "hash" not in (rule or "").lower():
        return None
    text = matched or ""
    if not (BCRYPT_HASH.search(text) or OTHER_HASH.search(text)):
        return None
    if not SEED_FILE.search(path or ""):
        return None
    # The account has to be being created here.  A hash in a schema that is
    # only a column default, or a test comparing against a fixture, is not a
    # credential anybody can log in with.
    window = "\n".join((source or "").splitlines()[max(0, line - 6):line + 6])
    if not (ACCOUNT_CONTEXT.search(window) or ACCOUNT_CONTEXT.search(text)):
        return None
    # And something has to load the file.  A reference copy nobody includes
    # creates no account, whatever the INSERT in it says.
    if not _anything_loads(path, list(corpus)):
        return None

    known = _published_hash(text)
    if known:
        plaintext, where = known
        message = (
            "A default administrator credential is created by this file. The "
            "hash is the bcrypt of \"%s\", which is %s, so it is in every "
            "default credential wordlist. Any install where nobody changed it "
            "can be logged into by anyone who has read the source."
            % (plaintext, where))
    else:
        message = (
            "A password hash is written into a file that creates an account, "
            "so every install built from it starts with the same credential "
            "and the source says what it is. Generate one per install, or "
            "require a change at first login."
        )
    return {"severity": "critical",
            "cwe": "CWE-1392: Use of Default Credentials",
            "message": message,
            "rule": "seeded-default-credential"}


# --- what the rule called a leak and the file calls doing it properly --------
#
# detected-bcrypt-hash fires on a database dump and reports it high:
#
#     INSERT INTO `users` (`username`, `password`) VALUES
#     (1, 'rogers63', '$2y$12$s.YfVZdfvAuO/Iz6fte5iO..ZbbEgreZnDcYOGvX4NGJskYQIstcG'),
#
# That is a hashed password.  It is what a password is supposed to look like
# once it has been stored, and finding one is evidence the application did the
# right thing.  On a twenty repository corpus this was 47 findings, every one
# graded high and every one of them wrong.
#
# The one case where a hash in a file does matter is already handled above, by
# _promotion: a hash in a file that creates an account is a default credential
# and goes up to critical.  This is the other side of the same coin, and the
# two are deliberately written next to each other so neither can be changed
# without seeing the other.
DOC_EXTENSION = re.compile(r"\.(?:md|mdx|rst|txt|adoc|po|pot|snap|golden)$", re.I)


def _hash_demotion(rule: str, matched: str, line_text: str = ""):
    """-> a demotion for a password hash that is not a default credential.

    The whole line is read as well as the matched span.  A bcrypt hash is
    sixty characters and a match that clips it by one would otherwise look
    like an ordinary string, which is the difference between this firing and
    not on the same finding.
    """
    if "hash" not in (rule or "").lower() and "password" not in (rule or "").lower():
        return None
    text = (matched or "") + "\n" + (line_text or "")
    if BCRYPT_HASH.search(text):
        family = "bcrypt"
    elif OTHER_HASH.search(text):
        family = "a deliberately slow password hash"
    else:
        return None
    return {
        "severity": "info",
        "verdict": NOT_APPLICABLE,
        "reason": ("this is %s, which is what a password is supposed to look "
                   "like at rest rather than a password anybody can use. A "
                   "hash here is evidence the application stored it properly"
                   % family),
        "rule": "password-hash-at-rest",
    }


def _documentation_demotion(path: str):
    """-> a demotion for a finding on a line of documentation.

    The credential pass has dropped the grade of a secret found in a README
    since it was written, because an example in documentation is an example.
    Code findings went through no such pass, so a detected-jwt-token in an
    .rst file came out high: 46 high or critical findings on one corpus, all
    of them in prose.
    """
    text = path or ""
    if not any(pattern.search(text) for pattern in PLACEHOLDER_PATHS):
        return None
    prose = bool(DOC_EXTENSION.search(text))
    # info rather than low, to agree with what ingest already does with a
    # not_applicable verdict.  Two different answers to the same question, one
    # from the scanner and one from the application, is how a report and a
    # screen end up disagreeing about the same finding.
    return {
        "severity": "info",
        "verdict": NOT_APPLICABLE,
        "reason": ("this is %s, so the line is an example somebody wrote down "
                   "rather than code that runs"
                   % ("a documentation file" if prose
                      else "a path this installation treats as examples")),
        "rule": "documentation-path",
    }


def judge(rule: str, path: str, matched: str, source: str, line: int = 0,
          muted: tuple = (), escapers=BASE_ESCAPERS) -> tuple:
    """-> (verdict, reason, which rule decided).  Conservative by construction."""
    if rule in muted:
        return (ADVISORY,
                "an advisory rule: it reports every use of this, not a misuse "
                "of it. Set aside in Settings, and still recorded here.",
                "muted-rule")

    for pattern, why in THIRD_PARTY_PATHS:
        if re.search(pattern, path, re.I):
            return THIRD_PARTY, f"in {why}", "third-party-path"

    text = matched.strip()

    if rule in XSS_FAMILY:
        if JSON_OUT.search(text) and _header_before(source, JSON_HEADER, line):
            return (NOT_APPLICABLE,
                    "a JSON response, not an HTML page: the file sets a JSON "
                    "content type and this is json_encode output",
                    "json-endpoint")
        if (_header_before(source, DOWNLOAD_HEADER, line)
                or _download_branch(source or "", line)) and \
                re.match(OUTPUT_PREFIX + r"\$[A-Za-z_]", text):
            return (NOT_APPLICABLE,
                    "a file download, not an HTML page: the file sets a "
                    "download or binary content type",
                    "download-endpoint")
        if NUMERIC.search(text):
            return (NOT_APPLICABLE,
                    "cast to a number before output, which cannot carry markup",
                    "numeric-cast")
        if ESCAPED.search(text):
            return NOT_APPLICABLE, "escaped on the way out", "escaped-output"
        if SAFE_RETURN.search(text):
            return (NOT_APPLICABLE,
                    "the value comes from a function that cannot return markup",
                    "safe-return")
        # Everything above asks whether the line contains something safe.  This
        # asks the harder question: is anything left over that is not.
        #
        # A lookup into an array written out in full returns one of the
        # literals in it, whatever the key happens to be.
        maps = _literal_map_variables(source or "", text, line)
        looked_at = _drop_literal_subscripts(text, maps) if maps else text
        remaining = _unescaped_values(looked_at, escapers)
        if remaining == []:
            return (NOT_APPLICABLE,
                    "every value in this output is escaped before it is "
                    "written",
                    "fully-escaped")
        if remaining:
            # The cast is usually written where the value arrives, not where it
            # is printed:  $id = intval($_GET['id'])  ...  echo $id
            traced = []
            for variable in remaining:
                if variable in SUPERGLOBALS:
                    break
                origin = _assignment_before(source or "", variable, line)
                if origin and _unescaped_values("echo " + origin, escapers) == []:
                    traced.append(variable)
                    continue
                break
            else:
                if traced:
                    return (NOT_APPLICABLE,
                            "every value in this output was escaped or cast to "
                            "a number where it was assigned",
                            "escaped-at-assignment")

    if rule in PATH_FAMILY and text:
        # A lookup written straight into the sink, is_file($allowed[$key][0]),
        # is the same proof as one that went through a variable first.
        tables = _literal_map_variables(source or "", text, line)
        looked_at = _drop_literal_subscripts(text, tables) if tables else text
        names = set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", looked_at))
        if tables and not names:
            return (NOT_APPLICABLE,
                    "the path comes out of a table written into the source, "
                    "so the request chooses which entry and never what is in "
                    "it",
                    "literal-path-table")
        # Every part of a joined path has to be accounted for.  One checked
        # component beside one unchecked one is not a safe path, and clearing
        # on the first safe one is how this rule would hide a traversal.
        if names and not (names & set(SUPERGLOBALS)):
            if all(_path_component_safe(source or "", name, line)
                   for name in names):
                return (NOT_APPLICABLE,
                        "the name is checked against a pattern anchored at "
                        "both ends that admits no separator, so it cannot "
                        "leave the directory it is joined to",
                        "anchored-path-check")
            if all(_from_literal_table(source or "", name, line)
                   for name in names):
                return (NOT_APPLICABLE,
                        "the path comes out of a table written into the "
                        "source, so the request chooses which entry and never "
                        "what is in it",
                        "literal-path-table")

    if rule in ("eval-detected", "exec-detected") and PY_LITERAL_CALL.match(text):
        return (NOT_APPLICABLE,
                "the argument is a string literal, so there is no input to "
                "inject into it",
                "literal-eval")

    if rule == "detect-non-literal-regexp" and text.count("RegExp") == 1 \
            and JS_LITERAL_REGEXP.search(text):
        return (NOT_APPLICABLE,
                "the pattern is a string literal, which is what this rule "
                "exists to rule out",
                "literal-regexp")

    if rule == "run-shell-injection":
        expressions = ACTIONS_EXPR.findall(text)
        if expressions and all(_expression_is_fixed(e, source) for e in expressions):
            return (NOT_APPLICABLE,
                    "every value interpolated into this step is fixed: a "
                    "choice input, which GitHub validates against its options "
                    "list, or an env value that is never set from an "
                    "expression. There is no attacker input to inject.",
                    "actions-fixed-input")

    if rule in CODEQL_XSS:
        written = _line(source, line)
        if TEXT_SINK.search(written) and not HTML_SINK.search(written):
            return (NOT_APPLICABLE,
                    "the value is written into the page as a text node, which "
                    "the browser never parses as markup, so it cannot inject "
                    "script",
                    "codeql-text-node")

    if rule == "js/unvalidated-dynamic-method-call":
        guard = _codeql_guarded_call(source, line)
        if guard:
            return (NOT_APPLICABLE,
                    "the method is only looked up after %s, so it can only be "
                    "one of the functions in a table declared in this file, "
                    "never a prototype method like constructor" % guard[:80],
                    "codeql-own-key")

    # This rule matches "type": "service_account", which is the label on a
    # Google key file and not the key.  It fired on a comment in a secret
    # scanner describing what it looks for.  The file only leaks something if
    # the private key is in it as well, written out, so that is what decides.
    if rule == "detected-google-gcm-service-account" \
            and not SERVICE_ACCOUNT_KEY.search(source or ""):
        return (NOT_APPLICABLE,
                "it names the type of a Google service account file, but no "
                "private key is written out anywhere in this file, so there "
                "is no credential here",
                "service-account-without-key")

    if PLACEHOLDERS and CREDENTIAL_RULE.search(rule):
        for candidate in [text] + QUOTED_VALUE.findall(text):
            value = candidate.strip()
            if not value:
                continue
            # Key armour is exempt for the same reason it is on the secrets
            # side: a private key body is base64, and base64 spells anything
            # given enough of it.
            if "PRIVATE KEY-----" in value:
                break
            for pattern in PLACEHOLDERS:
                if pattern.search(value):
                    return (NOT_APPLICABLE,
                            "a stand-in rather than a credential: the value "
                            "matches the same placeholder rules the secrets "
                            "pass applies, which this finding never went "
                            "through",
                            "placeholder-credential")
            if len(value) >= 8 and _shannon(value) < DEFAULTS["min_entropy"]:
                return (NOT_APPLICABLE,
                        "padding rather than a credential: too little variety "
                        "in it to be a real key, by the same entropy floor the "
                        "secrets pass uses",
                        "low-entropy-credential")
            if len(value) >= 8 and len(set(value)) <= 4:
                return (NOT_APPLICABLE,
                        "four or fewer distinct characters, which is filler "
                        "rather than a credential",
                        "low-diversity-credential")

    if rule in EXEC_FAMILY and text:
        command = _command_expression(text)
        if command:
            safe, why = _shell_is_safe(command)
            if safe:
                return NOT_APPLICABLE, why, "shell-safe-inline"
        found = FIRST_ARG_VAR.search(text)
        if found:
            variable = found.group(1)
            # A parameter declared as an array cannot be a string by the time
            # it is used, whatever the caller passed.
            declared = re.compile(r"function\s+\w+\s*\([^)]*\barray\s+"
                                  + re.escape(variable))
            if declared.search(source or ""):
                return (NOT_APPLICABLE,
                        "the command is declared as an array parameter, so it "
                        "reaches the process through execve with no shell in "
                        "between",
                        "shell-array-param")
            built = _assignment_before(source or "", variable, line)
            if built:
                safe, why = _shell_is_safe(built)
                if safe:
                    return NOT_APPLICABLE, why, "shell-safe-assignment"

    if rule == "tainted-sql-string" and text:
        # Two hops, because the idiom is written in two lines:
        #
        #     $cids         = array_filter(array_map('intval', $raw));
        #     $placeholders = implode(',', $cids);
        #     "... WHERE id IN ($placeholders)"
        #
        # Following only the first hop finds the implode and stops, which is
        # how this rule missed every one of them on the repository it was
        # written for.
        for variable in set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", text)):
            built = _assignment_before(source or "", variable, line)
            if not built:
                continue
            if INT_MAPPED.search(built):
                return (NOT_APPLICABLE,
                        "the values spliced in are mapped through intval, so "
                        "the list is digits and commas and carries no SQL",
                        "int-mapped-sql")
            if PLACEHOLDER_LIST.search(built):
                return (NOT_APPLICABLE,
                        "what is spliced in is a generated list of bind "
                        "placeholders, so the statement gets question marks "
                        "and the values are bound separately",
                        "placeholder-list-sql")
            for inner in set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", built)):
                if inner == variable:
                    continue
                deeper = _assignment_before(source or "", inner, line)
                if deeper and INT_MAPPED.search(deeper):
                    return (NOT_APPLICABLE,
                            "the values spliced in are mapped through intval "
                            "before they are joined, so the list is digits and "
                            "commas and carries no SQL",
                            "int-mapped-sql")
                if deeper and PLACEHOLDER_LIST.search(deeper):
                    return (NOT_APPLICABLE,
                            "what is spliced in is a generated list of bind "
                            "placeholders, so the statement gets question "
                            "marks and the values are bound separately",
                            "placeholder-list-sql")

    if rule == "tainted-sql-string" and text and not SQL_STATEMENT.search(text):
        return (NOT_APPLICABLE,
                "the string is not SQL: it has no statement in it",
                "not-sql")

    return REVIEW, "", ""


# --- a python subprocess call that never reaches a shell ----------------------
#
# subprocess.run(["git", "clone", url]) and subprocess.run(f"git clone {url}",
# shell=True) are the same function and completely different risks.  The first
# goes to execve with the arguments already separated, so a semicolon in url is
# a semicolon in an argument and nothing else.  The second hands the whole
# string to /bin/sh.
#
# The rules that flag these cannot tell them apart: they see data reaching
# subprocess and report command injection either way.  On this codebase that
# was two findings, one of them the loudest thing in the list, and both of them
# were the safe form.
#
# What decides it is whether a shell is involved, so that is what is checked
# first and it wins over everything else.  Any mention of shell that is not
# plainly False leaves the finding exactly where it is: a call this cannot read
# confidently is a call it says nothing about.  Guessing towards safe here
# would silence the one shape that actually is command injection.

SUBPROCESS_RULES = {
    "subprocess-injection",
    "dangerous-subprocess-use-tainted-env-args",
    "dangerous-subprocess-use-audit",
    "subprocess-shell-true",
}

SUBPROCESS_CALL = re.compile(
    r"\b(?:subprocess\s*\.\s*)?(?:run|call|check_call|check_output|Popen)\s*\(")
# shell= followed by anything at all.  Only an explicit False is read as safe;
# shell=flag or shell=cfg.get("shell") is unknown, and unknown means leave it.
# Brackets and dots are in the class so a lookup is captured as something
# other than False; parentheses are deliberately not, because including them
# swallowed the closing bracket of the call and turned shell=False into the
# string "False)", which matches nothing and left the safe spelling uncleared.
SHELL_KWARG = re.compile(r"\bshell\s*=\s*([A-Za-z0-9_.\[\]\"']+)")
LIST_ASSIGN = re.compile(r"^\s*\[")


def _call_text(source: str, line: int, limit: int = 40) -> str:
    """The whole call starting at this line, brackets balanced.

    A subprocess call is routinely spread over five lines, and reading only the
    line the finding points at would miss a shell=True sitting two lines below
    it.  Missing that is the one mistake this must not make.
    """
    lines = (source or "").splitlines()
    if not (1 <= line <= len(lines)):
        return ""
    text = "\n".join(lines[line - 1:line - 1 + limit])
    start = SUBPROCESS_CALL.search(text)
    if not start:
        return ""
    depth = 0
    for index in range(start.end() - 1, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start.start():index + 1]
    return ""            # never closed within the window: say nothing


def _first_argument(call: str) -> str:
    """The first positional argument, which is the command being run."""
    open_at = call.find("(")
    if open_at < 0:
        return ""
    depth = 0
    for index in range(open_at, len(call)):
        char = call[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return call[open_at + 1:index].strip()
        elif char == "," and depth == 1:
            return call[open_at + 1:index].strip()
    return ""


def _subprocess_not_a_shell(rule: str, source: str, line: int):
    """-> a reason this is not command injection, or None.

    Says nothing unless two things are both true: no shell, and a command that
    is a list.  Either one unknown means the finding stands.
    """
    if rule not in SUBPROCESS_RULES:
        return None
    call = _call_text(source, line)
    if not call:
        return None

    # A shell decides it, and it is checked before anything else.
    shell = SHELL_KWARG.search(call)
    if shell and shell.group(1).strip() not in ("False", "0"):
        return None

    argument = _first_argument(call)
    if not argument:
        return None

    if LIST_ASSIGN.match(argument):
        return ("the arguments are a list and no shell is asked for, so this "
                "goes straight to execve: there is nothing for a shell "
                "metacharacter to be interpreted by")

    # A bare name, built earlier.  Followed back to where it was made, because
    # the safe form is routinely assembled over several lines before the call.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", argument):
        assigned = _assignment_before(source, argument, line)
        if assigned and LIST_ASSIGN.match(assigned.strip()):
            # Anything that could have replaced it with a string between the
            # assignment and the call means this cannot be relied on.  Appends
            # and extends keep it a list; a second plain assignment does not.
            window = "\n".join((source or "").splitlines()[:max(0, line - 1)])
            rebound = re.findall(r"^\s*" + re.escape(argument) + r"\s*=\s*(.*)$",
                                 window, re.M)
            if rebound and not LIST_ASSIGN.match(rebound[-1].strip()):
                return None
            return ("%s is built as a list and no shell is asked for, so the "
                    "arguments reach the process already separated and a shell "
                    "metacharacter in any of them is just a character"
                    % argument)
    return None


# --- a logger that mentions a secret rather than logging one -----------------
#
# The rule reads the message and not the values.  A line that says it could not
# get a token contains the word token, so the rule fires, and what is actually
# written to the log is an exception.
#
#     log.warning("could not reach Microsoft to get a token: %s", exc)
#
# Nothing there is a credential.  The sentence is about a credential, which is
# what an error message about authentication is bound to be, and the only
# variable in it is the failure.  Reported as written, the rule fires on
# roughly every honest error message in an authentication path, which is
# exactly where careful messages get written.
#
# So this asks the only question that matters: what reaches the log.  The
# literal text is not evidence either way, because a message has to be allowed
# to name the thing it failed to get.
LOGGER_RULES = {
    "python-logger-credential-disclosure",
    "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure",
}

LOGGER_CALL = re.compile(
    r"\b(?:log|logger|logging|_log|LOG|LOGGER)\s*\.\s*"
    r"(?:debug|info|warning|warn|error|exception|critical|fatal|log)\s*\(")

# Names that would make this a real disclosure.
#
# Matched anywhere in the expression rather than on word boundaries, and that
# is deliberate.  An underscore is a word character, so a boundary anchored
# pattern does not match bearer_token, get_access_key or api_token, which is
# precisely how these are named in Python.  Written the careful way it missed
# three real disclosures in the first run of its own tests.
#
# Matching loosely errs toward keeping a finding, which is the direction to
# err in: the cost of keeping one is somebody reads a line and moves on, and
# the cost of clearing one is a credential sitting in a log file that nobody
# is looking through any more.
SECRET_NAME = re.compile(
    r"secret|token|password|passwd|pwd|apikey|api_key|access_key|"
    r"privatekey|private_key|credential|auth|bearer|session_key|"
    r"client_secret|refresh_token|passphrase|signing_key", re.I)

# What an exception is called.  These carry a message about a failure, and a
# provider that puts a credential into an error string has a problem this rule
# was not written to find.
FAILURE_NAME = re.compile(
    r"^(?:exc|e|err|error|ex|reason|why|detail|status|code|resp\.status|"
    r"response\.status|exc\.code|exc\.reason|type\(exc\)\.__name__)$", re.I)


def _logger_arguments(call: str) -> list:
    """Everything the call would interpolate, or None when it cannot be read.

    The format string itself is not one of them: it is a literal written by
    whoever wrote the line.  What matters is the values filled into it, plus
    anything inside an f-string, which is the same thing spelled differently.
    """
    open_at = call.find("(")
    if open_at < 0:
        return None
    depth = 0
    quote = ""
    parts, current = [], ""
    index = open_at
    while index < len(call):
        char = call[index]

        # Inside a string nothing is punctuation.  Without this a message
        # holding a comma, which is most of them, is split into pieces and
        # half a sentence is reported as a value being logged.  It was, and
        # the reason printed on a finding read "the values logged are %d
        # day(s)", which is not a value and not a sentence.
        if quote:
            if char == "\\":
                current += call[index:index + 2]
                index += 2
                continue
            if call.startswith(quote, index):
                current += quote
                index += len(quote)
                quote = ""
                continue
            current += char
            index += 1
            continue

        if char in "\"'":
            for candidate in (char * 3, char):
                if call.startswith(candidate, index):
                    quote = candidate
                    current += candidate
                    index += len(candidate)
                    break
            continue

        if char in "([{":
            depth += 1
            if depth == 1:
                index += 1
                continue
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                parts.append(current)
                break
        elif char == "," and depth == 1:
            parts.append(current)
            current = ""
            index += 1
            continue
        current += char
        index += 1

    if not parts:
        return None
    parts = [piece.strip() for piece in parts]
    message, rest = parts[0], parts[1:]

    # An f-string interpolates inside the message, so its braces are arguments
    # even though they are written as part of the text.
    if re.match(r"^[rbu]*f", message, re.I):
        rest = rest + re.findall(r"\{([^{}]+)\}", message)

    # Concatenation is interpolation with a different spelling.
    if "+" in message and not re.match(r"^[rbu]*f", message, re.I):
        for piece in message.split("+"):
            piece = piece.strip()
            if piece and not piece.startswith(("'", '"')):
                rest.append(piece)

    # A keyword argument that is not a value being logged.
    rest = [piece for piece in rest
            if piece and not re.match(r"^(exc_info|stack_info|stacklevel|extra)\s*=", piece)]
    return rest


def _logger_not_a_secret(rule: str, source: str, line: int):
    """-> a reason this logs no credential, or None to leave the finding alone.

    Only ever answers when the whole call could be read and every value going
    into it could be named.  Anything unreadable leaves the finding standing,
    because the cost of being wrong here is a credential in a log file that
    nobody is looking for any more.
    """
    if rule not in LOGGER_RULES and not rule.endswith(
            "python-logger-credential-disclosure"):
        return None

    lines = (source or "").splitlines()
    if not (1 <= line <= len(lines)):
        return None
    window = "\n".join(lines[line - 1:line - 1 + 20])
    start = LOGGER_CALL.search(window)
    if not start:
        return None

    depth = 0
    call = ""
    for index in range(start.end() - 1, len(window)):
        char = window[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                call = window[start.start():index + 1]
                break
    if not call:
        return None

    arguments = _logger_arguments(call)
    if arguments is None:
        return None

    if not arguments:
        return ("the message is a literal with nothing interpolated into it, "
                "so whatever the sentence mentions, no value reaches the log")

    named = []
    for argument in arguments:
        if SECRET_NAME.search(argument):
            return None                     # something here really is one
        if not FAILURE_NAME.match(argument.strip()):
            named.append(argument.strip())

    if not named:
        return ("the only value logged is the failure itself, and the words in "
                "the message are the message naming what it could not get")

    return ("the values logged are %s, none of which is a credential: the rule "
            "matched words in the message text rather than anything reaching "
            "the log" % ", ".join(named[:4]))


# --- a code rule that fired on something that is not code ---------------------
#
# The largest single source of noise in a real estate turned out not to be any
# rule.  It was code analysis running over files that are not code: run logs,
# captured traffic, saved responses, the output of a load test.  Twenty
# percent of the findings on one estate were a code rule firing on a file that
# has never been executed by anything.
#
# A log cannot have a weakness in it.  It is a record of something that
# happened, and the rules here are about what a program does.  Matching a
# pattern inside a transcript says the transcript contains the pattern, which
# is a fact about the transcript.
#
# Credentials are the exception and they are deliberately untouched.  A token
# written into a log and committed is exposed exactly as much as one in a
# source file, arguably more, because nobody thinks to look there.  That is
# the credential scanner's job and it keeps doing it: this only ever answers
# for a code or configuration rule.
#
# The list is written as whole names and extensions rather than as a guess at
# what looks generated, because "looks generated" is how a real source file
# gets muted by accident.
GENERATED_SUFFIXES = (
    ".log", ".har", ".jsonl", ".ndjson", ".dmp", ".trace", ".pcap",
    ".out", ".stdout", ".stderr",
)

GENERATED_NAMES = (
    "output.txt", "output.bak", "results.xml", "mdrv.log", "vugen.log",
    "combined_res.xml", "console.log", "npm-debug.log", "yarn-error.log",
    "pip-log.txt", "junit.xml", "testng-results.xml", "nosetests.xml",
)

# A directory whose whole purpose is to hold what a run produced.
GENERATED_DIRS = (
    "test-results", "test-output", "testoutput", "allure-results",
    "surefire-reports", "failsafe-reports", "har", "recordings",
    "captured", "coverage", "htmlcov", ".pytest_cache", "result1",
)


def _looks_generated(path: str):
    """-> what kind of output this file is, or None if it is not output.

    Named parts only.  Anything cleverer, like calling a file generated
    because it is large or has long lines, mutes a minified bundle that
    somebody does ship and does want looked at.
    """
    if not path:
        return None
    lowered = path.replace("\\", "/").lower()
    name = lowered.rsplit("/", 1)[-1]

    if name in GENERATED_NAMES:
        return "a file that holds what a run produced"
    for suffix in GENERATED_SUFFIXES:
        if name.endswith(suffix):
            return "a %s file, which is a record of a run rather than code" % suffix
    parts = lowered.split("/")
    for directory in GENERATED_DIRS:
        if directory in parts:
            return ("inside a %s directory, which holds what a run produced"
                    % directory)
    # A backup of something, which is not what runs.  Checked after the names
    # above so that output.bak is described as output rather than as a backup.
    if name.endswith(".bak") or name.endswith(".orig") or name.endswith("~"):
        return ("a backup copy, which is not the file that runs: whatever is "
                "wrong in it is either fixed in the live file or reported "
                "against it separately")
    return None


def _not_code_at_all(kind: str, path: str):
    """-> a reason a code rule does not apply here, or None.

    Answers only for code and configuration rules.  A credential found in a
    log is a real disclosure and is left exactly where it is.
    """
    if kind not in ("code", "misconfiguration"):
        return None
    what = _looks_generated(path)
    if not what:
        return None
    return ("this is %s, and a rule about what a program does cannot be "
            "answered by a transcript of one: the pattern is in the record, "
            "not in anything that runs" % what)


SKIP_FRAMEWORK_DIRS = {
    "node_modules", "vendor", "third_party", "bower_components", ".venv",
    "venv", "site-packages", "dist", "build", "target", "__pycache__",
    "tests", "test", "fixtures", "testdata", "examples", "example", "docs",
}


# --- rules that belong to a framework nobody here uses ------------------------
#
# semgrep namespaces its rules by the thing they are about, so
# python.django.security.audit.django-no-csrf-token says plainly that it is a
# Django rule.  Run against an application that does not use Django it fires on
# every form it can find and reports the absence of a template tag that could
# not be there, because the framework that defines it is not installed.
#
# On this project that was fifty two findings out of a hundred and fifty eight,
# a third of the whole list, from one Django rule reading a FastAPI codebase.
# Every one of them was medium, and every one of them was wrong in the same way.
#
# So the namespace is read, and where it names a framework this can positively
# establish is not in use, the finding is set aside as not applicable with the
# reason.  Nothing is deleted and nothing is hidden: it lands under Set aside
# like every other verdict, with a sentence somebody can disagree with.
#
# The direction of the check is the important part.  A framework is only ever
# ruled out by finding its manifests and not finding it in them.  A repository
# whose manifests cannot be read at all decides nothing, because "I could not
# tell" and "it is not there" are different answers and only one of them is
# safe to act on.  Guess wrong towards absent and the tool silently stops
# reporting real findings, which is the failure this whole file exists to
# avoid.

# framework -> (manifest file names, pattern that names it inside one)
FRAMEWORK_MARKERS = {
    "django":  (("requirements.txt", "requirements-dev.txt", "pyproject.toml",
                 "Pipfile", "setup.py", "setup.cfg", "constraints.txt"),
                r"(?im)^[^#\n]*\bdjango\b"),
    "flask":   (("requirements.txt", "requirements-dev.txt", "pyproject.toml",
                 "Pipfile", "setup.py", "setup.cfg", "constraints.txt"),
                r"(?im)^[^#\n]*\bflask\b"),
    "fastapi": (("requirements.txt", "requirements-dev.txt", "pyproject.toml",
                 "Pipfile", "setup.py", "setup.cfg", "constraints.txt"),
                r"(?im)^[^#\n]*\bfastapi\b"),
    "express": (("package.json",), r"(?i)\"express\"\s*:"),
    "react":   (("package.json",), r"(?i)\"(react|next)\"\s*:"),
    "vue":     (("package.json",), r"(?i)\"(vue|nuxt)\"\s*:"),
    "rails":   (("Gemfile", "Gemfile.lock", "*.gemspec"), r"(?im)^[^#\n]*\brails\b"),
    "laravel": (("composer.json", "composer.lock"), r"(?i)laravel/framework"),
    "symfony": (("composer.json", "composer.lock"), r"(?i)symfony/"),
    "spring":  (("pom.xml", "build.gradle", "build.gradle.kts"),
                r"(?i)springframework|spring-boot"),
}

# A source import is proof the framework is used even when no manifest names
# it, which happens in a vendored tree or a monorepo whose manifest is
# somewhere else.  Only ever used to say present, never to say absent.
FRAMEWORK_IMPORTS = {
    "django":  r"(?m)^\s*(from|import)\s+django\b",
    "flask":   r"(?m)^\s*(from|import)\s+flask\b",
    "fastapi": r"(?m)^\s*(from|import)\s+fastapi\b",
    "express": r"""(?m)require\(\s*['"]express['"]|from\s+['"]express['"]""",
    "react":   r"""(?m)from\s+['"]react['"]|require\(\s*['"]react['"]""",
    "vue":     r"""(?m)from\s+['"]vue['"]|require\(\s*['"]vue['"]""",
    "rails":   r"(?m)^\s*require\s+['\"]rails",
    "laravel": r"(?m)^\s*use\s+Illuminate\\\\",
    "symfony": r"(?m)^\s*use\s+Symfony\\\\",
    "spring":  r"(?m)^\s*import\s+org\.springframework\b",
}

FRAMEWORK_MANIFEST_LIMIT = 400 * 1024


def _framework_evidence(repo_root: str) -> tuple:
    """-> (present, decidable)

    present is every framework this repository can be shown to use.
    decidable is every framework it is safe to have an opinion about at all,
    which means one of its manifests was found and read.  A framework missing
    from decidable is one nobody may rule out.
    """
    present, decidable = set(), set()
    if not repo_root or not os.path.isdir(repo_root):
        return present, decidable

    # Manifests, at the root and one level down, which is where a monorepo
    # keeps them.  Deeper than that and a fixture directory starts voting.
    found: dict = {}
    for depth_root in (repo_root,) + tuple(
            os.path.join(repo_root, name) for name in
            sorted(os.listdir(repo_root))[:80]
            if os.path.isdir(os.path.join(repo_root, name))
            and not name.startswith(".") and name not in SKIP_FRAMEWORK_DIRS):
        try:
            names = os.listdir(depth_root)
        except OSError:
            continue
        for name in names:
            path = os.path.join(depth_root, name)
            if not os.path.isfile(path):
                continue
            try:
                if os.path.getsize(path) > FRAMEWORK_MANIFEST_LIMIT:
                    continue
                with open(path, encoding="utf-8", errors="replace") as handle:
                    found.setdefault(name, []).append(handle.read())
            except OSError:
                continue

    for framework, (manifests, pattern) in FRAMEWORK_MARKERS.items():
        texts = []
        for wanted in manifests:
            if wanted.startswith("*"):
                for name, blobs in found.items():
                    if name.endswith(wanted[1:]):
                        texts.extend(blobs)
            else:
                texts.extend(found.get(wanted, []))
        if not texts:
            continue                      # nothing to read, so no opinion
        decidable.add(framework)
        if any(re.search(pattern, text) for text in texts):
            present.add(framework)

    return present, decidable


def _framework_in_source(repo_root: str, framework: str, limit: int = 3000) -> bool:
    """Does anything in the tree import it.  Only ever answers yes usefully."""
    pattern = FRAMEWORK_IMPORTS.get(framework)
    if not pattern:
        return False
    seen = 0
    for base, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs
                   if d not in SKIP_FRAMEWORK_DIRS and not d.startswith(".")]
        for name in files:
            if not name.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".rb",
                                  ".php", ".java", ".kt", ".vue")):
                continue
            seen += 1
            if seen > limit:
                return False
            text = _read(os.path.join(base, name))
            if text and re.search(pattern, text):
                return True
    return False


def _framework_absent(check_id: str, present: set, decidable: set,
                      repo_root: str, cache: dict):
    """-> a reason this rule does not apply here, or None.

    Reads the framework out of the rule's own namespace, so this covers every
    framework semgrep names without a list of rules to keep up to date.
    """
    parts = [p.lower() for p in str(check_id or "").split(".")]
    for framework in parts:
        if framework not in FRAMEWORK_MARKERS:
            continue
        if framework in present:
            return None
        if framework not in decidable:
            return None               # no manifest was readable: no opinion
        if framework not in cache:
            cache[framework] = _framework_in_source(repo_root, framework)
        if cache[framework]:
            return None               # the manifest missed it, the source did not
        return ("a %s rule, and nothing in this repository uses %s: its "
                "manifests were read and do not name it, and nothing imports "
                "it" % (framework, framework))
    return None

def triage(findings: list, repo_root: str, muted=()) -> list:
    """Add a triage verdict to every finding.  Nothing is removed."""
    muted = tuple(m.strip() for m in (muted or ()) if str(m).strip())
    escapers = _repo_escapers(repo_root)
    corpus = _reference_corpus(repo_root)
    # Worked out once for the repository rather than once per finding: the
    # manifests do not change between two findings in the same tree.
    present, decidable = _framework_evidence(repo_root)
    import_cache: dict = {}
    sources: dict = {}
    for finding in findings:
        path = str(finding.get("path") or "")
        relative = path
        if repo_root and path.startswith(repo_root):
            relative = path[len(repo_root):].lstrip("/")
        full = path if os.path.isabs(path) else os.path.join(repo_root, path)
        if full not in sources:
            sources[full] = _read(full)
        source = sources[full]

        check_id = str(finding.get("check_id") or "")
        rule = check_id.split(".")[-1]
        matched = _matched_text(source, finding)
        verdict, reason, decided_by = judge(
            rule, relative, matched, source,
            finding.get("start", {}).get("line", 0), muted, escapers)

        # Before anything else: is this a file that runs at all.
        #
        # First because it is the widest statement available.  Every other
        # check here reasons about what the code does, and none of that means
        # anything if the file is a transcript of a run rather than a program.
        if verdict == REVIEW:
            not_code = _not_code_at_all("code", relative)
            if not_code:
                verdict = NOT_APPLICABLE
                reason = not_code
                decided_by = "not-code"

        # A subprocess call that never reaches a shell is not command
        # injection, whatever the rule says.  Checked before the framework
        # question because it is the more specific statement: it is about this
        # line rather than about the repository.
        if verdict == REVIEW:
            no_shell = _subprocess_not_a_shell(rule, source,
                                               finding.get("start", {}).get("line", 0))
            if no_shell:
                verdict = NOT_APPLICABLE
                reason = no_shell
                decided_by = "subprocess-not-a-shell"

        # A log line that mentions a credential is not a log line that writes
        # one.  Same placement and the same reason as above: this is a fact
        # about the call on this line, which outranks anything read from the
        # manifests.
        if verdict == REVIEW:
            no_secret = _logger_not_a_secret(rule, source,
                                             finding.get("start", {}).get("line", 0))
            if no_secret:
                verdict = NOT_APPLICABLE
                reason = no_secret
                decided_by = "logger-logs-no-secret"

        # A rule for a framework this repository does not use is not a finding
        # about this repository.  Only where nothing stronger has been said:
        # judge returning anything but review means a fact about the file has
        # already claimed it, and a fact about the file outranks a fact about
        # the manifest.
        if verdict == REVIEW:
            not_here = _framework_absent(check_id, present, decidable,
                                         repo_root, import_cache)
            if not_here:
                verdict = NOT_APPLICABLE
                reason = not_here
                decided_by = "framework-not-used"
        # Two CodeQL questions that need the repository, not just the file.
        if verdict == REVIEW and rule == "js/missing-rate-limiting":
            limited = _codeql_rate_limited(
                repo_root, relative, source,
                finding.get("start", {}).get("line", 0),
                finding.get("end", {}).get("line", 0))
            if limited:
                verdict = NOT_APPLICABLE
                reason = ("the handler, or what it calls, holds callers back "
                          "itself (%s), which CodeQL does not recognize "
                          "because it only knows limiter packages by name"
                          % limited[:60])
                decided_by = "codeql-own-limiter"
        flow = finding.get("flow_source")
        if verdict == REVIEW and rule == "js/unvalidated-dynamic-method-call":
            guard = _codeql_guarded_on_flow(repo_root, flow)
            if guard:
                verdict = NOT_APPLICABLE
                reason = ("the method is looked up after %s, on the way here, "
                          "so it can only be one of the functions in that "
                          "table, never a prototype method" % guard[:120])
                decided_by = "codeql-own-key"
        if verdict == REVIEW and rule == "js/polynomial-redos":
            capped = _codeql_capped_source(repo_root, flow)
            if capped:
                verdict = NOT_APPLICABLE
                reason = ("the input is refused where it comes in when it is "
                          "longer than the cap in %s, and a polynomial regex "
                          "on a string that short finishes at once" % capped)
                decided_by = "codeql-capped-input"
        finding["triage"] = {"verdict": verdict, "reason": reason,
                             "rule": decided_by, "matched": matched[:200]}
        line_no = finding.get("start", {}).get("line", 0)
        if verdict == REVIEW and rule == "js/incomplete-multi-character-sanitization":
            var = _codeql_parser_only(source, line_no)
            if var:
                finding["triage"]["demote"] = {"severity": "low",
                                               "rule": "codeql-parser-only"}
                finding["triage"]["reason"] = (
                    "graded low: %s is only read by this function's own parser "
                    "and never returned or written out, so what is left of a "
                    "stripped comment is not put on a page from here.  What "
                    "the parser extracts from it is worth a look" % var)
                finding["triage"]["rule"] = "codeql-parser-only"
                continue
        if verdict == REVIEW and rule == "js/request-forgery" \
                and _codeql_connect_guard(source):
            finding["triage"]["demote"] = {"severity": "low",
                                           "rule": "codeql-connect-guard"}
            finding["triage"]["reason"] = (
                "graded low: every connection made here resolves through a "
                "lookup that filters the address at connect time, which is the "
                "defense against this and is not something CodeQL models.  "
                "Whether that filter allows the right ranges is the question "
                "to review")
            finding["triage"]["rule"] = "codeql-connect-guard"
            continue
        if verdict == REVIEW and rule in CODEQL_DOS:
            guard = _codeql_privileged_source(repo_root, finding.get("flow_source"))
            if guard:
                finding["triage"]["demote"] = {"severity": "low",
                                               "rule": "codeql-privileged-source"}
                finding["triage"]["reason"] = (
                    "real, but the input only comes from a route behind %s, so "
                    "only somebody already trusted with that can send it" % guard)
                finding["triage"]["rule"] = "codeql-privileged-source"
                continue
        promoted = _promotion(rule, relative, matched, source,
                              finding.get("start", {}).get("line", 0), corpus)
        if promoted:
            finding["triage"]["promote"] = promoted
            continue

        # A demotion only applies where nothing else has already claimed the
        # finding.  judge() returning anything but review means a stronger
        # statement has been made about it already, and a promotion means the
        # opposite statement entirely, so both come first.
        # A hash is a fact about the characters on the line, so it outranks
        # whatever generic verdict the entropy floor arrived at.  Left to
        # itself that floor calls a bcrypt hash "padding rather than a
        # credential", which reaches the right answer with the wrong reason,
        # and the reason is the part somebody reads.
        lines = (source or "").splitlines()
        at = finding.get("start", {}).get("line", 0) or 0
        line_text = lines[at - 1] if 1 <= at <= len(lines) else ""
        demoted = _hash_demotion(rule, matched, line_text)

        # A path is weaker evidence than a verdict somebody's rule already
        # reached, so documentation only speaks when nothing else has.
        if demoted is None and verdict == REVIEW:
            demoted = _documentation_demotion(relative)

        if demoted:
            finding["triage"]["demote"] = {"severity": demoted["severity"],
                                           "rule": demoted["rule"]}
            finding["triage"]["verdict"] = demoted["verdict"]
            finding["triage"]["reason"] = demoted["reason"]
            finding["triage"]["rule"] = demoted["rule"]
    return findings


def main() -> int:
    """Read a semgrep report on stdin or argv[1], write the triaged one out."""
    repo_root = sys.argv[2] if len(sys.argv) > 2 else "."
    # Comma separated, from the scanner config.
    muted = [m for m in (sys.argv[3] if len(sys.argv) > 3 else "").split(",") if m.strip()]
    raw = open(sys.argv[1]).read() if len(sys.argv) > 1 and sys.argv[1] != "-" \
        else sys.stdin.read()
    try:
        document = json.loads(raw or '{"results": []}')
    except ValueError:
        # A broken report must not take the scan down; report it untriaged.
        sys.stderr.write("code_triage: unreadable semgrep output\n")
        sys.stdout.write(raw)
        return 0
    document["results"] = triage(document.get("results", []), repo_root, muted)
    json.dump(document, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
