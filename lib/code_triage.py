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


def triage(findings: list, repo_root: str, muted=()) -> list:
    """Add a triage verdict to every finding.  Nothing is removed."""
    muted = tuple(m.strip() for m in (muted or ()) if str(m).strip())
    escapers = _repo_escapers(repo_root)
    corpus = _reference_corpus(repo_root)
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

        rule = str(finding.get("check_id") or "").split(".")[-1]
        matched = _matched_text(source, finding)
        verdict, reason, decided_by = judge(
            rule, relative, matched, source,
            finding.get("start", {}).get("line", 0), muted, escapers)
        finding["triage"] = {"verdict": verdict, "reason": reason,
                             "rule": decided_by, "matched": matched[:200]}
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
