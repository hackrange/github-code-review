"""What a finding is an example of, in words a reader outside security knows.

A report that lists rule names lists the tool's vocabulary.  "csharp-sqli" and
"formatted-sql-string" and "tainted-sql-string" are one problem written three
ways by three people, and a reader who does not already know that counts them
as three.

So findings are grouped by the weakness they are an instance of.  The engines
already say which one: semgrep and the advisory feeds both carry CWE numbers,
and a CWE is the closest thing this field has to a shared vocabulary.

The names here are deliberately not the official CWE titles.  "Improperly
Controlled Modification of Dynamically-Determined Object Attributes" is
correct and is not a sentence anybody has ever said out loud.  The name is
what a developer would call it, and the official identifier is printed beside
it so nothing is lost.

Each entry also carries what to do about it, because a report that names a
problem and stops has moved the work rather than reduced it.
"""

from __future__ import annotations

import re

# name, what it is, what to do about it.
#
# The list is the common ones rather than all of them.  A weakness nobody in
# this estate has is a row nobody reads, and one that appears once falls back
# to the rule name, which is at least accurate.
CWE_NAMES = {
    "CWE-798": ("Hardcoded credentials",
                "A password, key or token written into the source.",
                "Rotate it, then move it to a secret store or an environment "
                "variable.  Removing it from the file does not remove it from "
                "the history, so rotation comes first."),
    "CWE-321": ("Hardcoded cryptographic key",
                "A key or token used for signing or encryption, written into "
                "the source or into a file committed beside it.",
                "Rotate the key and load it at runtime.  Anything signed with "
                "the old one should be treated as forgeable."),
    "CWE-259": ("Hardcoded password",
                "A password written into the source.",
                "Rotate it and load it from configuration."),
    "CWE-89":  ("SQL injection",
                "A database query built by joining strings together, where "
                "part of the string can come from outside.",
                "Use parameters rather than string joining.  The database "
                "then treats the value as a value and never as syntax."),
    "CWE-79":  ("Cross site scripting",
                "Text from outside reaching a page without being escaped, so "
                "it can be read as markup instead of as text.",
                "Escape on output, and prefer a template that escapes by "
                "default over remembering to do it each time."),
    "CWE-78":  ("Command injection",
                "A system command built from a string where part of it can "
                "come from outside.",
                "Pass the arguments as a list and do not involve a shell.  "
                "Then a metacharacter in a value is just a character."),
    "CWE-22":  ("Path traversal",
                "A file path built from something supplied from outside, "
                "which can be made to point somewhere else.",
                "Resolve the path and check it is inside the directory you "
                "meant, after resolving rather than before."),
    "CWE-611": ("XML external entities",
                "An XML parser that will fetch and include whatever the "
                "document tells it to.",
                "Turn off external entities and document type declarations in "
                "the parser."),
    "CWE-502": ("Unsafe deserialization",
                "Rebuilding an object from data that came from outside, which "
                "can be made to run code while it is being read.",
                "Use a data format that cannot carry code, and validate the "
                "shape before using it."),
    "CWE-319": ("Cleartext transmission",
                "Something sent over a connection that is not encrypted.",
                "Use https or the encrypted form of the protocol.  Where the "
                "link is to a static asset the risk is lower, but a mixed "
                "page is still a weakened page."),
    "CWE-327": ("Weak cryptography",
                "An algorithm that is no longer considered strong enough.",
                "Move to a current algorithm.  The specific replacement "
                "depends on what it is used for."),
    "CWE-330": ("Weak randomness",
                "Random values produced by a generator that is predictable, "
                "used somewhere the value needs to be unguessable.",
                "Use the platform's cryptographic random source for anything "
                "that is a token, a key or an identifier."),
    "CWE-353": ("Missing integrity check",
                "Something loaded without any way to tell whether it is what "
                "was expected, usually a script from another origin.",
                "Add an integrity attribute, or host the file yourself.  It "
                "matters most where the other origin is outside your control."),
    "CWE-1357": ("Reliance on an uncontrolled component",
                 "Depending on something whose contents can change without "
                 "notice, such as a mutable tag or an unpinned action.",
                 "Pin it to a digest or an exact version, so what runs "
                 "tomorrow is what you reviewed today."),
    "CWE-1333": ("Inefficient regular expression",
                 "A pattern that can be made to take a very long time on a "
                 "short input, which is a way to exhaust a server.",
                 "Rewrite the pattern to remove the nested repetition, or put "
                 "a limit on the input it runs against."),
    "CWE-915": ("Object attribute injection",
                "Copying fields from outside onto an object without deciding "
                "which fields are allowed, which can change how it behaves.",
                "Copy the fields you meant, by name, rather than everything "
                "the input happens to carry."),
    "CWE-352": ("Cross site request forgery",
                "An action that can be triggered by another site because "
                "nothing proves the request came from yours.",
                "Require a token on anything that changes state, and check it "
                "on the server."),
    "CWE-287": ("Broken authentication",
                "A weakness in how the system decides who somebody is.",
                "Depends on the specific finding, and it is worth a person "
                "reading each of these rather than a blanket change."),
    "CWE-863": ("Broken authorization",
                "A weakness in how the system decides what somebody may do.",
                "Check the permission where the action happens, not only "
                "where the button is drawn."),
    "CWE-16":  ("Unsafe configuration",
                "A setting that leaves something more exposed than it needs "
                "to be.",
                "Change the setting in the infrastructure files and redeploy."),
    "CWE-732": ("Over permissive access",
                "Something readable or writable by more people than need it.",
                "Narrow it to what actually needs the access."),
    "CWE-295": ("Certificate validation disabled",
                "A connection that does not check the certificate it is "
                "given, so it cannot tell who it is talking to.",
                "Turn validation back on.  Where a self signed certificate is "
                "involved, trust that certificate specifically rather than "
                "turning off the check."),
    "CWE-94":  ("Code injection",
                "Text from outside being executed as code.",
                "Remove the dynamic execution.  Where it cannot be removed, "
                "restrict it to a fixed set of expressions."),
    "CWE-434": ("Unrestricted upload",
                "Accepting a file without deciding what kinds are allowed.",
                "Decide what is allowed by content rather than by the name "
                "the uploader chose, and store it outside the web root."),
    "CWE-209": ("Information in an error message",
                "An error that tells the caller more about the system than it "
                "should.",
                "Log the detail and return something plain."),
    "CWE-117": ("Log injection",
                "Text from outside written into a log without being cleaned, "
                "which can forge entries.",
                "Strip newlines and control characters before logging."),
    "CWE-400": ("Uncontrolled resource use",
                "Work that can be made arbitrarily large by whoever asks for "
                "it.",
                "Put a bound on it: a size, a depth or a timeout."),
    "CWE-346": ("Missing origin check",
                "A message accepted from another window or frame without "
                "checking where it came from.",
                "Check the origin against the one you expect before acting on "
                "the message, and do not accept a wildcard."),
    "CWE-470": ("Unsafe reflection",
                "Choosing which class or method to run from a value that can "
                "come from outside.",
                "Map the input to a fixed set of allowed choices rather than "
                "using it to look one up."),
    "CWE-20":  ("Incomplete input handling",
                "Input checked or cleaned in a way that misses cases, such as "
                "replacing only the first occurrence of something.",
                "Handle every occurrence, and prefer a library that does the "
                "cleaning over doing it by hand."),
    "CWE-250": ("Running with more privilege than needed",
                "A process or container running as a more powerful user than "
                "the work requires.",
                "Run as an unprivileged user.  In a container that is a USER "
                "line; elsewhere it is the account the service starts under."),
    "CWE-1104": ("Unmaintained dependency",
                 "A component that is no longer receiving fixes.",
                 "Move to a maintained alternative, or take on maintaining "
                 "it deliberately rather than by default."),
}

# What a finding is, when the rule name is a detector or an advisory number
# rather than a description.
#
# A credential scanner names its rules after the service it recognizes: jwt,
# snyk-key, polygon, box.  Those are useful names for the detector and useless
# as a category, because the reader gets one heading per service and no idea
# that they are all the same problem.  Every one of them is a credential in
# the source, which is what the kind already says.
#
# A dependency finding is named after the advisory, and there are eighteen
# thousand of those.  Grouped by rule name that is eighteen thousand
# categories of one, which is the worst possible grouping: it is a list
# pretending to be a summary.  What they have in common is the thing to do
# about them, and the section on the largest updates already says which
# package.
BY_KIND = {
    "credential": ("CWE-798", "Hardcoded credentials",
                   "A password, key or token found in the source or in its "
                   "history.  The detector names the service it recognized; "
                   "the problem is the same whichever it is.",
                   "Rotate it first, then remove it.  Taking it out of the "
                   "file does not take it out of the history, and anyone who "
                   "cloned the repository already has it."),
    "dependency": ("dependency", "Known vulnerability in a dependency",
                   "A published advisory against a version of a package this "
                   "code depends on.",
                   "Upgrade the package.  One upgrade usually answers several "
                   "advisories, and the largest of those are listed "
                   "separately in this report."),
}


# Where no CWE is carried, the rule name usually says what it is.  These are
# the families seen most often, matched loosely because engines spell them
# differently.
RULE_FAMILIES = (
    (r"sqli|sql-string|sql_injection", "CWE-89"),
    (r"xss|cross-site-script", "CWE-79"),
    (r"command-inject|shell-inject|exec-inject|os-command", "CWE-78"),
    (r"path-travers|zip-slip|directory-travers", "CWE-22"),
    (r"deserial|pickle|unmarshal", "CWE-502"),
    (r"hardcod|secret|api[-_]?key|password|token|credential", "CWE-798"),
    (r"http-link|cleartext|insecure-transport", "CWE-319"),
    (r"weak-(hash|cipher|crypto)|md5|sha1\b", "CWE-327"),
    (r"random|entropy", "CWE-330"),
    (r"integrity|subresource", "CWE-353"),
    (r"mutable|unpinned|floating-tag", "CWE-1357"),
    (r"regex|redos", "CWE-1333"),
    (r"prototype-pollution", "CWE-915"),
    (r"csrf|antiforgery|xsrf", "CWE-352"),
    (r"cert.*valid|verify=false|insecure-ssl", "CWE-295"),
    (r"eval|code-inject", "CWE-94"),
    (r"autoescape|template-inject", "CWE-79"),
    (r"reflection|unsafe-reflect", "CWE-470"),
    (r"postmessage|origin-validation|cors", "CWE-346"),
    (r"incomplete-sanitiz|incomplete-clean|partial-escape", "CWE-20"),
    (r"excessive-permission|overly-broad|over-permissive", "CWE-732"),
    (r"artipacked|credential-persist", "CWE-798"),
    # Container image rules, which are named by their checker rather than by
    # what they are about.
    (r"^ds-0002$|user-should-not-be-root|runs-as-root", "CWE-250"),
)


def _first_cwe(value: str) -> str:
    """The first CWE on a finding.  Several is common and the first decides."""
    for piece in str(value or "").split(","):
        piece = piece.strip().upper()
        if piece.startswith("CWE-"):
            return piece
        if piece.isdigit():
            return "CWE-" + piece
    return ""


# An advisory number is an identifier, not a description.
ADVISORY_ID = re.compile(r"^(?:CVE|GHSA|PYSEC|RUSTSEC|OSV|GO|MAL|SNYK)-", re.I)


def classify(cwe: str, rule: str = "", kind: str = "") -> tuple:
    """-> (key, name, what it is, what to do).

    In order: the CWE where there is one, the rule family where the name gives
    it away, and then what the kind of finding already tells us.  That last
    step matters more than it looks.  A credential detector is named after the
    service it recognized and a dependency finding after the advisory, so
    grouping either by rule name produces one heading per service or one per
    advisory, which is a list wearing a summary's clothes.

    Only after all of that does a finding keep its own rule name.  That is
    still better than a guess: an accurate name nobody recognizes can be
    looked up, and a wrong category cannot be unlearned.
    """
    identifier = _first_cwe(cwe)
    if identifier in CWE_NAMES:
        name, what, todo = CWE_NAMES[identifier]
        return identifier, name, what, todo

    lowered = (rule or "").lower()
    for pattern, mapped in RULE_FAMILIES:
        if re.search(pattern, lowered) and mapped in CWE_NAMES:
            name, what, todo = CWE_NAMES[mapped]
            return mapped, name, what, todo

    # What the kind of finding says, for the two kinds whose rule names are
    # identifiers rather than descriptions.
    kind_key = str(kind or "").lower().rsplit(".", 1)[-1]
    if kind_key in BY_KIND and (not rule or ADVISORY_ID.match(rule)
                                or kind_key == "credential"):
        return BY_KIND[kind_key]

    if identifier:
        return identifier, identifier, "", ""
    if rule:
        return "rule:" + rule, rule, "", ""
    return "other", "Other", "", ""
