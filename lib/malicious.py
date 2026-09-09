#!/usr/bin/env python3
"""Packages that are malicious rather than vulnerable.

Everything else in the dependency pass is CVE first.  A typosquat, a dependency
confusion package and a compromised maintainer's release have no CVE until well
after they have run, so a tree can look completely clean while the attack is
sitting in it.

Two halves, and this is the offline one.  The other half is the OSV feed, which
already reaches this tool through osv-scanner: OpenSSF publishes MAL advisories
into OSV, so a package somebody has already reported comes back with the rest
of the advisories and only has to be recognised.  What is here is the set of
questions that can only be answered while the checkout is on disk, which is the
same reason triage runs where it does.

  An install hook that fetches and runs something.  Whatever else a postinstall
  script is for, `curl | sh` in one is how most of these actually execute.

  A source that is not a registry.  A dependency pointed at a git URL or a
  tarball over plain HTTP is not covered by any registry's controls.

  A specifier that floats.  `*` or `latest` on a package means the next install
  takes whatever was published last, which is what turns one compromised
  release into everybody's problem.

  A name one edit away from a popular one.  Typosquatting, checked against the
  packages actually worth squatting rather than against the whole registry, and
  minus the real packages that happen to live next door to a famous one.

Nothing here is certain, and none of it is graded critical on its own.  A
finding says which signal fired and what the evidence was, so somebody can look
at the line and disagree.
"""

from __future__ import annotations

import json
import os
import re
import sys

# What a malicious signal is worth.  A published advisory is a fact; the rest
# are reasons to look, and grading them as facts is how a list stops being read.
CONFIRMED = "confirmed"
SUSPICIOUS = "suspicious"

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "third_party",
             "site-packages", "dist", "build", ".terraform", "__pycache__"}
MAX_FILES = 20000
MAX_FILE_BYTES = 1024 * 1024

# Fetch something and run it.  The individual pieces are ordinary; together in
# an install hook they are the shape of the thing.
FETCH_AND_RUN = re.compile(
    r"(curl|wget)\b[^\n|;&]{0,200}(\||\bsh\b|\bbash\b|-o\s|\bnode\b|\bpython)"
    r"|\bbase64\s+(-d|--decode)"
    r"|\beval\s*\("
    r"|\bnode\s+-e\b|\bpython\s+-c\b"
    r"|child_process|require\(['\"]https?['\"]\)"
    r"|\.decode\(['\"]base64['\"]\)"
    r"|/dev/tcp/", re.I)

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare",
                 "preprepare", "postprepare")

# A dependency that does not come from a registry.
NOT_A_REGISTRY = re.compile(
    r"^(git\+|git:|https?://|file:|link:|github:|bitbucket:|gitlab:)", re.I)

# A specifier that resolves to whatever was published most recently.
FLOATING = re.compile(r"^\s*(\*|latest|x|>=?\s*0|\^?0\.0\.0)\s*$", re.I)

# The names worth squatting.  A short list on purpose: edit distance against a
# whole registry produces noise, and these are the packages an attacker
# actually targets because everybody installs them.
POPULAR = {
    "npm": ["react", "lodash", "express", "axios", "chalk", "commander",
            "debug", "moment", "request", "async", "webpack", "babel",
            "typescript", "eslint", "jest", "dotenv", "uuid", "yargs",
            "colors", "cross-env", "node-fetch", "socket.io", "mongoose",
            "bluebird", "underscore", "jquery", "vue", "angular", "next",
            "redux", "rxjs", "socket", "ws", "body-parser", "cookie-parser"],
    "python": ["requests", "urllib3", "numpy", "pandas", "django", "flask",
               "boto3", "setuptools", "six", "pyyaml", "click", "jinja2",
               "cryptography", "certifi", "colorama", "pytest", "scipy",
               "matplotlib", "beautifulsoup4", "selenium", "pillow", "tensorflow",
               "torch", "sqlalchemy", "psycopg2", "redis", "celery"],
}


# The neighbors that are not squatting anybody.  Each of these is a real
# package that happens to sit one edit from a famous name, usually because the
# same people published both.  Keyed by the famous name, so an entry says who
# the package was being mistaken for.
KNOWN_GOOD = {
    "npm": {
        "vue": {"vuex"},
        "react": {"preact"},
        "next": {"nuxt", "nest"},
        "colors": {"color"},
        "uuid": {"uid"},
        # Two letters is too short for one edit to mean anything, and a lot of
        # the small names in a node tree land next to ws.
        "ws": {"ms", "qs", "fs", "os", "js", "es", "vs", "cs", "bs"},
    },
    "python": {
        "scipy": {"scapy"},
        "psycopg2": {"psycopg"},
        "boto3": {"boto"},
        "pandas": {"panda"},
    },
}


def _read(path: str) -> str:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _walk(root: str):
    seen = 0
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            seen += 1
            if seen > MAX_FILES:
                return
            full = os.path.join(base, name)
            yield full, os.path.relpath(full, root)


def edit_distance_one(a: str, b: str) -> bool:
    """Whether one name is a single edit from the other.

    Cheap on purpose: this is asked once per dependency against a few dozen
    names, and a full distance matrix would be the slowest thing in the scan
    for no extra answer.
    """
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        if diffs == 1:
            return True
        # A transposition reads as two substitutions and is the commonest typo
        # of all, so it is worth the extra comparison.
        if diffs == 2:
            pairs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
            i, j = pairs
            return j == i + 1 and a[i] == b[j] and a[j] == b[i]
        return False
    longer, shorter = (a, b) if la > lb else (b, a)
    for cut in range(len(longer)):
        if longer[:cut] + longer[cut + 1:] == shorter:
            return True
    return False


def typosquat_of(name: str, ecosystem: str) -> str:
    """The popular name this one is a single edit from, or "" for nothing.

    Sitting next to something famous is not proof on its own.  Vuex is one
    character off vue because the Vue team named it that, and reporting it
    every scan costs more than it ever finds.
    """
    lowered = name.lower()
    safe = KNOWN_GOOD.get(ecosystem, {})
    for popular in POPULAR.get(ecosystem, []):
        if not edit_distance_one(lowered, popular):
            continue
        if lowered in safe.get(popular, ()):
            continue
        return popular
    return ""


def _finding(name, version, eco, signal, confidence, reason, evidence, where):
    return {
        "package": name, "version": version or "", "ecosystem": eco,
        "signal": signal, "confidence": confidence, "reason": reason,
        "evidence": (evidence or "")[:300], "manifest": where,
    }


def check_npm(document: dict, rel: str) -> list:
    out = []
    scripts = document.get("scripts") or {}
    for hook in INSTALL_HOOKS:
        body = scripts.get(hook)
        if not isinstance(body, str):
            continue
        hit = FETCH_AND_RUN.search(body)
        if hit:
            out.append(_finding(
                document.get("name") or rel, document.get("version"), "npm",
                "install-hook", SUSPICIOUS,
                f"the {hook} script fetches or evaluates something at install "
                "time, which is where most supply chain attacks actually run",
                body, rel))

    for key, scope in (("dependencies", "runtime"),
                       ("devDependencies", "development"),
                       ("optionalDependencies", "optional")):
        for name, spec in (document.get(key) or {}).items():
            if not isinstance(spec, str):
                continue
            if NOT_A_REGISTRY.match(spec):
                out.append(_finding(
                    name, spec, "npm", "not-a-registry", SUSPICIOUS,
                    "this dependency does not come from the registry, so none "
                    "of the registry's controls apply to it",
                    f"{name}: {spec}", rel))
            elif FLOATING.match(spec):
                out.append(_finding(
                    name, spec, "npm", "floating-version", SUSPICIOUS,
                    "the version floats, so the next install takes whatever "
                    "was published most recently",
                    f"{name}: {spec} ({scope})", rel))
            popular = typosquat_of(name, "npm")
            if popular:
                out.append(_finding(
                    name, spec, "npm", "typosquat", SUSPICIOUS,
                    f"one character away from {popular}, which is what a "
                    "typosquat looks like",
                    f"{name} against {popular}", rel))
    return out


def check_python(text: str, rel: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            continue
        if NOT_A_REGISTRY.match(line):
            out.append(_finding(
                line.split("#")[0].strip()[:120], "", "python",
                "not-a-registry", SUSPICIOUS,
                "this requirement is fetched from a URL rather than the index, "
                "so nothing the index does applies to it",
                line, rel))
            continue
        match = re.match(r"^([A-Za-z0-9._-]+)\s*(.*)$", line)
        if not match:
            continue
        name, spec = match.group(1), match.group(2).strip()
        if not spec or spec in ("*",):
            # Unpinned is normal in python and not worth a finding on its own.
            pass
        popular = typosquat_of(name, "python")
        if popular:
            out.append(_finding(
                name, spec, "python", "typosquat", SUSPICIOUS,
                f"one character away from {popular}, which is what a "
                "typosquat looks like",
                f"{name} against {popular}", rel))
    return out


def check_setup_py(text: str, rel: str) -> list:
    """A setup.py runs on install, the same way a postinstall script does."""
    hit = FETCH_AND_RUN.search(text)
    if not hit:
        return []
    line = text[:hit.start()].count("\n") + 1
    return [_finding(
        os.path.dirname(rel) or rel, "", "python", "install-hook", SUSPICIOUS,
        "setup.py fetches or evaluates something, and it runs on install",
        text[max(0, hit.start() - 60):hit.end() + 60], f"{rel}:{line}")]


def scan(root: str) -> list:
    """Every signal in the checkout, one entry each."""
    out = []
    for full, rel in _walk(root):
        base = os.path.basename(full).lower()
        if base == "package.json":
            try:
                document = json.loads(_read(full) or "null")
            except ValueError:
                continue
            if isinstance(document, dict):
                out.extend(check_npm(document, rel))
        elif base.startswith("requirements") and base.endswith(".txt"):
            out.extend(check_python(_read(full), rel))
        elif base == "setup.py":
            out.extend(check_setup_py(_read(full), rel))

    # The same signal on the same package in the same file, once.
    seen, unique = set(), []
    for row in out:
        key = (row["package"], row["signal"], row["manifest"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: malicious.py <repo_root>\n")
        return 2
    json.dump(scan(sys.argv[1]), sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
