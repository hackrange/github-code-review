"""What a security report knows about the product before it grades anything.

A finding is real only when the code or package is in what ships, can be
reached, and can be reached by someone who should not cause the harm.  Most
of the wrong grades in a review come from not knowing the product: a Python
rule run on a PHP repository, a package version read from the base image
when the build upgrades it, an advisory about an Apache module the image
never loads.  This works out the facts that settle those questions, from the
checkout, in code, so the model is handed them instead of guessing, and so
the plainest ones are decided here without asking it at all.

Nothing here asks a model, and nothing leaves the checkout but short facts:
file names, the lines that name a base image, and yes or no answers.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.diagram import mask

# Extensions to the language they are written in.  Only languages a rule
# pack is named after, so a rule's language can be checked against them.
LANGUAGES = {
    ".py": "python", ".php": "php", ".js": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala", ".go": "go", ".rb": "ruby", ".cs": "csharp", ".rs": "rust",
    ".swift": "swift", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
}

# A framework is present when one of these is true of the checkout: a file
# with this name exists, or a build file mentions the package.
FRAMEWORKS = {
    "django": {"files": ("manage.py",), "words": ("django",)},
    "flask": {"files": (), "words": ("flask",)},
    "fastapi": {"files": (), "words": ("fastapi",)},
    "rails": {"files": ("config/routes.rb",), "words": ("rails",)},
    "spring": {"files": (), "words": ("spring-boot", "springframework")},
    "express": {"files": (), "words": ('"express"',)},
    "laravel": {"files": ("artisan",), "words": ("laravel/framework",)},
    "symfony": {"files": ("bin/console",), "words": ("symfony/framework-bundle",)},
    "react": {"files": (), "words": ('"react"',)},
    "angular": {"files": ("angular.json",), "words": ("@angular/core",)},
    "vue": {"files": (), "words": ('"vue"',)},
    "next": {"files": ("next.config.js", "next.config.mjs", "next.config.ts"),
             "words": ('"next"',)},
    "mule": {"files": ("mule-artifact.json",), "words": ()},
}
BUILD_FILES = ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py",
               "package.json", "composer.json", "pom.xml", "build.gradle",
               "build.gradle.kts", "go.mod", "Cargo.toml", "Gemfile", "Gemfile.lock")

# Rule pack prefixes (semgrep and the like name rules language.framework.…)
# and what must be in the repository for a rule from that pack to apply.
RULE_LANGUAGES = {
    "python": ("python",), "php": ("php",), "javascript": ("javascript", "typescript"),
    "typescript": ("typescript", "javascript"), "java": ("java", "kotlin", "scala"),
    "kotlin": ("kotlin", "java"), "scala": ("scala", "java"), "go": ("go",),
    "ruby": ("ruby",), "csharp": ("csharp",), "rust": ("rust",), "swift": ("swift",),
    "c": ("c", "cpp"), "cpp": ("cpp", "c"),
}

# The same words lib/images.sh looks for.  What sits between the tool and its
# verb is read up to the end of the command, because real options such as
# -o Dpkg::Options::=--force-confold do not fit a list of option shapes.  The
# verb must stand alone, so --only-upgrade foo and update-motd do not count.
_UPGRADE = re.compile(
    r"\b(?:apt-get|apt)\b[^;&|\n]*?\s(?:dist-|full-)?upgrade(?=[\s;&|]|$)"
    r"|\b(?:dnf|yum|microdnf)\b[^;&|\n]*?\s(?:update|upgrade|distro-sync)(?=[\s;&|]|$)"
    r"|\bzypper\b[^;&|\n]*?\s(?:update|up|dup|dist-upgrade)(?=[\s;&|]|$)"
    r"|\bapk\b[^;&|\n]*?\supgrade(?=[\s;&|]|$)"
    r"|\bpacman\s+[-\w]*Syu", re.IGNORECASE)
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?",
                   re.IGNORECASE)
# One CSP directive: its name and its sources, up to the ; or the end of the
# string or line that holds it.
_DIRECTIVE = re.compile(r"(?<![\w-])(script-src(?:-elem)?|default-src)\b([^;\"`\n]*)",
                        re.IGNORECASE)
_COMMENT = re.compile(r"^\s*(?:#|//|/?\*|<!--)")
_ELEVATED = re.compile(
    r"^\s*(privileged:\s*true|network_mode:\s*[\"']?host|cap_add:.*SYS_ADMIN"
    r"|-\s*[\"']?/var/run/docker\.sock)", re.IGNORECASE)
MAX_FILES = 20_000
MAX_READ = 400_000


def _read(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        return path.read_text("utf-8", "replace")[:MAX_READ]
    except OSError:
        return ""


def _skip(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in ("node_modules", "vendor", ".git", "dist", "build", "target",
                     "__pycache__", ".venv", "venv") for p in parts)


def build(root, paths=None) -> dict:
    """The product profile of a checkout.  {} when there is no checkout.

    paths is the list of files in it, relative and with forward slashes, when
    the caller already walked it.
    """
    if root is None:
        return {}
    root = Path(root)
    if paths is None:
        paths = []
        for p in root.rglob("*"):
            if len(paths) >= MAX_FILES:
                break
            if ".git" in p.parts or not p.is_file():
                continue
            paths.append(str(p.relative_to(root)).replace("\\", "/"))
    files = set(paths)

    counts, present = {}, set()
    for rel in paths:
        language = LANGUAGES.get(Path(rel).suffix.lower())
        if not language:
            continue
        # Every language in the checkout, vendored copies included, decides
        # whether a rule can apply: a rule that matched a vendored file did
        # match a file in that language.  The shown list leaves them out.
        present.add(language)
        if not _skip(rel):
            counts[language] = counts.get(language, 0) + 1
    languages = [name for name, _ in sorted(counts.items(), key=lambda kv: -kv[1])]

    build_text = ""
    build_seen = []
    for rel in sorted(files):
        if _skip(rel) or Path(rel).name not in BUILD_FILES:
            continue
        build_seen.append(rel)
        build_text += _read(root / rel).lower() + "\n"
        if len(build_seen) >= 40:
            break
    frameworks = []
    for name, marks in FRAMEWORKS.items():
        if (any(f in files or any(p.endswith("/" + f) for p in files)
                for f in marks["files"])
                or any(w in build_text for w in marks["words"])):
            frameworks.append(name)

    dockerfiles = []
    for rel in sorted(files):
        name = Path(rel).name.lower()
        if _skip(rel) or not (name == "dockerfile" or name.startswith("dockerfile.")
                              or name.endswith(".dockerfile")):
            continue
        # Line continuations folded first: nearly every upgrade is the second
        # half of a chained RUN, and a line by line read misses it.
        text = re.sub(r"\\[ \t]*\r?\n", " ", _read(root / rel))
        stages = []
        for line in text.splitlines():
            m = _FROM.match(line)
            if m:
                stages.append({"ref": m.group(1), "alias": (m.group(2) or "").lower(),
                               "upgrades": False})
            elif stages and not _COMMENT.match(line) and _UPGRADE.search(line):
                stages[-1]["upgrades"] = True
        # What ships is the last stage.  Its base may be another stage, so
        # the chain is followed to the image it rests on, and an upgrade
        # anywhere along it counts, the same way lib/images.sh reads it.
        ships, upgraded = "", False
        if stages:
            by_alias = {s["alias"]: i for i, s in enumerate(stages) if s["alias"]}
            index, seen = len(stages) - 1, set()
            while index not in seen:
                seen.add(index)
                upgraded = upgraded or stages[index]["upgrades"]
                parent = by_alias.get(stages[index]["ref"].lower())
                if parent is None or parent == index:
                    ships = stages[index]["ref"]
                    break
                index = parent
        dockerfiles.append({"file": rel,
                            # An image reference can carry a registry login;
                            # masked like every other line that leaves the checkout.
                            "from": [mask(s["ref"])[:200] for s in stages[:6]],
                            "multi_stage": len(stages) > 1, "upgrades": upgraded,
                            "ships": ships.lower()})
        if len(dockerfiles) >= 10:
            break

    elevated = []
    for rel in sorted(files):
        name = Path(rel).name.lower()
        if _skip(rel) or not (name.startswith(("docker-compose", "compose"))
                              and name.endswith((".yml", ".yaml"))):
            continue
        for n, line in enumerate(_read(root / rel).splitlines(), start=1):
            if _ELEVATED.match(line):
                elevated.append(f"{rel}:{n} {mask(line.strip())[:80]}")
        if len(elevated) >= 10:
            break

    # A Content-Security-Policy set anywhere in the code or server config,
    # and whether any of them really lets inline script run.
    csp, unsafe_inline, where, nonce = False, False, "", False
    for rel in paths:
        if _skip(rel) or Path(rel).suffix.lower() not in (
                ".php", ".py", ".js", ".ts", ".conf", ".java", ".rb", ".cs", ".go",
                ".json", ".yml", ".yaml", ".xml", ".htaccess", ".html", ".htm", ""):
            continue
        text = _read(root / rel)
        if "content-security-policy" not in text.lower():
            continue
        csp = True
        found, at, uses_nonce = _inline_script(text)
        nonce = nonce or uses_nonce
        if found:
            unsafe_inline, where = True, f"{rel}:{at}"
            break

    return {"languages": languages[:8], "present": sorted(present),
            "frameworks": frameworks,
            "build_files": build_seen[:12], "dockerfiles": dockerfiles,
            "elevated_containers": elevated,
            "csp": ("none found" if not csp else
                    f"set, allows inline script ({where})" if unsafe_inline else
                    "set, script-src uses a nonce or hash and allows no inline "
                    "script" if nonce else
                    "set, no 'unsafe-inline' for scripts found"),
            "has_github_workflows": any(p.startswith(".github/workflows/") for p in files)}


def _inline_script(text: str) -> tuple:
    """Does a policy in this file let inline script run.  -> (yes, line, nonce)

    Only the script-src directive decides it, or default-src when the file
    sets no script-src at all.  'unsafe-inline' under style-src is about
    styles, and a browser ignores it under script-src whenever a nonce or a
    hash is also listed there.  A policy built across several lines of code
    is read directive by directive, so one line holding style-src
    'unsafe-inline' and script-src 'nonce-...' is not misread as unsafe.
    Commented out lines are not policies.
    """
    has_script_src = bool(re.search(r"(?<![\w-])script-src", text, re.IGNORECASE))
    nonce = False
    for n, line in enumerate(text.splitlines(), start=1):
        if _COMMENT.match(line):
            continue
        for name, sources in _DIRECTIVE.findall(line):
            name, low = name.lower(), sources.lower()
            if name == "default-src" and has_script_src:
                continue
            keyed = any(k in low for k in ("'nonce-", "'sha256-", "'sha384-",
                                           "'sha512-", "'strict-dynamic'"))
            nonce = nonce or (keyed and name != "default-src")
            if "'unsafe-inline'" in low and not keyed:
                return True, n, nonce
    return False, 0, nonce


def upgraded_base(profile: dict, image_ref: str) -> str:
    """The Dockerfile that ships image_ref as its base and upgrades it, or "".

    A scanner reads package versions from the base image in the registry.
    When the build upgrades that image after pulling it, those versions are
    not the ones that ship (report check 1).
    """
    ref = (image_ref or "").strip().lower()
    if not profile or not ref:
        return ""
    for d in profile.get("dockerfiles") or []:
        if d.get("upgrades") and d.get("ships") and d["ships"] == ref:
            return d["file"]
    return ""


def as_text(profile: dict, fork_of: str = "", code: bool = True) -> str:
    """The profile as lines for a prompt.  "" when there is none.

    code is whether code may be sent at all.  Without it the compose lines
    are named by file and line only.
    """
    if not profile:
        return ""
    lines = ["Languages (by file count): " + (", ".join(profile["languages"]) or "none found"),
             "Frameworks found: " + (", ".join(profile["frameworks"]) or "none found"),
             "Build files: " + (", ".join(profile["build_files"]) or "none found")]
    for d in profile["dockerfiles"]:
        lines.append(f"Dockerfile {d['file']}: FROM {' then '.join(d['from']) or 'none'}"
                     + ("; multi stage, only the last stage ships" if d["multi_stage"] else "")
                     + ("; upgrades its packages after FROM, so the base image's "
                        "package versions are not the shipped versions"
                        if d["upgrades"] else ""))
    if profile["elevated_containers"]:
        shown = (profile["elevated_containers"] if code else
                 [e.split(" ", 1)[0] for e in profile["elevated_containers"]])
        lines.append("Elevated container settings: " + "; ".join(shown))
    lines.append(f"Content-Security-Policy: {profile['csp']}")
    if fork_of:
        lines.append(f"This repository is a copy of {fork_of}.  Files added only in "
                     "this copy are not part of that product.")
    return "\n".join(lines)


def rule_mismatch(rule: str, profile: dict) -> str:
    """Why a rule cannot apply to this repository, or "".

    A rule pack is named for a language and often a framework.  A Python rule
    on a repository with no Python, or a Django rule where Django is not used,
    is a false positive whatever it matched.  Only rules named the usual way
    are judged; anything else is left to the review.
    """
    if not profile or not rule:
        return ""
    parts = rule.lower().split(".")
    if len(parts) < 3:
        return ""
    language, framework = parts[0], parts[1]
    needs = RULE_LANGUAGES.get(language)
    if not needs:
        return ""
    if not any(n in profile.get("present", profile["languages"]) for n in needs):
        return (f"The rule is written for {language} code, and this repository has no "
                f"{language} files.")
    if framework in FRAMEWORKS and framework not in profile["frameworks"]:
        return (f"The rule is written for the {framework} framework, which this "
                "repository does not use.")
    return ""
