"""Pull the JavaScript out of HTML pages so it can be analysed as JavaScript.

semgrep does not read inside a <script> block.  It parses HTML and it parses
JavaScript, and a page with both gets the HTML rules only - so a cross site
scripting bug written in a page rather than in a module is invisible, which is
exactly where this kind of bug tends to live.  semgrep had an extract mode for
this once and it was removed, so the extraction happens here.

Each block is written out as its own file, and the manifest records which page
it came from and how far down it started, so a finding can be reported against
the line of the page a person would open rather than the line of a temporary
file nobody will ever see.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Blocks that are not JavaScript.  A JSON-LD block or a templating language is
# not code this can reason about, and feeding it to a JavaScript parser
# produces noise rather than findings.
NOT_JS = re.compile(r'type\s*=\s*["\']?(?!text/javascript|application/javascript|module)',
                    re.IGNORECASE)
# A block with a src attribute has no body worth reading; the file it names is
# scanned on its own if it is in the repository.
HAS_SRC = re.compile(r'\bsrc\s*=', re.IGNORECASE)
OPEN = re.compile(r'<script\b([^>]*)>', re.IGNORECASE)
CLOSE = re.compile(r'</script\s*>', re.IGNORECASE)

# A page bigger than this is generated, minified, or both.  Neither is worth
# the parse.
MAX_BYTES = 2_000_000

PAGES = (".html", ".htm")
# Server templates.  Their script blocks are where most DOM cross site
# scripting lives in a PHP, JSP, ERB or Razor application, and nothing read
# them.  They go to their own directory, because the server tags inside them
# have to be stood in for, and only this project's own rules are run there:
# the broad registry packs report every innerHTML in a template, which is the
# noise the curated rules exist to avoid.
TEMPLATES = (".php", ".phtml", ".jsp", ".jspx", ".erb", ".cshtml", ".vbhtml",
             ".aspx", ".ascx", ".twig", ".jinja", ".jinja2", ".j2", ".hbs",
             ".handlebars", ".ejs", ".mustache", ".tpl", ".vm", ".ftl", ".gsp")
SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "bower_components"}

# Server side tags, the ones that print a value and the ones that only steer.
# A printed value becomes __SERVER_VALUE__: a name, so it is valid wherever a
# value is, plain text inside a string, and a mark the rules can follow as
# data the server printed.  A control tag becomes a comment.  Either way the
# tag's lines are kept, so a finding's line is the line in the template.
SERVER_TAGS = re.compile(
    r"<\?(?:php\b|=)?.*?(?:\?>|$)|<%[=#-]?.*?%>|\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}",
    re.DOTALL)
PRINTS = re.compile(r"^(<\?=|<\?php\s+(echo|print)\b|<%=|\{\{)", re.IGNORECASE)


# What a printed tag holds when it cannot be anything a user typed: a
# translation, a number, a constant, a token the page needs.  Those become a
# plain 0, so only printed data is followed.
TRANSLATION = re.compile(r"(?<![\w$>])(t|__|_e|_x|_n|_|trans|trans_choice|lang|gettext|"
                         r"ngettext|i18n|translate|Lang::get|I18n\.t)\s*\(|"
                         r"\|\s*(trans|t|translate|i18n)\b")
PAGE_TOKEN = re.compile(r"csrf|nonce|xsrf", re.IGNORECASE)
NUMERIC = re.compile(r"\(int\)|\(float\)|\(bool\)|\bintval\s*\(|\bfloatval\s*\(|"
                     r"\bcount\s*\(|\bsizeof\s*\(|\bnumber_format\s*\(|\|\s*length\b")
KEYWORDS = {"echo", "print", "true", "false", "null", "none", "and", "or", "not", "if",
            "else", "raw", "safe", "json", "tojson", "json_encode", "escape", "e"}


def _printed_data(inner: str) -> bool:
    """Whether a printed tag prints a variable rather than a fixed value."""
    if TRANSLATION.search(inner) or PAGE_TOKEN.search(inner) or NUMERIC.search(inner):
        return False
    if re.search(r"[$@][A-Za-z_]", inner):              # $php, @ruby
        return True
    # Template engines name variables bare.  Function names, string
    # literals and CONSTANTS are not variables.
    bare = re.sub(r"(['\"]).*?\1", "", inner)
    bare = re.sub(r"\b[A-Za-z_][\w.:]*\s*\(", "(", bare)
    for word in re.findall(r"\b[a-z_][A-Za-z0-9_]*\b", bare):
        if word not in KEYWORDS:
            return True
    return False


def _stand_in(match) -> str:
    tag = match.group(0)
    lines = tag.count("\n")
    if PRINTS.match(tag):
        inner = re.sub(r"^(<\?=|<\?php|<%=|\{\{)|(\?>|%>|\}\})$", "", tag.strip())
        inner = re.sub(r"^\s*(echo|print)\b", "", inner)
        return ("__SERVER_VALUE__" if _printed_data(inner) else "0") + "\n" * lines
    return "/*-*/" + "\n" * lines


def extract(root: Path, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest, n = {}, 0

    for page in root.rglob("*"):
        suffix = page.suffix.lower()
        if not page.is_file() or suffix not in PAGES + TEMPLATES:
            continue
        if any(part in SKIP_DIRS for part in page.relative_to(root).parts[:-1]):
            continue
        template = suffix in TEMPLATES
        try:
            if page.stat().st_size > MAX_BYTES:
                continue
            text = page.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        pos = 0
        while True:
            m = OPEN.search(text, pos)
            if not m:
                break
            attrs = m.group(1) or ""
            end = CLOSE.search(text, m.end())
            if not end:
                break
            body = text[m.end():end.start()]
            pos = end.end()

            if HAS_SRC.search(attrs) or (attrs.strip() and NOT_JS.search(attrs)):
                continue
            if not body.strip():
                continue

            # The line the block's first line sits on in the original page.
            offset = text.count("\n", 0, m.end()) + 1
            n += 1
            name = f"block{n}.js"
            if template:
                body = SERVER_TAGS.sub(_stand_in, body)
                (out_dir / "templates").mkdir(exist_ok=True)
                (out_dir / "templates" / name).write_text(body, encoding="utf-8")
            else:
                (out_dir / name).write_text(body, encoding="utf-8")
            manifest[name] = {"path": str(page.relative_to(root)), "line_offset": offset,
                              "template": template}

    (out_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def remap(results_path: Path, manifest: dict, out_path: Path) -> int:
    """Rewrite findings in extracted blocks back onto the page they came from."""
    try:
        doc = json.loads(results_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    kept = []
    for r in doc.get("results", []):
        name = Path(r.get("path", "")).name
        entry = manifest.get(name)
        if not entry:
            continue
        off = entry["line_offset"] - 1
        r["path"] = entry["path"]
        for key in ("start", "end"):
            if isinstance(r.get(key), dict) and isinstance(r[key].get("line"), int):
                r[key]["line"] += off
        # Say where it was found.  A finding on a page is not the same claim as
        # one in a module, and somebody reading it should not have to work that
        # out from the file extension.
        meta = r.setdefault("extra", {}).setdefault("metadata", {})
        meta["embedded_in"] = ("server template script block" if entry.get("template")
                               else "html script block")
        kept.append(r)
    out_path.write_text(json.dumps({"results": kept}), encoding="utf-8")
    return len(kept)


if __name__ == "__main__":
    if sys.argv[1] == "extract":
        found = extract(Path(sys.argv[2]), Path(sys.argv[3]))
        print(len(found))
    elif sys.argv[1] == "remap":
        man = json.loads((Path(sys.argv[3]) / "manifest.json").read_text(encoding="utf-8"))
        print(remap(Path(sys.argv[2]), man, Path(sys.argv[4])))
