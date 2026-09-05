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


def extract(root: Path, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest, n = {}, 0

    for page in root.rglob("*"):
        if not page.is_file() or page.suffix.lower() not in (".html", ".htm"):
            continue
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
            (out_dir / name).write_text(body, encoding="utf-8")
            manifest[name] = {"path": str(page.relative_to(root)), "line_offset": offset}

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
        meta["embedded_in"] = "html script block"
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
