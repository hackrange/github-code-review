"""Libraries somebody copied in, which no package manifest mentions.

Dependency scanning reads manifests: composer.lock, package-lock.json, and the
rest.  A library that was copied into the tree has no manifest entry, so it is
not scanned, and the report comes back clean about it.  That is worse than a
noisy finding.  A noisy finding gets argued with; a missing one looks exactly
like a repository with nothing wrong.

One repository this was written against ships four of them and its manifest
names none: a mail library a decade past end of life and still called from the
application, a rich text editor, and two copies of a CSS framework.

What this does is small on purpose.  It finds the version somebody vendored and
writes it into the SBOM as a component with a package URL.  Everything after
that already exists: grype reads the SBOM, matches advisories, and the findings
come out through the same path as every other dependency.  No new severity
model, no second advisory source, no new kind of finding.

Every signature here was checked against a real file rather than written from
memory of what the banner looks like.
"""

from __future__ import annotations

import json
import os
import re
import sys

# Read enough to reach a version that is not in the banner.  Minified builds
# put it wherever the bundler left it, and a whole rich text editor is several
# megabytes of no interest.
READ_LIMIT = 400_000

# match:   which files are worth opening, on the path
# version: what the version looks like inside one
# purl:    what to call it so an advisory database recognises it
SIGNATURES = (
    {"name": "phpmailer/phpmailer", "purl": "pkg:composer/phpmailer/phpmailer",
     "match": r"(^|/)class\.phpmailer\.php$",
     "version": r"\$Version\s*=\s*['\"]([0-9][0-9.]*)"},
    {"name": "bootstrap", "purl": "pkg:npm/bootstrap",
     "match": r"(^|/)bootstrap(\.min)?\.(css|js)$",
     "version": r"Bootstrap\s+v([0-9][0-9.]*)"},
    {"name": "tinymce", "purl": "pkg:npm/tinymce",
     "match": r"(^|/)tinymce(\.min)?\.js$",
     "version": r"TinyMCE\s+version\s+([0-9][0-9.]*)"},
    {"name": "jquery", "purl": "pkg:npm/jquery",
     "match": r"(^|/)jquery[-.0-9]*(\.min)?\.js$",
     "version": r"jQuery\s+v([0-9][0-9.]*)"},
    {"name": "moment", "purl": "pkg:npm/moment",
     "match": r"(^|/)moment(\.min)?\.js$",
     "version": r"\bversion\s*[:=]\s*['\"]([0-9][0-9.]*)['\"]"},
    {"name": "lodash", "purl": "pkg:npm/lodash",
     "match": r"(^|/)lodash(\.min)?\.js$",
     "version": r"\bVERSION\s*[:=]\s*['\"]([0-9][0-9.]*)['\"]"},
    {"name": "ckeditor4", "purl": "pkg:npm/ckeditor4",
     "match": r"(^|/)ckeditor\.js$",
     "version": r"\bversion\s*[:=]\s*['\"]([0-9][0-9.]*)"},
    {"name": "tecnickcom/tcpdf", "purl": "pkg:composer/tecnickcom/tcpdf",
     "match": r"(^|/)tcpdf\.php$",
     "version": r"TCPDF_VERSION\s*[,)]?\s*['\"]?([0-9][0-9.]*)"},
)

SKIP_DIRECTORIES = {".git", "node_modules", "bower_components", "dist", "build"}


def _read(path: str) -> str:
    try:
        with open(path, errors="replace") as handle:
            return handle.read(READ_LIMIT)
    except OSError:
        return ""


def detect(root: str) -> list:
    """-> [{name, version, purl, path}] for every vendored copy found.

    A manifest is not consulted here.  A library that appears in both is
    reported by both, and the merge downstream drops the duplicate, which is
    the right way round: missing one is the failure this exists to stop.
    """
    found = []
    if not root or not os.path.isdir(root):
        return found
    matchers = [(re.compile(s["match"], re.I), re.compile(s["version"]), s)
                for s in SIGNATURES]
    for folder, directories, files in os.walk(root):
        directories[:] = [d for d in directories if d not in SKIP_DIRECTORIES]
        for filename in files:
            full = os.path.join(folder, filename)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            for path_pattern, version_pattern, signature in matchers:
                if not path_pattern.search(relative):
                    continue
                text = _read(full)
                if not text:
                    continue
                version = version_pattern.search(text)
                if not version:
                    continue
                found.append({"name": signature["name"],
                              "version": version.group(1).rstrip("."),
                              "purl": signature["purl"],
                              "path": relative})
                break
    found.sort(key=lambda row: (row["name"], row["path"]))
    return found


def components(rows: list) -> list:
    """Those detections as CycloneDX components an advisory scanner can read.

    One component per version, however many copies of it there are.  The same
    library at the same version in two directories is one thing to fix, and
    emitting it twice would report every advisory against it twice, which is
    the noise this whole pass exists to avoid making more of.  Both paths are
    kept, because which copy is loaded is the next question.
    """
    grouped = {}
    for row in rows:
        purl = "%s@%s" % (row["purl"], row["version"])
        entry = grouped.get(purl)
        if entry is None:
            grouped[purl] = {"row": row, "paths": [row["path"]]}
        elif row["path"] not in entry["paths"]:
            entry["paths"].append(row["path"])
    out = []
    for purl, entry in grouped.items():
        row = entry["row"]
        paths = sorted(entry["paths"])
        properties = [{"name": "ghscan:vendored", "value": "true"},
                      {"name": "ghscan:path", "value": paths[0]}]
        if len(paths) > 1:
            properties.append({"name": "ghscan:copies",
                               "value": ", ".join(paths)})
        out.append({
            "type": "library",
            "bom-ref": "vendored:%s" % purl,
            "name": row["name"],
            "version": row["version"],
            "purl": purl,
            # Where it was found, because the first question about a library
            # with no manifest entry is where it came from.
            "properties": properties,
        })
    out.sort(key=lambda component: component["purl"])
    return out


def merge_into_sbom(sbom_path: str, root: str) -> int:
    """Add what was vendored to an existing CycloneDX file.  -> how many.

    A broken or missing SBOM is left exactly as it was.  This pass adding
    nothing is a much smaller problem than this pass making the file
    unreadable and taking the real dependencies out with it.
    """
    rows = detect(root)
    if not rows:
        return 0
    try:
        with open(sbom_path) as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return 0
    if not isinstance(document, dict):
        return 0
    existing = document.get("components")
    if not isinstance(existing, list):
        existing = []
    known = {c.get("purl") for c in existing if isinstance(c, dict)}
    added = [c for c in components(rows) if c["purl"] not in known]
    if not added:
        return 0
    document["components"] = existing + added
    try:
        with open(sbom_path, "w") as handle:
            json.dump(document, handle)
    except OSError:
        return 0
    return len(added)


def main() -> int:
    """vendored.py <repo> [sbom.cdx.json]

    With an SBOM, merge into it and print how many were added.  Without one,
    print what was found, so the detection can be looked at on its own.
    """
    if len(sys.argv) < 2:
        sys.stderr.write("usage: vendored.py <repo> [sbom]\n")
        return 2
    root = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2]:
        sys.stdout.write("%d\n" % merge_into_sbom(sys.argv[2], root))
    else:
        json.dump(detect(root), sys.stdout, indent=1)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
