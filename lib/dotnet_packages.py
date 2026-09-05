""".NET dependencies, read from the files a source repository actually has.

syft finds nothing in a .NET project that has not been built.  Its three .NET
catalogers read a deps.json, a packages.lock.json, or a compiled assembly, and
a source repository normally has none of those: it has a csproj listing
PackageReference entries, or, on older projects, a packages.config.  Measured
against an independent scan of the same estate, that is the difference between
131 findings and several thousand.

So the packages are read from the project files here and added to the SBOM,
where the vulnerability matcher already looks.  Nothing is resolved over the
network: what is declared is what is reported, which means a transitive
dependency pulled in by one of these is still not seen.  That is a smaller gap
than the one it closes, and it is honest about which it is.
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PROJECT_FILES = (".csproj", ".vbproj", ".fsproj", ".props")
CONFIG_FILES = ("packages.config",)

# A version can be a range or an MSBuild property.  Neither is a version we can
# match an advisory against, and inventing one would be worse than saying
# nothing: a wrong version means a wrong answer about whether it is vulnerable.
UNRESOLVED = re.compile(r"^\s*[\[\(\$]")


def _tag(elem) -> str:
    return elem.tag.rsplit("}", 1)[-1].lower()


# Every file read here came out of somebody else's repository, so it is input
# from a stranger and not configuration.
#
# ElementTree does not resolve external entities, so a project file cannot be
# made to read /etc/passwd through this.  It does expand internal ones, and
# that is enough on its own: a dozen nested entity definitions in a document
# the size of a paragraph expand to gigabytes, and the scanner is what runs
# out of memory.  A repository that stops the scan of every repository behind
# it in the queue is a cheap thing for somebody to arrange.
#
# Both halves of the answer are refusals rather than limits on the damage.
# Expanding entities needs a document type declaration, and no legitimate
# MSBuild or NuGet file has one, so a file carrying a DOCTYPE is not parsed at
# all.  A size cap sits in front of that for the ordinary case of a file too
# large to be one of these, which also bounds the work done looking for the
# declaration.
MAX_PROJECT_BYTES = 8 * 1024 * 1024

_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)


def _safe_parse(path: Path):
    """The root element, or None when the file is not one we will read.

    Quiet on purpose: this runs over every file in every repository and a
    project file that is malformed, enormous or hostile is all the same
    outcome here, which is that its packages do not reach the inventory.
    """
    try:
        if path.stat().st_size > MAX_PROJECT_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if _DOCTYPE.search(raw):
        return None
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        return None


def from_project(path: Path):
    """PackageReference and PackageVersion entries out of an MSBuild file."""
    root = _safe_parse(path)
    if root is None:
        return
    for elem in root.iter():
        if _tag(elem) not in ("packagereference", "packageversion"):
            continue
        name = elem.get("Include") or elem.get("Update") or elem.get("include")
        version = elem.get("Version") or elem.get("version")
        if version is None:
            # <PackageReference Include="x"><Version>1.2.3</Version></...>
            for child in elem:
                if _tag(child) == "version":
                    version = (child.text or "").strip()
                    break
        if not name or not version or UNRESOLVED.match(version):
            continue
        yield name.strip(), version.strip()


def from_config(path: Path):
    """The <packages> list of a project that predates PackageReference."""
    root = _safe_parse(path)
    if root is None:
        return
    for elem in root.iter():
        if _tag(elem) != "package":
            continue
        name = elem.get("id") or elem.get("Id")
        version = elem.get("version") or elem.get("Version")
        if name and version and not UNRESOLVED.match(version):
            yield name.strip(), version.strip()


def collect(root: Path) -> list:
    seen, out = set(), []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        pairs = ()
        if name in CONFIG_FILES:
            pairs = from_config(path)
        elif path.suffix.lower() in PROJECT_FILES:
            pairs = from_project(path)
        for pkg, version in pairs:
            key = (pkg.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "type": "library",
                "name": pkg,
                "version": version,
                "purl": f"pkg:nuget/{pkg}@{version}",
                # Says where it came from, so a reader can tell this apart from
                # something the scanner found in a built artifact.
                "properties": [{"name": "gcr:source", "value": str(path.relative_to(root))}],
            })
    return out


if __name__ == "__main__":
    print(json.dumps(collect(Path(sys.argv[1]))))
