"""The editor packages, built from the source that ships in the image.

A developer cannot install this from a marketplace.  Most installations of
this product sit on a private network, plenty of them on one with no way out
at all, and an extension that has to be fetched from Microsoft is an extension
half the customers cannot have.  So the server hands out its own.

Built rather than committed, for two reasons.  A built package in the
repository is a copy of files already in it, and copies go stale in exactly
the way nobody notices: the version in the zip stops matching the version of
the server that is serving it.  And the package has to carry the version of
*this* installation, because the first question about a report from an editor
is which one produced it.

The bytes are deterministic.  Every entry is written with the same timestamp
and the same permissions, so building the package twice gives the same file
and the checksum on the page is a checksum somebody can actually compare
against what they downloaded.  Nothing here compiles anything: a .vsix is a
zip, the extension is JavaScript with no dependencies, and that is the whole
build.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import tempfile
import zipfile
from pathlib import Path

from app.config import VERSION, settings

log = logging.getLogger("gcr.editor_plugins")

# Where the source lives, in the image and in a checkout alike.
IDE_DIR = Path(__file__).resolve().parents[2] / "ide"

# Everything in the archives is stamped with this.  A zip records the local
# time of the machine that made it, which would make two builds of identical
# files differ, and a checksum that changes on its own is a checksum nobody
# checks.
FIXED_TIME = (1980, 1, 1, 0, 0, 0)

VSIX_NAME = f"git-code-review-{VERSION}.vsix"
LSP_NAME = f"git-code-review-lsp-{VERSION}.zip"

# The name the language server unpacks into, which the setup instructions on
# the page have to spell exactly.
LSP_ROOT = "git-code-review-lsp"


def output_dir() -> Path:
    """Where the built packages are kept between requests."""
    return settings.data_dir / "editor-plugins"


def _core_files() -> list:
    return sorted((IDE_DIR / "core").glob("*.js"))


def _newest_source() -> float:
    """The last time any of the source changed.

    Used to decide whether what is on disk is still current.  An upgrade
    replaces the files in the image, and a package built by the version before
    it would otherwise be handed out for ever.
    """
    newest = 0.0
    for path in IDE_DIR.rglob("*"):
        if path.is_file():
            newest = max(newest, path.stat().st_mtime)
    return newest


def _add(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    # Readable by everybody, writable by nobody: this is something people
    # unpack, not something they edit in place.
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _manifest(name: str) -> bytes:
    """The package.json for one of the two, with this server's version in it.

    The version is written here rather than kept in step by hand.  Two files
    claiming different versions of the same thing is the sort of detail that
    turns a support question into an afternoon.
    """
    document = json.loads((IDE_DIR / name / "package.json").read_text("utf-8"))
    document["version"] = VERSION
    return json.dumps(document, indent=2).encode("utf-8") + b"\n"


# --- the Visual Studio Code package -----------------------------------------

CONTENT_TYPES = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="md" ContentType="text/markdown"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
</Types>
"""

VSIX_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0"
    xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"
    xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="git-code-review" Version="{version}"
              Publisher="gitcodereview"/>
    <DisplayName>Git Code Review</DisplayName>
    <Description xml:space="preserve">Reviews the file you are editing against your own Git Code Review server.</Description>
    <Tags>security,sast,secrets,credentials</Tags>
    <Categories>Linters,Other</Categories>
    <GalleryFlags>Private</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.75.0"/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value=""/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value=""/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace,ui"/>
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json"
           Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details"
           Path="extension/README.md" Addressable="true"/>
  </Assets>
</PackageManifest>
"""


def _build_vsix(target: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        _add(archive, "[Content_Types].xml", CONTENT_TYPES.encode("utf-8"))
        _add(archive, "extension.vsixmanifest",
             VSIX_MANIFEST.format(version=VERSION).encode("utf-8"))
        _add(archive, "extension/package.json", _manifest("vscode"))
        _add(archive, "extension/extension.js",
             _read(IDE_DIR / "vscode" / "extension.js"))
        for path in _core_files():
            _add(archive, f"extension/core/{path.name}", _read(path))
        _add(archive, "extension/README.md",
             _read(IDE_DIR / "vscode" / "README.md"))
        _add(archive, "extension/LICENSE", _read(root / "LICENSE"))


# --- the language server, for everything else -------------------------------

def _build_lsp(target: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        _add(archive, f"{LSP_ROOT}/README.md", _read(IDE_DIR / "server" / "README.md"))
        _add(archive, f"{LSP_ROOT}/server/package.json", _manifest("server"))
        for name in ("main.js", "lsp.js"):
            _add(archive, f"{LSP_ROOT}/server/{name}",
                 _read(IDE_DIR / "server" / name))
        for path in _core_files():
            _add(archive, f"{LSP_ROOT}/core/{path.name}", _read(path))
        _add(archive, f"{LSP_ROOT}/LICENSE", _read(root / "LICENSE"))


BUILDERS = {
    "vsix": (VSIX_NAME, _build_vsix, "application/octet-stream"),
    "lsp": (LSP_NAME, _build_lsp, "application/zip"),
}


def available() -> bool:
    """Is the source here at all?

    An installation that predates this, or one where the directory was left
    out of an image somebody built themselves, should say so on the page
    rather than offer a download that 404s.
    """
    return (IDE_DIR / "vscode" / "extension.js").is_file()


def build(which: str) -> Path:
    """The package, built if it is missing or older than the source.

    Written to a temporary name and moved into place, so a second request
    arriving mid build gets the old file or the new one and never half of one.
    """
    if which not in BUILDERS:
        raise KeyError(which)
    name, builder, _media = BUILDERS[which]
    directory = output_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name

    if target.is_file() and target.stat().st_mtime >= _newest_source():
        return target

    with tempfile.NamedTemporaryFile(dir=directory, suffix=".part",
                                     delete=False) as handle:
        staged = Path(handle.name)
    try:
        builder(staged)
        staged.replace(target)
        log.info("built %s (%d bytes)", name, target.stat().st_size)
    finally:
        staged.unlink(missing_ok=True)
    return target


def describe(which: str) -> dict:
    """What the page shows about one package: its name, size and checksum."""
    name, _builder, media = BUILDERS[which]
    path = build(which)
    data = path.read_bytes()
    return {
        "key": which,
        "name": name,
        "media_type": media,
        "bytes": len(data),
        "kilobytes": max(1, round(len(data) / 1024)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "version": VERSION,
    }


def clear() -> None:
    """Throw away what was built.  Only used by the tests."""
    shutil.rmtree(output_dir(), ignore_errors=True)
