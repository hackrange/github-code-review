#!/usr/bin/env python3
"""semgrep's secret detectors, handed to the credential pass.

semgrep's p/secrets rules match a credential's value, and they used to be
filed as code findings.  So a key semgrep alone found was graded medium where
the credential policy says critical until something shows it is dead, it was
counted once per line, 202 times for one AppSync key in one recorded script,
and nothing that knows about credentials ever looked at it: no fingerprint,
no expiry, no placeholder check, no merge with the same value from gitleaks.

Two steps, so the value only ever travels in a pipe.

  --extract <semgrep.json> <clone_dir>
      One credential candidate per secret match on stdout, in the shape the
      other engines are normalized to, value included.  The caller pipes it
      straight into derive_secret_facts, which keeps the facts and drops it.

  --drop <semgrep.json> <keys.ndjson>
      The semgrep report without the matches that became credentials, so the
      code pass does not file them a second time.  Keys are read from the
      derived candidates, which hold no value.  A match whose value could not
      be read, or that the credential pass skips by path, is not in the keys
      and stays a code finding: moving it would close it for silence.
"""

import json
import re
import sys

# The rules whose match is a value, not a line of code.
SECRET_RULE = re.compile(r"^generic\.secrets\.")
QUOTED = re.compile(r"""(['"`])([^'"`\s]{8,})\1""")
ARMOR_END = re.compile(rb"-----END [A-Z0-9 ]*PRIVATE KEY-----")


def _key(result: dict) -> str:
    """Which semgrep match this is: file, line and rule."""
    start = result.get("start") or {}
    return "%s|%s|%s" % (re.sub(r"^\./", "", str(result.get("path") or "")),
                         start.get("line", 0), result.get("check_id") or "")


def _value(data: bytes, result: dict) -> str:
    """The credential inside a match, or "" when it cannot be told apart."""
    start, end = result.get("start") or {}, result.get("end") or {}
    lo, hi = start.get("offset"), end.get("offset")
    if not isinstance(lo, int) or not isinstance(hi, int) or not 0 <= lo < hi <= len(data):
        return ""
    matched = data[lo:hi]
    # A private key rule matches the armor line.  The key is the whole block.
    if matched.startswith(b"-----BEGIN") and b"PRIVATE KEY" in matched:
        closing = ARMOR_END.search(data, hi)
        if not closing:
            return ""
        matched = data[lo:closing.end()]
    text = matched.decode("utf-8", "replace").strip()
    # secret = "..." matches the whole assignment.  The value is what is
    # quoted, and the longest quoted run when there are several.
    if re.search(r"[=:]", text) and not text.startswith("-----BEGIN"):
        quoted = [m.group(2) for m in QUOTED.finditer(text)]
        if not quoted:
            return ""
        text = max(quoted, key=len)
    return text if len(text) >= 8 else ""


def extract(report_path: str, clone_dir: str, out) -> int:
    report = json.load(open(report_path))
    files = {}
    count = 0
    for result in report.get("results") or []:
        check = str(result.get("check_id") or "")
        if not SECRET_RULE.match(check):
            continue
        path = re.sub(r"^\./", "", str(result.get("path") or ""))
        if path not in files:
            try:
                with open("%s/%s" % (clone_dir.rstrip("/"), path), "rb") as handle:
                    files[path] = handle.read()
            except OSError:
                files[path] = b""
        value = _value(files[path], result)
        if not value:
            continue
        line = (result.get("start") or {}).get("line", 0)
        out.write(json.dumps({
            "engine": "semgrep", "detector": check.split(".")[-1],
            "rule_id": check, "description": "",
            "file": path, "start_line": line,
            "end_line": (result.get("end") or {}).get("line", line),
            "commit": "", "author_name": "", "author_email": "",
            "committed_at": "", "commit_message": None, "entropy": None,
            "verified": False, "verification_error": None,
            "engine_fingerprint": "", "tags": [],
            "code_rule": check.split(".")[-1], "code_line": line,
            "_code_key": _key(result),
            "_secret": value}) + "\n")
        count += 1
    return count


def drop(report_path: str, keys_path: str, out) -> None:
    keys = set()
    for raw in open(keys_path):
        raw = raw.strip()
        if raw:
            try:
                key = json.loads(raw).get("_code_key")
            except ValueError:
                continue
            if key:
                keys.add(key)
    report = json.load(open(report_path))
    report["results"] = [r for r in report.get("results") or [] if _key(r) not in keys]
    json.dump(report, out)


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--extract":
        extract(sys.argv[2], sys.argv[3], sys.stdout)
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "--drop":
        drop(sys.argv[2], sys.argv[3], sys.stdout)
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
