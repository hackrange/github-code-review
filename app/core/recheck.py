"""Check one finding again, right now, without touching anything.

A developer fixes a secret and wants to know within seconds whether it is gone.
A full scan takes half an hour and holds a lock the whole time, so this is a
second, much smaller path: shallow clone the one branch, run the one engine
over the one file, say what it sees, and write none of it down.

Read only on purpose.  A scan decides a finding's state by walking every branch
and every commit; this looks at one file at one moment.  "Not in this file on
this branch right now" is not the same as "gone", and writing that judgement
into the findings table would both race a running scan and overwrite a complete
answer with a partial one.  So the answer is shown and then discarded.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from app.core.db import session_scope
from app.core.models import Finding, FindingKind

log = logging.getLogger("gcr.recheck")

# A scan already runs four workers and their clones.  Letting a team pile
# rechecks on top of that is how a machine falls over mid scan.
_slots = threading.Semaphore(2)

CLONE_TIMEOUT = 90
ENGINE_TIMEOUT = 120

# Which username the host wants when the password is a token.
_GIT_USERNAME = {"github": "x-access-token", "gitlab": "oauth2"}


def _credential_args(token_file: Path, provider: str) -> list:
    """Feed git the token through a helper rather than the URL.

    A token in the URL leaks to anybody running ps and gets written into
    .git/config.
    """
    user = _GIT_USERNAME.get(provider, "x-access-token")
    helper = ('!f(){ test "$1" = get && { echo username=%s; '
              'echo "password=$(cat %s)"; }; }; f' % (user, token_file))
    return ["-c", "credential.helper=",
            "-c", "credential.helper=" + helper,
            "-c", "credential.useHttpPath=false"]


def _shallow_clone(url: str, branch: str, dest: Path, cred: list) -> tuple:
    """One branch, one commit deep.  Everything here needs the tip and no more."""
    command = ["git"] + cred + [
        "clone", "--quiet", "--depth", "1", "--single-branch",
        "--branch", branch, "--no-tags", url, str(dest)]
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, "the clone took too long"
    if done.returncode != 0:
        detail = (done.stderr or "").strip().splitlines()
        # Never echo a credential back to a page.
        last = detail[-1] if detail else "git would not clone it"
        return False, last[:200]
    return True, ""


def _gitleaks_hits(root: Path, rel_path: str) -> tuple:
    """Run the secret detector over the one file.  -> (ok, rules_found, detail)"""
    if shutil.which("gitleaks") is None:
        return False, [], "gitleaks is not installed here"
    target = root / rel_path
    if not target.exists():
        return True, [], ""
    report = root.parent / "gitleaks.json"
    command = ["gitleaks", "detect", "--source", str(target), "--no-git",
               "--report-format", "json", "--report-path", str(report),
               "--exit-code", "0", "--no-banner"]
    try:
        subprocess.run(command, capture_output=True, text=True,
                       timeout=ENGINE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, [], "the detector took too long"
    if not report.exists():
        return True, [], ""
    try:
        rows = json.loads(report.read_text() or "[]")
    except ValueError:
        return False, [], "the detector wrote something unreadable"
    return True, [str(r.get("RuleID") or r.get("Description") or "") for r in rows], ""


def _semgrep_hits(root: Path, rel_path: str, configs: list) -> tuple:
    """Run code analysis over the one file.  -> (ok, rule_names, detail)

    The scanner names a rule by the last dot separated piece of semgrep's
    check_id, so the same is done here or nothing would ever match.
    """
    venv = os.environ.get("GCR_SCANNER_VENV", "/opt/gcr/scanner-venv")
    binary = Path(venv) / "bin" / "semgrep"
    if not binary.exists():
        return False, [], "code analysis is not installed here"
    if not configs:
        return False, [], "no rulesets are configured"
    if not (root / rel_path).exists():
        return True, [], ""

    command = [str(binary), "--json", "--quiet", "--metrics", "off",
               "--timeout", "60"]
    for config in configs:
        command += ["--config", config]
    command.append(rel_path)
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              cwd=str(root), timeout=ENGINE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, [], "code analysis took too long"
    if not (done.stdout or "").strip():
        detail = (done.stderr or "").strip().splitlines()
        return False, [], (detail[-1][:200] if detail else "code analysis said nothing")
    try:
        payload = json.loads(done.stdout)
    except ValueError:
        return False, [], "code analysis wrote something unreadable"
    names = []
    for hit in payload.get("results", []):
        check_id = str(hit.get("check_id") or "")
        names.append(check_id.split(".")[-1] if check_id else "")
    return True, names, ""


def recheck(finding_id: int) -> dict:
    """Look at one finding again.  Returns a verdict; stores nothing."""
    if not _slots.acquire(blocking=False):
        return {"ok": False,
                "detail": "Two rechecks are already running. Try again in a moment."}
    try:
        return _recheck(finding_id)
    finally:
        _slots.release()


def _recheck(finding_id: int) -> dict:
    from app.core import connections as connection_store, scanner_config

    with session_scope() as db:
        row = db.query(Finding).filter(Finding.id == finding_id).one_or_none()
        if row is None:
            return {"ok": False, "detail": "That finding is gone."}
        kind = row.kind
        repo = row.repository or ""
        rel_path = row.file_path or ""
        branch = row.branch or ""
        rule = row.rule or ""
        connection = (connection_store.by_name(db, row.connection)
                      if row.connection else None)
        from app.core import settings_store as store
        rulesets = list(store.get(db, "code.rulesets") or [])
        provider = (getattr(connection, "provider", None) or "github")
        web = (connection.web_url if connection is not None else None) \
            or "https://github.com"

    if kind == FindingKind.DEPENDENCY:
        return {"ok": False,
                "detail": "A dependency finding comes from the manifest and the "
                          "vulnerability feeds, not from a file on a branch. "
                          "Run a scan of the repository instead."}
    if not rel_path:
        return {"ok": False,
                "detail": "This finding is not tied to a file, so there is "
                          "nothing to look at on its own."}
    if kind not in (FindingKind.CREDENTIAL, FindingKind.CODE):
        return {"ok": False,
                "detail": "That kind of finding cannot be looked at on its own."}

    with tempfile.TemporaryDirectory(prefix="gcr-recheck-") as tmp:
        work = Path(tmp)
        token_file = work / "token"
        with session_scope() as db:
            env = scanner_config.scanner_env(db, {}, connection=connection)
        token = env.get("GHSCAN_TOKEN", "")
        if not token:
            return {"ok": False, "detail": "No credential for that account."}
        token_file.write_text(token)
        token_file.chmod(0o600)

        url = "%s/%s.git" % (web.rstrip("/"), repo)
        dest = work / "repo"
        ok, why = _shallow_clone(url, branch or "HEAD", dest,
                                 _credential_args(token_file, provider))
        if not ok:
            return {"ok": False, "detail": "Could not fetch it: %s" % why}

        target = dest / rel_path
        if not target.exists():
            return {"ok": True, "present": False,
                    "detail": "The file is not on %s any more." % (branch or "that branch")}

        if kind == FindingKind.CREDENTIAL:
            ok, rules, why = _gitleaks_hits(dest, rel_path)
        else:
            ok, rules, why = _semgrep_hits(dest, rel_path, rulesets)
        if not ok:
            return {"ok": False, "detail": why}

        if not rules:
            return {"ok": True, "present": False,
                    "detail": "Nothing found in %s on %s." % (rel_path, branch or "that branch")}
        if rule and rule not in rules:
            return {"ok": True, "present": False,
                    "detail": "%s is clean of %s, though other rules still match "
                              "there." % (rel_path, rule)}
        return {"ok": True, "present": True,
                "detail": "Still there: %s in %s on %s." % (rule or "the finding",
                                                            rel_path,
                                                            branch or "that branch")}
