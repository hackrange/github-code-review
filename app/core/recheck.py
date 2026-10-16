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

import contextlib
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

# Which username the host wants when the password is a token.  Gitea and
# Forgejo read the token out of the password and pay no attention to the
# username, so the default is as good an answer there as any.
_GIT_USERNAME = {"github": "x-access-token", "gitlab": "oauth2",
                 "bitbucket": "x-token-auth"}


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
        return False, _explain_clone(last)[:300]
    return True, ""


def _explain_clone(line: str) -> str:
    """git's words for a repository the token cannot see, made accurate.

    GitHub answers a private repository the token has no access to as if it
    did not exist, and git reports that as the token failing.  The token is
    usually fine: it still reads everything else in the account.
    """
    lowered = line.lower()
    if ("authentication failed" in lowered or "repository not found" in lowered
            or "could not read username" in lowered):
        return ("this connection's token cannot see the repository.  Either "
                "it lost access (removed from the token, or the account was "
                "taken off the repository), the repository was renamed or "
                "deleted, or the token itself stopped working.  Test the "
                "connection on the Connections page to see which")
    return line


def _english(names) -> str:
    """A list of branches a sentence can contain."""
    names = list(names)
    if not names:
        return "nothing"
    if len(names) == 1:
        return names[0]
    if len(names) <= 4:
        return ", ".join(names[:-1]) + " and " + names[-1]
    return "%s and %d others" % (", ".join(names[:3]), len(names) - 3)


def _record(finding_id: int, present: bool, actor: str, branches) -> bool:
    """Write what the recheck proved.  -> whether the state moved.

    Two directions and they are not symmetrical.  Finding it again is positive
    evidence and only ever moves last_found_at, which cannot make anything look
    better than it is.  Not finding it closes the finding, and that is only
    reached from a caller that has looked at every branch on record.

    A waived finding is left alone in both directions.  Somebody decided that,
    and a recheck is not a decision.
    """
    from app.core.models import FindingState, utcnow

    with session_scope() as db:
        row = db.query(Finding).filter(Finding.id == finding_id).one_or_none()
        if row is None:
            return False
        if getattr(row, "excepted", False):
            return False
        now = utcnow()
        if present:
            row.last_found_at = now
            if row.state == FindingState.FIXED:
                # It came back.  The same rule the ingest uses, which keeps a
                # waived finding waived.
                from app.core.ingest import reopened_state
                row.state = reopened_state(db, row)
                row.resolved_at = None
            db.flush()
            return True
        if row.state != FindingState.OPEN:
            return False
        row.state = FindingState.FIXED
        row.resolved_at = now
        db.flush()
        log.info("%s rechecked %s and it was gone from %s, so it is closed",
                 actor or "somebody", row.fingerprint, ", ".join(branches))
        return True


def _fetch_branch(dest: Path, url: str, branch: str, cred: list) -> bool:
    """Bring one more branch tip into a clone that already exists.

    Cheaper than cloning again per branch, which is what checking a finding
    across every branch it is on would otherwise cost: one connection, one
    object store, one tip per branch.
    """
    command = ["git", "-C", str(dest)] + cred + [
        "fetch", "--quiet", "--depth", "1", "--no-tags", url,
        "+refs/heads/%s:refs/remotes/recheck/%s" % (branch, branch)]
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False
    return done.returncode == 0


def _checkout(dest: Path, ref: str) -> bool:
    """Put a fetched tip in the working tree so the engines can read it."""
    command = ["git", "-C", str(dest), "checkout", "--quiet", "--force", ref]
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False
    return done.returncode == 0


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
    # Everything after this is a path, whatever it looks like.
    #
    # rel_path comes from a finding, and a finding's path comes from somebody
    # else's repository.  A file committed as --config=https://elsewhere/rules
    # is a legal filename, and appended bare it would be read as an option
    # rather than as the file to scan: semgrep would go and fetch that ruleset.
    #
    # Not the command injection the rule that flags this line reports, because
    # this is a list and there is no shell for a semicolon to mean anything to.
    # It is argument injection, which is a smaller thing and still worth
    # closing, and it costs two characters.
    command.append("--")
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


# How many branches a recheck will walk before it stops offering to decide.
#
# Every branch is a fetch of one tip and one engine run over one file, so the
# cost is real but small, and the number of branches a finding sits on is
# usually one.  The ones that are not usually sit on thirty, and a person
# waiting on a page should not be made to wait for thirty of anything.  Past
# this the recheck still answers, it just answers about the branch it was asked
# about and does not offer to close anything.
MAX_BRANCHES = 20


# Shared memory, where there is enough of it.  The same rule the scanner uses
# for its own temp files (lib/common.sh _tmp_base): code read for a report
# should leave nothing behind on a disk.
MEMORY_DIR = "/dev/shm"
MEMORY_MIN_FREE = 256 * 1024 * 1024


def memory_dir() -> str:
    """-> /dev/shm when it is there, writable and roomy, else ""."""
    try:
        if not os.access(MEMORY_DIR, os.W_OK):
            return ""
        st = os.statvfs(MEMORY_DIR)
        return MEMORY_DIR if st.f_bavail * st.f_frsize >= MEMORY_MIN_FREE else ""
    except OSError:
        return ""


@contextlib.contextmanager
def branch_tip(connection_name: str, repository: str, branch: str,
               in_memory: bool = False):
    """A read only copy of one branch tip, gone again on the way out.

    -> yields (path, "") on success, (None, why) when it could not be fetched.

    For anything else that needs to read the code behind a finding, which is
    the same fetch a recheck does and should not be a second copy of how the
    credential reaches git.  Never raises for a fetch that fails: the caller is
    usually going to carry on without the code and say so.
    """
    from app.core import connections as connection_store, scanner_config

    with session_scope() as db:
        connection = (connection_store.by_name(db, connection_name)
                      if connection_name else None)
        provider = (getattr(connection, "provider", None) or "github")
        web = (connection.web_url if connection is not None else None) \
            or "https://github.com"
        env = scanner_config.scanner_env(db, {}, connection=connection)

    token = env.get("GHSCAN_TOKEN", "")
    if not token:
        yield None, "no credential for that account"
        return

    # in_memory asks for shared memory, and falls back to the usual temp
    # directory when there is none.  Either way the copy is gone on the way out.
    where = memory_dir() if in_memory else ""
    with tempfile.TemporaryDirectory(prefix="gcr-read-", dir=where or None) as tmp:
        work = Path(tmp)
        token_file = work / "token"
        token_file.write_text(token)
        token_file.chmod(0o600)
        dest = work / "repo"
        ok, why = _shallow_clone("%s/%s.git" % (web.rstrip("/"), repository),
                                 branch or "HEAD", dest,
                                 _credential_args(token_file, provider))
        # The token has done its job.  Nothing that reads the copy needs it.
        token_file.unlink(missing_ok=True)
        yield (dest, "") if ok else (None, why)


def recheck(finding_id: int, actor: str = "") -> dict:
    """Look at one finding again.  Returns a verdict.

    Writes only when the evidence is as complete as a scan's would be, which
    means having looked at every branch the finding is recorded on.  See
    _recheck for why that line is where it is.
    """
    if not _slots.acquire(blocking=False):
        return {"ok": False,
                "detail": "Two rechecks are already running. Try again in a moment."}
    try:
        return _recheck(finding_id, actor=actor)
    finally:
        _slots.release()


def _recheck(finding_id: int, actor: str = "") -> dict:
    """The work.  Reads the finding, looks again, and decides whether it may say so.

    A scan decides a finding's state by walking every branch.  This used to
    look at one and write nothing, on the argument that a partial answer must
    not overwrite a complete one, which is right and was applied too widely: a
    finding that lives on one branch is entirely covered by looking at that one
    branch, and refusing to act on that is refusing evidence it has.

    So the line is drawn at coverage rather than at method.  Every branch the
    finding is recorded on gets looked at, and only if all of them come back
    clean is it closed.  Anything less says so and changes nothing, because
    "not on the branch I looked at" and "gone" are still different sentences.

    That closing is for code findings only.  A credential is found in history,
    which a tip never covers, so a recheck can confirm one but not close it.
    """
    import json as _json

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
        state = row.state
        image_ref = getattr(row, "image_ref", "") or ""
        base_upgraded = bool(getattr(row, "base_upgraded", False))
        dockerfile = getattr(row, "dockerfile", "") or ""
        try:
            recorded = [b for b in (_json.loads(row.branches or "[]") or []) if b]
        except (TypeError, ValueError):
            recorded = []
        if not recorded and branch:
            recorded = [branch]
        connection = (connection_store.by_name(db, row.connection)
                      if row.connection else None)
        from app.core import settings_store as store
        rulesets = list(store.get(db, "code.rulesets") or [])
        provider = (getattr(connection, "provider", None) or "github")
        web = (connection.web_url if connection is not None else None) \
            or "https://github.com"

    if kind == FindingKind.DEPENDENCY:
        # Say which kind of dependency finding it is, because the honest answer
        # differs and one refusal for both was reading as a shrug.
        if image_ref and base_upgraded:
            where = (" It is asked for by %s." % dockerfile) if dockerfile else ""
            return {"ok": False,
                    "detail": "This package came from a pinned base image, and "
                              "the build upgrades it after pulling.  Reading "
                              "the image again would report the version the "
                              "digest ships, which is the one already named "
                              "here, so it would keep confirming a finding the "
                              "build has already dealt with." + where}
        if image_ref:
            return {"ok": False,
                    "detail": "This package came from a base image rather than "
                              "from this repository, so the fix is a newer "
                              "base.  Reading the image again needs the image, "
                              "which is a scan rather than a look at a file."}
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

        # Every branch this finding is recorded on, or just the one it was
        # filed against when the list is longer than a person should wait for.
        walk = recorded if recorded and len(recorded) <= MAX_BRANCHES else \
            ([branch] if branch else ["HEAD"])
        complete = walk == recorded and bool(recorded)

        def look(where: str) -> tuple:
            """-> (ok, still_there, why).  One branch, already checked out."""
            if not (dest / rel_path).exists():
                return True, False, ""
            if kind == FindingKind.CREDENTIAL:
                good, rules, why = _gitleaks_hits(dest, rel_path)
            else:
                good, rules, why = _semgrep_hits(dest, rel_path, rulesets)
            if not good:
                return False, False, why
            if not rules:
                return True, False, ""
            if rule and rule not in rules:
                return True, False, ""
            return True, True, ""

        found_on, missed = [], []
        for index, name in enumerate(walk):
            if index:
                if not (_fetch_branch(dest, url, name,
                                      _credential_args(token_file, provider))
                        and _checkout(dest, "recheck/" + name)):
                    # A branch that could not be read is not a branch that came
                    # back clean.  Recorded so the verdict below knows its own
                    # coverage is short, rather than counting silence as good
                    # news, which is the whole failure this guards against.
                    missed.append(name)
                    continue
            good, still_there, why = look(name)
            if not good:
                return {"ok": False, "detail": why}
            if still_there:
                found_on.append(name)

        if missed:
            complete = False
        looked_at = len(walk) - len(missed)

        if found_on:
            _record(finding_id, present=True, actor=actor, branches=found_on)
            return {"ok": True, "present": True, "wrote": "confirmed",
                    "detail": "Still there: %s in %s on %s."
                              % (rule or "the finding", rel_path,
                                 ", ".join(found_on))}

        if kind == FindingKind.CREDENTIAL:
            # Never closed from here.  A credential's branches are the ones
            # whose history holds the commit, not the ones where it sits at
            # the tip, and the scan reads that history.  Taking the line out
            # of the file leaves the commit where it was, so the next scan
            # finds it and reopens it, which read as the button not working.
            # Only rewriting history makes it gone, and a tip cannot show that.
            return {"ok": True, "present": False,
                    "detail": "The detector did not find it in %s at the tip "
                              "of %s.  Left open, because a credential stays "
                              "in the history of every branch that has the "
                              "commit, and the scan reads that history and "
                              "would reopen it.  Rotate the credential, then "
                              "waive it with that reason, or remove it from "
                              "the history and the next scan will close it."
                              % (rel_path, _english(walk))}

        if complete:
            closed = _record(finding_id, present=False, actor=actor,
                             branches=walk)
            if closed:
                return {"ok": True, "present": False, "wrote": "closed",
                        "detail": "Gone from %s, which is every branch this was "
                                  "recorded on, so it is closed."
                                  % _english(walk)}
            return {"ok": True, "present": False,
                    "detail": "Gone from every branch this was recorded on.  It "
                              "was already closed or waived, so nothing changed."}

        why_not = ("could not read %s" % _english(missed)) if missed else \
            ("this was recorded on %d branches, more than a recheck will walk"
             % len(recorded))
        return {"ok": True, "present": False,
                "detail": "Not in %s on %s.  Left open, because %s, and gone "
                          "from one branch is not gone."
                          % (rel_path, _english(walk[:len(walk)] if looked_at
                                                else walk), why_not)}
