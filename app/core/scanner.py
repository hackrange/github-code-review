"""Running a scan.

Shells out to bin/ghscan, waits, then folds the report into the database and
rewrites the two files on disk.  One scan at a time, because they all want the
same GitHub rate limit budget and the same disk.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import threading
from pathlib import Path

from app.config import settings
from app.core.audit import record
from app.core.db import session_scope
from app.core.ingest import ingest_components, ingest_report
from app.core import scanner_config
from app.core import settings_store as store
from app.core.models import ScanRun, utcnow
from app.core.reports import keep_sboms, write_reports

log = logging.getLogger("gcr.scanner")

# How many scans may run at once.  One by default, which is what this always
# did, so an installation that does not want this sees no change.  Worth
# raising once there is a schedule per organization: two small runs go together
# happily on a machine with the cores, and one slow organization should not
# hold up the rest of the night.
#
# The gate is a semaphore rather than a lock because the question changed from
# "is one running" to "are there fewer than N".
_gate = threading.BoundedSemaphore(1)
_gate_size = 1
_gate_lock = threading.Lock()

# Which scans are running, by run id, so a stop names the one it means.  This
# used to be a single handle and a single lock, which was fine while one was
# the only possible number.
_running = {}

# Connections with a scan already in flight, guarded by _process_lock.
#
# The gate counts scans, not accounts.  With more than one slot a manual scan
# and the nightly sweep can land on the same connection at the same time, both
# clone the same repositories and both ingest into the same rows.  That was
# seen: one connection scanned twice at once, seventeen results written by each.
_scanning_connections = set()

# How many runs hold a permit right now, which is not the same as how many
# have a process yet.  start_background returns as soon as the gate is taken,
# and a page that asks "is a scan running" in that gap has to be told yes or
# it will offer to start a second one.
_inflight = 0
_process_lock = threading.Lock()

# Set while a stop is being honoured, so the run that is going down knows the
# difference between being killed and falling over.
_stopped = threading.Event()


def set_concurrency(limit: int) -> None:
    """Resize the gate.  Called at start up from the settings.

    Only ever grows or shrinks between scans: a semaphore cannot be resized
    with permits outstanding, so this refuses rather than corrupting the count
    while anything is running.
    """
    global _gate, _gate_size
    limit = max(1, min(int(limit or 1), 16))
    with _gate_lock:
        if limit == _gate_size:
            return
        if _running:
            log.warning("not changing the scan limit to %d while %d scan(s) "
                        "are running; it takes effect next time", limit, len(_running))
            return
        _gate = threading.BoundedSemaphore(limit)
        _gate_size = limit
        log.info("up to %d scan(s) may run at once", limit)


def concurrency() -> int:
    return _gate_size


def running_ids() -> list:
    with _process_lock:
        return sorted(_running)


# What the scanner prints, and what it actually means.
#
# The log tail is the truth and it stays in log_excerpt.  This turns the part
# that matters into one sentence somebody can act on, because "exit 1" and
# forty lines of output do not tell a person which of their accounts to go and
# look at.
#
# Ordered, first match wins, so put the specific ones above the general ones.
FAILURE_REASONS = [
    ("nothing in scope",
     "No repositories to scan.  The credential reached the account, but there "
     "is nothing in it, or nothing it has been given access to."),
    ("bad credentials",
     "The credential was refused.  It has probably expired or been revoked."),
    ("401",
     "The credential was refused.  It has probably expired or been revoked."),
    ("could not resolve host",
     "The host could not be reached.  Check the address on the connection and "
     "whether this machine has a route to it."),
    ("connection refused",
     "The host refused the connection.  Check the address and any firewall "
     "between here and it."),
    ("rate limit",
     "The account ran out of API requests.  Raise the reserve on the Limits "
     "settings, or scan fewer repositories at once."),
    ("no space left",
     "The disk filled up.  Clones go to the work directory; free some space "
     "there and run it again."),
    ("ran past its time limit",
     "The scan ran longer than it is allowed to.  Raise \"give up on the whole "
     "scan after\" on the Limits settings, or narrow what this account covers."),
    ("killed",
     "A scanner engine was killed, which is almost always the machine running "
     "out of memory.  Lower the file size limit on the Limits settings."),
]


# What the scanner says when a credential worked and the account holds nothing.
# The scanner refuses to build a report out of no repositories, which is right,
# but it is not the same thing as a scan that went wrong.
NOTHING_IN_SCOPE = "nothing in scope"


def is_empty_account(text: str) -> bool:
    """Did this run end because there was nothing to scan.

    An account somebody has set up before the team puts anything in it scans
    cleanly and finds nothing, every night, for weeks.  Filing that as a failure
    teaches everybody to ignore a red row, and the night a real one appears it
    looks exactly the same.

    It is not recorded as a success either.  Zero repositories is also what a
    mistyped organization looks like, and a scan that quietly covers nothing
    while reporting that all is well is the one outcome this must never produce.
    """
    return NOTHING_IN_SCOPE in (text or "").lower()


def _scan_ceiling() -> int:
    """Seconds a whole run may take before it is stopped.

    The setting, because a scan that dies on this tells somebody to raise it
    and they have to be able to.  The environment variable still wins where it
    is set: an install that reached for it when there was nothing else should
    not have it quietly ignored by an upgrade.
    """
    from_env = os.environ.get("GCR_SCAN_TIMEOUT_SEC", "").strip()
    if from_env:
        try:
            return max(60, int(from_env))
        except ValueError:
            log.warning("GCR_SCAN_TIMEOUT_SEC is not a number, using the setting")

    try:
        with session_scope() as db:
            hours = float(store.get(db, "scan.max_hours") or 6)
    except Exception:
        hours = 6
    return max(60, int(hours * 3600))


def failure_reason(text: str, exit_code=None) -> str:
    """-> one sentence, or a fallback that at least says where to look."""
    lowered = (text or "").lower()
    for needle, sentence in FAILURE_REASONS:
        if needle in lowered:
            return sentence
    if exit_code == 2:
        return "The scanner refused its own configuration.  This is a bug, not a setting."
    for line in reversed((text or "").splitlines()):
        if "[error]" in line.lower():
            return line.split("]", 1)[-1].strip()[:300]
    return "The scan did not finish.  The output below says more."


def is_running() -> bool:
    """Is anything scanning.  Kept for the pages that only ask that much.

    Counts a run that has taken a permit but not yet started its process.
    Between those two moments the answer has to be yes, or the page offers a
    second scan that the gate is about to refuse.
    """
    with _process_lock:
        return _inflight > 0 or bool(_running)


def is_full() -> bool:
    """Are all the slots taken."""
    with _process_lock:
        return max(_inflight, len(_running)) >= _gate_size


def _took_a_slot() -> None:
    global _inflight
    with _process_lock:
        _inflight += 1


def _gave_it_back() -> None:
    global _inflight
    with _process_lock:
        _inflight = max(0, _inflight - 1)


def _scanner_env() -> dict:
    """What the scanner needs, and nothing else.

    The token comes from the environment we are already holding.  It never
    lands in a file, and it never appears in the command line.
    """
    # semgrep and detect-secrets live in their own venv, because semgrep pins
    # half of pypi and will not share one with the web app.  Without this on
    # the path the scanner quietly decides code analysis is not installed.
    venv = os.environ.get("GCR_SCANNER_VENV", "/opt/gcr/scanner-venv")
    extra = Path(venv) / "bin"

    env = os.environ.copy()
    # The web app's own keys stay with the web app.  Everything below this
    # reads files somebody pushed, through a dozen parsers, and any one of them
    # misbehaving would otherwise hand over the key that signs sessions, the key
    # that decrypts every stored credential, and the database password.  The
    # scanner reads none of them.
    for name in list(env):
        if name in ("GCR_SECRET_KEY", "GCR_ENCRYPTION_KEY", "GCR_DATABASE_URL",
                    "GCR_DB_PASSWORD", "GCR_DB_PASS", "GCR_DB_USER") \
                or name.startswith("GCR_OIDC_CLIENT_SECRET"):
            del env[name]
    if extra.is_dir():
        env["PATH"] = f"{extra}:{env.get('PATH', '')}"
    env.setdefault("GHSCAN_LOG_LEVEL", "info")
    env["GHSCAN_COLOR"] = "never"
    return env


def sweep_orphans() -> int:
    """Clear scan work directories left behind by a run that was killed.

    A scan holds its clones in a temp directory under work_dir, and Python
    removes that when the block exits.  A killed process never reaches the end
    of the block, so the clones stay.  The work area is usually capped, and a
    capped area full of yesterday's orphans is what makes today's scan fail to
    clone anything at all.

    Safe at startup and only at startup: no scan can be running in a process
    that has not finished booting, so nothing here is in use.  Returns how many
    were removed, for the log.
    """
    import shutil

    root = settings.work_dir
    if not root.exists():
        return 0

    removed = 0
    live = set(running_ids())
    for path in root.glob("gcr-scan-*"):
        if not path.is_dir():
            continue
        # The run id is in the name, so a directory belonging to a scan that
        # is going right now can be recognised and left alone.  This is meant
        # to run at start up, when nothing can be running, but relying on that
        # was one restructure away from deleting a live scan's clones out from
        # under it.
        parts = path.name.split("-")
        if len(parts) >= 3 and parts[2].isdigit() and int(parts[2]) in live:
            log.debug("%s belongs to a running scan, leaving it", path.name)
            continue
        try:
            shutil.rmtree(path)
            removed += 1
        except OSError as exc:
            # Never fatal.  Failing to tidy up is not a reason to refuse to
            # start, and the next run says so again if it still matters.
            log.warning("could not remove leftover scan directory %s: %s",
                        path, exc)
    return removed


def _build_command(out_dir: Path, config_path: Path, orgs=None, repos=None,
                   only=None) -> list:
    command = [str(settings.scanner_bin), "scan",
               "-c", str(config_path),
               "-o", str(out_dir), "-q"]
    if only:
        command += ["--only", only]
    return command


def _report_directory():
    """Ask the database where reports go, falling back to the environment."""
    from app.core.reports import output_dir
    try:
        with session_scope() as db:
            return output_dir(db)
    except Exception:
        return settings.reports_dir


def reports_writable() -> tuple:
    """Can we write where the report files go.

    Worth asking before a scan rather than after, since finding out at the end
    means an hour of work and a confusing error.
    """
    directory = _report_directory()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"cannot make {directory}: {exc}"

    probe = directory / ".gcr-write-test"
    try:
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return False, (
            f"{directory} is not writable by the user this runs as "
            f"(uid {os.getuid()}): {exc}. "
            f"On the host: chown -R 10001:10001 <your reports directory>")
    return True, ""


def _keep_what_finished(run_id, results_dir, why: str) -> dict:
    """Ingest the repositories that finished before this run stopped.

    Called on every path that ends a scan early.  The work is already done and
    on disk; the only question is whether anybody reads it.
    """
    from app.core.salvage import salvage

    # The findings go in on their own, before any book-keeping touches the
    # same transaction.
    #
    # They used to share one.  A run row that somebody removed from the history
    # while the scan was still winding down left an update with nothing to
    # update, that rolled the transaction back, and the repositories already
    # scanned and sitting on disk were never read.  Fifty seven of them went
    # that way in one evening.  The work is the part worth keeping; the row it
    # is filed under is not.
    kept = {"repositories": 0}
    try:
        with session_scope() as db:
            kept = salvage(db, results_dir)
    except Exception:            # noqa: BLE001 - salvage must never mask the failure
        log.exception("could not keep what the scan had already found")
        return {"repositories": 0}

    if not kept.get("repositories"):
        return kept

    # Then say so.  Allowed to fail on its own without taking the findings
    # with it: by here they are committed.
    try:
        with session_scope() as db:
            run = db.query(ScanRun).filter(ScanRun.id == run_id).one_or_none()
            if run is not None:
                run.repositories = kept["repositories"]
                run.findings_new = kept.get("new", 0)
                run.findings_updated = kept.get("updated", 0)
                # Deliberately not counted as resolved.  A repository this
                # run never reached still has whatever it had.
                run.findings_resolved = kept.get("resolved", 0)
            record(db, "scan.partial", actor="system",
                   detail=(f"{why}; kept {kept['repositories']} "
                           f"repository(ies) that had finished"),
                   outcome="warn")
    except Exception:            # noqa: BLE001
        log.warning("kept %d repository(ies) but could not record it against "
                    "run %s", kept["repositories"], run_id, exc_info=True)
    return kept


def _drop_results(results_dir) -> None:
    """Remove per repository results that have been read into the database."""
    import shutil
    try:
        shutil.rmtree(results_dir, ignore_errors=True)
    except Exception:            # noqa: BLE001
        log.debug("could not remove %s", results_dir, exc_info=True)


def salvage_interrupted() -> int:
    """At start up, read what any killed scan had already finished.

    This is the case the in process handlers cannot cover.  A container
    recreated mid scan does not run any of them: the process is simply gone,
    and everything it found is sitting in the work area with nobody to read
    it.  So the first thing after boot marks those runs interrupted, and the
    second thing is this.

    -> how many runs had something worth keeping.
    """
    from app.core.salvage import salvage

    work = Path(settings.work_dir)
    if not work.is_dir():
        return 0

    kept_runs = 0
    for directory in sorted(work.glob("gcr-results-*")):
        if not directory.is_dir():
            continue
        try:
            run_id = int(directory.name.rsplit("-", 1)[-1])
        except ValueError:
            log.warning("%s is not named after a run, leaving it alone",
                        directory.name)
            continue

        try:
            with session_scope() as db:
                run = db.query(ScanRun).filter(ScanRun.id == run_id).one_or_none()
                if run is None:
                    _drop_results(directory)
                    continue
                # A run that finished has already had these read in.
                if run.status == "finished":
                    _drop_results(directory)
                    continue

                kept = salvage(db, directory)
                if kept.get("repositories"):
                    kept_runs += 1
                    run.repositories = kept["repositories"]
                    run.findings_new = kept.get("new", 0)
                    run.findings_updated = kept.get("updated", 0)
                    excerpt = (f"This run did not finish.  "
                               f"{kept['repositories']} repository(ies) had "
                               f"completed and their findings were kept; "
                               f"anything it never reached is unchanged.\n\n")
                    run.log_excerpt = (excerpt + (run.log_excerpt or ""))[:8000]
                    record(db, "scan.partial", actor="system",
                           detail=(f"kept {kept['repositories']} repository(ies) "
                                   f"from a run that was interrupted"),
                           outcome="warn")
            _drop_results(directory)
        except Exception:            # noqa: BLE001 - never stop the app booting
            log.exception("could not salvage %s", directory.name)

    if kept_runs:
        log.warning("kept the work of %d interrupted scan(s)", kept_runs)
    return kept_runs


def stop_scan(run_id=None) -> dict:
    """Stop one running scan, by id.

    Signals the whole process group, waits a moment for it to tidy up, then
    stops being polite.  The temp directory goes with it either way, because
    the thread that started it is still inside the with block; the per
    repository results do not, which is how an operator gets to keep what it
    had already found.

    The id is optional only for the case where exactly one thing is running,
    because a page with a single Stop button meaning "whichever one happens to
    be going" is fine when there can only be one and wrong the moment there
    can be two.
    """
    import signal

    with _process_lock:
        if run_id is None:
            if len(_running) == 1:
                run_id = next(iter(_running))
            elif len(_running) > 1:
                return {"ok": False,
                        "reason": (f"{len(_running)} scans are running.  "
                                   "Say which one.")}
        process = _running.get(run_id)

    if process is None or process.poll() is not None:
        return {"ok": False, "reason": "Nothing is running."}

    _stopped.set()
    # Read this before signalling anything.  Once the process is gone its
    # command line is gone with it, and that is what identifies the strays.
    marker = _work_marker(process)

    try:
        group = os.getpgid(process.pid)
    except OSError:
        group = None

    try:
        if group is not None:
            os.killpg(group, signal.SIGTERM)
        else:
            process.terminate()
    except OSError as exc:
        return {"ok": False, "reason": f"could not stop it: {exc}"}

    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log.warning("the scanner did not stop when asked, killing it")

    # Then kill the group whatever happened.  The scanner exits as soon as it
    # is asked, but the workers it fanned out to are mid clone or mid scan and
    # some of them are slower to notice.
    try:
        if group is not None:
            os.killpg(group, signal.SIGKILL)
        else:
            process.kill()
    except OSError:
        pass

    # Anything left over.  Some of what the scanner drives puts itself in its
    # own process group, and those survive a signal aimed at ours.  They all
    # carry the run's working directory on their command line, so that is what
    # we look for.
    strays = _kill_strays(marker)
    if strays:
        log.warning("cleaned up %d stray process(es) after stopping", strays)

    return {"ok": True}


def _work_marker(process) -> str:
    """The run's temp directory, which every process in it names."""
    try:
        with open(f"/proc/{process.pid}/cmdline", "rb") as handle:
            argv = handle.read().decode("utf-8", "replace").split("\0")
    except OSError:
        argv = []
    for item in argv:
        if "gcr-scan-" in item:
            start = item.index("gcr-scan-")
            return item[:start + len("gcr-scan-") + 8]
    return ""


def _kill_strays(marker: str) -> int:
    """Kill anything still running that belongs to this scan.

    Matching on the working directory is precise: it is a fresh temp directory
    per run, so nothing else on the machine mentions it.
    """
    import signal

    if not marker:
        return 0

    killed = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                argv = handle.read().decode("utf-8", "replace")
        except OSError:
            continue
        if marker not in argv:
            continue
        try:
            os.kill(int(entry), signal.SIGKILL)
            killed += 1
        except OSError:
            pass
    return killed


def check_credential(connection_id=None) -> dict:
    """Ask GitHub who we are, using one connection or the settings.

    No repositories, no clones.  This is the button on the Settings page that
    tells somebody whether the token they just pasted actually works.
    """
    with tempfile.TemporaryDirectory(prefix="gcr-check-") as tmp:
        work = Path(tmp)
        with session_scope() as db:
            row = None
            if connection_id is not None:
                from app.core import connections as connection_store
                row = connection_store.by_id(db, connection_id)
            config_path = scanner_config.build(db, work, connection=row)
            env = scanner_config.scanner_env(db, _scanner_env(), connection=row)
            method = (row.auth_method if row is not None
                      else store.get(db, "github.auth_method"))
            if method == "app":
                scanner_config.write_app_key(db, work / "github-app.pem",
                                             connection=row)

        command = [str(settings.scanner_bin), "check", "-c", str(config_path)]
        try:
            done = subprocess.run(command, env=env, capture_output=True,
                                  text=True, timeout=120)
        except subprocess.TimeoutExpired:
            return {"ok": False, "detail": "GitHub did not answer in two minutes."}
        except OSError as exc:
            return {"ok": False, "detail": f"could not run the scanner: {exc}"}

    output = ((done.stdout or "") + "\n" + (done.stderr or "")).strip()
    return {"ok": done.returncode == 0, "detail": _explain_check(output,
                                                                done.returncode)}


def _explain_check(output: str, code: int) -> str:
    """Turn the scanner's log into one sentence somebody can act on."""
    import re

    lowered = output.lower()

    if code == 0:
        who = re.search(r"authenticated as (\S+)", output)
        left = re.search(r'"remaining":(\d+)', output)
        parts = ["Signed in to GitHub"]
        if who:
            parts.append(f"as {who.group(1)}")
        if left:
            parts.append(f"with {left.group(1)} requests left this hour")
        # Name anything that is absent.  A scanner missing an engine still
        # exits zero and reports nothing from it, which reads like a clean
        # repository rather than a check that never ran.
        absent = [line.split()[0] for line in output.splitlines()
                  if re.match(r"\s+\S+\s+absent\s", line)]
        if absent:
            parts.append("Not installed, so those checks find nothing: "
                         + ", ".join(absent) + ".")
        return " ".join(parts) + ("" if absent else ". Every engine is installed.")

    # The ones worth naming, because the fix is different for each.
    if "401" in output or "bad credentials" in lowered:
        return ("GitHub refused the credential. The token is wrong, expired, or "
                "was revoked. Make a new one and paste it in again.")
    if "sso" in lowered or "saml" in lowered:
        return ("The token works but has not been authorized for your "
                "organization. On the token's page press Configure SSO and "
                "authorize each organization you want scanned.")
    if "403" in output and "rate" in lowered:
        return ("GitHub is rate limiting this credential. Wait for the hour to "
                "turn over and try again.")
    if "403" in output:
        return ("GitHub answered but refused. The credential is missing a "
                "permission: it needs read access to repositories, and read "
                "access to organization members if you want the access report.")
    if "could not resolve" in lowered or "connection refused" in lowered:
        return ("Could not reach the API address. Check the API address at the "
                "top of this page, and whether this host can get out.")

    problems = re.findall(r"^\s+- (.+)$", output, re.M)
    if problems:
        return "Not ready yet: " + "; ".join(problems[:3])

    tail = [line.strip() for line in output.splitlines() if line.strip()]
    return tail[-1][:300] if tail else "The check produced no output at all."


# The scanner talks to us on stderr while it runs.  Reading it only after it
# exits, which is what communicate() does, means a connection that spends forty
# minutes in a rate limit backoff says nothing at all until it is over, and the
# whole time it looks like it has hung.  Pump both pipes on their own threads
# instead, so every warning reaches the log the moment ghscan writes it.
def _log_scanner_line(line: str) -> None:
    if "[error]" in line:
        log.error("ghscan: %s", line)
    elif "[warn " in line:
        log.warning("ghscan: %s", line)
    else:
        log.debug("ghscan: %s", line)


def _pump(pipe, collected: list, sink=None) -> None:
    """Read a pipe to the end, keeping every line and passing it on."""
    try:
        for line in pipe:
            line = line.rstrip("\n")
            collected.append(line)
            if sink is not None and line:
                try:
                    sink(line)
                except Exception:      # a bad log line must not kill the pump
                    pass
    except (OSError, ValueError):
        pass
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            pass


def _wait_streaming(process, timeout: int):
    """Wait for the scanner, streaming its stderr, and hand back both streams.

    Same contract as communicate(timeout=...): TimeoutExpired comes straight
    back out for the caller to deal with, and the process is left alone.
    """
    out_lines: list = []
    err_lines: list = []
    pumps = [
        threading.Thread(target=_pump, args=(process.stdout, out_lines),
                         daemon=True),
        threading.Thread(target=_pump, args=(process.stderr, err_lines,
                                             _log_scanner_line), daemon=True),
    ]
    for pump in pumps:
        pump.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Still running, so the readers will not finish.  Take what they have
        # and let the caller deal with the timeout.
        for pump in pumps:
            pump.join(timeout=1)
        raise
    # Bounded, because a grandchild holding the pipe open past its parent must
    # not take this thread down with it.
    for pump in pumps:
        pump.join(timeout=30)
    return "\n".join(out_lines), "\n".join(err_lines)


def run_scan(triggered_by: str = "", trigger: str = "manual",
             orgs=None, repos=None, only=None, connection=None,
             branch_names=None, _holds_lock: bool = False) -> dict:
    """Do a scan, start to finish.

    Blocks until it is done, so call it on a worker thread.  Returns a summary
    of what changed.

    connection names which account to scan.  Without one it falls back to the
    credential in the settings, which is what an install that predates
    connections has.
    """
    # _holds_lock says the caller already owns the gate on our behalf, which
    # is how a whole sweep of connections stays one indivisible job.
    if not _holds_lock:
        if not _gate.acquire(blocking=False):
            return {"ok": False, "reason": "A scan is already running."}
        _took_a_slot()

    ok, problem = reports_writable()
    if not ok:
        log.warning("reports directory problem: %s", problem)

    scope = json.dumps({"orgs": list(orgs or []), "repos": list(repos or []),
                        "branches": list(branch_names or []), "only": only or ""})

    # What this scan is aimed at, in the audit log's own words.  "scan.started"
    # with nothing beside it says a scan started, which nobody needed telling.
    # The useful question is which account, and after that which organizations,
    # and both are already known here.
    aimed_at = (connection.name if connection is not None else "")
    if not aimed_at:
        named = list(orgs or []) or list(repos or [])
        if named:
            aimed_at = ", ".join(str(n) for n in named[:3])
            if len(named) > 3:
                aimed_at += f" and {len(named) - 3} more"
        else:
            aimed_at = "everything the credential can see"
    aimed_at = aimed_at[:512]

    # One scan per connection.  This has to sit outside the _holds_lock test,
    # because the collision worth stopping is a sweep meeting a scan somebody
    # started by hand, and those two arrive by different routes.
    claimed = None
    if connection is not None:
        with _process_lock:
            if connection.id in _scanning_connections:
                if not _holds_lock:
                    _gate.release()
                    _gave_it_back()
                log.warning("%s is already being scanned, so this one stops here",
                            connection.name)
                return {"ok": False,
                        "reason": (f"{connection.name} is already being "
                                   f"scanned.  Wait for that one to finish.")}
            _scanning_connections.add(connection.id)
            claimed = connection.id

    # Claimed last, with nothing between here and the try that could raise.
    # A claim left behind by an exception would lock this connection out of
    # every future scan until a restart.
    run_id = None
    try:
        with session_scope() as db:
            run = ScanRun(triggered_by=triggered_by or "", trigger=trigger,
                          scope=scope, status="running",
                          connection=(connection.name if connection is not None else ""))
            db.add(run); db.flush()
            run_id = run.id
            record(db, "scan.started", actor=triggered_by or trigger,
                   target=aimed_at, detail=scope)

        # Per repository results live outside the scan's temp directory, and
        # outlive it deliberately.  Everything else here is thrown away when
        # the run ends however it ends; these are the work itself, and they
        # are removed only once they have been read into the database.  The
        # run id is in the name so that what is left after a kill can be
        # matched back to the run it belongs to.
        results_dir = Path(settings.work_dir) / f"gcr-results-{run_id}"
        try:
            results_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.warning("could not make a results directory, so an "
                        "interrupted scan will keep nothing: %s", exc)

        with tempfile.TemporaryDirectory(prefix=f"gcr-scan-{run_id}-",
                                         dir=str(settings.work_dir)
                                         if settings.work_dir.exists() else None) as tmp:
            out_dir = Path(tmp) / "out"

            # Build the scanner config from the settings in the database, into
            # the temp directory.  It goes away with everything else when this
            # block exits, so nothing site specific is left lying around.
            with session_scope() as db:
                live_connection = None
                if connection is not None:
                    from app.core import connections as connection_store
                    live_connection = connection_store.by_id(db, connection.id)
                config_path = scanner_config.build(db, Path(tmp), orgs=orgs,
                                                   repos=repos,
                                                   connection=live_connection,
                                                   branch_names=branch_names)
                env = scanner_config.scanner_env(db, _scanner_env(),
                                                 connection=live_connection)
                method = (live_connection.auth_method if live_connection is not None
                          else store.get(db, "github.auth_method"))
                if method == "app":
                    scanner_config.write_app_key(db, Path(tmp) / "github-app.pem",
                                                 connection=live_connection)

            env["GHSCAN_RESULTS_DIR"] = str(results_dir)

            # The rate limit belongs to the credential, not to this run.  Two
            # scans on the same connection have to watch one budget or they
            # race each other into a limit neither of them is counting.  The
            # scanner already shares this file across its own workers; this
            # widens it to every scan using the same credential.
            budget = Path(settings.work_dir) / (
                f"ratelimit-{connection.id}.json" if connection is not None
                else "ratelimit-default.json")
            env["GHSCAN_RL_STATE"] = str(budget)

            command = _build_command(out_dir, config_path, orgs, repos, only)
            log.info("scan starting: %s", " ".join(command))

            # Its own session, so stopping it takes the whole tree with it:
            # the scanner, the workers it fans out to, and whatever they are
            # running at the time.
            process = subprocess.Popen(
                command, env=env, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True)
            with _process_lock:
                _running[run_id] = process

            try:
                stdout, stderr = _wait_streaming(process, _scan_ceiling())
            finally:
                with _process_lock:
                    _running.pop(run_id, None)

            completed = subprocess.CompletedProcess(
                command, process.returncode, stdout, stderr)

            # The SBOMs, before the temporary directory takes them with it.
            #
            # Here rather than after the ingest because this runs for every
            # way a scan can end.  A run that was stopped half way still wrote
            # an SBOM for each repository that finished, and those are the
            # ones somebody is waiting on when they stopped it to look.
            kept_sboms = keep_sboms(out_dir, _report_directory())
            if kept_sboms["repositories"] or kept_sboms["combined"]:
                log.info("kept %d per-repository and %d combined SBOM file(s)",
                         kept_sboms["repositories"], kept_sboms["combined"])

            if _stopped.is_set():
                _stopped.clear()
                log.info("scan stopped by hand")
                with session_scope() as db:
                    run = db.query(ScanRun).filter(ScanRun.id == run_id).one()
                    run.status = "stopped"
                    run.finished_at = utcnow()
                    run.exit_code = completed.returncode
                    run.log_excerpt = "\n".join(
                        (completed.stderr or "").splitlines()[-40:])[:8000]
                    record(db, "scan.stopped", actor=triggered_by or trigger,
                           target=aimed_at,
                           detail="stopped from the Scans page")
                kept = _keep_what_finished(run_id, results_dir,
                                           "stopped from the Scans page")
                return {"ok": False, "reason": "The scan was stopped.",
                        "stopped": True, "kept": kept.get("repositories", 0)}

            # The last forty lines, plus every warning from the whole run.
            #
            # The tail on its own hid a real failure.  semgrep checks each of
            # its rulesets against the registry before it starts and drops any
            # the registry does not answer for, saying so once, early.  On a
            # scan of a large repository that line is thousands of lines from
            # the end, so it fell off and the run looked clean while quietly
            # missing most of its rules: one scan found 390 fewer things than
            # the one before it and reported success both times.
            #
            # A scanner that under-reports in silence is worse than one that
            # fails, because nothing about the output says to look.
            _err = (completed.stderr or "").splitlines()
            warnings = [line for line in _err
                        if "[warn " in line or "[error]" in line]
            tail = "\n".join(_err[-40:])
            if warnings:
                seen, unique = set(), []
                for line in warnings:
                    if line not in seen:
                        seen.add(line)
                        unique.append(line)
                tail = ("warnings from this run:\n"
                        + "\n".join(unique[-60:])
                        + "\n\nlast lines:\n" + tail)
            report = out_dir / "ghscan-report.json"

            if not report.exists():
                empty = is_empty_account(tail)
                if empty:
                    log.info("nothing to scan under %s", aimed_at)
                else:
                    log.error("scan produced no report, exit %s",
                              completed.returncode)
                with session_scope() as db:
                    run = db.query(ScanRun).filter(ScanRun.id == run_id).one()
                    run.status = "empty" if empty else "failed"
                    run.finished_at = utcnow()
                    run.exit_code = completed.returncode
                    run.log_excerpt = tail[:8000]
                    run.failure_reason = failure_reason(tail, completed.returncode)
                    record(db, "scan.empty" if empty else "scan.failed",
                           actor=triggered_by or trigger, target=aimed_at,
                           detail=("no repositories in scope" if empty
                                   else f"exit {completed.returncode}"),
                           outcome="warn" if empty else "error")
                kept = _keep_what_finished(
                    run_id, results_dir,
                    f"the scanner exited {completed.returncode} without a report")
                return {"ok": bool(empty),
                        "reason": ("There is nothing in this account to scan."
                                   if empty
                                   else "The scan did not produce a report."),
                        "empty": empty,
                        "exit_code": completed.returncode, "log": tail,
                        "kept": kept.get("repositories", 0)}

            scanned = set()
            trouble = []
            counted = {"failed": 0, "skipped": 0, "branches": 0}
            try:
                document = json.loads(report.read_text(encoding="utf-8"))
                for entry in document.get("repositories", []):
                    name = entry.get("repository", {}).get("full_name")
                    status = entry.get("status", "ok")
                    if name and status == "ok":
                        scanned.add(name)
                    elif name:
                        # Deliberately not added to `scanned`, including when
                        # it is partial.  Everything in that set has its absent
                        # findings marked resolved, and a repository that was
                        # stopped half way did not look for them: calling them
                        # fixed would be the scanner inventing good news.
                        # Say which one and why.  A repository that drops out
                        # without a word turns a partial scan into one that
                        # looks complete.
                        counted[status] = counted.get(status, 0) + 1
                        reason = (entry.get("error") or "no reason given")
                        if status == "partial":
                            done = ", ".join(entry.get("passes_complete") or []) or "nothing"
                            reason = f"kept what finished ({done})"
                        trouble.append(f"{status}: {name}: {reason}"[:300])
                    counted["branches"] += int(entry.get("branch_count") or 0)
            except (ValueError, KeyError, TypeError):
                pass

            if trouble:
                log.warning("%d repositor(y/ies) did not finish: %s",
                            len(trouble), "; ".join(trouble[:5]))

            # Save the scan first, on its own.  Writing the report files is a
            # separate job, because it can fail on something as ordinary as
            # the reports directory not being writable, and losing an hour of
            # scanning to that would be absurd.
            with session_scope() as db:
                tagged = None
                if connection is not None:
                    from app.core import connections as connection_store
                    tagged = connection_store.by_id(db, connection.id)
                counts = ingest_report(db, report, scanned_repos=scanned,
                                       connection=tagged)

                # The software inventory, from the SBOM bundle beside the
                # report.  Its own step because it can fail on a scan that
                # produced no SBOM at all, and that must not cost the
                # findings.
                try:
                    counts["components"] = ingest_components(
                        db, out_dir / "ghscan-report-sbom.json",
                        connection=tagged)["components"]
                except Exception:            # noqa: BLE001
                    log.warning("could not read the software inventory",
                                exc_info=True)

                # Tell somebody, while the session is still open and the
                # findings are still attached to it.  A transport that is down
                # must not take the scan with it, so nothing here is allowed
                # to raise.
                try:
                    from app.core import notify
                    if notify.enabled(db):
                        label = getattr(connection, "name", "") or ""
                        # The account row, not the handle the scan was started
                        # with.  It carries who asked to hear about this one,
                        # and it is already loaded on this session.
                        notify.announce(db, counts.get("new_findings") or [],
                                        scan_label=label, connection=tagged)
                except Exception:            # noqa: BLE001
                    log.warning("could not send notifications", exc_info=True)

                run = db.query(ScanRun).filter(ScanRun.id == run_id).one()
                run.status = "finished"
                run.finished_at = utcnow()
                run.exit_code = completed.returncode
                run.repositories = counts["repositories"]
                run.repositories_failed = counted.get("failed", 0)
                run.repositories_skipped = counted.get("skipped", 0)
                run.repositories_partial = counted.get("partial", 0)
                run.branches = counted.get("branches", 0)
                run.findings_new = counts["new"]
                run.findings_updated = counts["updated"]
                run.findings_resolved = counts["resolved"]
                # Keep the warnings even when the scan worked.  They are where
                # a repository that fell over says so.
                run.log_excerpt = ("\n".join(trouble) + "\n\n" + tail)[:8000]

                detail = (f"{counts['repositories']} repos, "
                          f"{counts['new']} new, {counts['updated']} updated, "
                          f"{counts['resolved']} resolved")
                if trouble:
                    detail += f", {len(trouble)} did not finish"
                record(db, "scan.finished", actor=triggered_by or trigger,
                       target=aimed_at,
                       outcome="warn" if trouble else "ok", detail=detail)

            counts.pop("new_findings", None)
            log.info("scan done: %s", counts)

            # The findings are in the database now, so the copies on disk have
            # done their job.  Removed here rather than in a finally, because
            # every other way out of this function wants them kept.
            _drop_results(results_dir)

            # Now the files.  If this fails the scan is still saved, and the
            # Report files page has a button to try again.
            reported = None
            try:
                with session_scope() as db:
                    reported = write_reports(db)["findings"]
            except OSError as exc:
                log.error("could not write the report files: %s", exc)
                with session_scope() as db:
                    run = db.query(ScanRun).filter(ScanRun.id == run_id).one()
                    run.log_excerpt = (
                        f"The scan worked and the findings are saved, but the "
                        f"report files could not be written: {exc}\n\n"
                        + (run.log_excerpt or ""))[:8000]
                    record(db, "reports.write_failed",
                           actor=triggered_by or trigger,
                           detail=str(exc)[:300], outcome="error")
                return {"ok": True, **counts, "reported": None,
                        "warning": f"The findings are saved but the report "
                                   f"files could not be written: {exc}"}

            return {"ok": True, **counts, "reported": reported}

    except subprocess.TimeoutExpired:
        log.error("scan timed out")
        with session_scope() as db:
            run = db.query(ScanRun).filter(ScanRun.id == run_id).one_or_none()
            if run is not None:
                run.status = "failed"
                run.finished_at = utcnow()
                run.log_excerpt = "the scan ran past its time limit"
                run.failure_reason = failure_reason("ran past its time limit")
            record(db, "scan.failed", actor=triggered_by or trigger,
                   target=aimed_at, detail="timed out", outcome="error")
        kept = _keep_what_finished(run_id, results_dir, "the scan timed out")
        return {"ok": False, "reason": "The scan ran past its time limit.",
                "kept": kept.get("repositories", 0)}

    except Exception as exc:
        log.exception("scan blew up")
        # The whole traceback, not just the message.  A scan that fails on
        # something nobody predicted leaves an operator with one sentence and
        # nowhere to look: "cannot use 'dict' as a dict key" says what went
        # wrong and nothing about where.  The traceback is already being
        # logged; putting it on the run means the Scans page can show it
        # without anybody having to reach the container.
        import traceback
        detail = traceback.format_exc()
        with session_scope() as db:
            run = db.query(ScanRun).filter(ScanRun.id == run_id).one_or_none()
            if run is not None:
                run.status = "failed"
                run.finished_at = utcnow()
                run.log_excerpt = detail[-8000:]
                run.failure_reason = failure_reason(str(exc))
            record(db, "scan.failed", actor=triggered_by or trigger,
                   target=aimed_at, detail=str(exc)[:200], outcome="error")
        kept = _keep_what_finished(run_id, results_dir,
                                   f"the scan failed: {str(exc)[:120]}")
        return {"ok": False, "reason": str(exc)[:200],
                "kept": kept.get("repositories", 0)}

    finally:
        if claimed is not None:
            with _process_lock:
                _scanning_connections.discard(claimed)
        if not _holds_lock:
            _gate.release()
            _gave_it_back()


def catchup_backlog(session, limit: int = 5):
    """The repositories whose history nobody has walked to the end.

    Furthest behind first: a repository that has been stuck at the same marker
    for weeks matters more than one that is a window from done.  Grouped by
    account, because a scan runs against one credential.
    """
    from app.core.models import Repository

    rows = (session.query(Repository)
            .filter(Repository.history_complete.is_(False))
            .filter(Repository.history_from != "")
            # Least recently attempted first, and only then furthest behind.
            #
            # Ordering by the marker alone made this a ranking rather than a
            # rotation.  A repository whose marker cannot move stays at the top
            # of a ranking for ever: one was picked every twenty minutes, four
            # passes running, doing two minutes of work each time and finishing
            # exactly where it started, while six others that could have
            # progressed waited behind it.  The marker was withheld because its
            # credential engine died, which is the correct thing to do and
            # which nothing here could see.
            #
            # This does not try to work out whether a repository is broken.  It
            # only stops any one of them holding the queue: attempted goes to
            # the back, and a broken one still comes round again in its turn.
            .order_by(Repository.history_attempted_at.asc().nullsfirst(),
                      Repository.history_from.asc())
            .limit(200).all())
    if not rows:
        return None, []

    # The account the most-behind repository belongs to takes this pass.
    lead = rows[0]
    same = [r for r in rows if r.connection_id == lead.connection_id][:max(1, limit)]
    return lead.connection_id, [r.full_name for r in same]


def run_catchup(triggered_by: str = "catchup") -> dict:
    """Walk another window of history, if the machine is doing nothing else.

    Deliberately timid.  It refuses when any scan is running rather than taking
    a free slot beside one, because the point is to use time nobody wants: a
    catch up pass that competes with the nightly scan has taken something
    rather than used something.
    """
    from app.core import connections as connection_store

    with _process_lock:
        if _running:
            return {"ok": False, "reason": "Something is already scanning."}

    with session_scope() as db:
        if not store.get(db, "catchup.enabled"):
            return {"ok": False, "reason": "Catch up is switched off."}
        try:
            limit = int(store.get(db, "catchup.repos_per_run") or 5)
        except (TypeError, ValueError):
            limit = 5
        if int(store.get(db, "secrets.history_window_days") or 0) <= 0:
            # Without a window nothing records how far it got, so there is
            # nothing to carry on from and this would just rescan.
            return {"ok": False, "reason": "No history window is set."}
        connection_id, repos = catchup_backlog(db, limit)
        if not repos:
            return {"ok": False, "reason": "Every history has been walked to its end."}
        # Written down before the scan rather than after it, because the point
        # is to record the attempt and not the outcome.  A pass that achieves
        # nothing is exactly the case this is here for, and a repository whose
        # scan dies would never reach a line placed afterwards.
        from app.core.models import Repository as _Repo

        (db.query(_Repo).filter(_Repo.full_name.in_(repos))
         .update({_Repo.history_attempted_at: utcnow()},
                 synchronize_session=False))
        db.flush()
        row = connection_store.by_id(db, connection_id)
        if row is None or not row.enabled or not connection_store.configured(row):
            return {"ok": False, "reason": "The account those repositories came from is not usable."}
        connection = _Detached(row)
        name = row.name

    log.info("catch up: %d repositor(y/ies) on %s", len(repos), name)
    return run_scan(triggered_by=triggered_by, trigger="catchup",
                    repos=repos, connection=connection)


def run_every_connection(triggered_by: str = "", trigger: str = "manual",
                        only=None, connection_id=None, orgs=None, repos=None,
                        _holds_lock: bool = False) -> dict:
    """Scan each account in turn, one run apiece.

    One run per connection rather than one run covering all of them, because
    each has its own credential, its own rate limit budget and its own way of
    failing.  A history that says which account was scanned and how it went is
    worth more than a single line that averages them.

    Falls back to a single scan on the settings credential when nobody has set
    a connection up.
    """
    from app.core import connections as connection_store

    # One gate for the whole sweep.  Taking it per connection would leave it
    # free in the gaps between them, and a scan started in one of those gaps
    # would make the next connection fail with "already running".
    mine = False
    if not _holds_lock:
        if not _gate.acquire(blocking=False):
            return {"ok": False, "reason": "A scan is already running."}
        _took_a_slot()
        mine = True

    try:
        return _every_connection(triggered_by, trigger, only, connection_id,
                                 orgs, repos)
    finally:
        if mine:
            _gate.release()
            _gave_it_back()


# Where the last sweep got to.  Not in settings_store.DEFAULTS on purpose:
# it is bookkeeping, not a preference, and the Settings page only renders keys
# it knows about.
SWEEP_CURSOR = "scan.sweep_cursor"


def _rotate(chosen: list, cursor: str) -> list:
    """Start the sweep after wherever the last one stopped.

    Connections come back in name order, so a sweep that runs out of time, or
    budget, or gets stopped, always gives up in the same place and the tail of
    the alphabet is never reached.  Not scanned reads exactly like nothing
    found, which is the failure this whole tool exists to avoid.  Rotating puts
    the ones that missed out at the front of the next run.

    Rotating beats shuffling here.  The order stays reproducible, and the
    accounts that actually went without are guaranteed to lead rather than
    being left to chance.
    """
    if not cursor or len(chosen) < 2:
        return chosen
    # Folded, because the database sorted these without regard to case and a
    # plain > would put "IAT" before "actions" and rotate to the wrong place.
    mark = cursor.lower()
    for i, row in enumerate(chosen):
        # Greater than, not equal to, so a connection renamed or deleted since
        # the last run still lands us on whoever follows it.
        if row.name.lower() > mark:
            return chosen[i:] + chosen[:i]
    # The cursor sits at or past the last name, so the next one round is the
    # list as it stands.
    return chosen


def _every_connection(triggered_by, trigger, only, connection_id,
                      orgs=None, repos=None) -> dict:
    """The sweep itself, with the gate already held."""
    from app.core import connections as connection_store

    with session_scope() as db:
        cursor = ""
        if connection_id is not None:
            wanted = connection_store.by_id(db, connection_id)
            chosen = [wanted] if wanted is not None else []
        else:
            chosen = connection_store.usable(db)
            cursor = store.get(db, SWEEP_CURSOR, "") or ""
        # Detach: each scan opens its own session, and a row from a closed one
        # is no use to it.
        chosen = [_Detached(row) for row in chosen]

    # One connection by name is somebody asking for that one, so leave the
    # sweep's place alone.
    if connection_id is None and len(chosen) > 1:
        chosen = _rotate(chosen, cursor)
        log.info("sweep order: %s", ", ".join(row.name for row in chosen))

    if not chosen:
        return run_scan(triggered_by=triggered_by, trigger=trigger, only=only,
                        orgs=orgs, repos=repos, _holds_lock=True)

    total = {"ok": True, "connections": 0, "new": 0, "updated": 0,
             "resolved": 0, "repositories": 0, "failed": [], "empty_connections": []}
    tally = threading.Lock()
    # Set once any connection reports that somebody pressed stop.
    #
    # The event itself cannot be used for this: run_scan clears it as it
    # handles the stop, so by the time the next connection looked it would be
    # false again and the sweep would carry on.  This is the sweep's own record
    # that a stop happened, and it only ever goes one way.
    halt = threading.Event()

    def _one(row):
        """Scan one connection and fold its answer into the total."""
        # Checked here rather than only at submission: with a pool every
        # connection is queued before the first one finishes, so a stop has to
        # be able to turn the ones still waiting into nothing.
        if halt.is_set() or _stopped.is_set():
            return {"ok": False, "reason": "The scan was stopped.",
                    "stopped": True, "skipped": True}
        log.info("scanning connection %s", row.name)
        result = run_scan(triggered_by=triggered_by, trigger=trigger,
                          only=only, orgs=orgs, repos=repos, connection=row,
                          _holds_lock=True)
        # Move the mark as we go, not at the end.  A run that dies half way
        # through is exactly the run this is here for, and one that saved
        # nothing would start from the same place again.  A connection that
        # was stopped never had its turn, so it keeps its place in the queue.
        if connection_id is None and not result.get("stopped"):
            with session_scope() as db:
                store.set_value(db, SWEEP_CURSOR, row.name,
                                actor=triggered_by or trigger)
        if result.get("stopped"):
            halt.set()
        # A connection that never ran because the sweep was stopping is not a
        # connection that was scanned, and not a failure worth reporting.
        if result.get("skipped"):
            return result
        with tally:
            total["connections"] += 1
            if result.get("ok"):
                if result.get("empty"):
                    total["empty_connections"].append(row.name)
                for key in ("new", "updated", "resolved", "repositories"):
                    total[key] += int(result.get(key) or 0)
            else:
                total["failed"].append({"connection": row.name,
                                        "reason": result.get("reason", "")})
        return result

    # Connections at a time, rather than one after another.
    #
    # This was serial: twenty six accounts in a queue, on a machine with sixty
    # four cores where four were busy.  Nothing about one connection depends on
    # the one before it, and the limit that actually binds is GitHub's, which
    # is counted per credential: every connection carries its own token and its
    # own budget, so two at once is two separate limits rather than twice the
    # pressure on one.  That is what makes this safe here and would not make it
    # safe on a single credential.
    #
    # Bounded by the same setting that bounds scans, because that is what its
    # name says.  One keeps exactly the old behavior for anybody who wants it.
    width = max(1, min(concurrency(), len(chosen)))
    if width == 1:
        for row in chosen:
            if halt.is_set() or _stopped.is_set():
                log.info("stopped, so the remaining connections are skipped")
                break
            _one(row)
    else:
        log.info("scanning %d connection(s), %d at a time", len(chosen), width)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=width,
                                thread_name_prefix="gcr-conn") as pool:
            futures = []
            for row in chosen:
                # Checked as we submit rather than only up front: a stop
                # pressed part way through should not queue the rest.
                if halt.is_set() or _stopped.is_set():
                    log.info("stopped, so the remaining connections are skipped")
                    break
                futures.append(pool.submit(_one, row))
            for future in futures:
                try:
                    future.result()
                except Exception:            # noqa: BLE001
                    # One account falling over is not the sweep falling over.
                    # It is already counted as failed by run_scan itself.
                    log.warning("a connection scan raised", exc_info=True)

    total["ok"] = total["connections"] > len(total["failed"])
    # Empty only describes the sweep when the sweep found nothing anywhere.  One
    # account waiting on its first repository among twenty five working ones is
    # an ordinary night, and the row should say so.
    total["empty"] = bool(total["empty_connections"]) and not total["failed"] \
        and total["repositories"] == 0
    return total


class _Detached:
    """The few fields a scan needs from a connection, off the session."""

    def __init__(self, row):
        self.id = row.id
        self.name = row.name
        self.auth_method = row.auth_method
        self.provider = getattr(row, "provider", None) or "github"


def connection_is_scanning(connection_id) -> bool:
    """Whether a scan of this connection is in flight right now."""
    with _process_lock:
        return connection_id in _scanning_connections


def connections_scanning_now() -> set:
    """The names of every account with a scan in flight.

    Named rather than numbered because the pages that ask this hold a
    repository, and a repository records the account by name.  Read from the
    same set the claim uses, so what a button says and what the scanner would
    actually do cannot drift apart.
    """
    from app.core import connections as connection_store

    with _process_lock:
        ids = set(_scanning_connections)
    if not ids:
        return set()
    with session_scope() as db:
        return {row.name for row in connection_store.all_connections(db)
                if row.id in ids}


def connection_ids_scanning_now() -> set:
    """The same accounts, by id.

    The id is what the scanner actually holds, so asking this way asks the
    question the refusal will ask.  A name can go stale: a repository records
    the account name it was last read under, and renaming an account leaves
    every row written before that pointing at a name nothing answers to.  The
    name answer stays for rows that never recorded an id.
    """
    with _process_lock:
        return set(_scanning_connections)


def start_background(triggered_by: str = "", trigger: str = "manual",
                     orgs=None, repos=None, only=None,
                     connection_id=None, branch_names=None) -> bool:
    """Kick a scan off and come straight back.

    The web request should not sit there for an hour waiting.

    With no organizations or repositories named it works through every account
    on the Connections page, one at a time.  Naming either means somebody asked
    for something specific, so that runs on its own.
    """
    # Take the gate here, on the request thread, rather than letting the
    # worker take it once it gets scheduled.  Checking a flag and then starting
    # a thread that acquires the lock later leaves a window: two clicks landing
    # together both saw nothing running, both were told "scanning", and only
    # one of them actually scanned.  Acquiring first means the answer we give
    # somebody is the answer that came true.
    # Asked here, on the request thread, so the page can say which connection
    # is busy rather than starting a scan that stops on its own two layers
    # down.  Not the guarantee: two clicks landing together can both pass this,
    # and the claim inside run_scan is what actually stops the second one.
    # This is about telling somebody the truth, not about the promise.
    if connection_id is not None and connection_is_scanning(connection_id):
        return False

    if not _gate.acquire(blocking=False):
        return False
    # Counted here, before the thread exists.  This is the whole point: the
    # answer to "is a scan running" has to be yes from this moment, not from
    # whenever the thread gets around to starting a process.
    _took_a_slot()

    if orgs or repos:
        # The account, when one was named.  Without this a scan of a single
        # repository ran on whatever credential the settings hold rather than
        # the one that owns the organization it is in, which on an estate with
        # an account per organization is a scan that can see nothing.  Resolved
        # here rather than passed as an id because run_scan wants the row.
        named = None
        if connection_id is not None:
            from app.core import connections as connection_store
            with session_scope() as db:
                named = connection_store.by_id(db, connection_id)
        if named is None:
            # A scope with no account named.  This is what EVERY developer
            # scan looks like: the scope comes from their assignments and they
            # cannot see the Connections page, so they have no id to send.
            # Falling through to run_scan with connection=None handed the scan
            # the settings credential, which on an install that keeps its
            # credentials on connections does not exist, so the run died with
            # "configuration is invalid: method=pat but neither $GITHUB_TOKEN
            # is set nor token_file is readable" and the learner was told the
            # scanner had refused its own configuration.  Sweeping instead
            # gives each account its own credential and applies the scope to
            # each, which is the same answer by a route that can authenticate.
            target, kwargs = run_every_connection, {
                "triggered_by": triggered_by, "trigger": trigger,
                "only": only, "connection_id": None,
                "orgs": orgs, "repos": repos}
        else:
            target, kwargs = run_scan, {
                "triggered_by": triggered_by, "trigger": trigger,
                "orgs": orgs, "repos": repos, "only": only,
                "connection": named, "branch_names": branch_names}
    else:
        target, kwargs = run_every_connection, {
            "triggered_by": triggered_by, "trigger": trigger, "only": only,
            "connection_id": connection_id}
    kwargs["_holds_lock"] = True

    def _job():
        # The gate is handed to this thread, so this thread gives it back.
        try:
            target(**kwargs)
        finally:
            _gate.release()
            _gave_it_back()

    thread = threading.Thread(target=_job, name="gcr-scan", daemon=True)
    try:
        thread.start()
    except BaseException:
        # Nothing is going to release it if the thread never ran.
        _gate.release()
        _gave_it_back()
        raise
    return True


def refresh_feeds() -> dict:
    """Pull the CISA and EPSS lists again.

    Cheap, and worth doing more often than a scan, since a finding you already
    have can become urgent overnight without the code changing at all.
    """
    import tempfile as _tempfile
    with _tempfile.TemporaryDirectory(prefix="gcr-feeds-") as tmp:
        with session_scope() as db:
            config_path = scanner_config.build(db, Path(tmp))
            env = scanner_config.scanner_env(db, _scanner_env())
        env["GHSCAN_REFRESH_INTEL"] = "1"
        command = [str(settings.scanner_bin), "check", "-c", str(config_path), "-q"]
        try:
            completed = subprocess.run(command, env=env, capture_output=True,
                                       text=True, timeout=600)
            ok = completed.returncode == 0
        except subprocess.SubprocessError as exc:
            return {"ok": False, "reason": str(exc)[:200]}

    with session_scope() as db:
        record(db, "feeds.refreshed", actor="schedule",
               detail="CISA known exploited and EPSS",
               outcome="ok" if ok else "error")
    return {"ok": ok}
