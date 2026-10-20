"""Pull request gate runs.

A CI job asks whether a change may merge.  The answer is worked out here by
running `ghscan review --fetch --base --head`, which reviews only what the
change added, and then putting what this installation already knows on top
of it: learned rules lower a grade the same way they do for the nightly scan,
and an approved exception on the same finding lets it through.  The policy in
config/gate-policy.yaml turns that into pass, warn or fail.

A run is a background job.  A gate can take minutes, and a request held open
that long behind the load balancer is a request that gets cut off, so the
caller gets a run id at once and asks again until it is done.

Nothing a gate finds is written as a Finding.  The run itself is kept, with
who asked, what it said and why.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

from app.config import settings
from app.core.audit import record
from app.core.db import session_scope
from app.core.models import GateRun, utcnow

log = logging.getLogger("gcr.gate")

ROOT = Path(__file__).resolve().parents[2]
GHSCAN = ROOT / "bin" / "ghscan"
POLICY = Path(os.environ.get("GCR_GATE_POLICY", str(ROOT / "config" / "gate-policy.yaml")))

# The hard limit from the design.  Past this the run is an error and the
# failure policy decides, rather than a CI job waiting on it for ever.
TIMEOUT = int(os.environ.get("GCR_GATE_TIMEOUT", "300"))

# Two at a time by default.  A gate run is a small scan, and the nightly scan
# shares this machine; a burst of pushes should queue rather than starve it.
WORKERS = max(1, int(os.environ.get("GCR_GATE_WORKERS", "2")))

# The biggest SARIF a run keeps.  MariaDB takes at most 16 MiB in one write,
# and the rest of the row goes in the same one.  A PR that adds this much
# still gets its verdict, just not the inline notes.
SARIF_LIMIT = 8 * 1024 * 1024

_pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="gate")
_policy_lock = threading.Lock()
_policy_module = None


def policy_module():
    """lib/gate_policy.py, loaded by path.

    It lives with the scanner so the command line can apply the same policy
    without the web app, and it has no imports the web app lacks.
    """
    global _policy_module
    with _policy_lock:
        if _policy_module is None:
            spec = importlib.util.spec_from_file_location(
                "gcr_gate_policy", ROOT / "lib" / "gate_policy.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _policy_module = module
    return _policy_module


def load_policy() -> dict:
    return policy_module().load(str(POLICY))


def start(session, user, token, repository, base_sha: str, head_sha: str,
          pull_request=None, mode: str = "") -> GateRun:
    """Queue a run and hand it back.  The work happens on the pool."""
    run = GateRun(repo_id=repository.id, repository=repository.full_name,
                  pull_request=pull_request, base_sha=base_sha[:64],
                  head_sha=head_sha[:64], caller=user.username,
                  token_id=getattr(token, "id", None),
                  requested_mode=(mode or "")[:16], status="queued")
    session.add(run)
    session.flush()
    return run


def submit(run_id: int) -> None:
    """Hand a queued run to the pool.  Call it once the row is committed, or
    the worker can go looking for a run that does not exist yet."""
    _pool.submit(_run_safely, run_id)


def _run_safely(run_id: int) -> None:
    try:
        _run(run_id)
    except Exception as exc:  # the worker must never die with the run open
        log.exception("gate run %s failed", run_id)
        _finish(run_id, status="error", error=f"The gate run failed: {exc}"[:400])


def _finish(run_id: int, **fields) -> None:
    with session_scope() as db:
        run = db.get(GateRun, run_id)
        if run is None:
            return
        for key, value in fields.items():
            setattr(run, key, value)
        run.finished_at = utcnow()
        if run.started_at is not None:
            started = run.started_at
            if started.tzinfo is None:
                from datetime import timezone
                started = started.replace(tzinfo=timezone.utc)
            run.duration_ms = int((run.finished_at - started).total_seconds() * 1000)
        if fields.get("status") == "error":
            # An error is still a verdict for whoever is waiting on it.  A
            # fail-closed repository fails; everything else is the caller's
            # failure policy to apply.
            run.verdict = "fail" if run.fail_closed else "error"


def _run(run_id: int) -> None:
    from app.core import connections as connection_store
    from app.core import scanner_config
    from app.core import settings_store as store
    from app.core.models import Repository
    from app.core.scanner import _scanner_env

    policy = load_policy()
    with session_scope() as db:
        run = db.get(GateRun, run_id)
        if run is None:
            return
        run.status = "running"
        run.started_at = utcnow()
        repo = db.get(Repository, run.repo_id) if run.repo_id else None
        effective = policy_module().for_repo(policy, run.repository)
        run.fail_closed = bool(effective.get("fail_closed"))
        run.policy_version = (policy.get("_version") or "")[:64]
        full_name = run.repository
        base_sha, head_sha = run.base_sha, run.head_sha
        requested = (run.requested_mode or "").lower()
        if repo is None:
            raise RuntimeError("the repository is no longer monitored")
        repo_id = repo.id
        connection_id = repo.connection_id

    mirrors = Path(settings.work_dir) / "gate-mirrors"
    mirror = mirrors / f"{repo_id}.git"
    with tempfile.TemporaryDirectory(prefix=f"gcr-gate-{run_id}-",
                                     dir=str(settings.work_dir)
                                     if Path(settings.work_dir).exists() else None) as tmp:
        with session_scope() as db:
            connection = (connection_store.by_id(db, connection_id)
                          if connection_id else None)
            config_path = scanner_config.build(db, Path(tmp), repos=[full_name],
                                               connection=connection)
            env = scanner_config.scanner_env(db, _scanner_env(),
                                             connection=connection)
            method = (connection.auth_method if connection is not None
                      else store.get(db, "github.auth_method"))
            if method == "app":
                scanner_config.write_app_key(db, Path(tmp) / "github-app.pem",
                                             connection=connection)
        env["GHSCAN_LOG_LEVEL"] = "warn"
        command = [str(GHSCAN), "review", "--fetch", full_name,
                   "--mirror", str(mirror), "-c", str(config_path),
                   "--base", base_sha, "--head", head_sha,
                   "--policy", str(POLICY)]
        started = time.monotonic()
        try:
            done = subprocess.run(command, env=env, capture_output=True,
                                  text=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            _finish(run_id, status="error",
                    error=f"The gate took longer than {TIMEOUT} seconds and was stopped.")
            return
        log.info("gate run %s for %s took %.1fs", run_id, full_name,
                 time.monotonic() - started)
        if done.returncode not in (0, 3) or not done.stdout.strip():
            # The error lines, and what follows them, rather than whatever
            # warning happened to come last before the scanner gave up.
            lines = (done.stderr or "").strip().splitlines()
            first = next((i for i, line in enumerate(lines) if "[error]" in line), None)
            tail = " ".join(line.strip() for line in
                            (lines[first:first + 4] if first is not None else lines[-3:]))
            _finish(run_id, status="error",
                    error=(_explain(done.returncode, tail))[:400])
            return
        try:
            doc = json.loads(done.stdout)
        except ValueError:
            _finish(run_id, status="error", error="The gate produced nothing readable.")
            return

    with session_scope() as db:
        regrade(db, doc, full_name)
        result = policy_module().evaluate(
            doc, policy, full_name, excepted=exception_lookup(db, repo_id, full_name, doc))
        # The request can make a run stricter than the policy, never laxer.
        # A workflow file is in the repository and anybody with push can edit
        # it, so a mode it asks for is not allowed to switch enforcement off.
        if requested == "enforce" and result["mode"] != "enforce":
            result["mode"] = "enforce"
            if result["blocking"]:
                result["verdict"] = "fail"
        sarif = sarif_for(doc, full_name)
        run = db.get(GateRun, run_id)
        run.merge_base = (doc.get("merge_base") or "")[:64]
        run.mode = result["mode"]
        run.verdict = result["verdict"]
        run.would_block = bool(result["would_block"])
        run.counts = json.dumps(doc.get("counts") or {})
        run.blocking = json.dumps(result["blocking"])
        run.warnings = json.dumps(result["warnings"])
        run.exceptions_applied = json.dumps(result["exceptions_applied"])
        text = json.dumps(sarif)
        if len(text) > SARIF_LIMIT:
            run.sarif = None
            run.error = (f"The SARIF was {len(text) / 1048576:.0f} MiB, too big to keep, "
                         "so nothing will show inline.  The verdict stands.")
        else:
            run.sarif = text
        record(db, "gate.run", actor=run.caller, target=full_name,
               detail=json.dumps({"run": run_id, "pr": run.pull_request,
                                  "head": head_sha, "verdict": result["verdict"],
                                  "mode": result["mode"],
                                  "blocking": len(result["blocking"]),
                                  "exceptions": len(result["exceptions_applied"]),
                                  "policy": run.policy_version}))
    _finish(run_id, status="done")


def _explain(code: int, tail: str) -> str:
    if code == 2:
        return f"The gate was asked something it could not answer: {tail}"
    return f"The gate did not finish (exit {code}): {tail}"


# --- what this installation already knows -----------------------------------

_KIND = {"credential": "credential", "code": "code", "misconfiguration":
         "misconfiguration", "dependency": "dependency"}


def _facts_of(finding: dict, repository: str):
    """A gate finding in the shape learned.facts reads off a Finding row."""
    from app.core.models import FindingKind, Severity
    package = finding.get("package") or {}
    try:
        kind = FindingKind(finding.get("kind"))
    except ValueError:
        kind = finding.get("kind")
    try:
        severity = Severity(str(finding.get("severity") or "unknown").lower())
    except ValueError:
        severity = Severity.UNKNOWN
    return SimpleNamespace(
        repository=repository, kind=kind, rule=finding.get("rule") or "",
        file_path=finding.get("file") or "",
        snippet=finding.get("matched") or "",
        package_name=package.get("name") or "",
        package_version=package.get("version") or "",
        vulnerability_id=finding.get("rule") if finding.get("kind") == "dependency" else "",
        severity=severity,
        reachability=(finding.get("reachability") or {}).get("verdict", "")
        if isinstance(finding.get("reachability"), dict) else "",
        image_ref="",
        known_exploited=bool(finding.get("known_exploited")),
        malicious=finding.get("malicious"))


def regrade(session, doc: dict, repository: str) -> None:
    """Apply learned rules to the new findings, in place.

    A rule learned from the nightly scan lowers the same pattern here, or a
    developer is blocked on something the scan already knows to be noise.
    learned.protected is respected, so no rule ever touches a credential, a
    KEV listing or a malicious package.
    """
    from app.core import learned
    index = None
    for finding in doc.get("findings") or []:
        if not finding.get("new") or finding.get("kind") == "credential":
            continue
        facts = _facts_of(finding, repository)
        if learned.protected(facts):
            continue
        if index is None:
            index = learned.load_rules(session)
            if not index:
                return
        rule = learned.match(index, facts)
        if rule is None:
            continue
        finding["severity_before_rule"] = finding.get("severity")
        finding["severity"] = getattr(rule.severity, "value", rule.severity)
        finding["learned_rule"] = rule.id


def _ingest_row(finding: dict, repository: str) -> dict:
    """The fields app.core.ingest.fingerprint_for reads, named its way."""
    return {
        "repository": repository,
        "file": finding.get("file"),
        "rule": finding.get("rule"),
        "rule_name": finding.get("rule"),
        "rule_id": finding.get("rule"),
        "detector": finding.get("rule"),
        "start_line": finding.get("line"),
        "matched": finding.get("matched"),
        "resource": finding.get("resource"),
        "secret_fingerprint": finding.get("fingerprint")
        if finding.get("kind") == "credential" else None,
        "package": finding.get("package") or {},
        "id": finding.get("rule") if finding.get("kind") == "dependency" else None,
    }


def exception_lookup(session, repo_id: int, repository: str, doc: dict):
    """A function from a gate finding to the exception covering it, or None.

    The finding is looked up by the fingerprint the web app itself would give
    it, worked out by the web app's own function, so the two cannot disagree.
    Covered means excepted and not expired, which is what an approved waiver
    and a matching exclusion rule both set.  The id handed back is the
    finding's GCR- id, which is what a reviewer approved.
    """
    from app.core.ingest import fingerprint_for, number_occurrences
    from app.core.models import Finding

    rows = {}
    code_rows = []
    for finding in doc.get("findings") or []:
        row = _ingest_row(finding, repository)
        rows[id(finding)] = row
        if finding.get("kind") == "code":
            code_rows.append(row)
    # Occurrence numbers come from every code finding in the head, old and
    # new, in the same order ingest numbers them.
    number_occurrences(code_rows)
    now = utcnow()

    def lookup(finding: dict):
        row = rows.get(id(finding))
        kind = _KIND.get(finding.get("kind"))
        if row is None or kind is None:
            return None
        fingerprint = fingerprint_for(kind, row)
        hit = (session.query(Finding)
               .filter(Finding.fingerprint == fingerprint,
                       Finding.repo_id == repo_id).one_or_none())
        if hit is None or not hit.excepted:
            return None
        expires = hit.exception_expires_at
        if expires is not None:
            if expires.tzinfo is None:
                from datetime import timezone
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= now:
                return None
        return hit.vuln_id
    return lookup


def sarif_for(doc: dict, repository: str) -> dict:
    """The new findings as SARIF, written by the same lib/sarif.py a scan uses."""
    spec = importlib.util.spec_from_file_location("gcr_sarif", ROOT / "lib" / "sarif.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fresh = dict(doc, findings=[f for f in doc.get("findings") or [] if f.get("new")])
    return module.build_review(fresh, repository, doc.get("reviewed") or "")


# --- what the API hands back -------------------------------------------------

def _loads(text, default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def as_dict(run: GateRun, base_url: str = "") -> dict:
    out = {
        "id": run.id,
        "status": run.status,
        "repo": run.repository,
        "pr": run.pull_request,
        "base_sha": run.base_sha,
        "head_sha": run.head_sha,
        "merge_base": run.merge_base or None,
        "verdict": run.verdict or None,
        "mode": run.mode or None,
        "would_block": bool(run.would_block),
        "fail_closed": bool(run.fail_closed),
        "policy_version": run.policy_version or None,
        "blocking": _loads(run.blocking, []),
        "warnings": _loads(run.warnings, []),
        "exceptions_applied": _loads(run.exceptions_applied, []),
        "counts": _loads(run.counts, {}),
        "duration_ms": run.duration_ms,
        "error": run.error or None,
        "status_url": f"{base_url}/api/v1/gate/runs/{run.id}",
    }
    if run.status == "done":
        out["sarif_url"] = f"{base_url}/api/v1/gate/runs/{run.id}/sarif"
    return out
