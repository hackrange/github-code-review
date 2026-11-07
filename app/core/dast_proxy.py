"""A per scan local proxy, so every engine signs in and stays in scope.

mitmproxy ships in the DAST virtual environment already (wapiti brings it).  For
a scan it is started on a local port with the addon in dast_checks/mitm_addon.py,
the stock engines are pointed at it, and it stamps the session on their requests
and refuses any host out of scope.  If mitmproxy is not there the scan runs
exactly as before: start() returns None and the engines go direct.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

log = logging.getLogger("gcr.dast_proxy")

_ADDON = Path(__file__).resolve().parent / "dast_checks" / "mitm_addon.py"


def mitmdump() -> str:
    """The mitmdump to run, or empty when it is not installed."""
    candidates = []
    dast_py = os.environ.get("GCR_DAST_PYTHON", "").strip()
    if dast_py:
        candidates.append(str(Path(dast_py).with_name("mitmdump")))
    candidates += ["/opt/gcr/dast-venv/bin/mitmdump", shutil.which("mitmdump") or ""]
    for cand in candidates:
        if cand and os.access(cand, os.X_OK):
            return cand
    return ""


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class Handle:
    """A running scan proxy.  url is what the engines are pointed at."""

    def __init__(self, url: str, proc: subprocess.Popen):
        self.url = url
        self._proc = proc

    def stop(self) -> None:
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - make sure it is gone
            try:
                self._proc.kill()
            except Exception:  # noqa: BLE001
                pass


def start(auth_headers: dict, hosts: list, upstream: str = "",
          workdir: Path = None) -> "Handle | None":
    """Start the scan proxy.  auth_headers is stamped on every request; hosts is
    the scope (company domains plus the target); upstream is a site proxy to
    chain through.  -> a Handle, or None when mitmproxy is not available or did
    not come up, so the caller just runs the engines direct."""
    exe = mitmdump()
    if not exe or not _ADDON.is_file():
        return None
    port = _free_port()
    confdir = Path(workdir or "/tmp") / "mitm"
    confdir.mkdir(parents=True, exist_ok=True)
    argv = [exe, "--listen-host", "127.0.0.1", "--listen-port", str(port),
            "-s", str(_ADDON), "--ssl-insecure", "-q",
            "--set", "flow_detail=0", "--set", f"confdir={confdir}"]
    if upstream:
        argv += ["--mode", f"upstream:{upstream}"]
    env = dict(os.environ,
               GCR_MITM_AUTH=json.dumps(auth_headers or {}),
               GCR_MITM_HOSTS=json.dumps([h for h in (hosts or []) if h]),
               GCR_MITM_SCOPE="1")
    try:
        proc = subprocess.Popen(argv, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:  # noqa: BLE001 - never let the proxy break a scan
        log.warning("scan proxy did not start: %s", exc)
        return None
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):   # up to ~10s for it to generate its CA and bind
        if proc.poll() is not None:
            log.warning("scan proxy exited before it was ready")
            return None
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return Handle(url, proc)
        except OSError:
            time.sleep(0.2)
    try:
        proc.terminate()
    except Exception:  # noqa: BLE001
        pass
    log.warning("scan proxy did not come up in time")
    return None
