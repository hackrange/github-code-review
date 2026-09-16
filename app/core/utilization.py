"""CPU, memory, disk and network, live and over time.

Sampled every five seconds.  The last hour stays in memory for the gauges, and
a row a minute goes to the database, kept two days.  Those are averaged into
two minute rows kept a month and ten minute rows kept a year.

Host numbers come from /proc, which inside a container still describes the
machine.  This application's own numbers come from its cgroup, which is the
whole container, scans included.  No Docker socket is ever needed, and handing
one to a tool that clones strangers' code would be a gaping hole.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import threading
import time
from collections import deque

from app.config import settings
from app.core.db import session_scope
from app.core.models import Utilization2Min, Utilization10Min, UtilizationMinute

log = logging.getLogger("gcr.utilization")

PERIOD_SEC = 5
LIVE_POINTS = 720                 # an hour at five seconds
DAY = 86400
# Where each resolution lives and for how long.  Anything past a year is gone.
TIERS = (
    {"model": UtilizationMinute, "name": "minute", "seconds": 60, "keep_days": 2},
    {"model": Utilization2Min, "name": "2min", "seconds": 120, "keep_days": 31},
    {"model": Utilization10Min, "name": "10min", "seconds": 600, "keep_days": 365},
)
# A day at one minute is 1440 points, so that is the most any chart asks for.
MAX_POINTS = 1440
MAX_SPAN_SEC = 366 * DAY

NODE = (re.sub(r"[^A-Za-z0-9._-]", "_",
               os.environ.get("GCR_NODE_NAME") or socket.gethostname())[:64]
        or "node")

AVERAGED = ("host_cpu", "app_cpu", "host_mem_used", "app_mem", "disk_used",
            "net_rx_bps", "net_tx_bps")
PEAKED = ("host_cpu_max", "host_mem_total", "disk_total", "net_rx_max",
          "net_tx_max")
COLUMNS = AVERAGED + PEAKED


# ---- readers, each one small and testable -----------------------------------

def parse_proc_stat(text):
    """The cpu line of /proc/stat, as {total, idle}, or None."""
    for line in str(text or "").splitlines():
        if line.startswith("cpu "):
            try:
                n = [int(v) for v in line.split()[1:9]]
            except ValueError:
                return None
            if len(n) < 4:
                return None
            return {"total": sum(n), "idle": n[3] + (n[4] if len(n) > 4 else 0)}
    return None


def cpu_percent(prev, cur):
    if not prev or not cur:
        return None
    total = cur["total"] - prev["total"]
    if total <= 0:
        return None
    busy = total - (cur["idle"] - prev["idle"])
    return max(0.0, min(100.0, 100.0 * busy / total))


def parse_meminfo(text):
    """Used is total less available, the figure free and top agree on."""
    def get(key):
        m = re.search(r"^%s:\s+(\d+)\s*kB" % key, str(text or ""), re.M)
        return int(m.group(1)) * 1024 if m else None

    total, available = get("MemTotal"), get("MemAvailable")
    if total is None or available is None:
        return None
    return {"total": total, "used": max(0, total - available)}


def parse_net_dev(text):
    """Every interface but loopback, summed.  Inside a container that is the
    container's own traffic."""
    rx = tx = 0
    for line in str(text or "").splitlines()[2:]:
        name, _, rest = line.partition(":")
        if not rest or name.strip() == "lo":
            continue
        try:
            fields = [int(v) for v in rest.split()]
        except ValueError:
            continue
        if len(fields) < 9:
            continue
        rx += fields[0]
        tx += fields[8]
    return {"rx": rx, "tx": tx}


def container_memory(current, stat):
    """Like docker stats: in use less inactive file cache, which the kernel
    would hand back anyway.  A missing file is "don't know", not zero."""
    raw = str(current if current is not None else "").strip()
    if not raw.isdigit():
        return None
    m = re.search(r"^inactive_file\s+(\d+)", str(stat or ""), re.M)
    return max(0, int(raw) - (int(m.group(1)) if m else 0))


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def _app_cpu_micros():
    v2 = _read("/sys/fs/cgroup/cpu.stat")
    m = v2 and re.search(r"^usage_usec\s+(\d+)", v2, re.M)
    if m:
        return int(m.group(1))
    v1 = (_read("/sys/fs/cgroup/cpuacct/cpuacct.usage") or "").strip()
    if v1.isdigit():
        return int(v1) / 1000
    t = os.times()
    return (t.user + t.system) * 1e6


def _app_memory():
    v2 = container_memory(_read("/sys/fs/cgroup/memory.current"),
                          _read("/sys/fs/cgroup/memory.stat"))
    if v2 is not None:
        return v2
    v1 = container_memory(_read("/sys/fs/cgroup/memory/memory.usage_in_bytes"),
                          _read("/sys/fs/cgroup/memory/memory.stat"))
    if v1 is not None:
        return v1
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024


def disk_path():
    """The disk scans clone onto, which is the one that fills."""
    for path in (settings.work_dir, settings.data_dir):
        if path and os.path.isdir(path):
            return str(path)
    return "/"


def _disk():
    try:
        s = os.statvfs(disk_path())
        return {"total": s.f_blocks * s.f_frsize,
                "used": (s.f_blocks - s.f_bfree) * s.f_frsize}
    except OSError:
        return {"total": 0, "used": 0}


def _cpus():
    return os.cpu_count() or 1


# ---- the sampler -------------------------------------------------------------

_lock = threading.Lock()
_live = deque(maxlen=LIVE_POINTS)
_minute = []
_prev = None
_breakdown = {"database": None, "reports": None, "at": 0}


def refresh_breakdown():
    """What is taking the space.  Every few minutes, not every sample."""
    global _breakdown
    try:
        with session_scope() as db:
            if db.get_bind().dialect.name == "sqlite":
                path = settings.db_path
                database = os.path.getsize(path) if os.path.exists(path) else 0
            else:
                from sqlalchemy import text
                database = db.execute(text(
                    "SELECT COALESCE(SUM(data_length + index_length), 0) "
                    "FROM information_schema.tables "
                    "WHERE table_schema = DATABASE()")).scalar() or 0
        reports = 0
        for root, _dirs, files in os.walk(str(settings.reports_dir)):
            for name in files:
                try:
                    reports += os.path.getsize(os.path.join(root, name))
                except OSError:
                    pass
        _breakdown = {"database": int(database), "reports": reports,
                      "at": int(time.time() * 1000)}
    except Exception:
        # Not worth shouting about, the gauge still works.
        pass


def sample(now=None):
    """Take one reading.  The first one only sets the baseline."""
    global _prev, _minute
    t = time.time() if now is None else now
    cpu = parse_proc_stat(_read("/proc/stat"))
    app_micros = _app_cpu_micros()
    net = parse_net_dev(_read("/proc/net/dev"))
    mem = parse_meminfo(_read("/proc/meminfo")) or {"total": 0, "used": 0}
    disk = _disk()

    done = None
    with _lock:
        if _prev is not None:
            secs = t - _prev["t"]
            if secs > 0:
                cores = max(0.0, (app_micros - _prev["app"]) / 1e6 / secs)
                point = {
                    "t": int(t * 1000),
                    "hostCpu": _round(cpu_percent(_prev["cpu"], cpu)),
                    "appCpu": _round(min(100.0, 100.0 * cores / _cpus())),
                    "appCores": _round(cores),
                    "hostMemUsed": mem["used"],
                    "hostMemTotal": mem["total"],
                    "appMem": _app_memory(),
                    "diskUsed": disk["used"],
                    "diskTotal": disk["total"],
                    "rxBps": max(0, round((net["rx"] - _prev["net"]["rx"]) / secs)),
                    "txBps": max(0, round((net["tx"] - _prev["net"]["tx"]) / secs)),
                }
                _live.append(point)
                minute = point["t"] // 60000
                if _minute and _minute[0]["t"] // 60000 != minute:
                    done, _minute = _minute, []
                _minute.append(point)
        _prev = {"t": t, "cpu": cpu, "app": app_micros, "net": net}
    if done:
        flush_minute(done)


def _round(value):
    return None if value is None else round(value, 2)


def _avg(points, key):
    values = [p[key] for p in points if p.get(key) is not None]
    return sum(values) / len(values) if values else 0


def _peak(points, key):
    values = [p[key] for p in points if p.get(key) is not None]
    return max(values) if values else 0


def flush_minute(points):
    """One minute of samples, as a row."""
    if not points:
        return
    row = {
        "host_cpu": _round(_avg(points, "hostCpu")),
        "host_cpu_max": _round(_peak(points, "hostCpu")),
        "app_cpu": _round(_avg(points, "appCpu")),
        "host_mem_used": round(_avg(points, "hostMemUsed")),
        "host_mem_total": round(_peak(points, "hostMemTotal")),
        "app_mem": round(_avg(points, "appMem")),
        "disk_used": round(_avg(points, "diskUsed")),
        "disk_total": round(_peak(points, "diskTotal")),
        "net_rx_bps": round(_avg(points, "rxBps")),
        "net_tx_bps": round(_avg(points, "txBps")),
        "net_rx_max": round(_peak(points, "rxBps")),
        "net_tx_max": round(_peak(points, "txBps")),
    }
    try:
        with session_scope() as db:
            _upsert(db, UtilizationMinute, points[0]["t"] // 60000 * 60, row)
    except Exception as exc:
        log.warning("could not save a utilization sample: %s", exc)


def _upsert(db, model, ts, values):
    existing = db.get(model, (NODE, ts))
    if existing is None:
        db.add(model(node=NODE, ts=ts, **values))
    else:
        for key, value in values.items():
            setattr(existing, key, value)


def rollup(now=None):
    """The last few hours of minutes, averaged into the wider tables, then
    everything past keeping goes.  Running it twice over the same window only
    rewrites the same rows, so a missed run catches up."""
    now = int(time.time() if now is None else now)
    try:
        with session_scope() as db:
            rows = (db.query(UtilizationMinute)
                    .filter(UtilizationMinute.ts >= now - 3 * 3600).all())
            for tier in TIERS[1:]:
                slots = {}
                for row in rows:
                    slot = (row.node, row.ts // tier["seconds"] * tier["seconds"])
                    slots.setdefault(slot, []).append(row)
                for (node, ts), members in slots.items():
                    values = _combine(members)
                    existing = db.get(tier["model"], (node, ts))
                    if existing is None:
                        db.add(tier["model"](node=node, ts=ts, **values))
                    else:
                        for key, value in values.items():
                            setattr(existing, key, value)
            for tier in TIERS:
                model = tier["model"]
                (db.query(model)
                 .filter(model.ts < now - tier["keep_days"] * DAY)
                 .delete(synchronize_session=False))
    except Exception as exc:
        log.warning("utilization rollup failed: %s", exc)


def _combine(rows):
    out = {}
    for key in AVERAGED:
        values = [getattr(r, key) for r in rows if getattr(r, key) is not None]
        out[key] = sum(values) / len(values) if values else 0
    for key in PEAKED:
        values = [getattr(r, key) for r in rows if getattr(r, key) is not None]
        out[key] = max(values) if values else 0
    for key in COLUMNS:
        if key not in ("host_cpu", "host_cpu_max", "app_cpu"):
            out[key] = int(round(out[key]))
        else:
            out[key] = round(out[key], 2)
    return out


# ---- what the api hands out --------------------------------------------------

def limits():
    quota = None
    parts = (_read("/sys/fs/cgroup/cpu.max") or "").split()
    if parts and parts[0] != "max":
        try:
            quota = int(parts[0]) / int(parts[1] if len(parts) > 1 else 100000)
        except ValueError:
            quota = None
    mem_max = (_read("/sys/fs/cgroup/memory.max") or "").strip()
    return {"hostCpus": _cpus(), "cpuLimitCores": quota,
            "memLimit": int(mem_max) if mem_max.isdigit() else None}


def current(since=0):
    with _lock:
        points = [p for p in _live if p["t"] > (since or 0)]
        now = _live[-1] if _live else None
    return {"node": NODE, "periodMs": PERIOD_SEC * 1000, "now": now,
            "points": points, "breakdown": dict(_breakdown),
            "limits": limits()}


def plan(from_sec, to_sec, now=None):
    """The finest table that still covers the start of the range: today at a
    minute, up to a month at two, past that at ten.  Only widened further when
    a range would draw more than MAX_POINTS."""
    now = time.time() if now is None else now
    span, age = to_sec - from_sec, now - from_sec
    tier = next((t for t in TIERS
                 if span <= t["keep_days"] * DAY
                 and age <= t["keep_days"] * DAY + DAY), TIERS[-1])
    base = tier["seconds"]
    per = -(-span // MAX_POINTS)                  # ceiling division
    bucket = max(base, -(-per // base) * base)
    return {"tier": tier, "source": tier["name"], "bucket": int(bucket)}


def history(from_ms, to_ms):
    from_sec, to_sec = int(from_ms // 1000), int(-(-to_ms // 1000))
    chosen = plan(from_sec, to_sec)
    model, bucket = chosen["tier"]["model"], chosen["bucket"]
    with session_scope() as db:
        rows = (db.query(model)
                .filter(model.node == NODE, model.ts >= from_sec,
                        model.ts < to_sec)
                .order_by(model.ts).all())
        slots = {}
        for row in rows:
            slots.setdefault(row.ts // bucket * bucket, []).append(row)
        points = []
        for ts in sorted(slots):
            c = _combine(slots[ts])
            points.append({
                "t": ts * 1000,
                "hostCpu": c["host_cpu"], "hostCpuMax": c["host_cpu_max"],
                "appCpu": c["app_cpu"],
                "hostMemUsed": c["host_mem_used"],
                "hostMemTotal": c["host_mem_total"], "appMem": c["app_mem"],
                "diskUsed": c["disk_used"], "diskTotal": c["disk_total"],
                "rxBps": c["net_rx_bps"], "txBps": c["net_tx_bps"],
                "rxMax": c["net_rx_max"], "txMax": c["net_tx_max"],
            })
    return {"node": NODE, "source": chosen["source"], "bucketSeconds": bucket,
            "from": int(from_ms), "to": int(to_ms), "points": points}
