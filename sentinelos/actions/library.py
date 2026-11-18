"""The actual action implementations. Fixed command lists, never a shell string."""
from __future__ import annotations

import os
import resource
import signal
import subprocess
import time
from typing import Callable, NamedTuple, Optional

from ..monitor.proc_reader import read_process
from .guard import safe_cgroup, safe_file

TERM_WAIT_S = 5.0
DEFAULT_PERIOD_US = 100_000
DEFAULT_MAX_DELETE_MB = 100.0


class Impl(NamedTuple):
    describe: Callable[[dict], str]
    run: Callable[[dict], tuple]            # -> (detail, rollback_or_None)
    precheck: Optional[Callable[[dict], Optional[str]]] = None


def _cmd(cmd: list, timeout: int = 20) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    if r.returncode != 0:
        raise OSError(f"{cmd[0]} exit {r.returncode}: {r.stderr.strip()[:200]}")
    return (r.stdout.strip() or "ok")[:300]


def _gone(pid: int) -> bool:
    p = read_process(pid)
    return p is None or p.state in ("Z", "X")


# ── renice ────────────────────────────────────────────────────────────────────
def _renice(p):
    old = os.getpriority(os.PRIO_PROCESS, p["pid"])
    os.setpriority(os.PRIO_PROCESS, p["pid"], p["nice_value"])
    return (f"nice {old} -> {p['nice_value']}",
            {"action_id": "renice_process", "params": {"pid": p["pid"], "nice_value": old}})


# ── signals ───────────────────────────────────────────────────────────────────
def _sigterm(p):
    os.kill(p["pid"], signal.SIGTERM)
    end = time.time() + TERM_WAIT_S
    while time.time() < end:
        if _gone(p["pid"]):
            return "SIGTERM sent, process exited", None
        time.sleep(0.2)
    return f"SIGTERM sent, still running after {TERM_WAIT_S:.0f}s (SIGKILL is a separate High-risk action)", None


def _sigkill(p):
    os.kill(p["pid"], signal.SIGKILL)
    return "SIGKILL sent", None


# ── memory ────────────────────────────────────────────────────────────────────
def _drop_caches(p):
    os.sync()
    with open("/proc/sys/vm/drop_caches", "w") as f:
        f.write(str(p["level"]))
    return f"drop_caches={p['level']}", None


# ── cgroup v2 CPU quota ───────────────────────────────────────────────────────
def _cg_set(p):
    f = os.path.join(os.path.realpath(p["cgroup_path"]), "cpu.max")
    old = open(f).read().strip()
    with open(f, "w") as fh:
        fh.write(f"{p['quota_us']} {p['period_us']}")
    return (f"cpu.max {old!r} -> '{p['quota_us']} {p['period_us']}'",
            {"action_id": "remove_cpu_cgroup_quota", "params": {"cgroup_path": p["cgroup_path"]}})


def _cg_remove(p):
    f = os.path.join(os.path.realpath(p["cgroup_path"]), "cpu.max")
    with open(f, "w") as fh:
        fh.write(f"max {DEFAULT_PERIOD_US}")
    return "cpu quota removed", None


# ── disk ──────────────────────────────────────────────────────────────────────
def _truncate(p):
    real = os.path.realpath(p["path"])
    size = os.path.getsize(real)
    os.truncate(real, 0)
    return f"truncated {real} ({size} bytes freed)", None


def _delete(p):
    real = os.path.realpath(p["path"])
    mb = os.path.getsize(real) / 1048576
    cap = p.get("max_size_mb", DEFAULT_MAX_DELETE_MB)
    if mb > cap:
        raise OSError(f"file is {mb:.1f} MB, above cap {cap} MB")
    os.remove(real)
    return f"deleted {real} ({mb:.1f} MB)", None


def _vacuum(p):
    return _cmd(["journalctl", f"--vacuum-size={p['max_size']}"]), None


# ── services ──────────────────────────────────────────────────────────────────
def _restart(p):
    return _cmd(["systemctl", "restart", p["unit"]], 60), None


def _stop(p):
    return _cmd(["systemctl", "stop", p["unit"]], 60), None


# ── file descriptors ──────────────────────────────────────────────────────────
def _ulimit(p):
    soft, hard = resource.prlimit(p["pid"], resource.RLIMIT_NOFILE)
    resource.prlimit(p["pid"], resource.RLIMIT_NOFILE, (p["new_limit"], max(hard, p["new_limit"])))
    rb = ({"action_id": "raise_ulimit_nofile", "params": {"pid": p["pid"], "new_limit": soft}}
          if soft >= 1024 else None)
    return f"RLIMIT_NOFILE soft {soft} -> {p['new_limit']}", rb


IMPLS: dict[str, Impl] = {
    "renice_process": Impl(lambda p: f"set nice of pid {p['pid']} to {p['nice_value']}", _renice),
    "kill_process_sigterm": Impl(lambda p: f"send SIGTERM to pid {p['pid']}", _sigterm),
    "kill_process_sigkill": Impl(lambda p: f"send SIGKILL to pid {p['pid']}", _sigkill),
    "drop_caches": Impl(lambda p: f"write {p['level']} to /proc/sys/vm/drop_caches", _drop_caches),
    "set_cpu_cgroup_quota": Impl(
        lambda p: f"set cpu.max of {p['cgroup_path']} to '{p['quota_us']} {p['period_us']}'",
        _cg_set, lambda p: safe_cgroup(p["cgroup_path"])),
    "remove_cpu_cgroup_quota": Impl(lambda p: f"remove cpu quota of {p['cgroup_path']}",
                                    _cg_remove, lambda p: safe_cgroup(p["cgroup_path"])),
    "truncate_log_file": Impl(lambda p: f"truncate {p['path']} to 0 bytes", _truncate,
                              lambda p: safe_file(p["path"])),
    "delete_file": Impl(lambda p: f"delete {p['path']}", _delete, lambda p: safe_file(p["path"])),
    "run_journalctl_vacuum": Impl(lambda p: f"journalctl --vacuum-size={p['max_size']}", _vacuum),
    "restart_systemd_unit": Impl(lambda p: f"systemctl restart {p['unit']}", _restart),
    "stop_systemd_unit": Impl(lambda p: f"systemctl stop {p['unit']}", _stop),
    "raise_ulimit_nofile": Impl(lambda p: f"raise open-file limit of pid {p['pid']} to {p['new_limit']}", _ulimit),
}