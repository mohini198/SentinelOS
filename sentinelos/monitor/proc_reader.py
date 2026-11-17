"""Raw /proc readers. All functions accept a `proc` root so tests can use a fake tree."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PROC = Path("/proc")


def _read(path: Path) -> Optional[str]:
    try:
        return Path(path).read_text(errors="replace")
    except (OSError, PermissionError):
        return None


# ── Memory ────────────────────────────────────────────────────────────────────
@dataclass
class MemInfo:
    total_kb: int
    free_kb: int
    available_kb: int
    buffers_kb: int
    cached_kb: int
    swap_total_kb: int
    swap_free_kb: int

    @property
    def available_pct(self) -> float:
        return 100.0 * self.available_kb / self.total_kb if self.total_kb else 0.0

    @property
    def swap_used_pct(self) -> float:
        if not self.swap_total_kb:
            return 0.0
        return 100.0 * (self.swap_total_kb - self.swap_free_kb) / self.swap_total_kb


def read_meminfo(proc: Path = PROC) -> MemInfo:
    text = _read(proc / "meminfo")
    if text is None:
        raise FileNotFoundError("meminfo not readable")
    d: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.split()
        if parts and parts[0].isdigit():
            d[key.strip()] = int(parts[0])
    free = d.get("MemFree", 0)
    return MemInfo(
        total_kb=d.get("MemTotal", 0),
        free_kb=free,
        available_kb=d.get("MemAvailable", free),  # fallback for very old kernels
        buffers_kb=d.get("Buffers", 0),
        cached_kb=d.get("Cached", 0),
        swap_total_kb=d.get("SwapTotal", 0),
        swap_free_kb=d.get("SwapFree", 0),
    )


# ── CPU ───────────────────────────────────────────────────────────────────────
CPU_FIELDS = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"]


def read_cpu_times(proc: Path = PROC) -> dict[str, int]:
    text = _read(proc / "stat")
    if text is None:
        raise FileNotFoundError("stat not readable")
    for line in text.splitlines():
        if line.startswith("cpu "):
            vals = [int(x) for x in line.split()[1:]]
            vals += [0] * (len(CPU_FIELDS) - len(vals))
            return dict(zip(CPU_FIELDS, vals))
    raise ValueError("no aggregate cpu line in /proc/stat")


def cpu_usage_pct(prev: dict[str, int], cur: dict[str, int]) -> float:
    """Busy % between two samples of read_cpu_times()."""
    total = sum(cur.values()) - sum(prev.values())
    idle = (cur["idle"] + cur["iowait"]) - (prev["idle"] + prev["iowait"])
    if total <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (total - idle) / total))


@dataclass
class LoadAvg:
    load1: float
    load5: float
    load15: float
    running: int
    total_tasks: int


def read_loadavg(proc: Path = PROC) -> LoadAvg:
    text = _read(proc / "loadavg")
    if text is None:
        raise FileNotFoundError("loadavg not readable")
    p = text.split()
    running, total = p[3].split("/")
    return LoadAvg(float(p[0]), float(p[1]), float(p[2]), int(running), int(total))


# ── System-wide file descriptors ──────────────────────────────────────────────
@dataclass
class FileNr:
    allocated: int
    unused: int
    maximum: int

    @property
    def used_pct(self) -> float:
        return 100.0 * self.allocated / self.maximum if self.maximum else 0.0


def read_file_nr(proc: Path = PROC) -> FileNr:
    text = _read(proc / "sys" / "fs" / "file-nr")
    if text is None:
        raise FileNotFoundError("file-nr not readable")
    a, u, m = (int(x) for x in text.split()[:3])
    return FileNr(a, u, m)


# ── Per-process ───────────────────────────────────────────────────────────────
@dataclass
class ProcInfo:
    pid: int
    name: str
    state: str           # R S D Z T ...
    ppid: int
    cpu_ticks: int       # utime + stime
    rss_kb: int
    num_fds: Optional[int]   # None if permission denied
    oom_score: Optional[int]
    oom_score_adj: Optional[int]
    cmdline: str = ""


def _int_file(path: Path) -> Optional[int]:
    t = _read(path)
    try:
        return int(t.strip()) if t else None
    except ValueError:
        return None


def read_process(pid: int, proc: Path = PROC) -> Optional[ProcInfo]:
    base = proc / str(pid)
    stat = _read(base / "stat")
    if not stat:
        return None  # process vanished or unreadable
    # comm can contain spaces and ')' so split on the LAST ')'
    l, r = stat.find("("), stat.rfind(")")
    if l == -1 or r == -1:
        return None
    name = stat[l + 1:r]
    rest = stat[r + 2:].split()
    try:
        state, ppid = rest[0], int(rest[1])
        cpu_ticks = int(rest[11]) + int(rest[12])  # utime + stime
    except (IndexError, ValueError):
        return None

    rss_kb = 0
    status = _read(base / "status")
    if status:
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                rss_kb = int(line.split()[1])
                break

    try:
        num_fds: Optional[int] = len(os.listdir(base / "fd"))
    except (OSError, PermissionError):
        num_fds = None

    cmd = _read(base / "cmdline")
    cmdline = cmd.replace("\x00", " ").strip() if cmd else ""

    return ProcInfo(
        pid=pid, name=name, state=state, ppid=ppid, cpu_ticks=cpu_ticks,
        rss_kb=rss_kb, num_fds=num_fds,
        oom_score=_int_file(base / "oom_score"),
        oom_score_adj=_int_file(base / "oom_score_adj"),
        cmdline=cmdline,
    )


def list_processes(proc: Path = PROC) -> list[ProcInfo]:
    out: list[ProcInfo] = []
    try:
        entries = os.listdir(proc)
    except OSError:
        return out
    for e in entries:
        if e.isdigit():
            info = read_process(int(e), proc)
            if info:
                out.append(info)
    return out