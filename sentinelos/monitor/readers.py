"""
SentinelOS — Raw /proc and PSI filesystem readers.

Design rules
------------
* Every parser takes a *string* (file content) and returns a typed dataclass.
  This makes unit-tests trivial: pass a fake string, check the result.
* Every filesystem reader accepts a `proc_root` parameter (default /proc).
  Tests override this to a temp directory containing fake files.
* All reads are wrapped in try/except so a missing or unreadable file
  returns a zero-value dataclass rather than crashing the monitor loop.
* psutil is NOT used here; it is only imported as a fallback for disk reads
  on platforms that lack os.statvfs (i.e. Windows during development).
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

PROC_ROOT = Path("/proc")


# ═══════════════════════════════════════════════════════════════════════════════
# Dataclasses — one per metric domain
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PsiStats:
    """Pressure Stall Information (PSI) values from /proc/pressure/*."""
    some_avg10:  float = 0.0
    some_avg60:  float = 0.0
    some_avg300: float = 0.0
    full_avg10:  float = 0.0
    full_avg60:  float = 0.0
    full_avg300: float = 0.0


@dataclass
class MemSnapshot:
    """Memory metrics from /proc/meminfo + /proc/pressure/memory."""
    total_kb:     int   = 0
    free_kb:      int   = 0
    available_kb: int   = 0
    cached_kb:    int   = 0
    used_kb:      int   = 0
    used_pct:     float = 0.0
    psi: PsiStats = field(default_factory=PsiStats)


@dataclass
class CpuTimes:
    """Raw cumulative CPU times from /proc/stat (in jiffies)."""
    user:    int = 0
    nice:    int = 0
    system:  int = 0
    idle:    int = 0
    iowait:  int = 0
    irq:     int = 0
    softirq: int = 0
    steal:   int = 0

    @property
    def total(self) -> int:
        return (self.user + self.nice + self.system + self.idle
                + self.iowait + self.irq + self.softirq + self.steal)

    @property
    def busy(self) -> int:
        """Everything except idle and iowait."""
        return self.total - self.idle - self.iowait


@dataclass
class LoadAvg:
    """System load averages from /proc/loadavg."""
    avg1:  float = 0.0
    avg5:  float = 0.0
    avg15: float = 0.0


@dataclass
class CpuSnapshot:
    """CPU metrics: computed % + load averages + PSI."""
    used_pct: float = 0.0
    times: CpuTimes = field(default_factory=CpuTimes)
    load:  LoadAvg  = field(default_factory=LoadAvg)
    psi:   PsiStats = field(default_factory=PsiStats)


@dataclass
class DiskMount:
    """Disk space and inode usage for one mount point."""
    mount:       str   = ""
    total_bytes: int   = 0
    used_bytes:  int   = 0
    free_bytes:  int   = 0
    used_pct:    float = 0.0
    inode_total: int   = 0
    inode_used:  int   = 0
    inode_pct:   float = 0.0


@dataclass
class FdInfo:
    """System-wide file descriptor usage from /proc/sys/fs/file-nr."""
    allocated: int   = 0
    max_fds:   int   = 1
    used_pct:  float = 0.0


@dataclass
class ProcessInfo:
    """Per-process metrics from /proc/<pid>/."""
    pid:        int   = 0
    name:       str   = ""
    state:      str   = "?"   # single char: R S D Z T etc.
    mem_rss_kb: int   = 0
    cpu_time:   int   = 0     # utime + stime in jiffies (absolute, for ranking)
    fd_count:   int   = 0
    oom_score:  int   = 0


@dataclass
class SystemSnapshot:
    """Complete system-state snapshot collected at one point in time."""
    timestamp: float = field(default_factory=time.time)
    mem:       MemSnapshot   = field(default_factory=MemSnapshot)
    cpu:       CpuSnapshot   = field(default_factory=CpuSnapshot)
    disks:     list[DiskMount]   = field(default_factory=list)
    fds:       FdInfo        = field(default_factory=FdInfo)
    processes: list[ProcessInfo] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Pure parsers  (string → dataclass, no I/O)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_meminfo(text: str) -> MemSnapshot:
    """Parse /proc/meminfo content into a MemSnapshot."""
    kv: dict[str, int] = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            parts = val.split()
            if parts:
                try:
                    kv[key.strip()] = int(parts[0])
                except ValueError:
                    pass

    total     = kv.get("MemTotal", 0)
    free      = kv.get("MemFree", 0)
    available = kv.get("MemAvailable", 0)
    cached    = kv.get("Cached", 0)
    used      = max(0, total - available)
    used_pct  = (used / total * 100.0) if total > 0 else 0.0

    return MemSnapshot(
        total_kb=total, free_kb=free, available_kb=available,
        cached_kb=cached, used_kb=used, used_pct=used_pct,
    )


def parse_psi(text: str) -> PsiStats:
    """
    Parse /proc/pressure/{memory,cpu,io} content.

    Format per line:
      some avg10=X.XX avg60=X.XX avg300=X.XX total=N
      full avg10=X.XX avg60=X.XX avg300=X.XX total=N
    """
    stats = PsiStats()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        kind = parts[0]
        vals: dict[str, float] = {}
        for token in parts[1:]:
            if "=" in token:
                k, _, v = token.partition("=")
                try:
                    vals[k] = float(v)
                except ValueError:
                    pass
        if kind == "some":
            stats.some_avg10  = vals.get("avg10",  0.0)
            stats.some_avg60  = vals.get("avg60",  0.0)
            stats.some_avg300 = vals.get("avg300", 0.0)
        elif kind == "full":
            stats.full_avg10  = vals.get("avg10",  0.0)
            stats.full_avg60  = vals.get("avg60",  0.0)
            stats.full_avg300 = vals.get("avg300", 0.0)
    return stats


def parse_cpu_times(text: str) -> CpuTimes:
    """Parse the aggregate 'cpu' line from /proc/stat."""
    for line in text.splitlines():
        if line.startswith("cpu "):
            parts = line.split()
            # Fields: user nice system idle iowait irq softirq steal [guest guest_nice]
            vals = []
            for p in parts[1:9]:
                try:
                    vals.append(int(p))
                except ValueError:
                    vals.append(0)
            while len(vals) < 8:
                vals.append(0)
            return CpuTimes(*vals[:8])
    return CpuTimes()


def parse_loadavg(text: str) -> LoadAvg:
    """Parse /proc/loadavg — first three space-separated floats."""
    parts = text.strip().split()
    if len(parts) >= 3:
        try:
            return LoadAvg(float(parts[0]), float(parts[1]), float(parts[2]))
        except ValueError:
            pass
    return LoadAvg()


def parse_file_nr(text: str) -> FdInfo:
    """
    Parse /proc/sys/fs/file-nr.

    Format: allocated  unused  max
    On Linux 2.6+ 'unused' is always 0, so used = allocated.
    """
    parts = text.strip().split()
    if len(parts) >= 3:
        try:
            allocated = int(parts[0])
            max_fds   = int(parts[2])
            used_pct  = (allocated / max_fds * 100.0) if max_fds > 0 else 0.0
            return FdInfo(allocated=allocated, max_fds=max_fds, used_pct=used_pct)
        except ValueError:
            pass
    return FdInfo()


# ═══════════════════════════════════════════════════════════════════════════════
# CPU delta helper
# ═══════════════════════════════════════════════════════════════════════════════

def cpu_pct(prev: Optional[CpuTimes], curr: CpuTimes) -> float:
    """
    Compute CPU usage % between two CpuTimes samples.
    Returns 0.0 if prev is None (first sample) or if no time has elapsed.
    """
    if prev is None:
        return 0.0
    total_delta = curr.total - prev.total
    busy_delta  = curr.busy  - prev.busy
    if total_delta <= 0:
        return 0.0
    return min(100.0, max(0.0, busy_delta / total_delta * 100.0))


# ═══════════════════════════════════════════════════════════════════════════════
# Filesystem readers  (proc_root-parameterised for testability)
# ═══════════════════════════════════════════════════════════════════════════════

def _slurp(path: Path) -> Optional[str]:
    """Read a text file; return None on any error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return None


def read_meminfo(proc_root: Path = PROC_ROOT) -> MemSnapshot:
    text = _slurp(proc_root / "meminfo") or ""
    return parse_meminfo(text)


def read_psi(resource: str, proc_root: Path = PROC_ROOT) -> PsiStats:
    """resource: 'memory' | 'cpu' | 'io'  — returns zero PsiStats if missing."""
    text = _slurp(proc_root / "pressure" / resource)
    return parse_psi(text) if text is not None else PsiStats()


def read_cpu_times(proc_root: Path = PROC_ROOT) -> CpuTimes:
    text = _slurp(proc_root / "stat") or ""
    return parse_cpu_times(text)


def read_loadavg(proc_root: Path = PROC_ROOT) -> LoadAvg:
    text = _slurp(proc_root / "loadavg") or ""
    return parse_loadavg(text)


def read_fd_info(proc_root: Path = PROC_ROOT) -> FdInfo:
    text = _slurp(proc_root / "sys" / "fs" / "file-nr")
    return parse_file_nr(text) if text is not None else FdInfo()


def _read_one_disk(mount: str) -> Optional[DiskMount]:
    """Read disk space and inode stats for a single mount point."""
    try:
        if hasattr(os, "statvfs"):
            st = os.statvfs(mount)
            bs          = st.f_frsize
            total       = st.f_blocks * bs
            free        = st.f_bfree  * bs
            used        = total - free
            used_pct    = (used  / total * 100.0) if total > 0 else 0.0
            inode_total = st.f_files
            inode_free  = st.f_ffree
            inode_used  = max(0, inode_total - inode_free)
            inode_pct   = (inode_used / inode_total * 100.0) if inode_total > 0 else 0.0
        else:
            # Windows fallback (dev only) — no inode info
            import shutil
            u = shutil.disk_usage(mount)
            total, used, free = u.total, u.used, u.free
            used_pct = (used / total * 100.0) if total > 0 else 0.0
            inode_total = inode_used = 0
            inode_pct   = 0.0

        return DiskMount(
            mount=mount, total_bytes=total, used_bytes=used, free_bytes=free,
            used_pct=used_pct, inode_total=inode_total,
            inode_used=inode_used, inode_pct=inode_pct,
        )
    except OSError as exc:
        log.debug("disk read failed for %s: %s", mount, exc)
        return None


# Virtual/pseudo filesystem prefixes to skip during auto-discovery
_SKIP_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/snap", "tmpfs")


def read_disks(
    monitored: Optional[list[str]] = None,
    proc_root: Path = PROC_ROOT,
) -> list[DiskMount]:
    """
    Read disk usage for every mount point.

    If `monitored` is non-empty, read only those mounts.
    Otherwise auto-discover from /proc/mounts, skipping virtual filesystems.
    """
    if monitored:
        return [d for m in monitored if (d := _read_one_disk(m)) is not None]

    text = _slurp(proc_root / "mounts") or ""
    seen:   set[str]       = set()
    result: list[DiskMount] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        mp = parts[1]
        if mp in seen:
            continue
        if any(mp.startswith(p) for p in _SKIP_PREFIXES):
            continue
        seen.add(mp)
        d = _read_one_disk(mp)
        if d:
            result.append(d)
    return result


# ── Per-process reader ────────────────────────────────────────────────────────

def _read_one_process(pid_dir: Path) -> Optional[ProcessInfo]:
    """
    Read metrics for a single PID directory.

    Returns None if the process disappears mid-read or is inaccessible.
    """
    if not pid_dir.name.isdigit():
        return None
    try:
        pid = int(pid_dir.name)

        # Name from /proc/PID/comm (one-line, no parsing needed)
        name = (_slurp(pid_dir / "comm") or "?").strip()

        # State and VmRSS from /proc/PID/status
        state   = "?"
        rss_kb  = 0
        status_text = _slurp(pid_dir / "status") or ""
        for line in status_text.splitlines():
            if line.startswith("State:"):
                parts = line.split()
                state = parts[1] if len(parts) > 1 else "?"
            elif line.startswith("VmRSS:"):
                parts = line.split()
                try:
                    rss_kb = int(parts[1]) if len(parts) > 1 else 0
                except ValueError:
                    pass

        # CPU time (utime + stime) from /proc/PID/stat
        # Format: pid (comm) state ppid pgrp sess tty tpgid flags
        #         minflt cminflt majflt cmajflt utime stime ...
        cpu_time = 0
        stat_text = _slurp(pid_dir / "stat") or ""
        if stat_text:
            # Strip the variable-length "(comm)" part then split the rest
            m = re.search(r"\)\s+\S+\s+(.*)", stat_text)
            if m:
                tail = m.group(1).split()
                # After state: ppid(0) pgrp(1) sess(2) tty(3) tpgid(4) flags(5)
                #   minflt(6) cminflt(7) majflt(8) cmajflt(9) utime(10) stime(11)
                if len(tail) >= 12:
                    try:
                        cpu_time = int(tail[10]) + int(tail[11])
                    except ValueError:
                        pass

        # FD count — length of /proc/PID/fd directory
        fd_count = 0
        try:
            fd_count = len(list((pid_dir / "fd").iterdir()))
        except (OSError, PermissionError):
            pass

        # OOM score
        oom_score = 0
        oom_text = _slurp(pid_dir / "oom_score")
        if oom_text:
            try:
                oom_score = int(oom_text.strip())
            except ValueError:
                pass

        return ProcessInfo(
            pid=pid, name=name, state=state, mem_rss_kb=rss_kb,
            cpu_time=cpu_time, fd_count=fd_count, oom_score=oom_score,
        )
    except (OSError, PermissionError, FileNotFoundError):
        return None


def read_processes(proc_root: Path = PROC_ROOT, limit: int = 300) -> list[ProcessInfo]:
    """
    Read metrics for all accessible PID directories under proc_root.
    Skips processes that disappear or are unreadable. Capped at `limit`.
    """
    procs: list[ProcessInfo] = []
    try:
        for entry in proc_root.iterdir():
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            p = _read_one_process(entry)
            if p is not None:
                procs.append(p)
            if len(procs) >= limit:
                break
    except (OSError, PermissionError):
        pass
    return procs


# ═══════════════════════════════════════════════════════════════════════════════
# Stateful SystemReader  (tracks previous CPU times for delta computation)
# ═══════════════════════════════════════════════════════════════════════════════

class SystemReader:
    """
    High-level reader that assembles a full SystemSnapshot.

    Maintains previous CpuTimes to compute CPU % on each call.
    The first call always returns cpu.used_pct == 0.0.
    """

    def __init__(
        self,
        proc_root: Path = PROC_ROOT,
        monitored_mounts: Optional[list[str]] = None,
    ) -> None:
        self.proc_root = proc_root
        self.monitored_mounts = monitored_mounts or []
        self._prev_cpu: Optional[CpuTimes] = None

    def read(self) -> SystemSnapshot:
        """Collect and return a complete SystemSnapshot."""
        mem = read_meminfo(self.proc_root)
        mem.psi = read_psi("memory", self.proc_root)

        curr_cpu  = read_cpu_times(self.proc_root)
        cpu_used  = cpu_pct(self._prev_cpu, curr_cpu)
        self._prev_cpu = curr_cpu

        return SystemSnapshot(
            timestamp=time.time(),
            mem=mem,
            cpu=CpuSnapshot(
                used_pct=cpu_used,
                times=curr_cpu,
                load=read_loadavg(self.proc_root),
                psi=read_psi("cpu", self.proc_root),
            ),
            disks=read_disks(self.monitored_mounts or None, self.proc_root),
            fds=read_fd_info(self.proc_root),
            processes=read_processes(self.proc_root),
        )
