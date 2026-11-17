"""Pure detection rules: Snapshot in, Findings out. No I/O here, so it is easy to test."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..config import ThresholdsConfig

WARNING = "WARNING"
CRITICAL = "CRITICAL"
RANK = {WARNING: 1, CRITICAL: 2}
LOAD_FACTOR = 2.0  # load1 >= 2x cores is flagged


@dataclass
class Snapshot:
    mem: object                      # MemInfo
    cpu_pct: Optional[float]         # None on first tick
    load: object                     # LoadAvg
    psi: dict                        # {"cpu": Psi|None, ...}
    disks: list                      # [DiskUsage]
    file_nr: Optional[object]        # FileNr
    procs: list                      # [ProcInfo]
    ncpu: int = 1


@dataclass
class Finding:
    fault_type: str
    severity: str
    summary: str
    key: str                         # used for dedup/cooldown
    evidence: dict = field(default_factory=dict)


def _make(fault_type: str, key: str, reasons: list, evidence: dict) -> Optional[Finding]:
    if not reasons:
        return None
    sev = max((r[0] for r in reasons), key=lambda s: RANK[s])
    return Finding(fault_type, sev, "; ".join(r[1] for r in reasons), key, evidence)


def check_memory(s: Snapshot, t: ThresholdsConfig) -> Optional[Finding]:
    m, r = t.memory, []
    used = 100.0 - s.mem.available_pct
    avail_mb = s.mem.available_kb / 1024
    if avail_mb < m.available_mb_critical:
        r.append((CRITICAL, f"only {avail_mb:.0f} MB memory available"))
    if used >= m.used_percent_critical:
        r.append((CRITICAL, f"memory {used:.1f}% used"))
    elif used >= m.used_percent_warning:
        r.append((WARNING, f"memory {used:.1f}% used"))
    p = s.psi.get("memory")
    if p:
        if p.full and p.full.avg10 >= m.psi_full_avg10_critical:
            r.append((CRITICAL, f"memory PSI full avg10={p.full.avg10}"))
        if p.some and p.some.avg10 >= m.psi_some_avg10_warning:
            r.append((WARNING, f"memory PSI some avg10={p.some.avg10}"))
    return _make("memory_pressure", "memory_pressure", r,
                 {"used_pct": round(used, 1), "available_mb": round(avail_mb),
                  "swap_used_pct": round(s.mem.swap_used_pct, 1)})


def check_cpu(s: Snapshot, t: ThresholdsConfig, history: list) -> Optional[Finding]:
    c, r = t.cpu, []
    n = c.sustained_samples
    recent = history[-n:]
    if len(recent) == n:
        if all(x >= c.used_percent_critical for x in recent):
            r.append((CRITICAL, f"CPU >= {c.used_percent_critical}% for {n} samples"))
        elif all(x >= c.used_percent_warning for x in recent):
            r.append((WARNING, f"CPU >= {c.used_percent_warning}% for {n} samples"))
    if s.load.load1 >= LOAD_FACTOR * s.ncpu:
        r.append((WARNING, f"load1 {s.load.load1} on {s.ncpu} cores"))
    p = s.psi.get("cpu")
    if p and p.some and p.some.avg10 >= c.psi_some_avg10_warning:
        r.append((WARNING, f"cpu PSI some avg10={p.some.avg10}"))
    return _make("cpu_exhaustion", "cpu_exhaustion", r,
                 {"recent_cpu_pct": recent, "load1": s.load.load1, "ncpu": s.ncpu})


def check_disks(s: Snapshot, t: ThresholdsConfig) -> list[Finding]:
    d, out = t.disk, []
    for u in s.disks:
        r = []
        if u.used_pct >= d.used_percent_critical:
            r.append((CRITICAL, f"{u.path} {u.used_pct:.1f}% full"))
        elif u.used_pct >= d.used_percent_warning:
            r.append((WARNING, f"{u.path} {u.used_pct:.1f}% full"))
        f = _make("disk_full", f"disk_full:{u.path}", r, {"path": u.path, "used_pct": round(u.used_pct, 1)})
        if f:
            out.append(f)
        if u.inodes_used_pct >= d.inode_used_percent_critical:
            out.append(Finding("inode_exhaustion", CRITICAL,
                               f"{u.path} inodes {u.inodes_used_pct:.1f}% used",
                               f"inode_exhaustion:{u.path}",
                               {"path": u.path, "inodes_used_pct": round(u.inodes_used_pct, 1)}))
    return out


def check_fds(s: Snapshot, t: ThresholdsConfig) -> Optional[Finding]:
    f, r, ev = t.file_descriptors, [], {}
    if s.file_nr and s.file_nr.used_pct >= f.system_fd_percent_critical:
        r.append((CRITICAL, f"system FDs {s.file_nr.used_pct:.1f}% used"))
        ev["system_used_pct"] = round(s.file_nr.used_pct, 1)
    with_fds = [p for p in s.procs if p.num_fds is not None]
    if with_fds:
        w = max(with_fds, key=lambda p: p.num_fds)
        if w.num_fds >= f.per_process_fd_critical:
            r.append((CRITICAL, f"{w.name}[{w.pid}] has {w.num_fds} open FDs"))
        elif w.num_fds >= f.per_process_fd_warning:
            r.append((WARNING, f"{w.name}[{w.pid}] has {w.num_fds} open FDs"))
        if r:
            ev.update(worst_pid=w.pid, worst_name=w.name, worst_fds=w.num_fds)
    return _make("fd_exhaustion", "fd_exhaustion", r, ev)


def _state_check(s: Snapshot, state: str, fault: str, warn: int, crit: int) -> Optional[Finding]:
    hit = [p for p in s.procs if p.state == state]
    n, r = len(hit), []
    if n >= crit:
        r.append((CRITICAL, f"{n} {fault} (>= {crit})"))
    elif n >= warn:
        r.append((WARNING, f"{n} {fault} (>= {warn})"))
    return _make(fault, fault, r,
                 {"count": n, "sample": [{"pid": p.pid, "name": p.name, "ppid": p.ppid} for p in hit[:10]]})


def check_processes(s: Snapshot, t: ThresholdsConfig) -> list[Finding]:
    p = t.process
    found = [_state_check(s, "Z", "zombie_processes", p.zombie_count_warning, p.zombie_count_critical),
             _state_check(s, "D", "dstate_processes", p.dstate_count_warning, p.dstate_count_critical)]
    return [f for f in found if f]


def evaluate(s: Snapshot, t: ThresholdsConfig, cpu_history: list) -> list[Finding]:
    out = [check_memory(s, t), check_cpu(s, t, cpu_history), check_fds(s, t)]
    out = [f for f in out if f]
    out += check_disks(s, t) + check_processes(s, t)
    return out