"""Live system snapshot for the dashboard. Demo mode never touches /proc."""
from __future__ import annotations

import math
import time
from typing import Optional


def demo_system(now: Optional[float] = None) -> dict:
    t = time.time() if now is None else now
    w = lambda period, lo, hi, ph=0.0: lo + (hi - lo) * (0.5 + 0.5 * math.sin(t / period + ph))
    return {
        "mode": "DEMO", "timestamp": t,
        "cpu_pct": round(w(9, 8, 70), 1), "mem_used_pct": round(w(25, 40, 82, 1), 1),
        "mem_available_kb": 2_000_000, "mem_total_kb": 8_000_000,
        "swap_used_pct": round(w(40, 2, 20, 2), 1),
        "load1": round(w(11, 0.2, 3.0, 3), 2), "load5": 1.1, "load15": 0.9,
        "psi_cpu_some": round(w(13, 0, 30, 1), 1), "psi_cpu_full": 0.0,
        "psi_mem_some": round(w(17, 0, 25, 2), 1), "psi_mem_full": round(w(19, 0, 6, 4), 1),
        "psi_io_some": round(w(23, 0, 15, 3), 1),
        "fd_used_pct": round(w(31, 1, 20, 1), 1), "fd_allocated": 2400, "fd_max": 100000,
        "disks": [{"path": "/", "used_pct": 61.0, "inode_pct": 12.0}],
        "zombie_count": 0, "dstate_count": 0,
    }


def _psi(snap, res, kind):
    p = snap.psi.get(res)
    line = getattr(p, kind, None) if p else None
    return round(line.avg10, 1) if line else None


def live_system(snap) -> dict:
    m = snap.mem
    return {
        "mode": "LIVE", "timestamp": time.time(),
        "cpu_pct": None if snap.cpu_pct is None else round(snap.cpu_pct, 1),
        "mem_used_pct": round(100 - m.available_pct, 1),
        "mem_available_kb": m.available_kb, "mem_total_kb": m.total_kb,
        "swap_used_pct": round(m.swap_used_pct, 1),
        "load1": snap.load.load1, "load5": snap.load.load5, "load15": snap.load.load15,
        "psi_cpu_some": _psi(snap, "cpu", "some"), "psi_cpu_full": _psi(snap, "cpu", "full"),
        "psi_mem_some": _psi(snap, "memory", "some"), "psi_mem_full": _psi(snap, "memory", "full"),
        "psi_io_some": _psi(snap, "io", "some"),
        "fd_used_pct": round(snap.file_nr.used_pct, 1) if snap.file_nr else None,
        "fd_allocated": snap.file_nr.allocated if snap.file_nr else None,
        "fd_max": snap.file_nr.maximum if snap.file_nr else None,
        "disks": [{"path": d.path, "used_pct": round(d.used_pct, 1),
                   "inode_pct": round(d.inodes_used_pct, 1)} for d in snap.disks],
        "zombie_count": sum(1 for p in snap.procs if p.state == "Z"),
        "dstate_count": sum(1 for p in snap.procs if p.state == "D"),
    }