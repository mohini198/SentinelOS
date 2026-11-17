"""Builds a Snapshot from /proc. Keeps previous CPU sample to compute usage %."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..monitor import (cpu_usage_pct, list_processes, read_all_psi, read_cpu_times,
                       read_disk, read_file_nr, read_loadavg, read_meminfo)
from ..monitor.proc_reader import PROC, _read
from .rules import Snapshot

REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "zfs", "f2fs"}


def real_mounts(proc: Path = PROC) -> list[str]:
    text = _read(proc / "mounts") or ""
    seen: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in REAL_FS and parts[1] not in seen:
            seen.append(parts[1])
    return seen or ["/"]


class Collector:
    def __init__(self, mounts: Optional[list[str]] = None, proc: Path = PROC):
        self.mounts = mounts          # None/[] = auto-detect
        self.proc = proc
        self._prev_cpu: Optional[dict] = None

    def snapshot(self) -> Snapshot:
        cur = read_cpu_times(self.proc)
        cpu = cpu_usage_pct(self._prev_cpu, cur) if self._prev_cpu else None
        self._prev_cpu = cur

        disks = []
        for path in (self.mounts or real_mounts(self.proc)):
            try:
                disks.append(read_disk(path))
            except (OSError, AttributeError):   # AttributeError: no statvfs (Windows)
                continue
        try:
            fnr = read_file_nr(self.proc)
        except FileNotFoundError:
            fnr = None
        return Snapshot(
            mem=read_meminfo(self.proc), cpu_pct=cpu, load=read_loadavg(self.proc),
            psi=read_all_psi(self.proc), disks=disks, file_nr=fnr,
            procs=list_processes(self.proc), ncpu=os.cpu_count() or 1,
        )