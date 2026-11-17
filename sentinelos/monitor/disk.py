"""Disk space and inode usage via statvfs."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class DiskUsage:
    path: str
    total_bytes: int
    used_bytes: int
    used_pct: float
    inodes_total: int
    inodes_used_pct: float


def read_disk(path: str = "/") -> DiskUsage:
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bfree * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    used = total - free
    # same formula as `df`: used / (used + available)
    denom = used + avail
    used_pct = 100.0 * used / denom if denom else 0.0
    if st.f_files:  # some filesystems (btrfs) report 0 inodes
        inodes_pct = 100.0 * (st.f_files - st.f_ffree) / st.f_files
    else:
        inodes_pct = 0.0
    return DiskUsage(path, total, used, used_pct, st.f_files, inodes_pct)