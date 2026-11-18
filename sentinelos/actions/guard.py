"""Safety checks: protected processes/units and safe file/cgroup paths."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..config import ProtectedProcessesConfig, settings
from ..monitor.proc_reader import PROC, _read, read_process

SAFE_FILE_ROOTS = ("/var/log", "/tmp")
CGROUP_ROOT = "/sys/fs/cgroup/"


def check_target_pid(pid: int, protected: Optional[ProtectedProcessesConfig] = None,
                     proc: Path = PROC) -> Optional[str]:
    """Return a reason string if the pid must NOT be touched, else None."""
    p = protected or settings.protected
    if pid <= 1 or pid in p.forbidden_pids:
        return f"pid {pid} is init/forbidden"
    if pid in (os.getpid(), os.getppid()):
        return "pid is the agent itself or its parent"
    info = read_process(pid, proc)
    if info is None:
        return f"pid {pid} does not exist"
    low = info.name.lower()
    for n in p.forbidden_names:
        if n.lower() in low:
            return f"process name {info.name!r} is protected ({n})"
    try:
        exe = os.readlink(proc / str(pid) / "exe")
        for pre in p.forbidden_exe_prefixes:
            if exe.startswith(pre):
                return f"executable {exe} is protected"
    except OSError:
        pass
    if p.protect_root_no_tty:
        status = _read(proc / str(pid) / "status") or ""
        uid = next((int(l.split()[1]) for l in status.splitlines() if l.startswith("Uid:")), None)
        stat = _read(proc / str(pid) / "stat") or ""
        rest = stat[stat.rfind(")") + 2:].split()
        tty = int(rest[4]) if len(rest) > 4 and rest[4].lstrip("-").isdigit() else None
        if uid == 0 and tty == 0:
            return "root-owned process with no controlling tty is protected"
    return None


def check_unit(unit: str, protected: Optional[ProtectedProcessesConfig] = None) -> Optional[str]:
    p = protected or settings.protected
    stem = unit.rsplit(".", 1)[0].lower()
    for n in p.forbidden_names:
        if n.lower() in stem:
            return f"unit {unit} is protected ({n})"
    return None


def safe_file(path: str) -> Optional[str]:
    """Only regular, non-symlink files under /var/log or /tmp."""
    if not os.path.isabs(path):
        return "path must be absolute"
    if os.path.islink(path):
        return "symlinks are not allowed"
    real = os.path.realpath(path)
    if not any(real.startswith(r + "/") for r in SAFE_FILE_ROOTS):
        return f"{real} is outside allowed directories {SAFE_FILE_ROOTS}"
    if not os.path.isfile(real):
        return "not a regular file"
    return None


def safe_cgroup(path: str) -> Optional[str]:
    real = os.path.realpath(path)
    if not (real + "/").startswith(CGROUP_ROOT) or real + "/" == CGROUP_ROOT:
        return "path is not inside a cgroup below /sys/fs/cgroup/"
    if not os.path.isdir(real):
        return "cgroup directory does not exist"
    return None