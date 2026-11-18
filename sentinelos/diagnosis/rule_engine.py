"""Rule-based diagnosis. Input: incident bundle (dict). Output: Diagnosis.
Works with no LLM. Log text is only substring-matched, never executed or obeyed."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Diagnosis:
    fault_type: str
    root_cause: str
    confidence: str                      # high | medium | low
    evidence: list = field(default_factory=list)
    culprit: Optional[dict] = None       # {"pid": .., "name": ..}
    hints: list = field(default_factory=list)   # plain-English directions, NOT commands


def _memory(b: dict) -> Diagnosis:
    sysd, ev = b.get("system", {}), b.get("evidence", {})
    total = sysd.get("mem_total_kb") or 0
    top = (b.get("top_mem") or [None])[0]
    lines = [f"{ev.get('used_pct')}% memory used, {ev.get('available_mb')} MB available"]
    if (ev.get("swap_used_pct") or 0) >= 50:
        lines.append(f"swap {ev['swap_used_pct']}% used (system is likely thrashing)")
    dmesg = (b.get("logs_untrusted") or {}).get("dmesg", [])
    if any("out of memory" in l.lower() or "oom-kill" in l.lower() for l in dmesg):
        lines.append("kernel log shows OOM killer activity")
    if top and total:
        share = 100.0 * top["rss_kb"] / total
        culprit = {"pid": top["pid"], "name": top["name"]}
        lines.append(f"{top['name']}[{top['pid']}] uses {top['rss_kb'] // 1024} MB ({share:.0f}% of RAM), oom_score={top.get('oom_score')}")
        if share >= 40:
            return Diagnosis("memory_pressure", f"{top['name']} (pid {top['pid']}) is consuming most of the RAM: likely a memory leak or oversized workload",
                             "high", lines, culprit,
                             ["limit the process with a cgroup memory cap", "restart the service if it keeps growing"])
        if share >= 20:
            return Diagnosis("memory_pressure", f"{top['name']} is the largest memory user but not the only one",
                             "medium", lines, culprit, ["cap the largest process", "check other big consumers"])
    return Diagnosis("memory_pressure", "memory is used by many processes; no single culprit", "low", lines, None,
                     ["review top memory consumers", "consider adding RAM or swap"])


def _cpu(b: dict) -> Diagnosis:
    ev = b.get("evidence", {})
    # top_cpu is by cumulative ticks, so prefer processes that are running right now
    running = [p for p in b.get("top_cpu", []) if p.get("state") == "R"]
    lines = [f"recent CPU samples {ev.get('recent_cpu_pct')}%, load1={ev.get('load1')} on {ev.get('ncpu')} cores"]
    if running:
        p = running[0]
        lines.append(f"{len(running)} of the top CPU processes are in running state; first: {p['name']}[{p['pid']}]")
        conf = "medium" if len(running) == 1 else "low"
        cause = (f"{p['name']} (pid {p['pid']}) is saturating the CPU" if len(running) == 1
                 else f"{len(running)} busy processes (e.g. {p['name']}) are saturating the CPU")
        return Diagnosis("cpu_exhaustion", cause, conf, lines, {"pid": p["pid"], "name": p["name"]},
                         ["lower priority with nice/renice", "apply a cgroup CPU limit", "terminate if it is a runaway"])
    return Diagnosis("cpu_exhaustion", "CPU is saturated but no single running process stands out", "low", lines, None,
                     ["inspect load over time"])


def _fd(b: dict) -> Diagnosis:
    ev = b.get("evidence", {})
    if "worst_pid" in ev:
        c = {"pid": ev["worst_pid"], "name": ev["worst_name"]}
        lines = [f"{c['name']}[{c['pid']}] has {ev['worst_fds']} open file descriptors"]
        if "system_used_pct" in ev:
            lines.append(f"system-wide FD table {ev['system_used_pct']}% used")
        return Diagnosis("fd_exhaustion", f"{c['name']} (pid {c['pid']}) is leaking file descriptors (not closing files/sockets)",
                         "high", lines, c, ["restart the leaking service", "raise its ulimit only as a temporary measure"])
    return Diagnosis("fd_exhaustion", "system-wide FD table is nearly full across many processes", "medium",
                     [f"system FDs {ev.get('system_used_pct')}% used"], None, ["find the top FD holders"])


def _zombies(b: dict) -> Diagnosis:
    ev = b.get("evidence", {})
    sample = ev.get("sample", [])
    ppids = Counter(z["ppid"] for z in sample)
    lines = [f"{ev.get('count')} zombie processes"]
    if ppids:
        ppid, n = ppids.most_common(1)[0]
        lines.append(f"{n} of the {len(sample)} sampled zombies share parent pid {ppid}")
        return Diagnosis("zombie_processes", f"parent process {ppid} is not reaping its finished children (missing wait())",
                         "high" if n == len(sample) else "medium", lines, {"pid": ppid, "name": "parent"},
                         ["zombies cannot be killed; signal the parent (SIGCHLD) or restart it so they are reaped"])
    return Diagnosis("zombie_processes", "zombies present but parent unknown", "low", lines, None, [])


def _dstate(b: dict) -> Diagnosis:
    ev = b.get("evidence", {})
    names = Counter(p["name"] for p in ev.get("sample", []))
    lines = [f"{ev.get('count')} processes in uninterruptible sleep (D)", f"names: {dict(names)}"]
    io = ((b.get("system", {}).get("psi") or {}).get("io") or {}).get("some") or {}
    if io.get("avg10", 0) >= 10:
        lines.append(f"I/O pressure avg10={io['avg10']}")
        return Diagnosis("dstate_processes", "processes are blocked waiting on slow or stuck I/O (disk/NFS)", "medium", lines, None,
                         ["check disk health and mounts", "D-state processes cannot be killed until I/O returns"])
    return Diagnosis("dstate_processes", "processes stuck in uninterruptible sleep, cause unclear", "low", lines, None,
                     ["check dmesg for I/O errors"])


def _disk(b: dict) -> Diagnosis:
    ev = b.get("evidence", {})
    return Diagnosis("disk_full", f"filesystem {ev.get('path')} is {ev.get('used_pct')}% full", "medium",
                     [f"{ev.get('path')} usage {ev.get('used_pct')}%"], None,
                     ["rotate or compress old logs", "clean old temp files", "find the largest directories"])


def _inode(b: dict) -> Diagnosis:
    ev = b.get("evidence", {})
    return Diagnosis("inode_exhaustion", f"{ev.get('path')} has run out of inodes: too many small files", "medium",
                     [f"inodes {ev.get('inodes_used_pct')}% used"], None,
                     ["find directories with huge file counts (sessions, caches, tmp)"])


RULES = {"memory_pressure": _memory, "cpu_exhaustion": _cpu, "fd_exhaustion": _fd,
         "zombie_processes": _zombies, "dstate_processes": _dstate,
         "disk_full": _disk, "inode_exhaustion": _inode}


def diagnose(bundle: dict) -> Diagnosis:
    ft = bundle.get("fault_type", "unknown")
    fn = RULES.get(ft)
    if fn is None:
        return Diagnosis(ft, "no rule for this fault type", "low", [bundle.get("summary", "")])
    return fn(bundle)