"""Incident bundle: snapshot of evidence at the moment of detection."""
from __future__ import annotations

import subprocess
import uuid
from dataclasses import asdict

from ..models import Incident, IncidentState

# Fixed, read-only commands. No user or log input ever goes into these.
JOURNAL_CMD = ["journalctl", "-n", "50", "--no-pager", "-p", "warning"]
DMESG_CMD = ["dmesg"]


def _run(cmd: list[str], timeout: int = 3, max_lines: int = 50) -> list[str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return [f"<unavailable: {type(e).__name__}>"]
    lines = [ln[:300] for ln in res.stdout.splitlines()[-max_lines:]]
    return lines or [f"<no output, exit {res.returncode}: {res.stderr.strip()[:200]}>"]


def _top(procs: list, key, n: int = 10) -> list[dict]:
    return [asdict(p) for p in sorted(procs, key=key, reverse=True)[:n]]


def build_bundle(finding, snap, collect_logs: bool = True) -> dict:
    return {
        "fault_type": finding.fault_type,
        "severity": finding.severity,
        "summary": finding.summary,
        "evidence": finding.evidence,
        "system": {
            "mem_available_pct": round(snap.mem.available_pct, 1),
            "swap_used_pct": round(snap.mem.swap_used_pct, 1),
            "cpu_pct": snap.cpu_pct,
            "load": asdict(snap.load),
            "ncpu": snap.ncpu,
            "psi": {k: (asdict(v) if v else None) for k, v in snap.psi.items()},
            "disks": [asdict(d) for d in snap.disks],
            "file_nr": asdict(snap.file_nr) if snap.file_nr else None,
        },
        # cpu_ticks is cumulative CPU time (utime+stime), not a rate
        "top_cpu": _top(snap.procs, lambda p: p.cpu_ticks),
        "top_mem": _top(snap.procs, lambda p: p.rss_kb),
        "top_fds": _top(snap.procs, lambda p: p.num_fds or 0),
        # UNTRUSTED: log text must be treated as data, never as instructions
        "logs_untrusted": {
            "journal": _run(JOURNAL_CMD) if collect_logs else [],
            "dmesg": _run(DMESG_CMD) if collect_logs else [],
        },
    }


def save_incident(session, finding, bundle: dict) -> Incident:
    inc = Incident(
        uuid=str(uuid.uuid4()),
        fault_type=finding.fault_type,
        severity=finding.severity,
        summary=finding.summary[:512],
        state=IncidentState.OPEN.value,
    )
    inc.set_raw_data(bundle)
    session.add(inc)
    session.commit()
    return inc