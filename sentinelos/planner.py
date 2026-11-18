"""Maps a Diagnosis to ranked, allowlisted proposals. Proposals are DATA only; nothing runs here."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .actions.guard import check_target_pid
from .config import settings
from .diagnosis import Diagnosis

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Forbidden": 3}


@dataclass
class Proposal:
    action_id: str
    params: dict
    risk: str
    rationale: str
    expected_effect: str
    blocked_reason: Optional[str] = None


def plan(diag: Diagnosis, check: Callable = check_target_pid) -> list[Proposal]:
    cand: list[tuple] = []     # (action_id, params, rationale, effect)
    pid = (diag.culprit or {}).get("pid")
    name = (diag.culprit or {}).get("name", "?")
    why = f"{diag.fault_type}: {diag.root_cause}"[:250]

    if diag.fault_type == "memory_pressure":
        cand.append(("drop_caches", {"level": 1}, "free reclaimable page cache", "a little memory freed, no data loss"))
        if pid:
            cand.append(("kill_process_sigterm", {"pid": pid, "reason": why}, f"stop the largest memory user {name}", "memory released when it exits"))
    elif diag.fault_type == "cpu_exhaustion" and pid:
        cand.append(("renice_process", {"pid": pid, "nice_value": 10}, f"lower priority of {name}", "other processes get CPU back"))
        cand.append(("kill_process_sigterm", {"pid": pid, "reason": why}, f"stop runaway {name}", "CPU freed"))
    elif diag.fault_type == "fd_exhaustion" and pid:
        cand.append(("raise_ulimit_nofile", {"pid": pid, "new_limit": 4096}, f"temporary relief for {name}", "buys time, does not fix the leak"))
        cand.append(("kill_process_sigterm", {"pid": pid, "reason": why}, f"restart/stop the leaking {name}", "all its FDs are released"))
    elif diag.fault_type == "zombie_processes" and pid:
        cand.append(("kill_process_sigterm", {"pid": pid, "reason": why}, f"stop the parent {pid} so init reaps the zombies", "zombies disappear"))
    elif diag.fault_type == "disk_full":
        cand.append(("run_journalctl_vacuum", {"max_size": "500M"}, "shrink the systemd journal", "frees disk space"))

    out = []
    for aid, params, rationale, effect in cand:
        spec = settings.allowlist.get_action(aid)
        if spec is None:
            continue
        reason = check(params["pid"]) if "pid" in params else None
        out.append(Proposal(aid, params, spec.risk, rationale, effect, reason))
    out.sort(key=lambda p: (p.blocked_reason is not None, RISK_ORDER.get(p.risk, 9)))
    return out