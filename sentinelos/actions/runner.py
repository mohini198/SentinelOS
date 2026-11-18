"""run_action(): the ONLY entry point for executing anything. Order of checks:
allowlist -> forbidden -> params schema -> protected targets -> precheck -> dry-run -> execute."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import AllowlistConfig, ProtectedProcessesConfig, settings
from ..monitor.proc_reader import PROC
from .guard import check_target_pid, check_unit
from .library import IMPLS
from .schema import validate_params


@dataclass
class ActionResult:
    action_id: str
    outcome: str                       # DRY_RUN | SUCCESS | FAILED | BLOCKED
    detail: str
    rollback: Optional[dict] = None    # {"action_id":..., "params":...} that undoes this action
    risk: Optional[str] = None


def run_action(action_id: str, params: dict, dry_run: bool = True,
               allowlist: Optional[AllowlistConfig] = None,
               protected: Optional[ProtectedProcessesConfig] = None,
               proc: Path = PROC) -> ActionResult:
    spec = (allowlist or settings.allowlist).get_action(action_id)
    risk = spec.risk if spec else None

    def out(outcome, detail, rollback=None):
        return ActionResult(action_id, outcome, detail, rollback, risk)

    if spec is None:
        return out("BLOCKED", "action is not in the allowlist")
    if spec.risk == "Forbidden" or action_id.startswith("__forbidden"):
        return out("BLOCKED", "action is FORBIDDEN and can never run")
    errs = validate_params(spec.params, params)
    if errs:
        return out("BLOCKED", "invalid params: " + "; ".join(errs))
    impl = IMPLS.get(action_id)
    if impl is None:
        return out("BLOCKED", "no implementation for this action")
    why = None
    if "pid" in params:
        why = check_target_pid(params["pid"], protected, proc)
    if why is None and "unit" in params:
        why = check_unit(params["unit"], protected)
    if why is None and impl.precheck:
        why = impl.precheck(params)
    if why:
        return out("BLOCKED", why)
    if dry_run:
        return out("DRY_RUN", "would " + impl.describe(params))
    try:
        detail, rollback = impl.run(params)
        return out("SUCCESS", detail, rollback)
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return out("FAILED", f"{type(e).__name__}: {e}")