"""Executor: runs ONE human-approved proposal, verifies its effect, rolls back if it made
things worse. Every decision (including blocks) goes to the hash-chained audit log."""
from __future__ import annotations

import datetime
import time
from dataclasses import dataclass
from typing import Optional

from .actions import run_action
from .audit import AuditLog
from .config import settings
from .detector import Collector
from .diagnosis import diagnose
from .models import Incident, IncidentState, make_engine, make_session_factory
from .monitor.proc_reader import read_process

S = IncidentState


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _target(params: dict):
    for k in ("pid", "unit", "path", "cgroup_path"):
        if k in params:
            return params[k]
    return None


# ── Verification ──────────────────────────────────────────────────────────────
def metric_from_snapshot(fault_type: str, ev: dict, snap) -> Optional[float]:
    """One number per fault type. LOWER is better."""
    if fault_type == "memory_pressure":
        return 100.0 - snap.mem.available_pct
    if fault_type == "cpu_exhaustion":
        return snap.cpu_pct
    if fault_type == "fd_exhaustion":
        pid = ev.get("worst_pid")
        if pid is not None:
            p = next((x for x in snap.procs if x.pid == pid), None)
            return float(p.num_fds or 0) if p else 0.0      # process gone -> 0
        return snap.file_nr.used_pct if snap.file_nr else None
    if fault_type == "zombie_processes":
        return float(sum(1 for p in snap.procs if p.state == "Z"))
    if fault_type == "dstate_processes":
        return float(sum(1 for p in snap.procs if p.state == "D"))
    if fault_type in ("disk_full", "inode_exhaustion"):
        d = next((x for x in snap.disks if x.path == ev.get("path")), None)
        if d is None:
            return None
        return d.used_pct if fault_type == "disk_full" else d.inodes_used_pct
    return None


def judge(before: Optional[float], after: Optional[float], tol: float = 0.10) -> str:
    if before is None or after is None:
        return "unknown"
    if after < before * (1 - tol) and before - after >= 0.5:
        return "improved"
    if after > before * (1 + tol) and after - before >= 1.0:
        return "worse"
    return "unchanged"


class Verifier:
    def __init__(self, collector=None, seconds: float = 10.0, interval: float = 2.0, sleep=time.sleep):
        self.collector = collector or Collector(settings.thresholds.disk.monitored_mounts or None)
        self.seconds, self.interval, self.sleep = seconds, interval, sleep

    def measure(self, fault_type: str, evidence: dict, seconds: Optional[float] = None) -> Optional[float]:
        secs = self.seconds if seconds is None else seconds
        n = max(2, int(secs / self.interval) + 1)     # >=2 samples so CPU % can be computed
        vals = []
        for i in range(n):
            v = metric_from_snapshot(fault_type, evidence, self.collector.snapshot())
            if v is not None:
                vals.append(v)
            if i < n - 1:
                self.sleep(self.interval)
        return sum(vals) / len(vals) if vals else None


# ── Executor ──────────────────────────────────────────────────────────────────
@dataclass
class ExecResult:
    outcome: str                       # DRY_RUN | SUCCESS | FAILED | BLOCKED | ROLLED_BACK
    detail: str
    verdict: Optional[str] = None
    before: Optional[float] = None
    after: Optional[float] = None
    rollback_outcome: Optional[str] = None


class Executor:
    def __init__(self, db_path=None, verifier=None, runner=run_action, lookup=read_process,
                 dry_run_default: Optional[bool] = None, max_per_hour: int = 5, cooldown_s: float = 120.0):
        db = db_path or settings.db_path
        self.audit = AuditLog(db)
        self.Session = make_session_factory(make_engine(db))
        self.verifier = verifier or Verifier()
        self.runner, self.lookup = runner, lookup
        self.global_dry = settings.dry_run if dry_run_default is None else dry_run_default
        self.max_per_hour, self.cooldown_s = max_per_hour, cooldown_s

    # -- helpers
    def _get(self, inc_id: int) -> Optional[Incident]:
        with self.Session() as s:
            return s.get(Incident, inc_id)

    def _set_state(self, inc_id: int, state: IncidentState, resolved: bool = False) -> None:
        with self.Session() as s:
            row = s.get(Incident, inc_id)
            row.state = state.value
            if resolved:
                row.resolved_at = _utcnow()
            s.commit()

    def _log(self, inc, p, outcome, detail, dry, by, action=None, params=None, risk=None, extra=None):
        ctx = {"incident": inc.uuid, "rationale": p.rationale}
        ctx.update(extra or {})
        self.audit.append(action_id=action or p.action_id, risk_tier=risk or p.risk, is_dry_run=dry,
                          params=params if params is not None else p.params, context=ctx,
                          approved_by=by, outcome=outcome, outcome_detail=(detail or "")[:500],
                          incident_ids=[inc.id])

    def _recent(self, window_s: float) -> list:
        cutoff = _utcnow() - datetime.timedelta(seconds=window_s)
        out = []
        for e in self.audit.get_entries(limit=500):          # newest first
            if e.created_at < cutoff:
                break
            if not e.is_dry_run and e.outcome in ("SUCCESS", "FAILED"):
                out.append(e)
        return out

    def _rate_limited(self, p) -> Optional[str]:
        if len(self._recent(3600)) >= self.max_per_hour:
            return f"rate limit: {self.max_per_hour} real actions already ran in the last hour"
        tgt = _target(p.params)
        for e in self._recent(self.cooldown_s):
            if e.action_id == p.action_id and _target(e.get_params()) == tgt:
                return f"cooldown: {p.action_id} on {tgt} ran less than {self.cooldown_s:.0f}s ago"
        return None

    def _identity_problem(self, p, diag) -> Optional[str]:
        """Human approval can take minutes; make sure the PID is still the same process (PID reuse)."""
        pid, c = p.params.get("pid"), diag.culprit or {}
        if pid is None or c.get("pid") != pid or c.get("name") in (None, "parent"):
            return None
        info = self.lookup(pid)
        if info is None:
            return f"pid {pid} no longer exists"
        if info.name != c["name"]:
            return f"pid {pid} is now {info.name!r} but was {c['name']!r} at detection (PID reused?)"
        return None

    # -- public API
    def reject(self, inc, p, by: str, reason: str = "") -> None:
        self._log(inc, p, "BLOCKED", f"rejected by {by}: {reason}", True, by)

    def execute(self, inc, p, approved_by: str, confirmation: Optional[str] = None,
                real: bool = False) -> ExecResult:
        dry = self.global_dry or not real

        def block(why: str) -> ExecResult:
            self._log(inc, p, "BLOCKED", why, dry, approved_by)
            return ExecResult("BLOCKED", why)

        if not (approved_by or "").strip():
            return block("an approver name is required")
        if p.risk == "Forbidden" or p.action_id.startswith("__forbidden"):
            return block("forbidden action can never run")
        if p.blocked_reason:
            return block(f"proposal is blocked: {p.blocked_reason}")
        fresh = self._get(inc.id)
        if fresh is None:
            return block("incident not found")
        inc = fresh
        if inc.state in (S.RESOLVED.value, S.DISMISSED.value, S.EXECUTING.value):
            return block(f"incident is already {inc.state}")
        bundle = inc.get_raw_data()
        why = self._identity_problem(p, diagnose(bundle))
        if why:
            return block(why)

        if dry:
            r = self.runner(p.action_id, p.params, dry_run=True)
            self._log(inc, p, r.outcome, r.detail, True, approved_by)
            return ExecResult(r.outcome, r.detail)

        if p.risk == "High" and confirmation != p.action_id:
            return block(f"High-risk action needs typed confirmation: type exactly {p.action_id!r}")
        why = self._rate_limited(p)
        if why:
            return block(why)

        evidence = bundle.get("evidence", {})
        self._set_state(inc.id, S.EXECUTING)
        try:
            before = self.verifier.measure(inc.fault_type, evidence, 0)
            r = self.runner(p.action_id, p.params, dry_run=False)
            if r.outcome != "SUCCESS":
                self._log(inc, p, r.outcome, r.detail, False, approved_by, extra={"before": before})
                return ExecResult(r.outcome, r.detail, before=before)

            after = self.verifier.measure(inc.fault_type, evidence)
            verdict = judge(before, after)
            self._log(inc, p, "SUCCESS", r.detail, False, approved_by,
                      extra={"before": before, "after": after, "verdict": verdict})

            if verdict == "worse" and r.rollback:
                rb = r.rollback
                rr = self.runner(rb["action_id"], rb["params"], dry_run=False)
                ok = rr.outcome == "SUCCESS"
                spec = settings.allowlist.get_action(rb["action_id"])
                self._log(inc, p, "ROLLED_BACK" if ok else "FAILED", rr.detail, False, approved_by,
                          action=rb["action_id"], params=rb["params"], risk=spec.risk if spec else "Low",
                          extra={"reason": "verification showed the system got worse"})
                if ok:
                    self._set_state(inc.id, S.ROLLED_BACK)
                return ExecResult("ROLLED_BACK" if ok else "FAILED", rr.detail, verdict, before, after, rr.outcome)

            detail = r.detail
            if verdict == "improved":
                self._set_state(inc.id, S.RESOLVED, resolved=True)
            elif verdict == "worse":
                detail += " | WARNING: got worse and no rollback exists, please review"
            else:
                detail += " | no measurable improvement yet"
            return ExecResult("SUCCESS", detail, verdict, before, after)
        finally:
            row = self._get(inc.id)
            if row and row.state == S.EXECUTING.value:
                self._set_state(inc.id, S.OPEN)