import uuid
from types import SimpleNamespace

import pytest

from sentinelos.actions import ActionResult
from sentinelos.approval import find_incident
from sentinelos.detector import Snapshot
from sentinelos.executor import Executor, judge, metric_from_snapshot
from sentinelos.models import Incident
from sentinelos.monitor import LoadAvg, MemInfo, ProcInfo
from sentinelos.planner import Proposal


class FakeVerifier:
    def __init__(self, *vals):
        self.vals = list(vals)

    def measure(self, fault_type, evidence, seconds=None):
        return self.vals.pop(0) if len(self.vals) > 1 else self.vals[0]


class FakeRunner:
    def __init__(self, outcome="SUCCESS", rollback=None):
        self.outcome, self.rollback, self.calls = outcome, rollback, []

    def __call__(self, action_id, params, dry_run=True, **kw):
        self.calls.append((action_id, dict(params), dry_run))
        if dry_run:
            return ActionResult(action_id, "DRY_RUN", "would do it", None, "Low")
        first_real = sum(1 for c in self.calls if not c[2]) == 1
        return ActionResult(action_id, self.outcome, "did it", self.rollback if first_real else None, "Low")


BUNDLE = {"fault_type": "cpu_exhaustion", "summary": "", "system": {}, "top_mem": [],
          "evidence": {"recent_cpu_pct": [99, 99, 99], "load1": 5, "ncpu": 4},
          "top_cpu": [{"pid": 4242, "name": "hog", "state": "R"}],
          "logs_untrusted": {"dmesg": [], "journal": []}}


def make(tmp_path, **kw):
    kw.setdefault("dry_run_default", False)
    kw.setdefault("verifier", FakeVerifier(50))
    kw.setdefault("runner", FakeRunner())
    kw.setdefault("lookup", lambda pid: SimpleNamespace(name="hog"))
    return Executor(tmp_path / "t.db", **kw)


def incident(ex, bundle=BUNDLE):
    with ex.Session() as s:
        inc = Incident(uuid=str(uuid.uuid4()), fault_type=bundle["fault_type"],
                       severity="CRITICAL", summary="t", state="OPEN")
        inc.set_raw_data(bundle)
        s.add(inc)
        s.commit()
        return inc


def prop(action="renice_process", risk="Low", params=None, blocked=None):
    return Proposal(action, params or {"pid": 4242, "nice_value": 5}, risk, "why", "effect", blocked)


def state(ex, inc):
    with ex.Session() as s:
        return s.get(Incident, inc.id).state


def test_dry_run_is_default_and_changes_nothing(tmp_path):
    runner = FakeRunner()
    ex = make(tmp_path, runner=runner, dry_run_default=True)
    inc = incident(ex)
    r = ex.execute(inc, prop(), "mohini", real=True)       # even with real=True
    assert r.outcome == "DRY_RUN"
    assert all(c[2] for c in runner.calls)
    assert ex.audit.count() == 1 and state(ex, inc) == "OPEN"


def test_improved_resolves_and_audits_before_after(tmp_path):
    ex = make(tmp_path, verifier=FakeVerifier(90, 40))
    inc = incident(ex)
    r = ex.execute(inc, prop(), "mohini", real=True)
    assert (r.outcome, r.verdict, r.before, r.after) == ("SUCCESS", "improved", 90, 40)
    assert state(ex, inc) == "RESOLVED"
    e = ex.audit.get_entries()[0]
    assert e.approved_by == "mohini" and not e.is_dry_run
    assert e.get_context()["verdict"] == "improved"
    assert ex.audit.verify_chain()[0]


def test_worse_triggers_rollback(tmp_path):
    rb = {"action_id": "renice_process", "params": {"pid": 4242, "nice_value": 0}}
    runner = FakeRunner(rollback=rb)
    ex = make(tmp_path, verifier=FakeVerifier(50, 80), runner=runner)
    inc = incident(ex)
    r = ex.execute(inc, prop(), "mohini", real=True)
    assert r.outcome == "ROLLED_BACK" and r.verdict == "worse" and r.rollback_outcome == "SUCCESS"
    real_calls = [c for c in runner.calls if not c[2]]
    assert len(real_calls) == 2 and real_calls[1][1]["nice_value"] == 0
    assert state(ex, inc) == "ROLLED_BACK"
    assert [e.outcome for e in ex.audit.get_entries()] == ["ROLLED_BACK", "SUCCESS"]
    assert ex.audit.verify_chain()[0]


def test_unchanged_stays_open_without_rollback(tmp_path):
    runner = FakeRunner(rollback={"action_id": "renice_process", "params": {"pid": 4242, "nice_value": 0}})
    ex = make(tmp_path, verifier=FakeVerifier(50), runner=runner)
    inc = incident(ex)
    r = ex.execute(inc, prop(), "mohini", real=True)
    assert r.outcome == "SUCCESS" and r.verdict == "unchanged"
    assert len([c for c in runner.calls if not c[2]]) == 1
    assert state(ex, inc) == "OPEN"


def test_worse_without_rollback_warns(tmp_path):
    ex = make(tmp_path, verifier=FakeVerifier(50, 80))
    inc = incident(ex)
    r = ex.execute(inc, prop(), "mohini", real=True)
    assert r.verdict == "worse" and "review" in r.detail and state(ex, inc) == "OPEN"


def test_failed_action_is_logged_and_incident_reopens(tmp_path):
    ex = make(tmp_path, runner=FakeRunner("FAILED"))
    inc = incident(ex)
    r = ex.execute(inc, prop(), "mohini", real=True)
    assert r.outcome == "FAILED" and state(ex, inc) == "OPEN"
    assert ex.audit.get_entries()[0].outcome == "FAILED"


def test_reject_is_logged(tmp_path):
    ex = make(tmp_path)
    inc = incident(ex)
    ex.reject(inc, prop(), "mohini", "too risky")
    e = ex.audit.get_entries()[0]
    assert "rejected by mohini" in e.outcome_detail and e.is_dry_run


def test_judge():
    assert judge(90, 40) == "improved" and judge(25, 0) == "improved"
    assert judge(50, 50) == "unchanged" and judge(0, 0) == "unchanged"
    assert judge(50, 70) == "worse"
    assert judge(None, 1) == "unknown"


def P(pid, state="S", fds=3):
    return ProcInfo(pid, "p", state, 1, 10, 100, fds, 0, 0)


def snap(procs=(), avail=1_000_000, cpu=None):
    return Snapshot(MemInfo(8_000_000, 0, avail, 0, 0, 0, 0), cpu, LoadAvg(0, 0, 0, 1, 1), {}, [], None, list(procs), 4)


def test_metrics():
    assert metric_from_snapshot("zombie_processes", {}, snap([P(i, "Z") for i in range(3)])) == 3
    assert metric_from_snapshot("fd_exhaustion", {"worst_pid": 9}, snap([P(9, fds=500)])) == 500
    assert metric_from_snapshot("fd_exhaustion", {"worst_pid": 9}, snap([])) == 0      # process gone
    assert metric_from_snapshot("memory_pressure", {}, snap(avail=2_000_000)) == pytest.approx(75.0)
    assert metric_from_snapshot("cpu_exhaustion", {}, snap(cpu=None)) is None
    assert metric_from_snapshot("mystery", {}, snap()) is None


def test_find_incident_by_id_and_uuid_prefix(tmp_path):
    ex = make(tmp_path)
    inc = incident(ex)
    with ex.Session() as s:
        assert find_incident(s, str(inc.id)).uuid == inc.uuid
        assert find_incident(s, inc.uuid[:8]).id == inc.id
        assert find_incident(s, "zzzz") is None