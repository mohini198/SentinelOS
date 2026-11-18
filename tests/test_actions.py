import os
import subprocess

import pytest

from sentinelos.actions import check_target_pid, run_action
from sentinelos.actions.guard import check_unit
from sentinelos.config import ProtectedProcessesConfig
from sentinelos.diagnosis import Diagnosis
from sentinelos.planner import plan

pytestmark = pytest.mark.skipif(not hasattr(os, "getpriority"), reason="Linux only")

PROT = ProtectedProcessesConfig(forbidden_names=["sshd", "systemd"])


@pytest.fixture
def sleeper():
    p = subprocess.Popen(["sleep", "60"])
    yield p
    if p.poll() is None:
        p.kill()
    p.wait()


def fake(root, pid, comm, uid=1000, tty=0):
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "stat").write_text(f"{pid} ({comm}) S 1 {pid} {pid} {tty} " + "0 " * 6 + "70 30 0 0 20 0 1 0 100 4096 10\n")
    (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")


# ── guard ─────────────────────────────────────────────────────────────────────
def test_guard_blocks_init_self_and_names(tmp_path):
    assert check_target_pid(1, PROT, tmp_path)
    assert check_target_pid(os.getpid(), PROT, tmp_path)
    fake(tmp_path, 5000, "sshd")
    assert "protected" in check_target_pid(5000, PROT, tmp_path)
    fake(tmp_path, 5001, "systemd-resolved")
    assert check_target_pid(5001, PROT, tmp_path)
    assert check_target_pid(9999, PROT, tmp_path)           # does not exist


def test_guard_root_no_tty_rule(tmp_path):
    fake(tmp_path, 6000, "worker", uid=0, tty=0)
    fake(tmp_path, 6001, "worker", uid=0, tty=34816)
    fake(tmp_path, 6002, "worker", uid=1000, tty=0)
    assert check_target_pid(6000, PROT, tmp_path)
    assert check_target_pid(6001, PROT, tmp_path) is None
    assert check_target_pid(6002, PROT, tmp_path) is None


def test_unit_guard():
    assert check_unit("sshd.service", PROT)
    assert check_unit("nginx.service", PROT) is None


# ── allowlist / schema ────────────────────────────────────────────────────────
def test_forbidden_unknown_and_bad_params_blocked():
    assert run_action("__forbidden_rm_rf", {}).outcome == "BLOCKED"
    assert run_action("rm_everything", {}).outcome == "BLOCKED"
    assert run_action("renice_process", {"pid": 1, "nice_value": 5}).outcome == "BLOCKED"          # min 2
    assert run_action("renice_process", {"pid": 99999, "nice_value": 50}).outcome == "BLOCKED"      # max 19
    assert run_action("renice_process", {"pid": "12"}).outcome == "BLOCKED"
    assert run_action("renice_process", {"pid": 12, "nice_value": 1, "evil": "x"}).outcome == "BLOCKED"
    assert run_action("drop_caches", {"level": 9}).outcome == "BLOCKED"
    assert run_action("run_journalctl_vacuum", {"max_size": "1G; rm -rf /"}).outcome == "BLOCKED"
    assert run_action("restart_systemd_unit", {"unit": "x.service --now"}).outcome == "BLOCKED"


def test_protected_targets_blocked_even_in_dry_run():
    assert run_action("kill_process_sigterm", {"pid": os.getpid()}).outcome == "BLOCKED"
    assert run_action("restart_systemd_unit", {"unit": "sshd.service"}).outcome == "BLOCKED"


def test_paths_outside_safe_roots_blocked(tmp_path):
    assert run_action("truncate_log_file", {"path": "/etc/passwd"}).outcome == "BLOCKED"
    assert run_action("delete_file", {"path": "/etc/hostname"}).outcome == "BLOCKED"
    assert run_action("set_cpu_cgroup_quota", {"cgroup_path": "/sys/fs/cgroup/../../etc",
                                               "quota_us": 5000, "period_us": 100000}).outcome == "BLOCKED"
    real = tmp_path / "real.log"
    real.write_text("x")
    link = tmp_path / "link.log"
    link.symlink_to("/etc/passwd")
    assert run_action("truncate_log_file", {"path": str(link)}).outcome == "BLOCKED"


# ── dry run and real execution ────────────────────────────────────────────────
def test_dry_run_is_default_and_changes_nothing(sleeper):
    before = os.getpriority(os.PRIO_PROCESS, sleeper.pid)
    r = run_action("renice_process", {"pid": sleeper.pid, "nice_value": 7})
    assert r.outcome == "DRY_RUN" and "would" in r.detail
    assert os.getpriority(os.PRIO_PROCESS, sleeper.pid) == before


def test_renice_real_and_rollback_info(sleeper):
    before = os.getpriority(os.PRIO_PROCESS, sleeper.pid)
    r = run_action("renice_process", {"pid": sleeper.pid, "nice_value": before + 5}, dry_run=False)
    assert r.outcome == "SUCCESS"
    assert os.getpriority(os.PRIO_PROCESS, sleeper.pid) == before + 5
    assert r.rollback == {"action_id": "renice_process", "params": {"pid": sleeper.pid, "nice_value": before}}


def test_sigterm_real(sleeper):
    r = run_action("kill_process_sigterm", {"pid": sleeper.pid, "reason": "test"}, dry_run=False)
    assert r.outcome == "SUCCESS" and "exited" in r.detail
    assert sleeper.wait(timeout=5) == -15


def test_sigkill_real(sleeper):
    assert run_action("kill_process_sigkill", {"pid": sleeper.pid}, dry_run=False).outcome == "SUCCESS"
    assert sleeper.wait(timeout=5) == -9


def test_truncate_and_delete_real(tmp_path):
    f = tmp_path / "app.log"
    f.write_text("a" * 1000)
    assert run_action("truncate_log_file", {"path": str(f)}, dry_run=False).outcome == "SUCCESS"
    assert f.stat().st_size == 0
    f.write_text("b" * 10)
    assert run_action("delete_file", {"path": str(f)}, dry_run=False).outcome == "SUCCESS"
    assert not f.exists()


def test_delete_respects_size_cap(tmp_path):
    f = tmp_path / "big.log"
    f.write_bytes(b"x" * 2 * 1048576)
    r = run_action("delete_file", {"path": str(f), "max_size_mb": 1}, dry_run=False)
    assert r.outcome == "FAILED" and f.exists()


def test_failed_execution_is_reported_not_raised(sleeper):
    sleeper.kill()
    sleeper.wait()
    r = run_action("renice_process", {"pid": sleeper.pid, "nice_value": 5}, dry_run=False)
    assert r.outcome in ("BLOCKED", "FAILED")      # gone: blocked as 'does not exist'


# ── planner ───────────────────────────────────────────────────────────────────
def test_planner_orders_by_risk_and_uses_culprit():
    d = Diagnosis("cpu_exhaustion", "hog is saturating CPU", "medium", [], {"pid": 4242, "name": "hog"})
    props = plan(d, check=lambda pid: None)
    assert [p.action_id for p in props] == ["renice_process", "kill_process_sigterm"]
    assert props[0].risk == "Low" and props[1].risk == "Medium"
    assert all(p.params["pid"] == 4242 for p in props)


def test_planner_marks_protected_targets_blocked_and_last():
    d = Diagnosis("zombie_processes", "parent not reaping", "high", [], {"pid": 1, "name": "parent"})
    props = plan(d)                                        # real guard: pid 1 is forbidden
    assert props and props[0].blocked_reason


def test_planner_disk_and_unknown():
    assert plan(Diagnosis("disk_full", "full", "medium", []))[0].action_id == "run_journalctl_vacuum"
    assert plan(Diagnosis("inode_exhaustion", "x", "medium", [])) == []