from sentinelos.config import ThresholdsConfig
from sentinelos.detector import Detector, Snapshot
from sentinelos.incident import build_bundle, save_incident
from sentinelos.models import Incident, make_engine, make_session_factory
from sentinelos.monitor import DiskUsage, FileNr, LoadAvg, MemInfo, ProcInfo, Psi, PsiLine

T = ThresholdsConfig()


def P(pid, state="S", fds=3, rss=100, ticks=10, name="p"):
    return ProcInfo(pid, name, state, 1, ticks, rss, fds, 0, 0)


def snap(avail_kb=4_000_000, cpu=10.0, psi=None, disks=None, fnr=None, procs=None, load1=0.1):
    mem = MemInfo(8_000_000, 1_000_000, avail_kb, 0, 0, 0, 0)
    return Snapshot(mem, cpu, LoadAvg(load1, 0, 0, 1, 100), psi or {}, disks or [], fnr, procs or [], 4)


def types(findings):
    return {f.fault_type for f in findings}


def test_healthy_system_no_findings():
    assert Detector(T).check(snap()) == []


def test_low_memory_is_critical():
    f = Detector(T).check(snap(avail_kb=100_000))
    assert f[0].fault_type == "memory_pressure" and f[0].severity == "CRITICAL"


def test_memory_psi_warning():
    psi = {"memory": Psi(PsiLine(25, 0, 0, 1), None)}
    f = Detector(T).check(snap(psi=psi))
    assert f[0].severity == "WARNING"


def test_cpu_needs_sustained_samples():
    d = Detector(T)
    assert d.check(snap(cpu=99)) == []
    assert d.check(snap(cpu=99)) == []
    f = d.check(snap(cpu=99))
    assert f[0].fault_type == "cpu_exhaustion" and f[0].severity == "CRITICAL"


def test_disk_and_inode():
    disk = DiskUsage("/", 100, 95, 95.0, 1000, 95.0)
    assert types(Detector(T).check(snap(disks=[disk]))) == {"disk_full", "inode_exhaustion"}


def test_zombies_warning_then_critical():
    assert Detector(T).check(snap(procs=[P(i, "Z") for i in range(6)]))[0].severity == "WARNING"
    assert Detector(T).check(snap(procs=[P(i, "Z") for i in range(25)]))[0].severity == "CRITICAL"


def test_dstate():
    f = Detector(T).check(snap(procs=[P(i, "D") for i in range(4)]))
    assert f[0].fault_type == "dstate_processes"


def test_fd_exhaustion_system_and_process():
    f = Detector(T).check(snap(fnr=FileNr(900, 0, 1000)))
    assert f[0].fault_type == "fd_exhaustion" and f[0].severity == "CRITICAL"
    f = Detector(T).check(snap(procs=[P(5, fds=950, name="leaky")]))
    assert "leaky" in f[0].summary


def test_cooldown_and_escalation():
    d = Detector(T, cooldown_s=100)
    assert d.check(snap(avail_kb=900_000), now=0)            # ~88% used -> WARNING
    assert d.check(snap(avail_kb=900_000), now=10) == []     # suppressed
    assert d.check(snap(avail_kb=100_000), now=20)           # escalated -> fires
    assert d.check(snap(avail_kb=100_000), now=30) == []
    assert d.check(snap(avail_kb=100_000), now=500)          # cooldown over


def test_bundle_ranking_and_save(tmp_path):
    procs = [P(1, rss=10, fds=1, ticks=5), P(2, rss=999, fds=2, ticks=1), P(3, rss=5, fds=80, ticks=900)]
    s = snap(avail_kb=100_000, procs=procs)
    f = Detector(T).check(s)[0]
    b = build_bundle(f, s, collect_logs=False)
    assert b["top_mem"][0]["pid"] == 2
    assert b["top_cpu"][0]["pid"] == 3
    assert b["top_fds"][0]["pid"] == 3
    assert "logs_untrusted" in b

    Session = make_session_factory(make_engine(tmp_path / "t.db"))
    with Session() as sess:
        inc = save_incident(sess, f, b)
        row = sess.get(Incident, inc.id)
        assert row.fault_type == "memory_pressure" and row.state == "OPEN"
        assert row.get_raw_data()["top_mem"][0]["pid"] == 2