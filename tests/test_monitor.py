import os
import pytest

from sentinelos.monitor import (
    cpu_usage_pct, list_processes, read_all_psi, read_cpu_times, read_disk,
    read_file_nr, read_loadavg, read_meminfo, read_process, read_psi,
)


def w(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


MEMINFO = """MemTotal:       8000000 kB
MemFree:         500000 kB
MemAvailable:    800000 kB
Buffers:         100000 kB
Cached:         1000000 kB
SwapTotal:      2000000 kB
SwapFree:        500000 kB
"""


def test_meminfo(tmp_path):
    w(tmp_path / "meminfo", MEMINFO)
    m = read_meminfo(tmp_path)
    assert m.total_kb == 8000000
    assert m.available_pct == pytest.approx(10.0)
    assert m.swap_used_pct == pytest.approx(75.0)


def test_meminfo_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_meminfo(tmp_path)


def test_cpu_usage(tmp_path):
    w(tmp_path / "stat", "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 1 1 1\n")
    a = read_cpu_times(tmp_path)
    w(tmp_path / "stat", "cpu  200 0 200 900 0 0 0 0 0 0\n")
    b = read_cpu_times(tmp_path)
    # delta: busy 200, idle 100 -> 66.7%
    assert cpu_usage_pct(a, b) == pytest.approx(66.67, abs=0.1)
    assert cpu_usage_pct(a, a) == 0.0


def test_loadavg(tmp_path):
    w(tmp_path / "loadavg", "1.50 0.90 0.40 3/250 12345\n")
    la = read_loadavg(tmp_path)
    assert (la.load1, la.running, la.total_tasks) == (1.5, 3, 250)


def test_file_nr(tmp_path):
    w(tmp_path / "sys/fs/file-nr", "900\t0\t1000\n")
    f = read_file_nr(tmp_path)
    assert f.used_pct == pytest.approx(90.0)


PSI = ("some avg10=25.50 avg60=10.00 avg300=2.00 total=123456\n"
       "full avg10=5.00 avg60=1.00 avg300=0.10 total=999\n")


def test_psi(tmp_path):
    w(tmp_path / "pressure/memory", PSI)
    p = read_psi("memory", tmp_path)
    assert p.some.avg10 == 25.5
    assert p.full.total == 999


def test_psi_unavailable_returns_none(tmp_path):
    assert read_psi("memory", tmp_path) is None
    assert all(v is None for v in read_all_psi(tmp_path).values())


def test_psi_cpu_without_full(tmp_path):
    w(tmp_path / "pressure/cpu", "some avg10=1.00 avg60=1.00 avg300=1.00 total=5\n")
    p = read_psi("cpu", tmp_path)
    assert p.some is not None and p.full is None


def test_psi_bad_resource(tmp_path):
    with pytest.raises(ValueError):
        read_psi("gpu", tmp_path)


def make_proc(root, pid, comm="myproc", state="S", ppid=1, utime=70, stime=30,
              rss=2048, fds=3, oom=100, adj=0):
    d = root / str(pid)
    w(d / "stat", f"{pid} ({comm}) {state} {ppid} " + "0 " * 9 +
      f"{utime} {stime} 0 0 20 0 1 0 100 4096 10\n")
    w(d / "status", f"Name:\t{comm}\nVmRSS:\t{rss} kB\n")
    w(d / "cmdline", "python\x00app.py\x00")
    w(d / "oom_score", f"{oom}\n")
    w(d / "oom_score_adj", f"{adj}\n")
    (d / "fd").mkdir(exist_ok=True)
    for i in range(fds):
        (d / "fd" / str(i)).write_text("")


def test_read_process(tmp_path):
    make_proc(tmp_path, 123, state="D", utime=70, stime=30, rss=4096, fds=5, oom=300)
    p = read_process(123, tmp_path)
    assert p.name == "myproc" and p.state == "D"
    assert p.cpu_ticks == 100 and p.rss_kb == 4096
    assert p.num_fds == 5 and p.oom_score == 300
    assert p.cmdline == "python app.py"


def test_comm_with_spaces_and_parens(tmp_path):
    make_proc(tmp_path, 7, comm="tricky) (name", state="Z")
    p = read_process(7, tmp_path)
    assert p.name == "tricky) (name" and p.state == "Z"


def test_vanished_process_returns_none(tmp_path):
    assert read_process(999, tmp_path) is None


def test_list_processes_skips_non_pid_and_broken(tmp_path):
    make_proc(tmp_path, 1)
    make_proc(tmp_path, 2)
    (tmp_path / "meminfo").write_text("x")
    (tmp_path / "3").mkdir()  # pid dir with no stat (vanished)
    pids = sorted(p.pid for p in list_processes(tmp_path))
    assert pids == [1, 2]

@pytest.mark.skipif(not hasattr(os, "statvfs"), reason="statvfs needs Linux")
def test_disk_real_root():
    d = read_disk("/")
    assert 0 <= d.used_pct <= 100
    assert d.total_bytes > 0
    assert 0 <= d.inodes_used_pct <= 100