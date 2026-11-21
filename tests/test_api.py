import importlib

from fastapi.testclient import TestClient


def client(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_DEMO", "true")
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "d.db"))
    import sentinelos.api.app as m
    importlib.reload(m)
    return TestClient(m.app)


def test_demo_flow_is_dry_run_only(monkeypatch, tmp_path):
    c = client(monkeypatch, tmp_path)
    assert c.get("/api/info").json() == {"demo": True}
    rows = c.get("/api/incidents").json()
    assert len(rows) == 3
    mem = next(r for r in rows if r["fault_type"] == "memory_pressure")
    d = c.get(f"/api/incidents/{mem['id']}").json()
    assert d["proposals"] and not any(p["blocked_reason"] for p in d["proposals"])
    r = c.post(f"/api/incidents/{mem['id']}/approve", json={"n": 2, "by": "tester"}).json()
    assert r["outcome"] == "DRY_RUN" and "demo" in r["detail"]
    a = c.get("/api/audit").json()
    assert a["chain_ok"] and a["entries"][0]["dry"] is True


def test_bad_input_rejected(monkeypatch, tmp_path):
    c = client(monkeypatch, tmp_path)
    assert c.post("/api/incidents/1/approve", json={"n": 0, "by": "x"}).status_code == 422
    assert c.post("/api/incidents/1/approve", json={"n": 99, "by": "x"}).status_code == 422   # schema cap
    assert c.post("/api/incidents/1/approve", json={"n": 15, "by": "x"}).status_code == 400   # more than proposals
    assert c.get("/api/incidents/9999").status_code == 404

def test_system_thresholds_timeline_filters(monkeypatch, tmp_path):
    c = client(monkeypatch, tmp_path)
    s = c.get("/api/system").json()
    for k in ("mode", "cpu_pct", "mem_used_pct", "swap_used_pct", "load1", "psi_mem_some",
              "fd_used_pct", "disks", "zombie_count"):
        assert k in s
    assert s["mode"] == "DEMO" and isinstance(s["cpu_pct"], float)
    assert c.get("/api/thresholds").json()["memory"]["used_percent_critical"] > 0
    assert c.get("/api/audit/verify").json()["ok"] is True
    rows = c.get("/api/incidents?severity=critical&fault_type=zombie_processes").json()
    assert len(rows) == 1 and rows[0]["fault_type"] == "zombie_processes"
    assert c.get("/api/incidents?state=resolved").json() == []
    inc = c.get(f"/api/incidents/{rows[0]['id']}").json()
    assert inc["timeline"][0]["step"] == "Detected"
    c.post(f"/api/incidents/{rows[0]['id']}/approve", json={"n": 1, "by": "t"})
    tl = c.get(f"/api/incidents/{rows[0]['id']}").json()["timeline"]
    assert tl[-1]["dry_run"] is True
