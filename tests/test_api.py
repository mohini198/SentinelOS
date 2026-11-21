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