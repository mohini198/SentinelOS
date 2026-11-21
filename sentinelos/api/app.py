"""Dashboard backend. SAFETY: this API can only DRY-RUN. Real execution exists only in the CLI."""
from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ..actions import ActionResult
from ..actions.library import IMPLS
from ..audit import AuditLog
from ..config import settings
from ..diagnosis import diagnose
from ..executor import Executor
from ..models import Incident, make_engine, make_session_factory
from ..planner import plan
from .seed import seed_demo
from .. import llm
from ..diagnosis.concepts import CONCEPTS

DEMO = os.environ.get("SENTINEL_DEMO", "").lower() in ("1", "true", "yes")
DB = os.environ.get("SENTINEL_DB_PATH", "demo.db" if DEMO else str(settings.db_path))

app = FastAPI(title="SentinelOS dashboard")
Session = make_session_factory(make_engine(DB))
if DEMO:
    seed_demo(Session)

_hits: deque = deque()          # crude global rate limit for the public demo


def _limit(per_min: int = 30) -> None:
    now = time.time()
    while _hits and now - _hits[0] > 60:
        _hits.popleft()
    if len(_hits) >= per_min:
        raise HTTPException(429, "too many requests, slow down")
    _hits.append(now)


def _load(iid: int):
    with Session() as s:
        inc = s.get(Incident, iid)
    if inc is None:
        raise HTTPException(404, "incident not found")
    diag = diagnose(inc.get_raw_data())
    props = plan(diag, check=lambda pid: None) if DEMO else plan(diag)
    return inc, diag, props


def _demo_runner(action_id, params, dry_run=True, **kw):
    return ActionResult(action_id, "DRY_RUN", "(demo) would " + IMPLS[action_id].describe(params), None, None)


@app.get("/api/info")
def info():
    return {"demo": DEMO}


@app.get("/api/incidents")
def incidents():
    with Session() as s:
        rows = s.query(Incident).order_by(Incident.id.desc()).limit(50).all()
    return [{"id": r.id, "uuid": r.uuid[:8], "severity": r.severity, "state": r.state,
             "fault_type": r.fault_type, "summary": r.summary,
             "detected_at": r.detected_at.isoformat()} for r in rows]


@app.get("/api/incidents/{iid}")
def incident(iid: int):
    inc, diag, props = _load(iid)
    logs = inc.get_raw_data().get("logs_untrusted", {})
    return {"id": inc.id, "severity": inc.severity, "state": inc.state, "fault_type": inc.fault_type,
            "summary": inc.summary, "diagnosis": asdict(diag),
            "proposals": [asdict(p) for p in props], "logs_untrusted": logs}


class Approval(BaseModel):
    n: int = Field(ge=1, le=20)
    by: str = Field(min_length=1, max_length=40)


@app.post("/api/incidents/{iid}/approve")
def approve(iid: int, body: Approval):
    _limit()
    inc, diag, props = _load(iid)
    if body.n > len(props):
        raise HTTPException(400, f"choose 1..{len(props)}")
    name = (diag.culprit or {}).get("name", "?")
    kw = {"runner": _demo_runner, "lookup": lambda pid: SimpleNamespace(name=name)} if DEMO else {}
    ex = Executor(DB, dry_run_default=True, **kw)
    res = ex.execute(inc, props[body.n - 1], body.by.strip(), real=False)    # never real from the web
    return {"outcome": res.outcome, "detail": res.detail,
            "note": "dashboard is dry-run only; real execution requires the CLI"}


@app.get("/api/audit")
def audit():
    log = AuditLog(DB)
    ok, msg = log.verify_chain()
    rows = [{"id": e.id, "time": e.created_at.isoformat(timespec="seconds"), "action": e.action_id,
             "risk": e.risk_tier, "outcome": e.outcome, "by": e.approved_by, "dry": e.is_dry_run,
             "detail": (e.outcome_detail or "")[:120]} for e in log.get_entries(50)]
    return {"chain_ok": ok, "chain_msg": msg, "entries": rows}


@app.get("/", response_class=HTMLResponse)
def home():
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")