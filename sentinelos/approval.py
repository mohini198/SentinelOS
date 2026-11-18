"""Helpers for the human approval CLI: find incidents, rebuild diagnosis + proposals, render them."""
from __future__ import annotations

from .actions import run_action
from .diagnosis import diagnose
from .models import Incident, make_engine, make_session_factory
from .planner import plan


def open_session(db_path):
    return make_session_factory(make_engine(db_path))()


def recent_incidents(session, limit: int = 15) -> list:
    return session.query(Incident).order_by(Incident.id.desc()).limit(limit).all()


def find_incident(session, ref: str):
    """ref = numeric id (e.g. 3) or a uuid prefix (e.g. e5ef7aa9)."""
    if ref.isdigit() and len(ref) < 8:
        return session.get(Incident, int(ref))
    return session.query(Incident).filter(Incident.uuid.startswith(ref)).first()


def build_review(inc):
    diag = diagnose(inc.get_raw_data())
    return diag, plan(diag)


def render_review(inc, diag, props) -> str:
    L = [f"Incident #{inc.id} ({inc.uuid[:8]}) [{inc.severity}] {inc.fault_type}, state {inc.state}",
         f"Summary: {inc.summary}",
         f"Root cause ({diag.confidence} confidence): {diag.root_cause}", "Evidence:"]
    L += [f"  - {e}" for e in diag.evidence]
    L.append("Proposed fixes:" if props else "No automatic fix proposed. Hints: " + "; ".join(diag.hints))
    for i, p in enumerate(props, 1):
        shown = {k: v for k, v in p.params.items() if k != "reason"}
        tag = f"   ** BLOCKED: {p.blocked_reason}" if p.blocked_reason else ""
        L.append(f"  [{i}] {p.action_id}  risk={p.risk}  {shown}{tag}")
        L.append(f"      why: {p.rationale} | effect: {p.expected_effect}")
        if not p.blocked_reason:
            r = run_action(p.action_id, p.params, dry_run=True)
            L.append(f"      preview: {r.outcome} - {r.detail}")
    return "\n".join(L)