"""
Tests for sentinelos.models — SQLAlchemy ORM layer.
"""

from __future__ import annotations

import datetime
import json
import uuid
from pathlib import Path

import pytest

from sentinelos.models import (
    ActionOutcome,
    ActionsTaken,
    AuditEntry,
    Base,
    Incident,
    IncidentState,
    RiskTier,
    Severity,
    make_engine,
    make_session_factory,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def session(tmp_path: Path):
    engine = make_engine(tmp_path / "test.db")
    Session = make_session_factory(engine)
    with Session() as sess:
        yield sess
    engine.dispose()


# ── Enum values ───────────────────────────────────────────────────────────────

class TestEnums:
    def test_severity_values(self):
        assert Severity.WARNING == "WARNING"
        assert Severity.CRITICAL == "CRITICAL"

    def test_incident_state_values(self):
        assert IncidentState.OPEN == "OPEN"
        assert IncidentState.RESOLVED == "RESOLVED"

    def test_risk_tier_values(self):
        assert RiskTier.LOW == "Low"
        assert RiskTier.FORBIDDEN == "Forbidden"

    def test_action_outcome_values(self):
        assert ActionOutcome.DRY_RUN == "DRY_RUN"
        assert ActionOutcome.SUCCESS == "SUCCESS"


# ── Incident ──────────────────────────────────────────────────────────────────

class TestIncident:
    def _make(self, session) -> Incident:
        inc = Incident(
            uuid=str(uuid.uuid4()),
            fault_type="memory_pressure",
            severity=Severity.CRITICAL,
            summary="RAM usage at 95%",
            state=IncidentState.OPEN,
            detected_at=datetime.datetime.utcnow(),
        )
        session.add(inc)
        session.flush()
        return inc

    def test_create_incident(self, session):
        inc = self._make(session)
        assert inc.id is not None
        assert inc.state == IncidentState.OPEN

    def test_set_and_get_raw_data(self, session):
        inc = self._make(session)
        payload = {"mem_used_pct": 95.3, "pid": 12345}
        inc.set_raw_data(payload)
        session.flush()
        assert inc.get_raw_data() == payload

    def test_raw_data_handles_non_serializable(self, session):
        inc = self._make(session)
        inc.set_raw_data({"ts": datetime.datetime(2024, 1, 1)})
        # Should not raise; datetime stringified by default=str
        data = inc.get_raw_data()
        assert "ts" in data

    def test_get_raw_data_empty(self, session):
        inc = self._make(session)
        assert inc.get_raw_data() == {}

    def test_uuid_is_unique(self, session):
        inc1 = self._make(session)
        inc2 = self._make(session)
        assert inc1.uuid != inc2.uuid

    def test_repr_contains_fault_type(self, session):
        inc = self._make(session)
        assert "memory_pressure" in repr(inc)

    def test_state_transition(self, session):
        inc = self._make(session)
        inc.state = IncidentState.RESOLVED
        inc.resolved_at = datetime.datetime.utcnow()
        session.flush()
        assert inc.state == IncidentState.RESOLVED
        assert inc.resolved_at is not None


# ── AuditEntry ────────────────────────────────────────────────────────────────

class TestAuditEntry:
    def _make(self, session, action_id: str = "drop_caches") -> AuditEntry:
        entry = AuditEntry(
            action_id=action_id,
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
            outcome=ActionOutcome.DRY_RUN,
            created_at=datetime.datetime.utcnow(),
        )
        session.add(entry)
        session.flush()
        return entry

    def test_create_audit_entry(self, session):
        entry = self._make(session)
        assert entry.id is not None
        assert entry.is_dry_run is True

    def test_set_and_get_params(self, session):
        entry = self._make(session)
        entry.set_params({"level": 1})
        session.flush()
        assert entry.get_params() == {"level": 1}

    def test_get_params_empty(self, session):
        entry = self._make(session)
        assert entry.get_params() == {}

    def test_set_and_get_context(self, session):
        entry = self._make(session)
        entry.set_context({"host": "ubuntu-vm"})
        session.flush()
        assert entry.get_context() == {"host": "ubuntu-vm"}

    def test_seal_computes_hash(self, session):
        entry = self._make(session)
        entry.seal(prev_hash=None)
        assert len(entry.entry_hash) == 64  # SHA-256 hex
        # seal(None) keeps prev_hash as None; genesis constant used inside compute_hash
        assert entry.prev_hash is None

    def test_seal_with_prev_hash(self, session):
        prev = "a" * 64
        entry = self._make(session)
        entry.seal(prev_hash=prev)
        assert entry.prev_hash == prev
        assert entry.entry_hash != ""
        assert entry.entry_hash != prev

    def test_hash_is_deterministic(self, session):
        entry = self._make(session)
        entry.seal(None)
        h1 = entry.compute_hash()
        h2 = entry.compute_hash()
        assert h1 == h2

    def test_different_actions_different_hashes(self, session):
        e1 = self._make(session, action_id="drop_caches")
        e2 = self._make(session, action_id="renice_process")
        e1.seal(None)
        e2.seal(None)
        assert e1.entry_hash != e2.entry_hash

    def test_repr_contains_action_id(self, session):
        entry = self._make(session)
        assert "drop_caches" in repr(entry)


# ── ActionsTaken (junction) ───────────────────────────────────────────────────

class TestActionsTaken:
    def test_link_incident_to_audit_entry(self, session):
        inc = Incident(
            uuid=str(uuid.uuid4()),
            fault_type="cpu_exhaustion",
            severity=Severity.WARNING,
            summary="CPU high",
            state=IncidentState.OPEN,
            detected_at=datetime.datetime.utcnow(),
        )
        session.add(inc)

        entry = AuditEntry(
            action_id="renice_process",
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
            outcome=ActionOutcome.DRY_RUN,
            created_at=datetime.datetime.utcnow(),
        )
        session.add(entry)
        session.flush()

        link = ActionsTaken(incident_id=inc.id, audit_entry_id=entry.id)
        session.add(link)
        session.flush()

        # Verify via raw query
        result = session.query(ActionsTaken).filter_by(incident_id=inc.id).first()
        assert result is not None
        assert result.audit_entry_id == entry.id


# ── make_engine ───────────────────────────────────────────────────────────────

class TestMakeEngine:
    def test_creates_all_tables(self, tmp_path):
        engine = make_engine(tmp_path / "schema_test.db")
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        assert "incidents" in tables
        assert "audit_log" in tables
        assert "actions_taken" in tables
        engine.dispose()

    def test_wal_mode_enabled(self, tmp_path):
        engine = make_engine(tmp_path / "wal_test.db")
        with engine.connect() as conn:
            result = conn.execute(
                __import__("sqlalchemy").text("PRAGMA journal_mode")
            )
            mode = result.scalar()
        assert mode == "wal"
        engine.dispose()

    def test_foreign_keys_enabled(self, tmp_path):
        engine = make_engine(tmp_path / "fk_test.db")
        with engine.connect() as conn:
            result = conn.execute(
                __import__("sqlalchemy").text("PRAGMA foreign_keys")
            )
            fk = result.scalar()
        assert fk == 1
        engine.dispose()
