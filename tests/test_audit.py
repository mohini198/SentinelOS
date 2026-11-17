"""
Tests for sentinelos.audit — hash-chained, append-only audit log.

Covers:
  - Appending entries
  - Hash chain correctness (genesis hash, prev_hash linkage)
  - verify_chain() on empty, valid, and tampered logs
  - Multiple sequential appends maintain chain
  - get_entries() filtering and ordering
  - count()
  - Idempotent repeated verify_chain calls
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinelos.audit import GENESIS_HASH, AuditLog
from sentinelos.models import ActionOutcome, AuditEntry, RiskTier, make_engine, make_session_factory


# ── Basic append ──────────────────────────────────────────────────────────────

class TestAppend:
    def test_append_returns_audit_entry(self, audit_log: AuditLog):
        entry = audit_log.append(
            action_id="drop_caches",
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
        )
        assert isinstance(entry, AuditEntry)
        assert entry.id is not None
        assert entry.action_id == "drop_caches"

    def test_first_entry_uses_genesis_prev_hash(self, audit_log: AuditLog):
        entry = audit_log.append(
            action_id="drop_caches",
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
        )
        assert entry.prev_hash == GENESIS_HASH

    def test_entry_hash_is_64_chars(self, audit_log: AuditLog):
        entry = audit_log.append(
            action_id="drop_caches",
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
        )
        assert len(entry.entry_hash) == 64

    def test_append_stores_params(self, audit_log: AuditLog):
        params = {"level": 2}
        entry = audit_log.append(
            action_id="drop_caches",
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
            params=params,
        )
        assert entry.get_params() == params

    def test_append_stores_context(self, audit_log: AuditLog):
        ctx = {"host": "ubuntu-vm-01", "triggered_by": "monitor"}
        entry = audit_log.append(
            action_id="drop_caches",
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
            context=ctx,
        )
        assert entry.get_context() == ctx

    def test_append_stores_approved_by(self, audit_log: AuditLog):
        entry = audit_log.append(
            action_id="kill_process_sigterm",
            risk_tier=RiskTier.MEDIUM,
            is_dry_run=False,
            approved_by="admin@localhost",
            outcome=ActionOutcome.SUCCESS,
        )
        assert entry.approved_by == "admin@localhost"
        assert entry.outcome == ActionOutcome.SUCCESS

    def test_append_stores_outcome_detail(self, audit_log: AuditLog):
        detail = "Process 1234 terminated successfully"
        entry = audit_log.append(
            action_id="kill_process_sigterm",
            risk_tier=RiskTier.MEDIUM,
            is_dry_run=False,
            outcome=ActionOutcome.SUCCESS,
            outcome_detail=detail,
        )
        assert entry.outcome_detail == detail

    def test_append_increments_count(self, audit_log: AuditLog):
        assert audit_log.count() == 0
        audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        assert audit_log.count() == 1
        audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        assert audit_log.count() == 2

    def test_append_with_incident_ids(self, tmp_db: Path):
        """AuditEntry should be linked to an Incident via ActionsTaken."""
        from sentinelos.models import Incident, IncidentState, Severity
        import datetime, uuid

        engine = make_engine(tmp_db)
        Session = make_session_factory(engine)

        # Create an incident first
        with Session() as sess:
            with sess.begin():
                inc = Incident(
                    uuid=str(uuid.uuid4()),
                    fault_type="disk_full",
                    severity=Severity.CRITICAL,
                    summary="/ at 92%",
                    state=IncidentState.OPEN,
                    detected_at=datetime.datetime.utcnow(),
                )
                sess.add(inc)
                sess.flush()
                inc_id = inc.id

        audit_log = AuditLog(db_path=tmp_db)
        entry = audit_log.append(
            action_id="run_journalctl_vacuum",
            risk_tier=RiskTier.LOW,
            is_dry_run=True,
            incident_ids=[inc_id],
        )
        assert entry.id is not None

        # Verify the link exists
        with Session() as sess:
            from sentinelos.models import ActionsTaken
            link = sess.query(ActionsTaken).filter_by(incident_id=inc_id).first()
            assert link is not None
            assert link.audit_entry_id == entry.id

        engine.dispose()


# ── Hash chain ────────────────────────────────────────────────────────────────

class TestHashChain:
    def test_second_entry_prev_hash_equals_first_entry_hash(self, audit_log: AuditLog):
        e1 = audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        e2 = audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        assert e2.prev_hash == e1.entry_hash

    def test_chain_links_across_multiple_appends(self, audit_log: AuditLog):
        entries = []
        for _ in range(5):
            e = audit_log.append(
                action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True
            )
            entries.append(e)

        for i in range(1, len(entries)):
            assert entries[i].prev_hash == entries[i - 1].entry_hash

    def test_different_actions_produce_different_hashes(self, audit_log: AuditLog):
        e1 = audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        e2 = audit_log.append(action_id="renice_process", risk_tier=RiskTier.LOW, is_dry_run=True)
        assert e1.entry_hash != e2.entry_hash


# ── verify_chain ──────────────────────────────────────────────────────────────

class TestVerifyChain:
    def test_empty_log_is_valid(self, audit_log: AuditLog):
        ok, msg = audit_log.verify_chain()
        assert ok is True
        assert "empty" in msg.lower()

    def test_single_entry_valid(self, audit_log: AuditLog):
        audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        ok, msg = audit_log.verify_chain()
        assert ok is True

    def test_multiple_entries_valid(self, audit_log: AuditLog):
        for _ in range(10):
            audit_log.append(
                action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True
            )
        ok, msg = audit_log.verify_chain()
        assert ok is True
        assert "10 entries" in msg

    def test_tampered_entry_hash_detected(self, tmp_db: Path):
        """Directly modify an entry's hash → verify_chain must detect it."""
        log = AuditLog(db_path=tmp_db)
        log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)

        # Tamper with the first entry
        engine = make_engine(tmp_db)
        Session = make_session_factory(engine)
        with Session() as sess:
            with sess.begin():
                first = sess.query(AuditEntry).order_by(AuditEntry.id).first()
                first.entry_hash = "deadbeef" * 8  # 64 chars but wrong
        engine.dispose()

        ok, msg = log.verify_chain()
        assert ok is False

    def test_tampered_prev_hash_detected(self, tmp_db: Path):
        """Directly modify prev_hash → verify_chain must detect it."""
        log = AuditLog(db_path=tmp_db)
        log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        log.append(action_id="renice_process", risk_tier=RiskTier.LOW, is_dry_run=True)

        engine = make_engine(tmp_db)
        Session = make_session_factory(engine)
        with Session() as sess:
            with sess.begin():
                second = (
                    sess.query(AuditEntry).order_by(AuditEntry.id.desc()).first()
                )
                second.prev_hash = "cafebabe" * 8  # corrupt prev_hash
        engine.dispose()

        ok, msg = log.verify_chain()
        assert ok is False

    def test_verify_chain_idempotent(self, audit_log: AuditLog):
        """Calling verify_chain multiple times on the same log returns consistent results."""
        for _ in range(3):
            audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)

        r1 = audit_log.verify_chain()
        r2 = audit_log.verify_chain()
        assert r1 == r2


# ── get_entries ───────────────────────────────────────────────────────────────

class TestGetEntries:
    def test_get_entries_empty(self, audit_log: AuditLog):
        entries = audit_log.get_entries()
        assert entries == []

    def test_get_entries_returns_newest_first(self, audit_log: AuditLog):
        ids = []
        for _ in range(5):
            e = audit_log.append(
                action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True
            )
            ids.append(e.id)

        entries = audit_log.get_entries()
        returned_ids = [e.id for e in entries]
        assert returned_ids == list(reversed(ids))

    def test_get_entries_limit(self, audit_log: AuditLog):
        for _ in range(10):
            audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        entries = audit_log.get_entries(limit=3)
        assert len(entries) == 3

    def test_get_entries_offset(self, audit_log: AuditLog):
        ids = []
        for _ in range(5):
            e = audit_log.append(
                action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True
            )
            ids.append(e.id)

        entries = audit_log.get_entries(offset=2, limit=10)
        assert len(entries) == 3  # 5 total, skip 2 newest

    def test_get_entries_filter_by_action_id(self, audit_log: AuditLog):
        audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
        audit_log.append(action_id="renice_process", risk_tier=RiskTier.LOW, is_dry_run=True)
        audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)

        entries = audit_log.get_entries(action_id="drop_caches")
        assert all(e.action_id == "drop_caches" for e in entries)
        assert len(entries) == 2


# ── count ─────────────────────────────────────────────────────────────────────

class TestCount:
    def test_count_empty(self, audit_log: AuditLog):
        assert audit_log.count() == 0

    def test_count_after_appends(self, audit_log: AuditLog):
        for n in range(1, 6):
            audit_log.append(action_id="drop_caches", risk_tier=RiskTier.LOW, is_dry_run=True)
            assert audit_log.count() == n
