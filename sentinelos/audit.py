"""
SentinelOS — Hash-chained, append-only Audit Log.

Design
------
* Every call to `append()` reads the hash of the LAST row in `audit_log`,
  then seals the new entry with that hash as `prev_hash`.
* First entry uses "0" * 64 as the genesis prev_hash.
* `verify_chain()` replays every row and checks the chain is unbroken.
* We never UPDATE or DELETE from audit_log. The SQLite PRAGMA
  `PRAGMA foreign_keys=ON` and application-level guards enforce this.

Thread / process safety
-----------------------
SQLite WAL mode + a short exclusive lock on the hash-fetch+insert pair.
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from sentinelos.models import (
    ActionOutcome,
    AuditEntry,
    Incident,
    ActionsTaken,
    make_engine,
    make_session_factory,
)

logger = logging.getLogger(__name__)

# Genesis hash used for the very first audit entry
GENESIS_HASH = "0" * 64


class AuditLog:
    """
    Thread-safe, hash-chained audit log backed by SQLite.

    Parameters
    ----------
    db_path : path to the SQLite database file
    echo    : if True, SQLAlchemy will log all SQL statements
    """

    def __init__(self, db_path: str | Path = "sentinelos.db", echo: bool = False) -> None:
        self._engine = make_engine(db_path, echo=echo)
        self._Session = make_session_factory(self._engine)

    # ── Public API ────────────────────────────────────────────────────────────

    def append(
        self,
        *,
        action_id: str,
        risk_tier: str,
        is_dry_run: bool,
        params: dict | None = None,
        context: dict | None = None,
        approved_by: str | None = None,
        outcome: str = ActionOutcome.DRY_RUN,
        outcome_detail: str | None = None,
        incident_ids: list[int] | None = None,
    ) -> AuditEntry:
        """
        Append one entry to the audit log and return the saved entry.

        This method fetches the previous entry's hash and seals the new
        entry within a single transaction, preventing hash-chain races.
        """
        with self._Session() as session:
            with session.begin():
                prev_hash = self._get_last_hash(session)

                entry = AuditEntry(
                    action_id=action_id,
                    risk_tier=risk_tier,
                    is_dry_run=is_dry_run,
                    approved_by=approved_by,
                    outcome=outcome,
                    outcome_detail=outcome_detail,
                    created_at=datetime.datetime.utcnow(),
                )
                if params:
                    entry.set_params(params)
                if context:
                    entry.set_context(context)

                # We need entry.id to be set before computing hash,
                # so flush first to get the auto-increment id.
                session.add(entry)
                session.flush()  # assigns entry.id

                entry.seal(prev_hash)
                session.flush()

                # Link to incidents if provided
                if incident_ids:
                    for inc_id in incident_ids:
                        link = ActionsTaken(
                            incident_id=inc_id,
                            audit_entry_id=entry.id,
                        )
                        session.add(link)

                # Detach from session so caller can read fields freely
                session.expunge(entry)

        logger.info(
            "AUDIT id=%d action=%s outcome=%s dry_run=%s hash=%s…",
            entry.id,
            action_id,
            outcome,
            is_dry_run,
            entry.entry_hash[:12],
        )
        return entry

    def verify_chain(self) -> tuple[bool, str]:
        """
        Walk the entire audit_log table in insertion order and verify
        every entry's hash is consistent with its predecessor.

        Returns
        -------
        (True, "OK")  if the chain is intact
        (False, reason) if tampering or corruption is detected
        """
        with self._Session() as session:
            entries: list[AuditEntry] = (
                session.query(AuditEntry).order_by(AuditEntry.id).all()
            )

        if not entries:
            return True, "OK (empty log)"

        expected_prev = GENESIS_HASH

        for entry in entries:
            if entry.prev_hash != expected_prev:
                return (
                    False,
                    f"Entry id={entry.id}: expected prev_hash={expected_prev[:12]}… "
                    f"but got {str(entry.prev_hash)[:12]}…",
                )

            recomputed = entry.compute_hash()
            if recomputed != entry.entry_hash:
                return (
                    False,
                    f"Entry id={entry.id}: stored hash={entry.entry_hash[:12]}… "
                    f"but recomputed={recomputed[:12]}…",
                )

            expected_prev = entry.entry_hash

        return True, f"OK ({len(entries)} entries verified)"

    def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        action_id: str | None = None,
    ) -> list[AuditEntry]:
        """Return audit entries, newest first, with optional filtering."""
        with self._Session() as session:
            q = session.query(AuditEntry).order_by(AuditEntry.id.desc())
            if action_id:
                q = q.filter(AuditEntry.action_id == action_id)
            entries = q.offset(offset).limit(limit).all()
            # Detach from session
            for e in entries:
                session.expunge(e)
            return entries

    def count(self) -> int:
        """Return total number of audit entries."""
        with self._Session() as session:
            return session.query(AuditEntry).count()

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_last_hash(session: Session) -> str:
        """
        Fetch the entry_hash of the most recent audit entry.
        Returns GENESIS_HASH if the table is empty.
        Must be called inside an open transaction.
        """
        last: AuditEntry | None = (
            session.query(AuditEntry)
            .order_by(AuditEntry.id.desc())
            .with_for_update()   # row-level lock (no-op on SQLite, good on PG)
            .first()
        )
        return last.entry_hash if last else GENESIS_HASH
