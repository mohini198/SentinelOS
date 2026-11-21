"""
SentinelOS — SQLite database models (SQLAlchemy 2.x mapped dataclasses style).

Tables
------
incidents       — one row per detected failure event
audit_log       — append-only, hash-chained action audit trail
actions_taken   — links incidents to audit_log entries
"""

from __future__ import annotations

import datetime
import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

def utcnow() -> datetime.datetime:
    """Naive UTC, same storage format as before (keeps the audit hash chain valid)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

# ── Enums (kept as Python strings in DB for readability) ──────────────────────

class Severity(str, Enum):
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class IncidentState(str, Enum):
    OPEN = "OPEN"
    DIAGNOSING = "DIAGNOSING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTING = "EXECUTING"
    RESOLVED = "RESOLVED"
    ROLLED_BACK = "ROLLED_BACK"
    DISMISSED = "DISMISSED"


class RiskTier(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    FORBIDDEN = "Forbidden"


class ActionOutcome(str, Enum):
    DRY_RUN = "DRY_RUN"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    BLOCKED = "BLOCKED"


# ── ORM Base ──────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Tables ────────────────────────────────────────────────────────────────────

class Incident(Base):
    """One row per detected failure event."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)

    # What was detected
    fault_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default=Severity.WARNING)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)

    # Raw snapshot stored as JSON text
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Lifecycle
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, default=IncidentState.OPEN
    )
    detected_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow
    )
    resolved_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    actions: Mapped[list["AuditEntry"]] = relationship(
        "AuditEntry",
        secondary="actions_taken",
        back_populates="incidents",
        lazy="select",
    )

    def set_raw_data(self, data: dict) -> None:
        self.raw_data = json.dumps(data, default=str)

    def get_raw_data(self) -> dict:
        if self.raw_data:
            return json.loads(self.raw_data)
        return {}

    def __repr__(self) -> str:
        return f"<Incident id={self.id} type={self.fault_type} state={self.state}>"


class AuditEntry(Base):
    """
    Append-only, hash-chained audit log.

    Each row contains a SHA-256 hash of the previous row's hash + this row's
    content fields. This makes the log tamper-evident: if any row is modified
    or deleted, the chain breaks and verification will fail.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Action identity
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Parameters and context (JSON)
    params: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Who approved it
    approved_by: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Outcome
    outcome: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ActionOutcome.DRY_RUN
    )
    outcome_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timing
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.datetime.utcnow
    )

    # Hash chain fields
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # Relationships
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident",
        secondary="actions_taken",
        back_populates="actions",
        lazy="select",
    )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def set_params(self, data: dict) -> None:
        self.params = json.dumps(data, default=str)

    def get_params(self) -> dict:
        return json.loads(self.params) if self.params else {}

    def set_context(self, data: dict) -> None:
        self.context = json.dumps(data, default=str)

    def get_context(self) -> dict:
        return json.loads(self.context) if self.context else {}

    def compute_hash(self) -> str:
        """
        Compute SHA-256 over the canonical fields of this entry
        plus the previous entry's hash (or '0' * 64 for the first).
        """
        payload = "|".join([
            str(self.id),
            self.action_id,
            self.risk_tier,
            str(self.is_dry_run),
            self.params or "",
            self.approved_by or "",
            self.outcome,
            self.created_at.isoformat(),
            self.prev_hash or ("0" * 64),
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def seal(self, prev_hash: str | None) -> None:
        """Set prev_hash then compute and store entry_hash."""
        self.prev_hash = prev_hash
        self.entry_hash = self.compute_hash()

    def __repr__(self) -> str:
        return (
            f"<AuditEntry id={self.id} action={self.action_id} "
            f"outcome={self.outcome} dry_run={self.is_dry_run}>"
        )


class ActionsTaken(Base):
    """Junction table linking Incidents to AuditEntries (M:M)."""

    __tablename__ = "actions_taken"

    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    audit_entry_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("audit_log.id", ondelete="CASCADE"), primary_key=True
    )


# ── Database engine factory ───────────────────────────────────────────────────

def make_engine(db_path: str | Path = "sentinelos.db", echo: bool = False):
    """Create a SQLite engine with WAL mode and foreign key enforcement."""
    url = f"sqlite:///{db_path}"
    engine = create_engine(url, echo=echo, future=True)

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    Base.metadata.create_all(engine)
    return engine


def make_session_factory(engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
