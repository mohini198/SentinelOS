"""
pytest shared fixtures for SentinelOS tests.

Provides:
  - `tmp_db`      : path to a fresh in-memory/temp SQLite DB per test
  - `audit_log`   : AuditLog instance backed by tmp_db
  - `settings_obj`: fresh Settings loaded from real config YAMLs
"""

from __future__ import annotations

import pytest
from pathlib import Path

from sentinelos.audit import AuditLog
from sentinelos.models import make_engine, Base


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Return a path to a temporary SQLite database (deleted after test)."""
    db_file = tmp_path / "test_sentinel.db"
    # Trigger table creation
    engine = make_engine(db_file)
    engine.dispose()
    return db_file


@pytest.fixture
def audit_log(tmp_db: Path) -> AuditLog:
    """Return an AuditLog instance backed by the temp database."""
    return AuditLog(db_path=tmp_db)
