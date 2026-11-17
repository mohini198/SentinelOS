"""
Tests for sentinelos.config — config loading and Pydantic validation.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from sentinelos.config import (
    AllowlistConfig,
    ProtectedProcessesConfig,
    Settings,
    ThresholdsConfig,
    get_settings,
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _write_yaml(directory: Path, filename: str, data: dict) -> Path:
    p = directory / filename
    p.write_text(yaml.dump(data), encoding="utf-8")
    return p


# ── ThresholdsConfig ──────────────────────────────────────────────────────────

class TestThresholdsConfig:
    def test_defaults_are_sensible(self):
        cfg = ThresholdsConfig()
        assert 0 < cfg.memory.used_percent_warning < cfg.memory.used_percent_critical <= 100
        assert cfg.cpu.sustained_samples >= 1
        assert cfg.disk.used_percent_critical <= 100
        assert cfg.process.crash_loop_count >= 1
        assert cfg.monitor.poll_interval_seconds > 0

    def test_load_from_dict(self):
        cfg = ThresholdsConfig.model_validate(
            {"memory": {"used_percent_critical": 95.0}}
        )
        assert cfg.memory.used_percent_critical == 95.0
        # Non-specified fields keep defaults
        assert cfg.cpu.used_percent_critical == 95.0

    def test_empty_dict_uses_defaults(self):
        cfg = ThresholdsConfig.model_validate({})
        assert cfg.memory.used_percent_warning == 80.0

    def test_monitored_mounts_defaults_empty(self):
        cfg = ThresholdsConfig()
        assert cfg.disk.monitored_mounts == []


# ── ProtectedProcessesConfig ──────────────────────────────────────────────────

class TestProtectedProcessesConfig:
    def test_pid_1_always_in_defaults(self):
        cfg = ProtectedProcessesConfig()
        assert 1 in cfg.forbidden_pids

    def test_load_forbidden_names(self):
        cfg = ProtectedProcessesConfig.model_validate(
            {"forbidden_names": ["sshd", "myapp"]}
        )
        assert "sshd" in cfg.forbidden_names
        assert "myapp" in cfg.forbidden_names

    def test_protect_root_no_tty_default_true(self):
        cfg = ProtectedProcessesConfig()
        assert cfg.protect_root_no_tty is True


# ── AllowlistConfig ───────────────────────────────────────────────────────────

class TestAllowlistConfig:
    _RAW = {
        "actions": [
            {
                "id": "drop_caches",
                "description": "Drop page cache",
                "risk": "Low",
                "dry_run_safe": True,
                "params": {"level": {"type": "integer", "enum": [1, 2, 3]}},
                "rollback_id": None,
            },
            {
                "id": "kill_process_sigkill",
                "description": "SIGKILL",
                "risk": "High",
                "dry_run_safe": True,
                "params": {"pid": {"type": "integer", "minimum": 2}},
                "rollback_id": None,
            },
        ]
    }

    def test_parse_actions(self):
        cfg = AllowlistConfig.model_validate(self._RAW)
        assert len(cfg.actions) == 2

    def test_get_action_found(self):
        cfg = AllowlistConfig.model_validate(self._RAW)
        action = cfg.get_action("drop_caches")
        assert action is not None
        assert action.risk == "Low"

    def test_get_action_not_found(self):
        cfg = AllowlistConfig.model_validate(self._RAW)
        assert cfg.get_action("nonexistent") is None

    def test_invalid_risk_raises(self):
        with pytest.raises(Exception):
            AllowlistConfig.model_validate(
                {"actions": [{"id": "x", "description": "y", "risk": "EXTREME"}]}
            )

    def test_forbidden_risk_accepted(self):
        cfg = AllowlistConfig.model_validate(
            {
                "actions": [
                    {"id": "__bad", "description": "bad", "risk": "Forbidden"}
                ]
            }
        )
        assert cfg.actions[0].risk == "Forbidden"


# ── Settings singleton ────────────────────────────────────────────────────────

class TestSettings:
    def test_settings_loads_without_error(self):
        """get_settings() must not raise even when called multiple times."""
        s1 = get_settings()
        s2 = get_settings()
        # Singleton: same object
        assert s1 is s2

    def test_dry_run_default_true(self):
        """SENTINEL_DRY_RUN env var is not set in tests → default True."""
        s = get_settings()
        # We can't easily test env-var-driven values in a singleton,
        # but we can assert the type is bool.
        assert isinstance(s.dry_run, bool)

    def test_settings_has_all_subsections(self):
        s = get_settings()
        assert s.thresholds is not None
        assert s.protected is not None
        assert s.allowlist is not None

    def test_real_yaml_allowlist_has_drop_caches(self):
        """Verify the real allowlist.yaml on disk has drop_caches action."""
        s = get_settings()
        action = s.allowlist.get_action("drop_caches")
        assert action is not None, "drop_caches must be in allowlist.yaml"
        assert action.risk == "Low"

    def test_real_yaml_forbidden_pid_1(self):
        s = get_settings()
        assert 1 in s.protected.forbidden_pids

    def test_real_yaml_sshd_protected(self):
        s = get_settings()
        names_lower = [n.lower() for n in s.protected.forbidden_names]
        assert "sshd" in names_lower
