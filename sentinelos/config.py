"""
SentinelOS — Configuration loader.

Loads and validates all YAML config files from the config/ directory.
Exposes a single `settings` singleton so every module can do:

    from sentinelos.config import settings
    threshold = settings.memory.used_percent_critical
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

# ── Locate config dir ──────────────────────────────────────────────────────────
_CONFIG_DIR = Path(os.environ.get("SENTINEL_CONFIG_DIR", Path(__file__).parent.parent / "config"))


def _load_yaml(filename: str) -> dict[str, Any]:
    """Read a YAML file from the config directory. Returns {} on missing file."""
    path = _CONFIG_DIR / filename
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ── Sub-models ─────────────────────────────────────────────────────────────────

class MemoryThresholds(BaseModel):
    used_percent_warning: float = 80.0
    used_percent_critical: float = 90.0
    available_mb_critical: int = 256
    psi_some_avg10_warning: float = 20.0
    psi_full_avg10_critical: float = 10.0


class CpuThresholds(BaseModel):
    used_percent_warning: float = 85.0
    used_percent_critical: float = 95.0
    sustained_samples: int = 3
    sample_interval_seconds: int = 5
    psi_some_avg10_warning: float = 50.0
    psi_full_avg10_critical: float = 30.0


class DiskThresholds(BaseModel):
    used_percent_warning: float = 80.0
    used_percent_critical: float = 90.0
    inode_used_percent_critical: float = 90.0
    monitored_mounts: list[str] = Field(default_factory=list)


class FdThresholds(BaseModel):
    system_fd_percent_critical: float = 85.0
    per_process_fd_warning: int = 500
    per_process_fd_critical: int = 900


class ProcessThresholds(BaseModel):
    zombie_count_warning: int = 5
    zombie_count_critical: int = 20
    dstate_count_warning: int = 3
    dstate_count_critical: int = 10
    crash_loop_count: int = 3
    crash_loop_window_seconds: int = 60


class MonitorConfig(BaseModel):
    poll_interval_seconds: int = 10
    incident_queue_size: int = 100


class ThresholdsConfig(BaseModel):
    memory: MemoryThresholds = Field(default_factory=MemoryThresholds)
    cpu: CpuThresholds = Field(default_factory=CpuThresholds)
    disk: DiskThresholds = Field(default_factory=DiskThresholds)
    file_descriptors: FdThresholds = Field(default_factory=FdThresholds)
    process: ProcessThresholds = Field(default_factory=ProcessThresholds)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)


class ProtectedProcessesConfig(BaseModel):
    forbidden_pids: list[int] = Field(default_factory=lambda: [1])
    forbidden_names: list[str] = Field(default_factory=list)
    forbidden_exe_prefixes: list[str] = Field(default_factory=list)
    protect_root_no_tty: bool = True


class ActionParam(BaseModel):
    type: str
    description: str = ""
    enum: list[Any] | None = None
    minimum: float | None = None
    maximum: float | None = None
    maxLength: int | None = None
    pattern: str | None = None


class AllowedAction(BaseModel):
    id: str
    description: str
    risk: str  # Low | Medium | High | Forbidden
    dry_run_safe: bool = True
    params: dict[str, dict[str, Any]] = Field(default_factory=dict)
    rollback_id: str | None = None

    @field_validator("risk")
    @classmethod
    def validate_risk(cls, v: str) -> str:
        allowed = {"Low", "Medium", "High", "Forbidden"}
        if v not in allowed:
            raise ValueError(f"risk must be one of {allowed}, got {v!r}")
        return v


class AllowlistConfig(BaseModel):
    actions: list[AllowedAction] = Field(default_factory=list)

    def get_action(self, action_id: str) -> AllowedAction | None:
        for a in self.actions:
            if a.id == action_id:
                return a
        return None


# ── Top-level Settings ─────────────────────────────────────────────────────────

class Settings(BaseModel):
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    protected: ProtectedProcessesConfig = Field(default_factory=ProtectedProcessesConfig)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)

    # Runtime flags
    dry_run: bool = Field(
        default_factory=lambda: os.environ.get("SENTINEL_DRY_RUN", "true").lower() != "false"
    )
    db_path: Path = Field(
        default_factory=lambda: Path(
            os.environ.get("SENTINEL_DB_PATH", "sentinelos.db")
        )
    )
    config_dir: Path = _CONFIG_DIR


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and return the global settings singleton (cached)."""
    thresholds_data = _load_yaml("thresholds.yaml")
    protected_data = _load_yaml("protected_processes.yaml")
    allowlist_data = _load_yaml("allowlist.yaml")

    return Settings(
        thresholds=ThresholdsConfig.model_validate(thresholds_data),
        protected=ProtectedProcessesConfig.model_validate(protected_data),
        allowlist=AllowlistConfig.model_validate(allowlist_data),
    )


# Convenience singleton — import this everywhere
settings: Settings = get_settings()
