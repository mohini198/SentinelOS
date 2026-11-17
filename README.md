# SentinelOS

> AI-assisted Linux failure diagnosis and safe remediation agent for Ubuntu 22.04/24.04.

## Quick Start

```bash
# 1. Create a virtual environment
python3.11 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\Activate.ps1  # Windows (dev only)

# 2. Install in editable mode with dev extras
pip install -e ".[dev]"

# 3. Run the test suite
pytest

# 4. Verify the audit log on a live DB
sentinelos audit-verify --db sentinelos.db
```

## Project Structure

```
sentinelos/
├── config/
│   ├── thresholds.yaml          # Detection thresholds (tunable)
│   ├── protected_processes.yaml # Forbidden processes (never touched)
│   └── allowlist.yaml           # Fixed action allowlist with risk tiers
├── sentinelos/
│   ├── config.py    # Pydantic settings loader
│   ├── models.py    # SQLAlchemy ORM (Incident, AuditEntry)
│   ├── audit.py     # Hash-chained, append-only audit log
│   ├── main.py      # Typer CLI entry point
│   ├── monitor.py   # (Step 2)
│   ├── detector.py  # (Step 3)
│   ├── incident.py  # (Step 3)
│   ├── diagnosis.py # (Step 5)
│   ├── planner.py   # (Step 6)
│   ├── actions.py   # (Step 6)
│   ├── approval.py  # (Step 7)
│   ├── executor.py  # (Step 7)
│   └── api.py       # (Step 10)
├── native/          # C component (Step 11)
├── dashboard/       # Web UI (Step 10)
├── faults/          # Fault injection scripts (Step 4)
├── tests/
│   ├── conftest.py
│   ├── test_config.py
│   ├── test_models.py
│   └── test_audit.py
├── docs/
└── pyproject.toml
```

## Safety Rules

| Risk Tier | Requires |
|-----------|----------|
| Low       | Auto-approved in supervised mode |
| Medium    | Human confirmation (`y/n`) |
| High      | Typed confirmation (`YES I CONFIRM`) |
| Forbidden | **Always blocked** — never executed |

Dry-run mode is **on by default**. Set `SENTINEL_DRY_RUN=false` to enable live execution.
