"""Pressure Stall Information readers (/proc/pressure/{cpu,memory,io})."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .proc_reader import PROC, _read

RESOURCES = ("cpu", "memory", "io")


@dataclass
class PsiLine:
    avg10: float
    avg60: float
    avg300: float
    total: int


@dataclass
class Psi:
    some: Optional[PsiLine]
    full: Optional[PsiLine]


def _parse_line(line: str) -> PsiLine:
    kv = dict(tok.split("=") for tok in line.split()[1:])
    return PsiLine(float(kv["avg10"]), float(kv["avg60"]), float(kv["avg300"]), int(kv["total"]))


def read_psi(resource: str, proc: Path = PROC) -> Optional[Psi]:
    """Return Psi, or None if PSI is unavailable (disabled kernel / old VM)."""
    if resource not in RESOURCES:
        raise ValueError(f"unknown PSI resource: {resource}")
    text = _read(proc / "pressure" / resource)
    if not text:
        return None
    some = full = None
    for line in text.splitlines():
        try:
            if line.startswith("some"):
                some = _parse_line(line)
            elif line.startswith("full"):
                full = _parse_line(line)
        except (KeyError, ValueError):
            continue
    return Psi(some, full)


def read_all_psi(proc: Path = PROC) -> dict[str, Optional[Psi]]:
    return {r: read_psi(r, proc) for r in RESOURCES}