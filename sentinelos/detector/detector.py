from __future__ import annotations

import time
from typing import Optional

from ..config import ThresholdsConfig, settings
from .rules import RANK, Finding, Snapshot, evaluate


class Detector:
    """Runs rules on each snapshot; suppresses repeats within `cooldown_s`
    unless the severity escalated."""

    def __init__(self, thresholds: Optional[ThresholdsConfig] = None, cooldown_s: float = 300.0):
        self.t = thresholds or settings.thresholds
        self.cooldown_s = cooldown_s
        self._cpu: list[float] = []
        self._last: dict[str, tuple[float, str]] = {}

    def check(self, snap: Snapshot, now: Optional[float] = None) -> list[Finding]:
        now = time.monotonic() if now is None else now
        if snap.cpu_pct is not None:
            self._cpu = (self._cpu + [snap.cpu_pct])[-50:]
        fired = []
        for f in evaluate(snap, self.t, self._cpu):
            prev = self._last.get(f.key)
            if prev:
                t0, sev0 = prev
                if now - t0 < self.cooldown_s and RANK[f.severity] <= RANK[sev0]:
                    continue
            self._last[f.key] = (now, f.severity)
            fired.append(f)
        return fired