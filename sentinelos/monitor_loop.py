from __future__ import annotations

import json
import time

from .config import settings
from .detector import Collector, Detector
from .incident import build_bundle, save_incident
from .models import make_engine, make_session_factory


def run_monitor(interval: float = 2.0, cooldown: float = 60.0, once: bool = False,
                no_logs: bool = False) -> None:
    collector = Collector(settings.thresholds.disk.monitored_mounts or None)
    detector = Detector(settings.thresholds, cooldown_s=cooldown)
    Session = make_session_factory(make_engine(settings.db_path))
    print(f"SentinelOS monitor started (every {interval}s, Ctrl+C to stop)", flush=True)
    try:
        while True:
            snap = collector.snapshot()
            for f in detector.check(snap):
                bundle = build_bundle(f, snap, collect_logs=not no_logs)
                with Session() as sess:
                    inc = save_incident(sess, f, bundle)
                top = bundle["top_mem"][0] if bundle["top_mem"] else {}
                print(f"[{f.severity}] {f.fault_type}: {f.summary}  (incident {inc.uuid[:8]})", flush=True)
                print("   evidence:", json.dumps(f.evidence, default=str)[:200], flush=True)
                if f.fault_type == "memory_pressure" and top:
                    print(f"   top memory: {top['name']}[{top['pid']}] {top['rss_kb']//1024} MB", flush=True)
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nmonitor stopped")