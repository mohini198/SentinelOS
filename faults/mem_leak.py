"""Leaks memory in steps. Safety: stops at --max-mb or --max-seconds. Run in a VM."""
import argparse
import time

ap = argparse.ArgumentParser()
ap.add_argument("--max-mb", type=int, default=1500)
ap.add_argument("--step-mb", type=int, default=50)
ap.add_argument("--max-seconds", type=int, default=120)
a = ap.parse_args()

hold, start = [], time.time()
while len(hold) * a.step_mb < a.max_mb and time.time() - start < a.max_seconds:
    hold.append(bytearray(a.step_mb * 1024 * 1024))
    for i in range(0, len(hold[-1]), 4096):   # touch pages so they are really resident
        hold[-1][i] = 1
    print(f"leaked {len(hold) * a.step_mb} MB", flush=True)
    time.sleep(1)
print("cap reached, holding 20s then exiting", flush=True)
time.sleep(300)