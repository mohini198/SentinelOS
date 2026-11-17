"""Opens files without closing them. Stops at --max-fds or --max-seconds."""
import argparse
import time

ap = argparse.ArgumentParser()
ap.add_argument("--max-fds", type=int, default=1000)
ap.add_argument("--max-seconds", type=int, default=90)
a = ap.parse_args()

held, start = [], time.time()
try:
    while len(held) < a.max_fds and time.time() - start < a.max_seconds:
        held.append(open("/dev/null"))
        if len(held) % 100 == 0:
            print(f"{len(held)} fds open", flush=True)
        time.sleep(0.01)
except OSError as e:
    print("hit limit:", e)
print("holding 20s then exiting", flush=True)
time.sleep(20)