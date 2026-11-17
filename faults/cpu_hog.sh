#!/usr/bin/env bash
# Burns all cores for N seconds (default 60), then stops by itself.
DUR=${1:-60}
N=$(nproc)
for _ in $(seq "$N"); do
  timeout "$DUR" sh -c 'while :; do :; done' &
done
echo "burning $N cores for ${DUR}s"
wait