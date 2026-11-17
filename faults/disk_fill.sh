#!/usr/bin/env bash
# Writes a capped file into a TEMP dir only. Not a real disk-full; use a small tmpfs for that.
SIZE_MB=${1:-200}
DIR=$(mktemp -d /tmp/sentinel_fill.XXXXXX)
[ "$SIZE_MB" -gt 2000 ] && SIZE_MB=2000
dd if=/dev/zero of="$DIR/fill.bin" bs=1M count="$SIZE_MB" status=none
echo "wrote ${SIZE_MB}MB to $DIR, removing in 60s"
sleep 60
rm -rf "$DIR"