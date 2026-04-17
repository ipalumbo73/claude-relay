#!/bin/bash
# Host cron wrapper for fix-proxy.py
# Runs every 2 minutes to keep OpenClaw config aligned after server.mjs rewrites.

set -u
CONTAINER="openclaw-iar7-openclaw-1"
LOG="/docker/openclaw-iar7/fix-proxy.log"

if ! docker ps --filter "name=${CONTAINER}" --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    exit 0
fi

OUT=$(docker exec "$CONTAINER" python3 /data/fix-proxy.py 2>&1)
RC=$?

chown -R 1000:1000 /docker/openclaw-iar7/data/.openclaw/ 2>/dev/null || true

if [ $RC -ne 0 ] || [ "$OUT" = "Fixed" ]; then
    echo "$(date -Iseconds) rc=$RC out=$OUT" >> "$LOG"
fi
