#!/bin/bash
# Keeps openclaw npm package inside the container at the latest published version.
# Runs idempotently: no-op when already current, upgrade + restart otherwise.
# Config preservation across the restart is handled by fix-proxy-cron.sh.

set -u

CONTAINER="openclaw-iar7-openclaw-1"
LOG="/docker/openclaw-iar7/ensure-latest.log"
LOCK="/tmp/openclaw-ensure-latest.lock"

log() { echo "$(date -Iseconds) $*" >> "$LOG"; }

exec 9>"$LOCK"
flock -n 9 || { log "skip: another run is in progress"; exit 0; }

docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$" || {
  log "skip: container not running"
  exit 0
}

CURRENT=$(docker exec "$CONTAINER" openclaw --version 2>/dev/null | awk '{print $2}')
LATEST=$(docker exec "$CONTAINER" npm view openclaw version 2>/dev/null | tr -d '[:space:]')

if [ -z "$CURRENT" ] || [ -z "$LATEST" ]; then
  log "skip: unresolved versions current='$CURRENT' latest='$LATEST'"
  exit 0
fi

if [ "$CURRENT" = "$LATEST" ]; then
  exit 0
fi

log "upgrade openclaw $CURRENT -> $LATEST"

if ! docker exec -u 1000 "$CONTAINER" npm install -g openclaw@latest >>"$LOG" 2>&1; then
  log "ERROR: npm install failed, aborting restart"
  exit 1
fi

log "restarting container to load new binary"
docker restart "$CONTAINER" >>"$LOG" 2>&1

for i in $(seq 1 60); do
  if docker exec "$CONTAINER" pgrep -f openclaw-gateway >/dev/null 2>&1; then
    NEW=$(docker exec "$CONTAINER" openclaw --version 2>/dev/null | awk '{print $2}')
    log "gateway ready after $((i*2))s, version=$NEW"
    exit 0
  fi
  sleep 2
done

log "WARN: gateway did not come up within 120s"
exit 1
