#!/usr/bin/env bash
# End-to-end test for the BFT manager + userspace data plane.
#
#   scripts/e2e.sh
#
# Requires docker (with sudo) and python3. No TUN or NET_ADMIN is used. Set
# NETP2P_E2E_KEEP=1 to keep the stack running after the script finishes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DOCKER=(sudo -n docker)
COMPOSE=("${DOCKER[@]}" compose -f docker-compose.test.yml --env-file deploy/compose.env)
IMAGE=netp2p-test:latest
RUN_DIR=deploy/run

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

status_field() {
  python3 - "$1" "$2" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))[sys.argv[2]])
PY
}

wait_status() {
  local file=$1 name=$2
  for _ in $(seq 1 90); do
    if [ -s "$file" ]; then return 0; fi
    sleep 1
  done
  printf 'timed out waiting for %s (%s)\n' "$name" "$file" >&2
  "${COMPOSE[@]}" logs --no-log-prefix "$name" | tail -30 >&2 || true
  return 1
}

probe() {
  local service=$1 source=$2 target=$3 timeout=$4
  "${COMPOSE[@]}" exec -T "$service" netp2p-probe \
    --packet-listen 127.0.0.1:51820 --source "$source" --target "$target" --timeout "$timeout"
}

cleanup() {
  if [ "${NETP2P_E2E_KEEP:-0}" = "1" ]; then
    printf '\nkeeping stack; stop with: sudo docker compose -f docker-compose.test.yml down -v\n'
    return
  fi
  "${COMPOSE[@]}" --profile quorum down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "generate deterministic seed"
mkdir -p "$RUN_DIR"
rm -f "$RUN_DIR"/*.json
go run ./cmd/netp2pd --role seedgen --config deploy/state.json

MANAGER1_PEER_ID="$(python3 - deploy/state.json <<'PY'
import json, sys
seed = json.load(open(sys.argv[1]))
print(next(m["peerId"] for m in seed["managers"] if m["id"] == "manager-1"))
PY
)"
echo "MANAGER1_PEER_ID=$MANAGER1_PEER_ID" > deploy/compose.env
echo "manager-1 peer id: $MANAGER1_PEER_ID"

log "build image"
"${DOCKER[@]}" build -t "$IMAGE" .

log "start managers and clients"
"${COMPOSE[@]}" up -d --force-recreate

wait_status "$RUN_DIR/client-a.json" client-a
wait_status "$RUN_DIR/client-b.json" client-b
A_IP="$(status_field "$RUN_DIR/client-a.json" overlayIP)"
B_IP="$(status_field "$RUN_DIR/client-b.json" overlayIP)"
echo "client-a overlayIP=$A_IP"
echo "client-b overlayIP=$B_IP"
[ "$A_IP" != "$B_IP" ] || fail "clients received the same overlay IP"

log "client-a -> client-b ICMP must be allowed"
allowed=0
for _ in $(seq 1 15); do
  if probe client-a "$A_IP" "$B_IP" 4s >/dev/null 2>&1; then allowed=1; break; fi
  sleep 1
done
[ "$allowed" = "1" ] || fail "A->B probe never succeeded"
echo "OK: A->B echo reply received"

log "client-b -> client-a ICMP must be denied"
if probe client-b "$B_IP" "$A_IP" 3s >/dev/null 2>&1; then
  fail "B->A probe succeeded despite deny policy"
fi
echo "OK: B->A probe denied"

log "quorum must certify a new peer with one manager down"
"${COMPOSE[@]}" stop manager-4 >/dev/null
"${COMPOSE[@]}" --profile quorum up -d client-c
wait_status "$RUN_DIR/client-c.json" client-c
C_IP="$(status_field "$RUN_DIR/client-c.json" overlayIP)"
C_HEIGHT="$(status_field "$RUN_DIR/client-c.json" height)"
echo "client-c overlayIP=$C_IP certified height=$C_HEIGHT"
[ "$C_HEIGHT" -ge 4 ] || fail "client-c certified height $C_HEIGHT, want >= 4"
echo "OK: three managers certified a new registration"

log "e2e passed"
