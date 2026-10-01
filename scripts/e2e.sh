#!/usr/bin/env bash
# End-to-end test for the BFT manager + data plane.
#
#   scripts/e2e.sh                userspace UDP data plane only
#   scripts/e2e.sh --with-tun     also verify real kernel traffic through TUN
#   scripts/e2e.sh --with-exit    also verify subnet/exit routing (implies --with-tun)
#   scripts/e2e.sh --with-multihop force via-manager paths (implies --with-tun)
#   scripts/e2e.sh --with-quota   verify budget enforcement and usage history
#   scripts/e2e.sh --with-chaos   verify recovery after a manager restart
#
# Requires docker (with sudo) and python3. TUN mode additionally needs
# /dev/net/tun on the host and runs TUN clients with NET_ADMIN. Set
# NETP2P_E2E_KEEP=1 to keep the stack running after the script finishes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DOCKER=(sudo -n docker)
COMPOSE=("${DOCKER[@]}" compose -f docker-compose.test.yml --env-file deploy/compose.env)
IMAGE=netp2p-test:latest
RUN_DIR=deploy/run
WITH_TUN=0
WITH_EXIT=0
WITH_MULTIHOP=0
WITH_QUOTA=0
WITH_CHAOS=0
ADMIN_TOKEN=netp2p-admin-v0

for arg in "$@"; do
  case "$arg" in
    --with-tun) WITH_TUN=1 ;;
    --with-exit) WITH_TUN=1; WITH_EXIT=1 ;;
    --with-multihop) WITH_TUN=1; WITH_MULTIHOP=1 ;;
    --with-quota) WITH_QUOTA=1 ;;
    --with-chaos) WITH_CHAOS=1 ;;
    *) printf 'unknown flag: %s\nusage: e2e.sh [--with-tun|--with-exit|--with-multihop|--with-quota|--with-chaos]\n' "$arg" >&2; exit 2 ;;
  esac
done

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

wait_healthy() {
  local service=$1
  for _ in $(seq 1 30); do
    state="$("${COMPOSE[@]}" ps --format json "$service" 2>/dev/null | python3 -c 'import json,sys; value=sys.stdin.read().strip(); print(json.loads(value).get("Health","") if value else "")')"
    if [ "$state" = "healthy" ]; then return 0; fi
    sleep 1
  done
  printf '%s never became healthy\n' "$service" >&2
  return 1
}

admin_transition() {
  local action=$1 file=$2 attempt
  for attempt in $(seq 1 15); do
    if "${COMPOSE[@]}" --profile exit --profile multihop --profile quota --profile chaos exec -T admin-cli netp2pd \
      --role admin --manager "/dns4/manager-1/udp/4001/quic-v1/p2p/${MANAGER1_PEER_ID}" \
      --admin-token "$ADMIN_TOKEN" --action "$action" --file "$file"; then
      return 0
    fi
    sleep 2
  done
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
  profiles="--profile quorum"
  [ "$WITH_TUN" = "1" ] && profiles="$profiles --profile tun"
  [ "$WITH_EXIT" = "1" ] && profiles="$profiles --profile exit"
  [ "$WITH_MULTIHOP" = "1" ] && profiles="$profiles --profile multihop"
  [ "$WITH_QUOTA" = "1" ] && profiles="$profiles --profile quota"
  [ "$WITH_CHAOS" = "1" ] && profiles="$profiles --profile chaos"
  # shellcheck disable=SC2086
  "${COMPOSE[@]}" $profiles down -v --remove-orphans >/dev/null 2>&1 || true
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
start_profiles=""
[ "$WITH_TUN" = "1" ] && start_profiles="--profile tun"
[ "$WITH_EXIT" = "1" ] && start_profiles="$start_profiles --profile exit"
[ "$WITH_MULTIHOP" = "1" ] && start_profiles="$start_profiles --profile multihop"
[ "$WITH_QUOTA" = "1" ] && start_profiles="$start_profiles --profile quota"
[ "$WITH_CHAOS" = "1" ] && start_profiles="$start_profiles --profile chaos"
# shellcheck disable=SC2086
"${COMPOSE[@]}" $start_profiles up -d --force-recreate

wait_status "$RUN_DIR/client-a.json" client-a
wait_status "$RUN_DIR/client-b.json" client-b
A_TUN_IP=""
B_TUN_IP=""
if [ "$WITH_TUN" = "1" ]; then
  wait_status "$RUN_DIR/client-a-tun.json" client-a-tun
  wait_status "$RUN_DIR/client-b-tun.json" client-b-tun
  A_TUN_IP="$(status_field "$RUN_DIR/client-a-tun.json" overlayIP)"
  B_TUN_IP="$(status_field "$RUN_DIR/client-b-tun.json" overlayIP)"
  A_TUN_MODE="$(status_field "$RUN_DIR/client-a-tun.json" mode)"
  [ "$A_TUN_MODE" = "tun" ] || fail "client-a-tun reported mode=$A_TUN_MODE, want tun"
  for service in client-a-tun client-b-tun; do
    wait_healthy "$service" || fail "$service never became healthy"
  done
  echo "client-a-tun overlayIP=$A_TUN_IP ($A_TUN_MODE)"
  echo "client-b-tun overlayIP=$B_TUN_IP"
fi
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

if [ "$WITH_TUN" = "1" ]; then
  log "TUN: overlay DNS must resolve before kernel traffic uses peer routes"
  dns_ok=0
  for _ in $(seq 1 30); do
    resolved="$("${COMPOSE[@]}" exec -T client-a-tun getent hosts client-b-tun.netp2p.internal 2>/dev/null || true)"
    if [ -n "$resolved" ]; then
      dns_ok=1
      break
    fi
    sleep 1
  done
  [ "$dns_ok" = "1" ] || fail "client-a-tun never resolved client-b-tun.netp2p.internal"
  echo "OK: overlay DNS resolved ($resolved)"

  log "TUN: kernel ICMP must traverse the overlay"
  tun_ok=0
  for _ in $(seq 1 30); do
    if "${DOCKER[@]}" exec netp2p-client-a-tun-1 ping -c 1 -W 3 "$B_TUN_IP" >/dev/null 2>&1; then
      tun_ok=1
      break
    fi
    sleep 1
  done
  [ "$tun_ok" = "1" ] || fail "client-a-tun never pinged $B_TUN_IP via TUN"
  echo "OK: client-a-tun -> client-b-tun ICMP echo reply received"

  log "TUN: kernel TCP must follow the certified policy"
  # client-b-tun listens on the overlay address so client-a-tun can reach it
  # through the kernel's routing table (no userspace endpoint needed).
  "${DOCKER[@]}" exec -d netp2p-client-b-tun-1 sh -c "nc -l -s $B_TUN_IP -p 9999 >/dev/null 2>&1"
  tcp_ok=0
  for _ in $(seq 1 15); do
    if "${DOCKER[@]}" exec netp2p-client-a-tun-1 sh -c "echo netp2p-e2e | nc -w 3 $B_TUN_IP 9999" >/dev/null 2>&1; then
      tcp_ok=1
      break
    fi
    sleep 1
  done
  [ "$tcp_ok" = "1" ] || fail "client-a-tun never connected TCP to $B_TUN_IP:9999"
  echo "OK: client-a-tun -> client-b-tun TCP connection established"

  log "TUN: DNS must still forward names outside the overlay"
  external="$("${COMPOSE[@]}" exec -T client-a-tun getent hosts example.com 2>/dev/null | head -1 || true)"
  [ -n "$external" ] || fail "client-a-tun cannot forward external names after DNS takeover"
  echo "OK: forwarded DNS resolved through the TUN resolver ($external)"
fi

if [ "$WITH_EXIT" = "1" ]; then
  log "EXIT: promote client-exit-tun and certify a subnet route"
  wait_status "$RUN_DIR/client-exit-tun.json" client-exit-tun
  EXIT_PEER_ID="$(status_field "$RUN_DIR/client-exit-tun.json" peerID)"
  wait_healthy client-exit-tun
  echo "exit gateway peerID=$EXIT_PEER_ID"

  cat > deploy/exit-peer.json <<JSON
{"peerId":"$EXIT_PEER_ID","isExitNode":true}
JSON
  cat > deploy/exit-route.json <<'JSON'
{"id":"subnet-exit","destination":"198.18.0.0/24","routingGroup":"exit-gateways","distributionGroups":["clients-a"],"metric":10,"masquerade":true}
JSON

  admin_transition update-peer /config/exit-peer.json || fail "update-peer admin transition failed"
  admin_transition upsert-route /config/exit-route.json || fail "upsert-route admin transition failed"
  echo "OK: exit node promoted and subnet route certified"

  log "EXIT: source client must install the certified subnet route"
  route_ok=0
  for _ in $(seq 1 30); do
    if "${DOCKER[@]}" exec netp2p-client-a-tun-1 ip route show 198.18.0.0/24 2>/dev/null | grep -q netp2p0; then
      route_ok=1
      break
    fi
    sleep 1
  done
  [ "$route_ok" = "1" ] || fail "client-a-tun never installed the subnet route"
  echo "OK: client-a-tun routes 198.18.0.0/24 through netp2p0"

  log "EXIT: kernel traffic must reach the foreign subnet through the gateway"
  exit_ok=0
  for _ in $(seq 1 30); do
    if "${DOCKER[@]}" exec netp2p-client-a-tun-1 ping -c 1 -W 3 198.18.0.10 >/dev/null 2>&1; then
      exit_ok=1
      break
    fi
    sleep 1
  done
  [ "$exit_ok" = "1" ] || fail "client-a-tun never reached the subnet target via the exit node"
  echo "OK: subnet target reachable through the exit node"

  log "EXIT: the gateway must masquerade overlay sources"
  "${DOCKER[@]}" exec netp2p-client-exit-tun-1 iptables -t nat -S POSTROUTING | grep -q MASQUERADE \
    || fail "exit node did not install a MASQUERADE rule"
  echo "OK: gateway installed a MASQUERADE rule"
fi

log "quorum must certify a new peer with one manager down"
"${COMPOSE[@]}" stop manager-4 >/dev/null
"${COMPOSE[@]}" --profile quorum up -d client-c
wait_status "$RUN_DIR/client-c.json" client-c
C_IP="$(status_field "$RUN_DIR/client-c.json" overlayIP)"
C_HEIGHT="$(status_field "$RUN_DIR/client-c.json" height)"
echo "client-c overlayIP=$C_IP certified height=$C_HEIGHT"
[ "$C_HEIGHT" -ge 4 ] || fail "client-c certified height $C_HEIGHT, want >= 4"
echo "OK: three managers certified a new registration"

log "client status must report certified assignments and a live height"
python3 - "$RUN_DIR/client-a.json" <<'PY' || fail "client-a status missing assignment fields"
import json, sys
status = json.load(open(sys.argv[1]))
assert isinstance(status.get("assignments"), list), "assignments must be a list"
assert int(status.get("height", 0)) >= 2, f"height too low: {status.get('height')}"
for path in status["assignments"]:
    assert path.get("kind") in ("direct", "via_manager"), f"unexpected path kind {path.get('kind')}"
PY
echo "OK: client-a status carries certified assignment data"

log "manager metrics endpoint must be scrapable"
metrics=""
for _ in $(seq 1 20); do
  metrics="$(curl -fsS http://127.0.0.1:9100/metrics 2>/dev/null || true)"
  [ -n "$metrics" ] && break
  sleep 1
done
printf '%s' "$metrics" | grep -q 'netp2p_bft_height' || fail "metrics endpoint missing netp2p_bft_height"
printf '%s' "$metrics" | grep -q 'netp2p_forward' || fail "metrics endpoint missing forwarding metrics"
echo "OK: /metrics exposes BFT and forwarding metrics"

# fetch_settings merge <overrides-json> writes a full NetworkSettings record,
# because update_network_settings replaces the record wholesale.
fetch_settings() {
  local overrides=$1
  curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:8080/api/v1/snapshot \
    | python3 -c '
import json, sys
snapshot = json.load(sys.stdin)
settings = snapshot.get("state", {}).get("settings", {}) or {}
settings.update(json.loads(sys.argv[1]))
json.dump(settings, sys.stdout)
' "$overrides"
}

if [ "$WITH_MULTIHOP" = "1" ]; then
  log "MULTIHOP: force via-manager paths with two manager hops"
  fetch_settings '{"directPathEnabled": false, "viaManagerEnabled": true, "maxManagerHops": 2}' \
    > deploy/multihop-settings.json
  admin_transition update-settings /config/multihop-settings.json || fail "update-settings failed"
  echo "OK: certified settings disable direct paths and enable via-manager paths"

  multihop_ok=0
  for _ in $(seq 1 30); do
    if python3 - "$RUN_DIR/client-a-tun.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
kinds = {path.get("kind") for path in status.get("assignments", [])}
sys.exit(0 if kinds & {"via_manager", "multi_hop"} else 1)
PY
    then multihop_ok=1; break; fi
    sleep 1
  done
  [ "$multihop_ok" = "1" ] || fail "client-a-tun never received a via-manager assignment"
  echo "OK: planner produced a via-manager assignment under the new settings"

  if "${DOCKER[@]}" exec netp2p-client-a-tun-1 ping -c 2 -W 4 "$B_TUN_IP" >/dev/null 2>&1; then
    echo "OK: kernel traffic still reaches client-b-tun through the manager"
  else
    fail "client-a-tun could not reach $B_TUN_IP after forcing via-manager paths"
  fi
  forwarded="$(curl -fsS http://127.0.0.1:9100/metrics 2>/dev/null | grep '^netp2p_forward_forwarded_total' || true)"
  echo "OK: manager forwarding metrics: ${forwarded:-<none>}"
fi

if [ "$WITH_QUOTA" = "1" ]; then
  log "QUOTA: enforce a per-peer budget and rebuild usage history"
  A_PEER_ID="$(status_field "$RUN_DIR/client-a.json" peerID)"
  cat > deploy/quota-budget.json <<JSON
{"id":"quota-a","subjectType":"peer","subjectID":"$A_PEER_ID","dailyBytes":4096,"monthlyBytes":4096,"peakBps":0,"forwardingCostLimit":0,"onExhausted":"block"}
JSON
  admin_transition upsert-budget /config/quota-budget.json || fail "upsert-budget failed"
  fetch_settings '{"quotaEnforcementEnabled": true, "quotaReportIntervalSeconds": 5}' \
    > deploy/quota-settings.json
  admin_transition update-settings /config/quota-settings.json || fail "quota settings update failed"
  echo "OK: certified budget and enforcement settings committed"

  for _ in $(seq 1 20); do probe client-a "$A_IP" "$B_IP" 2s >/dev/null 2>&1 || true; sleep 1; done
  history_ok=0
  for _ in $(seq 1 30); do
    count="$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
      'http://127.0.0.1:8080/api/v1/quota/history?period=daily' 2>/dev/null \
      | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("entries", [])))' 2>/dev/null || echo 0)"
    if [ "${count:-0}" -gt 0 ]; then history_ok=1; break; fi
    sleep 2
  done
  [ "$history_ok" = "1" ] || fail "quota history stayed empty after traffic"
  echo "OK: quota history rebuilt from the decision log ($count entries)"
fi

if [ "$WITH_CHAOS" = "1" ]; then
  log "CHAOS: restart the failed manager and confirm the committee recovers"
  "${COMPOSE[@]}" start manager-4 >/dev/null
  sleep 5
  fetch_settings '{"loginExpirationDays": 30}' > deploy/chaos-settings.json
  admin_transition update-settings /config/chaos-settings.json \
    || fail "committee could not certify after manager-4 restarted"
  echo "OK: four managers certified again after the restart"
fi

log "e2e passed"
