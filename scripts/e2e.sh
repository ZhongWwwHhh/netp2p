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

if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
  DOCKER=(docker)
else
  DOCKER=(sudo -n docker)
fi
COMPOSE=("${DOCKER[@]}" compose -f docker-compose.test.yml --env-file deploy/compose.env)
IMAGE=netp2p-test:latest
RUN_DIR=deploy/run
WITH_TUN=0
WITH_EXIT=0
WITH_MULTIHOP=0
WITH_QUOTA=0
WITH_CHAOS=0
ADMIN_TOKEN=netp2p-admin-v0
METRICS_URL="${NETP2P_METRICS_URL:-http://127.0.0.1:9100/metrics}"

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

mkdir -p "$RUN_DIR"
exec 9>"$RUN_DIR/e2e.lock"
if ! flock -n 9; then
  fail "another e2e run already owns $RUN_DIR/e2e.lock"
fi

status_field() {
  python3 - "$1" "$2" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))[sys.argv[2]])
PY
}

metric_value() {
  curl -fsS "$METRICS_URL" 2>/dev/null | awk -v key="$1" '$1 == key { print $2; exit }'
}

wait_metric_above() {
  local key=$1 before=$2 value attempt
  for attempt in $(seq 1 50); do
    value="$(metric_value "$key" || true)"
    value="${value:-0}"
    if awk -v before="$before" -v value="$value" 'BEGIN { exit !(value > before) }'; then
      printf '%s\n' "$value"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_status() {
  local file=$1 name=$2
  # Windows Docker's first run after image creation can take longer than the
  # client's bounded login retries before the committee becomes dialable.
  for _ in $(seq 1 180); do
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

# admin_query runs a read-only inspection over the authenticated admin
# protocol. The manager serves it from certified local state; the plain
# browser-bootstrap listener intentionally exposes only /api/bootstrap.
admin_query() {
  local action=$1 attempt
  for attempt in $(seq 1 15); do
    if "${COMPOSE[@]}" --profile exit --profile multihop --profile quota --profile chaos exec -T admin-cli netp2pd \
      --role admin --manager "/dns4/manager-1/udp/4001/quic-v1/p2p/${MANAGER1_PEER_ID}" \
      --admin-token "$ADMIN_TOKEN" --action "$action" 2>/dev/null; then
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
"${COMPOSE[@]}" --profile quorum --profile tun --profile exit --profile multihop --profile quota --profile chaos \
  down -v --remove-orphans >/dev/null 2>&1 || true
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

if "${DOCKER[@]}" image inspect "$IMAGE" >/dev/null 2>&1; then
  log "reuse image"
else
  log "build image"
  "${DOCKER[@]}" build -t "$IMAGE" .
fi

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
  "${DOCKER[@]}" exec netp2p-client-exit-tun-1 sh -c \
    'iptables -t nat -C POSTROUTING -s 100.64.0.0/24 -j NETP2P_SNAT && iptables -t nat -S NETP2P_SNAT | grep -q MASQUERADE' \
    || fail "exit node did not install a POSTROUTING jump and MASQUERADE rule"
  echo "OK: gateway installed a MASQUERADE rule"
fi

log "3-of-3 writes must block while one manager is down"
"${COMPOSE[@]}" --profile quorum rm -sf client-c >/dev/null 2>&1 || true
rm -f "$RUN_DIR/client-c.json"
"${COMPOSE[@]}" stop manager-3 >/dev/null
"${COMPOSE[@]}" --profile quorum up -d client-c
sleep 8
if [ -s "$RUN_DIR/client-c.json" ]; then
  fail "client-c registered despite an unavailable 3-of-3 manager"
fi
echo "OK: registration remained blocked without quorum"
"${COMPOSE[@]}" start manager-3 >/dev/null
wait_status "$RUN_DIR/client-c.json" client-c
C_IP="$(status_field "$RUN_DIR/client-c.json" overlayIP)"
C_HEIGHT="$(status_field "$RUN_DIR/client-c.json" height)"
echo "client-c overlayIP=$C_IP certified height=$C_HEIGHT"
[ "$C_HEIGHT" -ge 2 ] || fail "client-c certified height $C_HEIGHT, want >= 2"
echo "OK: the restored committee certified the pending registration"

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
  metrics="$(curl -fsS "$METRICS_URL" 2>/dev/null || true)"
  [ -n "$metrics" ] && break
  sleep 1
done
printf '%s' "$metrics" | grep -q 'netp2p_bft_height' || fail "metrics endpoint missing netp2p_bft_height"
printf '%s' "$metrics" | grep -q 'netp2p_forward' || fail "metrics endpoint missing forwarding metrics"
echo "OK: /metrics exposes BFT and forwarding metrics"

# fetch_settings merge <overrides-json> writes a full NetworkSettings record,
# because update_network_settings replaces the record wholesale. The current
# record is read from the manager over the authenticated admin protocol.
fetch_settings() {
  local overrides=$1
  admin_query show-snapshot | python3 -c '
import json, sys
snapshot = json.load(sys.stdin)
settings = snapshot.get("state", {}).get("settings", {}) or {}
settings.update(json.loads(sys.argv[1]))
json.dump(settings, sys.stdout)
' "$overrides"
}

if [ "$WITH_MULTIHOP" = "1" ]; then
  log "MULTIHOP: force via-manager paths with two manager hops"
  fetch_settings '{"directPathEnabled": false, "viaManagerEnabled": true, "maxManagerHops": 2, "defaultFlowClass": "latency"}' \
    > deploy/multihop-settings.json
  admin_transition update-settings /config/multihop-settings.json || fail "update-settings failed"
  echo "OK: certified settings disable direct paths and enable via-manager paths"

  cat > deploy/multihop-udp-a-to-b-policy.json <<'JSON'
{
  "id": "allow-a-to-b-udp",
  "sourceGroups": ["clients-a"],
  "destinationGroups": ["clients-b"],
  "services": [{"protocol": "udp", "startPort": 18081, "endPort": 18081}],
  "effect": "allow",
  "direction": "unidirectional"
}
JSON
  admin_transition upsert-policy /config/multihop-udp-a-to-b-policy.json || fail "upsert A-to-B UDP policy failed"
  cat > deploy/multihop-udp-b-to-a-policy.json <<'JSON'
{
  "id": "allow-b-to-a-udp",
  "sourceGroups": ["clients-b"],
  "destinationGroups": ["clients-a"],
  "services": [{"protocol": "udp", "startPort": 18081, "endPort": 18081}],
  "effect": "allow",
  "direction": "unidirectional"
}
JSON
  admin_transition upsert-policy /config/multihop-udp-b-to-a-policy.json || fail "upsert B-to-A UDP policy failed"
  echo "OK: certified UDP policy allows real datagrams in both directions"

  routing_state_ok=0
  rm -f deploy/multihop-snapshot.json.tmp
  for _ in $(seq 1 90); do
    if admin_query show-snapshot > deploy/multihop-snapshot.json.tmp 2>/dev/null; then
      mv -f deploy/multihop-snapshot.json.tmp deploy/multihop-snapshot.json
    fi
    if python3 - deploy/multihop-snapshot.json 2>/dev/null <<'PY'
import json, sys
snapshot = json.load(open(sys.argv[1]))
state = snapshot.get("state", {})
settings = state.get("settings", {})
committee = snapshot.get("committee", [])
families = state.get("pathFamilies", [])
domains = state.get("routingDomains", [])
assert not settings.get("directPathEnabled")
assert settings.get("viaManagerEnabled") is True
assert settings.get("maxManagerHops") == 2
assert settings.get("defaultFlowClass") == "latency"
assert len(committee) == 3 and all(m.get("forwardingEnabled") for m in committee)
assert any(f.get("kind") == "multi_hop" and len(f.get("managerHops", [])) == 2 for f in families)
assert domains and all(d.get("pathFamilyIds") for d in domains)
def has_udp_domain(source_group, destination_group):
    for domain in domains:
        key = domain.get("key", {})
        if key.get("sourceGroupId") != source_group:
            continue
        if key.get("destinationScope") != f"group:{destination_group}":
            continue
        if any(service.get("protocol") == "udp" for service in domain.get("services", [])):
            return True
    return False
assert has_udp_domain("clients-a", "clients-b")
assert has_udp_domain("clients-b", "clients-a")
PY
    then routing_state_ok=1; break; fi
    sleep 1
  done
  [ "$routing_state_ok" = "1" ] || fail "global planner never certified multi-hop families and routing domains"
  echo "OK: certified state contains forwarding managers, routing domains, and two-hop families"
  python3 - "$RUN_DIR/client-a-tun.json" "$RUN_DIR/client-b-tun.json" <<'PY'
import json, sys
for path in sys.argv[1:]:
    status = json.load(open(path))
    failover = status.get("managerFailover", {})
    assert failover.get("configured") == 3, (path, failover)
PY
  echo "OK: TUN clients learned all three certified manager endpoints from the signed manifest"

  forward_before="$(metric_value netp2p_forward_forwarded_total || true)"
  forward_before="${forward_before:-0}"
  multihop_ok=0
  for _ in $(seq 1 90); do
    if "${DOCKER[@]}" exec netp2p-client-a-tun-1 ping -c 2 -W 4 "$B_TUN_IP" >/dev/null 2>&1; then
      if python3 - "$RUN_DIR/client-a-tun.json" "$MANAGER1_PEER_ID" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
diagnostics = status.get("pathDiagnostics", {})
assert status.get("state") == "ready"
assert diagnostics.get("lastPathId") == "global-scale"
assert diagnostics.get("lastKind") in ("via_manager", "multi_hop")
assert diagnostics.get("lastManagerPeerId") == sys.argv[2]
assert diagnostics.get("lastRoutingDomainId")
PY
      then multihop_ok=1; break; fi
    fi
    sleep 1
  done
  [ "$multihop_ok" = "1" ] || fail "client-a-tun never sent a certified global-scale packet"
  forward_after="$(metric_value netp2p_forward_forwarded_total || true)"
  forward_after="${forward_after:-0}"
  awk -v before="$forward_before" -v after="$forward_after" 'BEGIN { exit !(after > before) }' \
    || fail "manager forwarding counter did not advance (before=$forward_before after=$forward_after)"
  echo "OK: real kernel ICMP used global-scale and advanced manager forwarding (before=$forward_before after=$forward_after)"

  # Weighted rendezvous selects per TCP flow. A spread of source ports proves
  # the planner can actually select a certified two-manager family, not merely
  # publish one in certified state.
  "${DOCKER[@]}" exec -d netp2p-client-b-tun-1 sh -c 'while true; do nc -l 18080 >/dev/null 2>&1; done'
  for _ in $(seq 1 80); do
    "${DOCKER[@]}" exec netp2p-client-a-tun-1 nc -z -w 2 "$B_TUN_IP" 18080 >/dev/null 2>&1 || true
  done
  curl -fsS "$METRICS_URL" > deploy/multihop-metrics.txt
  python3 - deploy/multihop-snapshot.json deploy/multihop-metrics.txt <<'PY' \
    || fail "no real TCP flow selected a certified two-manager path family"
import json, re, sys
snapshot = json.load(open(sys.argv[1]))
families = {f.get("id") for f in snapshot.get("state", {}).get("pathFamilies", [])}
selected = 0.0
for line in open(sys.argv[2], encoding="utf-8"):
    if not line.startswith("netp2p_forward_scale_path_selections_total{"):
        continue
    labels = dict(re.findall(r'(\w+)="([^"]*)"', line))
    if labels.get("kind") == "multi_hop" and labels.get("manager_hops") == "2":
        assert labels.get("path_family") in families, labels
        selected += float(line.rsplit(None, 1)[1])
assert selected > 0, "no two-manager family was selected"
print(f"OK: {selected:g} scale envelopes selected certified two-manager families")
PY

  log "MULTIHOP: idle stream closure must not lose the first UDP datagram"
  # The frame transport closes an idle inbound stream after one minute. This
  # delay makes the E2E exercise the exact production failure mode rather than
  # relying on retries to hide a lost first packet.
  sleep 65
  udp_forward_before="$(metric_value netp2p_forward_forwarded_total || true)"
  udp_forward_before="${udp_forward_before:-0}"
  udp_drop_before="$(metric_value netp2p_forward_dropped_total || true)"
  udp_drop_before="${udp_drop_before:-0}"
  "${DOCKER[@]}" exec -d netp2p-client-b-tun-1 sh -c \
    'rm -f /tmp/netp2p-udp-a-to-b; timeout 20 nc -l -u -p 18081 > /tmp/netp2p-udp-a-to-b'
  if ! "${COMPOSE[@]}" exec -T client-a-tun sh -c \
    'printf netp2p-udp-a-to-b | nc -u -w 2 "$1" 18081' sh "$B_TUN_IP" >/dev/null; then
    fail "A->B first UDP datagram after idle was not sent"
  fi
  if ! "${COMPOSE[@]}" exec -T client-b-tun sh -c \
    'test "$(cat /tmp/netp2p-udp-a-to-b 2>/dev/null)" = netp2p-udp-a-to-b'; then
    fail "A->B first UDP datagram after idle was not delivered over global-scale"
  fi
  udp_forward_after="$(wait_metric_above netp2p_forward_forwarded_total "$udp_forward_before")" \
    || fail "first idle UDP forwarding counter did not advance (before=$udp_forward_before)"
  udp_drop_after="$(metric_value netp2p_forward_dropped_total || true)"
  udp_drop_after="${udp_drop_after:-0}"
  [ "$udp_drop_after" = "$udp_drop_before" ] \
    || fail "first idle UDP increased drops (before=$udp_drop_before after=$udp_drop_after)"
  echo "OK: first UDP datagram after idle stream closure was delivered and acknowledged (forwarded=$udp_forward_after)"
  python3 - "$RUN_DIR/client-a-tun.json" "$MANAGER1_PEER_ID" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
diagnostics = status.get("pathDiagnostics", {})
assert diagnostics.get("lastPathId") == "global-scale"
assert diagnostics.get("lastKind") in ("via_manager", "multi_hop")
assert diagnostics.get("lastManagerPeerId") == sys.argv[2]
PY

  "${DOCKER[@]}" exec -d netp2p-client-a-tun-1 sh -c \
    'rm -f /tmp/netp2p-udp-b-to-a; timeout 20 nc -l -u -p 18081 > /tmp/netp2p-udp-b-to-a'
  udp_b_to_a=0
  for _ in $(seq 1 20); do
    "${COMPOSE[@]}" exec -T client-b-tun sh -c \
      'printf netp2p-udp-b-to-a | nc -u -w 2 "$1" 18081' sh "$A_TUN_IP" >/dev/null 2>&1 || true
    if "${DOCKER[@]}" exec netp2p-client-a-tun-1 sh -c \
      'test "$(cat /tmp/netp2p-udp-b-to-a 2>/dev/null)" = netp2p-udp-b-to-a'; then
      udp_b_to_a=1
      break
    fi
    sleep 1
  done
  [ "$udp_b_to_a" = "1" ] || fail "B->A real UDP datagram was not delivered over global-scale"
  python3 - "$RUN_DIR/client-b-tun.json" "$MANAGER1_PEER_ID" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
diagnostics = status.get("pathDiagnostics", {})
assert diagnostics.get("lastPathId") == "global-scale"
assert diagnostics.get("lastKind") in ("via_manager", "multi_hop")
assert diagnostics.get("lastManagerPeerId") == sys.argv[2]
PY
  udp_forward_after="$(metric_value netp2p_forward_forwarded_total || true)"
  udp_forward_after="${udp_forward_after:-0}"
  awk -v before="$udp_forward_before" -v after="$udp_forward_after" 'BEGIN { exit !(after > before) }' \
    || fail "UDP forwarding counter did not advance (before=$udp_forward_before after=$udp_forward_after)"
  echo "OK: real UDP datagrams traversed global-scale in both directions (before=$udp_forward_before after=$udp_forward_after)"
fi

if [ "$WITH_QUOTA" = "1" ]; then
  log "QUOTA: exhaust a per-peer budget and confirm enforcement"
  B_PEER_ID="$(status_field "$RUN_DIR/client-b.json" peerID)"
  cat > deploy/quota-budget.json <<JSON
{"id":"quota-b","subjectType":"peer","subjectID":"$B_PEER_ID","dailyBytes":2048,"monthlyBytes":2048,"peakBps":0,"forwardingCostLimit":0,"onExhausted":"block"}
JSON
  admin_transition upsert-budget /config/quota-budget.json || fail "upsert-budget failed"
  fetch_settings '{"quotaEnforcementEnabled": true, "quotaReportIntervalSeconds": 5}' \
    > deploy/quota-settings.json
  admin_transition update-settings /config/quota-settings.json || fail "quota settings update failed"
  echo "OK: certified budget and enforcement settings committed"

  # Give clients a moment to sync the budget and the enforcement flag, then
  # push traffic until the 2 KiB budget for client-b is spent.
  sleep 5
  for _ in $(seq 1 60); do probe client-a "$A_IP" "$B_IP" 2s >/dev/null 2>&1 || true; done

  # Client-side admission blocks locally as soon as the tracked usage exceeds
  # the cap, so probes to the over-budget peer must now be dropped.
  blocked=0
  for _ in $(seq 1 20); do
    if ! probe client-a "$A_IP" "$B_IP" 2s >/dev/null 2>&1; then blocked=1; break; fi
  done
  [ "$blocked" = "1" ] || fail "client-a kept sending after its budget was exhausted"
  echo "OK: exhausted budget blocked further client-a -> client-b traffic"

  # Certified usage settles on a 60s cadence: the manager turns client reports
  # into an update_budget_usage transition the committee must certify.
  usage_ok=0
  usage_bytes=0
  for _ in $(seq 1 90); do
    usage_bytes="$(admin_query show-snapshot | python3 -c '
import json, sys
snapshot = json.load(sys.stdin)
for budget in snapshot.get("state", {}).get("budgets", []):
    if budget.get("id") == "quota-b":
        print(budget.get("usedDailyBytes", 0))
        break
else:
    print(0)
' 2>/dev/null || echo 0)"
    if [ "${usage_bytes:-0}" -gt 0 ]; then usage_ok=1; break; fi
    sleep 2
  done
  [ "$usage_ok" = "1" ] || fail "certified budget usage never settled into the decision log"
  echo "OK: certified budget usage settled ($usage_bytes bytes)"
fi

if [ "$WITH_CHAOS" = "1" ]; then
  log "CHAOS: stop one manager, prove writes block, then recover"
  "${COMPOSE[@]}" stop manager-3 >/dev/null
  sleep 5
  if admin_transition update-settings /config/chaos-settings.json; then
    fail "committee certified while a 3-of-3 manager was down"
  fi
  echo "OK: committee writes blocked while degraded"
  "${COMPOSE[@]}" start manager-3 >/dev/null
  sleep 5
  fetch_settings '{"loginExpirationDays": 30}' > deploy/chaos-settings.json
  admin_transition update-settings /config/chaos-settings.json \
    || fail "committee could not certify after manager-3 restarted"
  echo "OK: all three managers certified again after the restart"
fi

log "e2e passed"
