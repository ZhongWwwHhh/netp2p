#!/usr/bin/env bash
# Real Docker and libp2p adversarial test for NetP2P's public boundaries.
#
# The stack is isolated from scripts/e2e.sh and does not test through mocks:
# HTTP assertions use the published manager listener, protocol assertions use
# a real attacker binary, and results are checked against certified snapshots,
# Prometheus metrics, and container logs.
set -Eeuo pipefail

# MSYS and some minimal Unix environments do not put coreutils ahead of Windows
# aliases in the inherited PATH.
case ":$PATH:" in
  *:/usr/bin:*) ;;
  *) PATH="/usr/bin:$PATH" ;;
esac
export PATH

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_DIR="$ROOT/tmp/security-e2e"
LOG_DIR="$ROOT/tmp/doc/verification"
TIMESTAMP="$(date +%Y%m%dT%H%M%S%z)"
LOG_FILE="$LOG_DIR/security-e2e-$TIMESTAMP.log"
IMAGE=netp2p-security-test:latest
PROJECT=netp2p-security-test
COMPOSE_FILE="scripts/docker-compose.security-test.yml"
ENV_FILE="tmp/security-e2e/compose.env"
WEB_BASE="http://127.0.0.1:18080"
METRICS_URL="http://127.0.0.1:19100/metrics"
ADMIN_TOKEN=netp2p-admin-v0
OWNER_EMAIL=security-owner@example.com
OWNER_PASSWORD=security-owner-password-2026

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

if ! python3 --version >/dev/null 2>&1; then
  if python --version >/dev/null 2>&1; then
    python3() { python "$@"; }
  else
    fail "python3 or python is required"
  fi
fi
if ! command -v curl >/dev/null 2>&1; then
  fail "curl is required"
fi
if ! docker version >/dev/null 2>&1; then
  fail "docker is required"
fi

compose() {
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
    docker compose -f "$COMPOSE_FILE" --project-name "$PROJECT" --env-file "$ENV_FILE" "$@"
}

cleanup() {
  if [ "${NETP2P_SECURITY_E2E_KEEP:-0}" = "1" ]; then
    printf '\nkeeping security stack; clean it with: docker compose -f %s --project-name %s down -v --remove-orphans\n' \
      "$COMPOSE_FILE" "$PROJECT"
    return
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)[sys.argv[2]])
PY
}

http_code() {
  local output=$1
  shift
  curl -sS -o "$output" -w '%{http_code}' "$@"
}

wait_file() {
  local file=$1 name=$2 attempt
  for attempt in $(seq 1 120); do
    if [ -s "$file" ]; then return 0; fi
    sleep 1
  done
  compose logs --no-log-prefix "$name" | tail -80 >&2 || true
  fail "$name did not write status"
}

wait_ready() {
  local url=$1 name=$2 attempt
  for attempt in $(seq 1 120); do
    if curl -fsS "$url/readyz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  compose logs --no-log-prefix "$name" | tail -80 >&2 || true
  fail "$name never became ready"
}

admin_snapshot() {
  local output=$1
  compose exec -T admin-cli netp2pd --role admin \
    --manager "/dns4/manager-1/udp/4001/quic-v1/p2p/$MANAGER1_PEER_ID" \
    --admin-token "$ADMIN_TOKEN" --action show-snapshot \
    >"$output"
}

# The attacker is a real external libp2p host, but it runs inside the Docker
# network. Running it on the Windows host makes libp2p rediscover the manager's
# container-private address, which Docker Desktop cannot route from the host.
attack() {
  compose exec -T admin-cli /config/security-attacker-linux \
    --manager "/dns4/manager-1/udp/4001/quic-v1/p2p/$MANAGER1_PEER_ID" \
    --network netp2p-test "$@"
}

metric_value() {
  curl -fsS "$METRICS_URL" | awk -v key="$1" '$1 == key { print $2; exit }'
}

log "prepare isolated security-test directories"
MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
  docker compose -f "$COMPOSE_FILE" --project-name "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/run" "$RUN_DIR/http"

log "generate seed and build current-code image"
go run ./cmd/netp2pd --role seedgen --config "$RUN_DIR/state.json"
MANAGER1_PEER_ID="$(python3 - "$RUN_DIR/state.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    seed = json.load(source)
print(next(manager["peerId"] for manager in seed["managers"] if manager["id"] == "manager-1"))
PY
)"
printf 'MANAGER1_PEER_ID=%s\n' "$MANAGER1_PEER_ID" >"$ENV_FILE"
if [ "${NETP2P_SECURITY_E2E_REBUILD:-1}" = "1" ]; then
  docker build --target test -t "$IMAGE" .
else
  docker image inspect "$IMAGE" >/dev/null
fi
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -o "$RUN_DIR/security-attacker-linux" ./scripts/security-attacker

log "start three managers and two real clients"
compose up -d --wait mock-idp
compose up -d manager-1 manager-2 manager-3 client-a client-b admin-cli
wait_ready "$WEB_BASE" manager-1
wait_ready "http://127.0.0.1:18081" manager-2
wait_ready "http://127.0.0.1:18082" manager-3
wait_file "$RUN_DIR/run/client-a.json" client-a
wait_file "$RUN_DIR/run/client-b.json" client-b
[ "$(json_field "$RUN_DIR/run/client-a.json" state)" = "ready" ] || fail "client-a did not reach ready"
[ "$(json_field "$RUN_DIR/run/client-b.json" state)" = "ready" ] || fail "client-b did not reach ready"
A_PEER_ID="$(json_field "$RUN_DIR/run/client-a.json" peerID)"
B_PEER_ID="$(json_field "$RUN_DIR/run/client-b.json" peerID)"
printf 'manager-1=%s client-a=%s client-b=%s\n' "$MANAGER1_PEER_ID" "$A_PEER_ID" "$B_PEER_ID"

log "HTTP: unauthenticated API must be rejected"
code="$(http_code "$RUN_DIR/http/unauth.json" "$WEB_BASE/api/v1/snapshot")"
[ "$code" = "401" ] || fail "unauthenticated snapshot returned $code"

log "HTTP: first-run owner bootstrap and local login"
cat >"$RUN_DIR/http/owner.json" <<JSON
{"email":"$OWNER_EMAIL","name":"Security Owner","password":"$OWNER_PASSWORD"}
JSON
code="$(http_code "$RUN_DIR/http/owner-response.json" -X POST "$WEB_BASE/api/v1/bootstrap/owner" \
  -H 'Content-Type: application/json' -D "$RUN_DIR/http/owner.headers" \
  --data-binary "@$RUN_DIR/http/owner.json")"
[ "$code" = "200" ] || fail "owner bootstrap returned $code: $(cat "$RUN_DIR/http/owner-response.json")"
SESSION_COOKIE="$(awk 'tolower($1) == "set-cookie:" {print $2}' "$RUN_DIR/http/owner.headers" | cut -d';' -f1)"
[ -n "$SESSION_COOKIE" ] || fail "owner bootstrap did not issue a session cookie"

log "HTTP: unknown-account brute force must lock out"
for attempt in $(seq 1 5); do
  code="$(http_code "$RUN_DIR/http/login-$attempt.json" -X POST "$WEB_BASE/api/v1/auth/login" \
    -H 'Content-Type: application/json' --data '{"email":"attacker@example.com","password":"wrong-password"}')"
  [ "$code" = "401" ] || fail "unknown-account attempt $attempt returned $code"
done
code="$(http_code "$RUN_DIR/http/login-locked.json" -X POST "$WEB_BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' --data '{"email":"attacker@example.com","password":"wrong-password"}')"
[ "$code" = "429" ] || fail "sixth unknown-account login returned $code instead of 429"

log "HTTP: cookie mutation requires same-origin"
code="$(http_code "$RUN_DIR/http/csrf.json" -X POST "$WEB_BASE/api/v1/transitions" \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -H "Cookie: $SESSION_COOKIE" --data '{"transition":{"type":"upsert_group","group":{"id":"csrf-group"}}}')"
[ "$code" = "403" ] || fail "cross-origin cookie mutation returned $code instead of 403"

log "HTTP: OIDC redirect and callback forgery"
location="$(curl -sS -D - -o /dev/null "$WEB_BASE/auth/login?redirect=https%3A%2F%2Fevil.example" \
  | awk 'tolower($1) == "location:" {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}')"
case "$location" in
  /auth/idp/*) ;;
  *) fail "OIDC login redirected to unsafe location: $location" ;;
esac
location="$(curl -sS -D - -o /dev/null "$WEB_BASE/auth/login?redirect=%2F%2Fevil.example" \
  | awk 'tolower($1) == "location:" {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}')"
case "$location" in
  /auth/idp/*) ;;
  *) fail "OIDC login accepted protocol-relative redirect: $location" ;;
esac
code="$(http_code "$RUN_DIR/http/oidc-forged.json" "$WEB_BASE/auth/callback?code=forged&state=forged")"
[ "$code" = "400" ] || fail "forged OIDC callback returned $code instead of 400"

log "HTTP: oversized login body must be rejected without killing the manager"
python3 - "$RUN_DIR/http/oversized-login.json" <<'PY'
import json
import sys
payload = {"email": "oversized@example.com", "password": "x" * 32768}
with open(sys.argv[1], "w", encoding="utf-8") as target:
    json.dump(payload, target)
PY
code="$(http_code "$RUN_DIR/http/oversized-response.json" -X POST "$WEB_BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' --data-binary "@$RUN_DIR/http/oversized-login.json")"
[ "$code" = "400" ] || fail "oversized login body returned $code instead of 400"
curl -fsS "$WEB_BASE/healthz" >/dev/null || fail "manager became unhealthy after oversized body"

log "HTTP: client-visible snapshot must be redacted"
code="$(http_code "$RUN_DIR/http/snapshot.json" -H "Authorization: Bearer $ADMIN_TOKEN" "$WEB_BASE/api/v1/snapshot")"
[ "$code" = "200" ] || fail "authenticated snapshot returned $code"
python3 - "$RUN_DIR/http/snapshot.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    snapshot = json.load(source)
assert snapshot.get("height", 0) >= 1
for key in snapshot.get("state", {}).get("setupKeys", []):
    for forbidden in ("token", "tokenPrefix", "tokenHash"):
        assert forbidden not in key, (key.get("id"), forbidden)
for user in snapshot.get("state", {}).get("users", []):
    assert "passwordVerifier" not in user, user.get("id")
for member in snapshot.get("committee", []):
    assert not member.get("keySeed"), member.get("id")
assert "managerJoinTokenHash" not in snapshot.get("state", {})
PY

log "libp2p: unauthorized admin, setup-key brute force, state-update spoof, oversized control frame"
attack --admin-token "$ADMIN_TOKEN" \
  --attacks unauthorized-admin,state-update-spoof,oversized-control,setup-key-bruteforce
curl -fsS "$WEB_BASE/healthz" >/dev/null || fail "manager unhealthy after oversized control frame"

log "quota: remote identity may not report another peer's usage"
cat >"$RUN_DIR/http/budget.json" <<JSON
{"transition":{"type":"upsert_budget","budget":{"id":"security-victim","subjectType":"peer","subjectID":"$B_PEER_ID","dailyBytes":100000,"monthlyBytes":100000,"peakBps":0,"forwardingCostLimit":0,"onExhausted":"block"}}}
JSON
code="$(http_code "$RUN_DIR/http/budget-response.json" -X POST "$WEB_BASE/api/v1/transitions" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $ADMIN_TOKEN" \
  --data-binary "@$RUN_DIR/http/budget.json")"
[ "$code" = "200" ] || fail "budget transition returned $code: $(cat "$RUN_DIR/http/budget-response.json")"
code="$(http_code "$RUN_DIR/http/quota-before.json" -H "Authorization: Bearer $ADMIN_TOKEN" "$WEB_BASE/api/v1/quota")"
[ "$code" = "200" ] || fail "quota query returned $code"
attack --victim-peer "$B_PEER_ID" --budget-id security-victim --attacks quota-spoof
sleep 1
code="$(http_code "$RUN_DIR/http/quota-after.json" -H "Authorization: Bearer $ADMIN_TOKEN" "$WEB_BASE/api/v1/quota")"
[ "$code" = "200" ] || fail "quota query after spoof returned $code"
python3 - "$RUN_DIR/http/quota-after.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    payload = json.load(source)
budgets = [item for item in payload.get("usage", []) if item.get("id") == "security-victim"]
assert len(budgets) == 1, budgets
assert budgets[0].get("usedDailyBytes") == 0, budgets[0]
assert budgets[0].get("usedMonthlyBytes") == 0, budgets[0]
PY

log "data plane: forwarded source identity may not be impersonated"
cat >"$RUN_DIR/http/assignment.json" <<JSON
{"transition":{"type":"update_route_assignment","assignment":{"id":"security-forward-assignment","sourcePeerId":"$A_PEER_ID","destinationPeerId":"$B_PEER_ID","epoch":1,"primary":{"id":"security-forward-path","kind":"via_manager","managerHops":["$MANAGER1_PEER_ID"],"rttMilliseconds":1,"jitterMilliseconds":0.1,"lossPercent":0,"bandwidthMbps":1000,"confidence":0.9},"updatedAt":"2026-10-14T14:20:00Z","requiresAdmission":false,"maxHops":1}}}
JSON
code="$(http_code "$RUN_DIR/http/assignment-response.json" -X POST "$WEB_BASE/api/v1/transitions" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $ADMIN_TOKEN" \
  --data-binary "@$RUN_DIR/http/assignment.json")"
[ "$code" = "200" ] || fail "assignment transition returned $code: $(cat "$RUN_DIR/http/assignment-response.json")"
DROPS_BEFORE="$(metric_value netp2p_forward_dropped_total)"
DROPS_BEFORE="${DROPS_BEFORE:-0}"
attack --assignment-id security-forward-assignment --path-id security-forward-path \
  --source-peer "$A_PEER_ID" --destination-peer "$B_PEER_ID" --attacks forward-spoof
sleep 1
DROPS_AFTER="$(metric_value netp2p_forward_dropped_total)"
DROPS_AFTER="${DROPS_AFTER:-0}"
[ "$DROPS_AFTER" -gt "$DROPS_BEFORE" ] || fail "spoofed forward was not counted as dropped ($DROPS_BEFORE -> $DROPS_AFTER)"

log "manager join token: query-only scope and brute-force rate limit"
JOIN_TOKEN="$(python3 -c 'import secrets; print("security-join-" + secrets.token_urlsafe(32))')"
printf '{"token":"%s"}\n' "$JOIN_TOKEN" >"$RUN_DIR/join-token.json"
compose exec -T admin-cli netp2pd --role admin \
  --manager "/dns4/manager-1/udp/4001/quic-v1/p2p/$MANAGER1_PEER_ID" \
  --admin-token "$ADMIN_TOKEN" --action rotate-manager-join-token \
  --file /config/join-token.json >/dev/null
attack --join-token "$JOIN_TOKEN" --attacks manager-join-token

log "logs: credentials and verifiers must not leak"
compose logs --no-log-prefix manager-1 manager-2 manager-3 >"$RUN_DIR/manager-logs.txt"
python3 - "$RUN_DIR/manager-logs.txt" "$ADMIN_TOKEN" "$OWNER_PASSWORD" "$SESSION_COOKIE" "$JOIN_TOKEN" <<'PY'
import sys
with open(sys.argv[1], encoding="utf-8", errors="replace") as source:
    logs = source.read()
for secret in sys.argv[2:]:
    assert secret not in logs, "secret leaked into manager logs"
for forbidden in ("setup-key-a", "setup-key-b", "tokenHash", "passwordVerifier", "managerJoinTokenHash"):
    assert forbidden not in logs, forbidden
PY

log "PASS: real Docker adversarial security suite"
