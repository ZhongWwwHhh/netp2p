#!/usr/bin/env bash
# Real seven-manager committee E2E.
#
# The stack uses its own Compose project, an internal bridge network, static
# container addresses, and no published host ports. It starts with a real
# three-manager DKG genesis, joins managers 4 through 7 one at a time, restarts
# all seven, then performs controlled 7->5 and 5->4 DKG shrinks and verifies
# the retained four-manager committee after another restart.
set -Eeuo pipefail

export PATH="/usr/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_DIR="$ROOT/tmp/committee-test"
LOG_DIR="$ROOT/tmp/doc/verification"
TIMESTAMP="$(date +%Y%m%dT%H%M%S%z)"
LOG_FILE="$LOG_DIR/committee-e2e-$TIMESTAMP.log"
IMAGE=netp2p-committee-test:latest
COMPOSE=(docker compose -f docker-compose.committee-test.yml --project-name netp2p-committee-test)
MANAGERS=(manager-1 manager-2 manager-3 manager-4 manager-5 manager-6 manager-7)

# Keep POSIX-to-Windows path conversion for host tools such as go and python,
# but disable it for Compose commands that carry container paths.
compose() {
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "${COMPOSE[@]}" "$@"
}

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Some Windows Python installs expose only the python3 WindowsApps alias, which
# exits without running. Prefer a real python3, then fall back to python.
if ! python3 --version >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
    python3() { python "$@"; }
  else
    fail "python3 or python is required"
  fi
fi

cleanup() {
  if [ "${NETP2P_COMMITTEE_E2E_KEEP:-0}" = "1" ]; then
    printf '\nkeeping committee stack; clean it with: %s\n' \
      "docker compose -f docker-compose.committee-test.yml --project-name netp2p-committee-test down -v --remove-orphans"
    return
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

admin_snapshot() {
  compose exec -T admin-cli netp2pd --role admin \
    --manager "$MANAGER1_ADDR" --admin-token "$ADMIN_TOKEN" --action show-snapshot
}

manager_snapshot() {
  local address=$1
  compose exec -T admin-cli netp2pd --role admin \
    --manager "$address" --admin-token "$ADMIN_TOKEN" --action show-snapshot
}

snapshot_state() {
  local file=$1 expected_size=$2 minimum_height=$3 expected_quorum=$4
  python3 - "$file" "$expected_size" "$minimum_height" "$expected_quorum" <<'PY'
import json
import sys

path, expected_size, minimum_height, expected_quorum = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    snapshot = json.load(source)
transition = snapshot.get("transition") or {}
committee = snapshot.get("committee") or []
config = snapshot.get("committeeConfig") or {}
if transition.get("type") == "activate_committee" and transition.get("committee"):
    committee = transition["committee"]
    config = transition.get("committeeConfig") or config
state_config = snapshot.get("state", {}).get("committeeConfig") or {}
ready = (
    int(snapshot.get("height", 0)) >= int(minimum_height)
    and len(committee) == int(expected_size)
    and int(config.get("size", 0)) == int(expected_size)
    and int(config.get("threshold", 0)) == int(expected_quorum)
    and state_config == config
)
print("ready" if ready else "waiting")
PY
}

wait_for_snapshot() {
  local expected_size=$1 minimum_height=$2 expected_quorum=$3 service=$4 attempt
  for attempt in $(seq 1 150); do
    if admin_snapshot > "$RUN_DIR/admin/snapshot.json" 2>"$RUN_DIR/admin/query-error.log"; then
      state="$(snapshot_state "$RUN_DIR/admin/snapshot.json" "$expected_size" "$minimum_height" "$expected_quorum")"
      if [ "$state" = "ready" ]; then
        printf 'OK: %s reached height >= %s with committee %s/%s\n' \
          "$service" "$minimum_height" "$expected_size" "$expected_quorum"
        return 0
      fi
    fi
    sleep 2
  done
  compose logs --no-log-prefix "$service" | tail -80 >&2 || true
  fail "$service did not reach committee $expected_size/$expected_quorum at height >= $minimum_height"
}

wait_for_candidate_persistence() {
  local manager=$1 attempt
  for attempt in $(seq 1 90); do
    if compose exec -T "$manager" sh -c \
      'test -s /data/network.json && test -s /data/manager.json && test -s /data/manager.sqlite'; then
      return 0
    fi
    sleep 2
  done
  compose logs --no-log-prefix "$manager" | tail -120 >&2 || true
  fail "$manager did not persist its activated manager material"
}

wait_for_activated_manifest() {
  local manager=$1 expected_size=$2 expected_quorum=$3 attempt
  for attempt in $(seq 1 90); do
    if compose exec -T "$manager" cat /data/network.json > "$RUN_DIR/admin/$manager-network.json" 2>/dev/null; then
      if python3 - "$RUN_DIR/admin/$manager-network.json" "$expected_size" "$expected_quorum" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
params = manifest["committeeParams"]
ready = (
    len(manifest["managers"]) == int(sys.argv[2])
    and (params["size"], params["faultLimit"], params["quorumSize"])
    == (int(sys.argv[2]), (int(sys.argv[2]) - 1) // 3, int(sys.argv[3]))
)
raise SystemExit(0 if ready else 1)
PY
      then
        return 0
      fi
    fi
    sleep 2
  done
  compose logs --no-log-prefix "$manager" | tail -120 >&2 || true
  fail "$manager did not persist its activated $expected_size-manager manifest"
}

write_shrink_target() {
  local snapshot_file=$1 expected_size=$2 output=$3
  python3 - "$snapshot_file" "$expected_size" "$output" <<'PY'
import json
import sys

snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
transition = snapshot.get("transition") or {}
committee = snapshot.get("committee") or []
if transition.get("type") == "activate_committee" and transition.get("committee"):
    committee = transition["committee"]
retained = [member for member in committee if int(member["id"].split("-")[-1]) <= int(sys.argv[2])]
if len(retained) != int(sys.argv[2]):
    raise SystemExit(f"expected {sys.argv[2]} retained managers, found {len(retained)}")
with open(sys.argv[3], "w", encoding="utf-8") as target:
    json.dump(retained, target, indent=2)
    target.write("\n")
PY
}

request_committee_shrink() {
  local expected_size=$1 expected_quorum=$2 request_height
  admin_snapshot > "$RUN_DIR/admin/before-shrink-$expected_size.json"
  write_shrink_target "$RUN_DIR/admin/before-shrink-$expected_size.json" \
    "$expected_size" "$RUN_DIR/admin/shrink-$expected_size.json"
  compose exec -T admin-cli netp2pd --role admin \
    --manager "$MANAGER1_ADDR" --admin-token "$ADMIN_TOKEN" \
    --action request-committee-shrink --file "/work/shrink-$expected_size.json" \
    > "$RUN_DIR/admin/shrink-request-$expected_size.json"
  request_height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' \
    "$RUN_DIR/admin/shrink-request-$expected_size.json")"
  wait_for_snapshot "$expected_size" "$request_height" "$expected_quorum" "manager-1"
}

manager_address() {
  python3 - "$RUN_DIR/current-network.json" "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
for manager in manifest["managers"]:
    if manager["id"] == sys.argv[2]:
        print(f'{manager["address"]}/p2p/{manager["peerId"]}')
        break
else:
    raise SystemExit(f'manager {sys.argv[2]} not found')
PY
}

write_join_token() {
  local number=$1 token
  token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  printf '%s' "$token" > "$RUN_DIR/admin/join-token-$number.txt"
  python3 - "$RUN_DIR/admin/join-token-$number.txt" "$RUN_DIR/admin/rotate-token-$number.json" <<'PY'
import json
import pathlib
import sys

token = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
pathlib.Path(sys.argv[2]).write_text(json.dumps({"token": token}) + "\n", encoding="utf-8")
PY
}

if ! command -v docker >/dev/null 2>&1 || ! docker version >/dev/null 2>&1; then
  fail "docker is required"
fi

log "prepare isolated test directories"
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/admin"
for manager in "${MANAGERS[@]}"; do
  mkdir -p "$RUN_DIR/$manager" "$RUN_DIR/$manager-data"
done

log "run committee shrink and DKG recovery coverage"
go test ./internal/bft -run '^TestCommitteeResizeThreeFourSevenFiveFourWithDKGAndRecovery$' -count=1

log "generate random three-manager production material"
go run ./cmd/netp2p init production \
  --output-dir "$RUN_DIR/bootstrap" \
  --network committee-e2e \
  --overlay-cidr 100.64.0.0/24 \
  --manager manager-1,manager-1.netp2p.example,203.0.113.11,4001 \
  --manager manager-2,manager-2.netp2p.example,203.0.113.12,4001 \
  --manager manager-3,manager-3.netp2p.example,203.0.113.13,4001 \
  --force

cp "$RUN_DIR/bootstrap/network.json" "$RUN_DIR/current-network.json"
for number in 1 2 3; do
  cp "$RUN_DIR/bootstrap/network.json" "$RUN_DIR/manager-$number/network.json"
  cp "$RUN_DIR/bootstrap/manager-manager-$number.json" "$RUN_DIR/manager-$number/manager.json"
done

ADMIN_TOKEN="$(python3 - "$RUN_DIR/bootstrap/manager-manager-1.json" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["adminToken"])
PY
)"
MANAGER1_ADDR="$(manager_address manager-1)"

log "build local test image"
if [ "${NETP2P_COMMITTEE_E2E_REBUILD:-1}" = "1" ]; then
  docker build --target test -t "$IMAGE" .
else
  docker image inspect "$IMAGE" >/dev/null
fi

log "start the initial three-manager committee"
compose up -d admin-cli manager-1 manager-2 manager-3
wait_for_snapshot 3 1 3 manager-1

for number in 4 5 6 7; do
  manager="manager-$number"
  fault=$(((number - 1) / 3))
  quorum=$((number - fault))

  log "enroll $manager into the current committee"
  if [ "$number" -gt 4 ]; then
    write_join_token "$number"
    compose exec -T admin-cli netp2pd --role admin \
      --manager "$MANAGER1_ADDR" --admin-token "$ADMIN_TOKEN" \
      --action rotate-manager-join-token --file "/work/rotate-token-$number.json"
    join_token_file="$RUN_DIR/admin/join-token-$number.txt"
  else
    join_token_file="$RUN_DIR/bootstrap/manager-join-token.txt"
  fi

  go run ./cmd/netp2p init manager-join \
    --manifest "$RUN_DIR/current-network.json" \
    --manager-bundle "$RUN_DIR/bootstrap/manager-manager-1.json" \
    --join-token-file "$join_token_file" \
    --manager "$manager,$manager.netp2p.example,203.0.113.$number,4001" \
    --init-domain manager-1.netp2p.example \
    --output "$RUN_DIR/$manager/manager-join.json" \
    --force

  compose up -d "$manager"

  pending=0
  for attempt in $(seq 1 90); do
    if admin_snapshot > "$RUN_DIR/admin/snapshot.json" 2>/dev/null; then
      if python3 - "$RUN_DIR/admin/snapshot.json" "$manager" <<'PY'
import json
import sys

snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
for request in snapshot.get("state", {}).get("managerJoinRequests", []):
    if request.get("managerId") == sys.argv[2] and request.get("status") == "pending":
        raise SystemExit(0)
raise SystemExit(1)
PY
      then
        pending=1
        break
      fi
    fi
    sleep 2
  done
  [ "$pending" = "1" ] || fail "$manager never submitted a pending join request"
  printf 'OK: %s submitted a pending join request\n' "$manager"

  compose exec -T admin-cli netp2pd --role admin \
    --manager "$MANAGER1_ADDR" --admin-token "$ADMIN_TOKEN" \
    --action approve-manager-join --target "$manager"

  wait_for_snapshot "$number" 1 "$quorum" "$manager"
  wait_for_candidate_persistence "$manager"
  compose exec -T "$manager" cat /data/network.json > "$RUN_DIR/current-network.json"
  printf 'OK: %s activated; managers persist the certified manifest locally\n' "$manager"
done

log "verify the seven-manager committee"
admin_snapshot > "$RUN_DIR/admin/seven-managers.json"
python3 - "$RUN_DIR/admin/seven-managers.json" <<'PY'
import json
import sys

snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
transition = snapshot.get("transition") or {}
committee = snapshot.get("committee") or []
if transition.get("type") == "activate_committee" and transition.get("committee"):
    committee = transition["committee"]
ids = sorted(member["id"] for member in committee)
assert ids == [f"manager-{number}" for number in range(1, 8)], ids
config = transition.get("committeeConfig") if transition.get("type") == "activate_committee" else snapshot["committeeConfig"]
assert (config["size"], config["threshold"]) == (7, 5), config
assert snapshot["state"]["committeeConfig"] == config
print(f'OK: committee={ids} params=7/2/5 epoch={config["committeeEpoch"]} latest_transition={transition["type"]}')
PY

log "commit a post-resize transition"
printf '%s\n' '{"id":"committee-e2e-post-resize","name":"Committee E2E post-resize"}' \
  > "$RUN_DIR/admin/post-resize-group.json"
before_height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' "$RUN_DIR/admin/seven-managers.json")"
compose exec -T admin-cli netp2pd --role admin \
  --manager "$MANAGER1_ADDR" --admin-token "$ADMIN_TOKEN" \
  --action upsert-group --file /work/post-resize-group.json \
  > "$RUN_DIR/admin/post-resize-result.json"
post_height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' "$RUN_DIR/admin/post-resize-result.json")"
[ "$post_height" -gt "$before_height" ] || fail "post-resize transition did not advance height"
printf 'OK: post-resize transition committed at height %s\n' "$post_height"

log "verify every manager before restart"
for manager in "${MANAGERS[@]}"; do
  address="$(manager_address "$manager")"
  height=0
  for attempt in $(seq 1 60); do
    if manager_snapshot "$address" > "$RUN_DIR/admin/$manager-before.json" 2>/dev/null; then
      height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' "$RUN_DIR/admin/$manager-before.json")"
      if [ "$height" -ge "$post_height" ]; then
        printf 'OK: %s is at height %s before restart\n' "$manager" "$height"
        break
      fi
    fi
    sleep 2
  done
  [ "${height:-0}" -ge "$post_height" ] || fail "$manager did not reach height $post_height before restart"
done

log "restart all seven managers together"
compose stop "${MANAGERS[@]}"
compose start "${MANAGERS[@]}"

log "verify state and identity after restart"
for manager in "${MANAGERS[@]}"; do
  address="$(manager_address "$manager")"
  height=0
  for attempt in $(seq 1 150); do
    if manager_snapshot "$address" > "$RUN_DIR/admin/$manager-after.json" 2>/dev/null; then
      height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' "$RUN_DIR/admin/$manager-after.json")"
      if [ "$height" -ge "$post_height" ]; then
        break
      fi
    fi
    sleep 2
  done
  [ "$height" -ge "$post_height" ] || fail "$manager lost state after restart (height=$height)"
  python3 - "$RUN_DIR/current-network.json" "$RUN_DIR/admin/$manager-after.json" "$manager" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
snapshot = json.load(open(sys.argv[2], encoding="utf-8"))
expected = {member["id"]: member["peerId"] for member in manifest["managers"]}
actual = {member["id"]: member["peerId"] for member in snapshot["committee"]}
assert actual == expected, (sys.argv[3], actual, expected)
assert snapshot["state"]["committeeConfig"]["committeeEpoch"] >= 4
PY
  printf 'OK: %s restored height %s and its certified identity\n' "$manager" "$height"
done

for number in 4 5 6 7; do
  compose exec -T "manager-$number" sh -c \
    'test -s /data/manager.json && test -s /data/manager.sqlite' \
    || fail "manager-$number did not persist identity and ledger"
done

log "shrink the committee from seven to five managers"
admin_snapshot > "$RUN_DIR/admin/before-seven-shrink.json"
request_committee_shrink 5 4
for number in 1 2 3 4 5; do
  wait_for_activated_manifest "manager-$number" 5 4
done
compose exec -T manager-1 cat /data/network.json > "$RUN_DIR/current-network.json"
admin_snapshot > "$RUN_DIR/admin/after-five-shrink.json"
python3 - "$RUN_DIR/admin/before-seven-shrink.json" "$RUN_DIR/admin/after-five-shrink.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
transition = after.get("transition") or {}
config = transition.get("committeeConfig") or after["committeeConfig"]
ids = sorted(member["id"] for member in transition.get("committee") or after["committee"])
assert ids == [f"manager-{number}" for number in range(1, 6)], ids
assert (config["size"], config["threshold"]) == (5, 4), config
assert after["state"]["committeeConfig"] == config
assert after["state"].get("pendingCommitteeShrink") in (None, []), after["state"].get("pendingCommitteeShrink")
assert config["groupPublicKey"] != before["state"]["committeeConfig"]["groupPublicKey"]
print(f'OK: 7->5 shrink certified with a fresh DKG key at epoch {config["committeeEpoch"]}')
PY
compose stop manager-6 manager-7

log "commit a transition with the five-manager committee"
printf '%s\n' '{"id":"committee-e2e-post-shrink-5","name":"Committee E2E post-shrink 5"}' \
  > "$RUN_DIR/admin/post-shrink-5-group.json"
five_before_height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' \
  "$RUN_DIR/admin/after-five-shrink.json")"
compose exec -T admin-cli netp2pd --role admin \
  --manager "$MANAGER1_ADDR" --admin-token "$ADMIN_TOKEN" \
  --action upsert-group --file /work/post-shrink-5-group.json \
  > "$RUN_DIR/admin/post-shrink-5-result.json"
five_post_height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' \
  "$RUN_DIR/admin/post-shrink-5-result.json")"
[ "$five_post_height" -gt "$five_before_height" ] || fail "five-manager transition did not advance height"
printf 'OK: five-manager transition committed at height %s\n' "$five_post_height"

log "shrink the committee from five to four managers"
admin_snapshot > "$RUN_DIR/admin/before-five-shrink.json"
request_committee_shrink 4 3
for number in 1 2 3 4; do
  wait_for_activated_manifest "manager-$number" 4 3
done
compose exec -T manager-1 cat /data/network.json > "$RUN_DIR/current-network.json"
admin_snapshot > "$RUN_DIR/admin/after-four-shrink.json"
python3 - "$RUN_DIR/admin/before-five-shrink.json" "$RUN_DIR/admin/after-four-shrink.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
transition = after.get("transition") or {}
config = transition.get("committeeConfig") or after["committeeConfig"]
ids = sorted(member["id"] for member in transition.get("committee") or after["committee"])
assert ids == [f"manager-{number}" for number in range(1, 5)], ids
assert (config["size"], config["threshold"]) == (4, 3), config
assert after["state"]["committeeConfig"] == config
assert after["state"].get("pendingCommitteeShrink") in (None, []), after["state"].get("pendingCommitteeShrink")
assert config["groupPublicKey"] != before["state"]["committeeConfig"]["groupPublicKey"]
print(f'OK: 5->4 shrink certified with a fresh DKG key at epoch {config["committeeEpoch"]}')
PY
compose stop manager-5

log "commit a transition with the four-manager committee"
printf '%s\n' '{"id":"committee-e2e-post-shrink-4","name":"Committee E2E post-shrink 4"}' \
  > "$RUN_DIR/admin/post-shrink-4-group.json"
four_before_height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' \
  "$RUN_DIR/admin/after-four-shrink.json")"
compose exec -T admin-cli netp2pd --role admin \
  --manager "$MANAGER1_ADDR" --admin-token "$ADMIN_TOKEN" \
  --action upsert-group --file /work/post-shrink-4-group.json \
  > "$RUN_DIR/admin/post-shrink-4-result.json"
four_post_height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' \
  "$RUN_DIR/admin/post-shrink-4-result.json")"
[ "$four_post_height" -gt "$four_before_height" ] || fail "four-manager transition did not advance height"
printf 'OK: four-manager transition committed at height %s\n' "$four_post_height"

log "restart the retained four managers together"
compose stop manager-1 manager-2 manager-3 manager-4
compose start manager-1 manager-2 manager-3 manager-4

log "verify the retained committee after its final restart"
for manager in manager-1 manager-2 manager-3 manager-4; do
  address="$(manager_address "$manager")"
  height=0
  for attempt in $(seq 1 150); do
    if manager_snapshot "$address" > "$RUN_DIR/admin/$manager-final.json" 2>/dev/null; then
      height="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' \
        "$RUN_DIR/admin/$manager-final.json")"
      if [ "$height" -ge "$four_post_height" ]; then
        break
      fi
    fi
    sleep 2
  done
  [ "$height" -ge "$four_post_height" ] || fail "$manager lost state after final restart (height=$height)"
  python3 - "$RUN_DIR/current-network.json" "$RUN_DIR/admin/$manager-final.json" "$manager" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
snapshot = json.load(open(sys.argv[2], encoding="utf-8"))
expected = {member["id"]: member["peerId"] for member in manifest["managers"]}
actual = {member["id"]: member["peerId"] for member in snapshot["committee"]}
assert actual == expected, (sys.argv[3], actual, expected)
assert (snapshot["committeeConfig"]["size"], snapshot["committeeConfig"]["threshold"]) == (4, 3)
assert snapshot["state"]["committeeConfig"] == snapshot["committeeConfig"]
assert snapshot["state"].get("pendingCommitteeShrink") in (None, [])
PY
  printf 'OK: %s restored height %s after shrink and rekey\n' "$manager" "$height"
done

log "PASS: real 3->4->7 expansion, 7/2/5 writes, restart, 7->5->4 shrink, rekey, and recovery"
printf 'log: %s\n' "$LOG_FILE"
