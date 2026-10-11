# Operations

## Health

- `GET /healthz`: liveness. Returns 200 when the web process can serve.
- `GET /readyz`: readiness. Returns committee membership/connectivity, quorum, height, ledger state, and degraded status; 503 when not ready.
- `GET /api/v1/committee/status`: authenticated per-manager committee view.
- `GET /api/v1/diagnostics`: authenticated operational summary and problem list.

For automation, use `/readyz` on each direct manager URL. Equal heights across all three are as important as HTTP 200.

## Metrics

Each manager exposes Prometheus metrics on the restricted port 9101 (`/metrics`). Monitor at least:

- `netp2p_bft_height` and height spread
- committee online/quorum gauges
- commit, catch-up, sync, and submit success/failure counters
- forwarding forwarded/dropped counters and queue/drop gauges where exposed
- client presence
- DNS failures
- quota enforcement
- process memory and goroutines

Alert immediately when any of three managers is disconnected or height differs across managers.

## Logs

Linux:

```bash
journalctl -u netp2p-client -f
docker compose -f /opt/netp2p/docker-compose.yml logs -f netp2p caddy
```

Windows:

```powershell
Get-Content "$env:ProgramData\NetP2P\logs\netp2pd.log" -Tail 200
Get-WinEvent -LogName Application -MaxEvents 200 | Where-Object ProviderName -like '*NetP2P*'
```

Manager logs record structured BFT transitions and errors. Client logs cover login, sync, TUN/DNS setup, forwarding, and doctor findings. Redact session tokens and setup keys before sharing logs.

## Client diagnosis

```bash
netp2p status --json
netp2p doctor
netp2p netcheck
netp2p debug bundle
```

`doctor` reports TUN/platform privileges, protocol/version match, clock, manager reachability, DNS, and current state with a next action. `debug bundle` collects local diagnostics; inspect it for secrets before uploading.

## Backup

Back up every manager, not one node. At minimum capture:

- SQLite manager state/ledger
- DKG/private share and manager identity material
- runtime configuration
- image digest/config version used at backup time
- Caddy configuration/certificates where not automatically re-issuable

Store encrypted backups off-host with access control. A backup is valid only after a successful restore drill. Record the BFT height and state hash; back up at a quiet point with all managers healthy and no in-flight writes.

## Restore

Always stop the affected scope first:

- One-node restore: stop that manager, restore its data/config, restart, verify catch-up and height equality.
- Committee-wide restore: use a maintenance window, stop all three, restore the same coherent backup set, recreate/start together, then run readiness and client E2E.

After restore, require matching heights/state hashes, 3/3 connectivity, successful login, snapshot validation, and a client traffic probe before resuming normal operation.

## Common failures

| Symptom | First checks | Action |
| --- | --- | --- |
| Writes time out | direct `/readyz`, committee status | restore 3/3 connectivity; avoid config churn |
| Heights differ | metrics and snapshot-at-height | catch up/rebuild lagging manager |
| Login fails | auth status and auth events | check account lock, credentials, clock, HTTPS |
| Client stuck `needs-login` | setup key, manager endpoint, logs | reissue key and provision |
| Peer unreachable | policy/route/presence, both directions | probe and inspect assignments, not status alone |
| DNS fails | resolver listener, DNS settings, upstream | test overlay and external names separately |

Escalate with two timestamps, versions, client status JSON, relevant logs, topology, and exact successful/failed probes.
