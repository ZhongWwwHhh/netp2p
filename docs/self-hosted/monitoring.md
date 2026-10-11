# Monitor NetP2P managers

Track committee health, data-plane activity, and client presence.

## Health endpoints

Each manager exposes:

- `GET /healthz` — process liveness (200 when serving).
- `GET /readyz` — full readiness: committee connectivity, quorum, height,
  ledger state, degraded flag. Returns 503 when not ready.
- `GET /api/v1/committee/status` — authenticated per-manager committee view.
- `GET /api/v1/diagnostics` — authenticated operational summary.

For automation, poll `/readyz` on each direct manager URL. Equal heights across
all three are as important as HTTP 200.

## Metrics

Each manager exposes Prometheus metrics on the restricted port 9101 (`/metrics`).
Monitor at minimum:

- `netp2p_bft_height` and height spread across managers
- Committee online/quorum gauges
- Commit, catch-up, sync, and submit success/failure counters
- Forwarding forwarded/dropped counters and queue depth
- Client presence
- DNS failures
- Quota enforcement
- Process memory and goroutines

Alert immediately when any manager disconnects or heights differ.

## Example alerts

```promql
# Manager height fork
max(netp2p_bft_height) - min(netp2p_bft_height) > 0

# Committee degraded
netp2p_committee_online < 3
```

Route metrics to your existing Prometheus/VictoriaMetrics stack. Keep the
metrics port off the public internet.
