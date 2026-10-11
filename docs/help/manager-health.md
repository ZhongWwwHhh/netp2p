# Manager and committee health

Fix problems with the manager committee.

## Symptoms

- Writes time out
- Console shows degraded or a quorum warning
- Heights differ across managers
- One manager unreachable

## Diagnosis

Check each direct manager URL:

```bash
curl -fsS https://manager-1.netp2p.example:9443/readyz
curl -fsS https://manager-2.netp2p.example:9443/readyz
curl -fsS https://manager-3.netp2p.example:9443/readyz
```

Compare `height`, `committee`, `quorum`, `ledgerReady`, and `degraded` fields.
Check metrics for height lag, commit rate, and connectivity.

## Fixes

| Finding | Action |
| --- | --- |
| One manager down | Restore/connect it; it catches up on return. Avoid config changes until quorum returns |
| Heights differ | Identify the lagging manager, let it catch up. Do not submit more transitions |
| `/healthz` ok but `/readyz` fails | The process is alive but not ready; check ledger and committee state |
| Writes time out with all three online | Check submit failure metrics and store write failures |

## Rules

- `/healthz` alone is never evidence of quorum.
- Restart only the failed manager for recovery.
- Restart all three together only for a committee-wide upgrade or restore.
- Never roll one manager at a time during an upgrade.
