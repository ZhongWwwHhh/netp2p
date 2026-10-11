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
Check these metrics:

| Metric | Meaning |
| --- | --- |
| `netp2p_bft_height` and `netp2p_bft_height_lag` | Certified height and lag behind the highest manager |
| `netp2p_bft_uncommitted_proposals` | Proposals pending in the current view |
| `netp2p_bft_round_timeouts_total` | View changes caused by round deadlines |
| `netp2p_bft_submit_attempts_total` and `netp2p_bft_submit_failures_total` | Submit volume and rejected or failed submissions |

## Fixes

| Finding | Action |
| --- | --- |
| One manager down | Restore/connect it; it catches up on return. Avoid config changes until quorum returns |
| Heights differ | Identify the lagging manager, let it catch up. Do not submit more transitions |
| Height lag persists | Check manager connectivity and catch-up metrics; do not force a config change |
| Uncommitted proposals remain | Check round timeouts and submit failures; restore quorum before retrying |
| `/healthz` ok but `/readyz` fails | The process is alive but not ready; check ledger and committee state |
| Writes time out with all three online | Check submit failure metrics, `/readyz` ledger state, and manager logs |

## Rules

- `/healthz` alone is never evidence of quorum.
- Restart only the failed manager for recovery.
- Restart all three together only for a committee-wide upgrade or restore.
- Never roll one manager at a time during an upgrade.
