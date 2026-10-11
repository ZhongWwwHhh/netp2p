# Back up and restore manager state

Protect the certified ledger, DKG material, and configuration against data loss.

## Outcome

Encrypted, tested backups of every manager, with a validated restore procedure.

## What to back up

On every manager, capture:

- SQLite manager state and ledger (under `/var/lib/netp2p`)
- DKG private share and manager identity material
- Runtime configuration (`/etc/netp2p`)
- Image digest and configuration version used at backup time
- Caddy configuration and certificates if not automatically re-issuable

Store encrypted backups off-host with access control. Never copy secrets into
repositories or shared tickets.

## When to back up

Back up at a quiet point: all managers healthy, equal heights, no in-flight
writes. Record the BFT height and state hash with each backup set. A backup is
only valid after a successful restore drill.

## Restore

Always stop the affected scope first.

### One-node restore

Use when one manager's data is corrupted or its disk is replaced:

1. Stop that manager container.
2. Restore its data and configuration from the latest committee-wide backup.
3. Start the manager.
4. Verify catch-up, height equality, and `3/3` connectivity.

### Committee-wide restore

Use when multiple managers are corrupted or you need to return to a prior state:

1. Schedule a maintenance window.
2. Stop all three managers together.
3. Restore the same coherent backup set on all three.
4. Recreate and start all together.
5. Require matching heights and state hashes, `3/3` connectivity, successful
   login, snapshot validation, and a client traffic probe before resuming.

Never restore a one-node old snapshot over a newer ledger.
