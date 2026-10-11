# Upgrade and roll back managers

Upgrade the committee to a new release without losing state, or return to a
known-good version.

## Outcome

All three managers run the same pinned version with a consistent ledger and no
client-visible interruption beyond the maintenance window.

## Prerequisites

- All three managers report `ready` with equal heights.
- A completed [backup](backup-restore.md) taken at a quiet point.
- The new image digest recorded from the release (not a local image ID).
- A maintenance window announced to users.

## Why all-at-once

The 3-of-3 committee blocks writes when any manager is offline. A rolling
restart necessarily removes quorum twice (once per stop and once per start) and
can strand a manager on the old version. Always use an atomic all-stop/all-start.

## Upgrade steps

1. Verify all three `/readyz` endpoints and record current heights.
2. On each host, pre-pull the pinned image:

   ```bash
   docker compose pull
   ```

3. On each host, recreate containers without starting:

   ```bash
   docker compose create --force-recreate
   ```

4. Start all three managers together.
5. Validate each `/readyz`, confirm equal heights, HTTPS, metrics, and run a
   client login plus traffic probe.
6. Keep the previous digest and backup until soak validation passes.

Never roll one manager at a time for a committee upgrade.

## Rollback steps

1. Announce another maintenance window.
2. Back up current state.
3. Stop all three managers together.
4. Revert image/config pins to the prior tested release. Preserve
   `/var/lib/netp2p`, manager identity, seed/share material, and ledger history.
5. Recreate and start all three together.
6. Re-run readiness and client checks.

Do not restore a single-node old snapshot over a newer committee ledger.
Committee-wide restore requires the [backup/restore procedure](backup-restore.md).
