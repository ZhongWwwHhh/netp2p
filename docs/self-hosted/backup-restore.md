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

## Create a backup

These commands assume a Compose service named `manager`, data at
`/var/lib/netp2p`, and configuration at `/etc/netp2p`. Run them on each manager.
Run Compose commands from the manager project root, usually `/opt/netp2p`.

```bash
BACKUP_ID=$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -o 999 -g 999 -m 700 /var/lib/netp2p/backups

docker compose exec manager netp2pd manager backup \
  --data-dir /var/lib/netp2p \
  --output /var/lib/netp2p/backups/manager-$BACKUP_ID.sqlite

sudo install -d -m 700 /var/backups/netp2p
sudo cp /var/lib/netp2p/backups/manager-$BACKUP_ID.sqlite \
  /var/backups/netp2p/manager-$BACKUP_ID.sqlite
sudo tar -C / -czf /var/backups/netp2p/manager-$BACKUP_ID-config.tgz \
  /etc/netp2p /var/lib/netp2p/dkg-share-*.json
```

The `manager backup` command creates a transactionally consistent SQLite backup
and refuses an empty ledger. Record the image digest, BFT height, and state hash
with the backup set, then transfer both files to your approved encrypted backup
store.

## When to back up

Back up at a quiet point: all managers healthy, equal heights, no in-flight
writes. Record the BFT height and state hash with each backup set. A backup is
only valid after a successful restore drill.

## Restore

Always stop the affected scope first.

### One-node restore

Use when one manager's data is corrupted or its disk is replaced:

1. Stop that manager container:

   ```bash
   docker compose stop manager
   ```

2. Restore `/etc/netp2p` and the matching DKG share from the config archive.
3. Stage the backup inside the manager data volume and restore it:

   ```bash
   sudo install -o 999 -g 999 -m 600 \
     /var/backups/netp2p/manager-BACKUP_ID.sqlite \
     /var/lib/netp2p/.restore-manager.sqlite

   docker compose run --rm manager manager restore \
     --backup /var/lib/netp2p/.restore-manager.sqlite \
     --data-dir /var/lib/netp2p \
     --overwrite

   sudo rm /var/lib/netp2p/.restore-manager.sqlite
   ```

4. Start the manager:

   ```bash
   docker compose start manager
   ```

5. Verify catch-up, height equality, and `3/3` connectivity.

### Committee-wide restore

Use when multiple managers are corrupted or you need to return to a prior state:

1. Schedule a maintenance window.
2. Stop all three managers together.
3. Restore the same coherent backup set on all three.
4. Recreate all containers without starting.
5. Require matching heights and state hashes, `3/3` connectivity, successful
   login, snapshot validation, and a client traffic probe before resuming.

Never restore a one-node old snapshot over a newer ledger.

## Validate a restore

After any restore:

1. Poll `/readyz` on all three managers and require HTTP 200, `ready`,
   `ledgerReady=true`, and `3/3` committee connectivity.
2. Confirm all three managers report the same height and state hash.
3. Sign in to the console with a valid account.
4. Run `netp2p up` and `netp2p status --json` on a test client.
5. Probe another allowed peer in both directions with `netp2p ping`.
6. Submit one low-risk configuration change and confirm the certified height
   increases only after the committee reports ready.
