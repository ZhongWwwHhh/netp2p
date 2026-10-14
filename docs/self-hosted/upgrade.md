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

4. Stop all three manager containers together. These examples assume the Compose
   service is named `manager`:

   ```bash
   docker compose stop manager
   ```

5. Start all three managers together:

   ```bash
   docker compose start manager
   ```

6. Validate each `/readyz`, confirm equal heights, HTTPS, metrics, and run a
   client login plus traffic probe.
7. Keep the previous digest and backup until soak validation passes.

Never roll one manager at a time for a committee upgrade.

For releases that change RoutingEpoch signing, upgrade managers and clients in
the same maintenance window. NetP2P v0.3.9 replaces the legacy single-manager
Ed25519 routing epoch with committee threshold signatures; older clients must
not remain on the removed signing path after the managers are activated.

## Add a manager

NetP2P separates discovery from trust:

1. A manager join token lets a candidate reach an existing manager.
2. The candidate submits a signed join request.
3. An owner or network administrator approves it in the console.
4. Existing managers and the candidate run a fresh DKG ceremony.
5. The committee certifies an `activate_committee` transition for the next epoch.

On a trusted administrator machine, generate a private join bundle for the new
host:

```bash
netp2p init manager-join \
  --manifest ./network.json \
  --manager-bundle ./manager-1.json \
  --join-token-file ./manager-join-token.txt \
  --manager manager-4,manager-4.netp2p.example,203.0.113.14,4001 \
  --init-domain console.netp2p.example \
  --output ./manager-4-join.json
```

Copy only that bundle to the new host, then start the candidate:

```bash
netp2pd manager join \
  --bundle /etc/netp2p/manager-join.json \
  --data-dir /var/lib/netp2p
```

Open **Committee → Manager join requests** in the console and approve the
candidate. After activation, verify the new manager's `/readyz` endpoint and the
committee's certified size and epoch.

For headless operation, approve or reject the pending request with the admin CLI:

```bash
netp2pd --role admin \
  --manager /dns4/manager-1.netp2p.example/udp/4001/quic-v1/p2p/<manager-1-peer-id> \
  --admin-token "$NETP2P_ADMIN_TOKEN" \
  --action approve-manager-join \
  --target manager-4
```

After an activation consumes the join token, rotate it before enrolling another
candidate. The JSON input contains the new plaintext token only long enough for
the CLI to derive its verifier:

```bash
netp2pd --role admin \
  --manager /dns4/manager-1.netp2p.example/udp/4001/quic-v1/p2p/<manager-1-peer-id> \
  --admin-token "$NETP2P_ADMIN_TOKEN" \
  --action rotate-manager-join-token \
  --file ./manager-join-token.json
```

The join token is an enrollment convenience, not a trust decision. A leaked token
can only create a pending request; it cannot add the candidate to the committee
without administrator approval.

## Remove a manager

Before removing a manager, back up every remaining manager and confirm the next
committee still meets quorum. Submit a committee update from the console only
after the target manager has stopped receiving client traffic. Keep the removed
host's identity and DKG share offline in case a rollback is required.

## Rollback steps

1. Announce another maintenance window.
2. Back up current state.
3. Stop all three managers together.
4. Revert image/config pins to the prior tested release. Preserve
   `/var/lib/netp2p`, manager identity, seed/share material, and ledger history.
5. Recreate all three without starting:

   ```bash
   docker compose create --force-recreate
   ```

6. Start all three together, then re-run readiness and client checks.

Do not restore a single-node old snapshot over a newer committee ledger.
Committee-wide restore requires the [backup/restore procedure](backup-restore.md).
