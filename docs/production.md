# Production deployment

## Committee

Production runs three manager committee members:

| Node | Direct WebUI | Public IPv4 |
| --- | --- | --- |
| `fr` | <https://manager-1.netp2p.example:9443/> | `203.0.113.11` |
| `sg` | <https://manager-2.netp2p.example:9443/> | `203.0.113.12` |
| `us-phx` | <https://manager-3.netp2p.example:9443/> | `203.0.113.13` |

Primary round-robin entry: <https://console.netp2p.example:9443/>.

Committee parameters are `n=3`, `f=0`, `quorum=3`. Every write needs all three managers. Losing any node makes the control plane read-only/degraded; clients may continue using already-certified data-plane policy, but cannot enroll peers or change state until the node returns.

## Network exposure

| Port | Protocol | Purpose |
| --- | --- | --- |
| 4001/udp | public | libp2p QUIC control/data |
| 4101/udp | public | WebRTC/bootstrap |
| 9443/tcp | public | Caddy HTTPS to embedded WebUI/API |
| 18080/tcp | loopback | manager web listener behind Caddy |
| 9101/tcp | restricted | Prometheus metrics |

DNS is grey-cloud/direct. Do not enable Cloudflare proxy for manager names; it does not carry the required QUIC/WebRTC paths.

## Runtime layout

Ansible deploys `/opt/netp2p` for Docker Compose, `/etc/netp2p` for runtime configuration, and `/var/lib/netp2p` for SQLite/DKG/ledger data. Manager containers run read-only as `999:999` without `NET_ADMIN`; Caddy listens publicly on 9443 and proxies to `127.0.0.1:18080`. Images are pinned by digest, not `latest`.

## Health before changes

Check all direct endpoints:

```bash
for h in fr sg us-phx; do
  curl -fsS "https://${h}.console.netp2p.example:9443/readyz"
done
```

Require HTTP 200, `ready`, equal BFT heights, committee/quorum values `3/3`, and ledger readiness. `/healthz` only proves process liveness and is not sufficient before an upgrade.

## Atomic upgrade

Never roll one manager at a time. A rolling stop necessarily removes quorum.

1. Back up every manager and test that the archive is readable.
2. Publish and record the new manager/Caddy image digests.
3. Update Ansible digest variables and run syntax/check checks.
4. Pre-pull the same digest on all three nodes.
5. Stop all three managers together.
6. Recreate containers from the pinned digest.
7. Start all three together inside the planned maintenance window.
8. Validate `/readyz`, matching heights, HTTPS, metrics, and client login/traffic.
9. Keep the prior digests and backup until soak validation passes.

## Rollback

1. Announce another maintenance window.
2. Back up current state before changing anything.
3. Stop all three managers together.
4. Revert only image/config pins to the prior tested release; preserve `/var/lib/netp2p`, manager identity, seed/share material, and ledger history.
5. Recreate and start all three together.
6. Repeat readiness and client E2E checks.

Do not restore a one-node old snapshot over a newer committee ledger. Restore the same coherent backup set on all three managers only after stopping the committee.

## Recovery

- One manager down: restore/connect it, then let it catch up. Avoid configuration changes until quorum returns.
- Data corruption on one node: stop that manager, restore its data from the latest committee-wide backup, and restart it for catch-up.
- Corruption on multiple nodes: use the committee-wide maintenance procedure and restore the same backup set on all three.
- Lost seed/share material: follow disaster-recovery and key-rotation procedures before attempting re-genesis.

The 3-of-3 committee favors consistency and a small trusted base over write availability. Four- or seven-member configurations require a tested reconfiguration path before production use.
