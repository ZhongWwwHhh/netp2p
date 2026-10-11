# Troubleshooting

Start with exact outputs and change one variable at a time. Version, protocol, and clock mismatches often look like network errors.

## First pass

```bash
netp2p status --json
netp2p doctor
netp2p netcheck
```

For each manager:

```bash
curl -fsS https://manager-1.netp2p.example:9443/readyz
curl -fsS https://manager-2.netp2p.example:9443/readyz
curl -fsS https://manager-3.netp2p.example:9443/readyz
```

Record versions, protocol, BFT height, quorum, committee connectivity, client state, and overlay IP.

## WebUI/login

| Symptom | Cause/action |
| --- | --- |
| Certificate warning | wrong direct host or expired/missing DNS-01 cert; check Caddy and DNS |
| Round-robin URL fails | it is not health-aware; retry or use a direct node URL |
| `needsOwner` true | bootstrap first owner through console/API |
| `owner already exists` | owner exists; sign in or use controlled credential recovery |
| 401 | expired/invalid cookie or bearer token; sign in again |
| 429/locked | five failed attempts; wait 15 minutes, then use controlled recovery |
| Password forgotten | no self-service reset; use owner/CLI-controlled recovery and keep an audit trail |

Never expose a password or admin token in a troubleshooting command, log, or ticket.

## Committee and writes

- If writes time out, check all three `/readyz` endpoints; 3-of-3 requires every manager.
- If heights differ, identify the lagging manager and let it catch up. Do not submit more transitions.
- A manager can be alive but not ready. `/healthz` alone is not evidence of quorum.
- Restart only the failed manager for recovery. Restart all three together only for a committee-wide upgrade/restore.

## Client enrollment

- `needs-login`: run `login` with a valid setup key and manager endpoint.
- Setup key rejected: check expiry/use count, target groups, protocol, and manager reachability.
- Login loops: capture debug data, then `down`, `logout`, and re-provision. This removes local enrollment; re-check policy afterward.
- Wrong overlay IP: inspect the certified snapshot/profile, not a local cache.

## TUN, routes, and DNS

- Linux: confirm `/dev/net/tun`, `CAP_NET_ADMIN`, `iptables`, and systemd unit logs.
- Windows: run elevated, confirm Wintun installed, service running, and no conflicting VPN/filter driver.
- Route loss after crash: compare intended routes before changing them; use `doctor`, then restart the service for managed cleanup.
- External DNS broken: verify only overlay domains use the NetP2P resolver and upstreams remain reachable.
- Overlay DNS fails: check certified DNS zones/settings and the resolver listener.

Do not manually destroy routes or DNS state while the service is running unless a diagnostic directs it; use `netp2p down` or a service restart first.

## Peer connectivity

Test both directions and both protocols:

```bash
ping <peer-overlay-ip>
nc -vz <peer-overlay-ip> <tcp-port>
```

If A to B succeeds and B to A fails, suspect directional policy, local host firewall, return-path/routing, or admission state. Check certified policy, assignments, presence, and forwarding drop counters. A peer showing a direct path is not proof that a probe succeeds.

If direct fails, verify NAT/netcheck and whether certified settings permit direct. If via-manager fails, verify manager forwarding, quotas, queue/drop metrics, and policy. Multi-hop requires settings and route constraints to allow it.

## Escalation bundle

Include:

1. UTC timestamps.
2. Client and manager versions/protocol.
3. `netp2p status --json`, doctor, and netcheck output.
4. All manager `/readyz` outputs.
5. Relevant logs with secrets redacted.
6. Network topology and exact probes.
7. Last configuration height/event and current metrics.
