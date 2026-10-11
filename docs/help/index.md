# Help

Find and fix problems by symptom. Start with the general checklist, then open
the page that matches your situation.

## First pass on any problem

Run these on the affected client:

```bash
netp2p status --json
netp2p doctor
netp2p netcheck
```

Check each manager:

```bash
curl -fsS https://manager-1.netp2p.example:9443/readyz
curl -fsS https://manager-2.netp2p.example:9443/readyz
curl -fsS https://manager-3.netp2p.example:9443/readyz
```

Record versions, protocol, BFT height, quorum, committee connectivity, client
state, and overlay IP before changing anything.

## Symptom pages

| Symptom | Page |
| --- | --- |
| Login rejected, setup key invalid, stuck `needs-login` | [Login and enrollment](login-and-enrollment.md) |
| Peer unreachable, ping fails, one direction only | [Connectivity](connectivity.md) |
| DNS broken, wrong name resolution, route loss | [DNS and routes](dns-and-routes.md) |
| Writes time out, committee degraded, height fork | [Manager health](manager-health.md) |

## Escalation checklist

When opening a support request, include:

1. UTC timestamps.
2. Client and manager versions and protocol.
3. `netp2p status --json`, `doctor`, and `netcheck` output.
4. All manager `/readyz` outputs.
5. Relevant logs with secrets redacted.
6. Network topology and exact probes (source, destination, port, result).
7. Last configuration height/event and current metrics.

Never share passwords, setup keys, admin tokens, or private key material.
