# Peer connectivity issues

Fix problems where peers cannot reach each other.

## Symptoms

- `netp2p ping` gets no replies
- A to B works but B to A fails (or vice versa)
- TCP to a service port fails while ping works

## Diagnosis

Test both directions and both protocols:

```bash
netp2p ping <peer-overlay-ip>
nc -vz <peer-overlay-ip> <tcp-port>
```

On Windows, use `netp2p ping` and `Test-NetConnection <peer-overlay-ip> -Port
<tcp-port>` from an elevated PowerShell window.

On each client:

```bash
netp2p status --json
netp2p netcheck
netp2p doctor
```

Then check manager readiness (see the [help index](index.md)) and inspect
policy, routes, and peer presence in the console.

## Fixes

| Finding | Action |
| --- | --- |
| One direction only | Check directional policy, local host firewall, return-path routing |
| Both directions fail, status shows `ready` | Verify certified policy and group membership; peer may be blocked by policy |
| Direct path fails, NAT type restrictive | Verify certified settings allow direct; check firewall for UDP 4001/4101 |
| Via-manager fails | Check manager forwarding, quotas, queue/drop metrics |
| Peer shows `direct` but probe fails | Status display is not proof; rely on actual probe results |

## Data points that matter

* Overlay IPs of both peers (from `netp2p ip`)
* Path type per peer (`direct`, `via-manager`, or `multi-hop`)
* Forwarding drop counters
* The exact policy that should allow the flow
