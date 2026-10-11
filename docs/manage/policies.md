# Policies

Policies define which source groups can reach destination groups, protocols,
and ports.

## Prerequisites

- Source and destination groups already exist.
- Owner or network administrator access.
- The minimum required protocol and port range.

## Policy fields

| Field | Use |
| --- | --- |
| Source groups | Selecting peers or users |
| Destination groups | Reachable peers |
| Services | Protocol plus optional TCP/UDP port range |
| Effect | `allow` or `deny` |
| Direction | `ingress`, `egress`, or `bidirectional` |
| Posture | Peer-advertised labels that must all match |
| Priority | Order for overlapping rules |
| Flow class | Optional path-planning hint |

## Allow SSH from workstations to servers

Create a policy with a shape like:

```json
{
  "id": "workstations-to-servers-ssh",
  "name": "Workstations to servers SSH",
  "sourceGroups": ["workstations"],
  "destinationGroups": ["servers"],
  "services": [{"protocol": "tcp", "startPort": 22, "endPort": 22}],
  "effect": "allow",
  "direction": "bidirectional",
  "priority": 100
}
```

Submit it in the console policy editor, then refresh affected clients.

## Deny a broader rule

Create a higher-priority deny rule for a narrower group or port. For example,
place a deny from `contractors` to `production-database` before a broader allow.
Keep deny rules narrow enough to test and review.

## Validation

On a source peer:

```bash
netp2p up
netp2p ping DESTINATION_OVERLAY_IP
```

Then test the exact TCP or UDP workload. A denied probe is expected when policy
does not allow it.

## Troubleshooting

- **No connectivity**: verify both peers are in policy groups and present.
- **One direction fails**: use a bidirectional policy or add the reverse rule.
- **Too much access**: replace the `0-65535` port range with the minimum range.
- **Posture never matches**: compare peer-advertised labels with policy.
