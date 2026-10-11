# Manage NetP2P

Administrators use the web console to manage certified network state. Every
accepted change is committed by the BFT committee and becomes a new certified
height.

## Common tasks

| Task | Guide |
| --- | --- |
| Bootstrap owner or sign in | [Console access](console-access.md) |
| Control who can manage and connect | [Users and groups](users-and-groups.md) |
| Allow or deny traffic | [Policies](policies.md) |
| Publish subnets or exit access | [Routes](routes.md) |
| Resolve overlay names and private records | [DNS](dns.md) |
| Enroll machines safely | [Setup keys](setup-keys.md) |
| Inspect peers, health, events, and audit | [Peers and diagnostics](peers-and-diagnostics.md) |

## Safe change workflow

1. Confirm the manager and committee are healthy and quorum is available.
2. Make one scoped group, policy, route, DNS, or setup-key change.
3. Refresh the certified snapshot and confirm the height increased.
4. Probe from an affected client.
5. Review the activity event for the change.

## Permissions

The owner role has full access. Admin, network admin, auditor, usage viewer, and
user roles have narrower permissions. The console session response exposes the
effective permission matrix.
