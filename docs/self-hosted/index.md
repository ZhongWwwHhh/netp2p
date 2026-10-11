# Self-host NetP2P

Run your own overlay network with a manager committee, enroll clients, and operate it day to day.

## Start here

| Task | Guide |
| --- | --- |
| Install the manager stack for the first time | [Install](install.md) |
| Upgrade or roll back without breaking the committee | [Upgrade and rollback](upgrade.md) |
| Back up and restore manager state | [Backup and restore](backup-restore.md) |
| Monitor health, metrics, and alerts | [Monitoring](monitoring.md) |

## How the committee works

NetP2P uses a BFT manager committee to certify every network change. The
minimum production shape is three managers with `n=3`, `f=0`, `quorum=3`; a
four-manager deployment uses `n=4`, `f=1`, `quorum=3`:

- A three-manager committee requires all three managers online to accept writes.
- A four-manager committee keeps write quorum with any three managers online.
- Clients keep working with the last certified state while the committee is degraded.
- Losing more managers than the fault allowance blocks enrollment and configuration changes.

This favors consistency over write availability. Plan maintenance windows
accordingly and never stop managers one at a time during a version upgrade.
See [Upgrade and rollback](upgrade.md) for atomic upgrades, manager addition,
and manager removal.

## Example addresses

This documentation uses placeholder addresses throughout:

| Placeholder | Meaning |
| --- | --- |
| `manager-1.netp2p.example` | First manager, `203.0.113.11` |
| `manager-2.netp2p.example` | Second manager, `203.0.113.12` |
| `manager-3.netp2p.example` | Third manager, `203.0.113.13` |
| `manager-4.netp2p.example` | Fourth manager, `203.0.113.14` |
| `console.netp2p.example` | Round-robin console entry |

Replace them with your own DNS names and addresses.
