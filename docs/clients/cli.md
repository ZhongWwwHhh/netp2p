# NetP2P CLI reference

Commands available on the `netp2p` user CLI (Linux and Windows).

## Commands

| Command | Purpose |
| --- | --- |
| `netp2p login` | Provision with a manager endpoint and setup key |
| `netp2p up` | Sync certified state, apply routes/DNS, connect |
| `netp2p down` | Disconnect and restore host networking |
| `netp2p status` | Show daemon state, overlay IP, peer paths |
| `netp2p status --json` | Machine-readable status |
| `netp2p ip` | Print the local overlay IP |
| `netp2p ping <ip>` | Probe a peer over the overlay |
| `netp2p netcheck` | Report NAT type and reachability |
| `netp2p doctor` | Diagnose TUN, DNS, routes, manager reachability |
| `netp2p debug bundle` | Collect a redacted diagnostics archive |
| `netp2p logout` | Remove local enrollment material |
| `netp2p service status` | Windows: query the service |
| `netp2p tray` | Windows: launch the tray app |
| `netp2p version` | Print client version and protocol |

## States

The daemon reports one of:

| State | Meaning | Next action |
| --- | --- | --- |
| `needs-login` | No enrollment material | Run `netp2p login` |
| `degraded` | Local state present but quorum/sync unavailable | Check manager `/readyz`, retry `up` |
| `ready` | Connected and applying certified state | Normal operation |
| `failed` | Permanent error | Run `netp2p doctor` |

## Exit codes

`0` on success. Non-zero on error with a message on stderr. `doctor` and
`status --json` are safe to script against.
