# Clients

Connect Linux, Windows, or Docker hosts to a NetP2P network.

## Choose a client

| Platform | Install method | Kernel networking | Guide |
| --- | --- | --- | --- |
| Linux | DEB, RPM, or tarball | TUN (`/dev/net/tun`) | [Linux](linux/index.md) |
| Windows | MSI | Wintun | [Windows](windows/index.md) |
| Docker | Local image or tarball in your container | userspace (`--no-tun`) or TUN device | [Docker](docker.md) |

All clients share the same CLI: `netp2pd` is the long-running daemon and
`netp2p` is the user CLI that talks to it over local IPC.

## Join flow

Every client follows the same pattern:

1. Install the package or binary.
2. Run `netp2p login` with a manager endpoint and a setup key from an administrator.
3. Run `netp2p up` to sync, apply routes/DNS, and connect.
4. Verify with `netp2p status` and `netp2p ping <peer-overlay-ip>`.

The daemon stores identity and the certified profile locally. Reboots and
service restarts reuse them; only `logout` removes enrollment.

## Supported and not available

Implemented today: setup-key enrollment, TUN or userspace networking, overlay
DNS, status/doctor/netcheck, manager failover, and bidirectional peer probes.

Not yet available: macOS PKG, mobile clients, auto-update, and multi-profile
support. See the [roadmap](../roadmap.md) for planned work.
