# Linux client

Install and run NetP2P on a Linux machine with systemd.

## Outcome

A `netp2p-client` systemd service in `ready` state with an overlay IP and
working peer connectivity.

## Prerequisites

- systemd
- `iptables`
- `/dev/net/tun` and `CAP_NET_ADMIN` for kernel networking (or run userspace
  with `--no-tun`)
- A setup key from a NetP2P administrator
- UDP 4001/4101 and TCP 9443 reachability to the manager

## Install

Debian/Ubuntu:

```bash
sudo apt install ./netp2p_*_amd64.deb
```

RHEL/Fedora-compatible:

```bash
sudo dnf install ./netp2p-*.rpm
```

The package installs `/usr/bin/netp2pd`, `/usr/bin/netp2p`,
`/etc/netp2p/runtime.yaml`, and `netp2p-client.service`. The service starts
idle in `needs-login` state.

## Join

```bash
sudo netp2p login --manager <manager-endpoint> --setup-key-file /root/setup-key
sudo netp2p up
rm -f /root/setup-key
```

Identity and certified profile persist under `/var/lib/netp2p`. Reboots and
service restarts reuse them; do not delete the data directory for a normal
restart.

## Daily commands

```bash
netp2p status
netp2p status --json
netp2p ip
netp2p ping <peer-overlay-ip>
netp2p doctor
netp2p netcheck
netp2p down
netp2p debug bundle
```

`login` provisions; `up` connects; `down` disconnects and restores host
networking; `logout` removes enrollment material.

## Service and files

```bash
systemctl status netp2p-client
sudo systemctl restart netp2p-client
journalctl -u netp2p-client -f
```

| Path | Purpose |
| --- | --- |
| `/etc/netp2p/runtime.yaml` | Runtime config |
| `/var/lib/netp2p` | Identity, certified profile, state |
| `/run/netp2p/netp2pd.sock` | CLI-to-daemon IPC |

Do not edit identity/profile files manually.

## Upgrade and rollback

1. Capture `netp2p status --json` and confirm `ready`.
2. Run `netp2p down`, then stop the service.
3. Install the new DEB/RPM.
4. Start the service and run `netp2p up`.
5. Confirm version, protocol, `ready`, the same overlay IP, and traffic.

Roll back by installing the previous package and restarting. Preserve
`/var/lib/netp2p` unless intentionally re-enrolling.

## Uninstall

```bash
sudo netp2p down
sudo systemctl stop netp2p-client
sudo apt remove netp2p      # Debian/Ubuntu
sudo dnf remove netp2p      # RHEL-family
```

Remove `/var/lib/netp2p` only when you are intentionally retiring or
re-enrolling the machine.
