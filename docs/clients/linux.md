# Linux client

## Install

Install the release DEB on Debian/Ubuntu:

```bash
sudo apt install ./netp2p_*_amd64.deb
```

Install the RPM on RHEL/Fedora-compatible systems:

```bash
sudo dnf install ./netp2p-*.rpm
```

The package installs `/usr/bin/netp2pd`, `/usr/bin/netp2p`, `/etc/netp2p/runtime.yaml`, and `netp2p-client.service`. It requires `iptables`; full TUN mode additionally requires `/dev/net/tun` and `CAP_NET_ADMIN`.

The service starts idle and reports `needs-login` until provisioned.

## Join

Write the setup key to a root-readable file, then run:

```bash
sudo netp2p login --manager <manager-endpoint> --setup-key-file /root/setup-key
sudo netp2p up
rm -f /root/setup-key
```

The service stores identity and certified profile under `/var/lib/netp2p` with restrictive permissions. Restarting the service reuses that local identity and syncs certified state; do not delete the data directory for a normal restart.

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

`login` provisions; `up` connects; `down` disconnects and restores host networking; `logout` removes enrollment material.

## Service and files

```bash
systemctl status netp2p-client
sudo systemctl restart netp2p-client
journalctl -u netp2p-client -f
```

Important paths:

- `/etc/netp2p/runtime.yaml`: runtime config
- `/var/lib/netp2p`: identity, certified profile, and state
- `/run/netp2p/netp2pd.sock`: CLI-to-daemon IPC

Do not edit identity/profile files manually. Change runtime settings through the package template or documented provisioning flow.

## Upgrade and rollback

1. Capture `netp2p status --json` and confirm `ready`.
2. Install the new DEB/RPM.
3. Restart the service.
4. Confirm protocol/version, `ready`, the same overlay IP, and traffic.

Roll back by installing the previous package and restarting. Preserve `/var/lib/netp2p` unless intentionally re-enrolling. Reconcile packaged runtime-config examples explicitly; do not overwrite local enrollment files.

## Uninstall

```bash
sudo netp2p down
sudo apt remove netp2p      # Debian/Ubuntu
sudo dnf remove netp2p      # RHEL-family
```

Package removal scripts stop the service and perform managed cleanup. Back up `/var/lib/netp2p` only if you deliberately need the old client identity.
