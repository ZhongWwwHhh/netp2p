# Quickstart

This procedure joins one Linux or Windows machine to the production network. You need a valid one-time setup key from an administrator.

## Requirements

- Linux: systemd, `iptables`, and `/dev/net/tun` for kernel networking. The package installs both `netp2pd` and `netp2p`.
- Windows: Windows 10/11 or Server 2019+, administrator rights, and the bundled Wintun driver.
- Reachability: UDP 4001 and 4101 to managers, HTTPS 9443 to the chosen manager endpoint.

## 1. Install Linux

Download the matching `netp2p_VERSION_amd64.deb` or RPM from the release. Replace `VERSION` and the package name with the release values.

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install ./netp2p_*_amd64.deb
```

RHEL/compatible:

```bash
sudo dnf install ./netp2p-*.rpm
```

The service starts idle in `needs-login` state. For an unprivileged test without systemd, unpack the Linux tarball and run `./netp2pd --role client --config runtime.yaml`.

## 2. Install Windows

Download `netp2p-$VERSION-windows-amd64.msi` from the release. Run the MSI as administrator. It installs:

- `C:\Program Files\NetP2P\bin\netp2pd.exe`
- `C:\Program Files\NetP2P\bin\netp2p.exe`
- the NetP2P Windows service
- the Wintun-based client runtime

Start `netp2p tray` for status and console access if it is not running. PowerShell examples below use the installed CLI; run them from an elevated PowerShell.

## 3. Join

Linux:

```bash
sudo netp2p login --manager /dns4/console.netp2p.example/udp/4001/quic-v1 --setup-key-file /path/to/setup-key
sudo netp2p up
```

Windows:

```powershell
netp2p login --manager <manager-endpoint-from-administrator> --setup-key-file C:\secure\setup-key.txt
netp2p up
```

The exact `--manager` value is provided with the setup key. The key is used once by `login`; keep it in a protected file and delete it after enrollment.

## 4. Verify

```bash
netp2p status
netp2p status --json
netp2p ip
netp2p ping <peer-overlay-ip>
netp2p doctor
```

Linux service checks:

```bash
systemctl status netp2p-client
journalctl -u netp2p-client -f
```

Windows service checks:

```powershell
Get-Service NetP2P
Get-Content "$env:ProgramData\NetP2P\logs\netp2pd.log" -Tail 100
```

Success means `status` reports `ready`, `ip` prints an overlay address, and `ping` receives replies from an allowed peer. Directional policy can legitimately make one direction succeed while the reverse is denied.

## 5. Disconnect or reset

```bash
netp2p down
netp2p logout
```

`down` removes the overlay route/DNS configuration. `logout` clears local enrollment material. Do not use `logout` for a temporary stop.
