# Windows client

Install and run NetP2P on Windows 10/11 or Server 2019+.

## Outcome

The NetP2P Windows service in `ready` state with Wintun networking and a
working overlay IP.

## Prerequisites

- Windows 10/11 or Server 2019+
- Administrator rights for install and service/network configuration
- Wintun driver (installed by the MSI)
- A setup key from a NetP2P administrator
- UDP 4001/4101 and TCP 9443 reachability to the manager

## Install

Run the release MSI as administrator. It installs:

- `C:\Program Files\NetP2P\bin\netp2pd.exe`
- `C:\Program Files\NetP2P\bin\netp2p.exe`
- the NetP2P Windows service
- Wintun-based networking and NRPT DNS integration

The service starts idle in `needs-login`.

## Join

From elevated PowerShell:

```powershell
netp2p login --manager <manager-endpoint> --setup-key-file <setup-key-path>
netp2p up
Remove-Item <setup-key-path>
```

Identity persists across service restarts and reboots. Do not rerun `login`
after a normal restart.

## Daily commands

```powershell
netp2p status
netp2p status --json
netp2p ip
netp2p ping <peer-overlay-ip>
netp2p doctor
netp2p netcheck
netp2p down
netp2p debug bundle
netp2p service status
netp2p tray
```

The tray shows state and connect/disconnect actions and can open the WebUI.

## Service and files

```powershell
Get-Service NetP2P
Restart-Service NetP2P
Get-Content "$env:ProgramData\NetP2P\logs\netp2pd.log" -Tail 200
```

Use `netp2p doctor` before changing Wintun, firewall, NRPT, antivirus, or
VPN-adapter settings.

## Upgrade and rollback

1. Capture `netp2p status --json`.
2. Run the new MSI over the old installation.
3. Restart the NetP2P service.
4. Confirm version, protocol, `ready`, overlay IP, and bidirectional traffic.

To roll back, stop/disable the service, install the prior MSI, and restart.
Preserve the client profile unless intentionally re-enrolling.

## Uninstall

```powershell
netp2p down
netp2p service stop
```

Then remove NetP2P from **Settings > Apps** or `msiexec /x <product-code>`.
Verify the service, adapter, and NRPT rules are gone if uninstall was
interrupted.
