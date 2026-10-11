# Windows client

## Install

Run the release MSI as administrator. It installs `netp2pd.exe`, `netp2p.exe`, service registration, Wintun-based networking, and a default runtime profile under `C:\Program Files\NetP2P` and `C:\ProgramData\NetP2P`.

The service starts idle in `needs-login`. Wintun is used for kernel networking; DNS policy integration uses Windows NRPT where configured. Administrator approval is required for service and network configuration.

## Join

From elevated PowerShell:

```powershell
netp2p login --manager <manager-endpoint> --setup-key-file C:\secure\setup-key.txt
netp2p up
Remove-Item C:\secure\setup-key.txt
```

Local identity and certified profile persist across service restarts and reboots. `up` syncs and applies the network; do not rerun `login` after a normal restart.

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

The tray shows state and connect/disconnect actions and can open the WebUI. Run service operations from an elevated shell.

## Service and files

```powershell
Get-Service NetP2P
Restart-Service NetP2P
Get-Content "$env:ProgramData\NetP2P\logs\netp2pd.log" -Tail 200
```

Use `netp2p doctor` before changing Wintun, firewall, NRPT, antivirus, or VPN-adapter settings. `debug bundle` is the first support artifact after removing tokens/secrets.

## Upgrade and rollback

1. Capture `netp2p status --json`.
2. Run the new MSI over the old installation.
3. Restart the NetP2P service.
4. Confirm version, protocol, `ready`, overlay IP, and bidirectional traffic.

To roll back, stop/disable the service, install the prior MSI, and restart. Preserve the client profile unless intentionally re-enrolling. If Wintun or service registration is damaged, uninstall cleanly before reinstalling.

## Uninstall

```powershell
netp2p down
netp2p service stop
```

Then remove NetP2P from **Settings > Apps** or `msiexec /x <product-code>`. Verify the service, adapter, and NRPT rules are gone if uninstall was interrupted.
