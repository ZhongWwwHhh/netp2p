# Join a Windows peer

Install the MSI and enroll Windows 10/11 or Windows Server 2019+.

## Prerequisites

- Administrator rights.
- Manager HTTPS access.
- UDP 4001 and 4101 access.
- A valid setup key and manager endpoint from the administrator.

## Install

Download `netp2p-VERSION-windows-amd64.msi`, verify its checksum, and run it as
administrator. The installer registers the NetP2P service, installs the CLI and
daemon, and prepares Wintun-based networking.

## Enroll

Open an elevated PowerShell window, enroll, connect, and delete the temporary
key file:

```powershell
$key = Join-Path $env:TEMP 'example-setup-key.txt'
Set-Content -NoNewline -Encoding ascii $key 'PASTE_SETUP_KEY'
netp2p login --manager /dns4/manager-1.netp2p.example/udp/4001/quic-v1 `
  --setup-key-file $key
netp2p up
Remove-Item $key
```

Use the endpoint supplied by your administrator. `login` persists local identity
and certified state; `up` connects. Reboots do not require `login` again.

## Validate

```powershell
Get-Service NetP2P
netp2p status
netp2p ip
netp2p doctor
```

Success is a running service, `ready` status, an overlay IP, and no failed
doctor checks.

## Troubleshooting

- **Service is `needs-login`**: complete `login` and `up`.
- **Wintun or service error**: run `netp2p doctor` before changing adapters,
  firewalls, antivirus, or NRPT.
- **Manager unreachable**: check HTTPS, UDP 4001/4101, endpoint syntax, and DNS.
- **Login rejected**: check expiry, revocation, usage limit, and policy groups.
