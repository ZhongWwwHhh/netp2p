# Join a Linux peer

Install the client and enroll a Linux machine with a setup key.

## Prerequisites

- Debian/Ubuntu or RHEL-compatible Linux.
- `systemd`, `iptables`, and `/dev/net/tun` for full TUN mode.
- Manager HTTPS access.
- UDP 4001 and 4101 access.
- A valid setup key and manager endpoint from the administrator.

## Install

Download the release package and install it.

Debian/Ubuntu:

```bash
sudo apt install ./netp2p_VERSION_amd64.deb
```

RHEL-compatible:

```bash
sudo dnf install ./netp2p-VERSION.rpm
```

The package installs `netp2pd`, `netp2p`, a runtime configuration template, and
the `netp2p-client` service. The service starts in `needs-login`.

## Enroll

Put the setup key in a root-readable file, then enroll:

```bash
sudo install -m 600 /dev/null /root/example-setup-key
printf '%s\n' 'PASTE_SETUP_KEY' | sudo tee /root/example-setup-key >/dev/null
sudo netp2p login --manager /dns4/manager-1.netp2p.example/udp/4001/quic-v1 \
  --setup-key-file /root/example-setup-key
sudo netp2p up
rm -f /root/example-setup-key
```

Use the endpoint provided by your administrator. `login` provisions local
identity and certified state; `up` applies it. Do not rerun `login` after an
ordinary restart.

## Validate

```bash
systemctl status netp2p-client
netp2p status
netp2p ip
netp2p doctor
```

Success is `ready` status, an overlay IP, and no failed doctor checks.

## Troubleshooting

- **Service is `needs-login`**: complete `login` and `up`.
- **TUN or permission error**: run the service with administrator capabilities
  and confirm `/dev/net/tun`; use the tarball runtime for a userspace test.
- **Manager unreachable**: check HTTPS, UDP 4001/4101, endpoint syntax, and DNS.
- **Login rejected**: the key may be expired, revoked, exhausted, or policy may
  not admit the peer's assigned group.
