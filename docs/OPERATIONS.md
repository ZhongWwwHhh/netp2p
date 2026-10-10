# NetP2P Operations

This runbook covers the three-manager deployment in `../../ansible/netp2p`. It
assumes release artifacts have already been built and published.

## Operating model

The production committee is fixed at `n=3`, `f=0`, and quorum `3`. All three
managers must be online for writes. A single manager outage or restart makes
the committee read-only until all three are reachable again.

Public endpoints:

| Endpoint | IPv4 | Use |
| --- | --- | --- |
| `fr.netp2p.zhongwwhhhh.cc` | `193.42.62.111` | Manager, FR |
| `sg.netp2p.zhongwwhhhh.cc` | `45.127.32.84` | Manager, SG |
| `us-phx.netp2p.zhongwwhhhh.cc` | `129.146.72.228` | Manager, US-PHX |
| `netp2p.zhongwwhhhh.cc` | all three | Round-robin console bootstrap only |

The root name is not health-aware. Prefer a specific manager endpoint for
diagnostics and client bootstrap.

All records are grey-cloud (`proxied: false`); Cloudflare does not proxy QUIC
or WebRTC.

Ports opened by the current Ansible firewall task:

| Port | Protocol | Exposure |
| --- | --- | --- |
| `4001` | UDP | Public QUIC |
| `4101` | UDP | Public WebRTC |
| `9443` | TCP | Public HTTPS |
| `18080` | TCP | Loopback manager web |
| `9101` | TCP | Metrics, restricted to `129.146.72.228` |

IPv6 inbound traffic on these ports is rejected. Ansible validates that every
manager in the production manifest uses
`/ip4/0.0.0.0/udp/4101/webrtc-direct`, matching the firewall rule.

Caddy terminates HTTPS on `9443` with Cloudflare DNS-01 and proxies to the
loopback manager web listener on `18080`.

The firewall rules are installed as `netp2p-firewall.service`.

Each manager runs in Docker Compose with host networking, a read-only root
filesystem, `tmpfs` on `/tmp`, user `999:999`, and restart policy
`unless-stopped`. The stop grace period is `30s`.

## Artifacts and digest pinning

Build local release artifacts from one commit:

```bash
cd netp2p
make release VERSION=x.y.z
```

For deployment, push tag `vx.y.z`. The release workflow then publishes the
manager and Caddy images to GHCR plus the Linux packages, Windows MSI,
checksums, SBOM, and image-digest files. Record the manager image digest:

```bash
docker buildx imagetools inspect ghcr.io/zhongwwwhhh/netp2p-manager:x.y.z \
  --format '{{.Manifest.Digest}}'
```

Put that value in `ansible/netp2p/vars/main.yml` as
`netp2p_manager_image_digest`, and pin the Caddy digest from
`netp2p-caddy-<version>-image-digest.txt` as `netp2p_proxy_image_digest`.
The install, upgrade, and rollback playbooks refuse an empty or non-`sha256`
digest.

## First bootstrap

1. Build and publish the manager image and client packages.
2. On a trusted admin machine, generate production trust material:
   - one public `NetworkManifest`
   - one private `ManagerBundle` for each of `manager-fr`, `manager-sg`, and
     `manager-us-phx`
   - one secret-free `ClientTrust` bundle

   Use `netp2p init production`; do not use `netp2p init network`, which is
   only a development seed generator.

   ```bash
   netp2p init production \
     --output-dir ./netp2p-production-bootstrap \
     --manager fr,fr.netp2p.zhongwwhhhh.cc,193.42.62.111,4001 \
     --manager sg,sg.netp2p.zhongwwhhhh.cc,45.127.32.84,4001 \
     --manager us-phx,us-phx.netp2p.zhongwwhhhh.cc,129.146.72.228,4001
   ```

3. Store the trust material in the NetP2P Ansible vault:
   - `vault_netp2p_manifest_json`
   - `vault_netp2p_manager_bundles`, keyed by manager ID
   - `vault_netp2p_client_trust_json`

   Treat the manager bundles as root-of-trust material and do not commit them
   to Git.
4. Publish DNS:

   ```bash
   cd ../ansible
   ansible-playbook netp2p/playbooks/dns.yaml
   ```

5. Install the managers:

   ```bash
   ansible-playbook netp2p/playbooks/install.yaml
   ```

6. Open `https://fr.netp2p.zhongwwhhhh.cc:9443`.
7. Complete first-run owner creation in the console. The owner account is
   created through `/api/v1/bootstrap/owner` only while no owner exists.
8. As the owner, create the first setup key in the console, store it as
   `vault_netp2p_setup_key`, and use it to join the first client.

## Atomic deployment and maintenance

Never use a rolling restart. The supported sequence is:

1. Stop console and CLI writes.
2. Stop all three managers.
3. Pre-pull and recreate all three containers.
4. Start all three together.
5. Validate health, quorum, protocol version, and height.

`install.yaml` pre-pulls both images, recreates all three containers, and starts
them together. `upgrade.yaml` additionally stops every manager before changing
the image. For a manual maintenance window:

```bash
ansible netp2p_managers -b -m command \
  -a "docker compose --project-directory /opt/netp2p stop"

ansible netp2p_managers -b -m command \
  -a "docker compose --project-directory /opt/netp2p start"
```

Upgrade with:

```bash
ansible-playbook netp2p/playbooks/upgrade.yaml
```

Set the new image digest before running it. The playbook uses
`any_errors_fatal: true` and `max_fail_percentage: 0`.

## Deployment validation

From the Ansible controller:

```bash
curl -fsS https://fr.netp2p.zhongwwhhhh.cc:9443/healthz
curl -fsS https://sg.netp2p.zhongwwhhhh.cc:9443/healthz
curl -fsS https://us-phx.netp2p.zhongwwhhhh.cc:9443/healthz
```

Check the public bootstrap document on each manager:

```bash
curl -fsS https://fr.netp2p.zhongwwhhhh.cc:9443/api/bootstrap | jq .
```

Require:

- `committee` has exactly three members.
- `version` is `3.0.0`.
- HTTPS succeeds on all three endpoints.

On each manager:

```bash
docker compose --project-directory /opt/netp2p ps
curl -fsS http://127.0.0.1:9101/metrics | grep -E \
  'netp2p_bft_height|netp2p_bft_commits_total|go_goroutines|process_resident_memory_bytes'
```

`netp2p_bft_height` must be greater than zero after genesis.

## Linux client installation

Install with Ansible:

```bash
ansible-playbook netp2p/playbooks/client-install.yaml \
  -e target=netp2p_clients_linux
```

For a manual install:

```bash
sudo dpkg -i dist/netp2p_<version>_amd64.deb
# or
sudo rpm -ivh dist/netp2p-<version>.x86_64.rpm
```

Put the setup key in `/etc/netp2p/setup-key` with mode `0600`, then edit
`/etc/netp2p/runtime.yaml`:

```yaml
version: 1
role: client
network: netp2p
dataDir: /var/lib/netp2p
listen: /ip4/0.0.0.0/udp/0/quic-v1
manager: /dns4/fr.netp2p.zhongwwhhhh.cc/udp/4001/quic-v1/p2p/<manager-peer-id>
setupKeyFile: /etc/netp2p/setup-key
packetListen: 127.0.0.1:51820
tun: netp2p0
tunMtu: 1280
dnsListen: 127.0.0.1:53
dnsManageResolvConf: true
```

Start the packaged service:

```bash
sudo systemctl enable --now netp2p-client
sudo netp2p status --json
```

The package installs `netp2p-client.service`, matching the Ansible client
playbook.

## Windows client installation

Install the MSI:

```powershell
msiexec /i netp2p-<version>-windows-amd64.msi /qn
```

The MSI installs:

- `C:\Program Files\NetP2P\netp2pd.exe`
- `C:\Program Files\NetP2P\netp2p.exe`
- the `NetP2PClient` Windows service
- the Wintun DLL
- the tray startup shortcut

Edit `C:\ProgramData\netp2p\runtime.yaml`, then restart the service:

```powershell
Restart-Service NetP2PClient
& 'C:\Program Files\NetP2P\netp2p.exe' status --json
```

The MSI and Ansible both use `C:\ProgramData\netp2p\runtime.yaml`.

## Client states

| State | Meaning | Operator action |
| --- | --- | --- |
| `ready` | Login, certified snapshot, TUN, and routes are ready | None |
| `degraded` | A validated snapshot is cached, but manager sync is unavailable | Restore manager quorum |
| `needs-login` | No valid login or setup-key session | Run `netp2p login` |
| `failed` | No usable client state | Run `netp2p doctor` and inspect logs |

Useful client commands:

```bash
netp2p status --json
netp2p ip
netp2p ping <overlay-ip>
netp2p netcheck
netp2p doctor
netp2p debug bundle
```

Ansible installs a three-manager `trust.json` and renders `trust:` in the
client runtime. The daemon loads every endpoint from that bundle, uses them as
libp2p static relays, pins their hosts to the underlay, and fails over between
them without falling back to an untrusted manager.

## Backup and restore

The manager SQLite ledger can be backed up without stopping the manager:

```bash
netp2pd manager backup \
  --data-dir /var/lib/netp2p \
  --output /backup/netp2p-manager-$(date +%Y%m%d%H%M%S).sqlite
```

The command refuses an empty ledger and does not overwrite an existing output.
It uses SQLite `VACUUM INTO`, so the backup is transactionally consistent even
if WAL writes are active.

Restore only while the matching manager is stopped:

```bash
docker compose --project-directory /opt/netp2p stop
netp2pd manager restore \
  --backup /backup/netp2p-manager-<timestamp>.sqlite \
  --data-dir /var/lib/netp2p \
  --overwrite
docker compose --project-directory /opt/netp2p start
```

The restore validates that the backup contains a certified ledger. A target
database must not exist, or the operator must explicitly pass `--overwrite`.
The old database is staged as `manager.sqlite.pre-restore` until the restored
database is installed.

For a complete node backup, also archive trust material and DKG shares:

```bash
docker compose --project-directory /opt/netp2p stop
sudo tar --numeric-owner -czf /backup/netp2p-$(date +%Y%m%d%H%M%S).tar.gz \
  /etc/netp2p /var/lib/netp2p
docker compose --project-directory /opt/netp2p start
```

This captures:

- `/var/lib/netp2p/manager.sqlite`
- SQLite WAL and SHM files
- DKG share files
- `/etc/netp2p/network.json`
- `/etc/netp2p/manager-<manager-id>.json`
- runtime and Caddy configuration

Restore on all three managers only during a maintenance window:

```bash
docker compose --project-directory /opt/netp2p stop
sudo tar --numeric-owner -xpf /backup/netp2p-<timestamp>.tar.gz -C /
docker compose --project-directory /opt/netp2p start
```

After restore, confirm that all three managers report the same
`netp2p_bft_height` and that `/healthz` returns 200.

### Client profile archive

A diagnostic bundle can include the recoverable client profile:

```bash
netp2p debug bundle --include-profile --output netp2p-profile.zip
```

The profile contains `client/identity.key`, `client/state.json`, and, when
present, `client/paths.json`. The archive is written with owner-only
permissions and the redacted `runtime.json` in the bundle is not itself a
recovery record. Restore it only while the client is stopped:

```bash
netp2p debug restore-profile \
  --archive netp2p-profile.zip \
  --data-dir /var/lib/netp2p \
  --overwrite
```

## Troubleshooting

- Manager writes fail or hang:
  1. Check all three `/healthz` endpoints.
  2. Check `docker compose ps`.
  3. Confirm `netp2p_bft_height` is stable.
  4. Restore the missing manager; do not restart the other two one at a time.
- Client cannot connect:
  1. Run `netp2p doctor`.
  2. Run `netp2p debug bundle`.
  3. Confirm DNS and the manager multiaddr.
  4. Confirm UDP `4001` is reachable.
- Web console unreachable:
  1. Check `docker logs netp2p-proxy`.
  2. Confirm TCP `9443` is open.
  3. Check the Caddy certificate and DNS record.
- Metrics missing:
  1. Check TCP `9101` is allowed only from `129.146.72.228`.
  2. Curl `http://127.0.0.1:9101/metrics` on the manager.
- Firewall mismatch:

  ```bash
  sudo iptables -S NETP2P_INPUT
  sudo ip6tables -S NETP2P_INPUT
  ```

## Rollback

Keep the previous image repository and digest. Roll back with:

```bash
ansible-playbook netp2p/playbooks/rollback.yaml \
  -e netp2p_previous_manager_image=ghcr.io/zhongwwwhhh/netp2p-manager \
  -e netp2p_previous_manager_image_digest=sha256:<old-digest> \
  -e netp2p_previous_proxy_image=ghcr.io/zhongwwwhhh/netp2p-caddy \
  -e netp2p_previous_proxy_image_digest=sha256:<old-digest>
```

The playbook stops all managers, recreates them with the previous digests, and
starts all three together. It does not delete `/var/lib/netp2p` or the trust
material.

After manager rollback, reinstall the matching Linux or Windows client package
