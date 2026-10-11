# Docker client

Run a NetP2P peer inside a Docker container.

## Outcome

A containerized peer joined to the overlay with userspace or TUN networking.

## Prerequisites

- Docker Engine
- A NetP2P client binary (from the Linux tarball or built locally); a prebuilt
  client image is not published yet
- A setup key from a NetP2P administrator

## Userspace mode (no TUN)

Works without privileged mode. The peer uses a userspace UDP packet endpoint
instead of a kernel interface.

Create a versioned runtime config and mount the setup key as a read-only file.
Use every manager endpoint so the daemon can fail over without recreating the
container:

```yaml
version: 1
role: client
dataDir: /var/lib/netp2p
network: example-network
managerEndpoints:
  - /dns4/manager-1.netp2p.example/udp/4001/quic-v1
  - /dns4/manager-2.netp2p.example/udp/4001/quic-v1
  - /dns4/manager-3.netp2p.example/udp/4001/quic-v1
setupKeyFile: /run/secrets/netp2p-setup-key
noTun: true
dnsManageResolvConf: false
```

Then run the container:

```bash
docker run -d --name netp2p-client \
  -v netp2p-data:/var/lib/netp2p \
  -v ./runtime.yaml:/etc/netp2p/runtime.yaml:ro \
  -v ./setup-key:/run/secrets/netp2p-setup-key:ro \
  <your-netp2p-image> \
  netp2pd --config-file /etc/netp2p/runtime.yaml
```

Provisioning runs at container start. Put the setup-key file in your secret
manager and avoid passing it as a command-line argument or environment variable.

## TUN mode

For a kernel interface inside the container:

```bash
docker run -d --name netp2p-client \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v netp2p-data:/var/lib/netp2p \
  -v ./runtime-tun.yaml:/etc/netp2p/runtime.yaml:ro \
  -v ./setup-key:/run/secrets/netp2p-setup-key:ro \
  <your-netp2p-image> \
  netp2pd --config-file /etc/netp2p/runtime.yaml
```

For TUN mode, set `noTun: false` in `runtime.yaml`.

## Validate

From another peer (or via `docker exec`):

```bash
docker exec netp2p-client netp2p status --config /etc/netp2p/runtime.yaml
docker exec netp2p-client netp2p ping <peer-overlay-ip> --config /etc/netp2p/runtime.yaml
```

## Upgrade and rollback

1. Record the current image digest and capture `netp2p status --json`.
2. Stop and remove the container; do not remove `netp2p-data`.
3. Start a container from the pinned new image with the same config, secret
   mount, and data volume.
4. Run `status`, `doctor`, and a bidirectional peer probe.

To roll back, repeat the procedure with the previous digest. If the new daemon
changed local state unexpectedly, stop it before restoring a client-profile
debug bundle.

## Uninstall

```bash
docker exec netp2p-client netp2p down --config /etc/netp2p/runtime.yaml
docker rm --force netp2p-client
docker volume rm netp2p-data
```

Removing the volume deletes the peer identity and certified profile. Omit the
second command if you are only replacing the container.

## Notes and limits

- Exit nodes and subnet routes require TUN mode plus `iptables` in the image.
- Without `--no-tun` and without `/dev/net/tun`, the daemon logs an explicit
  warning and falls back to userspace mode.
- The test image built by `scripts/e2e.sh` includes `iptables` for exit-node
  testing; production images should do the same if routing is needed.
- The named volume preserves identity and certified state across container
  recreation. Do not pass `-v` to `docker rm`, and delete the volume only when
  you are retiring the peer.
