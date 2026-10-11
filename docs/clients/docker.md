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
instead of a kernel interface:

```bash
docker run -d --name netp2p-client \
  -v netp2p-data:/var/lib/netp2p \
  <your-netp2p-image> \
  netp2pd --role client --no-tun \
  --manager <manager-endpoint> \
  --setup-key <setup-key>
```

Provisioning runs at container start. The setup key is consumed once; store it
in a secret manager rather than a plain environment variable in production.

## TUN mode

For a kernel interface inside the container:

```bash
docker run -d --name netp2p-client \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v netp2p-data:/var/lib/netp2p \
  <your-netp2p-image> \
  netp2pd --role client \
  --manager <manager-endpoint> \
  --setup-key <setup-key>
```

## Validate

From another peer (or via `docker exec`):

```bash
docker exec netp2p-client netp2p status
docker exec netp2p-client netp2p ping <peer-overlay-ip>
```

## Notes and limits

- Exit nodes and subnet routes require TUN mode plus `iptables` in the image.
- Without `--no-tun` and without `/dev/net/tun`, the daemon logs an explicit
  warning and falls back to userspace mode.
- The test image built by `scripts/e2e.sh` includes `iptables` for exit-node
  testing; production images should do the same if routing is needed.
