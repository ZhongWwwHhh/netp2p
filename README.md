# NetP2P

NetP2P is a decentralized overlay network with a 3-node BFT management committee, libp2p transport, certified network state, policy-based access, routes, DNS, quotas, and client packages for Linux and Windows.

## Production entry points

- Primary WebUI: <https://console.netp2p.example:9443/>
- Direct WebUIs: [fr](https://manager-1.netp2p.example:9443/), [sg](https://manager-2.netp2p.example:9443/), [us-phx](https://manager-3.netp2p.example:9443/)

Use the primary name for normal access. A direct name is useful when diagnosing one manager. Sign in with an owner/administrator account; passwords are never stored in this repository.

## Documentation

Start at the [documentation map](docs/index.md).

| Task | Document |
| --- | --- |
| Install and join | [Quickstart](docs/quickstart.md) |
| Manage the network | [Web console](docs/console.md) |
| Run the production committee | [Production](docs/production.md) |
| Health, metrics, logs, backup | [Operations](docs/operations.md) |
| Security model | [Security](docs/security.md) |
| Linux client | [Linux](docs/clients/linux.md) |
| Windows client | [Windows](docs/clients/windows.md) |
| REST contract | [API](docs/api.md) and [OpenAPI](api/openapi.yaml) |
| Troubleshooting | [Troubleshooting](docs/troubleshooting.md) |
| Release process | [Release](docs/release.md) |
| Test matrix | [Testing](docs/testing.md) |

## Development

Requirements are declared in `go.mod`, `ui/package.json`, and workflow files. Common commands:

```bash
make test         # UI tests, Go tests, race tests, vet
make ui           # build the embedded web console
make build        # build netp2pd and netp2p
scripts/e2e.sh    # container userspace E2E; add --with-tun for kernel networking
```

`make release` builds Linux DEB/RPM/tarball, Windows MSI, checksums, and a CycloneDX SBOM. Tagged releases also publish manager and Caddy images to GHCR with digest files. See [Release](docs/release.md).

## Protocol status

The client/manager wire protocol is `3.0.0`; breaking protocol changes require coordinated manager and client upgrades. The REST API is still evolving: resource-level CRUD is marked as planned in [API](docs/api.md), while certified snapshot reads, generic authenticated transitions, and owner credential updates are implemented.
