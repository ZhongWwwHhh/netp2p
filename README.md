# NetP2P

NetP2P is an overlay network for connecting Linux and Windows machines across
existing networks. It provides certified network state, identity-based access
policy, peer-to-peer or relayed data paths, overlay DNS, routes, quotas, and a
web console.

Management state is certified by a BFT committee. Clients receive a signed
network snapshot and exchange traffic only when policy and routing state admit
the flow.

## Documentation

Start with the [documentation map](docs/index.md).

| Task | Guide |
| --- | --- |
| Install and join your first machine | [Get started](docs/get-started/index.md) |
| Create a network | [Create a network](docs/get-started/create-network.md) |
| Use the web console | [Manage NetP2P](docs/manage/index.md) |
| Enroll with a setup key | [Join Linux](docs/get-started/join-linux.md) / [Join Windows](docs/get-started/join-windows.md) |

## Development

Requirements are declared by `go.mod`, `ui/package.json`, and CI workflow files.

```bash
make test     # UI and Go tests, race tests, and vet
make ui       # build the embedded console
make build    # build netp2pd and netp2p
```

The protocol version is `3.0.0`. Breaking protocol changes require a
coordinated client and manager upgrade.
