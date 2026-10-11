# NetP2P documentation map

NetP2P runs a certified overlay network from a 3-of-3 BFT committee. This site separates what is available today from what is planned for v0.3.0.

## Start here

- [Quickstart](quickstart.md): install Linux or Windows, join with a setup key, verify connectivity.
- [Web console](console.md): owner bootstrap, users, groups, policies, routes, DNS, setup keys, and diagnostics.
- [Linux client](clients/linux.md): package, systemd service, files, commands, and upgrade.
- [Windows client](clients/windows.md): MSI, service, Wintun, files, commands, and upgrade.

## Operate

- [Production](production.md): `fr`, `sg`, `us-phx`, 3-of-3 upgrade rules, DNS endpoints, rollback, and recovery.
- [Operations](operations.md): health, readiness, metrics, logs, backup/restore, and common failures.
- [Troubleshooting](troubleshooting.md): login, committee, TUN, DNS, route, and data-path diagnosis.

## Understand and extend

- [Security](security.md): BFT/DKG, Ed25519, Argon2id, sessions, setup-key hashes, secrets, and threat model.
- [API](api.md): implemented REST surface and v0.3 contract direction.
- [OpenAPI](../api/openapi.yaml): machine-readable contract; planned paths carry `x-status: planned`.
- [Release](release.md): artifacts, digests, checksums, SBOM, and deployment pins.
- [Testing](testing.md): local, container, Windows, production, and soak tests.
- [Architecture](architecture.md): protocol and implementation details.
- [Roadmap](roadmap.md): release history and remaining production work.

## Contract status

Implemented today: bootstrap, local authentication and sessions, certified snapshot reads, authenticated generic transitions, setup-key creation, diagnostics, quota/event reads, and local client IPC.

Implemented in the working tree: certified owner email/password updates, password-change session revocation, and last-owner protection. Planned for v0.3.0: resource-level REST CRUD, service-user PATs, dedicated routing resources, traffic events, and IPv6 overlay APIs. Do not script against planned paths until they are marked implemented in [API](api.md).
