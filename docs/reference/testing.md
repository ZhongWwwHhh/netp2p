# Testing

NetP2P has unit, race, process E2E, chaos, UI, package, and production validation layers. A documentation-only change can run link/build checks; behavior changes must run at least the relevant Go/E2E suites before merge.

## Local development

```bash
make test
go test ./cmd/... ./internal/...
go test -race ./internal/...
go vet ./...
```

`make test` also builds and tests the UI. Frontend-only iteration:

```bash
cd ui
npm ci
npm run build
npx vitest run
```

Windows uses MSYS2/MinGW GCC for cgo-backed race analysis where needed. Keep test listeners loopback-only to avoid unnecessary Windows firewall prompts.

## Process E2E

`internal/e2e` runs multiple managers and clients in one process and covers genesis, setup-key/SSO enrollment, certified snapshots, policy direction, manager loss/recovery, QC validation, quota accounting, links, and via-manager forwarding.

Useful examples:

```bash
go test ./internal/e2e
go test ./internal/e2e -run TestChaos -v
go test ./internal/web
go test ./internal/bft
```

Expected invariants include tampered snapshots being rejected, one manager down blocking writes, recovery allowing catch-up and new enrollment, and denied policy directions actually dropping traffic.

## Container E2E

Prerequisites are Docker and the script's Python dependency. The default userspace mode needs neither TUN nor `NET_ADMIN`.

```bash
scripts/e2e.sh
scripts/e2e.sh --with-tun
scripts/e2e.sh --with-exit
scripts/e2e.sh --with-multihop
scripts/e2e.sh --with-quota
scripts/e2e.sh --with-chaos
```

The script builds a test image, runs committee members and clients, verifies enrollment/policy/traffic, inspects status and metrics, and exercises optional kernel TUN, exit routing, multihop, quota, and chaos paths.

## Packaging and platforms

CI validates Linux package construction and a clean Debian DEB install, plus Windows build/tests and MSI construction. Release qualification additionally requires:

- RPM install
- Linux tarball startup
- clean Windows MSI install
- Windows upgrade and reboot persistence
- service recovery after forced termination
- bidirectional ICMP/TCP between two clients

Run package tests on clean hosts or containers, not only a development machine with prior state.

## Security and API checks

Cover every new route with authentication, RBAC, invalid-input, oversize-body, and redaction tests. Snapshot and log tests must prove that password verifiers, setup-key plaintext, admin tokens, private shares, and session tokens are absent from client-visible data. For OpenAPI changes, run `npx --yes @redocly/cli@1.34.2 lint api/openapi.yaml` and verify implemented examples against actual routes.

## Production validation

Before promoting a build to a three-manager production committee:

1. All `/readyz` endpoints return ready with equal height.
2. Committee is 3/3 and quorum is 3.
3. HTTPS works on primary and all direct URLs.
4. A test client logs in, syncs, and probes an allowed peer in both permitted directions.
5. Metrics and alerts update.
6. A backup/restore drill has succeeded at the current release.

For significant releases, run a 24-hour soak with continuous traffic, DNS, client reconnects, safe manager restart/catch-up, policy/route churn, and metric review. CI success alone is not production readiness.
