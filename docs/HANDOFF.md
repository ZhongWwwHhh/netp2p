# NetP2P handoff - current state and remaining work

Snapshot date: 2026-10-10.
Repository: `https://github.com/ZhongWwwHhh/netp2p` (public).
Ansible component: `<private-ansible-root>\netp2p` (local repo, no remote configured).

## 1. Where the project stands

The productionization work described in the plan is implemented, committed and
pushed. `main` is at the time of writing:

| Item | Value |
| --- | --- |
| Head commit | `d09359d` - "fix: use standard directories in msi" |
| Branch | `main`, in sync with `origin/main` (`0 0` ahead/behind) |
| Tags | none yet |
| CI (GitHub Actions, workflow `ci`) | run 30 on `d09359d` - **all jobs success** |
| Go tests, `go vet`, race, e2e, UI, package, Windows MSI, cross builds | green |
| `npm audit` (ui) | 0 vulnerabilities |
| `govulncheck ./...` | 0 reachable vulnerabilities |
| Dependabot open alerts | 0 |

The Ansible side is committed locally at `c7603d3` - "feat: finish netp2p trust delivery".
That repository has **no git remote**, so nothing there has been pushed anywhere.

## 2. What is already done (do not redo)

- Committee parameters are seed-driven; production uses `size=3, faultLimit=0,
  quorumSize=3`. `ProtocolVersion` is `3.0.0`.
- Trust material is split into a public `NetworkManifest`, per-manager private
  `ManagerBundle`, and a public `ClientTrust`. Clients read all three manager
  endpoints from `ClientTrust` and fail over; the legacy single `manager` key is
  development-only.
- Manager persistence uses an embedded SQLite store (certified snapshots,
  decision log, users, sessions, setup-key verifiers, audit events) with WAL,
  replay on startup, and degraded read-only mode when quorum is unavailable.
- Client split: `netp2pd` daemon plus `netp2p` CLI over a Unix socket / Windows
  named pipe, with `up/down/status/status --json/ip/login/logout/ping/netcheck/
  doctor/debug bundle` and a first-run wizard.
- Linux packaging: DEB, RPM, tarball, and `netp2p-client.service` (verified by
  installing the DEB in a clean Debian container). Makefile targets
  `build-linux`, `package-linux`, `package-tarball`, `package-windows`,
  `checksums`, `sbom`, `release`.
- Windows packaging: `netp2p-windows-amd64.msi` (WiX 6, v4 schema), native
  service `NetP2PClient`, Wintun pinned to the signed 0.14.1 DLL, config at
  `C:\ProgramData\netp2p\runtime.yaml`. The MSI now builds in CI.
- Container images: `Dockerfile` and `Dockerfile.caddy` are multi-arch
  (`linux/amd64`, `linux/arm64`) with cross-compilation from `$BUILDPLATFORM`;
  Caddy includes `dns.providers.cloudflare` v0.2.4. Both were built and
  inspected locally for both architectures.
- Release workflow (`.github/workflows/release.yml`, triggered by `v*` tags)
  builds the MSI, Linux packages, tarball, SBOM, checksums, and pushes both
  images to GHCR with digest files.
- Benchmarks exist for policy, conntrack, forwarding, direct and via-manager
  throughput, DNS, snapshots, TUN, and exit-node (first baseline in
  `docs/performance-baseline.md`).
- Operation and test documentation: `docs/OPERATIONS.md`, `docs/testing.md`.

## 3. Remaining work

Ordered. Items 1-3 are the release path; 4-8 are the real deployment.

### 3.1 Tag and publish the first release

```bash
git tag v0.1.0
git push origin v0.1.0
```

This triggers the `release` workflow. Watch it in the Actions tab. On success it
publishes a GitHub Release with `netp2p-0.1.0-image-digest.txt` and
`netp2p-caddy-0.1.0-image-digest.txt`.

Open question to settle first: confirm that `v0.1.0` is the intended first
version, and that `0.1.0` is acceptable given the internal `ProtocolVersion`
is already `3.0.0` (they are independent numbers).

### 3.2 Verify GHCR package visibility

The release workflow pushes with `GITHUB_TOKEN`. For a public repo these
packages can still default to private, which would make the three managers
unable to pull without credentials. After the workflow runs, check both
`ghcr.io/zhongwwwhhh/netp2p-manager` and `ghcr.io/zhongwwwhhh/netp2p-caddy`
and set them to public, or configure `docker login` on the managers.

### 3.3 Pin the digests in Ansible

In `ansible/netp2p/vars/main.yml` set:

```yaml
netp2p_manager_image_digest: "sha256:<from netp2p-0.1.0-image-digest.txt>"
netp2p_proxy_image_digest: "sha256:<from netp2p-caddy-0.1.0-image-digest.txt>"
```

`install.yaml` deliberately refuses to run while these are empty. Do not weaken
that assertion.

### 3.4 Prepare the three managers

- Confirm each cloud provider security group allows UDP `4001`, UDP `4101`,
  TCP `9443` from anywhere, and TCP `9101` only from the monitoring hub.
- `fr` was resource constrained (about 149 MiB free RAM, swap heavily used,
  about 4.9 GB disk free with ~2.9 GB of reclaimable Docker images). Reclaim
  only dangling/unused images; do not touch unrelated stacks.
- Vault password lives at `<private-ansible-root>\passwd\<vault-password-file>`.
  Inside WSL it must be copied to `/tmp` and `chmod 600` again before each
  invocation, because `/tmp` may be cleared.

### 3.5 DNS

```bash
cd <private-ansible-root>
ansible-playbook --syntax-check -i inventory.yaml \
  --vault-password-file /tmp/netp2p_<vault-password-file> netp2p/playbooks/dns.yaml
ansible-playbook -i inventory.yaml \
  --vault-password-file /tmp/netp2p_<vault-password-file> netp2p/playbooks/dns.yaml
```

Grey-cloud (unproxied) A records for the three manager names plus a round-robin
record for the console. Cloudflare must not proxy QUIC or WebRTC.

### 3.6 Install the managers

The playbook pre-pulls on all hosts, runs `docker compose create
--force-recreate` on all hosts, then starts all three together. Never use a
rolling restart: quorum is 3-of-3, so any single manager down blocks writes.

```bash
ansible-playbook -i inventory.yaml \
  --vault-password-file /tmp/netp2p_<vault-password-file> netp2p/playbooks/install.yaml
```

Validation performed by the playbook, per host: `/healthz` returns 200,
`/api/bootstrap` returns three committee members with `protocolVersion`
`3.0.0`, `/metrics` is scrapable and reports a certified height, and HTTPS works
on port 9443.

### 3.7 Monitoring

Add a Prometheus scrape job for `netp2p` on port `9101` and alerts for BFT
height, commit rate, quorum availability, manager connectivity, forwarding
volume, queue depth, drop ratio, DNS failures, quota enforcement, memory, and
goroutines. Any manager disconnect should alert immediately because of the
3-of-3 quorum.

### 3.8 Clients and validation

- Install the Linux client (DEB from the release) on a local Docker host.
- Install the Windows MSI locally.
- Exercise direct and via-manager paths, policy, DNS, exit node, quota, and
  manager failover.
- Run a 24-hour soak with continuous traffic, a manager restart, client
  reconnect, route and policy churn, DNS queries, and metrics collection, then
  record throughput, latency, commit time, CPU, memory, and drop baselines.

## 4. Known pitfalls already hit (save time next round)

- **Docker Hub from this host** resolves to an unreachable IPv6. Build with
  `--build-context <image>=docker-image://docker.m.daocloud.io/...` overrides
  instead of editing the Dockerfile.
- **WiX 7** now requires accepting an OSMF EULA, so both workflows pin WiX
  `6.0.2` and the WXS uses the v4 namespace with `StandardDirectory`. Do not
  "modernize" it back to v7 without solving licensing.
- **Wintun download is not reproducible**: the upstream zip is regenerated, so
  only the signed DLL is hash-pinned (`build-msi.ps1`), plus an Authenticode
  check on the WireGuard LLC signer thumbprint.
- **nfpm rewrites `0.0.0-dev`** to `0.0.0~dev` in DEB/RPM filenames. CI paths
  must use the rewritten name.
- **Go test discovery and `ui/node_modules`** interfere on Windows: use
  `go test ./cmd/... ./internal/...` rather than `./...` when `node_modules`
  exists, and delete a locked `node_modules` by renaming it first.
- **npm peer conflicts**: `ui/.npmrc` sets `legacy-peer-deps=true` and the
  Dockerfile copies it before `npm ci`. Removing one without the other breaks
  the image build.
- **Benchmark baseline is stale**: `docs/performance-baseline.md` was collected
  with Go 1.25.7; the toolchain is now Go 1.26.9. Refresh it, and collect the
  Linux-only exit-node benchmark on a Linux runner (still not done).
- **`bootstrap.version` vs `protocolVersion`**: the bootstrap document carries
  both; validation must assert `protocolVersion`, not `version`.

## 5. Verification commands

```bash
# Go
go test ./cmd/... ./internal/... -count=1
go vet ./cmd/... ./internal/...
go test -run '^$' -bench . -benchtime=1x ./cmd/... ./internal/...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# UI
cd ui && npm ci && npm run build && npm test && npm audit --audit-level=low

# Packages
make package-linux package-tarball VERSION=0.0.0-dev SKIP_UI=1

# Ansible (from WSL, see the vault note above)
for playbook in netp2p/playbooks/{dns,install,upgrade,rollback,client-install}.yaml; do
  ansible-playbook --syntax-check -i inventory.yaml \
    --vault-password-file /tmp/netp2p_<vault-password-file> "$playbook"
done
```

## 6. File map

- Control plane: `internal/bft`, `internal/manager`, `internal/store`,
  `internal/model`, `internal/config`.
- Data plane: `internal/client`, `internal/forward`, `internal/transport`,
  `internal/tun`, `internal/dns`, `internal/exitnode`, `internal/quota`.
- User surface: `cmd/netp2p`, `cmd/netp2pd`, `ui/`, `internal/web`.
- Packaging: `packaging/`, `packaging/windows/`, `Dockerfile`,
  `Dockerfile.caddy`, `Makefile`.
- CI/release: `.github/workflows/ci.yml`, `.github/workflows/release.yml`.
- Docs: `docs/OPERATIONS.md`, `docs/testing.md`,
  `docs/performance-baseline.md`, `docs/architecture.md`.

## 7. Security notes

No secrets are stored in this repository. Manager private bundles, the setup
key, admin/session secrets, and the Cloudflare DNS token live only in the
Ansible vault (`ansible/netp2p/vaults/secrets.yaml`). Keep it that way; the
repository is public.
