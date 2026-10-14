# Release process

## Artifacts

Tagging `vX.Y.Z` triggers the release workflow to run tests and publish:

- manager image: `ghcr.io/zhongwwwhhh/netp2p-manager:X.Y.Z`
- Caddy image: `ghcr.io/zhongwwwhhh/netp2p-caddy:X.Y.Z`
- Linux DEB, RPM, and amd64 tarball
- Windows MSI
- SHA256SUMS
- CycloneDX SBOM
- image digest files and release notes

Both images support `linux/amd64` and `linux/arm64`. The release version is injected into binaries, UI metadata, package metadata, and image labels.

The CycloneDX SBOM is generated from the source tree, not from local build
scratch directories. Generated artifacts such as `bin/`, `dist/`, `deploy/`,
`tmp/`, `ui/node_modules/`, and the embedded web bundle are excluded from the
source scan. `SHA256SUMS` names the exact artifacts for the tagged release
rather than every file that happens to remain in a local `dist/` directory.

## Pre-tag checklist

1. `main` CI is green: vet, Go unit/race tests, userspace E2E, UI build/tests, OpenAPI lint, Linux package smoke test, Windows tests/MSI.
2. Version, protocol compatibility, and migration notes are reviewed.
3. Release notes list security changes, API additions, planned versus implemented features, upgrade rules, and rollback.
4. Ansible digest variables are ready to update after publication.
5. The previous release's rollback artifact/checksum remains available.

## Verify a release

Check registry digests:

```bash
docker buildx imagetools inspect \
  ghcr.io/zhongwwwhhh/netp2p-manager:X.Y.Z --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect \
  ghcr.io/zhongwwwhhh/netp2p-caddy:X.Y.Z --format '{{.Manifest.Digest}}'
```

Check archives/installers:

```bash
sha256sum -c netp2p-X.Y.Z-SHA256SUMS
```

Validate the manifest/SBOM and confirm the digest-file value equals the registry digest. Never construct a registry digest from a local image ID.

## Deploy

Use the atomic production procedure: pre-pull all nodes, stop all managers together, recreate from pinned digests, start together, then validate readiness, equal heights, HTTPS, metrics, and client E2E. Keep the previous digest and backup until soak passes.

Package validation should include clean Debian install, RPM install, tarball startup, Windows clean install/upgrade/reboot, service recovery, and bidirectional client traffic. Record results in the release checklist.

## Failure handling

If an artifact is incomplete, do not silently overwrite user-visible bytes. Publish a corrected patch version or a clearly documented replacement artifact and update checksums/SBOM. If deployment fails, stop the committee safely and execute the documented rollback; do not attempt a one-node rollback.
