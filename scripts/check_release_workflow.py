#!/usr/bin/env python3
"""Fail release if workflows or container base images are not securely pinned."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ACTION_RE = re.compile(r"(?m)^\s*-?\s*uses:\s*([^@\s]+)@(\S+)")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.IGNORECASE
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
STEP_NAME_RE = re.compile(r"(?m)^\s*- name:\s*(.+?)\s*$")
RELEASE_JOB_RE = re.compile(r"(?ms)^  linux:\n(.*?)(?=^\S|\Z)")
MUTABLE_RELEASE_TAG_RE = re.compile(
    r"(?m)(?:-t\s+\S+:latest\b|\$\{?IMAGE\}?:latest\b|ghcr\.io/\S+:latest\b)"
)
CONSOLE_ASSET_RE = re.compile(r"(?:src|href)=\"(/assets/[^\"]+)\"")


def dockerfile_base_images(text: str) -> list[str]:
    stage_aliases: set[str] = set()
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0].upper() == "FROM" and parts[-2].upper() == "AS":
            stage_aliases.add(parts[-1])

    images: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts or parts[0].upper() != "FROM":
            continue
        for token in parts[1:]:
            if token.upper() == "AS":
                break
            if token.startswith("--"):
                continue
            if token not in stage_aliases:
                images.append(token)
            break
    return images


def release_job_text(text: str) -> str:
    match = RELEASE_JOB_RE.search(text)
    return match.group(1) if match else ""


def release_step_names(text: str) -> list[str]:
    return [match.group(1) for match in STEP_NAME_RE.finditer(release_job_text(text))]


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, check=True
    )
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def check_release_order(text: str, findings: list[str]) -> None:
    required_order = [
        "Generate SBOM",
        "Build manager image archive",
        "Build Caddy image archive",
        "Install release scan tools",
        "Record image digests",
        "Generate release notes",
        "Generate checksums",
        "Scan source and release artifacts",
        "Push manager image",
        "Push Caddy image",
        "Install Cosign",
        "Sign manager and Caddy images",
        "Sign release checksums and SBOM",
        "Verify release signatures",
        "Attest release artifact provenance",
        "Attest manager image provenance",
        "Attest Caddy image provenance",
        "Publish release",
    ]
    names = release_step_names(text)
    missing = [name for name in required_order if name not in names]
    for name in missing:
        findings.append(f"release workflow is missing required step: {name}")

    positions = [names.index(name) for name in required_order if name in names]
    if positions != sorted(positions):
        findings.append(
            "release workflow order must build and scan artifacts before push, sign, attest, or publish"
        )


def check_embedded_console(root: Path, tracked_files: list[str]) -> list[str]:
    index_path = root / "internal" / "web" / "dist" / "index.html"
    if "internal/web/dist/index.html" not in tracked_files:
        return ["internal/web/dist/index.html must be tracked for release source archives"]
    try:
        index_text = index_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return [f"internal/web/dist/index.html could not be read: {error}"]

    findings: list[str] = []
    referenced = set(CONSOLE_ASSET_RE.findall(index_text))
    if not referenced:
        findings.append("internal/web/dist/index.html references no hashed console assets")
    for asset in sorted(referenced):
        relative = "internal/web/dist/" + asset.lstrip("/")
        if relative not in tracked_files:
            findings.append(f"{relative} must be tracked for release source archives")
        elif not (root / relative).is_file():
            findings.append(f"internal/web/dist/{relative} is tracked but missing")

    tracked_assets = {
        name for name in tracked_files
        if name.startswith("internal/web/dist/assets/")
    }
    stale = tracked_assets - {f"internal/web/dist/{asset.lstrip('/')}" for asset in referenced}
    for asset in sorted(stale):
        findings.append(f"{asset} is no longer referenced by the embedded console and must be removed")
    return findings


def check_file(path: Path) -> list[str]:
    findings: list[str] = []
    text = path.read_text(encoding="utf-8")

    for match in ACTION_RE.finditer(text):
        action, ref = match.groups()
        if not SHA_RE.fullmatch(ref):
            findings.append(
                f"{path}: action {action} must be pinned to a 40-character commit SHA, got {ref}"
            )

    if PIPE_TO_SHELL_RE.search(text):
        findings.append(f"{path}: remote installers must not be piped into a shell")

    if path.name == "release.yml":
        release_job = release_job_text(text)
        check_release_order(text, findings)
        if MUTABLE_RELEASE_TAG_RE.search(release_job):
            findings.append(f"{path}: release images must not publish mutable latest tags")
        if "--push" in release_job:
            findings.append(f"{path}: image push must happen after release artifact scanning")
        for required in (
            '--output "type=oci,name=$IMAGE:$VERSION,dest=$ARCHIVE"',
            "skopeo copy --all",
            "python scripts/check_docs.py --release-dir dist --denylist",
            "RELEASE_DENYLIST:",
            "generate_release_notes: false",
            "body_path: dist/netp2p-${{ env.VERSION }}-release-notes.md",
        ):
            if required not in text:
                findings.append(f"{path}: release hygiene control is missing: {required}")
        for required in (
            "SYFT_VERSION:",
            "SYFT_SHA256:",
            "COSIGN_VERSION:",
            "COSIGN_SHA256:",
            "cosign sign --yes",
            "cosign sign-blob --yes",
            "cosign verify",
            "attest-build-provenance@",
        ):
            if required not in text:
                findings.append(f"{path}: release security step is missing: {required}")

    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings: list[str] = []
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        print("release workflow lint failures: no workflows found", file=sys.stderr)
        return 1

    for workflow in workflows:
        findings.extend(check_file(workflow))

    for dockerfile in sorted(root.glob("Dockerfile*")):
        if not dockerfile.is_file():
            continue
        for image in dockerfile_base_images(dockerfile.read_text(encoding="utf-8")):
            if not DIGEST_RE.search(image):
                findings.append(f"{dockerfile}: base image {image} must be digest-pinned")

    tracked = tracked_files()
    findings.extend(check_embedded_console(root, tracked))

    if findings:
        print("release workflow lint failures:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        print(f"{len(findings)} finding(s)", file=sys.stderr)
        return 1

    print(
        f"release workflow lint OK ({len(workflows)} workflows, "
        "all base images digest-pinned)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
