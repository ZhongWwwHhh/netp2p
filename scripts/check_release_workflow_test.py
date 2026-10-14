import tempfile
import unittest
from pathlib import Path

from check_release_workflow import check_embedded_console, check_file, dockerfile_base_images


def secure_release_workflow(step_lines: list[str]) -> str:
    release_steps = "\n".join(f"      - name: {step}" for step in step_lines)
    return "\n".join(
        [
            "on: push",
            "jobs:",
            "  linux:",
            "    steps:",
            release_steps,
            "      - name: Scan source and release artifacts",
            "        run: python scripts/check_docs.py --release-dir dist --denylist file",
            "      - name: Push manager image",
            "        run: skopeo copy --all oci-archive:image.tar docker://image:1.2.3",
            "      - name: Push Caddy image",
            "        run: skopeo copy --all oci-archive:caddy.tar docker://caddy:1.2.3",
            "      - name: Install Cosign",
            "        run: cosign version",
            "      - name: Sign manager and Caddy images",
            "        run: cosign sign --yes image",
            "      - name: Sign release checksums and SBOM",
            "        run: cosign sign-blob --yes file",
            "      - name: Verify release signatures",
            "        run: cosign verify image",
            "      - name: Attest release artifact provenance",
            "        uses: actions/attest-build-provenance@2222222222222222222222222222222222222222",
            "      - name: Attest manager image provenance",
            "        uses: actions/attest-build-provenance@2222222222222222222222222222222222222222",
            "      - name: Attest Caddy image provenance",
            "        uses: actions/attest-build-provenance@2222222222222222222222222222222222222222",
            "      - name: Publish release",
            "        run: echo published",
            "      - name: Embedded controls",
            "        run: |",
            "          SYFT_VERSION: v1.2.3",
            "          SYFT_SHA256: " + "a" * 64,
            "          COSIGN_VERSION: v2.3.4",
            "          COSIGN_SHA256: " + "b" * 64,
            "          RELEASE_DENYLIST:",
            "          --output \"type=oci,name=$IMAGE:$VERSION,dest=$ARCHIVE\"",
            "          generate_release_notes: false",
            "          body_path: dist/netp2p-${{ env.VERSION }}-release-notes.md",
        ]
    )


class ReleaseWorkflowLintTest(unittest.TestCase):
    def test_accepts_sha_actions_and_required_release_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "release.yml"
            workflow.write_text(
                secure_release_workflow(
                    [
                        "Generate SBOM",
                        "Build manager image archive",
                        "Build Caddy image archive",
                        "Install release scan tools",
                        "Record image digests",
                        "Generate release notes",
                        "Generate checksums",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(check_file(workflow), [])

    def test_rejects_push_or_sign_before_artifact_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "release.yml"
            workflow.write_text(
                secure_release_workflow(
                    [
                        "Generate SBOM",
                        "Build manager image archive",
                        "Build Caddy image archive",
                        "Install release scan tools",
                        "Record image digests",
                        "Generate release notes",
                        "Generate checksums",
                        "Push manager image",
                    ]
                ),
                encoding="utf-8",
            )
            findings = check_file(workflow)
            self.assertIn(
                "release workflow order must build and scan artifacts before push, sign, attest, or publish",
                findings,
            )

    def test_rejects_mutable_release_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "release.yml"
            text = secure_release_workflow(
                [
                    "Generate SBOM",
                    "Build manager image archive",
                    "Build Caddy image archive",
                    "Install release scan tools",
                    "Record image digests",
                        "Generate release notes",
                    "Generate checksums",
                ]
            ).replace("docker://image:1.2.3", "-t image:latest")
            workflow.write_text(text, encoding="utf-8")
            findings = check_file(workflow)
            self.assertTrue(
                any("release images must not publish mutable latest tags" in finding for finding in findings)
            )

    def test_rejects_tag_actions_and_remote_shell_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "ci.yml"
            workflow.write_text(
                "uses: actions/checkout@v4\ncurl https://example.test/install.sh | sh\n",
                encoding="utf-8",
            )
            findings = check_file(workflow)
            self.assertEqual(len(findings), 2)
            self.assertIn("must be pinned", findings[0])
            self.assertIn("piped into a shell", findings[1])

    def test_parses_dockerfile_base_image_with_build_option(self):
        image = "node:24@sha256:" + "c" * 64
        self.assertEqual(
            dockerfile_base_images(f"FROM --platform=$BUILDPLATFORM {image} AS ui\n"),
            [image],
        )

    def test_internal_dockerfile_stages_do_not_need_digests(self):
        dockerfile = (
            "FROM debian:bookworm-slim@sha256:" + "d" * 64 + " AS base\n"
            "FROM base AS runtime\n"
        )
        self.assertEqual(
            dockerfile_base_images(dockerfile),
            ["debian:bookworm-slim@sha256:" + "d" * 64],
        )

    def test_embedded_console_assets_must_be_tracked_and_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "internal" / "web" / "dist"
            assets = dist / "assets"
            assets.mkdir(parents=True)
            (dist / "index.html").write_text(
                '<script src="/assets/index-test.js"></script>',
                encoding="utf-8",
            )
            (assets / "index-test.js").write_text("console.log('safe')", encoding="utf-8")
            tracked = [
                "internal/web/dist/index.html",
                "internal/web/dist/assets/index-test.js",
            ]
            self.assertEqual(check_embedded_console(root, tracked), [])

            tracked_with_stale = tracked + ["internal/web/dist/assets/index-old.js"]
            findings = check_embedded_console(root, tracked_with_stale)
            self.assertEqual(
                findings,
                [
                    "internal/web/dist/assets/index-old.js is no longer referenced by the embedded console and must be removed"
                ],
            )

            findings = check_embedded_console(root, ["internal/web/dist/index.html"])
            self.assertEqual(
                findings,
                [
                    "internal/web/dist/assets/index-test.js must be tracked for release source archives"
                ],
            )


if __name__ == "__main__":
    unittest.main()
