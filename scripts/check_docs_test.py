import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from check_docs import (
    check_author_paths,
    check_forbidden_host,
    check_internal_paths,
    check_ip,
    check_secret_refs,
    scan_release_artifacts,
)


MARKER = "private-test-deployment-value"


class HygieneCheckTest(unittest.TestCase):
    def test_public_ips_are_rejected_and_documentation_addresses_allowed(self):
        findings: list[str] = []
        check_ip("Use 203.0.113.10 or 198.51.100.20 in examples.", findings)
        self.assertEqual(findings, [])
        check_ip("The manager is 192.0.2.10.", findings)
        self.assertEqual(findings, [])
        public_dns = ".".join(["8", "8", "8", "8"])
        check_ip(f"Do not hard-code {public_dns}.", findings)
        self.assertEqual(len(findings), 1)
        self.assertIn("public IPv4 address", findings[0])

    def test_author_local_paths_are_rejected(self):
        findings: list[str] = []
        separator = "\\"
        generic_windows = separator.join(["C:", "Program Files", "NetP2P"])
        author_windows = separator.join(["D:", "Code", "services", "netp2p"])
        check_author_paths(f"Install under {generic_windows}.", findings)
        self.assertEqual(findings, [])
        check_author_paths(f"Open {author_windows}.", findings)
        self.assertEqual(len(findings), 1)
        self.assertIn("author-local absolute path", findings[0])

    def test_secret_and_internal_references_are_rejected(self):
        findings: list[str] = []
        secret_reference = "-".join(["vault", "password"])
        check_secret_refs(f"restore {secret_reference}.txt", findings)
        self.assertEqual(findings, [f"secret-file reference '{secret_reference}'"])

        findings = []
        deployment_host = ".".join(["console", "zhongwww" + "hhh", "cc"])
        check_forbidden_host(f"https://{deployment_host}:9443/", findings)
        self.assertEqual(len(findings), 1)
        self.assertIn("deployment hostname", findings[0])

        findings = []
        internal_document = "/".join(["tmp", "doc", "deployment.md"])
        check_internal_paths(f"See {internal_document} for details.", findings)
        self.assertEqual(len(findings), 1)
        self.assertIn("internal-only path reference", findings[0])

        findings = []
        check_internal_paths("temporary documentation is not internal", findings)
        self.assertEqual(findings, [])


def deb_bytes(inner_name: str, payload: bytes) -> bytes:
    header = (
        inner_name.ljust(16).encode("ascii") +
        "0".ljust(12).encode("ascii") +
        "0".ljust(6).encode("ascii") +
        "0".ljust(6).encode("ascii") +
        "0".ljust(8).encode("ascii") +
        str(len(payload)).encode("ascii").ljust(10) +
        "`\n".encode("ascii")
    )
    padding = b"\0" if len(payload) % 2 else b""
    return b"!<arch>\n" + header + payload + padding


class ReleaseScanTest(unittest.TestCase):
    def scan(self, files: dict[str, bytes]) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            return scan_release_artifacts(root, [MARKER])

    def test_finds_marker_in_compressed_tar(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            payload = MARKER.encode("utf-8")
            member = tarfile.TarInfo("nested/config.txt")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        findings = self.scan({"bundle.tar.gz": buffer.getvalue()})
        self.assertEqual(len(findings), 1)
        self.assertIn("nested/config.txt", findings[0])

    def test_finds_marker_in_deb_data_archive(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            payload = MARKER.encode("utf-8")
            member = tarfile.TarInfo("./usr/share/netp2p/config")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        findings = self.scan({"netp2p.deb": deb_bytes("data.tar.gz", buffer.getvalue())})
        self.assertEqual(len(findings), 1)
        self.assertIn("data.tar.gz", findings[0])

    def test_clean_directory_has_no_findings(self):
        self.assertEqual(self.scan({"checksums.txt": b"only safe bytes\n"}), [])

    def test_missing_msi_helper_is_not_a_release_failure(self):
        with patch("shutil.which", return_value=None):
            findings = self.scan({"netp2p.msi": b"safe raw bytes\n"})
        self.assertEqual(findings, [])

    def test_unreadable_release_artifact_is_explicit_finding(self):
        def unreadable_artifact(path: Path):
            raise OSError("device error")

        with patch("shutil.which", return_value=None):
            with patch.object(Path, "read_bytes", side_effect=unreadable_artifact, autospec=True):
                findings = self.scan({"nested/netp2p.msi": b"safe raw bytes\n"})
        self.assertEqual(findings, ["nested/netp2p.msi: unreadable release artifact: device error"])

    def test_msi_extraction_failure_is_explicit_finding(self):
        result = subprocess.CompletedProcess([], 1, stderr=b"msiextract: bad package\n")
        with patch("shutil.which", return_value="/fake/bin/msiextract"):
            with patch("subprocess.run", return_value=result):
                findings = self.scan({"netp2p.msi": b"safe raw bytes\n"})
        self.assertEqual(len(findings), 1)
        self.assertIn("netp2p.msi: MSI extraction failed with exit code 1", findings[0])
        self.assertIn("msiextract: bad package", findings[0])

    def test_msi_member_can_be_scanned_by_relative_path(self):
        def run_msiextract(command, **_kwargs):
            output = Path(command[2])
            member = output / "CommApp" / "netp2p" / "runtime.yaml"
            member.parent.mkdir(parents=True, exist_ok=True)
            member.write_text(MARKER, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch("shutil.which", return_value="/fake/bin/msiextract"):
            with patch("subprocess.run", side_effect=run_msiextract):
                findings = self.scan({"netp2p.msi": b"safe raw bytes\n"})
        self.assertEqual(len(findings), 1)
        self.assertIn("netp2p.msi:CommApp/netp2p/runtime.yaml", findings[0])

    def test_unreadable_msi_member_is_explicit_finding(self):
        def run_msiextract(command, **_kwargs):
            output = Path(command[2])
            member = output / "CommApp" / "netp2p" / "runtime.yaml"
            member.parent.mkdir(parents=True, exist_ok=True)
            member.write_text(MARKER, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        original_read_bytes = Path.read_bytes

        def unreadable_runtime(path: Path):
            if path.name == "runtime.yaml":
                raise OSError("permission denied")
            return original_read_bytes(path)

        with patch("shutil.which", return_value="/fake/bin/msiextract"):
            with patch("subprocess.run", side_effect=run_msiextract):
                with patch.object(Path, "read_bytes", side_effect=unreadable_runtime, autospec=True):
                    findings = self.scan({"netp2p.msi": b"safe raw bytes\n"})
        self.assertEqual(len(findings), 1)
        self.assertIn("netp2p.msi:CommApp/netp2p/runtime.yaml: unreadable extracted member", findings[0])
        self.assertIn("permission denied", findings[0])

    def test_missing_msi_member_is_explicit_finding(self):
        def run_msiextract(command, **_kwargs):
            output = Path(command[2])
            member = output / "CommApp" / "netp2p" / "runtime.yaml"
            member.parent.mkdir(parents=True, exist_ok=True)
            member.write_text(MARKER, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        original_read_bytes = Path.read_bytes

        def missing_runtime(path: Path):
            if path.name == "runtime.yaml":
                raise FileNotFoundError(path)
            return original_read_bytes(path)

        with patch("shutil.which", return_value="/fake/bin/msiextract"):
            with patch("subprocess.run", side_effect=run_msiextract):
                with patch.object(Path, "read_bytes", side_effect=missing_runtime, autospec=True):
                    findings = self.scan({"netp2p.msi": b"safe raw bytes\n"})
        self.assertEqual(len(findings), 1)
        self.assertIn("netp2p.msi:CommApp/netp2p/runtime.yaml: missing extracted member", findings[0])

    def test_rpm_extraction_failure_is_explicit_finding(self):
        def run_rpm_tools(command, **_kwargs):
            if command[0] == "rpm2cpio":
                return subprocess.CompletedProcess(command, 0)
            return subprocess.CompletedProcess(command, 2, stderr=b"cpio: archive damaged\n")

        with patch("shutil.which", return_value="/fake/bin/tool"):
            with patch("subprocess.run", side_effect=run_rpm_tools):
                findings = self.scan({"netp2p.rpm": b"safe raw bytes\n"})
        self.assertEqual(len(findings), 1)
        self.assertIn("netp2p.rpm: cpio failed with exit code 2", findings[0])
        self.assertIn("cpio: archive damaged", findings[0])

    def test_rpm2cpio_nonzero_with_valid_payload_is_not_failure(self):
        def run_rpm_tools(command, **kwargs):
            if command[0] == "rpm2cpio":
                kwargs["stdout"].write(b"valid cpio payload")
                return subprocess.CompletedProcess(command, 1)
            output = Path(kwargs["cwd"])
            member = output / "usr/bin/netp2p"
            member.parent.mkdir(parents=True, exist_ok=True)
            member.write_text("safe bytes\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch("shutil.which", return_value="/fake/bin/tool"):
            with patch("subprocess.run", side_effect=run_rpm_tools):
                findings = self.scan({"netp2p.rpm": b"safe raw bytes\n"})
        self.assertEqual(findings, [])

    def test_rpm2cpio_nonzero_without_payload_is_explicit_failure(self):
        result = subprocess.CompletedProcess([], 1, stderr=b"rpm2cpio: unsupported payload\n")
        with patch("shutil.which", return_value="/fake/bin/tool"):
            with patch("subprocess.run", return_value=result):
                findings = self.scan({"netp2p.rpm": b"safe raw bytes\n"})
        self.assertEqual(findings, ["netp2p.rpm: rpm2cpio failed with exit code 1: rpm2cpio: unsupported payload"])

    def test_rpm2cpio_nonzero_with_invalid_payload_is_cpio_failure(self):
        def run_rpm_tools(command, **kwargs):
            if command[0] == "rpm2cpio":
                kwargs["stdout"].write(b"damaged cpio payload")
                return subprocess.CompletedProcess(command, 1)
            return subprocess.CompletedProcess(command, 2, stderr=b"cpio: archive damaged\n")

        with patch("shutil.which", return_value="/fake/bin/tool"):
            with patch("subprocess.run", side_effect=run_rpm_tools):
                findings = self.scan({"netp2p.rpm": b"safe raw bytes\n"})
        self.assertEqual(len(findings), 1)
        self.assertIn("netp2p.rpm: cpio failed with exit code 2", findings[0])
        self.assertIn("cpio: archive damaged", findings[0])

    def test_rpm_cpio_success_without_members_is_explicit_failure(self):
        def run_rpm_tools(command, **kwargs):
            if command[0] == "rpm2cpio":
                kwargs["stdout"].write(b"valid cpio payload")
                return subprocess.CompletedProcess(command, 0)
            return subprocess.CompletedProcess(command, 0)

        with patch("shutil.which", return_value="/fake/bin/tool"):
            with patch("subprocess.run", side_effect=run_rpm_tools):
                findings = self.scan({"netp2p.rpm": b"safe raw bytes\n"})
        self.assertEqual(findings, ["netp2p.rpm: extraction produced no files"])


if __name__ == "__main__":
    unittest.main()
