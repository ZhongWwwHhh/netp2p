import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from check_docs import scan_release_artifacts


MARKER = "private-test-deployment-value"


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


if __name__ == "__main__":
    unittest.main()
