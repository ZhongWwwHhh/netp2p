import io
import tarfile
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
