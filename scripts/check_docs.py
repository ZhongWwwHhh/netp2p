#!/usr/bin/env python3
"""Hygiene and Markdown link checks for tracked files.

Stdlib-only. Run from the repository root: python scripts/check_docs.py
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import argparse
import io
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import zipfile
from pathlib import Path


TEXT_SUFFIXES = {
    ".go", ".md", ".ts", ".tsx", ".js", ".json", ".yaml", ".yml",
    ".sh", ".py", ".ps1", ".sql", ".html", ".css", ".txt", ".mod", ".sum",
    ".wxs", ".wxl", ".plist", ".service", ".timer", ".conf", ".j2",
}

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Deployment identity: the real test deployment domain (including historical
# misspellings). The public GHCR/GitHub namespace is intentionally allowed.
FORBIDDEN_HOST_RE = re.compile(r"zhongww[a-z0-9-]*\.cc", re.IGNORECASE)

# Paths that expose the author's machine rather than generic install layout.
AUTHOR_PATH_RES = [
    re.compile(r"(?<![%\w])[A-Za-z]:[\\/][^\s`\"')\]]*"),
    re.compile(r"\bC:[\\/](?:Users|Users\\)[^\s`\"')\]]*", re.IGNORECASE),
    re.compile(r"/mnt/[A-Za-z]/"),
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
    re.compile(r"/Volumes/"),
]

# C:\Program Files, C:\ProgramData, and C:\Windows are generic install
# locations used by packaging and docs; they are not machine identifiers.
GENERIC_WINDOWS_PREFIXES = ("c:\\program files", "c:\\programdata", "c:\\windows", "c:\\secure\\")

SECRET_REF_RES = [
    re.compile(r"vault[_-]password", re.IGNORECASE),
    re.compile(r"\bpasswd/", re.IGNORECASE),
    re.compile(r"\bpasswords/", re.IGNORECASE),
    re.compile(r"\bid_rsa\b"),
    re.compile(r"\.ssh/[^\s`\"')\]]*"),
]

INTERNAL_PATH_RES = [
    re.compile(r"(?:^|[\s(`'\[])(?:\./)?tmp/doc(?:/|[\s`'\]])", re.IGNORECASE),
    re.compile(r"(?:^|[\s/])(?:\.codex|\.cache)/", re.IGNORECASE),
]

LINK_RE = re.compile(r"\[[^\]]*\]\(<([^>]+)>|\[[^\]]*\]\(([^)\s]+)")


def load_denylist(path: str) -> list[str]:
    values: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and value not in values:
            values.append(value)
    return values


def denied_values(data: bytes, values: list[str]) -> bool:
    return any(value.encode("utf-8") in data for value in values)


def tar_members(label: str, payload: bytes):
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                yield f"{label}:{member.name}", stream.read()
    except (tarfile.TarError, OSError):
        return


def deb_members(label: str, data: bytes):
    if not data.startswith(b"!<arch>\n"):
        return
    position = len(b"!<arch>\n")
    while position + 60 <= len(data):
        header = data[position:position + 60]
        name = header[:16].decode("ascii", "replace").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            return
        position += 60
        payload = data[position:position + size]
        yield f"{label}:{name}", payload
        if name.startswith(("control.tar", "data.tar")):
            yield from tar_members(f"{label}:{name}", payload)
        position += size + (size & 1)


def archive_members(path: Path, data: bytes):
    label = path.name
    suffixes = {path.suffix.lower(), "".join(path.suffixes[-2:]).lower()}
    if ".tar" in suffixes or ".tar.gz" in suffixes or ".tgz" in suffixes:
        yield from tar_members(label, data)
    elif path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if not name.endswith("/"):
                        yield f"{label}:{name}", archive.read(name)
        except (zipfile.BadZipFile, OSError):
            return
    elif path.suffix.lower() == ".deb":
        yield from deb_members(label, data)


def _bounded_stderr(stderr: bytes | None) -> str:
    if not stderr:
        return ""
    text = stderr.decode("utf-8", "replace").strip()
    if len(text) > 2000:
        text = text[:2000] + "..."
    return text.replace("\r", " ").replace("\n", " | ")


def extracted_members(path: Path) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Extract package formats that need a platform decoder.

    CI installs the helper tools before release scanning. When a helper is
    absent locally, only the raw file scan is performed; local development does
    not silently require platform packages.
    """
    suffix = path.suffix.lower()
    if suffix == ".msi":
        if not shutil.which("msiextract"):
            return [], []
    elif suffix == ".rpm":
        if not (shutil.which("rpm2cpio") and shutil.which("cpio")):
            return [], []
    else:
        return [], []

    directory = tempfile.mkdtemp(prefix="netp2p-release-scan-")
    output = Path(directory)
    payload = output / "payload.cpio"
    findings: list[str] = []
    try:
        if suffix == ".msi":
            try:
                result = subprocess.run(
                    ["msiextract", "--directory", str(output), str(path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False,
                )
            except OSError as error:
                return [], [f"{path.name}: MSI extraction failed: {error}"]
            if result.returncode != 0:
                diagnostic = _bounded_stderr(result.stderr)
                detail = f": {diagnostic}" if diagnostic else ""
                return [], [f"{path.name}: MSI extraction failed with exit code {result.returncode}{detail}"]
        else:
            try:
                with payload.open("wb") as stream:
                    result = subprocess.run(
                        ["rpm2cpio", str(path)], stdout=stream,
                        stderr=subprocess.PIPE, check=False,
                    )
            except OSError as error:
                return [], [f"{path.name}: RPM extraction failed while running rpm2cpio: {error}"]
            # rpm2cpio on some distributions exits 1 after successfully
            # writing a complete payload. Treat an empty payload as the real
            # failure and let the following cpio extraction validate the data.
            try:
                cpio_payload = payload.read_bytes()
            except OSError as error:
                return [], [f"{path.name}: RPM extraction failed while reading rpm2cpio payload: {error}"]
            if result.returncode != 0 and not cpio_payload:
                diagnostic = _bounded_stderr(result.stderr)
                detail = f": {diagnostic}" if diagnostic else ""
                return [], [f"{path.name}: rpm2cpio failed with exit code {result.returncode}{detail}"]
            try:
                result = subprocess.run(
                    ["cpio", "-id", "--quiet", "--no-absolute-filenames"],
                    cwd=output, input=cpio_payload,
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=False,
                )
            except OSError as error:
                return [], [f"{path.name}: RPM extraction failed while running cpio: {error}"]
            if result.returncode != 0:
                diagnostic = _bounded_stderr(result.stderr)
                detail = f": {diagnostic}" if diagnostic else ""
                return [], [f"{path.name}: cpio failed with exit code {result.returncode}{detail}"]

        members: list[tuple[str, bytes]] = []
        extracted_files = [
            item for item in output.rglob("*")
            if item.is_file() and item != payload
        ]
        for item in extracted_files:
            relative = item.relative_to(output).as_posix()
            try:
                members.append((relative, item.read_bytes()))
            except FileNotFoundError:
                findings.append(f"{path.name}:{relative}: missing extracted member")
            except OSError as error:
                findings.append(f"{path.name}:{relative}: unreadable extracted member: {error}")
        if not extracted_files:
            findings.append(f"{path.name}: extraction produced no files")
        return members, findings
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def scan_release_artifacts(directory: Path, values: list[str]) -> list[str]:
    findings: list[str] = []
    files = 0
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        files += 1
        try:
            data = path.read_bytes()
        except OSError as error:
            relative = path.relative_to(directory).as_posix()
            findings.append(f"{relative}: unreadable release artifact: {error}")
            continue
        if denied_values(data, values):
            findings.append(f"{path}: contains a denied deployment value")
        for label, payload in archive_members(path, data):
            if denied_values(payload, values):
                findings.append(f"{label}: contains a denied deployment value")
        extracted, package_findings = extracted_members(path)
        findings.extend(package_findings)
        for relative, payload in extracted:
            if denied_values(payload, values):
                findings.append(f"{path.name}:{relative}: contains a denied deployment value")
    if not files:
        findings.append(f"{directory}: no release artifacts found")
    return findings


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, check=True
    )
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def check_ip(line: str, findings: list[str]) -> None:
    for match in IPV4_RE.finditer(line):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if address.version == 4 and address.is_global:
            findings.append(f"public IPv4 address {address} (use RFC 5737 or private ranges)")


def check_author_paths(line: str, findings: list[str]) -> None:
    lowered = line.lower()
    for pattern in AUTHOR_PATH_RES:
        for match in pattern.finditer(line):
            text = match.group(0)
            if text.lower().startswith(("c:\\program", "c:/program", "c:\\windows", "c:/windows")):
                continue
            findings.append(f"author-local absolute path {text!r}")
            break


def check_secret_refs(line: str, findings: list[str]) -> None:
    for pattern in SECRET_REF_RES:
        match = pattern.search(line)
        if match:
            findings.append(f"secret-file reference {match.group(0)!r}")


def check_forbidden_host(line: str, findings: list[str]) -> None:
    match = FORBIDDEN_HOST_RE.search(line)
    if match:
        findings.append(f"deployment hostname {match.group(0)!r}")


def check_internal_paths(line: str, findings: list[str]) -> None:
    for pattern in INTERNAL_PATH_RES:
        match = pattern.search(line)
        if match:
            findings.append(f"internal-only path reference {match.group(0).strip()!r}")
            return


def check_markdown_links(path: str, lines: list[str], findings: list[str]) -> None:
    base = Path(path).parent
    for number, line in enumerate(lines, start=1):
        for match in LINK_RE.finditer(line):
            target = match.group(1) or match.group(2)
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            clean = urllib.parse.unquote(target.split("#", 1)[0])
            if not clean:
                continue
            resolved = (base / clean).resolve()
            if not resolved.exists():
                findings.append(f"broken relative Markdown link {target!r} (line {number})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, help="recursive release artifact directory to scan")
    parser.add_argument("--denylist", help="file containing one private deployment value per line")
    args = parser.parse_args()
    if bool(args.release_dir) != bool(args.denylist):
        parser.error("--release-dir and --denylist must be used together")
    files = tracked_files()
    failures: list[str] = []
    for name in files:
        if name.startswith("tmp/") or "/tmp/" in name:
            failures.append(f"{name}: tracked tmp path")
        if name == "scripts/check_docs.py":
            continue
        if name.startswith("internal/web/dist/"):
            continue
        path = Path(name)
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            file_findings: list[str] = []
            check_ip(line, file_findings)
            check_author_paths(line, file_findings)
            check_secret_refs(line, file_findings)
            check_forbidden_host(line, file_findings)
            check_internal_paths(line, file_findings)
            failures.extend(f"{name}:{number}: {finding}" for finding in file_findings)
        if path.suffix == ".md":
            md_findings: list[str] = []
            check_markdown_links(name, lines, md_findings)
            failures.extend(f"{name}: {finding}" for finding in md_findings)

    if args.release_dir:
        release_values = load_denylist(args.denylist)
        failures.extend(scan_release_artifacts(args.release_dir, release_values))

    if failures:
        print("docs hygiene failures:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(f"{len(failures)} finding(s)", file=sys.stderr)
        return 1
    release_count = len(list(args.release_dir.rglob("*"))) if args.release_dir else 0
    print(f"docs hygiene OK ({len(files)} tracked files, {release_count} release entries checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
