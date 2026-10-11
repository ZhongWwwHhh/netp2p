#!/usr/bin/env python3
"""Hygiene and Markdown link checks for tracked files.

Stdlib-only. Run from the repository root: python scripts/check_docs.py
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
import urllib.parse
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

LINK_RE = re.compile(r"\[[^\]]*\]\(<([^>]+)>|\[[^\]]*\]\(([^)\s]+)")


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
            failures.extend(f"{name}:{number}: {finding}" for finding in file_findings)
        if path.suffix == ".md":
            md_findings: list[str] = []
            check_markdown_links(name, lines, md_findings)
            failures.extend(f"{name}: {finding}" for finding in md_findings)

    if failures:
        print("docs hygiene failures:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(f"{len(failures)} finding(s)", file=sys.stderr)
        return 1
    print(f"docs hygiene OK ({len(files)} tracked files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
