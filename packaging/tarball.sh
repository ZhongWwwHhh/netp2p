#!/bin/sh
set -eu
VERSION="${1:?version}"
OUTPUT="${2:?output tarball}"
ROOT="${3:-.}"
STAGE="$(mktemp -d)"
TARFILE="$(mktemp)"
trap 'rm -rf "$STAGE" "$TARFILE"' EXIT
mkdir -p "$STAGE/netp2p_$VERSION"
cp "$ROOT/bin/netp2pd" "$STAGE/netp2p_$VERSION/"
cp "$ROOT/bin/netp2p" "$STAGE/netp2p_$VERSION/"
cp "$ROOT/packaging/runtime.example.yaml" "$STAGE/netp2p_$VERSION/runtime.yaml"
cp "$ROOT/packaging/netp2p-client.service" "$STAGE/netp2p_$VERSION/"

# MSYS cannot persist POSIX executable bits on NTFS staging directories. Record
# the modes explicitly in the archive so clean Linux extraction works everywhere.
tar -C "$STAGE" --no-recursion --mode=0755 -cf "$TARFILE" "netp2p_$VERSION"
tar -C "$STAGE" --mode=0644 --append -f "$TARFILE" \
  "netp2p_$VERSION/runtime.yaml" "netp2p_$VERSION/netp2p-client.service"
tar -C "$STAGE" --mode=0755 --append -f "$TARFILE" \
  "netp2p_$VERSION/netp2p" "netp2p_$VERSION/netp2pd"
gzip -c "$TARFILE" > "$OUTPUT"
