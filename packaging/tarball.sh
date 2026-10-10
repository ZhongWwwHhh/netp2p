#!/bin/sh
set -eu
VERSION="${1:?version}"
OUTPUT="${2:?output tarball}"
ROOT="${3:-.}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/netp2p_$VERSION"
cp "$ROOT/bin/netp2pd" "$STAGE/netp2p_$VERSION/"
cp "$ROOT/bin/netp2p" "$STAGE/netp2p_$VERSION/"
cp "$ROOT/packaging/runtime.example.yaml" "$STAGE/netp2p_$VERSION/runtime.yaml"
cp "$ROOT/packaging/netp2p-client.service" "$STAGE/netp2p_$VERSION/"
tar -C "$STAGE" -czf "$OUTPUT" "netp2p_$VERSION"
