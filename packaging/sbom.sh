#!/bin/sh
set -eu
OUT="${1:?SBOM output}"
shift
VERSION="${VERSION:-0.0.0-dev}"
syft scan "$@" \
  --source-name netp2p \
  --source-version "$VERSION" \
  --exclude './.git/**' \
  --exclude './bin/**' \
  --exclude './deploy/**' \
  --exclude './dist/**' \
  --exclude './internal/web/dist/**' \
  --exclude './tmp/**' \
  --exclude './ui/node_modules/**' \
  -o cyclonedx-json > "$OUT"
