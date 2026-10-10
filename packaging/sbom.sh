#!/bin/sh
set -eu
OUT="${1:?SBOM output}"
shift
syft scan "$@" -o cyclonedx-json > "$OUT"
