#!/bin/sh
set -eu
OUT="${1:?checksum file}"
shift
: > "$OUT"
for file in "$@"; do
  sha256sum "$file" >> "$OUT"
done
