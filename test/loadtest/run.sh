#!/usr/bin/env bash
set -euo pipefail

scenario="${1:-quick}"
shift || true

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

exec go run ./test/loadtest/cmd --scenario "$scenario" "$@"
