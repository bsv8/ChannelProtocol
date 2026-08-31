#!/usr/bin/env bash
set -euo pipefail

# ChannelProtocol 仓库级验收入口。
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"
go test ./...
go test -race ./...
go vet ./...

cd "${ROOT_DIR}/typescript"
npm ci --ignore-scripts --no-audit --no-fund
npm test
npm audit --omit=dev --audit-level=high
npm pack --dry-run

cd "${ROOT_DIR}"
./scripts/test-integration.sh
echo "ChannelProtocol repository acceptance passed"
