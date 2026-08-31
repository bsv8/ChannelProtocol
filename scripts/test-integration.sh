#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "${TMP_DIR}"' EXIT

cd "${PROJECT_DIR}/typescript"
npm ci --ignore-scripts --no-audit --no-fund
npm run build

cd "${PROJECT_DIR}"
go run ./integration/fixture > "${TMP_DIR}/go.json"
node typescript/test/integration-cli.js --verify-go "${TMP_DIR}/go.json" > "${TMP_DIR}/typescript.json"
go run ./integration/fixture --verify-ts "${TMP_DIR}/typescript.json" > "${TMP_DIR}/go-verified.json"

cmp "${TMP_DIR}/go.json" "${TMP_DIR}/go-verified.json"
cmp "${TMP_DIR}/go.json" "${TMP_DIR}/typescript.json"
echo "channels Go/TypeScript fixture integration passed"
