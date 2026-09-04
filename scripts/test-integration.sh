#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "${TMP_DIR}"' EXIT

cd "${PROJECT_DIR}/typescript"
npm ci --ignore-scripts --no-audit --no-fund
npm run build
PACKED_TARBALL="$(npm pack --silent --pack-destination "${TMP_DIR}")"

PACKAGE_TEST_DIR="${TMP_DIR}/package-test"
mkdir -p "${PACKAGE_TEST_DIR}"
cd "${PACKAGE_TEST_DIR}"
npm init -y --silent
npm install --ignore-scripts --no-audit --no-fund "${TMP_DIR}/${PACKED_TARBALL}"
node --input-type=module <<'NODE'
import { sign, marshal, parseAndVerify } from "bsv8-channel-protocol/public-message";
import { verifySignedPrivateMessage } from "bsv8-channel-protocol/inbox";

if (typeof sign !== "function" || typeof marshal !== "function" || typeof parseAndVerify !== "function" || typeof verifySignedPrivateMessage !== "function") {
  throw new Error("打包后的 public-message/inbox ESM 导出不完整");
}
console.log("npm tarball ESM subpath imports passed");
NODE
node --input-type=module - "${PACKAGE_TEST_DIR}/consumer.ts" <<'NODE'
import { writeFile } from "node:fs/promises";

const destination = process.argv[2];
await writeFile(destination, `
import { marshal, parseAndVerify, sign, type UnsignedPublicMessage } from "bsv8-channel-protocol/public-message";
import { verifySignedPrivateMessage, type SignedPrivateMessage } from "bsv8-channel-protocol/inbox";

declare const publicMessage: UnsignedPublicMessage;
declare const publicKey: Parameters<typeof sign>[1];
const signed = sign(publicMessage, publicKey);
const verified = parseAndVerify(publicMessage.channel, marshal(signed), publicMessage.issued_at_ms);
declare const privateMessage: SignedPrivateMessage;
const localVerified = verifySignedPrivateMessage(privateMessage, publicMessage.issued_at_ms);
void verified;
void localVerified;
`);
NODE
"${PROJECT_DIR}/typescript/node_modules/.bin/tsc" --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext "${PACKAGE_TEST_DIR}/consumer.ts"
echo "npm tarball TypeScript declarations passed"

cd "${PROJECT_DIR}"
go run ./integration/fixture > "${TMP_DIR}/go.json"
node typescript/test/integration-cli.js --verify-go "${TMP_DIR}/go.json" > "${TMP_DIR}/typescript.json"
go run ./integration/fixture --verify-ts "${TMP_DIR}/typescript.json" > "${TMP_DIR}/go-verified.json"

cmp "${TMP_DIR}/go.json" "${TMP_DIR}/go-verified.json"
cmp "${TMP_DIR}/go.json" "${TMP_DIR}/typescript.json"
echo "channels Go/TypeScript fixture integration passed"
