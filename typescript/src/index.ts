/** BSV8 三方频道协议 SDK 根入口。 */
export * from "./registry.js";
export * from "./internal/errors.js";
export * from "./internal/limits.js";
export {
  type MessageID,
  type PrivateKey,
  type PublicKey,
  type SessionID,
  type SHA256Hash,
  type Signature,
  type RandomSource,
  base64urlEncode,
  fixedRandom,
  generatePrivateKey,
  inboxChannel,
  messageIDFromBytes,
  newMessageID,
  newSessionID,
  sessionIDFromBytes,
  parseInboxChannel,
  parseMessageID,
  parsePrivateKey,
  parsePublicKey,
  parseSHA256Hash,
  parseSessionID,
  parseSignature,
  parseUnixMillis,
  publicKeyFromBytes,
  publicKeyFromPrivate,
  secureRandom,
  sha256HashFromBytes,
  signatureFromDER,
} from "./internal/encoding.js";
export { canonicalizeJSON, canonicalizeValue, sha256 } from "./internal/jcs.js";
/** JSONValue 是各协议允许的递归 JSON 数据类型。 */
export type { JSONValue } from "./internal/strict-json.js";

import { HASH_REQUEST_CHANNEL } from "./registry.js";
import { ERROR_CODES, protocolError } from "./internal/errors.js";
import { parseAndVerify as parseHashRequest } from "./hash-request/index.js";
import { openAndDispatch as openInboxAndDispatch, reviewOfferForHashRequest as reviewInboxOfferForHashRequest } from "./inbox/index.js";
import type { PrivateKey } from "./internal/encoding.js";
import type { VerifiedHashRequest } from "./hash-request/index.js";
import type { DecodedInboxMessage, VerifiedPrivateMessage } from "./inbox/index.js";
import type { SessionKey } from "./webrtc-signal/index.js";

/** 根入口：严格解析并验签公开 Hash 请求频道。 */
export function decodePublicChannel(channel: string, contentJSON: string | Uint8Array, nowMs: number): VerifiedHashRequest {
  return parseHashRequest(channel, contentJSON, nowMs);
}

/** 根入口：解密并按 protocol 返回强类型私密消息。 */
export async function decodePrivateChannel(channel: string, envelopeJSON: string | Uint8Array, recipientPrivateKey: PrivateKey | Uint8Array, nowMs: number): Promise<DecodedInboxMessage> {
  return openInboxAndDispatch(channel, envelopeJSON, recipientPrivateKey, nowMs);
}

/** 根入口：统一审查 WebRTC offer 与已验证 Hash 请求的关系。 */
export function reviewOfferForHashRequest(hashRequest: VerifiedHashRequest, offer: VerifiedPrivateMessage, nowMs: number): SessionKey {
  return reviewInboxOfferForHashRequest(hashRequest, offer, nowMs);
}

/** 根入口：按频道自动选择公开 Hash 或私密 inbox 解码。 */
export function decodeChannel(channel: string, contentJSON: string | Uint8Array, nowMs: number, recipientPrivateKey?: PrivateKey | Uint8Array): VerifiedHashRequest | Promise<DecodedInboxMessage> {
  if (channel === HASH_REQUEST_CHANNEL) return decodePublicChannel(channel, contentJSON, nowMs);
  if (recipientPrivateKey === undefined) throw protocolError(ERROR_CODES.INVALID_CHANNEL, "私密频道解码需要 recipient_private_key");
  return decodePrivateChannel(channel, contentJSON, recipientPrivateKey, nowMs);
}

/** Go 风格跨协议 offer/Hash 关系审查别名。 */
export const ReviewOfferForHashRequest = reviewOfferForHashRequest;
