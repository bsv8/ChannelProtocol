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
export {
  PUBLIC_MESSAGE_SCOPE,
  PUBLIC_MESSAGE_MAX_LIFETIME_MS,
  MAX_FUTURE_SKEW_MS,
} from "./public-message/index.js";
export type {
  UnsignedPublicMessage,
  SignedPublicMessage,
  VerifiedPublicMessage,
  DeduplicationKey as PublicMessageDeduplicationKey,
} from "./public-message/index.js";
// 私密收件箱的有效期上限；业务层应复用这些协议常量，避免自行复制 TTL。
export {
  PRIVATE_MESSAGE_DEFAULT_MAX_LIFETIME_MS,
  PING_PRIVATE_MESSAGE_MAX_LIFETIME_MS,
  WEBRTC_PRIVATE_MESSAGE_MAX_LIFETIME_MS,
  privateMessageMaxLifetimeMs
} from "./inbox/index.js";
/** JSONValue 是各协议允许的递归 JSON 数据类型。 */
export type { JSONValue } from "./internal/strict-json.js";
