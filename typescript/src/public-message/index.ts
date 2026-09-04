/** 任意精确公开频道的统一签名消息原语。 */

import { ERROR_CODES, protocolError } from "../internal/errors.js";
import { canonicalizeValue, sha256 } from "../internal/jcs.js";
import {
  MessageID,
  PrivateKey,
  PublicKey,
  SHA256Hash,
  Signature,
  checkIdentity,
  parseMessageID,
  parsePrivateKey,
  parsePublicKey,
  parseSignature,
  parseUnixMillis,
  publicKeyFromPrivate,
  sha256HashFromBytes,
} from "../internal/encoding.js";
import { MAX_JSON_BYTES } from "../internal/limits.js";
import { isJSONObject, JSONValue, parseStrictJSON, requireExactObjectKeys, requireField, requireObjectKeys } from "../internal/strict-json.js";
import { signDigest, verifyDigest } from "../internal/secp256k1.js";
import { cloneAndFreeze, freezeDeep } from "../internal/immutable.js";

/** 公开消息签名作用域；与 Go SDK 固定一致。 */
export const PUBLIC_MESSAGE_SCOPE = "bsv8.public-message.v1" as const;

/** 公开消息最大有效期。 */
export const PUBLIC_MESSAGE_MAX_LIFETIME_MS = 10 * 60 * 1000;

/** 公开消息允许的发布时间未来偏差。 */
export const MAX_FUTURE_SKEW_MS = 60 * 1000;

/** 任意合法精确频道的待签名消息。 */
export interface UnsignedPublicMessage {
  /** 发布到的精确频道；不允许 wildcard，且不写入线上 JSON。 */
  readonly channel: string;
  /** 发布者长期压缩公钥。 */
  readonly from_public_key: PublicKey;
  /** 32 字节公开消息编号。 */
  readonly message_id: MessageID;
  /** 发布时间 Unix 毫秒。 */
  readonly issued_at_ms: number;
  /** 过期时间 Unix 毫秒。 */
  readonly expires_at_ms: number;
  /** 应用自定义的受限 JSON 值。 */
  readonly body: JSONValue;
}

/** 已签名的公开消息。 */
export interface SignedPublicMessage extends UnsignedPublicMessage {
  /** bsv8.public-message.v1 签名。 */
  readonly signature: Signature;
}

/** 已完成结构、时间和签名验证的公开消息。 */
export interface VerifiedPublicMessage extends SignedPublicMessage {
  /** 签名逻辑对象的稳定 SHA-256 摘要。 */
  readonly digest: SHA256Hash;
}

/** 公开消息的 (channel, from_public_key, message_id) 去重键。 */
export interface DeduplicationKey {
  /** 发布消息时使用的精确频道。 */
  readonly channel: string;
  /** 发布者公钥。 */
  readonly from_public_key: PublicKey;
  /** 消息编号。 */
  readonly message_id: MessageID;
}

const verifiedPublicMessages = new WeakSet<object>();

/** 校验精确频道。 */
export function validateChannel(channel: string): void {
  if (typeof channel !== "string" || channel.length === 0 || channel === "*") {
    throw protocolError(ERROR_CODES.INVALID_CHANNEL, "公开消息必须使用非空精确 channel");
  }
  rejectUnpairedSurrogates(channel);
  const bytes = new TextEncoder().encode(channel);
  if (bytes.byteLength > 256) throw protocolError(ERROR_CODES.INVALID_CHANNEL, "channel 超过 256 UTF-8 字节");
  for (const character of channel) {
    const code = character.codePointAt(0) as number;
    if (code < 0x20 || code === 0x7f) throw protocolError(ERROR_CODES.INVALID_CHANNEL, "channel 包含控制字符");
  }
}

/** 使用发布者长期私钥生成公开消息签名。 */
export function sign(message: UnsignedPublicMessage, privateKey: PrivateKey | Uint8Array): SignedPublicMessage {
  validateUnsigned(message, false);
  const key = parsePrivateKey(privateKey);
  const derived = publicKeyFromPrivate(key);
  checkIdentity(derived, message.from_public_key, "私钥推导公钥与 from_public_key 不一致");
  const snapshot = cloneAndFreeze(message);
  const digest = signingDigest(snapshot);
  return freezeDeep({ ...snapshot, signature: signDigest(key, digest) });
}

/** 输出不含 channel 字段的规范公开消息 JSON UTF-8。 */
export function marshal(message: SignedPublicMessage): Uint8Array {
  validateUnsigned(message, true);
  parseSignature(message.signature);
  verifyDigest(message.from_public_key, signingDigest(message), message.signature);
  const result = canonicalizeValue(messageValue(message));
  if (result.byteLength > MAX_JSON_BYTES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "公开消息超过 JSON 字节上限");
  return new Uint8Array(result);
}

/** 严格解析并验签指定精确频道上的公开消息。 */
export function parseAndVerify(channel: string, input: string | Uint8Array, nowMs: number): VerifiedPublicMessage {
  validateChannel(channel);
  const now = parseUnixMillis(nowMs, "now_ms");
  const value = parseStrictJSON(input);
  if (!isJSONObject(value)) throw protocolError(ERROR_CODES.INVALID_JSON, "公开消息根值必须是 object");
  requireObjectKeys(value, ["from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"]);
  const message: SignedPublicMessage = {
    channel,
    from_public_key: parsePublicKey(stringField(value, "from_public_key")),
    message_id: parseMessageID(stringField(value, "message_id")),
    issued_at_ms: parseUnixMillis(requireField(value, "issued_at_ms"), "issued_at_ms"),
    expires_at_ms: parseUnixMillis(requireField(value, "expires_at_ms"), "expires_at_ms"),
    body: requireField(value, "body"),
    signature: parseSignature(stringField(value, "signature")),
  };
  validateUnsigned(message, true);
  if (message.issued_at_ms > now && message.issued_at_ms - now > MAX_FUTURE_SKEW_MS) {
    throw protocolError(ERROR_CODES.INVALID_TIME, "公开消息发布时间超出允许的未来时钟偏差");
  }
  if (now >= message.expires_at_ms) throw protocolError(ERROR_CODES.MESSAGE_EXPIRED, "公开消息已过期");
  const digest = signingDigest(message);
  verifyDigest(message.from_public_key, digest, message.signature);
  return verifiedPublicMessage({ ...message, digest: sha256HashFromBytes(digest) });
}

/** 返回值是否由本 SDK 的 parseAndVerify 创建，供信任边界检查使用。 */
export function isVerifiedPublicMessage(value: unknown): value is VerifiedPublicMessage {
  return value !== null && typeof value === "object" && verifiedPublicMessages.has(value) && Object.isFrozen(value);
}

/** 返回公开消息三元去重键；输入必须来自本 SDK 的验签结果。 */
export function dedupKey(message: VerifiedPublicMessage): DeduplicationKey {
  requireVerifiedPublicMessage(message);
  return freezeDeep({ channel: message.channel, from_public_key: message.from_public_key, message_id: message.message_id });
}

/** 返回签名逻辑对象摘要。 */
export function signedDigest(message: UnsignedPublicMessage | SignedPublicMessage): SHA256Hash {
  return sha256HashFromBytes(signingDigest(message));
}

/** 检查相同三元去重键对应的摘要是否冲突。 */
export function checkDigestConflict(existing: SHA256Hash, incoming: SHA256Hash): void {
  if (existing !== incoming) throw protocolError(ERROR_CODES.MESSAGE_ID_CONFLICT, "同一公开去重键对应不同已签名内容");
}

function verifiedPublicMessage(value: VerifiedPublicMessage): VerifiedPublicMessage {
  const frozen = freezeDeep(cloneAndFreeze(value));
  verifiedPublicMessages.add(frozen as object);
  return frozen;
}

function requireVerifiedPublicMessage(value: unknown): asserts value is VerifiedPublicMessage {
  if (!isVerifiedPublicMessage(value)) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "消息不是 SDK 生成的已验证公开消息");
  }
}

function validateUnsigned(message: UnsignedPublicMessage, withSignature: boolean): void {
  requireExactObjectKeys(
    message,
    withSignature
      ? ["channel", "from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"]
      : ["channel", "from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body"],
    "公开消息",
  );
  validateChannel(message.channel);
  parsePublicKey(message.from_public_key);
  parseMessageID(message.message_id);
  const issued = parseUnixMillis(message.issued_at_ms, "issued_at_ms");
  const expires = parseUnixMillis(message.expires_at_ms, "expires_at_ms");
  if (issued >= expires || expires - issued > PUBLIC_MESSAGE_MAX_LIFETIME_MS) {
    throw protocolError(ERROR_CODES.INVALID_TIME, "公开消息时间顺序或最长有效期不合法");
  }
  canonicalizeValue(message.body);
}

function signingDigest(message: UnsignedPublicMessage): Uint8Array {
  return sha256(canonicalizeValue({
    scope: PUBLIC_MESSAGE_SCOPE,
    channel: message.channel,
    from_public_key: message.from_public_key,
    message: {
      message_id: message.message_id,
      issued_at_ms: message.issued_at_ms,
      expires_at_ms: message.expires_at_ms,
      body: message.body,
    },
  }));
}

function messageValue(message: SignedPublicMessage): Record<string, unknown> {
  return {
    from_public_key: message.from_public_key,
    message_id: message.message_id,
    issued_at_ms: message.issued_at_ms,
    expires_at_ms: message.expires_at_ms,
    body: message.body,
    signature: message.signature,
  };
}

function stringField(object: Record<string, JSONValue>, field: string): string {
  const value = requireField(object, field);
  if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_BODY, `${field} 必须是 string`);
  return value;
}

function rejectUnpairedSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) throw protocolError(ERROR_CODES.INVALID_CHANNEL, "channel 包含孤立 high surrogate");
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) throw protocolError(ERROR_CODES.INVALID_CHANNEL, "channel high surrogate 缺少配对");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw protocolError(ERROR_CODES.INVALID_CHANNEL, "channel 包含孤立 low surrogate");
    }
  }
}
