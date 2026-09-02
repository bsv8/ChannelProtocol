/** Hash 请求频道模块，对应 01-Hash请求频道.md。 */
import { multiaddr } from "@multiformats/multiaddr";

import { HASH_REQUEST_CHANNEL } from "../registry.js";
import { canonicalizeValue, sha256 } from "../internal/jcs.js";
import { ERROR_CODES, protocolError } from "../internal/errors.js";
import {
  MessageID,
  PublicKey,
  SHA256Hash,
  Signature,
  parseMessageID,
  parsePublicKey,
  parseSHA256Hash,
  parseSignature,
  parseUnixMillis,
  publicKeyFromPrivate,
  checkIdentity,
  sha256HashFromBytes,
} from "../internal/encoding.js";
import { PrivateKey } from "../internal/encoding.js";
import { MAX_JSON_BYTES } from "../internal/limits.js";
import { isJSONObject, JSONValue, parseStrictJSON, requireExactObjectKeys, requireField, requireObjectKeys } from "../internal/strict-json.js";
import { signDigest, verifyDigest } from "../internal/secp256k1.js";
import { cloneAndFreeze, freezeDeep } from "../internal/immutable.js";

export { HASH_REQUEST_CHANNEL };

const MAX_FUTURE_SKEW_MS = 60 * 1000;

const verifiedHashRequests = new WeakSet<object>();

/** locator 的联合 discriminator。 */
export type LocatorKind = "multiaddr" | "webrtc-sdp";

/** 直接连接用的标准 multiaddr locator。 */
export interface MultiaddrLocator {
  /** 分支固定为 multiaddr。 */
  readonly kind: "multiaddr";
  /** 不带 multiaddr: 包装的标准 multiaddr。 */
  readonly address: string;
}

/** 通过私密收件箱交换 WebRTC SDP 的 locator。 */
export interface WebRTCSDPLocator {
  /** 分支固定为 webrtc-sdp。 */
  readonly kind: "webrtc-sdp";
}

/** Hash 请求 locator 联合类型。 */
export type Locator = MultiaddrLocator | WebRTCSDPLocator;

/** Hash 请求正文。 */
export interface HashRequestBody {
  /** 文件字节的 SHA-256 Hash。 */
  readonly hash: SHA256Hash;
  /** 按建议尝试顺序排列的 locator，至少一个。 */
  readonly locators: readonly Locator[];
}

/** 待签名公开 Hash 请求。 */
export interface UnsignedHashRequest {
  /** 请求者长期压缩公钥。 */
  readonly from_public_key: PublicKey;
  /** 公开请求去重编号。 */
  readonly message_id: MessageID;
  /** 发布时间 Unix 毫秒。 */
  readonly issued_at_ms: number;
  /** 过期时间 Unix 毫秒，最长 10 分钟。 */
  readonly expires_at_ms: number;
  /** Hash 请求正文。 */
  readonly body: HashRequestBody;
}

/** 已签名公开 Hash 请求。 */
export interface SignedHashRequest extends UnsignedHashRequest {
  /** bsv8.public-message.v1 唯一业务签名。 */
  readonly signature: Signature;
}

/** 已完成结构、时间和签名验证的公开消息。 */
export interface VerifiedHashRequest extends SignedHashRequest {
  /** 签名逻辑对象的稳定 SHA-256 摘要。 */
  readonly digest: SHA256Hash;
}

/** 公开消息的 (from_public_key, message_id) 去重键。 */
export interface DeduplicationKey {
  /** 消息发送者公钥。 */
  readonly from_public_key: PublicKey;
  /** 消息编号。 */
  readonly message_id: MessageID;
}

/** 构造并校验 multiaddr locator。 */
export function newMultiaddrLocator(address: string): MultiaddrLocator {
  validateMultiaddr(address);
  return Object.freeze({ kind: "multiaddr", address });
}

/** 构造 WebRTC locator。 */
export function newWebRTCSDPLocator(): WebRTCSDPLocator {
  return Object.freeze({ kind: "webrtc-sdp" });
}

/** 使用发送者长期私钥生成公开消息唯一签名。 */
export function sign(message: UnsignedHashRequest, privateKey: PrivateKey | Uint8Array): SignedHashRequest {
  validateUnsigned(message, false);
  const derived = publicKeyFromPrivate(privateKey);
  checkIdentity(derived, message.from_public_key, "私钥推导公钥与 from_public_key 不一致");
  const snapshot = cloneAndFreeze(message);
  const digest = signingDigest(snapshot);
  return freezeDeep({ ...snapshot, signature: signDigest(privateKey as PrivateKey, digest) });
}

/** 输出不含 channel 字段的规范 JCS 公开消息 JSON UTF-8。 */
export function marshal(message: SignedHashRequest): Uint8Array {
  validateUnsigned(message, true);
  parseSignature(message.signature);
  verifyDigest(message.from_public_key, signingDigest(message), message.signature);
  const result = canonicalizeValue(messageValue(message));
  if (result.byteLength > MAX_JSON_BYTES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "公开消息超过 JSON 字节上限");
  return new Uint8Array(result);
}

/** 严格解析并验签公开消息，输入字段顺序可以不同。 */
export function parseAndVerify(channel: string, input: string | Uint8Array, nowMs: number): VerifiedHashRequest {
  if (channel !== HASH_REQUEST_CHANNEL) throw protocolError(ERROR_CODES.INVALID_CHANNEL, "公开 Hash 请求 channel 不合法");
  const now = parseUnixMillis(nowMs, "now_ms");
  const value = parseStrictJSON(input);
  if (!isJSONObject(value)) throw protocolError(ERROR_CODES.INVALID_JSON, "公开消息根值必须是 object");
  requireObjectKeys(value, ["from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"]);
  const message = parseMessage(value);
  validateUnsigned(message, true);
  if (message.issued_at_ms > now && message.issued_at_ms - now > MAX_FUTURE_SKEW_MS) throw protocolError(ERROR_CODES.INVALID_TIME, "公开消息发布时间超出允许的未来时钟偏差");
  if (now >= message.expires_at_ms) throw protocolError(ERROR_CODES.MESSAGE_EXPIRED, "公开消息已过期");
  const digest = signingDigest(message);
  verifyDigest(message.from_public_key, digest, message.signature);
  return verifiedHashRequest({ ...message, digest: sha256HashFromBytes(digest) });
}

/** 返回公开消息去重键。 */
export function dedupKey(message: VerifiedHashRequest): DeduplicationKey {
  requireVerifiedHashRequest(message);
  return freezeDeep({ from_public_key: message.from_public_key, message_id: message.message_id });
}

/** 返回值是否由本 SDK 的 parseAndVerify 创建，供跨模块关系审查使用。 */
export function isVerifiedHashRequest(value: unknown): value is VerifiedHashRequest {
  return value !== null && typeof value === "object" && verifiedHashRequests.has(value) && Object.isFrozen(value);
}

/** 返回已签名逻辑消息摘要。 */
export function signedDigest(message: UnsignedHashRequest | SignedHashRequest): SHA256Hash {
  return sha256HashFromBytes(signingDigest(message));
}

/** 检查相同去重键对应的消息是否冲突。 */
export function checkDigestConflict(existing: SHA256Hash, incoming: SHA256Hash): void {
  if (existing !== incoming) throw protocolError(ERROR_CODES.MESSAGE_ID_CONFLICT, "同一公开去重键对应不同已签名内容");
}

function verifiedHashRequest(value: VerifiedHashRequest): VerifiedHashRequest {
  const frozen = freezeDeep(cloneAndFreeze(value));
  verifiedHashRequests.add(frozen);
  return frozen;
}

function requireVerifiedHashRequest(value: unknown): asserts value is VerifiedHashRequest {
  if (!isVerifiedHashRequest(value) || !Object.isFrozen(value)) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "消息不是 SDK 生成的已验证 Hash 请求");
  }
}

function messageValue(message: SignedHashRequest): unknown {
  return {
    from_public_key: message.from_public_key,
    message_id: message.message_id,
    issued_at_ms: message.issued_at_ms,
    expires_at_ms: message.expires_at_ms,
    body: bodyValue(message.body),
    signature: message.signature,
  };
}

function signingValue(message: UnsignedHashRequest): unknown {
  return {
    scope: "bsv8.public-message.v1",
    channel: HASH_REQUEST_CHANNEL,
    from_public_key: message.from_public_key,
    message: {
      message_id: message.message_id,
      issued_at_ms: message.issued_at_ms,
      expires_at_ms: message.expires_at_ms,
      body: bodyValue(message.body),
    },
  };
}

function signingDigest(message: UnsignedHashRequest): Uint8Array {
  return sha256(canonicalizeValue(signingValue(message)));
}

function bodyValue(body: HashRequestBody): unknown {
  return {
    hash: body.hash,
    locators: body.locators.map((locator) => locator.kind === "multiaddr" ? { kind: locator.kind, address: locator.address } : { kind: locator.kind }),
  };
}

function parseMessage(value: Record<string, JSONValue>): SignedHashRequest {
  const from_public_key = parsePublicKey(stringField(value, "from_public_key"));
  const message_id = parseMessageID(stringField(value, "message_id"));
  const issued_at_ms = parseUnixMillis(requireField(value, "issued_at_ms"), "issued_at_ms");
  const expires_at_ms = parseUnixMillis(requireField(value, "expires_at_ms"), "expires_at_ms");
  const bodyValueRaw = requireField(value, "body");
  if (!isJSONObject(bodyValueRaw)) throw protocolError(ERROR_CODES.INVALID_BODY, "Hash 请求 body 必须是 object");
  const body = parseBody(bodyValueRaw);
  const signature = parseSignature(stringField(value, "signature"));
  return { from_public_key, message_id, issued_at_ms, expires_at_ms, body, signature };
}

function parseBody(value: Record<string, JSONValue>): HashRequestBody {
  requireObjectKeys(value, ["hash", "locators"]);
  const hash = parseSHA256Hash(stringField(value, "hash"));
  const locatorsValue = requireField(value, "locators");
  if (!Array.isArray(locatorsValue) || locatorsValue.length === 0) throw protocolError(ERROR_CODES.INVALID_BODY, "locators 必须是至少一个元素的数组");
  const locators = locatorsValue.map((raw) => {
    if (!isJSONObject(raw)) throw protocolError(ERROR_CODES.INVALID_BODY, "locator 必须是 object");
    const kind = stringField(raw, "kind") as LocatorKind;
    if (kind === "multiaddr") {
      requireObjectKeys(raw, ["kind", "address"]);
      const address = stringField(raw, "address");
      validateMultiaddr(address);
      return Object.freeze({ kind: "multiaddr", address }) as MultiaddrLocator;
    }
    if (kind === "webrtc-sdp") {
      requireObjectKeys(raw, ["kind"]);
      return Object.freeze({ kind: "webrtc-sdp" }) as WebRTCSDPLocator;
    }
    throw protocolError(ERROR_CODES.INVALID_BODY, "不支持的 locator.kind");
  });
  return cloneAndFreeze({ hash, locators });
}

function validateUnsigned(message: UnsignedHashRequest, withSignature: boolean): void {
  requireExactObjectKeys(message, withSignature ? ["from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"] : ["from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body"], "Hash 请求消息");
  parsePublicKey(message.from_public_key);
  parseMessageID(message.message_id);
  const issued = parseUnixMillis(message.issued_at_ms, "issued_at_ms");
  const expires = parseUnixMillis(message.expires_at_ms, "expires_at_ms");
  if (issued >= expires || expires - issued > 10 * 60 * 1000) throw protocolError(ERROR_CODES.INVALID_TIME, "Hash 请求时间顺序或最长有效期不合法");
  requireExactObjectKeys(message.body, ["hash", "locators"], "Hash 请求 body");
  parseSHA256Hash(message.body.hash);
  if (!Array.isArray(message.body.locators) || message.body.locators.length === 0) throw protocolError(ERROR_CODES.INVALID_BODY, "至少需要一个 locator");
  for (const locator of message.body.locators) {
    if (locator === null || typeof locator !== "object" || Array.isArray(locator)) throw protocolError(ERROR_CODES.INVALID_BODY, "locator 必须是 object");
    if (locator.kind === "multiaddr") {
      requireExactObjectKeys(locator, ["kind", "address"], "multiaddr locator");
      validateMultiaddr(locator.address as string);
    } else if (locator.kind === "webrtc-sdp") {
      requireExactObjectKeys(locator, ["kind"], "webrtc-sdp locator");
    } else {
      throw protocolError(ERROR_CODES.INVALID_BODY, "locator 分支字段不合法");
    }
  }
}

function validateMultiaddr(address: string): void {
  if (typeof address !== "string" || address.length === 0) throw protocolError(ERROR_CODES.INVALID_BODY, "multiaddr address 不能为空");
  try {
    multiaddr(address);
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_BODY, "multiaddr address 语法不合法", cause);
  }
}

function stringField(object: Record<string, JSONValue>, field: string): string {
  const value = requireField(object, field);
  if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_BODY, `${field} 必须是 string`);
  return value;
}
