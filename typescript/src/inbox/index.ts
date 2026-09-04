/** 私密收件箱模块，对应 02-私密收件箱.md。 */
import { INBOX_CHANNEL_PREFIX, INBOX_ENVELOPE_VERSION, APP_MESSAGE_PROTOCOL, PING_PROTOCOL, WEBRTC_SIGNAL_PROTOCOL } from "../registry.js";
import { ERROR_CODES, ChannelProtocolError, hasCode, protocolError } from "../internal/errors.js";
import {
  MessageID,
  PrivateKey,
  PublicKey,
  SHA256Hash,
  Signature,
  RandomSource,
  base64urlEncode,
  decodeFixedBase64URL,
  decodeRawBase64URL,
  inboxChannel,
  parseInboxChannel,
  parseMessageID,
  parsePrivateKey,
  parsePublicKey,
  parseSignature,
  parseUnixMillis,
  publicKeyFromPrivate,
  secureRandom,
  sha256HashFromBytes,
  checkIdentity,
} from "../internal/encoding.js";
import { canonicalizeValue, sha256 } from "../internal/jcs.js";
import { clearBytes, decrypt, deriveKey, encrypt } from "../internal/crypto-box.js";
import { MAX_JSON_BYTES } from "../internal/limits.js";
import { isJSONObject, JSONValue, parseStrictJSON, requireExactObjectKeys, requireField, requireObjectKeys } from "../internal/strict-json.js";
import { ecdh as ecdhImported, signDigest as signDigestImported, verifyDigest as verifyDigestImported } from "../internal/secp256k1.js";
import { cloneAndFreeze, freezeDeep } from "../internal/immutable.js";
import { MAX_LIFETIME_MS as APP_MESSAGE_MAX_LIFETIME_MS, MessageV1Body, parseBodyValue as parseAppBodyValue, validateBody as validateAppBody } from "../app-message/index.js";
import { MAX_LIFETIME_MS as WEBRTC_MAX_LIFETIME_MS, SessionKey, WebRTCSignalV1Body, parseBodyValue as parseWebRTCBodyValue, sessionKey, validateBody as validateWebRTCBody } from "../webrtc-signal/index.js";
import { MAX_LIFETIME_MS as PING_MAX_LIFETIME_MS, PingBody, PongBody, parseBodyValue as parsePingBodyValue, validateBody as validatePingBody } from "../ping/index.js";
import type { VerifiedHashRequest } from "../hash-request/index.js";
import { isVerifiedHashRequest } from "../hash-request/index.js";

export { INBOX_CHANNEL_PREFIX, INBOX_ENVELOPE_VERSION };

/**
 * 私密消息默认的最大有效期（24 小时）。调用方可以选择更短的有效期，
 * 但不能超过对应子协议的上限。
 */
export const PRIVATE_MESSAGE_DEFAULT_MAX_LIFETIME_MS = APP_MESSAGE_MAX_LIFETIME_MS;
/** Ping/Pong 私密消息的最大有效期（60 秒）。 */
export const PING_PRIVATE_MESSAGE_MAX_LIFETIME_MS = PING_MAX_LIFETIME_MS;
/** WebRTC SDP/ICE 私密消息的最大有效期（120 秒）。 */
export const WEBRTC_PRIVATE_MESSAGE_MAX_LIFETIME_MS = WEBRTC_MAX_LIFETIME_MS;

/** 返回指定私密子协议允许的最大有效期；未知协议使用默认上限。 */
export function privateMessageMaxLifetimeMs(protocol: string): number {
  if (protocol === WEBRTC_SIGNAL_PROTOCOL) return WEBRTC_PRIVATE_MESSAGE_MAX_LIFETIME_MS;
  if (protocol === PING_PROTOCOL) return PING_PRIVATE_MESSAGE_MAX_LIFETIME_MS;
  return PRIVATE_MESSAGE_DEFAULT_MAX_LIFETIME_MS;
}

const verifiedPrivateMessages = new WeakSet<object>();

/** 私密消息可用的强类型 body 联合类型。 */
export type PrivateBody = WebRTCSignalV1Body | MessageV1Body | PingBody | PongBody;

/** V1 加密信封；字段即线上 JSON 字段，所有字节均使用无填充 base64url。 */
export interface EncryptedEnvelopeV1 {
  /** 实际目标 inbox channel，不写入信封 JSON。 */
  readonly channel: string;
  /** 加密格式版本，固定为 1。 */
  readonly envelope_version: 1;
  /** 信封发送者长期公钥。 */
  readonly from_public_key: PublicKey;
  /** 每条消息新的 32 字节 HKDF salt。 */
  readonly kdf_salt: string;
  /** 每条消息新的 12 字节 AES-GCM nonce。 */
  readonly nonce: string;
  /** ciphertext || 16-byte GCM tag。 */
  readonly ciphertext: string;
}

/** 待签名私密消息的公共字段；protocol/body 在联合分支中保持一一对应。 */
interface UnsignedPrivateMessageFields {
  /** 实际目标 inbox channel。 */
  readonly channel: string;
  /** 信封发送者长期公钥。 */
  readonly from_public_key: PublicKey;
  /** 私密消息去重编号。 */
  readonly message_id: MessageID;
  /** 发布时间 Unix 毫秒。 */
  readonly issued_at_ms: number;
  /** 过期时间 Unix 毫秒。 */
  readonly expires_at_ms: number;
}

/** 待签名私密消息；protocol 与 body 是相关联的 discriminated union。 */
export type UnsignedPrivateMessage =
  | (UnsignedPrivateMessageFields & { readonly protocol: typeof WEBRTC_SIGNAL_PROTOCOL; readonly body: WebRTCSignalV1Body })
  | (UnsignedPrivateMessageFields & { readonly protocol: typeof APP_MESSAGE_PROTOCOL; readonly body: MessageV1Body })
  | (UnsignedPrivateMessageFields & { readonly protocol: typeof PING_PROTOCOL; readonly body: PingBody | PongBody });

/** 已签名私密消息；signature 只在公共消息壳添加一次。 */
export type SignedPrivateMessage = UnsignedPrivateMessage & {
  /** bsv8.private-message.v1 唯一业务签名。 */
  readonly signature: Signature;
};

/** Open 完成解密、时间、签名验证和固定协议分派后的唯一结果。 */
export interface VerifiedPrivateMessage {
  /** 实际 inbox channel。 */
  readonly channel: string;
  /** 只能取信封 from_public_key。 */
  readonly from_public_key: PublicKey;
  /** 只能取 channel 后缀公钥。 */
  readonly to_public_key: PublicKey;
  /** 解密后的 protocol。 */
  readonly protocol: string;
  /** 私密消息编号。 */
  readonly message_id: MessageID;
  /** 发布时间 Unix 毫秒。 */
  readonly issued_at_ms: number;
  /** 过期时间 Unix 毫秒。 */
  readonly expires_at_ms: number;
  /** 已验证的强类型 body。 */
  readonly body: PrivateBody;
  /** 已验签的唯一业务签名。 */
  readonly signature: Signature;
  /** 签名逻辑摘要。 */
  readonly digest: SHA256Hash;
  /** 运行时身份由模块私有 WeakSet 维护，调用方不能伪造。 */
}

/** 私密消息去重键。 */
export interface DeduplicationKey {
  /** 子协议名称。 */
  readonly protocol: string;
  /** 发送者公钥。 */
  readonly from_public_key: PublicKey;
  /** 消息编号。 */
  readonly message_id: MessageID;
}

/** 严格解析不解密的加密信封。 */
export function parseEnvelope(channel: string, input: string | Uint8Array): EncryptedEnvelopeV1 {
  const toPublicKey = parseInboxChannel(channel, INBOX_CHANNEL_PREFIX);
  const value = parseStrictJSON(input);
  if (!isJSONObject(value)) throw protocolError(ERROR_CODES.INVALID_JSON, "加密信封根值必须是 object");
  requireObjectKeys(value, ["envelope_version", "from_public_key", "kdf_salt", "nonce", "ciphertext"]);
  if (value.envelope_version !== 1) throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "envelope_version 必须精确为 1");
  const from_public_key = parsePublicKey(stringField(value, "from_public_key"));
  const kdf_salt = stringField(value, "kdf_salt");
  decodeFixedBase64URL(kdf_salt, 32, ERROR_CODES.INVALID_ENVELOPE, "kdf_salt");
  const nonce = stringField(value, "nonce");
  decodeFixedBase64URL(nonce, 12, ERROR_CODES.INVALID_ENVELOPE, "nonce");
  const ciphertext = stringField(value, "ciphertext");
  const ciphertextBytes = decodeRawBase64URL(ciphertext, ERROR_CODES.INVALID_ENVELOPE, "ciphertext");
  if (ciphertextBytes.length < 16) throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "ciphertext 必须包含 16 字节 GCM tag");
  void toPublicKey;
  return freezeDeep({ channel, envelope_version: INBOX_ENVELOPE_VERSION, from_public_key, kdf_salt, nonce, ciphertext });
}

/** 输出规范 JCS 加密信封 JSON UTF-8。 */
export function marshalEnvelope(envelope: EncryptedEnvelopeV1): Uint8Array {
  validateEnvelope(envelope);
  const result = canonicalizeValue({
    envelope_version: envelope.envelope_version,
    from_public_key: envelope.from_public_key,
    kdf_salt: envelope.kdf_salt,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
  });
  if (result.byteLength > MAX_JSON_BYTES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "加密信封超过 JSON 字节上限");
  return new Uint8Array(result);
}

/** 对强类型私密消息生成唯一确定性签名。 */
export function signPrivateMessage(message: UnsignedPrivateMessage, privateKey: PrivateKey | Uint8Array): SignedPrivateMessage {
  validateUnsigned(message, false);
  const snapshot = cloneAndFreeze(message);
  const derived = publicKeyFromPrivate(privateKey);
  checkIdentity(derived, snapshot.from_public_key, "私钥推导公钥与 from_public_key 不一致");
  const digest = signingDigest(snapshot);
  return freezeDeep({ ...snapshot, signature: signDigestWithPrivate(privateKey, digest) });
}

/**
 * 验证一条本地已签名私密消息并提升为关系校验可用的 verified 值。
 *
 * 该入口不执行解密；适用于发送方保留自己刚生成的 Ping，随后用
 * `validatePongRelation` 校验收到的 Pong。远端密文仍必须先经过 `open`。
 */
export function verifySignedPrivateMessage(message: SignedPrivateMessage, nowMs: number): VerifiedPrivateMessage {
  parseUnixMillis(nowMs, "now_ms");
  validateUnsigned(message, true);
  parseSignature(message.signature);
  const digest = signingDigest(message);
  verifyDigestWithPublic(message.from_public_key, digest, message.signature);
  validatePrivateTimes(message.issued_at_ms, message.expires_at_ms, nowMs, message.protocol, true);
  const recipient = parseInboxChannel(message.channel, INBOX_CHANNEL_PREFIX);
  return verifiedPrivateMessage({
    channel: message.channel,
    from_public_key: message.from_public_key,
    to_public_key: recipient,
    protocol: message.protocol,
    message_id: message.message_id,
    issued_at_ms: message.issued_at_ms,
    expires_at_ms: message.expires_at_ms,
    body: message.body,
    signature: message.signature,
    digest: sha256HashFromBytes(digest),
  });
}

/** 输出已签名私密消息明文的规范 JCS JSON；不包含 channel/from_public_key。 */
export function marshalPrivateMessage(message: SignedPrivateMessage): Uint8Array {
  validateUnsigned(message, true);
  parseSignature(message.signature);
  verifyDigestWithPublic(message.from_public_key, signingDigest(message), message.signature);
  const result = canonicalizeValue(signedMessageValue(message));
  if (result.byteLength > MAX_JSON_BYTES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "私密明文超过 JSON 字节上限");
  return new Uint8Array(result);
}

/** 使用新的 salt/nonce 重新加密同一份已签名消息。 */
export async function sealSigned(message: SignedPrivateMessage, senderPrivateKey: PrivateKey | Uint8Array, source: RandomSource = secureRandom): Promise<EncryptedEnvelopeV1> {
  validateSigned(message, senderPrivateKey);
  const sender = parsePrivateKey(senderPrivateKey);
  const recipient = parseInboxChannel(message.channel, INBOX_CHANNEL_PREFIX);
  const salt = source.randomBytes(32);
  const nonce = source.randomBytes(12);
  if (salt.length !== 32 || nonce.length !== 12) throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "随机源返回的 salt/nonce 长度不合法");
  const shared = ecdhWithPrivate(sender, recipient);
  try {
    const info = canonicalizeValue({ scope: "bsv8.inbox.envelope.v1", channel: message.channel, from_public_key: message.from_public_key });
    const kdf_salt = base64urlEncode(salt);
    const nonceText = base64urlEncode(nonce);
    const aad = canonicalizeValue({ channel: message.channel, envelope_version: INBOX_ENVELOPE_VERSION, from_public_key: message.from_public_key, kdf_salt, nonce: nonceText });
    const key = await deriveKey(shared, salt, info);
    try {
      const plaintext = marshalPrivateMessage(message);
      try {
        const ciphertext = await encrypt(key, nonce, plaintext, aad);
        const envelope = freezeDeep({ channel: message.channel, envelope_version: INBOX_ENVELOPE_VERSION, from_public_key: message.from_public_key, kdf_salt, nonce: nonceText, ciphertext: base64urlEncode(ciphertext) });
        marshalEnvelope(envelope);
        return envelope;
      } finally {
        clearBytes(plaintext);
      }
    } finally {
      clearBytes(key);
    }
  } finally {
    clearBytes(shared);
  }
}

/** 首次发送的签名加密便利组合。 */
export async function signAndSeal(message: UnsignedPrivateMessage, privateKey: PrivateKey | Uint8Array, source: RandomSource = secureRandom): Promise<EncryptedEnvelopeV1> {
  return sealSigned(signPrivateMessage(message, privateKey), privateKey, source);
}

/** 解密、严格解析、时间检查并验证唯一私密消息签名。 */
export async function open(channel: string, envelopeJSON: string | Uint8Array, recipientPrivateKey: PrivateKey | Uint8Array, nowMs: number): Promise<VerifiedPrivateMessage> {
  parseUnixMillis(nowMs, "now_ms");
  const envelope = parseEnvelope(channel, envelopeJSON);
  try {
    const recipient = parseInboxChannel(channel, INBOX_CHANNEL_PREFIX);
    const recipientKey = parsePrivateKey(recipientPrivateKey);
    if (publicKeyFromPrivate(recipientKey) !== recipient) throw new Error("recipient mismatch");
    const shared = ecdhWithPrivate(recipientKey, envelope.from_public_key);
    try {
      const salt = decodeFixedBase64URL(envelope.kdf_salt, 32, ERROR_CODES.OPEN_FAILED, "kdf_salt");
      const nonce = decodeFixedBase64URL(envelope.nonce, 12, ERROR_CODES.OPEN_FAILED, "nonce");
      const info = canonicalizeValue({ scope: "bsv8.inbox.envelope.v1", channel, from_public_key: envelope.from_public_key });
      const aad = canonicalizeValue({ channel, envelope_version: INBOX_ENVELOPE_VERSION, from_public_key: envelope.from_public_key, kdf_salt: envelope.kdf_salt, nonce: envelope.nonce });
      const key = await deriveKey(shared, salt, info);
      try {
        const ciphertext = decodeRawBase64URL(envelope.ciphertext, ERROR_CODES.OPEN_FAILED, "ciphertext");
        const plaintext = await decrypt(key, nonce, ciphertext, aad);
        try {
          const value = parseStrictJSON(plaintext);
          if (!isJSONObject(value)) throw new Error("private message root");
          requireObjectKeys(value, ["protocol", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"]);
          const protocol = stringField(value, "protocol");
          const message_id = parseMessageID(stringField(value, "message_id"));
          const issued_at_ms = parseUnixMillis(requireField(value, "issued_at_ms"), "issued_at_ms");
          const expires_at_ms = parseUnixMillis(requireField(value, "expires_at_ms"), "expires_at_ms");
          validatePrivateTimes(issued_at_ms, expires_at_ms, nowMs, protocol, true);
          const bodyValue = requireField(value, "body");
          const signature = parseSignature(stringField(value, "signature"));
          const digest = signingDigestRaw(channel, envelope.from_public_key, protocol, message_id, issued_at_ms, expires_at_ms, bodyValue);
          verifyDigestWithPublic(envelope.from_public_key, digest, signature);
          const body = parsePrivateBody(protocol, bodyValue);
          return verifiedPrivateMessage({ channel, from_public_key: envelope.from_public_key, to_public_key: recipient, protocol, message_id, issued_at_ms, expires_at_ms, body, signature, digest: sha256HashFromBytes(digest) });
        } finally {
          clearBytes(plaintext);
        }
      } finally {
        clearBytes(key);
      }
    } finally {
      clearBytes(shared);
    }
  } catch (error) {
    if (error instanceof ChannelProtocolError && (hasCode(error, ERROR_CODES.MESSAGE_EXPIRED) || hasCode(error, ERROR_CODES.INVALID_TIME) || hasCode(error, ERROR_CODES.UNSUPPORTED_PROTOCOL))) throw error;
    throw protocolError(ERROR_CODES.OPEN_FAILED, "私密信封无法打开");
  }
}

/** 从两条已解密、已验签的完整私密消息检查 Deliver/ACK 关系。 */
export function validateAckRelation(delivery: VerifiedPrivateMessage, ack: VerifiedPrivateMessage): void {
  requireVerifiedPrivateMessage(delivery);
  requireVerifiedPrivateMessage(ack);
  if (delivery.protocol !== APP_MESSAGE_PROTOCOL || ack.protocol !== APP_MESSAGE_PROTOCOL) throw protocolError(ERROR_CODES.INVALID_RELATION, "Deliver 和 ACK 必须属于应用消息子协议");
	if (!isAppBody(delivery.body) || delivery.body.type !== "deliver") throw protocolError(ERROR_CODES.INVALID_RELATION, "第一条应用消息不是 Deliver");
	if (!isAppBody(ack.body) || ack.body.type !== "ack") throw protocolError(ERROR_CODES.INVALID_RELATION, "第二条应用消息不是 ACK");
  if (ack.from_public_key !== delivery.to_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "ACK 发送者不是 Deliver 接收者");
  if (ack.to_public_key !== delivery.from_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "ACK 接收者不是 Deliver 发送者");
	if (ack.body.acknowledged_message_id !== delivery.message_id) throw protocolError(ERROR_CODES.INVALID_RELATION, "ACK 未关联原 Deliver message_id");
}

/** 从两条已解密、已验签的完整私密消息检查 Ping/Pong 关系。 */
export function validatePongRelation(pingMessage: VerifiedPrivateMessage, pongMessage: VerifiedPrivateMessage): void {
  requireVerifiedPrivateMessage(pingMessage);
  requireVerifiedPrivateMessage(pongMessage);
  if (pingMessage.protocol !== PING_PROTOCOL || pongMessage.protocol !== PING_PROTOCOL) throw protocolError(ERROR_CODES.INVALID_RELATION, "Ping 和 Pong 必须属于 Ping/Pong 子协议");
	if (!isPingBody(pingMessage.body) || pingMessage.body.type !== "ping" || !isPingBody(pongMessage.body) || pongMessage.body.type !== "pong") throw protocolError(ERROR_CODES.INVALID_RELATION, "Ping/Pong body 类型不匹配");
  if (pongMessage.from_public_key !== pingMessage.to_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "Pong 发送者不是 Ping 接收者");
  if (pongMessage.to_public_key !== pingMessage.from_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "Pong 接收者不是 Ping 发送者");
	if (pongMessage.body.ping_message_id !== pingMessage.message_id) throw protocolError(ERROR_CODES.INVALID_RELATION, "Pong 未关联原 Ping message_id");
}

/** 从已解密、已验签的 offer 和后续信令检查 WebRTC 关系。 */
export function validateWebRTCRelation(offer: VerifiedPrivateMessage, message: VerifiedPrivateMessage): void {
  requireVerifiedPrivateMessage(offer);
  requireVerifiedPrivateMessage(message);
  if (offer.protocol !== WEBRTC_SIGNAL_PROTOCOL || message.protocol !== WEBRTC_SIGNAL_PROTOCOL) throw protocolError(ERROR_CODES.INVALID_RELATION, "WebRTC 消息必须属于 WebRTC 子协议");
	if (!isWebRTCBody(offer.body) || offer.body.signal.type !== "offer") throw protocolError(ERROR_CODES.INVALID_RELATION, "第一条 WebRTC 消息必须是 offer");
	if (!isWebRTCBody(message.body)) throw protocolError(ERROR_CODES.INVALID_RELATION, "WebRTC 后续消息 body 不合法");
	const offerBody = offer.body;
	const nextBody = message.body;
  if (nextBody.request_message_id !== offerBody.request_message_id || nextBody.session_id !== offerBody.session_id) throw protocolError(ERROR_CODES.INVALID_RELATION, "WebRTC request_message_id 或 session_id 不匹配");
  if (nextBody.signal.type === "answer") {
    if (message.from_public_key !== offer.to_public_key || message.to_public_key !== offer.from_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "answer 方向与 offer 不匹配");
    return;
  }
  if (nextBody.signal.type !== "ice-candidate" && nextBody.signal.type !== "end-of-candidates") throw protocolError(ERROR_CODES.INVALID_RELATION, "WebRTC 后续消息必须是 answer、ICE 或 end-of-candidates");
  const senderIsParticipant = message.from_public_key === offer.from_public_key || message.from_public_key === offer.to_public_key;
  const recipientIsParticipant = message.to_public_key === offer.from_public_key || message.to_public_key === offer.to_public_key;
  if (!senderIsParticipant || !recipientIsParticipant || message.from_public_key === message.to_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "ICE 发送者或接收者不属于 offer 双方");
}

/**
 * 统一审查 WebRTC offer 与已验证 Hash 请求的跨协议关系。
 * session_id 是否已被本地使用仍由调用方状态存储负责。
 */
export function reviewOfferForHashRequest(hashRequest: VerifiedHashRequest, offer: VerifiedPrivateMessage, nowMs: number): SessionKey {
  if (!isVerifiedHashRequest(hashRequest) || !Object.isFrozen(hashRequest)) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "Hash 请求不是 SDK 生成的已验证结果");
  }
  requireVerifiedPrivateMessage(offer);
  const now = parseUnixMillis(nowMs, "now_ms");
  if (now >= hashRequest.expires_at_ms) throw protocolError(ERROR_CODES.MESSAGE_EXPIRED, "引用的 Hash 请求已过期");
  if (!hashRequest.body.locators.some((locator) => locator.kind === "webrtc-sdp")) {
    throw protocolError(ERROR_CODES.INVALID_RELATION, "Hash 请求未声明 webrtc-sdp locator");
  }
  if (offer.protocol !== WEBRTC_SIGNAL_PROTOCOL) throw protocolError(ERROR_CODES.INVALID_RELATION, "offer protocol 不是 WebRTC 子协议");
	if (!isWebRTCBody(offer.body) || offer.body.signal.type !== "offer") throw protocolError(ERROR_CODES.INVALID_RELATION, "引用的私密消息不是 WebRTC offer");
	const body = offer.body;
  if (body.request_message_id !== hashRequest.message_id) throw protocolError(ERROR_CODES.INVALID_RELATION, "offer 未关联该 Hash 请求 message_id");
  if (offer.to_public_key !== hashRequest.from_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "offer 接收者不是 Hash 请求者");
  return sessionKey(hashRequest.message_id, offer.from_public_key, body.session_id);
}

/** 返回私密消息去重键。 */
export function dedupKey(message: VerifiedPrivateMessage): DeduplicationKey {
  requireVerifiedPrivateMessage(message);
  return freezeDeep({ protocol: message.protocol, from_public_key: message.from_public_key, message_id: message.message_id });
}

/** 检查两个摘要是否冲突。 */
export function checkDigestConflict(existing: SHA256Hash, incoming: SHA256Hash): void {
  if (existing !== incoming) throw protocolError(ERROR_CODES.MESSAGE_ID_CONFLICT, "同一私密去重键对应不同已签名内容");
}

/** 返回私密签名逻辑对象摘要。 */
export function signedDigest(message: UnsignedPrivateMessage | SignedPrivateMessage): SHA256Hash {
  return sha256HashFromBytes(signingDigest(message));
}

function verifiedPrivateMessage(value: VerifiedPrivateMessage): VerifiedPrivateMessage {
  const frozen = freezeDeep(cloneAndFreeze(value));
  verifiedPrivateMessages.add(frozen);
  return frozen;
}

function requireVerifiedPrivateMessage(value: unknown): asserts value is VerifiedPrivateMessage {
  if (value === null || typeof value !== "object" || !verifiedPrivateMessages.has(value) || !Object.isFrozen(value)) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "消息不是 SDK 生成的已验证私密消息");
  }
}

function parsePrivateBody(protocol: string, value: JSONValue): PrivateBody {
  if (protocol === WEBRTC_SIGNAL_PROTOCOL) return parseWebRTCBodyValue(value);
  if (protocol === APP_MESSAGE_PROTOCOL) return parseAppBodyValue(value);
  if (protocol === PING_PROTOCOL) return parsePingBodyValue(value);
  throw protocolError(ERROR_CODES.UNSUPPORTED_PROTOCOL, "私密消息 protocol 未注册");
}

function validateEnvelope(envelope: EncryptedEnvelopeV1): void {
  requireExactObjectKeys(envelope, ["channel", "envelope_version", "from_public_key", "kdf_salt", "nonce", "ciphertext"], "加密信封", ERROR_CODES.INVALID_ENVELOPE);
  parseInboxChannel(envelope.channel, INBOX_CHANNEL_PREFIX);
  if (envelope.envelope_version !== 1) throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "envelope_version 不支持");
  parsePublicKey(envelope.from_public_key);
  decodeFixedBase64URL(envelope.kdf_salt, 32, ERROR_CODES.INVALID_ENVELOPE, "kdf_salt");
  decodeFixedBase64URL(envelope.nonce, 12, ERROR_CODES.INVALID_ENVELOPE, "nonce");
  if (decodeRawBase64URL(envelope.ciphertext, ERROR_CODES.INVALID_ENVELOPE, "ciphertext").length < 16) throw protocolError(ERROR_CODES.INVALID_ENVELOPE, "ciphertext 缺少 GCM tag");
}

function validateUnsigned(message: UnsignedPrivateMessage, withSignature: boolean): void {
  requireExactObjectKeys(message, withSignature ? ["channel", "from_public_key", "protocol", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"] : ["channel", "from_public_key", "protocol", "message_id", "issued_at_ms", "expires_at_ms", "body"], "私密消息");
  parseInboxChannel(message.channel, INBOX_CHANNEL_PREFIX);
  parsePublicKey(message.from_public_key);
  parseMessageID(message.message_id);
  if (message.protocol !== WEBRTC_SIGNAL_PROTOCOL && message.protocol !== APP_MESSAGE_PROTOCOL && message.protocol !== PING_PROTOCOL) throw protocolError(ERROR_CODES.UNSUPPORTED_PROTOCOL, "私密消息 protocol 未注册");
  if (message.protocol === WEBRTC_SIGNAL_PROTOCOL) {
    if (!isWebRTCBody(message.body)) throw protocolError(ERROR_CODES.INVALID_BODY, "protocol 与 WebRTC body 类型不一致");
    validateWebRTCBody(message.body);
  } else if (message.protocol === APP_MESSAGE_PROTOCOL) {
    if (!isAppBody(message.body)) throw protocolError(ERROR_CODES.INVALID_BODY, "protocol 与应用 body 类型不一致");
    validateAppBody(message.body);
  } else {
    if (!isPingBody(message.body)) throw protocolError(ERROR_CODES.INVALID_BODY, "protocol 与 Ping/Pong body 类型不一致");
    validatePingBody(message.body);
  }
  validatePrivateTimes(message.issued_at_ms, message.expires_at_ms, 0, message.protocol, false);
}

function validateSigned(message: SignedPrivateMessage, privateKey: PrivateKey | Uint8Array): void {
  validateUnsigned(message, true);
  const sender = publicKeyFromPrivate(privateKey);
  checkIdentity(sender, message.from_public_key, "Seal 使用的私钥与已签名发送者不一致");
  parseSignature(message.signature);
  const digest = signingDigest(message);
  verifyDigestWithPublic(message.from_public_key, digest, message.signature);
}

function signedMessageValue(message: SignedPrivateMessage): unknown {
  return { protocol: message.protocol, message_id: message.message_id, issued_at_ms: message.issued_at_ms, expires_at_ms: message.expires_at_ms, body: message.body, signature: message.signature };
}

function signingValue(message: UnsignedPrivateMessage): unknown {
  return { scope: "bsv8.private-message.v1", channel: message.channel, from_public_key: message.from_public_key, message: { protocol: message.protocol, message_id: message.message_id, issued_at_ms: message.issued_at_ms, expires_at_ms: message.expires_at_ms, body: message.body } };
}

function signingDigest(message: UnsignedPrivateMessage): Uint8Array {
  return sha256(canonicalizeValue(signingValue(message)));
}

function signingDigestRaw(channel: string, fromPublicKey: PublicKey, protocol: string, messageId: MessageID, issued: number, expires: number, body: JSONValue): Uint8Array {
  return sha256(canonicalizeValue({ scope: "bsv8.private-message.v1", channel, from_public_key: fromPublicKey, message: { protocol, message_id: messageId, issued_at_ms: issued, expires_at_ms: expires, body } }));
}

function validatePrivateTimes(issued: number, expires: number, now: number, protocol: string, checkCurrent: boolean): void {
  parseUnixMillis(issued, "issued_at_ms");
  parseUnixMillis(expires, "expires_at_ms");
  if (issued >= expires) throw protocolError(ERROR_CODES.INVALID_TIME, "私密消息时间顺序不合法");
  const maxLifetime = privateMessageMaxLifetimeMs(protocol);
  if (expires - issued > maxLifetime) throw protocolError(ERROR_CODES.INVALID_TIME, "私密消息有效期超过子协议上限");
  if (checkCurrent && issued > now && issued - now > 60 * 1000) throw protocolError(ERROR_CODES.INVALID_TIME, "私密消息发布时间超出本地时钟容差");
  if (checkCurrent && now >= expires) throw protocolError(ERROR_CODES.MESSAGE_EXPIRED, "私密消息已过期");
}

function signDigestWithPrivate(privateKey: PrivateKey | Uint8Array, digest: Uint8Array): Signature {
  // signDigest 在内部再次复制并校验私钥，避免把调用方 Uint8Array 交给异步或缓存状态。
  return signDigestImported(parsePrivateKey(privateKey), digest);
}

function verifyDigestWithPublic(publicKey: PublicKey, digest: Uint8Array, signature: Signature): void {
  verifyDigestImported(publicKey, digest, signature);
}

function ecdhWithPrivate(privateKey: PrivateKey, publicKey: PublicKey): Uint8Array {
  return ecdhImported(privateKey, publicKey);
}

function stringField(object: Record<string, JSONValue>, field: string): string {
  const value = requireField(object, field);
  if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_ENVELOPE, `${field} 必须是 string`);
  return value;
}

function isWebRTCBody(value: PrivateBody): value is WebRTCSignalV1Body {
  return value !== null && typeof value === "object" && !Array.isArray(value) && "request_message_id" in value && "session_id" in value && "signal" in value;
}

function isAppBody(value: PrivateBody): value is MessageV1Body {
  return value !== null && typeof value === "object" && !Array.isArray(value) && "type" in value && (value.type === "deliver" || value.type === "ack");
}

function isPingBody(value: PrivateBody): value is PingBody | PongBody {
  return value !== null && typeof value === "object" && !Array.isArray(value) && "type" in value && (value.type === "ping" || value.type === "pong");
}
