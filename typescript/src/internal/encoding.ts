import { secp256k1 } from "@noble/curves/secp256k1";

import { ERROR_CODES, ErrorCode, protocolError } from "./errors.js";

/** 33 字节压缩 secp256k1 公钥的小写 hex 品牌类型。 */
export type PublicKey = string & { readonly __publicKey: unique symbol };
/** 32 字节长期 secp256k1 私钥品牌类型，运行时仍是防御性复制的 Uint8Array。 */
export type PrivateKey = Uint8Array & { readonly __privateKey: unique symbol };
/** 32 字节无填充 base64url 消息编号品牌类型。 */
export type MessageID = string & { readonly __messageId: unique symbol };
/** 32 字节无填充 base64url WebRTC 会话编号品牌类型。 */
export type SessionID = string & { readonly __sessionId: unique symbol };
/** 32 字节 SHA-256 小写 hex 品牌类型。 */
export type SHA256Hash = string & { readonly __sha256Hash: unique symbol };
/** strict DER low-S 签名的无填充 base64url 品牌类型。 */
export type Signature = string & { readonly __signature: unique symbol };

/** 随机源接口；生产默认使用 Web Crypto，测试可注入固定实现。 */
export interface RandomSource {
  /** 返回指定长度的随机字节副本。 */
  randomBytes(length: number): Uint8Array;
}

/** 默认密码学安全随机源。 */
export const secureRandom: RandomSource = Object.freeze({
  randomBytes(length: number): Uint8Array {
    if (!globalThis.crypto?.getRandomValues) throw new Error("当前运行时没有 Web Crypto 安全随机源");
    const result = new Uint8Array(length);
    globalThis.crypto.getRandomValues(result);
    return result;
  },
});

/** 从固定字节创建可复现随机源；仅用于测试。 */
export function fixedRandom(bytes: Uint8Array): RandomSource {
  const source = new Uint8Array(bytes);
  let offset = 0;
  return Object.freeze({
    randomBytes(length: number): Uint8Array {
      if (length < 0 || offset + length > source.length) throw new Error("固定随机源字节不足");
      const result = source.slice(offset, offset + length);
      offset += length;
      return result;
    },
  });
}

/** 解析 66 位小写压缩 secp256k1 公钥 hex。 */
export function parsePublicKey(value: string): PublicKey {
  if (!/^[0-9a-f]{66}$/.test(value)) throw protocolError(ERROR_CODES.INVALID_PUBLIC_KEY, "公钥必须是 66 位小写 hex");
  const bytes = hexDecode(value);
  try {
    if (!secp256k1.utils.isValidPublicKey(bytes, true)) throw new Error("invalid point");
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_PUBLIC_KEY, "公钥不是有效压缩 secp256k1 曲线点", cause);
  }
  return value as PublicKey;
}

/** 从公钥字节创建公钥品牌值，输入会被复制。 */
export function publicKeyFromBytes(value: Uint8Array): PublicKey {
  if (value.length !== 33) throw protocolError(ERROR_CODES.INVALID_PUBLIC_KEY, "公钥必须是 33 字节");
  return parsePublicKey(hexEncode(value));
}

/** 解析并复制 32 字节长期私钥。 */
export function parsePrivateKey(value: Uint8Array): PrivateKey {
  const copy = new Uint8Array(value);
  if (copy.length !== 32 || !secp256k1.utils.isValidSecretKey(copy)) {
    throw protocolError(ERROR_CODES.INVALID_PRIVATE_KEY, "私钥必须位于 secp256k1 有效范围内");
  }
  return copy as PrivateKey;
}

/** 推导长期私钥对应的压缩公钥。 */
export function publicKeyFromPrivate(value: PrivateKey | Uint8Array): PublicKey {
  const privateKey = parsePrivateKey(value);
  return publicKeyFromBytes(secp256k1.getPublicKey(privateKey, true));
}

/** 检查外层认证公钥与报文声明公钥的合法性和 exact bytes 一致性。 */
export function checkIdentity(authenticated: PublicKey, claimed: PublicKey, message: string): void {
  parsePublicKey(authenticated);
  parsePublicKey(claimed);
  if (authenticated !== claimed) throw protocolError(ERROR_CODES.IDENTITY_MISMATCH, message);
}

/** 解析固定 43 字符的 message_id。 */
export function parseMessageID(value: string): MessageID {
  const bytes = decodeFixedBase64URL(value, 32, ERROR_CODES.INVALID_MESSAGE_ID, "message_id");
  void bytes;
  return value as MessageID;
}

/** 生成密码学安全 message_id。 */
export function newMessageID(source: RandomSource = secureRandom): MessageID {
  return messageIDFromBytes(source.randomBytes(32));
}

/** 生成范围合法的长期 secp256k1 私钥；默认使用密码学安全随机源。 */
export function generatePrivateKey(source: RandomSource = secureRandom): PrivateKey {
  for (let attempt = 0; attempt < 128; attempt += 1) {
    try {
      return parsePrivateKey(source.randomBytes(32));
    } catch (error) {
      if (error instanceof Error && "code" in error && (error as { code?: string }).code === ERROR_CODES.INVALID_PRIVATE_KEY) continue;
      throw error;
    }
  }
  throw protocolError(ERROR_CODES.INVALID_PRIVATE_KEY, "随机源未生成有效 secp256k1 私钥");
}

/** 从 32 字节创建 message_id，输入会被复制。 */
export function messageIDFromBytes(value: Uint8Array): MessageID {
  if (value.length !== 32) throw protocolError(ERROR_CODES.INVALID_MESSAGE_ID, "message_id 必须是 32 字节");
  return base64urlEncode(value) as MessageID;
}

/** 解析固定 43 字符的 session_id。 */
export function parseSessionID(value: string): SessionID {
  decodeFixedBase64URL(value, 32, ERROR_CODES.INVALID_MESSAGE_ID, "session_id");
  return value as SessionID;
}

/** 生成密码学安全 session_id。 */
export function newSessionID(source: RandomSource = secureRandom): SessionID {
  return sessionIDFromBytes(source.randomBytes(32));
}

/** 从 32 字节创建 session_id，输入会被复制。 */
export function sessionIDFromBytes(value: Uint8Array): SessionID {
  if (value.length !== 32) throw protocolError(ERROR_CODES.INVALID_MESSAGE_ID, "session_id 必须是 32 字节");
  return base64urlEncode(value) as SessionID;
}

/** 解析 64 位小写 SHA-256 Hash。 */
export function parseSHA256Hash(value: string): SHA256Hash {
  if (!/^[0-9a-f]{64}$/.test(value)) throw protocolError(ERROR_CODES.INVALID_BODY, "hash 必须是 64 位小写 hex");
  return value as SHA256Hash;
}

/** 从 32 字节创建 SHA-256 Hash 品牌值。 */
export function sha256HashFromBytes(value: Uint8Array): SHA256Hash {
  if (value.length !== 32) throw protocolError(ERROR_CODES.INVALID_BODY, "Hash 必须是 32 字节");
  return hexEncode(value) as SHA256Hash;
}

/** 解析签名外层无填充 base64url。DER/low-S 在验签入口继续检查。 */
export function parseSignature(value: string): Signature {
  const bytes = decodeRawBase64URL(value, ERROR_CODES.INVALID_SIGNATURE, "signature");
  if (bytes.length < 8 || bytes.length > 72) throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "signature DER 长度不合法");
  validateSignatureDER(bytes);
  return value as Signature;
}

/** 将签名字节编码为无填充 base64url。 */
export function signatureFromDER(value: Uint8Array): Signature {
  if (value.length < 8 || value.length > 72) throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "DER 签名长度不合法");
  validateSignatureDER(value);
  return base64urlEncode(value) as Signature;
}

/** 严格解析非负 JSON safe integer。 */
export function parseUnixMillis(value: unknown, field = "时间"): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw protocolError(ERROR_CODES.INVALID_TIME, `${field} 必须是非负 JSON safe integer`);
  }
  return value;
}

/** 返回 inbox 频道目标公钥。 */
export function parseInboxChannel(channel: string, prefix = "bsv8.inbox."): PublicKey {
  if (!channel.startsWith(prefix)) throw protocolError(ERROR_CODES.INVALID_CHANNEL, "inbox channel 前缀不合法");
  try {
    return parsePublicKey(channel.slice(prefix.length));
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_CHANNEL, "inbox channel 目标公钥不合法", cause);
  }
}

/** 生成 inbox 频道。 */
export function inboxChannel(publicKey: PublicKey, prefix = "bsv8.inbox."): string {
  parsePublicKey(publicKey);
  return `${prefix}${publicKey}`;
}

/** 严格 base64url 编码。 */
export function base64urlEncode(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/** 严格解码任意长度无填充 base64url。 */
export function decodeRawBase64URL(value: string, code: ErrorCode = ERROR_CODES.INVALID_JSON, field = "base64url"): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw protocolError(code, `${field} 不是规范无填充 base64url`);
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch (cause) {
    throw protocolError(code, `${field} base64url 解码失败`, cause);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64urlEncode(bytes) !== value) throw protocolError(code, `${field} 不是规范 base64url`);
  return bytes;
}

/** 严格解码并检查固定字节长度。 */
export function decodeFixedBase64URL(value: string, expectedBytes: number, code: ErrorCode, field: string): Uint8Array {
  const bytes = decodeRawBase64URL(value, code, field);
  if (bytes.length !== expectedBytes) throw protocolError(code, `${field} 必须是 ${expectedBytes} 字节`);
  return bytes;
}

/** 小写 hex 编码。 */
export function hexEncode(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** 严格 hex 解码。 */
export function hexDecode(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) throw new Error("invalid hex");
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return result;
}

function validateSignatureDER(value: Uint8Array): void {
  try {
    const parsed = secp256k1.Signature.fromBytes(new Uint8Array(value), "der");
    if (parsed.hasHighS() || !equalBytes(parsed.toDERRawBytes(), value)) throw new Error("non-canonical signature");
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "signature 不是 strict DER low-S 签名", cause);
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}
