/** BSV 多市场、多交易对价格频道协议。 */

import {
  BSV_PRICE_CHANNEL_PREFIX,
  BSV_PRICE_PROTOCOL,
} from "../registry.js";
import { ERROR_CODES, protocolError } from "../internal/errors.js";
import {
  MessageID,
  PrivateKey,
  PublicKey,
  SHA256Hash,
  Signature,
  parseMessageID,
  parsePublicKey,
  parseSignature,
  parseUnixMillis,
} from "../internal/encoding.js";
import { cloneAndFreeze, freezeDeep } from "../internal/immutable.js";
import {
  JSONValue,
  requireExactObjectKeys,
} from "../internal/strict-json.js";
import {
  PUBLIC_MESSAGE_MAX_LIFETIME_MS,
  parseAndVerify as parsePublicMessage,
  marshal as marshalPublicMessage,
  sign as signPublicMessage,
  signedDigest as signedPublicDigest,
} from "../public-message/index.js";

export { BSV_PRICE_CHANNEL_PREFIX, BSV_PRICE_PROTOCOL };

const MAX_MARKETS = 100;
const MAX_PAIRS_PER_MARKET = 100;
const MAX_IDENTIFIER_BYTES = 64;
const MAX_PRICE_BYTES = 128;
const IDENTIFIER_RE = /^[a-z0-9][a-z0-9._-]*$/u;
const DECIMAL_RE = /^(0|[1-9][0-9]*)(\.[0-9]+)?$/u;

/** 一次完整的 BSV 多市场、多交易对价格快照。 */
export interface BSVPriceBody {
  /** 固定为 bsv8.bsv-price.v1。 */
  readonly protocol: typeof BSV_PRICE_PROTOCOL;
  /** 行情源生成本次完整快照的 Unix 毫秒时间。 */
  readonly snapshot_at_ms: number;
  /** 市场编号到交易对价格的映射；价格必须使用十进制字符串。 */
  readonly markets: Readonly<Record<string, Readonly<Record<string, string>>>>;
}

/** 待签名的 BSV 价格公开消息。 */
export interface UnsignedBSVPriceMessage {
  /** 价格发布者长期压缩公钥。 */
  readonly from_public_key: PublicKey;
  /** 公开消息去重编号。 */
  readonly message_id: MessageID;
  /** 公开消息发布时间 Unix 毫秒。 */
  readonly issued_at_ms: number;
  /** 公开消息过期时间 Unix 毫秒。 */
  readonly expires_at_ms: number;
  /** 完整价格快照正文。 */
  readonly body: BSVPriceBody;
}

/** 已签名的 BSV 价格公开消息。 */
export interface SignedBSVPriceMessage extends UnsignedBSVPriceMessage {
  /** bsv8.public-message.v1 唯一业务签名。 */
  readonly signature: Signature;
}

/** 已完成结构、时间、频道关系和签名验证的 BSV 价格消息。 */
export interface VerifiedBSVPriceMessage extends SignedBSVPriceMessage {
  /** 签名逻辑对象的稳定 SHA-256 摘要。 */
  readonly digest: SHA256Hash;
}

/** 固定价格频道上的公开消息去重键。 */
export interface DeduplicationKey {
  /** 价格发布者公钥。 */
  readonly from_public_key: PublicKey;
  /** 消息编号。 */
  readonly message_id: MessageID;
}

/** 价格消息的简短类型别名。 */
export type UnsignedMessage = UnsignedBSVPriceMessage;
export type SignedMessage = SignedBSVPriceMessage;
export type VerifiedMessage = VerifiedBSVPriceMessage;

const verifiedBSVPriceMessages = new WeakSet<object>();

/** 根据发布者公钥生成稳定的 BSV 价格频道。 */
export function bsvPriceChannel(publicKey: PublicKey): string {
  parsePublicKey(publicKey);
  return `${BSV_PRICE_CHANNEL_PREFIX}${publicKey}`;
}

/** 严格解析 bsvprice.<public_key_hex> 并返回发布者公钥。 */
export function parseBSVPriceChannel(value: string): PublicKey {
  if (typeof value !== "string" || !value.startsWith(BSV_PRICE_CHANNEL_PREFIX)) {
    throw protocolError(ERROR_CODES.INVALID_CHANNEL, "BSV 价格频道前缀不合法");
  }
  try {
    return parsePublicKey(value.slice(BSV_PRICE_CHANNEL_PREFIX.length));
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_CHANNEL, "BSV 价格频道发布者公钥不合法", cause);
  }
}

/** 构造带固定协议标识的价格正文。 */
export function newBody(
  snapshot_at_ms: number,
  markets: Readonly<Record<string, Readonly<Record<string, string>>>>,
): BSVPriceBody {
  const body = { protocol: BSV_PRICE_PROTOCOL, snapshot_at_ms, markets } as BSVPriceBody;
  validateBody(body);
  return cloneAndFreeze(body);
}

/** 校验价格正文。 */
export function validateBody(value: unknown): asserts value is BSVPriceBody {
  requireExactObjectKeys(value, ["protocol", "snapshot_at_ms", "markets"], "BSV 价格 body");
  const body = value as Record<string, unknown>;
  if (body.protocol !== BSV_PRICE_PROTOCOL) {
    throw protocolError(ERROR_CODES.UNSUPPORTED_PROTOCOL, "BSV 价格 body protocol 不支持");
  }
  parseUnixMillis(body.snapshot_at_ms, "snapshot_at_ms");
  if (!isPlainObject(body.markets)) {
    throw protocolError(ERROR_CODES.INVALID_BODY, "markets 必须是 object");
  }
  const markets = body.markets as Record<string, unknown>;
  const marketNames = Object.keys(markets);
  if (marketNames.length > MAX_MARKETS) {
    throw protocolError(ERROR_CODES.INVALID_BODY, "markets 必须包含 0 至 100 个市场");
  }
  for (const market of marketNames) {
    validateIdentifier(market, "市场");
    const rawQuotes = markets[market];
    if (!isPlainObject(rawQuotes)) {
      throw protocolError(ERROR_CODES.INVALID_BODY, "每个市场必须是交易对 object");
    }
    const quotes = rawQuotes as Record<string, unknown>;
    const pairs = Object.keys(quotes);
    if (pairs.length === 0 || pairs.length > MAX_PAIRS_PER_MARKET) {
      throw protocolError(ERROR_CODES.INVALID_BODY, "每个市场必须包含 1 至 100 个交易对");
    }
    for (const pair of pairs) {
      validateIdentifier(pair, "交易对");
      const price = quotes[pair];
      if (typeof price !== "string" || !DECIMAL_RE.test(price) || new TextEncoder().encode(price).byteLength > MAX_PRICE_BYTES) {
        throw protocolError(ERROR_CODES.INVALID_BODY, "价格必须是非负十进制字符串");
      }
    }
  }
}

/** 将已解析的 JSON 值转换为深冻结的强类型价格正文。 */
export function parseBody(value: unknown): BSVPriceBody {
  if (!isPlainObject(value)) {
    throw protocolError(ERROR_CODES.INVALID_BODY, "BSV 价格 body 必须是 object");
  }
  validateBody(value);
  return cloneAndFreeze({
    protocol: BSV_PRICE_PROTOCOL,
    snapshot_at_ms: (value as Record<string, unknown>).snapshot_at_ms as number,
    markets: (value as Record<string, unknown>).markets as BSVPriceBody["markets"],
  });
}

/** 使用发布者长期私钥生成 BSV 价格消息签名。 */
export function sign(message: UnsignedBSVPriceMessage, privateKey: PrivateKey | Uint8Array): SignedBSVPriceMessage {
  validateUnsigned(message, false);
  const snapshot = cloneAndFreeze(message);
  const signed = signPublicMessage({
    channel: bsvPriceChannel(snapshot.from_public_key),
    from_public_key: snapshot.from_public_key,
    message_id: snapshot.message_id,
    issued_at_ms: snapshot.issued_at_ms,
    expires_at_ms: snapshot.expires_at_ms,
    body: bodyValue(snapshot.body),
  }, privateKey);
  return freezeDeep({ ...snapshot, signature: signed.signature });
}

/** 输出不含 channel 字段的规范价格消息 JSON UTF-8。 */
export function marshal(message: SignedBSVPriceMessage): Uint8Array {
  validateUnsigned(message, true);
  parseSignature(message.signature);
  return marshalPublicMessage({
    channel: bsvPriceChannel(message.from_public_key),
    from_public_key: message.from_public_key,
    message_id: message.message_id,
    issued_at_ms: message.issued_at_ms,
    expires_at_ms: message.expires_at_ms,
    body: bodyValue(message.body),
    signature: message.signature,
  });
}

/** 严格解析指定价格频道上的消息并完成验签；过期判断由调用方负责。 */
export function parseAndVerify(channelName: string, input: string | Uint8Array): VerifiedBSVPriceMessage {
  const publisher = parseBSVPriceChannel(channelName);
  const message = parsePublicMessage(channelName, input);
  if (message.from_public_key !== publisher) {
    throw protocolError(ERROR_CODES.IDENTITY_MISMATCH, "BSV 价格频道公钥与消息作者不一致");
  }
  const body = parseBody(message.body);
  return verifiedBSVPriceMessage({
    from_public_key: message.from_public_key,
    message_id: message.message_id,
    issued_at_ms: message.issued_at_ms,
    expires_at_ms: message.expires_at_ms,
    body,
    signature: message.signature,
    digest: message.digest,
  });
}

/** 返回值是否由本 SDK 的 parseAndVerify 创建。 */
export function isVerifiedBSVPriceMessage(value: unknown): value is VerifiedBSVPriceMessage {
  return value !== null && typeof value === "object" && verifiedBSVPriceMessages.has(value);
}

/** isVerifiedBSVPriceMessage 的简短别名。 */
export const isVerifiedMessage = isVerifiedBSVPriceMessage;

/** 返回价格消息的去重键；输入必须来自本 SDK 的验签结果。 */
export function dedupKey(message: VerifiedBSVPriceMessage): DeduplicationKey {
  requireVerified(message);
  return freezeDeep({ from_public_key: message.from_public_key, message_id: message.message_id });
}

/** 返回签名逻辑对象摘要。 */
export function signedDigest(message: UnsignedBSVPriceMessage | SignedBSVPriceMessage): SHA256Hash {
  validateUnsigned(message, "signature" in message);
  return signedPublicDigest({
    channel: bsvPriceChannel(message.from_public_key),
    from_public_key: message.from_public_key,
    message_id: message.message_id,
    issued_at_ms: message.issued_at_ms,
    expires_at_ms: message.expires_at_ms,
    body: bodyValue(message.body),
  });
}

/** 检查相同去重键对应的消息摘要是否冲突。 */
export function checkDigestConflict(existing: SHA256Hash, incoming: SHA256Hash): void {
  if (existing !== incoming) throw protocolError(ERROR_CODES.MESSAGE_ID_CONFLICT, "同一公开去重键对应不同已签名内容");
}

function verifiedBSVPriceMessage(value: VerifiedBSVPriceMessage): VerifiedBSVPriceMessage {
  const frozen = freezeDeep(cloneAndFreeze(value));
  verifiedBSVPriceMessages.add(frozen);
  return frozen;
}

function requireVerified(value: unknown): asserts value is VerifiedBSVPriceMessage {
  if (!isVerifiedBSVPriceMessage(value) || !Object.isFrozen(value)) {
    throw protocolError(ERROR_CODES.INVALID_SIGNATURE, "消息不是 SDK 生成的已验证 BSV 价格消息");
  }
}

function validateUnsigned(message: unknown, withSignature: boolean): asserts message is UnsignedBSVPriceMessage | SignedBSVPriceMessage {
  requireExactObjectKeys(
    message,
    withSignature
      ? ["from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"]
      : ["from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body"],
    "BSV 价格消息",
  );
  const value = message as Record<string, unknown>;
  parsePublicKey(value.from_public_key as PublicKey);
  parseMessageID(value.message_id as MessageID);
  const issued = parseUnixMillis(value.issued_at_ms, "issued_at_ms");
  const expires = parseUnixMillis(value.expires_at_ms, "expires_at_ms");
  if (issued >= expires || expires - issued > PUBLIC_MESSAGE_MAX_LIFETIME_MS) {
    throw protocolError(ERROR_CODES.INVALID_TIME, "公开消息时间顺序或最长有效期不合法");
  }
  validateBody(value.body);
  if (withSignature) parseSignature(value.signature as Signature);
}

function bodyValue(body: BSVPriceBody): JSONValue {
  validateBody(body);
  const markets: Record<string, Record<string, string>> = {};
  for (const market of Object.keys(body.markets)) {
    markets[market] = {};
    for (const pair of Object.keys(body.markets[market] ?? {})) {
      markets[market]![pair] = body.markets[market]![pair]!;
    }
  }
  return {
    protocol: BSV_PRICE_PROTOCOL,
    snapshot_at_ms: body.snapshot_at_ms,
    markets,
  };
}

function validateIdentifier(value: string, label: string): void {
  if (new TextEncoder().encode(value).byteLength > MAX_IDENTIFIER_BYTES || !IDENTIFIER_RE.test(value)) {
    throw protocolError(ERROR_CODES.INVALID_BODY, `${label}编号只能使用小写字母、数字、点、短横线和下划线`);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
