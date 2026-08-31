/** 应用消息子协议模块，对应 04-应用消息子协议.md。 */
import { APP_MESSAGE_PROTOCOL } from "../registry.js";
import { ERROR_CODES, protocolError } from "../internal/errors.js";
import { MessageID, PublicKey, SHA256Hash, parseMessageID, parsePublicKey, parseSHA256Hash } from "../internal/encoding.js";
import { canonicalizeValue } from "../internal/jcs.js";
import { MAX_JSON_BYTES } from "../internal/limits.js";
import { isJSONObject, JSONValue, parseStrictJSON, requireExactObjectKeys, requireField, requireObjectKeys } from "../internal/strict-json.js";
import { cloneAndFreeze, freezeDeep } from "../internal/immutable.js";

export { APP_MESSAGE_PROTOCOL };

/** 应用消息 body discriminator。 */
export type MessageType = "deliver" | "ack";

/** Deliver 应用消息正文。 */
export interface DeliverBody {
  /** 分支固定为 deliver。 */
  readonly type: "deliver";
  /** 任意 JCS 兼容 JSON 应用内容。 */
  readonly content: JSONValue;
}

/** ACK 可靠接收确认正文。 */
export interface AckBody {
  /** 分支固定为 ack。 */
  readonly type: "ack";
  /** 原 Deliver 私密消息的 message_id。 */
  readonly acknowledged_message_id: MessageID;
}

/** 应用消息 body 联合类型。 */
export type MessageV1Body = DeliverBody | AckBody;

/** 构造并校验 Deliver body。 */
export function newDeliver(content: JSONValue): DeliverBody {
  const canonical = canonicalizeContent(content);
  if (canonical.byteLength > MAX_JSON_BYTES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "deliver.content 超过 JSON 字节上限");
  return cloneAndFreeze({ type: "deliver", content });
}

/** 构造并校验 ACK body。 */
export function newAck(acknowledgedMessageId: MessageID): AckBody {
  parseMessageID(acknowledgedMessageId);
  return freezeDeep({ type: "ack", acknowledged_message_id: acknowledgedMessageId });
}

/** 校验应用 body。 */
export function validateBody(body: MessageV1Body): void {
  if (body === null || typeof body !== "object" || Array.isArray(body)) throw protocolError(ERROR_CODES.INVALID_BODY, "应用消息 body 必须是 object");
  if (body.type === "deliver") {
    requireExactObjectKeys(body, ["type", "content"], "deliver body");
    const canonical = canonicalizeContent(body.content);
    if (canonical.byteLength > MAX_JSON_BYTES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "deliver.content 超过 JSON 字节上限");
    return;
  }
  if (body.type === "ack") {
    requireExactObjectKeys(body, ["type", "acknowledged_message_id"], "ack body");
    parseMessageID(body.acknowledged_message_id);
    return;
  }
  throw protocolError(ERROR_CODES.INVALID_BODY, "不支持的应用消息 body.type");
}

function canonicalizeContent(content: JSONValue): Uint8Array {
  try {
    return canonicalizeValue(content);
  } catch (error) {
    if (error instanceof Error && "code" in error && (error as { code?: string }).code === ERROR_CODES.MESSAGE_TOO_LARGE) throw error;
    throw protocolError(ERROR_CODES.INVALID_BODY, "deliver.content 不是 JCS 兼容 JSON 值", error);
  }
}

/** 严格解析应用消息 body。 */
export function parseBody(input: string | Uint8Array): MessageV1Body {
  const value = parseStrictJSON(input);
  return parseBodyValue(value);
}

/** 将严格 JSON 值分派为 DeliverBody 或 AckBody。 */
export function parseBodyValue(value: JSONValue): MessageV1Body {
  if (!isJSONObject(value)) throw protocolError(ERROR_CODES.INVALID_BODY, "应用消息 body 必须是 object");
  const type = stringField(value, "type") as MessageType;
  if (type === "deliver") {
    requireObjectKeys(value, ["type", "content"]);
    const body = { type: "deliver", content: requireField(value, "content") } as DeliverBody;
    validateBody(body);
    return cloneAndFreeze(body);
  }
  if (type === "ack") {
    requireObjectKeys(value, ["type", "acknowledged_message_id"]);
    const body = { type: "ack", acknowledged_message_id: parseMessageID(stringField(value, "acknowledged_message_id")) } as AckBody;
    validateBody(body);
    return freezeDeep(body);
  }
  throw protocolError(ERROR_CODES.INVALID_BODY, "不支持的应用消息 body.type");
}

/** 原 Deliver 的身份和编号上下文。 */
export interface DeliveryContext {
  /** Deliver 信封发送者。 */
  readonly from_public_key: PublicKey;
  /** Deliver inbox channel 目标。 */
  readonly to_public_key: PublicKey;
  /** Deliver 外层私密 message_id。 */
  readonly message_id: MessageID;
}

/** ACK 的信封身份和 body 上下文。 */
export interface AckContext {
  /** ACK 信封发送者。 */
  readonly from_public_key: PublicKey;
  /** ACK inbox channel 目标。 */
  readonly to_public_key: PublicKey;
  /** ACK body。 */
  readonly body: AckBody;
}

/** 检查 ACK 发送者、接收者和 acknowledged_message_id 与 Deliver 关系。 */
export function validateAckRelation(delivery: DeliveryContext, ack: AckContext): void {
  parsePublicKey(delivery.from_public_key);
  parsePublicKey(delivery.to_public_key);
  parsePublicKey(ack.from_public_key);
  parsePublicKey(ack.to_public_key);
  parseMessageID(delivery.message_id);
  validateBody(ack.body);
  if (ack.from_public_key !== delivery.to_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "ACK 发送者不是 Deliver 接收者");
  if (ack.to_public_key !== delivery.from_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "ACK 接收者不是 Deliver 发送者");
  if (ack.body.acknowledged_message_id !== delivery.message_id) throw protocolError(ERROR_CODES.INVALID_RELATION, "ACK 未关联原 Deliver message_id");
}

/** 应用消息去重键。 */
export interface DeduplicationKey {
  /** 固定应用子协议。 */
  readonly protocol: typeof APP_MESSAGE_PROTOCOL;
  /** 发送者公钥。 */
  readonly from_public_key: PublicKey;
  /** 外层私密消息编号。 */
  readonly message_id: MessageID;
}

/** 构造应用消息去重键。 */
export function dedupKey(fromPublicKey: PublicKey, messageId: MessageID): DeduplicationKey {
  parsePublicKey(fromPublicKey);
  parseMessageID(messageId);
  return Object.freeze({ protocol: APP_MESSAGE_PROTOCOL, from_public_key: fromPublicKey, message_id: messageId });
}

/** 检查两个已计算摘要是否冲突。 */
export function checkDigestConflict(existing: SHA256Hash, incoming: SHA256Hash): void {
  parseSHA256Hash(existing);
  parseSHA256Hash(incoming);
  if (existing !== incoming) throw protocolError(ERROR_CODES.MESSAGE_ID_CONFLICT, "同一应用消息去重键对应不同已签名内容");
}

/** Deliver/ACK 最大有效期（24 小时）。 */
export const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Go 风格大写别名。 */
export const NewDeliver = newDeliver;
/** Go 风格大写别名。 */
export const NewAck = newAck;
/** Go 风格大写别名。 */
export const ParseBody = parseBody;
/** Go 风格大写别名。 */
export const ValidateAckRelation = validateAckRelation;
/** Go 风格大写别名。 */
export const DedupKey = dedupKey;
/** Go 风格大写别名。 */
export const CheckDigestConflict = checkDigestConflict;

function stringField(object: Record<string, JSONValue>, field: string): string {
  const value = requireField(object, field);
  if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_BODY, `${field} 必须是 string`);
  return value;
}
