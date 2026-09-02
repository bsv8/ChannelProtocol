/** 应用消息子协议模块，对应 04-应用消息子协议.md。 */
import { APP_MESSAGE_PROTOCOL } from "../registry.js";
import { ERROR_CODES, protocolError } from "../internal/errors.js";
import { MessageID, parseMessageID } from "../internal/encoding.js";
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

/** Deliver/ACK 最大有效期（24 小时）。 */
export const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;

function stringField(object: Record<string, JSONValue>, field: string): string {
  const value = requireField(object, field);
  if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_BODY, `${field} 必须是 string`);
  return value;
}
