/** Ping/Pong 独立私密子协议模块。 */
import { PING_PROTOCOL } from "../registry.js";
import { ERROR_CODES, protocolError } from "../internal/errors.js";
import { MessageID, parseMessageID } from "../internal/encoding.js";
import { freezeDeep } from "../internal/immutable.js";
import { JSONValue, parseStrictJSON, isJSONObject, requireExactObjectKeys, requireField, requireObjectKeys } from "../internal/strict-json.js";

export { PING_PROTOCOL };

export type PingType = "ping" | "pong";

export interface PingBody {
  readonly type: "ping";
}

export interface PongBody {
  readonly type: "pong";
  /** 所引用 Ping 私密消息的 message_id。 */
  readonly ping_message_id: MessageID;
}

export type Body = PingBody | PongBody;

export function newPing(): PingBody {
  return freezeDeep({ type: "ping" });
}

export function newPong(pingMessageID: MessageID): PongBody {
  parseMessageID(pingMessageID);
  return freezeDeep({ type: "pong", ping_message_id: pingMessageID });
}

export function validateBody(body: Body): void {
  if (body === null || typeof body !== "object" || Array.isArray(body)) throw protocolError(ERROR_CODES.INVALID_BODY, "Ping/Pong body 必须是 object");
  if (body.type === "ping") {
    requireExactObjectKeys(body, ["type"], "ping body");
    return;
  }
  if (body.type === "pong") {
    requireExactObjectKeys(body, ["type", "ping_message_id"], "pong body");
    parseMessageID(body.ping_message_id);
    return;
  }
  throw protocolError(ERROR_CODES.INVALID_BODY, "不支持的 Ping/Pong body.type");
}

export function parseBody(input: string | Uint8Array): Body {
  return parseBodyValue(parseStrictJSON(input));
}

export function parseBodyValue(value: JSONValue): Body {
  if (!isJSONObject(value)) throw protocolError(ERROR_CODES.INVALID_BODY, "Ping/Pong body 必须是 object");
  const type = stringField(value, "type") as PingType;
  if (type === "ping") {
    requireObjectKeys(value, ["type"]);
    return newPing();
  }
  if (type === "pong") {
    requireObjectKeys(value, ["type", "ping_message_id"]);
    return newPong(parseMessageID(stringField(value, "ping_message_id")));
  }
  throw protocolError(ERROR_CODES.INVALID_BODY, "不支持的 Ping/Pong body.type");
}

export const MAX_LIFETIME_MS = 60 * 1000;

function stringField(object: Record<string, JSONValue>, field: string): string {
  const value = requireField(object, field);
  if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_BODY, `${field} 必须是 string`);
  return value;
}
