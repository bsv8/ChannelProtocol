import { sha256 as nobleSha256 } from "@noble/hashes/sha256";

import { ERROR_CODES, protocolError } from "./errors.js";
import { JSONValue, parseStrictJSON } from "./strict-json.js";
import { MAX_JSON_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES } from "./limits.js";

/** RFC 8785 JCS 规范化 JSON，并返回 UTF-8 字节。 */
export function canonicalizeJSON(input: string | Uint8Array): Uint8Array {
  return canonicalizeValue(parseStrictJSON(input));
}

/** 将 JSON 兼容值按 RFC 8785 输出；对象键按 UTF-16 code unit 排序。 */
export function canonicalizeValue(value: unknown): Uint8Array {
  const state = { nodes: 0 };
  const text = serialize(value, new Set<unknown>(), 0, state);
  const result = new TextEncoder().encode(text);
  if (result.byteLength > MAX_JSON_BYTES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JCS 输出超过 1,048,000 字节");
  return result;
}

/** 对 JCS 字节执行一次 SHA-256。 */
export function sha256(value: Uint8Array): Uint8Array {
  return new Uint8Array(nobleSha256(new Uint8Array(value)));
}

function serialize(value: unknown, seen: Set<unknown>, depth: number, state: { nodes: number }): string {
  state.nodes += 1;
  if (state.nodes > MAX_JSON_NODES) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 节点数超过 100,000");
  if (depth > MAX_JSON_DEPTH) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 嵌套深度超过 64");
  if (value === null) return "null";
  if (typeof value === "string") {
    rejectUnpairedSurrogates(value);
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON number 必须是有限数");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw protocolError(ERROR_CODES.INVALID_JSON, "值不是 JCS 兼容 JSON");
  if (depth >= MAX_JSON_DEPTH) throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 嵌套深度超过 64");
  if (seen.has(value)) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON 值存在循环引用");
  seen.add(value);
  let result: string;
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw protocolError(ERROR_CODES.INVALID_JSON, "JCS 数组不允许 hole");
      items.push(serialize(value[index], seen, depth + 1, state));
    }
    result = `[${items.join(",")}]`;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw protocolError(ERROR_CODES.INVALID_JSON, "JCS object 必须是普通 object");
    }
    const keys = Object.keys(value).sort();
    const object = value as Record<string, unknown>;
    const fields = keys.map((key) => {
      rejectUnpairedSurrogates(key);
      return `${JSON.stringify(key)}:${serialize(object[key], seen, depth + 1, state)}`;
    });
    result = `{${fields.join(",")}}`;
  }
  seen.delete(value);
  return result;
}

function rejectUnpairedSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length || value.charCodeAt(index + 1) < 0xdc00 || value.charCodeAt(index + 1) > 0xdfff) {
        throw protocolError(ERROR_CODES.INVALID_JSON, "字符串包含孤立 high surrogate");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw protocolError(ERROR_CODES.INVALID_JSON, "字符串包含孤立 low surrogate");
    }
  }
}
