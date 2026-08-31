import { ERROR_CODES, ErrorCode, protocolError } from "./errors.js";
import { MAX_JSON_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES } from "./limits.js";

/** 可进入 channels 协议层的 JSON 值。 */
export type JSONValue = null | boolean | number | string | JSONValue[] | { [key: string]: JSONValue };

/** 严格 JSON object 类型。 */
export type JSONObject = { [key: string]: JSONValue };

const textEncoder = new TextEncoder();

/** 将 UTF-8 字节或 JS 字符串转换为严格解析文本并执行字节上限检查。 */
export function jsonText(input: string | Uint8Array): string {
  if (typeof input === "string") {
    if (textEncoder.encode(input).byteLength > MAX_JSON_BYTES) {
      throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 输入超过 1,048,000 字节");
    }
    rejectUnpairedSurrogates(input);
    return input;
  }
  const copy = new Uint8Array(input);
  if (copy.byteLength > MAX_JSON_BYTES) {
    throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 输入超过 1,048,000 字节");
  }
  try {
    // 保留 BOM 让语法层拒绝它；Go 严格入口同样不把 BOM 当作 JSON whitespace。
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(copy);
  } catch (cause) {
    throw protocolError(ERROR_CODES.INVALID_JSON, "输入不是合法 UTF-8", cause);
  }
}

/** 严格解析完整 JSON，拒绝重复字段、非法 surrogate 和资源超限。 */
export function parseStrictJSON(input: string | Uint8Array): JSONValue {
  return new Parser(jsonText(input)).parse();
}

/** 检查 object 只包含允许字段。 */
export function requireObjectKeys(object: JSONObject, allowed: readonly string[]): void {
  const set = new Set(allowed);
  for (const key of Object.keys(object)) {
    if (!set.has(key)) {
      throw protocolError(ERROR_CODES.UNKNOWN_FIELD, `未知字段 ${JSON.stringify(key)}`);
    }
  }
}

/** 校验运行时构造值是只含指定字段的 object；额外字段返回 UNKNOWN_FIELD。 */
export function requireExactObjectKeys(value: unknown, allowed: readonly string[], label: string, invalidCode: ErrorCode = ERROR_CODES.INVALID_BODY): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw protocolError(invalidCode, `${label} 必须是 object`);
  }
  const object = value as Record<string, unknown>;
  const allowedSet = new Set(allowed);
  const keys = Object.keys(object);
  for (const key of keys) {
    if (!allowedSet.has(key)) throw protocolError(ERROR_CODES.UNKNOWN_FIELD, `${label} 存在未知字段 ${JSON.stringify(key)}`);
  }
  if (keys.length !== allowed.length) throw protocolError(invalidCode, `${label} 缺少必需字段`);
}

/** 读取必需字段，严格区分缺字段和 JSON null。 */
export function requireField(object: JSONObject, key: string): JSONValue {
  if (!Object.prototype.hasOwnProperty.call(object, key)) {
    throw protocolError(ERROR_CODES.INVALID_JSON, `缺少必需字段 ${key}`);
  }
  return object[key];
}

/** 判断 JSON object（数组不属于 object 分支）。 */
export function isJSONObject(value: JSONValue): value is JSONObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function rejectUnpairedSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) {
        throw protocolError(ERROR_CODES.INVALID_JSON, "文本包含孤立 high surrogate");
      }
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw protocolError(ERROR_CODES.INVALID_JSON, "文本 high surrogate 缺少配对");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw protocolError(ERROR_CODES.INVALID_JSON, "文本包含孤立 low surrogate");
    }
  }
}

class Parser {
  private index = 0;
  private nodes = 0;

  constructor(private readonly text: string) {}

  parse(): JSONValue {
    this.skipWhitespace();
    if (this.index >= this.text.length) {
      throw protocolError(ERROR_CODES.INVALID_JSON, "JSON 为空");
    }
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      throw protocolError(ERROR_CODES.INVALID_JSON, "JSON 后存在未解析内容");
    }
    return value;
  }

  private parseValue(depth: number): JSONValue {
    this.nodes += 1;
    if (this.nodes > MAX_JSON_NODES) {
      throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 节点数超过 100,000");
    }
    const character = this.text[this.index];
    if (character === "{") return this.parseObject(depth);
    if (character === "[") return this.parseArray(depth);
    if (character === '"') return this.parseString();
    if (character === "t") return this.parseLiteral("true", true);
    if (character === "f") return this.parseLiteral("false", false);
    if (character === "n") return this.parseLiteral("null", null);
    if (character === "-" || isDigit(character)) return this.parseNumber();
    throw protocolError(ERROR_CODES.INVALID_JSON, "JSON 值类型不合法");
  }

  private parseObject(depth: number): JSONObject {
    if (depth >= MAX_JSON_DEPTH) {
      throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 嵌套深度超过 64");
    }
    this.index += 1;
    const object: JSONObject = Object.create(null) as JSONObject;
    this.skipWhitespace();
    if (this.consume("}")) return object;
    while (true) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') {
        throw protocolError(ERROR_CODES.INVALID_JSON, "object key 必须是字符串");
      }
      const key = this.parseString();
      if (typeof key !== "string") throw protocolError(ERROR_CODES.INVALID_JSON, "object key 类型不合法");
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        throw protocolError(ERROR_CODES.INVALID_JSON, "JSON object 存在重复字段");
      }
      this.skipWhitespace();
      if (!this.consume(":")) throw protocolError(ERROR_CODES.INVALID_JSON, "object key 后缺少冒号");
      this.skipWhitespace();
      object[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      if (this.consume("}")) return object;
      if (!this.consume(",")) throw protocolError(ERROR_CODES.INVALID_JSON, "object 字段之间缺少逗号或右括号");
    }
  }

  private parseArray(depth: number): JSONValue[] {
    if (depth >= MAX_JSON_DEPTH) {
      throw protocolError(ERROR_CODES.MESSAGE_TOO_LARGE, "JSON 嵌套深度超过 64");
    }
    this.index += 1;
    const array: JSONValue[] = [];
    this.skipWhitespace();
    if (this.consume("]")) return array;
    while (true) {
      this.skipWhitespace();
      array.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume("]")) return array;
      if (!this.consume(",")) throw protocolError(ERROR_CODES.INVALID_JSON, "array 元素之间缺少逗号或右括号");
    }
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        const raw = this.text.slice(start, this.index);
        let value: unknown;
        try {
          value = JSON.parse(raw);
        } catch (cause) {
          throw protocolError(ERROR_CODES.INVALID_JSON, "字符串转义不合法", cause);
        }
        if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_JSON, "字符串类型不合法");
        rejectUnpairedSurrogates(value);
        return value;
      }
      if (code < 0x20) throw protocolError(ERROR_CODES.INVALID_JSON, "字符串包含未转义控制字符");
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === "u") {
          const unit = this.parseUnicodeEscape();
          if (unit >= 0xdc00 && unit <= 0xdfff) {
            throw protocolError(ERROR_CODES.INVALID_JSON, "字符串包含孤立 low surrogate");
          }
          if (unit >= 0xd800 && unit <= 0xdbff) {
            if (this.text[this.index] !== "\\" || this.text[this.index + 1] !== "u") {
              throw protocolError(ERROR_CODES.INVALID_JSON, "字符串 high surrogate 缺少配对");
            }
            this.index += 2;
            const low = this.parseUnicodeEscapeDigits();
            if (low < 0xdc00 || low > 0xdfff) {
              throw protocolError(ERROR_CODES.INVALID_JSON, "字符串 surrogate 配对不合法");
            }
          }
        } else if (!["\"", "\\", "/", "b", "f", "n", "r", "t"].includes(escape)) {
          throw protocolError(ERROR_CODES.INVALID_JSON, "字符串包含未知转义");
        } else {
          this.index += 1;
        }
        continue;
      }
      if (code >= 0xd800 && code <= 0xdbff) {
        if (this.index + 1 >= this.text.length || this.text.charCodeAt(this.index + 1) < 0xdc00 || this.text.charCodeAt(this.index + 1) > 0xdfff) {
          throw protocolError(ERROR_CODES.INVALID_JSON, "字符串包含孤立 high surrogate");
        }
        this.index += 2;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw protocolError(ERROR_CODES.INVALID_JSON, "字符串包含孤立 low surrogate");
      } else {
        this.index += 1;
      }
    }
    throw protocolError(ERROR_CODES.INVALID_JSON, "字符串缺少结束引号");
  }

  private parseUnicodeEscape(): number {
    this.index += 1;
    return this.parseUnicodeEscapeDigits();
  }

  private parseUnicodeEscapeDigits(): number {
    const raw = this.text.slice(this.index, this.index + 4);
    if (raw.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(raw)) {
      throw protocolError(ERROR_CODES.INVALID_JSON, "Unicode 转义不是四位十六进制");
    }
    this.index += 4;
    return Number.parseInt(raw, 16);
  }

  private parseLiteral(literal: string, value: JSONValue): JSONValue {
    if (this.text.slice(this.index, this.index + literal.length) !== literal) {
      throw protocolError(ERROR_CODES.INVALID_JSON, "JSON literal 不完整");
    }
    this.index += literal.length;
    return value;
  }

  private parseNumber(): number {
    const start = this.index;
    if (this.text[this.index] === "-") {
      this.index += 1;
      if (this.index >= this.text.length) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON number 不完整");
    }
    if (this.text[this.index] === "0") {
      this.index += 1;
      if (isDigit(this.text[this.index])) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON number 不允许前导零");
    } else {
      if (!isNonZeroDigit(this.text[this.index])) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON number 整数部分不合法");
      while (isDigit(this.text[this.index])) this.index += 1;
    }
    if (this.text[this.index] === ".") {
      this.index += 1;
      const fractionStart = this.index;
      while (isDigit(this.text[this.index])) this.index += 1;
      if (fractionStart === this.index) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON number 小数部分不合法");
    }
    if (this.text[this.index] === "e" || this.text[this.index] === "E") {
      this.index += 1;
      if (this.text[this.index] === "+" || this.text[this.index] === "-") this.index += 1;
      const exponentStart = this.index;
      while (isDigit(this.text[this.index])) this.index += 1;
      if (exponentStart === this.index) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON number 指数不合法");
    }
    const raw = this.text.slice(start, this.index);
    const value = Number(raw);
    if (!Number.isFinite(value)) throw protocolError(ERROR_CODES.INVALID_JSON, "JSON number 不能表示为有限 IEEE 754 double");
    return value;
  }

  private skipWhitespace(): void {
    while ([" ", "\t", "\r", "\n"].includes(this.text[this.index])) this.index += 1;
  }

  private consume(character: string): boolean {
    if (this.text[this.index] === character) {
      this.index += 1;
      return true;
    }
    return false;
  }
}

function isDigit(value: string | undefined): boolean {
  return value !== undefined && value >= "0" && value <= "9";
}

function isNonZeroDigit(value: string | undefined): boolean {
  return value !== undefined && value >= "1" && value <= "9";
}
