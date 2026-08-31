/** TypeScript 与 Go 共享的稳定错误码。 */
export const ERROR_CODES = Object.freeze({
  INVALID_JSON: "INVALID_JSON",
  UNKNOWN_FIELD: "UNKNOWN_FIELD",
  INVALID_CHANNEL: "INVALID_CHANNEL",
  INVALID_PUBLIC_KEY: "INVALID_PUBLIC_KEY",
  INVALID_PRIVATE_KEY: "INVALID_PRIVATE_KEY",
  IDENTITY_MISMATCH: "IDENTITY_MISMATCH",
  INVALID_MESSAGE_ID: "INVALID_MESSAGE_ID",
  INVALID_TIME: "INVALID_TIME",
  MESSAGE_EXPIRED: "MESSAGE_EXPIRED",
  INVALID_BODY: "INVALID_BODY",
  UNSUPPORTED_PROTOCOL: "UNSUPPORTED_PROTOCOL",
  INVALID_SIGNATURE: "INVALID_SIGNATURE",
  INVALID_ENVELOPE: "INVALID_ENVELOPE",
  OPEN_FAILED: "OPEN_FAILED",
  MESSAGE_ID_CONFLICT: "MESSAGE_ID_CONFLICT",
  INVALID_RELATION: "INVALID_RELATION",
  MESSAGE_TOO_LARGE: "MESSAGE_TOO_LARGE",
} as const);

/** 稳定错误码联合类型；业务代码不要依赖错误文本。 */
export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

/** SDK 结构化错误，code 是跨语言兼容字段，cause 仅供本地诊断。 */
export class ChannelProtocolError extends Error {
  /** 跨语言稳定错误码。 */
  readonly code: ErrorCode;
  /** 可选本地原因，不应作为远程错误协议暴露。 */
  readonly cause?: unknown;

  constructor(code: ErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "ChannelProtocolError";
    this.code = code;
    this.cause = cause;
  }
}
/** 创建中文上下文错误。 */
export function protocolError(code: ErrorCode, message: string, cause?: unknown): ChannelProtocolError {
  return new ChannelProtocolError(code, message, cause);
}

/** 将未知异常转换为指定稳定错误码。 */
export function asProtocolError(code: ErrorCode, message: string, cause?: unknown): ChannelProtocolError {
  return new ChannelProtocolError(code, message, cause);
}

/** 判断异常是否属于指定稳定错误码。 */
export function hasCode(error: unknown, code: ErrorCode): boolean {
  return error instanceof ChannelProtocolError && error.code === code;
}
