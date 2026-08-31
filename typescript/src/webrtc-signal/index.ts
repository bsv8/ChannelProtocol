/** WebRTC SDP 子协议模块，对应 03-WebRTC-SDP子协议.md。 */
import { WEBRTC_SIGNAL_PROTOCOL } from "../registry.js";
import { ERROR_CODES, protocolError } from "../internal/errors.js";
import { MessageID, PublicKey, SessionID, parseMessageID, parsePublicKey, parseSessionID, parseUnixMillis } from "../internal/encoding.js";
import { isJSONObject, JSONValue, parseStrictJSON, requireExactObjectKeys, requireField, requireObjectKeys } from "../internal/strict-json.js";
import { cloneAndFreeze, freezeDeep } from "../internal/immutable.js";

export { WEBRTC_SIGNAL_PROTOCOL };

/** WebRTC signal 的联合 discriminator。 */
export type SignalType = "offer" | "answer" | "ice-candidate" | "end-of-candidates";

/** SDP offer 分支。 */
export interface OfferSignal {
  /** 分支固定为 offer。 */
  readonly type: "offer";
  /** 非空 SDP 文本。 */
  readonly sdp: string;
}

/** SDP answer 分支。 */
export interface AnswerSignal {
  /** 分支固定为 answer。 */
  readonly type: "answer";
  /** 非空 SDP 文本。 */
  readonly sdp: string;
}

/** ICE candidate 对象。 */
export interface ICECandidate {
  /** ICE candidate 文本。 */
  readonly candidate: string;
  /** media section，可为 null。 */
  readonly sdp_mid: string | null;
  /** media 行索引，可为 null。 */
  readonly sdp_m_line_index: number | null;
}

/** ICE candidate 信令分支。 */
export interface ICECandidateSignal {
  /** 分支固定为 ice-candidate。 */
  readonly type: "ice-candidate";
  /** ICE candidate 对象。 */
  readonly candidate: ICECandidate;
}

/** 候选发送结束分支。 */
export interface EndOfCandidatesSignal {
  /** 分支固定为 end-of-candidates。 */
  readonly type: "end-of-candidates";
}

/** 严格互斥的 WebRTC signal 联合类型。 */
export type Signal = OfferSignal | AnswerSignal | ICECandidateSignal | EndOfCandidatesSignal;

/** WebRTC 子协议私密消息 body。 */
export interface WebRTCSignalV1Body {
  /** 所属公开 Hash 请求编号。 */
  readonly request_message_id: MessageID;
  /** offerer 创建的一次会话编号。 */
  readonly session_id: SessionID;
  /** SDP/ICE 联合信令。 */
  readonly signal: Signal;
}

/** 构造并校验 offer body。 */
export function newOffer(requestMessageId: MessageID, sessionId: SessionID, sdp: string): WebRTCSignalV1Body {
  const body = { request_message_id: requestMessageId, session_id: sessionId, signal: { type: "offer", sdp } } as const;
  validateBody(body);
  return cloneAndFreeze(body);
}

/** 构造并校验 answer body。 */
export function newAnswer(requestMessageId: MessageID, sessionId: SessionID, sdp: string): WebRTCSignalV1Body {
  const body = { request_message_id: requestMessageId, session_id: sessionId, signal: { type: "answer", sdp } } as const;
  validateBody(body);
  return cloneAndFreeze(body);
}

/** 构造并校验 ICE candidate body。 */
export function newICECandidate(requestMessageId: MessageID, sessionId: SessionID, candidate: ICECandidate): WebRTCSignalV1Body {
  const body = { request_message_id: requestMessageId, session_id: sessionId, signal: { type: "ice-candidate", candidate } } as const;
  validateBody(body);
  return cloneAndFreeze(body);
}

/** 构造 end-of-candidates body。 */
export function newEndOfCandidates(requestMessageId: MessageID, sessionId: SessionID): WebRTCSignalV1Body {
  const body = { request_message_id: requestMessageId, session_id: sessionId, signal: { type: "end-of-candidates" } } as const;
  validateBody(body);
  return cloneAndFreeze(body);
}

/** 校验 WebRTC body。 */
export function validateBody(body: WebRTCSignalV1Body): void {
  requireExactObjectKeys(body, ["request_message_id", "session_id", "signal"], "WebRTC body");
  parseMessageID(body.request_message_id);
  parseSessionID(body.session_id);
  const signal = body.signal;
  if (signal === null || typeof signal !== "object" || Array.isArray(signal)) throw protocolError(ERROR_CODES.INVALID_BODY, "signal 必须是 object");
  if (signal.type === "offer" || signal.type === "answer") {
    requireExactObjectKeys(signal, ["type", "sdp"], "WebRTC signal");
    if (typeof signal.sdp !== "string" || signal.sdp.length === 0) throw protocolError(ERROR_CODES.INVALID_BODY, "offer/answer 只能包含非空 sdp");
  } else if (signal.type === "ice-candidate") {
    requireExactObjectKeys(signal, ["type", "candidate"], "WebRTC signal");
    if (!signal.candidate || typeof signal.candidate !== "object" || Array.isArray(signal.candidate)) throw protocolError(ERROR_CODES.INVALID_BODY, "ice-candidate 只能包含 candidate");
    validateCandidate(signal.candidate);
  } else if (signal.type === "end-of-candidates") {
    requireExactObjectKeys(signal, ["type"], "WebRTC signal");
  } else {
    throw protocolError(ERROR_CODES.INVALID_BODY, "不支持的 WebRTC signal.type");
  }
}

/** 从严格 JSON body 解析 WebRTC 联合类型。 */
export function parseBody(input: string | Uint8Array): WebRTCSignalV1Body {
  const value = parseStrictJSON(input);
  if (!isJSONObject(value)) throw protocolError(ERROR_CODES.INVALID_BODY, "WebRTC body 必须是 object");
  return parseBodyValue(value);
}

/** 将严格 JSON 值分派成 WebRTC 强类型 body。 */
export function parseBodyValue(value: JSONValue): WebRTCSignalV1Body {
  if (!isJSONObject(value)) throw protocolError(ERROR_CODES.INVALID_BODY, "WebRTC body 必须是 object");
  requireObjectKeys(value, ["request_message_id", "session_id", "signal"]);
  const request_message_id = parseMessageID(stringField(value, "request_message_id"));
  const session_id = parseSessionID(stringField(value, "session_id"));
  const signalRaw = requireField(value, "signal");
  if (!isJSONObject(signalRaw)) throw protocolError(ERROR_CODES.INVALID_BODY, "signal 必须是 object");
  const type = stringField(signalRaw, "type") as SignalType;
  let signal: Signal;
  if (type === "offer" || type === "answer") {
    requireObjectKeys(signalRaw, ["type", "sdp"]);
    const sdp = stringField(signalRaw, "sdp");
    signal = type === "offer" ? { type, sdp } : { type, sdp };
  } else if (type === "ice-candidate") {
    requireObjectKeys(signalRaw, ["type", "candidate"]);
    const candidateRaw = requireField(signalRaw, "candidate");
    if (!isJSONObject(candidateRaw)) throw protocolError(ERROR_CODES.INVALID_BODY, "candidate 必须是 object");
    requireObjectKeys(candidateRaw, ["candidate", "sdp_mid", "sdp_m_line_index"]);
    const candidate = stringField(candidateRaw, "candidate");
    const midRaw = requireField(candidateRaw, "sdp_mid");
    const sdp_mid = midRaw === null ? null : stringValue(midRaw, "sdp_mid");
    const lineRaw = requireField(candidateRaw, "sdp_m_line_index");
    const sdp_m_line_index = lineRaw === null ? null : parseCandidateIndex(lineRaw);
    signal = { type, candidate: { candidate, sdp_mid, sdp_m_line_index } };
  } else if (type === "end-of-candidates") {
    requireObjectKeys(signalRaw, ["type"]);
    signal = { type };
  } else {
    throw protocolError(ERROR_CODES.INVALID_BODY, "不支持的 WebRTC signal.type");
  }
  const body = { request_message_id, session_id, signal };
  validateBody(body);
  return cloneAndFreeze(body);
}

/** WebRTC 会话三元组的强类型辅助值。 */
export interface SessionKey {
  /** 所属公开 Hash 请求编号。 */
  readonly request_message_id: MessageID;
  /** 创建 offer 的信封发送者公钥。 */
  readonly offerer_public_key: PublicKey;
  /** offerer 创建的 session_id。 */
  readonly session_id: SessionID;
  /** 本地无歧义键文本，不是线上字段。 */
  readonly key: string;
}

/** 构造 WebRTC SessionKey。 */
export function sessionKey(requestMessageId: MessageID, offererPublicKey: PublicKey, sessionId: SessionID): SessionKey {
  parseMessageID(requestMessageId);
  parsePublicKey(offererPublicKey);
  parseSessionID(sessionId);
  return freezeDeep({ request_message_id: requestMessageId, offerer_public_key: offererPublicKey, session_id: sessionId, key: `${requestMessageId}\0${offererPublicKey}\0${sessionId}` });
}

/** 调用方保存的 offer 会话上下文；SDK 不保存连接状态。 */
export interface SessionContext {
  /** 会话三元组。 */
  readonly key: SessionKey;
  /** inbox channel 后缀对应的 answerer 公钥。 */
  readonly answerer_public_key: PublicKey;
}

/** 从 offer 和双方身份创建关系校验上下文。 */
export function newSessionContext(offer: WebRTCSignalV1Body, offererPublicKey: PublicKey, answererPublicKey: PublicKey): SessionContext {
  validateBody(offer);
  if (offer.signal.type !== "offer") throw protocolError(ERROR_CODES.INVALID_RELATION, "会话上下文必须由 offer 创建");
  parsePublicKey(answererPublicKey);
  return freezeDeep({ key: sessionKey(offer.request_message_id, offererPublicKey, offer.session_id), answerer_public_key: answererPublicKey });
}

/** 纯函数检查 offer/answer/ICE 与已保存会话关系。 */
export function validateRelation(body: WebRTCSignalV1Body, context: SessionContext, senderPublicKey: PublicKey): void {
  validateBody(body);
  parseMessageID(context.key.request_message_id);
  parsePublicKey(context.key.offerer_public_key);
  parseSessionID(context.key.session_id);
  parsePublicKey(context.answerer_public_key);
  parsePublicKey(senderPublicKey);
  if (body.request_message_id !== context.key.request_message_id || body.session_id !== context.key.session_id) throw protocolError(ERROR_CODES.INVALID_RELATION, "request_message_id 或 session_id 与会话上下文不一致");
  if (body.signal.type === "offer" && senderPublicKey !== context.key.offerer_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "offer 发送者不是 offerer");
  if (body.signal.type === "answer" && senderPublicKey !== context.answerer_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "answer 发送者不是 answerer");
  if ((body.signal.type === "ice-candidate" || body.signal.type === "end-of-candidates") && senderPublicKey !== context.key.offerer_public_key && senderPublicKey !== context.answerer_public_key) throw protocolError(ERROR_CODES.INVALID_RELATION, "ICE 发送者不属于会话双方");
}

/** 本子协议允许的最大有效期。 */
export const MAX_LIFETIME_MS = 2 * 60 * 1000;

/** Go 风格大写别名。 */
export const NewOffer = newOffer;
/** Go 风格大写别名。 */
export const NewAnswer = newAnswer;
/** Go 风格大写别名。 */
export const NewICECandidate = newICECandidate;
/** Go 风格大写别名。 */
export const NewEndOfCandidates = newEndOfCandidates;
/** Go 风格大写别名。 */
export const ParseBody = parseBody;
/** Go 风格大写别名。 */
export const SessionKeyFor = sessionKey;
/** Go 风格大写别名。 */
export const NewSessionContext = newSessionContext;
/** Go 风格大写别名。 */
export const ValidateRelation = validateRelation;

function validateCandidate(candidate: ICECandidate): void {
  requireExactObjectKeys(candidate, ["candidate", "sdp_mid", "sdp_m_line_index"], "ICE candidate");
  if (typeof candidate.candidate !== "string" || candidate.candidate.length === 0) throw protocolError(ERROR_CODES.INVALID_BODY, "candidate 不能为空");
  if (candidate.sdp_mid !== null && typeof candidate.sdp_mid !== "string") throw protocolError(ERROR_CODES.INVALID_BODY, "sdp_mid 必须是 string 或 null");
  if (candidate.sdp_m_line_index !== null) parseCandidateIndex(candidate.sdp_m_line_index);
  if (Object.keys(candidate).length !== 3) throw protocolError(ERROR_CODES.INVALID_BODY, "candidate 存在未知字段");
}

function stringField(object: Record<string, JSONValue>, field: string): string {
  return stringValue(requireField(object, field), field);
}

function stringValue(value: JSONValue, field: string): string {
  if (typeof value !== "string") throw protocolError(ERROR_CODES.INVALID_BODY, `${field} 必须是 string`);
  return value;
}

function parseCandidateIndex(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw protocolError(ERROR_CODES.INVALID_BODY, "sdp_m_line_index 必须是非负 safe integer 或 null");
  return value;
}
