/** 公开 Hash 请求频道的精确名称。 */
export const HASH_REQUEST_CHANNEL = "bsv8.hash.request.v1" as const;

/** 私密收件箱频道前缀，后接目标公钥小写 hex。 */
export const INBOX_CHANNEL_PREFIX = "bsv8.inbox." as const;

/** WebRTC SDP/ICE 收件箱子协议名称。 */
export const WEBRTC_SIGNAL_PROTOCOL = "bsv8.webrtc.signal.v1" as const;

/** 应用消息 Deliver/ACK 收件箱子协议名称。 */
export const APP_MESSAGE_PROTOCOL = "bsv8.message.v1" as const;

/** Ping/Pong 收件箱子协议名称。 */
export const PING_PROTOCOL = "bsv8.ping.v1" as const;

/** 当前私密收件箱加密信封版本。 */
export const INBOX_ENVELOPE_VERSION = 1 as const;
