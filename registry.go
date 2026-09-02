// Package channels 提供三方频道协议的稳定线上常量。
//
// 正式解析、签名、验签和私密收件箱 API 按协议子包提供；这里不维护运行时注册表。
package channels

import "github.com/bsv8/ChannelProtocol/internal/protocol"

const (
	// HashRequestChannel 是公开 Hash 请求频道的精确名称。
	HashRequestChannel = protocol.HashRequestChannel
	// InboxChannelPrefix 是私密收件箱频道的固定前缀，后接目标公钥小写 hex。
	InboxChannelPrefix = protocol.InboxChannelPrefix
	// WebRTCSignalProtocol 是 WebRTC SDP/ICE 收件箱子协议名称。
	WebRTCSignalProtocol = protocol.WebRTCSignalProtocol
	// AppMessageProtocol 是应用消息 Deliver/ACK 收件箱子协议名称。
	AppMessageProtocol = protocol.AppMessageProtocol
	// PingProtocol 是 Ping/Pong 收件箱子协议名称。
	PingProtocol = protocol.PingProtocol
	// InboxEnvelopeVersion 是当前私密收件箱加密信封版本。
	InboxEnvelopeVersion = protocol.InboxEnvelopeVersion
	// PublicMessageScope 是公开消息签名作用域。
	PublicMessageScope = protocol.PublicMessageScope
	// PrivateMessageScope 是私密消息签名作用域。
	PrivateMessageScope = protocol.PrivateMessageScope
)

// MaxJSONBytes 是输入和构造结果允许的最大 JSON UTF-8 字节数。
const MaxJSONBytes = 1_048_000

// MaxJSONDepth 是严格 JSON 允许的最大嵌套深度。
const MaxJSONDepth = 64

// MaxJSONNodes 是严格 JSON 允许的最大值节点数。
const MaxJSONNodes = 100_000
