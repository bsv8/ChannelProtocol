// Package protocol 保存三方频道 V1 的线上常量，供 Go 各模块共享。
package protocol

const (
	// HashRequestChannel 是公开 Hash 请求频道。
	HashRequestChannel = "bsv8.hash.request.v1"
	// InboxChannelPrefix 是私密收件箱频道前缀。
	InboxChannelPrefix = "bsv8.inbox."
	// WebRTCSignalProtocol 是 WebRTC SDP/ICE 子协议。
	WebRTCSignalProtocol = "bsv8.webrtc.signal.v1"
	// AppMessageProtocol 是应用消息 Deliver/ACK 子协议。
	AppMessageProtocol = "bsv8.message.v1"
	// PingProtocol 是 Ping/Pong 收件箱子协议。
	PingProtocol = "bsv8.ping.v1"
	// PublicMessageScope 是公开消息签名作用域。
	PublicMessageScope = "bsv8.public-message.v1"
	// BSVPriceProtocol 是 BSV 多市场、多交易对价格快照的业务协议标识。
	BSVPriceProtocol = "bsv8.bsv-price.v1"
	// BSVPriceChannelPrefix 是价格频道前缀，后接发布者压缩公钥小写 hex。
	BSVPriceChannelPrefix = "bsvprice."
	// PrivateMessageScope 是私密消息签名作用域。
	PrivateMessageScope = "bsv8.private-message.v1"
	// InboxEnvelopeVersion 是私密信封版本。
	InboxEnvelopeVersion = 1
)
