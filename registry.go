// Package channels 提供三方频道协议的统一入口和协议注册信息。
//
// 当前文件只冻结模块边界；正式解析、签名、验签和私密收件箱 API 按施工单实现。
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

// ProtocolDescriptor 描述一份协议文档与代码模块的固定映射。
type ProtocolDescriptor struct {
	// Identifier 是线上频道名称、频道前缀或子协议名称。
	Identifier string
	// DescriptionZH 是中文业务说明。
	DescriptionZH string
	// GoPackage 是对应的 Go package 目录。
	GoPackage string
	// TypeScriptExport 是对应的 npm 子路径导出。
	TypeScriptExport string
}

var protocolRegistry = [...]ProtocolDescriptor{
	{HashRequestChannel, "公开广播文件 Hash 需求", "hashrequest", "./hash-request"},
	{InboxChannelPrefix + "<public_key_hex>", "按目标公钥投递端到端加密信封", "inbox", "./inbox"},
	{WebRTCSignalProtocol, "WebRTC SDP 和 ICE 强类型子协议", "webrtcsignal", "./webrtc-signal"},
	{AppMessageProtocol, "应用消息 Deliver 和 ACK 强类型子协议", "appmessage", "./app-message"},
}

// ProtocolRegistry 返回协议注册表副本，调用方不能修改 SDK 内部状态。
func ProtocolRegistry() []ProtocolDescriptor {
	result := make([]ProtocolDescriptor, len(protocolRegistry))
	copy(result, protocolRegistry[:])
	return result
}
