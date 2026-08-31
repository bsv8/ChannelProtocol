package channels

import (
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

// DecodePublicChannel 是根入口：严格解析并验签公开 Hash 请求。
func DecodePublicChannel(channel string, contentJSON []byte, nowMs int64) (hashrequest.VerifiedMessage, error) {
	return hashrequest.ParseAndVerify(channel, contentJSON, nowMs)
}

// DecodeInboxChannel 是根入口：解密并返回 WebRTC/应用消息强类型分派结果。
func DecodeInboxChannel(channel string, envelopeJSON []byte, recipientPrivateKey PrivateKey, nowMs int64) (inbox.DecodedInboxMessage, error) {
	return inbox.OpenAndDispatch(channel, envelopeJSON, recipientPrivateKey, nowMs)
}

type decodedChannelKind uint8

const (
	decodedChannelInvalid decodedChannelKind = iota
	decodedChannelPublic
	decodedChannelInbox
)

// DecodedChannel 是 DecodeChannel 的明确 tagged union。
// Public/Inbox 方法返回对应结果和是否匹配，避免用 any 让调用方猜测返回类型。
type DecodedChannel struct {
	kind   decodedChannelKind
	valid  bool
	public hashrequest.VerifiedMessage
	inbox  inbox.DecodedInboxMessage
}

// IsPublic 返回联合值是否为公开 Hash 消息。
func (decoded DecodedChannel) IsPublic() bool {
	return decoded.valid && decoded.kind == decodedChannelPublic
}

// IsInbox 返回联合值是否为私密收件箱消息。
func (decoded DecodedChannel) IsInbox() bool {
	return decoded.valid && decoded.kind == decodedChannelInbox
}

// Public 返回公开 Hash 验证结果；当前不是公开分支时 ok=false。
func (decoded DecodedChannel) Public() (hashrequest.VerifiedMessage, bool) {
	return decoded.public, decoded.IsPublic()
}

// Inbox 返回私密强类型分派结果；当前不是 inbox 分支时 ok=false。
func (decoded DecodedChannel) Inbox() (inbox.DecodedInboxMessage, bool) {
	return decoded.inbox, decoded.IsInbox()
}

// ReviewOfferForHashRequest 统一审查 WebRTC offer 与已验证 Hash 请求的跨协议关系。
func ReviewOfferForHashRequest(hashRequest hashrequest.VerifiedMessage, offer inbox.VerifiedPrivateMessage, nowMs int64) (webrtcsignal.SessionKey, error) {
	return inbox.ReviewOfferForHashRequest(hashRequest, offer, nowMs)
}

// DecodeChannel 按实际 channel 自动选择公开 Hash 或私密 inbox 解码。
// 私密分支要求 recipientPrivateKey 非零有效私钥；返回明确 tagged union。
func DecodeChannel(channel string, contentJSON []byte, recipientPrivateKey *PrivateKey, nowMs int64) (DecodedChannel, error) {
	if channel == HashRequestChannel {
		message, err := DecodePublicChannel(channel, contentJSON, nowMs)
		if err != nil {
			return DecodedChannel{}, err
		}
		return DecodedChannel{kind: decodedChannelPublic, valid: true, public: message}, nil
	}
	if recipientPrivateKey == nil {
		return DecodedChannel{}, ErrInvalidChannel
	}
	message, err := DecodeInboxChannel(channel, contentJSON, *recipientPrivateKey, nowMs)
	if err != nil {
		return DecodedChannel{}, err
	}
	return DecodedChannel{kind: decodedChannelInbox, valid: true, inbox: message}, nil
}
