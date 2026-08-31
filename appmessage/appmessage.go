// Package appmessage 实现 bsv8.message.v1 的强类型 body。
package appmessage

import (
	"fmt"

	"github.com/bsv8/ChannelProtocol/internal/canonicaljson"
	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocol"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
)

const maxLifetimeMs int64 = 24 * 60 * 60 * 1000

// MessageType 是应用消息 body 的联合类型 discriminator。
type MessageType string

const (
	// MessageTypeDeliver 表示应用消息投递。
	MessageTypeDeliver MessageType = "deliver"
	// MessageTypeAck 表示可靠接收确认。
	MessageTypeAck MessageType = "ack"
)

// MessageV1Body 是 bsv8.message.v1 的强类型 body 联合接口。
type MessageV1Body interface {
	// ProtocolName 返回固定子协议名称。
	ProtocolName() string
	// JSONValue 返回不含公共头的 JSON 值。
	JSONValue() any
	// Validate 检查当前联合分支。
	Validate() error
	// MessageType 返回 deliver 或 ack。
	MessageType() MessageType
}

// DeliverBody 是应用消息投递正文。
type DeliverBody struct {
	// Content 是任意可被 RFC 8785 JCS 表示的 JSON 值。
	Content any
}

// AckBody 是可靠接收确认正文。
type AckBody struct {
	// AcknowledgedMessageID 是原 Deliver 私密消息的 message_id。
	AcknowledgedMessageID encoding.MessageID
}

// ProtocolName 返回 Deliver 所属子协议。
func (DeliverBody) ProtocolName() string { return protocol.AppMessageProtocol }

// JSONValue 返回 Deliver body。
func (body DeliverBody) JSONValue() any {
	return map[string]any{"type": string(MessageTypeDeliver), "content": body.Content}
}

// Validate 检查 content 能否被严格 JCS 编码。
func (body DeliverBody) Validate() error {
	canonical, err := canonicaljson.CanonicalizeValue(body.Content)
	if err != nil {
		if protocolerror.Is(err, protocolerror.MessageTooLarge) {
			return err
		}
		return protocolerror.New(protocolerror.InvalidBody, "deliver.content 不是 JCS 兼容 JSON 值")
	}
	if len(canonical) > strictjson.MaxJSONBytes {
		return protocolerror.New(protocolerror.MessageTooLarge, "deliver.content 超过 JSON 字节上限")
	}
	return nil
}

// MessageType 返回 deliver。
func (DeliverBody) MessageType() MessageType { return MessageTypeDeliver }

// ProtocolName 返回 ACK 所属子协议。
func (AckBody) ProtocolName() string { return protocol.AppMessageProtocol }

// JSONValue 返回 ACK body。
func (body AckBody) JSONValue() any {
	return map[string]any{"type": string(MessageTypeAck), "acknowledged_message_id": body.AcknowledgedMessageID.String()}
}

// Validate 检查 ACK 关联编号格式。
func (body AckBody) Validate() error {
	if _, err := encoding.ParseMessageID(body.AcknowledgedMessageID.String()); err != nil {
		return err
	}
	return nil
}

// MessageType 返回 ack。
func (AckBody) MessageType() MessageType { return MessageTypeAck }

// NewDeliver 构造并校验 Deliver body。
func NewDeliver(content any) (DeliverBody, error) {
	body := DeliverBody{Content: content}
	return body, body.Validate()
}

// NewAck 构造并校验 ACK body。
func NewAck(messageID encoding.MessageID) (AckBody, error) {
	body := AckBody{AcknowledgedMessageID: messageID}
	return body, body.Validate()
}

// ParseBody 从 JSON 严格解析 MessageV1Body。
func ParseBody(input []byte) (MessageV1Body, error) {
	value, err := strictjson.Parse(input)
	if err != nil {
		return nil, err
	}
	return ParseBodyValue(value)
}

// ParseBodyValue 将严格解析的 JSON 值分派为 DeliverBody 或 AckBody。
func ParseBodyValue(value strictjson.JSONValue) (MessageV1Body, error) {
	object, ok := value.(map[string]strictjson.JSONValue)
	if !ok {
		return nil, protocolerror.New(protocolerror.InvalidBody, "应用消息 body 必须是 object")
	}
	typeText, err := requiredString(object, "type")
	if err != nil {
		return nil, err
	}
	switch MessageType(typeText) {
	case MessageTypeDeliver:
		if err := strictjson.RequireObjectKeys(object, "type", "content"); err != nil {
			return nil, err
		}
		content, err := strictjson.RequireField(object, "content")
		if err != nil {
			return nil, err
		}
		body := DeliverBody{Content: content}
		return body, body.Validate()
	case MessageTypeAck:
		if err := strictjson.RequireObjectKeys(object, "type", "acknowledged_message_id"); err != nil {
			return nil, err
		}
		messageText, err := requiredString(object, "acknowledged_message_id")
		if err != nil {
			return nil, err
		}
		messageID, err := encoding.ParseMessageID(messageText)
		if err != nil {
			return nil, err
		}
		body := AckBody{AcknowledgedMessageID: messageID}
		return body, body.Validate()
	default:
		return nil, protocolerror.New(protocolerror.InvalidBody, "不支持的应用消息 body.type")
	}
}

// DeliveryContext 描述原 Deliver 的发送者、接收者和外层消息编号。
type DeliveryContext struct {
	// FromPublicKey 是 Deliver 信封发送者。
	FromPublicKey encoding.PublicKey
	// ToPublicKey 是 Deliver inbox channel 目标。
	ToPublicKey encoding.PublicKey
	// MessageID 是原 Deliver 私密消息编号。
	MessageID encoding.MessageID
}

// AckContext 描述 ACK 信封身份和 ACK body。
type AckContext struct {
	// FromPublicKey 是 ACK 信封发送者。
	FromPublicKey encoding.PublicKey
	// ToPublicKey 是 ACK inbox channel 目标。
	ToPublicKey encoding.PublicKey
	// Body 是 ACK 强类型正文。
	Body AckBody
}

// ValidateAckRelation 检查 ACK 的发送者、接收者和 acknowledged_message_id。
func ValidateAckRelation(delivery DeliveryContext, ack AckContext) error {
	if _, err := encoding.ParsePublicKey(delivery.FromPublicKey.String()); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(delivery.ToPublicKey.String()); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(ack.FromPublicKey.String()); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(ack.ToPublicKey.String()); err != nil {
		return err
	}
	if _, err := encoding.ParseMessageID(delivery.MessageID.String()); err != nil {
		return err
	}
	if err := ack.Body.Validate(); err != nil {
		return err
	}
	if !ack.FromPublicKey.Equal(delivery.ToPublicKey) {
		return protocolerror.New(protocolerror.InvalidRelation, "ACK 发送者不是 Deliver 接收者")
	}
	if !ack.ToPublicKey.Equal(delivery.FromPublicKey) {
		return protocolerror.New(protocolerror.InvalidRelation, "ACK 接收者不是 Deliver 发送者")
	}
	if !ack.Body.AcknowledgedMessageID.Equal(delivery.MessageID) {
		return protocolerror.New(protocolerror.InvalidRelation, "ACK 未关联原 Deliver message_id")
	}
	return nil
}

// DeduplicationKey 是应用消息的 (protocol, from_public_key, message_id) 去重键。
type DeduplicationKey struct {
	// Protocol 固定为 bsv8.message.v1。
	Protocol string
	// FromPublicKey 是私密消息发送者。
	FromPublicKey encoding.PublicKey
	// MessageID 是私密消息编号。
	MessageID encoding.MessageID
}

// NewDeduplicationKey 构造应用消息去重键。
func NewDeduplicationKey(from encoding.PublicKey, messageID encoding.MessageID) DeduplicationKey {
	return DeduplicationKey{Protocol: protocol.AppMessageProtocol, FromPublicKey: from, MessageID: messageID}
}

// CheckDigestConflict 检查相同去重键的两个签名摘要是否冲突。
func CheckDigestConflict(existing, incoming encoding.SHA256Hash) error {
	if !existing.Equal(incoming) {
		return protocolerror.New(protocolerror.MessageIDConflict, "同一应用消息去重键对应不同已签名内容")
	}
	return nil
}

// MaxLifetimeMs 返回 Deliver/ACK 的最大有效期。
func MaxLifetimeMs() int64 { return maxLifetimeMs }

func requiredString(object map[string]strictjson.JSONValue, field string) (string, error) {
	value, err := strictjson.RequireField(object, field)
	if err != nil {
		return "", err
	}
	result, ok := value.(string)
	if !ok {
		return "", protocolerror.New(protocolerror.InvalidBody, fmt.Sprintf("%s 必须是 string", field))
	}
	return result, nil
}
