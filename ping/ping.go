// Package ping 实现 bsv8.ping.v1 的 Ping/Pong content_json body。
package ping

import (
	"fmt"

	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
)

// Type 是 Ping/Pong body 的 discriminator。
type Type string

const (
	// TypePing 表示一次探测。
	TypePing Type = "ping"
	// TypePong 表示对指定 Ping 的响应。
	TypePong Type = "pong"
)

// Body 是 bsv8.ping.v1 的强类型联合 body。
type Body struct {
	// Type 决定当前是 Ping 还是 Pong。
	Type Type
	// PingMessageID 是 Pong 所引用的 Ping 私密消息 message_id；Ping 时为空。
	PingMessageID encoding.MessageID
}

// JSONValue 返回不含外层发布头的 body JSON 值。
func (body Body) JSONValue() any {
	if body.Type == TypePong {
		return map[string]any{"type": string(TypePong), "ping_message_id": body.PingMessageID.String()}
	}
	return map[string]any{"type": string(TypePing)}
}

// Validate 检查 Ping/Pong body 的严格字段和编号。
func (body Body) Validate() error {
	switch body.Type {
	case TypePing:
		if body.PingMessageID != (encoding.MessageID{}) {
			return protocolerror.New(protocolerror.InvalidBody, "ping 不允许携带 ping_message_id")
		}
	case TypePong:
		if _, err := encoding.ParseMessageID(body.PingMessageID.String()); err != nil {
			return err
		}
	default:
		return protocolerror.New(protocolerror.InvalidBody, "不支持的 Ping/Pong body.type")
	}
	return nil
}

// NewPing 构造 Ping body。
func NewPing() Body { return Body{Type: TypePing} }

// NewPong 构造引用 Ping message_id 的 Pong body。
func NewPong(pingMessageID encoding.MessageID) (Body, error) {
	body := Body{Type: TypePong, PingMessageID: pingMessageID}
	return body, body.Validate()
}

// ParseBody 严格解析 Ping/Pong body。
func ParseBody(input []byte) (Body, error) {
	value, err := strictjson.Parse(input)
	if err != nil {
		return Body{}, err
	}
	return ParseBodyValue(value)
}

// ParseBodyValue 将严格 JSON 值解析为 Ping/Pong body。
func ParseBodyValue(value strictjson.JSONValue) (Body, error) {
	object, ok := value.(map[string]strictjson.JSONValue)
	if !ok {
		return Body{}, protocolerror.New(protocolerror.InvalidBody, "Ping/Pong body 必须是 object")
	}
	typeText, err := requiredString(object, "type")
	if err != nil {
		return Body{}, err
	}
	switch Type(typeText) {
	case TypePing:
		if err := strictjson.RequireObjectKeys(object, "type"); err != nil {
			return Body{}, err
		}
		return NewPing(), nil
	case TypePong:
		if err := strictjson.RequireObjectKeys(object, "type", "ping_message_id"); err != nil {
			return Body{}, err
		}
		idText, err := requiredString(object, "ping_message_id")
		if err != nil {
			return Body{}, err
		}
		id, err := encoding.ParseMessageID(idText)
		if err != nil {
			return Body{}, err
		}
		return NewPong(id)
	default:
		return Body{}, protocolerror.New(protocolerror.InvalidBody, "不支持的 Ping/Pong body.type")
	}
}

const maxLifetimeMs int64 = 60 * 1000

// MaxLifetimeMs 返回 Ping/Pong 的最大外层 Publish 有效期。
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
