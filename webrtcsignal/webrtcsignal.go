// Package webrtcsignal 实现 bsv8.webrtc.signal.v1 的强类型 body。
package webrtcsignal

import (
	stdjson "encoding/json"
	"fmt"

	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocol"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
)

const maxLifetimeMs int64 = 2 * 60 * 1000

// SignalType 是 WebRTC 信令联合类型 discriminator。
type SignalType string

const (
	// SignalOffer 是资源提供者发送的 SDP offer。
	SignalOffer SignalType = "offer"
	// SignalAnswer 是请求者返回的 SDP answer。
	SignalAnswer SignalType = "answer"
	// SignalICECandidate 是单个 ICE candidate。
	SignalICECandidate SignalType = "ice-candidate"
	// SignalEndOfCandidates 表示当前候选发送结束。
	SignalEndOfCandidates SignalType = "end-of-candidates"
)

// ICECandidate 是严格的 ICE candidate 正文；两个索引字段都允许显式 null。
type ICECandidate struct {
	// Candidate 是 WebRTC ICE candidate 字符串。
	Candidate string
	// SDPMid 是对应 media section，可为 nil 表示 JSON null。
	SDPMid *string
	// SDPMLineIndex 是 media 行索引，可为 nil 表示 JSON null。
	SDPMLineIndex *int
}

// Signal 是严格互斥的 offer/answer/ICE/end-of-candidates 联合值。
type Signal struct {
	// Type 决定本值允许出现的字段分支。
	Type SignalType
	// SDP 是 offer 或 answer 的 SDP 文本。
	SDP string
	// Candidate 是 ice-candidate 分支的 candidate 对象。
	Candidate *ICECandidate
}

// WebRTCSignalV1Body 是 bsv8.webrtc.signal.v1 的私密消息 body。
type WebRTCSignalV1Body struct {
	// RequestMessageID 是所属公开 Hash 请求编号。
	RequestMessageID encoding.MessageID
	// SessionID 是 offerer 为一次连接生成的会话编号。
	SessionID encoding.SessionID
	// Signal 是 SDP/ICE 联合信令值。
	Signal Signal
}

// ProtocolName 返回该 body 绑定的私密子协议名称。
func (WebRTCSignalV1Body) ProtocolName() string { return protocol.WebRTCSignalProtocol }

// JSONValue 返回不含公共消息头的 JSON body 值。
func (body WebRTCSignalV1Body) JSONValue() any { return bodyValue(body) }

// Validate 检查 WebRTC body 的字段和联合分支。
func (body WebRTCSignalV1Body) Validate() error {
	if _, err := encoding.ParseMessageID(body.RequestMessageID.String()); err != nil {
		return err
	}
	if _, err := encoding.ParseSessionID(body.SessionID.String()); err != nil {
		return err
	}
	switch body.Signal.Type {
	case SignalOffer, SignalAnswer:
		if body.Signal.SDP == "" || body.Signal.Candidate != nil {
			return protocolerror.New(protocolerror.InvalidBody, "offer/answer 只能包含非空 sdp")
		}
	case SignalICECandidate:
		if body.Signal.SDP != "" || body.Signal.Candidate == nil {
			return protocolerror.New(protocolerror.InvalidBody, "ice-candidate 只能包含 candidate")
		}
		if err := validateCandidate(*body.Signal.Candidate); err != nil {
			return err
		}
	case SignalEndOfCandidates:
		if body.Signal.SDP != "" || body.Signal.Candidate != nil {
			return protocolerror.New(protocolerror.InvalidBody, "end-of-candidates 不允许额外字段")
		}
	default:
		return protocolerror.New(protocolerror.InvalidBody, "不支持的 WebRTC signal.type")
	}
	return nil
}

// NewOffer 构造并校验 offer body。
func NewOffer(requestID encoding.MessageID, sessionID encoding.SessionID, sdp string) (WebRTCSignalV1Body, error) {
	body := WebRTCSignalV1Body{RequestMessageID: requestID, SessionID: sessionID, Signal: Signal{Type: SignalOffer, SDP: sdp}}
	return body, body.Validate()
}

// NewAnswer 构造并校验 answer body。
func NewAnswer(requestID encoding.MessageID, sessionID encoding.SessionID, sdp string) (WebRTCSignalV1Body, error) {
	body := WebRTCSignalV1Body{RequestMessageID: requestID, SessionID: sessionID, Signal: Signal{Type: SignalAnswer, SDP: sdp}}
	return body, body.Validate()
}

// NewICECandidate 构造并校验 ICE body。
func NewICECandidate(requestID encoding.MessageID, sessionID encoding.SessionID, candidate ICECandidate) (WebRTCSignalV1Body, error) {
	body := WebRTCSignalV1Body{RequestMessageID: requestID, SessionID: sessionID, Signal: Signal{Type: SignalICECandidate, Candidate: &candidate}}
	return body, body.Validate()
}

// NewEndOfCandidates 构造并校验 end-of-candidates body。
func NewEndOfCandidates(requestID encoding.MessageID, sessionID encoding.SessionID) (WebRTCSignalV1Body, error) {
	body := WebRTCSignalV1Body{RequestMessageID: requestID, SessionID: sessionID, Signal: Signal{Type: SignalEndOfCandidates}}
	return body, body.Validate()
}

// ParseBody 从严格 JSON body 解析 WebRTC 联合结构。
func ParseBody(input []byte) (WebRTCSignalV1Body, error) {
	value, err := strictjson.Parse(input)
	if err != nil {
		return WebRTCSignalV1Body{}, err
	}
	return ParseBodyValue(value)
}

// ParseBodyValue 将已经严格解析的 JSON 值转换为 WebRTC 强类型 body。
func ParseBodyValue(value strictjson.JSONValue) (WebRTCSignalV1Body, error) {
	object, ok := value.(map[string]strictjson.JSONValue)
	if !ok {
		return WebRTCSignalV1Body{}, protocolerror.New(protocolerror.InvalidBody, "WebRTC body 必须是 object")
	}
	if err := strictjson.RequireObjectKeys(object, "request_message_id", "session_id", "signal"); err != nil {
		return WebRTCSignalV1Body{}, err
	}
	requestText, err := requiredString(object, "request_message_id")
	if err != nil {
		return WebRTCSignalV1Body{}, err
	}
	requestID, err := encoding.ParseMessageID(requestText)
	if err != nil {
		return WebRTCSignalV1Body{}, err
	}
	sessionText, err := requiredString(object, "session_id")
	if err != nil {
		return WebRTCSignalV1Body{}, err
	}
	sessionID, err := encoding.ParseSessionID(sessionText)
	if err != nil {
		return WebRTCSignalV1Body{}, err
	}
	signalRaw, err := strictjson.RequireField(object, "signal")
	if err != nil {
		return WebRTCSignalV1Body{}, err
	}
	signalObject, ok := signalRaw.(map[string]strictjson.JSONValue)
	if !ok {
		return WebRTCSignalV1Body{}, protocolerror.New(protocolerror.InvalidBody, "signal 必须是 object")
	}
	signal, err := parseSignal(signalObject)
	if err != nil {
		return WebRTCSignalV1Body{}, err
	}
	body := WebRTCSignalV1Body{RequestMessageID: requestID, SessionID: sessionID, Signal: signal}
	return body, body.Validate()
}

// SessionKey 是 (request_message_id, offerer_public_key, session_id) 会话唯一键。
type SessionKey struct {
	// RequestMessageID 是公开 Hash 请求编号。
	RequestMessageID encoding.MessageID
	// OffererPublicKey 是创建 offer 的信封发送者公钥。
	OffererPublicKey encoding.PublicKey
	// SessionID 是 offerer 创建的 WebRTC 会话编号。
	SessionID encoding.SessionID
}

// String 返回无歧义的本地会话键文本，不作为线上协议字段。
func (key SessionKey) String() string {
	return key.RequestMessageID.String() + "\x00" + key.OffererPublicKey.String() + "\x00" + key.SessionID.String()
}

// NewSessionKey 构造并校验 WebRTC 会话唯一键。
func NewSessionKey(requestID encoding.MessageID, offerer encoding.PublicKey, sessionID encoding.SessionID) (SessionKey, error) {
	if _, err := encoding.ParseMessageID(requestID.String()); err != nil {
		return SessionKey{}, err
	}
	if _, err := encoding.ParsePublicKey(offerer.String()); err != nil {
		return SessionKey{}, err
	}
	if _, err := encoding.ParseSessionID(sessionID.String()); err != nil {
		return SessionKey{}, err
	}
	return SessionKey{RequestMessageID: requestID, OffererPublicKey: offerer, SessionID: sessionID}, nil
}

// SessionContext 是调用方保存的 offer 会话上下文，不由 SDK 持久化。
type SessionContext struct {
	// Key 是会话三元组。
	Key SessionKey
	// AnswererPublicKey 是 offer 发送到的 inbox 目标公钥。
	AnswererPublicKey encoding.PublicKey
}

// NewSessionContext 从合法 offer 和双方身份创建关系校验上下文。
func NewSessionContext(offer WebRTCSignalV1Body, offerer, answerer encoding.PublicKey) (SessionContext, error) {
	if err := offer.Validate(); err != nil {
		return SessionContext{}, err
	}
	if offer.Signal.Type != SignalOffer {
		return SessionContext{}, protocolerror.New(protocolerror.InvalidRelation, "会话上下文必须由 offer 创建")
	}
	key, err := NewSessionKey(offer.RequestMessageID, offerer, offer.SessionID)
	if err != nil {
		return SessionContext{}, err
	}
	if _, err := encoding.ParsePublicKey(answerer.String()); err != nil {
		return SessionContext{}, err
	}
	return SessionContext{Key: key, AnswererPublicKey: answerer}, nil
}

// ValidateRelation 纯函数检查 offer/answer/ICE 与已保存会话及发送者的关系。
func ValidateRelation(body WebRTCSignalV1Body, context SessionContext, sender encoding.PublicKey) error {
	if err := body.Validate(); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(context.Key.OffererPublicKey.String()); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(context.AnswererPublicKey.String()); err != nil {
		return err
	}
	if _, err := encoding.ParseMessageID(context.Key.RequestMessageID.String()); err != nil {
		return err
	}
	if _, err := encoding.ParseSessionID(context.Key.SessionID.String()); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(sender.String()); err != nil {
		return err
	}
	if !body.RequestMessageID.Equal(context.Key.RequestMessageID) || !body.SessionID.Equal(context.Key.SessionID) {
		return protocolerror.New(protocolerror.InvalidRelation, "request_message_id 或 session_id 与会话上下文不一致")
	}
	switch body.Signal.Type {
	case SignalOffer:
		if !sender.Equal(context.Key.OffererPublicKey) {
			return protocolerror.New(protocolerror.InvalidRelation, "offer 发送者不是 offerer")
		}
	case SignalAnswer:
		if !sender.Equal(context.AnswererPublicKey) {
			return protocolerror.New(protocolerror.InvalidRelation, "answer 发送者不是 answerer")
		}
	case SignalICECandidate, SignalEndOfCandidates:
		if !sender.Equal(context.Key.OffererPublicKey) && !sender.Equal(context.AnswererPublicKey) {
			return protocolerror.New(protocolerror.InvalidRelation, "ICE 发送者不属于会话双方")
		}
	default:
		return protocolerror.New(protocolerror.InvalidRelation, "未知 WebRTC 信令类型")
	}
	return nil
}

// MaxLifetimeMs 返回本子协议允许的最大消息有效期。
func MaxLifetimeMs() int64 { return maxLifetimeMs }

func bodyValue(body WebRTCSignalV1Body) map[string]any {
	signal := map[string]any{"type": string(body.Signal.Type)}
	switch body.Signal.Type {
	case SignalOffer, SignalAnswer:
		signal["sdp"] = body.Signal.SDP
	case SignalICECandidate:
		candidate := body.Signal.Candidate
		var mid any
		if candidate.SDPMid != nil {
			mid = *candidate.SDPMid
		}
		var line any
		if candidate.SDPMLineIndex != nil {
			line = *candidate.SDPMLineIndex
		}
		signal["candidate"] = map[string]any{"candidate": candidate.Candidate, "sdp_mid": mid, "sdp_m_line_index": line}
	}
	return map[string]any{
		"request_message_id": body.RequestMessageID.String(),
		"session_id":         body.SessionID.String(),
		"signal":             signal,
	}
}

func parseSignal(object map[string]strictjson.JSONValue) (Signal, error) {
	typeText, err := requiredString(object, "type")
	if err != nil {
		return Signal{}, err
	}
	signal := Signal{Type: SignalType(typeText)}
	switch signal.Type {
	case SignalOffer, SignalAnswer:
		if err := strictjson.RequireObjectKeys(object, "type", "sdp"); err != nil {
			return Signal{}, err
		}
		signal.SDP, err = requiredString(object, "sdp")
		if err != nil {
			return Signal{}, err
		}
	case SignalICECandidate:
		if err := strictjson.RequireObjectKeys(object, "type", "candidate"); err != nil {
			return Signal{}, err
		}
		candidateRaw, err := strictjson.RequireField(object, "candidate")
		if err != nil {
			return Signal{}, err
		}
		candidateObject, ok := candidateRaw.(map[string]strictjson.JSONValue)
		if !ok {
			return Signal{}, protocolerror.New(protocolerror.InvalidBody, "candidate 必须是 object")
		}
		candidate, err := parseCandidate(candidateObject)
		if err != nil {
			return Signal{}, err
		}
		signal.Candidate = &candidate
	case SignalEndOfCandidates:
		if err := strictjson.RequireObjectKeys(object, "type"); err != nil {
			return Signal{}, err
		}
	default:
		return Signal{}, protocolerror.New(protocolerror.InvalidBody, "不支持的 WebRTC signal.type")
	}
	return signal, nil
}

func parseCandidate(object map[string]strictjson.JSONValue) (ICECandidate, error) {
	if err := strictjson.RequireObjectKeys(object, "candidate", "sdp_mid", "sdp_m_line_index"); err != nil {
		return ICECandidate{}, err
	}
	candidate, err := requiredString(object, "candidate")
	if err != nil {
		return ICECandidate{}, err
	}
	midRaw, err := strictjson.RequireField(object, "sdp_mid")
	if err != nil {
		return ICECandidate{}, err
	}
	var mid *string
	if midRaw != nil {
		midText, ok := midRaw.(string)
		if !ok {
			return ICECandidate{}, protocolerror.New(protocolerror.InvalidBody, "sdp_mid 必须是 string 或 null")
		}
		mid = &midText
	}
	lineRaw, err := strictjson.RequireField(object, "sdp_m_line_index")
	if err != nil {
		return ICECandidate{}, err
	}
	var line *int
	if lineRaw != nil {
		number, ok := lineRaw.(interface{ String() string })
		if !ok {
			return ICECandidate{}, protocolerror.New(protocolerror.InvalidBody, "sdp_m_line_index 必须是整数或 null")
		}
		parsed, err := encoding.ParsePositiveInt(stdjson.Number(number.String()), "sdp_m_line_index")
		if err != nil {
			return ICECandidate{}, err
		}
		line = &parsed
	}
	return ICECandidate{Candidate: candidate, SDPMid: mid, SDPMLineIndex: line}, validateCandidate(ICECandidate{Candidate: candidate, SDPMid: mid, SDPMLineIndex: line})
}

func validateCandidate(candidate ICECandidate) error {
	if candidate.Candidate == "" {
		return protocolerror.New(protocolerror.InvalidBody, "candidate 不能为空")
	}
	if candidate.SDPMLineIndex != nil && *candidate.SDPMLineIndex < 0 {
		return protocolerror.New(protocolerror.InvalidBody, "sdp_m_line_index 不能为负数")
	}
	return nil
}

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
