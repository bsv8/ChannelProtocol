// Package publicmessage implements bsv8.public-message.v1 for arbitrary exact
// SSP channels.
package publicmessage

import (
	"crypto/sha256"
	stdjson "encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/bsv8/ChannelProtocol/internal/canonicaljson"
	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocol"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/secp256k1"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
)

const (
	maxLifetimeMs   int64 = 10 * 60 * 1000
	maxFutureSkewMs int64 = 60 * 1000
	maxChannelBytes       = 256
	maxSafeInteger  int64 = 9_007_199_254_740_991
)

// UnsignedMessage 是任意精确公开频道上的待签名消息。
type UnsignedMessage struct {
	// Channel 是不含 wildcard 的精确 SSP channel。它不写入线上 JSON，
	// 但会绑定到 bsv8.public-message.v1 的签名逻辑对象。
	Channel string
	// FromPublicKey 是发布者长期压缩公钥。
	FromPublicKey encoding.PublicKey
	// MessageID 是 32 字节公开消息编号。
	MessageID encoding.MessageID
	// IssuedAtMs 是发布时间 Unix 毫秒。
	IssuedAtMs int64
	// ExpiresAtMs 是过期时间 Unix 毫秒。
	ExpiresAtMs int64
	// Body 是应用自定义的受限 JSON 值。
	Body strictjson.JSONValue
}

// SignedMessage 是包含唯一业务签名的公开消息。
type SignedMessage struct {
	UnsignedMessage
	// Signature 是 bsv8.public-message.v1 的 strict DER low-S 签名。
	Signature encoding.Signature
}

// VerifiedMessage 是已经完成结构、时间和签名验证的公开消息。
//
// 该类型的内部字段不可由包外代码构造。所有包含 JSON 值的访问器都会返回
// 独立快照，因此调用方不能通过 map 或 slice 改写验签时的内容。
type VerifiedMessage struct {
	signed   SignedMessage
	digest   encoding.SHA256Hash
	verified bool
}

// DeduplicationKey 是 (channel, from_public_key, message_id) 去重键。
type DeduplicationKey struct {
	// Channel 是发布消息时使用的精确频道。
	Channel string
	// FromPublicKey 是发布者公钥。
	FromPublicKey encoding.PublicKey
	// MessageID 是消息编号。
	MessageID encoding.MessageID
}

// MaxLifetimeMs 返回通用公开消息允许的最大有效期。
func MaxLifetimeMs() int64 { return maxLifetimeMs }

// MaxFutureSkewMs 返回通用公开消息允许的最大未来时钟偏差。
func MaxFutureSkewMs() int64 { return maxFutureSkewMs }

// ValidateChannel 校验非空、非 wildcard 且不超过 SSP channel 长度上限的频道。
func ValidateChannel(channel string) error {
	if channel == "" || channel == "*" || !utf8.ValidString(channel) || len([]byte(channel)) > maxChannelBytes {
		return protocolerror.New(protocolerror.InvalidChannel, "公开消息必须使用合法精确 channel")
	}
	for _, r := range channel {
		if r < 0x20 || r == 0x7f {
			return protocolerror.New(protocolerror.InvalidChannel, "channel 包含控制字符")
		}
	}
	return nil
}

// Sign 校验消息并生成确定性 low-S 签名。
//
// Body 会在返回值中保存为独立的严格 JSON 快照；调用方在 Sign 返回后修改
// 原始 map/slice 不会改变返回消息的规范 JSON 或摘要。
func Sign(message UnsignedMessage, privateKey encoding.PrivateKey) (SignedMessage, error) {
	if err := validatePrivateKey(privateKey); err != nil {
		return SignedMessage{}, err
	}
	if err := validateUnsigned(message); err != nil {
		return SignedMessage{}, err
	}
	derived, err := secp256k1.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return SignedMessage{}, protocolerror.New(protocolerror.InvalidPrivateKey, "无法从私钥推导公钥")
	}
	if err := encoding.CheckIdentity(derived, message.FromPublicKey, "私钥推导公钥与 from_public_key 不一致"); err != nil {
		return SignedMessage{}, err
	}
	body, err := snapshotBody(message.Body)
	if err != nil {
		return SignedMessage{}, err
	}
	snapshot := message
	snapshot.Body = body
	digest, err := signingDigest(snapshot)
	if err != nil {
		return SignedMessage{}, err
	}
	signature, err := secp256k1.Sign(privateKey, digest)
	if err != nil {
		return SignedMessage{}, protocolerror.New(protocolerror.InvalidSignature, "公开消息签名失败")
	}
	return SignedMessage{UnsignedMessage: snapshot, Signature: signature}, nil
}

// Marshal 输出不含 channel 字段的规范 JCS JSON。
func Marshal(message SignedMessage) ([]byte, error) {
	if err := validateUnsigned(message.UnsignedMessage); err != nil {
		return nil, err
	}
	if len(message.Signature.DER()) == 0 {
		return nil, protocolerror.New(protocolerror.InvalidSignature, "公开消息缺少 signature")
	}
	digest, err := signingDigest(message.UnsignedMessage)
	if err != nil {
		return nil, err
	}
	if err := secp256k1.Verify(message.FromPublicKey, digest, message.Signature); err != nil {
		return nil, err
	}
	result, err := canonicaljson.CanonicalizeValue(messageValue(message))
	if err != nil {
		return nil, err
	}
	if len(result) > strictjson.MaxJSONBytes {
		return nil, protocolerror.New(protocolerror.MessageTooLarge, "公开消息超过 JSON 字节上限")
	}
	return result, nil
}

// ParseAndVerify 严格解析指定 channel 上的公开消息并验签。
func ParseAndVerify(channel string, input []byte, nowMs int64) (VerifiedMessage, error) {
	if err := ValidateChannel(channel); err != nil {
		return VerifiedMessage{}, err
	}
	if err := validateNow(nowMs); err != nil {
		return VerifiedMessage{}, err
	}
	object, err := strictjson.ParseObject(input)
	if err != nil {
		return VerifiedMessage{}, err
	}
	if err := strictjson.RequireObjectKeys(object, "from_public_key", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"); err != nil {
		return VerifiedMessage{}, err
	}
	message, err := parseMessage(channel, object)
	if err != nil {
		return VerifiedMessage{}, err
	}
	if err := validateUnsigned(message.UnsignedMessage); err != nil {
		return VerifiedMessage{}, err
	}
	if message.IssuedAtMs > nowMs && message.IssuedAtMs-nowMs > maxFutureSkewMs {
		return VerifiedMessage{}, protocolerror.New(protocolerror.InvalidTime, "公开消息发布时间超出允许的未来时钟偏差")
	}
	if nowMs >= message.ExpiresAtMs {
		return VerifiedMessage{}, protocolerror.New(protocolerror.MessageExpired, "公开消息已过期")
	}
	digest, err := signingDigest(message.UnsignedMessage)
	if err != nil {
		return VerifiedMessage{}, err
	}
	if err := secp256k1.Verify(message.FromPublicKey, digest, message.Signature); err != nil {
		return VerifiedMessage{}, err
	}
	body, err := snapshotBody(message.Body)
	if err != nil {
		return VerifiedMessage{}, err
	}
	message.Body = body
	hash, err := encoding.NewSHA256HashFromBytes(digest[:])
	if err != nil {
		return VerifiedMessage{}, err
	}
	return VerifiedMessage{signed: cloneSignedMessage(message), digest: hash, verified: true}, nil
}

// IsVerified 返回该值是否来自 ParseAndVerify。
func (message VerifiedMessage) IsVerified() bool { return message.verified }

// SignedMessage 返回已经验签消息的防御性深拷贝。
func (message VerifiedMessage) SignedMessage() SignedMessage {
	return cloneSignedMessage(message.signed)
}

// Channel 返回精确频道。
func (message VerifiedMessage) Channel() string { return message.signed.Channel }

// FromPublicKey 返回发布者公钥。
func (message VerifiedMessage) FromPublicKey() encoding.PublicKey {
	return message.signed.FromPublicKey
}

// MessageID 返回消息编号。
func (message VerifiedMessage) MessageID() encoding.MessageID { return message.signed.MessageID }

// IssuedAtMs 返回发布时间。
func (message VerifiedMessage) IssuedAtMs() int64 { return message.signed.IssuedAtMs }

// ExpiresAtMs 返回过期时间。
func (message VerifiedMessage) ExpiresAtMs() int64 { return message.signed.ExpiresAtMs }

// Body 返回公开 JSON body 的防御性深拷贝。
func (message VerifiedMessage) Body() strictjson.JSONValue {
	return cloneJSONValue(message.signed.Body)
}

// Signature 返回业务签名。
func (message VerifiedMessage) Signature() encoding.Signature { return message.signed.Signature }

// Digest 返回签名逻辑对象摘要。
func (message VerifiedMessage) Digest() encoding.SHA256Hash { return message.digest }

// DedupKey 返回公开消息的三元去重键。
func (message VerifiedMessage) DedupKey() DeduplicationKey {
	return DeduplicationKey{
		Channel:       message.signed.Channel,
		FromPublicKey: message.signed.FromPublicKey,
		MessageID:     message.signed.MessageID,
	}
}

// SignedDigest 返回签名逻辑对象摘要。
//
// SignedMessage 是可由调用方构造的值，因此 body 被改成无法 JCS 化的值时，
// 摘要计算错误必须返回给调用方，不能伪装成全零摘要。
func (message SignedMessage) SignedDigest() (encoding.SHA256Hash, error) {
	digest, err := signingDigest(message.UnsignedMessage)
	if err != nil {
		return encoding.SHA256Hash{}, err
	}
	return encoding.NewSHA256HashFromBytes(digest[:])
}

// CheckDigestConflict 检查相同去重键对应的内容是否冲突。
func CheckDigestConflict(existing, incoming encoding.SHA256Hash) error {
	if !existing.Equal(incoming) {
		return protocolerror.New(protocolerror.MessageIDConflict, "同一公开去重键对应不同已签名内容")
	}
	return nil
}

func messageValue(message SignedMessage) map[string]any {
	return map[string]any{
		"from_public_key": message.FromPublicKey.String(),
		"message_id":      message.MessageID.String(),
		"issued_at_ms":    message.IssuedAtMs,
		"expires_at_ms":   message.ExpiresAtMs,
		"body":            message.Body,
		"signature":       message.Signature.String(),
	}
}

func signingValue(message UnsignedMessage) map[string]any {
	return map[string]any{
		"scope":           protocol.PublicMessageScope,
		"channel":         message.Channel,
		"from_public_key": message.FromPublicKey.String(),
		"message": map[string]any{
			"message_id":    message.MessageID.String(),
			"issued_at_ms":  message.IssuedAtMs,
			"expires_at_ms": message.ExpiresAtMs,
			"body":          message.Body,
		},
	}
}

func signingDigest(message UnsignedMessage) ([32]byte, error) {
	canonical, err := canonicaljson.CanonicalizeValue(signingValue(message))
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func parseMessage(channel string, object map[string]strictjson.JSONValue) (SignedMessage, error) {
	fromText, err := requiredString(object, "from_public_key")
	if err != nil {
		return SignedMessage{}, err
	}
	from, err := encoding.ParsePublicKey(fromText)
	if err != nil {
		return SignedMessage{}, err
	}
	idText, err := requiredString(object, "message_id")
	if err != nil {
		return SignedMessage{}, err
	}
	id, err := encoding.ParseMessageID(idText)
	if err != nil {
		return SignedMessage{}, err
	}
	issued, err := requiredMillis(object, "issued_at_ms")
	if err != nil {
		return SignedMessage{}, err
	}
	expires, err := requiredMillis(object, "expires_at_ms")
	if err != nil {
		return SignedMessage{}, err
	}
	body, err := strictjson.RequireField(object, "body")
	if err != nil {
		return SignedMessage{}, err
	}
	signatureText, err := requiredString(object, "signature")
	if err != nil {
		return SignedMessage{}, err
	}
	signature, err := encoding.ParseSignature(signatureText)
	if err != nil {
		return SignedMessage{}, err
	}
	return SignedMessage{UnsignedMessage: UnsignedMessage{
		Channel:       channel,
		FromPublicKey: from,
		MessageID:     id,
		IssuedAtMs:    issued,
		ExpiresAtMs:   expires,
		Body:          body,
	}, Signature: signature}, nil
}

func validateUnsigned(message UnsignedMessage) error {
	if err := ValidateChannel(message.Channel); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(message.FromPublicKey.String()); err != nil {
		return protocolerror.New(protocolerror.InvalidPublicKey, "from_public_key 不是有效公钥")
	}
	if _, err := encoding.ParseMessageID(message.MessageID.String()); err != nil {
		return err
	}
	if err := validateTimes(message.IssuedAtMs, message.ExpiresAtMs); err != nil {
		return err
	}
	if _, err := snapshotBody(message.Body); err != nil {
		return err
	}
	return nil
}

func validateTimes(issued, expires int64) error {
	if issued < 0 || expires < 0 || issued > maxSafeInteger || expires > maxSafeInteger {
		return protocolerror.New(protocolerror.InvalidTime, "时间必须是 JSON safe integer")
	}
	if issued >= expires || expires-issued > maxLifetimeMs {
		return protocolerror.New(protocolerror.InvalidTime, "公开消息时间顺序或最长有效期不合法")
	}
	return nil
}

// snapshotBody 先通过 JCS 验证和规范化，再用 strictjson 重新解析。
// strictjson 保留 json.Number，因此这里不会走 encoding/json 的 float64 默认路径。
func snapshotBody(value strictjson.JSONValue) (strictjson.JSONValue, error) {
	canonical, err := canonicaljson.CanonicalizeValue(value)
	if err != nil {
		if protocolerror.Is(err, protocolerror.MessageTooLarge) {
			return nil, err
		}
		return nil, protocolerror.Wrap(protocolerror.InvalidBody, "body 不是 JCS 兼容 JSON 值", err)
	}
	snapshot, err := strictjson.Parse(canonical)
	if err != nil {
		return nil, protocolerror.Wrap(protocolerror.InvalidBody, "body 快照无法严格解析", err)
	}
	return snapshot, nil
}

func cloneJSONValue(value strictjson.JSONValue) strictjson.JSONValue {
	switch current := value.(type) {
	case map[string]strictjson.JSONValue:
		result := make(map[string]strictjson.JSONValue, len(current))
		for key, child := range current {
			result[key] = cloneJSONValue(child)
		}
		return result
	case []strictjson.JSONValue:
		result := make([]strictjson.JSONValue, len(current))
		for index, child := range current {
			result[index] = cloneJSONValue(child)
		}
		return result
	case stdjson.Number:
		return stdjson.Number(current.String())
	default:
		return value
	}
}

func cloneUnsignedMessage(message UnsignedMessage) UnsignedMessage {
	message.Body = cloneJSONValue(message.Body)
	return message
}

func cloneSignedMessage(message SignedMessage) SignedMessage {
	message.UnsignedMessage = cloneUnsignedMessage(message.UnsignedMessage)
	return message
}

func requiredMillis(object map[string]strictjson.JSONValue, field string) (int64, error) {
	value, err := strictjson.RequireField(object, field)
	if err != nil {
		return 0, err
	}
	number, ok := value.(stdjson.Number)
	if !ok {
		return 0, protocolerror.New(protocolerror.InvalidTime, fmt.Sprintf("%s 必须是整数", field))
	}
	parsed, err := encoding.ParseUnixMillis(number)
	if err != nil {
		return 0, protocolerror.Wrap(protocolerror.InvalidTime, fmt.Sprintf("%s 超出 safe integer", field), err)
	}
	return parsed, nil
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

func validateNow(nowMs int64) error {
	if nowMs < 0 || nowMs > maxSafeInteger {
		return protocolerror.New(protocolerror.InvalidTime, "now_ms 超出 safe integer")
	}
	return nil
}

func validatePrivateKey(privateKey encoding.PrivateKey) error {
	if _, err := encoding.NewPrivateKey(privateKey.Bytes()); err != nil {
		return err
	}
	return nil
}
