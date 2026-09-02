// Package hashrequest 实现 bsv8.hash.request.v1 公开频道。
package hashrequest

import (
	"crypto/sha256"
	stdjson "encoding/json"
	"fmt"

	"github.com/bsv8/ChannelProtocol/internal/canonicaljson"
	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocol"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/secp256k1"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
	multiaddr "github.com/multiformats/go-multiaddr"
)

const (
	maxLifetimeMs   int64 = 10 * 60 * 1000
	maxFutureSkewMs int64 = 60 * 1000
)

// LocatorKind 是公开 Hash 请求的连接位置类型。
type LocatorKind string

const (
	// LocatorMultiaddr 表示直接使用标准 multiaddr 建立后续连接。
	LocatorMultiaddr LocatorKind = "multiaddr"
	// LocatorWebRTCSDP 表示通过私密收件箱交换 WebRTC SDP。
	LocatorWebRTCSDP LocatorKind = "webrtc-sdp"
)

// Locator 是按优先顺序排列的连接位置。
// multiaddr 类型必须填写 Address；webrtc-sdp 类型必须保持 Address 为空。
type Locator struct {
	// Kind 是 locator 分支类型。
	Kind LocatorKind
	// Address 是标准 multiaddr；webrtc-sdp 分支不使用该字段。
	Address string
}

// HashRequestBody 是公开 Hash 请求正文。
type HashRequestBody struct {
	// Hash 是文件字节的 SHA-256 Hash。
	Hash encoding.SHA256Hash
	// Locators 是按建议尝试顺序排列的连接位置，至少一个。
	Locators []Locator
}

// UnsignedMessage 是待签名的公开 Hash 请求。
type UnsignedMessage struct {
	// FromPublicKey 是请求者长期压缩公钥。
	FromPublicKey encoding.PublicKey
	// MessageID 是公开请求去重编号。
	MessageID encoding.MessageID
	// IssuedAtMs 是发布时间 Unix 毫秒。
	IssuedAtMs int64
	// ExpiresAtMs 是过期时间 Unix 毫秒。
	ExpiresAtMs int64
	// Body 是 Hash 与 locator 正文。
	Body HashRequestBody
}

// SignedMessage 是已经包含唯一业务签名的公开 Hash 请求。
type SignedMessage struct {
	UnsignedMessage
	// Signature 是 bsv8.public-message.v1 唯一业务签名。
	Signature encoding.Signature
}

// VerifiedMessage 表示已完成结构、时间和签名验证的公开消息。
//
// 内部快照字段刻意不导出。Go 没有语言级 const struct，因此这里通过私有字段
// 加复制访问器保证“已验证”结果不会被调用方通过 slice/map/嵌套值改写。
type VerifiedMessage struct {
	signed   SignedMessage
	digest   encoding.SHA256Hash
	verified bool
}

// DeduplicationKey 是公开消息的 (from_public_key, message_id) 去重键。
type DeduplicationKey struct {
	// FromPublicKey 是消息发送者公钥。
	FromPublicKey encoding.PublicKey
	// MessageID 是消息编号。
	MessageID encoding.MessageID
}

// NewMultiaddrLocator 构造并校验标准 multiaddr locator。
func NewMultiaddrLocator(address string) (Locator, error) {
	locator := Locator{Kind: LocatorMultiaddr, Address: address}
	if err := validateLocator(locator); err != nil {
		return Locator{}, err
	}
	return locator, nil
}

// NewWebRTCSDPLocator 构造无额外字段的 WebRTC locator。
func NewWebRTCSDPLocator() Locator { return Locator{Kind: LocatorWebRTCSDP} }

// IsVerified 返回该值是否由 ParseAndVerify 成功创建。
func (message VerifiedMessage) IsVerified() bool { return message.verified }

// SignedMessage 返回已验签消息的深拷贝；调用方修改返回值不会影响验证结果。
func (message VerifiedMessage) SignedMessage() SignedMessage {
	return cloneSignedMessage(message.signed)
}

// FromPublicKey 返回发送者公钥值。
func (message VerifiedMessage) FromPublicKey() encoding.PublicKey {
	return message.signed.FromPublicKey
}

// MessageID 返回消息编号值。
func (message VerifiedMessage) MessageID() encoding.MessageID { return message.signed.MessageID }

// IssuedAtMs 返回发布时间 Unix 毫秒。
func (message VerifiedMessage) IssuedAtMs() int64 { return message.signed.IssuedAtMs }

// ExpiresAtMs 返回过期时间 Unix 毫秒。
func (message VerifiedMessage) ExpiresAtMs() int64 { return message.signed.ExpiresAtMs }

// Body 返回 Hash 请求正文的深拷贝，包含 locators slice 的副本。
func (message VerifiedMessage) Body() HashRequestBody {
	return cloneHashRequestBody(message.signed.Body)
}

// Signature 返回签名值；Signature 内部字节通过 DER 方法复制。
func (message VerifiedMessage) Signature() encoding.Signature { return message.signed.Signature }

// Digest 返回验签逻辑对象摘要值。
func (message VerifiedMessage) Digest() encoding.SHA256Hash { return message.digest }

// Sign 校验待签名消息，并使用发送者长期私钥生成确定性 low-S 签名。
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
	digest, err := signingDigest(message)
	if err != nil {
		return SignedMessage{}, err
	}
	signature, err := secp256k1.Sign(privateKey, digest)
	if err != nil {
		return SignedMessage{}, protocolerror.New(protocolerror.InvalidSignature, "公开消息签名失败")
	}
	return SignedMessage{UnsignedMessage: message, Signature: signature}, nil
}

// Marshal 输出不含 channel 字段的规范 JCS 公开消息 JSON。
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

// ParseAndVerify 严格解析公开消息，允许输入字段顺序不同，再按 JCS 验签。
func ParseAndVerify(channel string, input []byte, nowMs int64) (VerifiedMessage, error) {
	if channel != protocol.HashRequestChannel {
		return VerifiedMessage{}, protocolerror.New(protocolerror.InvalidChannel, "公开 Hash 请求 channel 不合法")
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
	message, err := parseMessage(object)
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
	hash, err := encoding.NewSHA256HashFromBytes(digest[:])
	if err != nil {
		return VerifiedMessage{}, err
	}
	return VerifiedMessage{signed: cloneSignedMessage(message), digest: hash, verified: true}, nil
}

// DedupKey 返回公开消息去重键。
func (message VerifiedMessage) DedupKey() DeduplicationKey {
	return DeduplicationKey{FromPublicKey: message.signed.FromPublicKey, MessageID: message.signed.MessageID}
}

// SignedDigest 返回签名逻辑对象的稳定摘要；该值不含输入 JSON 的字段顺序。
func (message SignedMessage) SignedDigest() encoding.SHA256Hash {
	digest, err := signingDigest(message.UnsignedMessage)
	if err != nil {
		return encoding.SHA256Hash{}
	}
	result, _ := encoding.NewSHA256HashFromBytes(digest[:])
	return result
}

// CheckDigestConflict 在相同去重键对应不同摘要时返回 MESSAGE_ID_CONFLICT。
func CheckDigestConflict(existing, incoming encoding.SHA256Hash) error {
	if !existing.Equal(incoming) {
		return protocolerror.New(protocolerror.MessageIDConflict, "同一公开去重键对应不同已签名内容")
	}
	return nil
}

func (message VerifiedMessage) ensureVerified() error {
	if !message.verified {
		return protocolerror.New(protocolerror.InvalidSignature, "消息不是 SDK 生成的已验证结果")
	}
	return nil
}

func cloneHashRequestBody(body HashRequestBody) HashRequestBody {
	return HashRequestBody{
		Hash:     body.Hash,
		Locators: append([]Locator(nil), body.Locators...),
	}
}

func cloneUnsignedMessage(message UnsignedMessage) UnsignedMessage {
	message.Body = cloneHashRequestBody(message.Body)
	return message
}

func cloneSignedMessage(message SignedMessage) SignedMessage {
	message.UnsignedMessage = cloneUnsignedMessage(message.UnsignedMessage)
	return message
}

func messageValue(message SignedMessage) map[string]any {
	return map[string]any{
		"from_public_key": message.FromPublicKey.String(),
		"message_id":      message.MessageID.String(),
		"issued_at_ms":    message.IssuedAtMs,
		"expires_at_ms":   message.ExpiresAtMs,
		"body":            bodyValue(message.Body),
		"signature":       message.Signature.String(),
	}
}

func signingValue(message UnsignedMessage) map[string]any {
	return map[string]any{
		"scope":           protocol.PublicMessageScope,
		"channel":         protocol.HashRequestChannel,
		"from_public_key": message.FromPublicKey.String(),
		"message": map[string]any{
			"message_id":    message.MessageID.String(),
			"issued_at_ms":  message.IssuedAtMs,
			"expires_at_ms": message.ExpiresAtMs,
			"body":          bodyValue(message.Body),
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

func bodyValue(body HashRequestBody) map[string]any {
	locators := make([]any, 0, len(body.Locators))
	for _, locator := range body.Locators {
		value := map[string]any{"kind": string(locator.Kind)}
		if locator.Kind == LocatorMultiaddr {
			value["address"] = locator.Address
		}
		locators = append(locators, value)
	}
	return map[string]any{"hash": body.Hash.String(), "locators": locators}
}

func parseMessage(object map[string]strictjson.JSONValue) (SignedMessage, error) {
	from, err := requiredString(object, "from_public_key")
	if err != nil {
		return SignedMessage{}, err
	}
	fromKey, err := encoding.ParsePublicKey(from)
	if err != nil {
		return SignedMessage{}, err
	}
	messageIDText, err := requiredString(object, "message_id")
	if err != nil {
		return SignedMessage{}, err
	}
	messageID, err := encoding.ParseMessageID(messageIDText)
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
	bodyValueRaw, err := strictjson.RequireField(object, "body")
	if err != nil {
		return SignedMessage{}, err
	}
	bodyObject, ok := bodyValueRaw.(map[string]strictjson.JSONValue)
	if !ok {
		return SignedMessage{}, protocolerror.New(protocolerror.InvalidBody, "Hash 请求 body 必须是 object")
	}
	body, err := parseBody(bodyObject)
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
		FromPublicKey: fromKey,
		MessageID:     messageID,
		IssuedAtMs:    issued,
		ExpiresAtMs:   expires,
		Body:          body,
	}, Signature: signature}, nil
}

func parseBody(object map[string]strictjson.JSONValue) (HashRequestBody, error) {
	if err := strictjson.RequireObjectKeys(object, "hash", "locators"); err != nil {
		return HashRequestBody{}, err
	}
	hashText, err := requiredString(object, "hash")
	if err != nil {
		return HashRequestBody{}, err
	}
	hash, err := encoding.ParseSHA256Hash(hashText)
	if err != nil {
		return HashRequestBody{}, err
	}
	locatorsRaw, err := strictjson.RequireField(object, "locators")
	if err != nil {
		return HashRequestBody{}, err
	}
	locatorsArray, ok := locatorsRaw.([]strictjson.JSONValue)
	if !ok || len(locatorsArray) == 0 {
		return HashRequestBody{}, protocolerror.New(protocolerror.InvalidBody, "locators 必须是至少一个元素的数组")
	}
	locators := make([]Locator, 0, len(locatorsArray))
	for _, raw := range locatorsArray {
		locatorObject, ok := raw.(map[string]strictjson.JSONValue)
		if !ok {
			return HashRequestBody{}, protocolerror.New(protocolerror.InvalidBody, "locator 必须是 object")
		}
		kindText, err := requiredString(locatorObject, "kind")
		if err != nil {
			return HashRequestBody{}, err
		}
		locator := Locator{Kind: LocatorKind(kindText)}
		switch locator.Kind {
		case LocatorMultiaddr:
			if err := strictjson.RequireObjectKeys(locatorObject, "kind", "address"); err != nil {
				return HashRequestBody{}, err
			}
			locator.Address, err = requiredString(locatorObject, "address")
			if err != nil {
				return HashRequestBody{}, err
			}
		case LocatorWebRTCSDP:
			if err := strictjson.RequireObjectKeys(locatorObject, "kind"); err != nil {
				return HashRequestBody{}, err
			}
		default:
			return HashRequestBody{}, protocolerror.New(protocolerror.InvalidBody, "locator.kind 不支持")
		}
		if err := validateLocator(locator); err != nil {
			return HashRequestBody{}, err
		}
		locators = append(locators, locator)
	}
	return HashRequestBody{Hash: hash, Locators: locators}, nil
}

func validateUnsigned(message UnsignedMessage) error {
	if key, err := encoding.ParsePublicKey(message.FromPublicKey.String()); err != nil || !key.Equal(message.FromPublicKey) {
		return protocolerror.New(protocolerror.InvalidPublicKey, "from_public_key 不是有效公钥")
	}
	if _, err := encoding.ParseMessageID(message.MessageID.String()); err != nil {
		return err
	}
	if message.IssuedAtMs < 0 || message.ExpiresAtMs < 0 || message.IssuedAtMs > 9_007_199_254_740_991 || message.ExpiresAtMs > 9_007_199_254_740_991 {
		return protocolerror.New(protocolerror.InvalidTime, "时间必须是 JSON safe integer")
	}
	if message.IssuedAtMs >= message.ExpiresAtMs || message.ExpiresAtMs-message.IssuedAtMs > maxLifetimeMs {
		return protocolerror.New(protocolerror.InvalidTime, "Hash 请求时间顺序或最长有效期不合法")
	}
	if _, err := encoding.NewSHA256HashFromBytes(message.Body.Hash.Bytes()); err != nil {
		return err
	}
	if len(message.Body.Locators) == 0 {
		return protocolerror.New(protocolerror.InvalidBody, "至少需要一个 locator")
	}
	for _, locator := range message.Body.Locators {
		if err := validateLocator(locator); err != nil {
			return err
		}
	}
	return nil
}

func validateLocator(locator Locator) error {
	switch locator.Kind {
	case LocatorMultiaddr:
		if locator.Address == "" {
			return protocolerror.New(protocolerror.InvalidBody, "multiaddr locator 缺少 address")
		}
		if _, err := multiaddr.NewMultiaddr(locator.Address); err != nil {
			return protocolerror.New(protocolerror.InvalidBody, "multiaddr address 语法不合法")
		}
	case LocatorWebRTCSDP:
		if locator.Address != "" {
			return protocolerror.New(protocolerror.InvalidBody, "webrtc-sdp locator 不允许 address")
		}
	default:
		return protocolerror.New(protocolerror.InvalidBody, "不支持的 locator.kind")
	}
	return nil
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
	if nowMs < 0 || nowMs > 9_007_199_254_740_991 {
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
