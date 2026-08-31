// Package inbox 实现 bsv8.inbox.<public_key_hex> 私密收件箱。
package inbox

import (
	"crypto/sha256"
	stdjson "encoding/json"
	"fmt"
	"io"

	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/internal/canonicaljson"
	"github.com/bsv8/ChannelProtocol/internal/cryptobox"
	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocol"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/secp256k1"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

const (
	// KDFSaltBytes 是每条信封随机 salt 的长度。
	KDFSaltBytes = 32
	// NonceBytes 是 AES-GCM nonce 的长度。
	NonceBytes = 12
	// GCMTagBytes 是 AES-GCM tag 的固定长度。
	GCMTagBytes               = 16
	privateFutureSkewMs int64 = 60 * 1000
)

// PrivateBody 是可进入私密消息的强类型子协议 body。
// 仅内置 WebRTCSignalV1Body、DeliverBody 和 AckBody 实现此接口。
type PrivateBody interface {
	// ProtocolName 返回 body 绑定的子协议名称。
	ProtocolName() string
	// JSONValue 返回不含公共消息头的 JSON 值。
	JSONValue() any
	// Validate 检查 body 的全部字段。
	Validate() error
}

// EncryptedEnvelopeV1 是不包含接收者公钥和外层签名的 V1 加密信封。
type EncryptedEnvelopeV1 struct {
	// Channel 是实际的 bsv8.inbox.<to_public_key_hex> 频道。
	Channel string
	// EnvelopeVersion 是线上加密格式版本，当前固定为 1。
	EnvelopeVersion int
	// FromPublicKey 是信封发送者长期公钥。
	FromPublicKey encoding.PublicKey
	salt          [KDFSaltBytes]byte
	nonce         [NonceBytes]byte
	ciphertext    []byte
}

// KDFSalt 返回 salt 字节副本。
func (envelope EncryptedEnvelopeV1) KDFSalt() []byte { return append([]byte(nil), envelope.salt[:]...) }

// Nonce 返回 AES-GCM nonce 字节副本。
func (envelope EncryptedEnvelopeV1) Nonce() []byte { return append([]byte(nil), envelope.nonce[:]...) }

// Ciphertext 返回 ciphertext || GCM tag 字节副本。
func (envelope EncryptedEnvelopeV1) Ciphertext() []byte {
	return append([]byte(nil), envelope.ciphertext...)
}

// AdmissionReviewedEnvelope 表示额外完成外层认证公钥一致性检查的信封。
type AdmissionReviewedEnvelope struct {
	envelope               EncryptedEnvelopeV1
	authenticatedPublicKey encoding.PublicKey
	reviewed               bool
}

// UnsignedPrivateMessage 是待签名的私密消息公共壳。
type UnsignedPrivateMessage struct {
	// Channel 是签名和 ECDH 绑定的实际目标 inbox channel。
	Channel string
	// FromPublicKey 是发送者长期公钥。
	FromPublicKey encoding.PublicKey
	// Protocol 是强类型子协议名称。
	Protocol string
	// MessageID 是私密消息去重编号。
	MessageID encoding.MessageID
	// IssuedAtMs 是发布时间 Unix 毫秒。
	IssuedAtMs int64
	// ExpiresAtMs 是过期时间 Unix 毫秒。
	ExpiresAtMs int64
	// Body 是与 Protocol 一一对应的强类型正文。
	Body PrivateBody
}

// SignedPrivateMessage 是已生成唯一业务签名、尚未加密的私密消息。
type SignedPrivateMessage struct {
	UnsignedPrivateMessage
	// Signature 是 bsv8.private-message.v1 唯一业务签名。
	Signature encoding.Signature
}

// PrivateMessage 是 SignedPrivateMessage 的语义别名。
type PrivateMessage = SignedPrivateMessage

// VerifiedPrivateMessage 是 Open 完成解密、时间和签名验证后的低层 raw body 结果。
// Body 只作为低层分层 API 使用；业务入口应使用 Dispatch 得到强类型 body。
type VerifiedPrivateMessage struct {
	channel       string
	fromPublicKey encoding.PublicKey
	toPublicKey   encoding.PublicKey
	protocolName  string
	messageID     encoding.MessageID
	issuedAtMs    int64
	expiresAtMs   int64
	bodyJSON      []byte
	signature     encoding.Signature
	digest        encoding.SHA256Hash
	verified      bool
}

// DecodedBody 是 Dispatch 返回的强类型协议正文接口，不返回 map。
type DecodedBody interface {
	// ProtocolName 返回正文绑定的 protocol。
	ProtocolName() string
	// JSONValue 返回正文 JSON 值。
	JSONValue() any
	// Validate 返回正文校验结果。
	Validate() error
}

// DecodedInboxMessage 是强类型分派结果；Body 只会是一个已注册子协议类型。
type DecodedInboxMessage struct {
	channel       string
	fromPublicKey encoding.PublicKey
	toPublicKey   encoding.PublicKey
	protocolName  string
	messageID     encoding.MessageID
	issuedAtMs    int64
	expiresAtMs   int64
	bodyJSON      []byte
	signature     encoding.Signature
	digest        encoding.SHA256Hash
	decoded       bool
}

// WebRTCSignal 返回 WebRTC 强类型 body；若当前不是 WebRTC 则 ok=false。
func (message DecodedInboxMessage) WebRTCSignal() (webrtcsignal.WebRTCSignalV1Body, bool) {
	if !message.decoded || message.protocolName != protocol.WebRTCSignalProtocol {
		return webrtcsignal.WebRTCSignalV1Body{}, false
	}
	body, err := webrtcsignal.ParseBody(message.bodyJSON)
	return body, err == nil
}

// AppMessage 返回应用消息强类型 body；若当前不是应用消息则 ok=false。
func (message DecodedInboxMessage) AppMessage() (appmessage.MessageV1Body, bool) {
	if !message.decoded || message.protocolName != protocol.AppMessageProtocol {
		return nil, false
	}
	body, err := appmessage.ParseBody(message.bodyJSON)
	return body, err == nil
}

// IsVerified 返回该值是否由 Open 成功创建。
func (message VerifiedPrivateMessage) IsVerified() bool { return message.verified }

// Channel 返回实际收件箱频道。
func (message VerifiedPrivateMessage) Channel() string { return message.channel }

// FromPublicKey 返回信封发送者公钥值。
func (message VerifiedPrivateMessage) FromPublicKey() encoding.PublicKey {
	return message.fromPublicKey
}

// ToPublicKey 返回 channel 目标公钥值。
func (message VerifiedPrivateMessage) ToPublicKey() encoding.PublicKey { return message.toPublicKey }

// Protocol 返回已验签的私密子协议名称。
func (message VerifiedPrivateMessage) Protocol() string { return message.protocolName }

// MessageID 返回私密消息编号值。
func (message VerifiedPrivateMessage) MessageID() encoding.MessageID { return message.messageID }

// IssuedAtMs 返回发布时间 Unix 毫秒。
func (message VerifiedPrivateMessage) IssuedAtMs() int64 { return message.issuedAtMs }

// ExpiresAtMs 返回过期时间 Unix 毫秒。
func (message VerifiedPrivateMessage) ExpiresAtMs() int64 { return message.expiresAtMs }

// BodyJSON 返回规范 JCS body UTF-8 副本；调用方不能改写已验签快照。
func (message VerifiedPrivateMessage) BodyJSON() []byte {
	return append([]byte(nil), message.bodyJSON...)
}

// Signature 返回业务签名值。
func (message VerifiedPrivateMessage) Signature() encoding.Signature { return message.signature }

// Digest 返回签名逻辑对象摘要值。
func (message VerifiedPrivateMessage) Digest() encoding.SHA256Hash { return message.digest }

// IsDecoded 返回该值是否由 Dispatch 成功创建。
func (message DecodedInboxMessage) IsDecoded() bool { return message.decoded }

// Channel 返回实际收件箱频道。
func (message DecodedInboxMessage) Channel() string { return message.channel }

// FromPublicKey 返回信封发送者公钥值。
func (message DecodedInboxMessage) FromPublicKey() encoding.PublicKey { return message.fromPublicKey }

// ToPublicKey 返回 channel 目标公钥值。
func (message DecodedInboxMessage) ToPublicKey() encoding.PublicKey { return message.toPublicKey }

// Protocol 返回强类型分派使用的子协议名称。
func (message DecodedInboxMessage) Protocol() string { return message.protocolName }

// MessageID 返回私密消息编号值。
func (message DecodedInboxMessage) MessageID() encoding.MessageID { return message.messageID }

// IssuedAtMs 返回发布时间 Unix 毫秒。
func (message DecodedInboxMessage) IssuedAtMs() int64 { return message.issuedAtMs }

// ExpiresAtMs 返回过期时间 Unix 毫秒。
func (message DecodedInboxMessage) ExpiresAtMs() int64 { return message.expiresAtMs }

// BodyJSON 返回规范 JCS body UTF-8 副本。
func (message DecodedInboxMessage) BodyJSON() []byte { return append([]byte(nil), message.bodyJSON...) }

// Signature 返回业务签名值。
func (message DecodedInboxMessage) Signature() encoding.Signature { return message.signature }

// Digest 返回签名逻辑对象摘要值。
func (message DecodedInboxMessage) Digest() encoding.SHA256Hash { return message.digest }

// Envelope 返回审查过的信封副本。
func (message AdmissionReviewedEnvelope) Envelope() EncryptedEnvelopeV1 {
	return cloneEnvelope(message.envelope)
}

// AuthenticatedPublicKey 返回外层认证公钥值。
func (message AdmissionReviewedEnvelope) AuthenticatedPublicKey() encoding.PublicKey {
	return message.authenticatedPublicKey
}

// IsReviewed 返回该值是否由 ReviewEnvelopeAdmission 成功创建。
func (message AdmissionReviewedEnvelope) IsReviewed() bool { return message.reviewed }

// DeduplicationKey 是私密消息的 (protocol, from_public_key, message_id) 去重键。
type DeduplicationKey struct {
	// Protocol 是子协议名称。
	Protocol string
	// FromPublicKey 是发送者公钥。
	FromPublicKey encoding.PublicKey
	// MessageID 是消息编号。
	MessageID encoding.MessageID
}

// ParseEnvelope 不解密地严格解析信封，并校验 channel 与 envelope 字段。
func ParseEnvelope(channel string, input []byte) (EncryptedEnvelopeV1, error) {
	toPublicKey, err := parseInboxChannel(channel)
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	object, err := strictjson.ParseObject(input)
	if err != nil {
		return EncryptedEnvelopeV1{}, asEnvelopeError(err)
	}
	if err := strictjson.RequireObjectKeys(object, "envelope_version", "from_public_key", "kdf_salt", "nonce", "ciphertext"); err != nil {
		return EncryptedEnvelopeV1{}, asEnvelopeError(err)
	}
	versionRaw, err := strictjson.RequireField(object, "envelope_version")
	if err != nil {
		return EncryptedEnvelopeV1{}, asEnvelopeError(err)
	}
	versionNumber, ok := versionRaw.(stdjson.Number)
	version, versionErr := encoding.ParseUnixMillis(versionNumber)
	if !ok || versionErr != nil || version != protocol.InboxEnvelopeVersion {
		return EncryptedEnvelopeV1{}, protocolerror.New(protocolerror.InvalidEnvelope, "envelope_version 必须精确为 1")
	}
	fromText, err := requiredString(object, "from_public_key")
	if err != nil {
		return EncryptedEnvelopeV1{}, asEnvelopeError(err)
	}
	from, err := encoding.ParsePublicKey(fromText)
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	saltText, err := requiredString(object, "kdf_salt")
	if err != nil {
		return EncryptedEnvelopeV1{}, asEnvelopeError(err)
	}
	salt, err := encoding.DecodeBase64URL(saltText, KDFSaltBytes, protocolerror.InvalidEnvelope, "kdf_salt")
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	nonceText, err := requiredString(object, "nonce")
	if err != nil {
		return EncryptedEnvelopeV1{}, asEnvelopeError(err)
	}
	nonce, err := encoding.DecodeBase64URL(nonceText, NonceBytes, protocolerror.InvalidEnvelope, "nonce")
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	ciphertextText, err := requiredString(object, "ciphertext")
	if err != nil {
		return EncryptedEnvelopeV1{}, asEnvelopeError(err)
	}
	ciphertext, err := encoding.DecodeRawBase64URL(ciphertextText)
	if err != nil || len(ciphertext) < GCMTagBytes {
		return EncryptedEnvelopeV1{}, protocolerror.New(protocolerror.InvalidEnvelope, "ciphertext 必须包含至少 16 字节 GCM tag")
	}
	var saltArray [KDFSaltBytes]byte
	var nonceArray [NonceBytes]byte
	copy(saltArray[:], salt)
	copy(nonceArray[:], nonce)
	_ = toPublicKey // 目标已由 parseInboxChannel 校验；保留显式绑定语义。
	return EncryptedEnvelopeV1{
		Channel:         channel,
		EnvelopeVersion: protocol.InboxEnvelopeVersion,
		FromPublicKey:   from,
		salt:            saltArray,
		nonce:           nonceArray,
		ciphertext:      append([]byte(nil), ciphertext...),
	}, nil
}

// Marshal 输出规范 JCS 加密信封 JSON。
func Marshal(envelope EncryptedEnvelopeV1) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	result, err := canonicaljson.CanonicalizeValue(envelopeValue(envelope))
	if err != nil {
		return nil, err
	}
	if len(result) > strictjson.MaxJSONBytes {
		return nil, protocolerror.New(protocolerror.MessageTooLarge, "加密信封超过 JSON 字节上限")
	}
	return result, nil
}

// MarshalPrivateMessage 输出已签名私密消息明文的规范 JCS JSON。
func MarshalPrivateMessage(message SignedPrivateMessage) ([]byte, error) {
	if err := validateUnsigned(message.UnsignedPrivateMessage); err != nil {
		return nil, err
	}
	if len(message.Signature.DER()) == 0 {
		return nil, protocolerror.New(protocolerror.InvalidSignature, "私密消息缺少 signature")
	}
	digest, err := signingDigest(message.UnsignedPrivateMessage)
	if err != nil {
		return nil, err
	}
	if err := secp256k1.Verify(message.FromPublicKey, digest, message.Signature); err != nil {
		return nil, err
	}
	result, err := canonicaljson.CanonicalizeValue(signedMessageValue(message))
	if err != nil {
		return nil, err
	}
	if len(result) > strictjson.MaxJSONBytes {
		return nil, protocolerror.New(protocolerror.MessageTooLarge, "私密明文超过 JSON 字节上限")
	}
	return result, nil
}

// SignedDigest 返回已签名私密消息的签名逻辑摘要。
func (message SignedPrivateMessage) SignedDigest() encoding.SHA256Hash {
	digest, err := signingDigest(message.UnsignedPrivateMessage)
	if err != nil {
		return encoding.SHA256Hash{}
	}
	result, _ := encoding.NewSHA256HashFromBytes(digest[:])
	return result
}

// Marshal 返回已签名私密消息明文的规范 JCS JSON。
func (message SignedPrivateMessage) Marshal() ([]byte, error) { return MarshalPrivateMessage(message) }

// MarshalJSON 是信封的便捷方法，仍返回防御性新字节。
func (envelope EncryptedEnvelopeV1) MarshalJSON() ([]byte, error) { return Marshal(envelope) }

// ReviewEnvelopeAdmission 检查外层认证公钥等于信封 from_public_key。
func ReviewEnvelopeAdmission(envelope EncryptedEnvelopeV1, authenticatedPublicKey encoding.PublicKey) (AdmissionReviewedEnvelope, error) {
	if err := validateEnvelope(envelope); err != nil {
		return AdmissionReviewedEnvelope{}, err
	}
	if err := encoding.CheckIdentity(authenticatedPublicKey, envelope.FromPublicKey, "外层认证公钥与信封 from_public_key 不一致"); err != nil {
		return AdmissionReviewedEnvelope{}, err
	}
	envelope.ciphertext = append([]byte(nil), envelope.ciphertext...)
	return AdmissionReviewedEnvelope{envelope: envelope, authenticatedPublicKey: authenticatedPublicKey, reviewed: true}, nil
}

// SignPrivateMessage 对强类型私密消息生成唯一确定性签名。
func SignPrivateMessage(message UnsignedPrivateMessage, privateKey encoding.PrivateKey) (SignedPrivateMessage, error) {
	if err := validatePrivateKey(privateKey); err != nil {
		return SignedPrivateMessage{}, err
	}
	if err := validateUnsigned(message); err != nil {
		return SignedPrivateMessage{}, err
	}
	derived, err := secp256k1.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return SignedPrivateMessage{}, protocolerror.New(protocolerror.InvalidPrivateKey, "无法从私钥推导公钥")
	}
	if err := encoding.CheckIdentity(derived, message.FromPublicKey, "私钥推导公钥与 from_public_key 不一致"); err != nil {
		return SignedPrivateMessage{}, err
	}
	digest, err := signingDigest(message)
	if err != nil {
		return SignedPrivateMessage{}, err
	}
	signature, err := secp256k1.Sign(privateKey, digest)
	if err != nil {
		return SignedPrivateMessage{}, protocolerror.New(protocolerror.InvalidSignature, "私密消息签名失败")
	}
	return SignedPrivateMessage{UnsignedPrivateMessage: message, Signature: signature}, nil
}

// SealSigned 使用新的 salt/nonce 加密同一份已签名私密消息。
// randomSource 省略时使用 crypto/rand.Reader；测试可注入固定随机源。
func SealSigned(message SignedPrivateMessage, senderPrivateKey encoding.PrivateKey, randomSource ...io.Reader) (EncryptedEnvelopeV1, error) {
	if err := validatePrivateKey(senderPrivateKey); err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	if err := validateSigned(message, senderPrivateKey); err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	recipient, err := parseInboxChannel(message.Channel)
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	salt, err := encoding.RandomBytes(firstRandom(randomSource), KDFSaltBytes)
	if err != nil {
		return EncryptedEnvelopeV1{}, protocolerror.New(protocolerror.InvalidEnvelope, "生成 kdf_salt 失败")
	}
	nonce, err := encoding.RandomBytes(firstRandom(randomSource), NonceBytes)
	if err != nil {
		return EncryptedEnvelopeV1{}, protocolerror.New(protocolerror.InvalidEnvelope, "生成 nonce 失败")
	}
	shared, err := secp256k1.ECDH(senderPrivateKey, recipient)
	if err != nil {
		return EncryptedEnvelopeV1{}, protocolerror.New(protocolerror.InvalidEnvelope, "ECDH 失败")
	}
	defer cryptobox.Clear(shared)
	info, err := canonicaljson.CanonicalizeValue(map[string]any{
		"scope":           "bsv8.inbox.envelope.v1",
		"channel":         message.Channel,
		"from_public_key": message.FromPublicKey.String(),
	})
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	aad, err := canonicaljson.CanonicalizeValue(map[string]any{
		"channel":          message.Channel,
		"envelope_version": protocol.InboxEnvelopeVersion,
		"from_public_key":  message.FromPublicKey.String(),
		"kdf_salt":         encoding.EncodeBase64URL(salt),
		"nonce":            encoding.EncodeBase64URL(nonce),
	})
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	key, err := cryptobox.DeriveKey(shared, salt, info)
	if err != nil {
		return EncryptedEnvelopeV1{}, protocolerror.New(protocolerror.InvalidEnvelope, "HKDF 派生失败")
	}
	defer cryptobox.Clear(key)
	plaintext, err := canonicaljson.CanonicalizeValue(signedMessageValue(message))
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	defer cryptobox.Clear(plaintext)
	ciphertext, err := cryptobox.Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	var saltArray [KDFSaltBytes]byte
	var nonceArray [NonceBytes]byte
	copy(saltArray[:], salt)
	copy(nonceArray[:], nonce)
	envelope := EncryptedEnvelopeV1{
		Channel:         message.Channel,
		EnvelopeVersion: protocol.InboxEnvelopeVersion,
		FromPublicKey:   message.FromPublicKey,
		salt:            saltArray,
		nonce:           nonceArray,
		ciphertext:      append([]byte(nil), ciphertext...),
	}
	if _, err := Marshal(envelope); err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	return envelope, nil
}

// SignAndSeal 是首次发送的签名加密便利组合。
func SignAndSeal(message UnsignedPrivateMessage, privateKey encoding.PrivateKey, randomSource ...io.Reader) (EncryptedEnvelopeV1, error) {
	signed, err := SignPrivateMessage(message, privateKey)
	if err != nil {
		return EncryptedEnvelopeV1{}, err
	}
	return SealSigned(signed, privateKey, randomSource...)
}

// Open 解密、严格解析、检查时间并验证私密消息唯一签名。
// 解密后的格式、AES tag、明文 JSON 和私密验签失败统一返回 OPEN_FAILED。
func Open(channel string, envelopeJSON []byte, recipientPrivateKey encoding.PrivateKey, nowMs int64) (VerifiedPrivateMessage, error) {
	if err := validateNow(nowMs); err != nil {
		return VerifiedPrivateMessage{}, err
	}
	envelope, err := ParseEnvelope(channel, envelopeJSON)
	if err != nil {
		return VerifiedPrivateMessage{}, err
	}
	if err := validatePrivateKey(recipientPrivateKey); err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	recipient, err := parseInboxChannel(channel)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	derived, err := secp256k1.PublicKeyFromPrivate(recipientPrivateKey)
	if err != nil || !derived.Equal(recipient) {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	shared, err := secp256k1.ECDH(recipientPrivateKey, envelope.FromPublicKey)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	defer cryptobox.Clear(shared)
	info, err := canonicaljson.CanonicalizeValue(map[string]any{
		"scope":           "bsv8.inbox.envelope.v1",
		"channel":         channel,
		"from_public_key": envelope.FromPublicKey.String(),
	})
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	aad, err := canonicaljson.CanonicalizeValue(map[string]any{
		"channel":          channel,
		"envelope_version": protocol.InboxEnvelopeVersion,
		"from_public_key":  envelope.FromPublicKey.String(),
		"kdf_salt":         encoding.EncodeBase64URL(envelope.salt[:]),
		"nonce":            encoding.EncodeBase64URL(envelope.nonce[:]),
	})
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	key, err := cryptobox.DeriveKey(shared, envelope.salt[:], info)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	defer cryptobox.Clear(key)
	plaintext, err := cryptobox.Decrypt(key, envelope.nonce[:], envelope.ciphertext, aad)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	defer cryptobox.Clear(plaintext)
	object, err := strictjson.ParseObject(plaintext)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	parsed, err := parsePrivateMessage(object)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	if err := validatePrivateTimes(parsed.IssuedAtMs, parsed.ExpiresAtMs, nowMs, parsed.Protocol, true); err != nil {
		return VerifiedPrivateMessage{}, mapOpenError(err)
	}
	digest, err := signingDigestRaw(parsed, channel, envelope.FromPublicKey)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	if err := secp256k1.Verify(envelope.FromPublicKey, digest, parsed.Signature); err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	bodyJSON, err := canonicaljson.CanonicalizeValue(parsed.Body)
	if err != nil {
		return VerifiedPrivateMessage{}, protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
	}
	digestHash, _ := encoding.NewSHA256HashFromBytes(digest[:])
	return VerifiedPrivateMessage{
		channel:       channel,
		fromPublicKey: envelope.FromPublicKey,
		toPublicKey:   recipient,
		protocolName:  parsed.Protocol,
		messageID:     parsed.MessageID,
		issuedAtMs:    parsed.IssuedAtMs,
		expiresAtMs:   parsed.ExpiresAtMs,
		bodyJSON:      append([]byte(nil), bodyJSON...),
		signature:     parsed.Signature,
		digest:        digestHash,
		verified:      true,
	}, nil
}

// Dispatch 将 Open 的低层结果分派为 WebRTC 或应用消息强类型 body。
func Dispatch(message VerifiedPrivateMessage) (DecodedInboxMessage, error) {
	if !message.verified {
		return DecodedInboxMessage{}, protocolerror.New(protocolerror.InvalidSignature, "消息不是 SDK 生成的已验证结果")
	}
	rawBody, err := strictjson.Parse(message.bodyJSON)
	if err != nil {
		return DecodedInboxMessage{}, protocolerror.New(protocolerror.InvalidBody, "已验证消息 body 快照损坏")
	}
	var body DecodedBody
	switch message.protocolName {
	case protocol.WebRTCSignalProtocol:
		parsed, err := webrtcsignal.ParseBodyValue(rawBody)
		if err != nil {
			return DecodedInboxMessage{}, err
		}
		body = parsed
	case protocol.AppMessageProtocol:
		parsed, err := appmessage.ParseBodyValue(rawBody)
		if err != nil {
			return DecodedInboxMessage{}, err
		}
		body = parsed
	default:
		return DecodedInboxMessage{}, protocolerror.New(protocolerror.UnsupportedProtocol, "私密消息 protocol 未注册")
	}
	bodyJSON, err := canonicaljson.CanonicalizeValue(body.JSONValue())
	if err != nil {
		return DecodedInboxMessage{}, protocolerror.New(protocolerror.InvalidBody, "分派 body 无法规范化")
	}
	return DecodedInboxMessage{
		channel:       message.channel,
		fromPublicKey: message.fromPublicKey,
		toPublicKey:   message.toPublicKey,
		protocolName:  message.protocolName,
		messageID:     message.messageID,
		issuedAtMs:    message.issuedAtMs,
		expiresAtMs:   message.expiresAtMs,
		bodyJSON:      append([]byte(nil), bodyJSON...),
		signature:     message.signature,
		digest:        message.digest,
		decoded:       true,
	}, nil
}

// OpenAndDispatch 是严格解密并直接返回强类型分派结果的高层入口。
func OpenAndDispatch(channel string, envelopeJSON []byte, recipientPrivateKey encoding.PrivateKey, nowMs int64) (DecodedInboxMessage, error) {
	message, err := Open(channel, envelopeJSON, recipientPrivateKey, nowMs)
	if err != nil {
		return DecodedInboxMessage{}, err
	}
	return Dispatch(message)
}

// DedupKey 返回私密消息去重键。
func (message VerifiedPrivateMessage) DedupKey() DeduplicationKey {
	return DeduplicationKey{Protocol: message.protocolName, FromPublicKey: message.fromPublicKey, MessageID: message.messageID}
}

// SignedDigest 返回已验签私密消息的签名逻辑摘要。
func (message VerifiedPrivateMessage) SignedDigest() encoding.SHA256Hash { return message.digest }

// CheckDigestConflict 检查相同去重键的内容是否冲突。
func CheckDigestConflict(existing, incoming encoding.SHA256Hash) error {
	if !existing.Equal(incoming) {
		return protocolerror.New(protocolerror.MessageIDConflict, "同一私密去重键对应不同已签名内容")
	}
	return nil
}

// ReviewOfferForHashRequest 统一审查 WebRTC offer 与已验证 Hash 请求的跨协议关系。
// 调用方仍负责 session_id 是否已使用以及会话状态的保存。
func ReviewOfferForHashRequest(hashRequest hashrequest.VerifiedMessage, offer VerifiedPrivateMessage, nowMs int64) (webrtcsignal.SessionKey, error) {
	if !hashRequest.IsVerified() || !offer.IsVerified() {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidSignature, "Hash 请求或 offer 不是 SDK 生成的已验证结果")
	}
	if nowMs < 0 || nowMs > 9_007_199_254_740_991 {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidTime, "now_ms 超出 safe integer")
	}
	if nowMs >= hashRequest.ExpiresAtMs() {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.MessageExpired, "引用的 Hash 请求已过期")
	}
	hashBody := hashRequest.Body()
	hasWebRTCLocator := false
	for _, locator := range hashBody.Locators {
		if locator.Kind == hashrequest.LocatorWebRTCSDP {
			hasWebRTCLocator = true
			break
		}
	}
	if !hasWebRTCLocator {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidRelation, "Hash 请求未声明 webrtc-sdp locator")
	}
	if offer.Protocol() != protocol.WebRTCSignalProtocol {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidRelation, "offer protocol 不是 WebRTC 子协议")
	}
	offerBody, err := webrtcsignal.ParseBody(offer.BodyJSON())
	if err != nil {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidRelation, "offer body 不是合法 WebRTC body")
	}
	if offerBody.Signal.Type != webrtcsignal.SignalOffer {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidRelation, "引用的私密消息不是 WebRTC offer")
	}
	if !offerBody.RequestMessageID.Equal(hashRequest.MessageID()) {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidRelation, "offer 未关联该 Hash 请求 message_id")
	}
	if !offer.ToPublicKey().Equal(hashRequest.FromPublicKey()) {
		return webrtcsignal.SessionKey{}, protocolerror.New(protocolerror.InvalidRelation, "offer 接收者不是 Hash 请求者")
	}
	return webrtcsignal.NewSessionKey(hashRequest.MessageID(), offer.FromPublicKey(), offerBody.SessionID)
}

func parseInboxChannel(channel string) (encoding.PublicKey, error) {
	if len(channel) <= len(protocol.InboxChannelPrefix) || channel[:len(protocol.InboxChannelPrefix)] != protocol.InboxChannelPrefix {
		return encoding.PublicKey{}, protocolerror.New(protocolerror.InvalidChannel, "inbox channel 前缀不合法")
	}
	key, err := encoding.ParsePublicKey(channel[len(protocol.InboxChannelPrefix):])
	if err != nil {
		return encoding.PublicKey{}, protocolerror.New(protocolerror.InvalidChannel, "inbox channel 目标公钥不合法")
	}
	return key, nil
}

func envelopeValue(envelope EncryptedEnvelopeV1) map[string]any {
	return map[string]any{
		"envelope_version": envelope.EnvelopeVersion,
		"from_public_key":  envelope.FromPublicKey.String(),
		"kdf_salt":         encoding.EncodeBase64URL(envelope.salt[:]),
		"nonce":            encoding.EncodeBase64URL(envelope.nonce[:]),
		"ciphertext":       encoding.EncodeBase64URL(envelope.ciphertext),
	}
}

func cloneEnvelope(envelope EncryptedEnvelopeV1) EncryptedEnvelopeV1 {
	envelope.ciphertext = append([]byte(nil), envelope.ciphertext...)
	return envelope
}

func validateEnvelope(envelope EncryptedEnvelopeV1) error {
	if _, err := parseInboxChannel(envelope.Channel); err != nil {
		return err
	}
	if envelope.EnvelopeVersion != protocol.InboxEnvelopeVersion {
		return protocolerror.New(protocolerror.InvalidEnvelope, "envelope_version 不支持")
	}
	if _, err := encoding.ParsePublicKey(envelope.FromPublicKey.String()); err != nil {
		return err
	}
	if len(envelope.ciphertext) < GCMTagBytes {
		return protocolerror.New(protocolerror.InvalidEnvelope, "ciphertext 缺少 GCM tag")
	}
	return nil
}

func validateUnsigned(message UnsignedPrivateMessage) error {
	if _, err := parseInboxChannel(message.Channel); err != nil {
		return err
	}
	if _, err := encoding.ParsePublicKey(message.FromPublicKey.String()); err != nil {
		return err
	}
	if _, err := encoding.ParseMessageID(message.MessageID.String()); err != nil {
		return err
	}
	if message.Protocol != protocol.WebRTCSignalProtocol && message.Protocol != protocol.AppMessageProtocol {
		return protocolerror.New(protocolerror.UnsupportedProtocol, "私密消息 protocol 未注册")
	}
	if message.Body == nil {
		return protocolerror.New(protocolerror.InvalidBody, "私密消息缺少强类型 body")
	}
	switch body := message.Body.(type) {
	case webrtcsignal.WebRTCSignalV1Body:
		if message.Protocol != protocol.WebRTCSignalProtocol {
			return protocolerror.New(protocolerror.InvalidBody, "protocol 与 WebRTC body 类型不一致")
		}
		if err := body.Validate(); err != nil {
			return err
		}
	case *webrtcsignal.WebRTCSignalV1Body:
		if body == nil || message.Protocol != protocol.WebRTCSignalProtocol {
			return protocolerror.New(protocolerror.InvalidBody, "protocol 与 WebRTC body 类型不一致")
		}
		if err := body.Validate(); err != nil {
			return err
		}
	case appmessage.DeliverBody:
		if message.Protocol != protocol.AppMessageProtocol {
			return protocolerror.New(protocolerror.InvalidBody, "protocol 与应用 body 类型不一致")
		}
		if err := body.Validate(); err != nil {
			return err
		}
	case *appmessage.DeliverBody:
		if body == nil || message.Protocol != protocol.AppMessageProtocol {
			return protocolerror.New(protocolerror.InvalidBody, "protocol 与应用 body 类型不一致")
		}
		if err := body.Validate(); err != nil {
			return err
		}
	case appmessage.AckBody:
		if message.Protocol != protocol.AppMessageProtocol {
			return protocolerror.New(protocolerror.InvalidBody, "protocol 与应用 body 类型不一致")
		}
		if err := body.Validate(); err != nil {
			return err
		}
	case *appmessage.AckBody:
		if body == nil || message.Protocol != protocol.AppMessageProtocol {
			return protocolerror.New(protocolerror.InvalidBody, "protocol 与应用 body 类型不一致")
		}
		if err := body.Validate(); err != nil {
			return err
		}
	default:
		return protocolerror.New(protocolerror.InvalidBody, "私密消息 body 不是已注册强类型")
	}
	if err := validatePrivateTimes(message.IssuedAtMs, message.ExpiresAtMs, 0, message.Protocol, false); err != nil {
		return err
	}
	return nil
}

func validateSigned(message SignedPrivateMessage, privateKey encoding.PrivateKey) error {
	if err := validateUnsigned(message.UnsignedPrivateMessage); err != nil {
		return err
	}
	if len(message.Signature.DER()) == 0 {
		return protocolerror.New(protocolerror.InvalidSignature, "私密消息缺少 signature")
	}
	derived, err := secp256k1.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return protocolerror.New(protocolerror.IdentityMismatch, "Seal 使用的私钥与已签名发送者不一致")
	}
	if err := encoding.CheckIdentity(derived, message.FromPublicKey, "Seal 使用的私钥与已签名发送者不一致"); err != nil {
		return err
	}
	digest, err := signingDigest(message.UnsignedPrivateMessage)
	if err != nil {
		return err
	}
	if err := secp256k1.Verify(message.FromPublicKey, digest, message.Signature); err != nil {
		return err
	}
	return nil
}

func signedMessageValue(message SignedPrivateMessage) map[string]any {
	return map[string]any{
		"protocol":      message.Protocol,
		"message_id":    message.MessageID.String(),
		"issued_at_ms":  message.IssuedAtMs,
		"expires_at_ms": message.ExpiresAtMs,
		"body":          message.Body.JSONValue(),
		"signature":     message.Signature.String(),
	}
}

func signingValue(message UnsignedPrivateMessage) map[string]any {
	return map[string]any{
		"scope":           protocol.PrivateMessageScope,
		"channel":         message.Channel,
		"from_public_key": message.FromPublicKey.String(),
		"message": map[string]any{
			"protocol":      message.Protocol,
			"message_id":    message.MessageID.String(),
			"issued_at_ms":  message.IssuedAtMs,
			"expires_at_ms": message.ExpiresAtMs,
			"body":          message.Body.JSONValue(),
		},
	}
}

func signingDigest(message UnsignedPrivateMessage) ([32]byte, error) {
	canonical, err := canonicaljson.CanonicalizeValue(signingValue(message))
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

type parsedPrivateMessage struct {
	Protocol    string
	MessageID   encoding.MessageID
	IssuedAtMs  int64
	ExpiresAtMs int64
	Body        strictjson.JSONValue
	Signature   encoding.Signature
}

func parsePrivateMessage(object map[string]strictjson.JSONValue) (parsedPrivateMessage, error) {
	if err := strictjson.RequireObjectKeys(object, "protocol", "message_id", "issued_at_ms", "expires_at_ms", "body", "signature"); err != nil {
		return parsedPrivateMessage{}, err
	}
	protocolText, err := requiredString(object, "protocol")
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	messageText, err := requiredString(object, "message_id")
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	messageID, err := encoding.ParseMessageID(messageText)
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	issued, err := requiredMillis(object, "issued_at_ms")
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	expires, err := requiredMillis(object, "expires_at_ms")
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	body, err := strictjson.RequireField(object, "body")
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	signatureText, err := requiredString(object, "signature")
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	signature, err := encoding.ParseSignature(signatureText)
	if err != nil {
		return parsedPrivateMessage{}, err
	}
	return parsedPrivateMessage{Protocol: protocolText, MessageID: messageID, IssuedAtMs: issued, ExpiresAtMs: expires, Body: body, Signature: signature}, nil
}

func signingDigestRaw(message parsedPrivateMessage, channel string, from encoding.PublicKey) ([32]byte, error) {
	value := map[string]any{
		"scope":           protocol.PrivateMessageScope,
		"channel":         channel,
		"from_public_key": from.String(),
		"message": map[string]any{
			"protocol":      message.Protocol,
			"message_id":    message.MessageID.String(),
			"issued_at_ms":  message.IssuedAtMs,
			"expires_at_ms": message.ExpiresAtMs,
			"body":          message.Body,
		},
	}
	canonical, err := canonicaljson.CanonicalizeValue(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func validatePrivateTimes(issued, expires, now int64, protocolName string, checkCurrent bool) error {
	if issued < 0 || expires < 0 || issued > 9_007_199_254_740_991 || expires > 9_007_199_254_740_991 {
		return protocolerror.New(protocolerror.InvalidTime, "私密消息时间超出 safe integer")
	}
	if issued >= expires {
		return protocolerror.New(protocolerror.InvalidTime, "私密消息时间顺序不合法")
	}
	maxLifetime := int64(24 * 60 * 60 * 1000)
	if protocolName == protocol.WebRTCSignalProtocol {
		maxLifetime = 2 * 60 * 1000
	}
	if expires-issued > maxLifetime {
		return protocolerror.New(protocolerror.InvalidTime, "私密消息有效期超过子协议上限")
	}
	if checkCurrent && issued > now && issued-now > privateFutureSkewMs {
		return protocolerror.New(protocolerror.InvalidTime, "私密消息发布时间超出本地时钟容差")
	}
	if checkCurrent && now >= expires {
		return protocolerror.New(protocolerror.MessageExpired, "私密消息已过期")
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
		return "", protocolerror.New(protocolerror.InvalidEnvelope, fmt.Sprintf("%s 必须是 string", field))
	}
	return result, nil
}

func validatePrivateKey(privateKey encoding.PrivateKey) error {
	if _, err := encoding.NewPrivateKey(privateKey.Bytes()); err != nil {
		return err
	}
	return nil
}

func validateNow(nowMs int64) error {
	if nowMs < 0 || nowMs > 9_007_199_254_740_991 {
		return protocolerror.New(protocolerror.InvalidTime, "now_ms 超出 safe integer")
	}
	return nil
}

func firstRandom(source []io.Reader) io.Reader {
	if len(source) == 0 {
		return nil
	}
	return source[0]
}

func asEnvelopeError(err error) error {
	if protocolerror.Is(err, protocolerror.InvalidJSON) {
		return err
	}
	if protocolerror.Is(err, protocolerror.UnknownField) {
		return err
	}
	if protocolerror.Is(err, protocolerror.MessageTooLarge) {
		return err
	}
	return protocolerror.New(protocolerror.InvalidEnvelope, "加密信封字段不合法")
}

func mapOpenError(err error) error {
	if protocolerror.Is(err, protocolerror.MessageExpired) || protocolerror.Is(err, protocolerror.InvalidTime) {
		return err
	}
	return protocolerror.New(protocolerror.OpenFailed, "私密信封无法打开")
}
