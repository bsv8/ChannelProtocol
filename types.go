package channels

import (
	stdjson "encoding/json"
	"io"

	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocol"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/secp256k1"
)

// PublicKey 是经过 secp256k1 曲线点校验的 33 字节压缩公钥。
type PublicKey = encoding.PublicKey

// PrivateKey 是经过范围校验的 32 字节长期私钥；不会自动 JSON 序列化。
type PrivateKey = encoding.PrivateKey

// MessageID 是 32 字节无填充 base64url 消息编号。
type MessageID = encoding.MessageID

// SessionID 是 32 字节无填充 base64url WebRTC 会话编号。
type SessionID = encoding.SessionID

// SHA256Hash 是 32 字节文件内容 SHA-256 Hash。
type SHA256Hash = encoding.SHA256Hash

// Signature 是 strict DER、low-S 业务签名。
type Signature = encoding.Signature

// ParsePublicKey 解析并校验压缩 secp256k1 公钥。
func ParsePublicKey(value string) (PublicKey, error) { return encoding.ParsePublicKey(value) }

// NewPublicKeyFromBytes 从压缩公钥字节创建公钥，输入会被复制。
func NewPublicKeyFromBytes(value []byte) (PublicKey, error) {
	return encoding.NewPublicKeyFromBytes(value)
}

// ParsePrivateKey 解析并校验长期私钥，输入会被复制。
func ParsePrivateKey(value []byte) (PrivateKey, error) { return encoding.NewPrivateKey(value) }

// GeneratePrivateKey 使用密码学安全随机源生成长期私钥。
func GeneratePrivateKey() (PrivateKey, error) { return encoding.GeneratePrivateKey() }

// GeneratePrivateKeyFrom 使用注入随机源生成长期私钥，测试可获得可复现结果。
func GeneratePrivateKeyFrom(source io.Reader) (PrivateKey, error) {
	return encoding.GeneratePrivateKeyFrom(source)
}

// PublicKeyFromPrivate 从长期私钥推导压缩公钥；私钥不会被缓存。
func PublicKeyFromPrivate(privateKey PrivateKey) (PublicKey, error) {
	return secp256k1.PublicKeyFromPrivate(privateKey)
}

// ParseMessageID 解析固定 43 字符的 message_id。
func ParseMessageID(value string) (MessageID, error) { return encoding.ParseMessageID(value) }

// NewMessageID 使用密码学安全随机源生成 message_id；传 nil 使用默认安全随机源。
func NewMessageID(source io.Reader) (MessageID, error) { return encoding.NewMessageID(source) }

// ParseSessionID 解析固定 43 字符的 session_id。
func ParseSessionID(value string) (SessionID, error) { return encoding.ParseSessionID(value) }

// ParseUnixMillis 解析 JSON number 形式的非负 safe integer Unix 毫秒。
func ParseUnixMillis(value stdjson.Number) (int64, error) { return encoding.ParseUnixMillis(value) }

// NewSessionID 使用密码学安全随机源生成 session_id。
func NewSessionID(source io.Reader) (SessionID, error) { return encoding.NewSessionID(source) }

// ParseSHA256Hash 解析固定 64 位小写文件 Hash。
func ParseSHA256Hash(value string) (SHA256Hash, error) { return encoding.ParseSHA256Hash(value) }

// ParseSignature 解析无填充 base64url DER 签名。
func ParseSignature(value string) (Signature, error) { return encoding.ParseSignature(value) }

// NewSignatureFromDER 从 DER 字节创建签名，输入会被复制。
func NewSignatureFromDER(value []byte) (Signature, error) { return encoding.NewSignatureFromDER(value) }

// InboxChannel 返回目标公钥对应的稳定私密频道。
func InboxChannel(toPublicKey PublicKey) string {
	return protocol.InboxChannelPrefix + toPublicKey.String()
}

// ParseInboxChannel 严格解析 bsv8.inbox.<public_key_hex> 并返回目标公钥。
func ParseInboxChannel(channel string) (PublicKey, error) {
	if len(channel) <= len(protocol.InboxChannelPrefix) || channel[:len(protocol.InboxChannelPrefix)] != protocol.InboxChannelPrefix {
		return PublicKey{}, protocolerror.New(protocolerror.InvalidChannel, "inbox channel 前缀不合法")
	}
	key, err := encoding.ParsePublicKey(channel[len(protocol.InboxChannelPrefix):])
	if err != nil {
		return PublicKey{}, protocolerror.New(protocolerror.InvalidChannel, "inbox channel 目标公钥不合法")
	}
	return key, nil
}

// CanonicalizeJSON 输出 RFC 8785 JCS UTF-8 字节。
func CanonicalizeJSON(input []byte) ([]byte, error) {
	return canonicalizeJSON(input)
}

// CanonicalizeValue 将可 JSON 化的 Go 值输出为 RFC 8785 JCS UTF-8 字节。
func CanonicalizeValue(value any) ([]byte, error) {
	return canonicalizeValue(value)
}
