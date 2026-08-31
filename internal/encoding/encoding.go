// Package encoding 实现三方频道公共原语的严格线上编码。
package encoding

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	// PublicKeyBytes 是压缩 secp256k1 公钥的字节长度。
	PublicKeyBytes = 33
	// PrivateKeyBytes 是 secp256k1 私钥的字节长度。
	PrivateKeyBytes = 32
	// MessageIDBytes 是消息编号和 Session ID 的字节长度。
	MessageIDBytes = 32
	// PublicKeyHexChars 是公钥线上 hex 字符数。
	PublicKeyHexChars = PublicKeyBytes * 2
	// HashHexChars 是 SHA-256 Hash 线上 hex 字符数。
	HashHexChars = 64
)

var curveOrder = secp256k1.Params().N

// PublicKey 是经过曲线点校验的压缩 secp256k1 公钥。
// 其底层字节不可直接访问，Bytes 方法始终返回副本。
type PublicKey struct{ bytes [PublicKeyBytes]byte }

// PrivateKey 是经过范围校验的长期 secp256k1 私钥。
// 该类型的 String 和 JSON 表示均不会暴露密钥字节，避免意外打印或序列化。
type PrivateKey struct{ bytes [PrivateKeyBytes]byte }

// MessageID 是 32 字节无填充 base64url 消息编号。
type MessageID struct{ bytes [MessageIDBytes]byte }

// SessionID 是 32 字节无填充 base64url WebRTC 会话编号。
type SessionID struct{ bytes [MessageIDBytes]byte }

// SHA256Hash 是 32 字节文件内容 Hash。
type SHA256Hash struct{ bytes [MessageIDBytes]byte }

// Signature 是 strict DER、low-S ECDSA 签名的原始字节。
type Signature struct{ der []byte }

// NewPrivateKey 从 32 字节大端私钥创建强类型值，并执行 [1,N-1] 范围检查。
func NewPrivateKey(value []byte) (PrivateKey, error) {
	var result PrivateKey
	if len(value) != PrivateKeyBytes {
		return result, protocolerror.New(protocolerror.InvalidPrivateKey, "私钥必须是 32 字节")
	}
	integer := new(big.Int).SetBytes(value)
	if integer.Sign() <= 0 || integer.Cmp(curveOrder) >= 0 {
		return result, protocolerror.New(protocolerror.InvalidPrivateKey, "私钥不在 secp256k1 有效范围内")
	}
	copy(result.bytes[:], value)
	return result, nil
}

// GeneratePrivateKey 使用密码学安全随机源生成长期私钥。
func GeneratePrivateKey() (PrivateKey, error) { return GeneratePrivateKeyFrom(rand.Reader) }

// GeneratePrivateKeyFrom 使用调用方注入的随机源生成长期私钥。
func GeneratePrivateKeyFrom(source io.Reader) (PrivateKey, error) {
	if source == nil {
		source = rand.Reader
	}
	var value [PrivateKeyBytes]byte
	for attempt := 0; attempt < 128; attempt++ {
		if _, err := io.ReadFull(source, value[:]); err != nil {
			return PrivateKey{}, protocolerror.Wrap(protocolerror.InvalidPrivateKey, "随机源读取私钥失败", err)
		}
		key, err := NewPrivateKey(value[:])
		if err == nil {
			return key, nil
		}
	}
	return PrivateKey{}, protocolerror.New(protocolerror.InvalidPrivateKey, "随机源未生成有效 secp256k1 私钥")
}

// Bytes 返回私钥字节副本；调用方使用完毕后应尽力清零副本。
func (p PrivateKey) Bytes() []byte {
	result := make([]byte, PrivateKeyBytes)
	copy(result, p.bytes[:])
	return result
}

// String 返回脱敏文本，绝不返回私钥字节。
func (p PrivateKey) String() string { return "<private key>" }

// Format 覆盖 fmt 的全部常见格式化路径，避免 %#v 等调试格式泄露私钥字节。
func (p PrivateKey) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, "<private key>") }

// MarshalJSON 拒绝把私钥编码进 JSON。
func (p PrivateKey) MarshalJSON() ([]byte, error) {
	return nil, protocolerror.New(protocolerror.InvalidPrivateKey, "PrivateKey 不允许 JSON 序列化")
}

// ParsePublicKey 解析 66 位小写压缩公钥 hex，并校验曲线点。
func ParsePublicKey(value string) (PublicKey, error) {
	var result PublicKey
	if len(value) != PublicKeyHexChars || value != strings.ToLower(value) {
		return result, protocolerror.New(protocolerror.InvalidPublicKey, "公钥必须是 66 位小写 hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != PublicKeyBytes || (decoded[0] != 0x02 && decoded[0] != 0x03) {
		return result, protocolerror.New(protocolerror.InvalidPublicKey, "公钥编码不是压缩 secp256k1 公钥")
	}
	key, err := secp256k1.ParsePubKey(decoded)
	if err != nil || !equalBytes(key.SerializeCompressed(), decoded) {
		return result, protocolerror.New(protocolerror.InvalidPublicKey, "公钥不是有效 secp256k1 曲线点")
	}
	copy(result.bytes[:], decoded)
	return result, nil
}

// NewPublicKeyFromBytes 从压缩公钥字节创建强类型公钥。
func NewPublicKeyFromBytes(value []byte) (PublicKey, error) {
	return ParsePublicKey(hex.EncodeToString(value))
}

// Bytes 返回公钥字节副本。
func (p PublicKey) Bytes() []byte {
	result := make([]byte, PublicKeyBytes)
	copy(result, p.bytes[:])
	return result
}

// String 返回公钥的小写 hex 表示。
func (p PublicKey) String() string { return hex.EncodeToString(p.bytes[:]) }

// Equal 按规范化后的公钥字节比较两个身份。
func (p PublicKey) Equal(other PublicKey) bool { return p.bytes == other.bytes }

// CheckIdentity 检查两个公钥均为合法值，并执行规范化后的 exact bytes 比较。
// authenticated 是外层已认证身份，claimed 是报文声明身份。
func CheckIdentity(authenticated, claimed PublicKey, message string) error {
	if _, err := ParsePublicKey(authenticated.String()); err != nil {
		return err
	}
	if _, err := ParsePublicKey(claimed.String()); err != nil {
		return err
	}
	if !authenticated.Equal(claimed) {
		return protocolerror.New(protocolerror.IdentityMismatch, message)
	}
	return nil
}

// ParseMessageID 解析固定 43 字符的 32 字节无填充 base64url 编号。
func ParseMessageID(value string) (MessageID, error) {
	decoded, err := decodeFixedBase64URL(value, MessageIDBytes)
	if err != nil {
		return MessageID{}, protocolerror.Wrap(protocolerror.InvalidMessageID, "message_id 必须是 32 字节无填充 base64url", err)
	}
	var result MessageID
	copy(result.bytes[:], decoded)
	return result, nil
}

// NewMessageID 使用密码学安全随机源生成消息编号。
func NewMessageID(source io.Reader) (MessageID, error) {
	bytes, err := randomFixed(source, MessageIDBytes)
	if err != nil {
		return MessageID{}, protocolerror.Wrap(protocolerror.InvalidMessageID, "生成 message_id 失败", err)
	}
	var result MessageID
	copy(result.bytes[:], bytes)
	return result, nil
}

// Bytes 返回消息编号字节副本。
func (id MessageID) Bytes() []byte {
	result := make([]byte, MessageIDBytes)
	copy(result, id.bytes[:])
	return result
}

// String 返回消息编号的无填充 base64url 表示。
func (id MessageID) String() string { return base64.RawURLEncoding.EncodeToString(id.bytes[:]) }

// Equal 比较两个消息编号。
func (id MessageID) Equal(other MessageID) bool { return id.bytes == other.bytes }

// ParseSessionID 解析固定 43 字符的 WebRTC session_id。
func ParseSessionID(value string) (SessionID, error) {
	decoded, err := decodeFixedBase64URL(value, MessageIDBytes)
	if err != nil {
		return SessionID{}, protocolerror.Wrap(protocolerror.InvalidMessageID, "session_id 必须是 32 字节无填充 base64url", err)
	}
	var result SessionID
	copy(result.bytes[:], decoded)
	return result, nil
}

// NewSessionID 使用密码学安全随机源生成 WebRTC session_id。
func NewSessionID(source io.Reader) (SessionID, error) {
	bytes, err := randomFixed(source, MessageIDBytes)
	if err != nil {
		return SessionID{}, protocolerror.Wrap(protocolerror.InvalidMessageID, "生成 session_id 失败", err)
	}
	var result SessionID
	copy(result.bytes[:], bytes)
	return result, nil
}

// Bytes 返回 Session ID 字节副本。
func (id SessionID) Bytes() []byte {
	result := make([]byte, MessageIDBytes)
	copy(result, id.bytes[:])
	return result
}

// String 返回 Session ID 的无填充 base64url 表示。
func (id SessionID) String() string { return base64.RawURLEncoding.EncodeToString(id.bytes[:]) }

// Equal 比较两个 Session ID。
func (id SessionID) Equal(other SessionID) bool { return id.bytes == other.bytes }

// ParseSHA256Hash 解析 64 位小写文件 Hash hex。
func ParseSHA256Hash(value string) (SHA256Hash, error) {
	var result SHA256Hash
	if len(value) != HashHexChars || value != strings.ToLower(value) {
		return result, protocolerror.New(protocolerror.InvalidBody, "hash 必须是 64 位小写 hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != MessageIDBytes {
		return result, protocolerror.New(protocolerror.InvalidBody, "hash 不是 32 字节 SHA-256")
	}
	copy(result.bytes[:], decoded)
	return result, nil
}

// NewSHA256HashFromBytes 从 32 字节 Hash 创建强类型值。
func NewSHA256HashFromBytes(value []byte) (SHA256Hash, error) {
	return ParseSHA256Hash(hex.EncodeToString(value))
}

// Bytes 返回 Hash 字节副本。
func (hash SHA256Hash) Bytes() []byte {
	result := make([]byte, MessageIDBytes)
	copy(result, hash.bytes[:])
	return result
}

// String 返回 Hash 的小写 hex 表示。
func (hash SHA256Hash) String() string { return hex.EncodeToString(hash.bytes[:]) }

// Equal 比较两个 SHA-256 Hash。
func (hash SHA256Hash) Equal(other SHA256Hash) bool { return hash.bytes == other.bytes }

// ParseSignature 解析 strict DER 签名的无填充 base64url 外层编码。
// DER 结构和 low-S 规则由 internal/secp256k1 在验签时继续检查。
func ParseSignature(value string) (Signature, error) {
	decoded, err := decodeRawBase64URL(value)
	if err != nil || len(decoded) < 8 || len(decoded) > 72 {
		return Signature{}, protocolerror.New(protocolerror.InvalidSignature, "signature 必须是 8 至 72 字节 DER 的无填充 base64url")
	}
	if err := validateSignatureDER(decoded); err != nil {
		return Signature{}, err
	}
	return Signature{der: append([]byte(nil), decoded...)}, nil
}

// NewSignatureFromDER 从 DER 字节创建签名值，验签时仍会执行 strict DER/low-S 检查。
func NewSignatureFromDER(value []byte) (Signature, error) {
	if len(value) < 8 || len(value) > 72 {
		return Signature{}, protocolerror.New(protocolerror.InvalidSignature, "DER 签名长度不合法")
	}
	if err := validateSignatureDER(value); err != nil {
		return Signature{}, err
	}
	return Signature{der: append([]byte(nil), value...)}, nil
}

// DER 返回签名字节副本。
func (sig Signature) DER() []byte { return append([]byte(nil), sig.der...) }

// String 返回签名的无填充 base64url 表示。
func (sig Signature) String() string { return base64.RawURLEncoding.EncodeToString(sig.der) }

// DecodeBase64URL 严格解码无填充 base64url，并检查固定字节长度。
func DecodeBase64URL(value string, expectedBytes int, code protocolerror.Code, field string) ([]byte, error) {
	decoded, err := decodeFixedBase64URL(value, expectedBytes)
	if err != nil {
		return nil, protocolerror.Wrap(code, fmt.Sprintf("%s 必须是 %d 字节无填充 base64url", field, expectedBytes), err)
	}
	return decoded, nil
}

// DecodeRawBase64URL 严格解码不带长度约束的无填充 base64url。
func DecodeRawBase64URL(value string) ([]byte, error) { return decodeRawBase64URL(value) }

// EncodeBase64URL 将字节编码为无填充 base64url。
func EncodeBase64URL(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

// ParseUnixMillis 将严格 JSON number 转换为非负安全 Unix 毫秒。
func ParseUnixMillis(value json.Number) (int64, error) {
	raw := value.String()
	parsed, err := strconv.ParseFloat(raw, 64)
	// JSON 没有独立整数类型；按 ECMAScript Number 的 safe-integer 语义判断。
	// 下溢到有限 0 的 ErrRange 仍可接受，Infinity/NaN 和非整数值必须拒绝。
	if raw == "" || (err != nil && !errors.Is(err, strconv.ErrRange)) || math.IsInf(parsed, 0) || math.IsNaN(parsed) || parsed < 0 || math.Trunc(parsed) != parsed || parsed > 9_007_199_254_740_991 {
		return 0, protocolerror.New(protocolerror.InvalidTime, "时间必须在 JSON safe integer 范围内")
	}
	return int64(parsed), nil
}

// ParsePositiveInt 将协议中的非负安全整数解析为 int。
func ParsePositiveInt(value json.Number, field string) (int, error) {
	millis, err := ParseUnixMillis(value)
	if err != nil || millis > int64(^uint(0)>>1) {
		return 0, protocolerror.New(protocolerror.InvalidBody, fmt.Sprintf("%s 必须是非负安全整数", field))
	}
	return int(millis), nil
}

// RandomBytes 从注入随机源读取固定长度字节；nil 使用 crypto/rand.Reader。
func RandomBytes(source io.Reader, length int) ([]byte, error) {
	return randomFixed(source, length)
}

func randomFixed(source io.Reader, length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("negative random length")
	}
	if source == nil {
		source = rand.Reader
	}
	result := make([]byte, length)
	if _, err := io.ReadFull(source, result); err != nil {
		return nil, err
	}
	return result, nil
}

func decodeFixedBase64URL(value string, expected int) ([]byte, error) {
	decoded, err := decodeRawBase64URL(value)
	if err != nil || len(decoded) != expected || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("non-canonical base64url")
	}
	return decoded, nil
}

func decodeRawBase64URL(value string) ([]byte, error) {
	if strings.ContainsAny(value, "= \t\r\n") || strings.Contains(value, "+") || strings.Contains(value, "/") {
		return nil, fmt.Errorf("padding or non-url character")
	}
	if value == "" {
		return []byte{}, nil
	}
	for _, c := range value {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, fmt.Errorf("invalid base64url character")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(value)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}

func validateSignatureDER(value []byte) error {
	signature, err := ecdsa.ParseDERSignature(value)
	if err != nil {
		return protocolerror.New(protocolerror.InvalidSignature, "signature 不是 strict DER")
	}
	sValue := signature.S()
	if sValue.IsOverHalfOrder() {
		return protocolerror.New(protocolerror.InvalidSignature, "signature 使用 high-S")
	}
	if !equalBytes(signature.Serialize(), value) {
		return protocolerror.New(protocolerror.InvalidSignature, "signature DER 不是唯一规范编码")
	}
	return nil
}
