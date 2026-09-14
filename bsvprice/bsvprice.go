package bsvprice

import (
	stdjson "encoding/json"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/bsv8/ChannelProtocol/internal/encoding"
	"github.com/bsv8/ChannelProtocol/internal/protocol"
	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
	"github.com/bsv8/ChannelProtocol/publicmessage"
)

const (
	// Protocol 是 BSV 价格正文的业务协议标识。
	Protocol = protocol.BSVPriceProtocol
	// ChannelPrefix 是价格频道的固定前缀。
	ChannelPrefix = protocol.BSVPriceChannelPrefix

	maxSafeInteger     int64 = 9_007_199_254_740_991
	maxMarkets               = 100
	maxPairsPerMarket        = 100
	maxIdentifierBytes       = 64
	maxPriceBytes            = 128
)

// BSVPriceBody 是一次完整的 BSV 多市场、多交易对价格快照。
//
// Markets 的第一层 key 是市场编号（例如 gate、okx），第二层 key 是交易对
// 编号（例如 bsvusdt、bsvcny），价格使用十进制字符串以避免浮点精度损失。
type BSVPriceBody struct {
	// Protocol 固定为 bsv8.bsv-price.v1。
	Protocol string `json:"protocol"`
	// SnapshotAtMs 是行情源生成本次完整快照的 Unix 毫秒时间。
	SnapshotAtMs int64 `json:"snapshot_at_ms"`
	// Markets 是市场编号到交易对价格的映射。
	Markets map[string]map[string]string `json:"markets"`
}

// UnsignedMessage 是待签名的 BSV 价格公开消息。
// 频道由 FromPublicKey 派生，不重复作为消息字段传入。
type UnsignedMessage struct {
	// FromPublicKey 是价格发布者长期压缩公钥。
	FromPublicKey encoding.PublicKey
	// MessageID 是公开消息去重编号。
	MessageID encoding.MessageID
	// IssuedAtMs 是公开消息发布时间 Unix 毫秒。
	IssuedAtMs int64
	// ExpiresAtMs 是公开消息过期时间 Unix 毫秒。
	ExpiresAtMs int64
	// Body 是完整价格快照正文。
	Body BSVPriceBody
}

// SignedMessage 是已经生成唯一业务签名的 BSV 价格消息。
type SignedMessage struct {
	UnsignedMessage
	// Signature 是 bsv8.public-message.v1 的 strict DER、low-S 签名。
	Signature encoding.Signature
}

// VerifiedMessage 是已完成结构、时间、频道关系和签名验证的价格消息。
type VerifiedMessage struct {
	signed   SignedMessage
	digest   encoding.SHA256Hash
	verified bool
}

// DeduplicationKey 是固定价格频道上的公开消息去重键。
type DeduplicationKey struct {
	// FromPublicKey 是价格发布者公钥。
	FromPublicKey encoding.PublicKey
	// MessageID 是消息编号。
	MessageID encoding.MessageID
}

// Channel 返回给定价格发布者对应的稳定频道。
func Channel(publisherPublicKey encoding.PublicKey) string {
	return ChannelPrefix + publisherPublicKey.String()
}

// ParseChannel 严格解析 bsvprice.<public_key_hex> 并返回频道发布者公钥。
func ParseChannel(channel string) (encoding.PublicKey, error) {
	if len(channel) <= len(ChannelPrefix) || !strings.HasPrefix(channel, ChannelPrefix) {
		return encoding.PublicKey{}, protocolerror.New(protocolerror.InvalidChannel, "BSV 价格频道前缀不合法")
	}
	key, err := encoding.ParsePublicKey(channel[len(ChannelPrefix):])
	if err != nil {
		return encoding.PublicKey{}, protocolerror.New(protocolerror.InvalidChannel, "BSV 价格频道发布者公钥不合法")
	}
	return key, nil
}

// NewBody 构造并校验带固定协议标识的价格快照正文。
func NewBody(snapshotAtMs int64, markets map[string]map[string]string) (BSVPriceBody, error) {
	return normalizeBody(BSVPriceBody{Protocol: Protocol, SnapshotAtMs: snapshotAtMs, Markets: markets})
}

// ValidateBody 校验价格正文，不会持有或修改调用方的 map。
func ValidateBody(body BSVPriceBody) error {
	_, err := normalizeBody(body)
	return err
}

// ParseBody 将已解析的 JSON object 转换为强类型价格正文。
func ParseBody(value any) (BSVPriceBody, error) {
	object, ok := coerceObject(value)
	if !ok {
		return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "BSV 价格 body 必须是 object")
	}
	if err := strictjson.RequireObjectKeys(object, "protocol", "snapshot_at_ms", "markets"); err != nil {
		return BSVPriceBody{}, err
	}
	protocolValue, err := strictjson.RequireField(object, "protocol")
	if err != nil {
		return BSVPriceBody{}, err
	}
	protocolText, ok := protocolValue.(string)
	if !ok {
		return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "protocol 必须是 string")
	}
	snapshotValue, err := strictjson.RequireField(object, "snapshot_at_ms")
	if err != nil {
		return BSVPriceBody{}, err
	}
	snapshotAtMs, err := parseSnapshotMillis(snapshotValue)
	if err != nil {
		return BSVPriceBody{}, err
	}
	marketsValue, err := strictjson.RequireField(object, "markets")
	if err != nil {
		return BSVPriceBody{}, err
	}
	marketsObject, ok := marketsValue.(map[string]strictjson.JSONValue)
	if !ok {
		return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "markets 必须是 object")
	}
	markets := make(map[string]map[string]string, len(marketsObject))
	for market, rawQuotes := range marketsObject {
		quotesObject, ok := rawQuotes.(map[string]strictjson.JSONValue)
		if !ok {
			return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "每个市场必须是交易对 object")
		}
		quotes := make(map[string]string, len(quotesObject))
		for pair, rawPrice := range quotesObject {
			price, ok := rawPrice.(string)
			if !ok {
				return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "价格必须是十进制 string")
			}
			quotes[pair] = price
		}
		markets[market] = quotes
	}
	return normalizeBody(BSVPriceBody{Protocol: protocolText, SnapshotAtMs: snapshotAtMs, Markets: markets})
}

// Sign 校验价格消息并生成确定性的公开消息签名。
func Sign(message UnsignedMessage, privateKey encoding.PrivateKey) (SignedMessage, error) {
	body, err := normalizeBody(message.Body)
	if err != nil {
		return SignedMessage{}, err
	}
	message.Body = body
	if err := validateUnsigned(message); err != nil {
		return SignedMessage{}, err
	}
	public, err := publicmessage.Sign(publicmessage.UnsignedMessage{
		Channel:       Channel(message.FromPublicKey),
		FromPublicKey: message.FromPublicKey,
		MessageID:     message.MessageID,
		IssuedAtMs:    message.IssuedAtMs,
		ExpiresAtMs:   message.ExpiresAtMs,
		Body:          bodyValue(body),
	}, privateKey)
	if err != nil {
		return SignedMessage{}, err
	}
	return SignedMessage{UnsignedMessage: message, Signature: public.Signature}, nil
}

// Marshal 输出不含 channel 字段的规范 JCS 价格消息 JSON。
func Marshal(message SignedMessage) ([]byte, error) {
	body, err := normalizeBody(message.Body)
	if err != nil {
		return nil, err
	}
	message.Body = body
	if err := validateUnsigned(message.UnsignedMessage); err != nil {
		return nil, err
	}
	public := publicmessage.SignedMessage{
		UnsignedMessage: publicmessage.UnsignedMessage{
			Channel:       Channel(message.FromPublicKey),
			FromPublicKey: message.FromPublicKey,
			MessageID:     message.MessageID,
			IssuedAtMs:    message.IssuedAtMs,
			ExpiresAtMs:   message.ExpiresAtMs,
			Body:          bodyValue(body),
		},
		Signature: message.Signature,
	}
	return publicmessage.Marshal(public)
}

// ParseAndVerify 严格解析指定价格频道上的消息并完成验签。
func ParseAndVerify(channel string, input []byte, nowMs int64) (VerifiedMessage, error) {
	publisher, err := ParseChannel(channel)
	if err != nil {
		return VerifiedMessage{}, err
	}
	public, err := publicmessage.ParseAndVerify(channel, input, nowMs)
	if err != nil {
		return VerifiedMessage{}, err
	}
	if !publisher.Equal(public.FromPublicKey()) {
		return VerifiedMessage{}, protocolerror.New(protocolerror.IdentityMismatch, "BSV 价格频道公钥与消息作者不一致")
	}
	body, err := ParseBody(public.Body())
	if err != nil {
		return VerifiedMessage{}, err
	}
	signed := public.SignedMessage()
	return VerifiedMessage{
		signed: SignedMessage{
			UnsignedMessage: UnsignedMessage{
				FromPublicKey: signed.FromPublicKey,
				MessageID:     signed.MessageID,
				IssuedAtMs:    signed.IssuedAtMs,
				ExpiresAtMs:   signed.ExpiresAtMs,
				Body:          body,
			},
			Signature: signed.Signature,
		},
		digest:   public.Digest(),
		verified: true,
	}, nil
}

// IsVerified 返回该值是否由 ParseAndVerify 成功创建。
func (message VerifiedMessage) IsVerified() bool { return message.verified }

// SignedMessage 返回已验签消息的防御性深拷贝。
func (message VerifiedMessage) SignedMessage() SignedMessage {
	return cloneSignedMessage(message.signed)
}

// FromPublicKey 返回价格发布者公钥。
func (message VerifiedMessage) FromPublicKey() encoding.PublicKey {
	return message.signed.FromPublicKey
}

// MessageID 返回公开消息编号。
func (message VerifiedMessage) MessageID() encoding.MessageID { return message.signed.MessageID }

// IssuedAtMs 返回公开消息发布时间。
func (message VerifiedMessage) IssuedAtMs() int64 { return message.signed.IssuedAtMs }

// ExpiresAtMs 返回公开消息过期时间。
func (message VerifiedMessage) ExpiresAtMs() int64 { return message.signed.ExpiresAtMs }

// Body 返回价格正文的防御性深拷贝。
func (message VerifiedMessage) Body() BSVPriceBody { return cloneBody(message.signed.Body) }

// Signature 返回唯一业务签名。
func (message VerifiedMessage) Signature() encoding.Signature { return message.signed.Signature }

// Digest 返回签名逻辑对象摘要。
func (message VerifiedMessage) Digest() encoding.SHA256Hash { return message.digest }

// DedupKey 返回固定价格频道上的公开消息去重键。
func (message VerifiedMessage) DedupKey() DeduplicationKey {
	return DeduplicationKey{FromPublicKey: message.signed.FromPublicKey, MessageID: message.signed.MessageID}
}

// SignedDigest 返回签名逻辑对象的稳定摘要。
func (message SignedMessage) SignedDigest() encoding.SHA256Hash {
	public := publicmessage.UnsignedMessage{
		Channel:       Channel(message.FromPublicKey),
		FromPublicKey: message.FromPublicKey,
		MessageID:     message.MessageID,
		IssuedAtMs:    message.IssuedAtMs,
		ExpiresAtMs:   message.ExpiresAtMs,
		Body:          bodyValue(message.Body),
	}
	digest, err := (publicmessage.SignedMessage{UnsignedMessage: public}).SignedDigest()
	if err != nil {
		return encoding.SHA256Hash{}
	}
	return digest
}

// CheckDigestConflict 检查相同去重键对应的消息摘要是否冲突。
func CheckDigestConflict(existing, incoming encoding.SHA256Hash) error {
	return publicmessage.CheckDigestConflict(existing, incoming)
}

func validateUnsigned(message UnsignedMessage) error {
	if _, err := encoding.ParsePublicKey(message.FromPublicKey.String()); err != nil {
		return protocolerror.New(protocolerror.InvalidPublicKey, "from_public_key 不是有效公钥")
	}
	if _, err := encoding.ParseMessageID(message.MessageID.String()); err != nil {
		return err
	}
	if err := validateTimes(message.IssuedAtMs, message.ExpiresAtMs); err != nil {
		return err
	}
	return ValidateBody(message.Body)
}

func validateTimes(issuedAtMs, expiresAtMs int64) error {
	if issuedAtMs < 0 || expiresAtMs < 0 || issuedAtMs > maxSafeInteger || expiresAtMs > maxSafeInteger {
		return protocolerror.New(protocolerror.InvalidTime, "时间必须是 JSON safe integer")
	}
	if issuedAtMs >= expiresAtMs || expiresAtMs-issuedAtMs > publicmessage.MaxLifetimeMs() {
		return protocolerror.New(protocolerror.InvalidTime, "公开消息时间顺序或最长有效期不合法")
	}
	return nil
}

func normalizeBody(body BSVPriceBody) (BSVPriceBody, error) {
	if body.Protocol != Protocol {
		return BSVPriceBody{}, protocolerror.New(protocolerror.UnsupportedProtocol, "BSV 价格 body protocol 不支持")
	}
	if body.SnapshotAtMs < 0 || body.SnapshotAtMs > maxSafeInteger {
		return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "snapshot_at_ms 必须是非负 JSON safe integer")
	}
	if len(body.Markets) > maxMarkets {
		return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "markets 必须包含 0 至 100 个市场")
	}
	result := BSVPriceBody{Protocol: Protocol, SnapshotAtMs: body.SnapshotAtMs, Markets: make(map[string]map[string]string, len(body.Markets))}
	for market, sourceQuotes := range body.Markets {
		if err := validateIdentifier(market, "市场"); err != nil {
			return BSVPriceBody{}, err
		}
		if len(sourceQuotes) == 0 || len(sourceQuotes) > maxPairsPerMarket {
			return BSVPriceBody{}, protocolerror.New(protocolerror.InvalidBody, "每个市场必须包含 1 至 100 个交易对")
		}
		quotes := make(map[string]string, len(sourceQuotes))
		for pair, price := range sourceQuotes {
			if err := validateIdentifier(pair, "交易对"); err != nil {
				return BSVPriceBody{}, err
			}
			if err := validatePrice(price); err != nil {
				return BSVPriceBody{}, err
			}
			quotes[pair] = price
		}
		result.Markets[market] = quotes
	}
	return result, nil
}

func validateIdentifier(value, label string) error {
	if value == "" || len([]byte(value)) > maxIdentifierBytes || !utf8.ValidString(value) {
		return protocolerror.New(protocolerror.InvalidBody, fmt.Sprintf("%s编号不合法", label))
	}
	for index, character := range value {
		if index == 0 && !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')) {
			return protocolerror.New(protocolerror.InvalidBody, fmt.Sprintf("%s编号必须以小写字母或数字开头", label))
		}
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '-' || character == '_' {
			continue
		}
		return protocolerror.New(protocolerror.InvalidBody, fmt.Sprintf("%s编号只能使用小写字母、数字、点、短横线和下划线", label))
	}
	return nil
}

func validatePrice(price string) error {
	if len(price) == 0 || len([]byte(price)) > maxPriceBytes || !utf8.ValidString(price) {
		return protocolerror.New(protocolerror.InvalidBody, "价格必须是十进制 string")
	}
	dotSeen := false
	digitsBeforeDot := 0
	digitsAfterDot := 0
	for index, character := range price {
		switch {
		case character >= '0' && character <= '9':
			if dotSeen {
				digitsAfterDot++
			} else {
				digitsBeforeDot++
			}
		case character == '.' && !dotSeen:
			dotSeen = true
		default:
			return protocolerror.New(protocolerror.InvalidBody, "价格必须是非负十进制字符串")
		}
		if index == 0 && character == '.' {
			return protocolerror.New(protocolerror.InvalidBody, "价格整数部分不能为空")
		}
	}
	if digitsBeforeDot == 0 || (dotSeen && digitsAfterDot == 0) {
		return protocolerror.New(protocolerror.InvalidBody, "价格必须包含有效数字")
	}
	if digitsBeforeDot > 1 && price[0] == '0' {
		return protocolerror.New(protocolerror.InvalidBody, "价格整数部分不允许前导零")
	}
	return nil
}

func bodyValue(body BSVPriceBody) map[string]any {
	markets := make(map[string]any, len(body.Markets))
	for market, quotes := range body.Markets {
		values := make(map[string]any, len(quotes))
		for pair, price := range quotes {
			values[pair] = price
		}
		markets[market] = values
	}
	return map[string]any{"protocol": Protocol, "snapshot_at_ms": body.SnapshotAtMs, "markets": markets}
}

func cloneBody(body BSVPriceBody) BSVPriceBody {
	result := BSVPriceBody{Protocol: body.Protocol, SnapshotAtMs: body.SnapshotAtMs, Markets: make(map[string]map[string]string, len(body.Markets))}
	for market, quotes := range body.Markets {
		result.Markets[market] = make(map[string]string, len(quotes))
		for pair, price := range quotes {
			result.Markets[market][pair] = price
		}
	}
	return result
}

func cloneUnsignedMessage(message UnsignedMessage) UnsignedMessage {
	message.Body = cloneBody(message.Body)
	return message
}

func cloneSignedMessage(message SignedMessage) SignedMessage {
	message.UnsignedMessage = cloneUnsignedMessage(message.UnsignedMessage)
	return message
}

func coerceObject(value any) (map[string]strictjson.JSONValue, bool) {
	switch object := value.(type) {
	case map[string]strictjson.JSONValue:
		return object, true
	case map[string]any:
		result := make(map[string]strictjson.JSONValue, len(object))
		for key, child := range object {
			result[key] = coerceValue(child)
		}
		return result, true
	default:
		return nil, false
	}
}

func coerceValue(value any) strictjson.JSONValue {
	switch current := value.(type) {
	case map[string]strictjson.JSONValue:
		return current
	case map[string]any:
		result := make(map[string]strictjson.JSONValue, len(current))
		for key, child := range current {
			result[key] = coerceValue(child)
		}
		return result
	case map[string]string:
		result := make(map[string]strictjson.JSONValue, len(current))
		for key, child := range current {
			result[key] = child
		}
		return result
	case map[string]map[string]string:
		result := make(map[string]strictjson.JSONValue, len(current))
		for key, child := range current {
			result[key] = coerceValue(child)
		}
		return result
	case []any:
		result := make([]strictjson.JSONValue, len(current))
		for index, child := range current {
			result[index] = coerceValue(child)
		}
		return result
	default:
		return value
	}
}

func parseSnapshotMillis(value any) (int64, error) {
	switch current := value.(type) {
	case stdjson.Number:
		parsed, err := encoding.ParseUnixMillis(current)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	case int:
		return parseInteger(int64(current))
	case int8:
		return parseInteger(int64(current))
	case int16:
		return parseInteger(int64(current))
	case int32:
		return parseInteger(int64(current))
	case int64:
		return parseInteger(current)
	case uint:
		if uint64(current) > uint64(maxSafeInteger) {
			return 0, protocolerror.New(protocolerror.InvalidTime, "snapshot_at_ms 超出 JSON safe integer")
		}
		return int64(current), nil
	case uint8:
		return int64(current), nil
	case uint16:
		return int64(current), nil
	case uint32:
		return parseSnapshotMillis(uint64(current))
	case uint64:
		if current > uint64(maxSafeInteger) {
			return 0, protocolerror.New(protocolerror.InvalidTime, "snapshot_at_ms 超出 JSON safe integer")
		}
		return int64(current), nil
	case float64:
		if math.IsNaN(current) || math.IsInf(current, 0) || math.Trunc(current) != current || current < 0 || current > float64(maxSafeInteger) {
			return 0, protocolerror.New(protocolerror.InvalidTime, "snapshot_at_ms 必须是非负 JSON safe integer")
		}
		return int64(current), nil
	default:
		return 0, protocolerror.New(protocolerror.InvalidTime, "snapshot_at_ms 必须是整数")
	}
}

func parseInteger(value int64) (int64, error) {
	if value < 0 || value > maxSafeInteger {
		return 0, protocolerror.New(protocolerror.InvalidTime, "snapshot_at_ms 必须是非负 JSON safe integer")
	}
	return value, nil
}
