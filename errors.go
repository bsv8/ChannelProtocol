package channels

import "github.com/bsv8/ChannelProtocol/internal/protocolerror"

// ErrorCode 是 Go/TypeScript 共享的稳定错误码类型。
type ErrorCode = protocolerror.Code

// ChannelProtocolError 是 channels SDK 的结构化错误。
type ChannelProtocolError = protocolerror.Error

// 稳定错误码常量；调用方应依赖这些 Code，而非错误文本。
const (
	InvalidJSONCode         ErrorCode = protocolerror.InvalidJSON
	UnknownFieldCode        ErrorCode = protocolerror.UnknownField
	InvalidChannelCode      ErrorCode = protocolerror.InvalidChannel
	InvalidPublicKeyCode    ErrorCode = protocolerror.InvalidPublicKey
	InvalidPrivateKeyCode   ErrorCode = protocolerror.InvalidPrivateKey
	IdentityMismatchCode    ErrorCode = protocolerror.IdentityMismatch
	InvalidMessageIDCode    ErrorCode = protocolerror.InvalidMessageID
	InvalidTimeCode         ErrorCode = protocolerror.InvalidTime
	MessageExpiredCode      ErrorCode = protocolerror.MessageExpired
	InvalidBodyCode         ErrorCode = protocolerror.InvalidBody
	UnsupportedProtocolCode ErrorCode = protocolerror.UnsupportedProtocol
	InvalidSignatureCode    ErrorCode = protocolerror.InvalidSignature
	InvalidEnvelopeCode     ErrorCode = protocolerror.InvalidEnvelope
	OpenFailedCode          ErrorCode = protocolerror.OpenFailed
	MessageIDConflictCode   ErrorCode = protocolerror.MessageIDConflict
	InvalidRelationCode     ErrorCode = protocolerror.InvalidRelation
	MessageTooLargeCode     ErrorCode = protocolerror.MessageTooLarge
)

// 错误分类哨兵，可配合 errors.Is 使用。
var (
	ErrInvalidJSON         = protocolerror.Sentinel(protocolerror.InvalidJSON)
	ErrUnknownField        = protocolerror.Sentinel(protocolerror.UnknownField)
	ErrInvalidChannel      = protocolerror.Sentinel(protocolerror.InvalidChannel)
	ErrInvalidPublicKey    = protocolerror.Sentinel(protocolerror.InvalidPublicKey)
	ErrInvalidPrivateKey   = protocolerror.Sentinel(protocolerror.InvalidPrivateKey)
	ErrIdentityMismatch    = protocolerror.Sentinel(protocolerror.IdentityMismatch)
	ErrInvalidMessageID    = protocolerror.Sentinel(protocolerror.InvalidMessageID)
	ErrInvalidTime         = protocolerror.Sentinel(protocolerror.InvalidTime)
	ErrMessageExpired      = protocolerror.Sentinel(protocolerror.MessageExpired)
	ErrInvalidBody         = protocolerror.Sentinel(protocolerror.InvalidBody)
	ErrUnsupportedProtocol = protocolerror.Sentinel(protocolerror.UnsupportedProtocol)
	ErrInvalidSignature    = protocolerror.Sentinel(protocolerror.InvalidSignature)
	ErrInvalidEnvelope     = protocolerror.Sentinel(protocolerror.InvalidEnvelope)
	ErrOpenFailed          = protocolerror.Sentinel(protocolerror.OpenFailed)
	ErrMessageIDConflict   = protocolerror.Sentinel(protocolerror.MessageIDConflict)
	ErrInvalidRelation     = protocolerror.Sentinel(protocolerror.InvalidRelation)
	ErrMessageTooLarge     = protocolerror.Sentinel(protocolerror.MessageTooLarge)
)

// IsErrorCode 判断错误是否属于指定稳定错误码。
func IsErrorCode(err error, code ErrorCode) bool { return protocolerror.Is(err, code) }
