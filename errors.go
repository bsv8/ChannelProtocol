package channels

import "github.com/bsv8/ChannelProtocol/internal/protocolerror"

// ChannelProtocolError 是 channels SDK 的结构化错误。
type ChannelProtocolError = protocolerror.Error

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
