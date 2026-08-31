// Package protocolerror 定义 channels SDK 的跨语言稳定错误分类。
package protocolerror

import (
	"errors"
	"fmt"
)

// Code 是调用方可以依赖的稳定错误码。
type Code string

// V1ErrorCode 是 Go 与 TypeScript 必须保持一致的错误码集合。
const (
	InvalidJSON         Code = "INVALID_JSON"
	UnknownField        Code = "UNKNOWN_FIELD"
	InvalidChannel      Code = "INVALID_CHANNEL"
	InvalidPublicKey    Code = "INVALID_PUBLIC_KEY"
	InvalidPrivateKey   Code = "INVALID_PRIVATE_KEY"
	IdentityMismatch    Code = "IDENTITY_MISMATCH"
	InvalidMessageID    Code = "INVALID_MESSAGE_ID"
	InvalidTime         Code = "INVALID_TIME"
	MessageExpired      Code = "MESSAGE_EXPIRED"
	InvalidBody         Code = "INVALID_BODY"
	UnsupportedProtocol Code = "UNSUPPORTED_PROTOCOL"
	InvalidSignature    Code = "INVALID_SIGNATURE"
	InvalidEnvelope     Code = "INVALID_ENVELOPE"
	OpenFailed          Code = "OPEN_FAILED"
	MessageIDConflict   Code = "MESSAGE_ID_CONFLICT"
	InvalidRelation     Code = "INVALID_RELATION"
	MessageTooLarge     Code = "MESSAGE_TOO_LARGE"
)

// Error 是 SDK 返回的结构化错误。调用方应检查 Code，而不是匹配 Error 文本。
type Error struct {
	// Code 是稳定的机器可读错误码。
	Code Code
	// Message 是便于日志和调试的中文上下文，不属于兼容性 API。
	Message string
	// Cause 是内部原因；OpenFailed 不会把它暴露给远端调用者。
	Cause error
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap 保留本地诊断链，同时不改变稳定 Code。
func (e *Error) Unwrap() error { return e.Cause }

// Is 让 errors.Is 可以按错误分类匹配，而不要求调用方依赖具体文本。
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.Code == other.Code
}

// New 创建一个带稳定分类的错误。
func New(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Wrap 用稳定分类包装本地原因。
func Wrap(code Code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Cause: cause}
}

// Sentinel 创建供 errors.Is 使用的分类哨兵值。
func Sentinel(code Code) *Error { return &Error{Code: code} }

// Is 按稳定错误码判断错误分类。
func Is(err error, code Code) bool { return errors.Is(err, Sentinel(code)) }
