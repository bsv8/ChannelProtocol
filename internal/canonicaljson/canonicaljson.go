// Package canonicaljson 封装 RFC 8785 JSON Canonicalization Scheme。
package canonicaljson

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"unicode/utf8"

	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// CanonicalizeJSON 严格解析 JSON 后输出 RFC 8785 JCS UTF-8 字节。
func CanonicalizeJSON(input []byte) ([]byte, error) {
	value, err := strictjson.Parse(input)
	if err != nil {
		return nil, err
	}
	return canonicalizeParsed(value)
}

// CanonicalizeValue 将 Go JSON 值编码并规范化。构造协议消息时必须使用此入口。
func CanonicalizeValue(value any) ([]byte, error) {
	if err := validateUTF8Strings(reflect.ValueOf(value), 0); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, protocolerror.Wrap(protocolerror.InvalidJSON, "值不能编码为 JSON", err)
	}
	parsed, err := strictjson.Parse(raw)
	if err != nil {
		return nil, err
	}
	return canonicalizeParsed(parsed)
}

// validateUTF8Strings 补上 encoding/json 对非法 UTF-8 string 自动替换的差异。
// 协议值只接受 UTF-8；不能让替换字符悄悄改变签名输入。
func validateUTF8Strings(value reflect.Value, depth int) error {
	if !value.IsValid() {
		return nil
	}
	if depth > strictjson.MaxJSONDepth {
		return protocolerror.New(protocolerror.MessageTooLarge, "JSON 值超过资源上限")
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
		depth++
		if depth > strictjson.MaxJSONDepth {
			return protocolerror.New(protocolerror.MessageTooLarge, "JSON 值超过资源上限")
		}
	}
	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return protocolerror.New(protocolerror.InvalidJSON, "JSON string 不是合法 UTF-8")
		}
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		iter := value.MapRange()
		for iter.Next() {
			if err := validateUTF8Strings(iter.Key(), depth+1); err != nil {
				return err
			}
			if err := validateUTF8Strings(iter.Value(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateUTF8Strings(value.Index(index), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			if field.CanInterface() {
				if err := validateUTF8Strings(field, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Digest 返回输入字节的 SHA-256。
func Digest(input []byte) [32]byte { return sha256.Sum256(input) }

func canonicalizeParsed(value strictjson.JSONValue) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, protocolerror.Wrap(protocolerror.InvalidJSON, "严格 JSON 值无法重新编码", err)
	}
	// 上游实现以 object/array 为根；用数组包裹标量不会改变标量的 JCS 字节。
	if len(raw) == 0 {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON 编码为空")
	}
	if raw[0] != '{' && raw[0] != '[' {
		wrapped := make([]byte, 0, len(raw)+2)
		wrapped = append(wrapped, '[')
		wrapped = append(wrapped, raw...)
		wrapped = append(wrapped, ']')
		result, err := jsoncanonicalizer.Transform(wrapped)
		if err != nil {
			return nil, protocolerror.Wrap(protocolerror.InvalidJSON, "JCS 规范化失败", err)
		}
		return bytes.Clone(result[1 : len(result)-1]), nil
	}
	result, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, protocolerror.Wrap(protocolerror.InvalidJSON, "JCS 规范化失败", err)
	}
	return bytes.Clone(result), nil
}
