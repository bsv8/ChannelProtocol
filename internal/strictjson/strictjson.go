// Package strictjson 提供带重复字段和资源上限检查的 JSON 解析器。
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/bsv8/ChannelProtocol/internal/protocolerror"
)

// MaxJSONBytes 是单份 JSON 输入和构造结果允许的最大 UTF-8 字节数。
const MaxJSONBytes = 1_048_000

// MaxJSONDepth 是 JSON 容器允许的最大嵌套深度。
const MaxJSONDepth = 64

// MaxJSONNodes 是一份 JSON 文档允许的最大值节点数。
const MaxJSONNodes = 100_000

// JSONValue 是严格解析后可进入协议层的 JSON 值。
type JSONValue any

type parser struct {
	data  []byte
	i     int
	nodes int
}

// Parse 严格解析完整 UTF-8 JSON，拒绝重复字段、非法 surrogate 和资源超限。
func Parse(data []byte) (JSONValue, error) {
	if len(data) > MaxJSONBytes {
		return nil, protocolerror.New(protocolerror.MessageTooLarge, "JSON 输入超过 1,048,000 字节")
	}
	if !utf8.Valid(data) {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "输入不是合法 UTF-8")
	}
	p := &parser{data: data}
	p.skipWhitespace()
	if p.i == len(p.data) {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON 为空")
	}
	value, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	p.skipWhitespace()
	if p.i != len(p.data) {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON 后存在未解析内容")
	}
	return value, nil
}

// ParseObject 严格解析并要求根值为 object。
func ParseObject(data []byte) (map[string]JSONValue, error) {
	value, err := Parse(data)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]JSONValue)
	if !ok {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "协议根值必须是 object")
	}
	return object, nil
}

func (p *parser) parseValue(depth int) (JSONValue, error) {
	if p.nodes >= MaxJSONNodes {
		return nil, protocolerror.New(protocolerror.MessageTooLarge, "JSON 节点数超过 100,000")
	}
	p.nodes++
	if p.i >= len(p.data) {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON 意外结束")
	}
	switch p.data[p.i] {
	case '{':
		return p.parseObject(depth)
	case '[':
		return p.parseArray(depth)
	case '"':
		return p.parseString()
	case 't':
		return p.parseLiteral("true", true)
	case 'f':
		return p.parseLiteral("false", false)
	case 'n':
		return p.parseLiteral("null", nil)
	default:
		if p.data[p.i] == '-' || (p.data[p.i] >= '0' && p.data[p.i] <= '9') {
			return p.parseNumber()
		}
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON 值类型不合法")
	}
}

func (p *parser) parseObject(depth int) (JSONValue, error) {
	if depth >= MaxJSONDepth {
		return nil, protocolerror.New(protocolerror.MessageTooLarge, "JSON 嵌套深度超过 64")
	}
	p.i++ // {
	object := make(map[string]JSONValue)
	p.skipWhitespace()
	if p.consume('}') {
		return object, nil
	}
	for {
		p.skipWhitespace()
		if p.i >= len(p.data) || p.data[p.i] != '"' {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "object key 必须是字符串")
		}
		keyValue, err := p.parseString()
		if err != nil {
			return nil, err
		}
		key := keyValue.(string)
		if _, exists := object[key]; exists {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON object 存在重复字段")
		}
		p.skipWhitespace()
		if !p.consume(':') {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "object key 后缺少冒号")
		}
		p.skipWhitespace()
		value, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		object[key] = value
		p.skipWhitespace()
		if p.consume('}') {
			return object, nil
		}
		if !p.consume(',') {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "object 字段之间缺少逗号或右括号")
		}
	}
}

func (p *parser) parseArray(depth int) (JSONValue, error) {
	if depth >= MaxJSONDepth {
		return nil, protocolerror.New(protocolerror.MessageTooLarge, "JSON 嵌套深度超过 64")
	}
	p.i++ // [
	array := make([]JSONValue, 0)
	p.skipWhitespace()
	if p.consume(']') {
		return array, nil
	}
	for {
		p.skipWhitespace()
		value, err := p.parseValue(depth + 1)
		if err != nil {
			return nil, err
		}
		array = append(array, value)
		p.skipWhitespace()
		if p.consume(']') {
			return array, nil
		}
		if !p.consume(',') {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "array 元素之间缺少逗号或右括号")
		}
	}
}

func (p *parser) parseString() (JSONValue, error) {
	start := p.i
	p.i++ // opening quote
	for p.i < len(p.data) {
		c := p.data[p.i]
		switch c {
		case '"':
			p.i++
			var result string
			if err := json.Unmarshal(p.data[start:p.i], &result); err != nil {
				return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串转义不合法")
			}
			return result, nil
		case '\\':
			p.i++
			if p.i >= len(p.data) {
				return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串转义意外结束")
			}
			switch p.data[p.i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				p.i++
			case 'u':
				unit, err := p.parseUnicodeEscape()
				if err != nil {
					return nil, err
				}
				if unit >= 0xDC00 && unit <= 0xDFFF {
					return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串包含孤立 low surrogate")
				}
				if unit >= 0xD800 && unit <= 0xDBFF {
					if p.i+1 >= len(p.data) || p.data[p.i] != '\\' || p.data[p.i+1] != 'u' {
						return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串 high surrogate 缺少配对")
					}
					p.i += 2
					low, err := p.parseUnicodeEscapeDigits()
					if err != nil {
						return nil, err
					}
					if low < 0xDC00 || low > 0xDFFF {
						return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串 surrogate 配对不合法")
					}
				}
			default:
				return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串包含未知转义")
			}
		default:
			if c < 0x20 {
				return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串包含未转义控制字符")
			}
			p.i++
		}
	}
	return nil, protocolerror.New(protocolerror.InvalidJSON, "字符串缺少结束引号")
}

func (p *parser) parseUnicodeEscape() (int, error) {
	p.i++ // u
	return p.parseUnicodeEscapeDigits()
}

func (p *parser) parseUnicodeEscapeDigits() (int, error) {
	if p.i+4 > len(p.data) {
		return 0, protocolerror.New(protocolerror.InvalidJSON, "Unicode 转义长度不足")
	}
	value, err := strconv.ParseUint(string(p.data[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, protocolerror.New(protocolerror.InvalidJSON, "Unicode 转义不是十六进制")
	}
	p.i += 4
	return int(value), nil
}

func (p *parser) parseLiteral(literal string, value JSONValue) (JSONValue, error) {
	if p.i+len(literal) > len(p.data) || string(p.data[p.i:p.i+len(literal)]) != literal {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON literal 不完整")
	}
	p.i += len(literal)
	return value, nil
}

func (p *parser) parseNumber() (JSONValue, error) {
	start := p.i
	if p.consume('-') && p.i >= len(p.data) {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON number 不完整")
	}
	if p.i < len(p.data) && p.data[p.i] == '0' {
		p.i++
		if p.i < len(p.data) && p.data[p.i] >= '0' && p.data[p.i] <= '9' {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON number 不允许前导零")
		}
	} else {
		if p.i >= len(p.data) || p.data[p.i] < '1' || p.data[p.i] > '9' {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON number 整数部分不合法")
		}
		for p.i < len(p.data) && p.data[p.i] >= '0' && p.data[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.data) && p.data[p.i] == '.' {
		p.i++
		fractionStart := p.i
		for p.i < len(p.data) && p.data[p.i] >= '0' && p.data[p.i] <= '9' {
			p.i++
		}
		if fractionStart == p.i {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON number 小数部分不合法")
		}
	}
	if p.i < len(p.data) && (p.data[p.i] == 'e' || p.data[p.i] == 'E') {
		p.i++
		if p.i < len(p.data) && (p.data[p.i] == '+' || p.data[p.i] == '-') {
			p.i++
		}
		exponentStart := p.i
		for p.i < len(p.data) && p.data[p.i] >= '0' && p.data[p.i] <= '9' {
			p.i++
		}
		if exponentStart == p.i {
			return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON number 指数不合法")
		}
	}
	raw := string(p.data[start:p.i])
	f, err := strconv.ParseFloat(raw, 64)
	// strconv 对下溢到有限 0 也返回 ErrRange；ECMAScript Number/JCS 接受该值。
	// 真正溢出到 Infinity 仍必须拒绝，避免 Go/TypeScript 数字语义分叉。
	if (err != nil && !errors.Is(err, strconv.ErrRange)) || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, protocolerror.New(protocolerror.InvalidJSON, "JSON number 不能表示为有限 IEEE 754 double")
	}
	return json.Number(raw), nil
}

func (p *parser) skipWhitespace() {
	for p.i < len(p.data) {
		switch p.data[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) consume(expected byte) bool {
	if p.i < len(p.data) && p.data[p.i] == expected {
		p.i++
		return true
	}
	return false
}

// RequireObjectKeys 检查 object 只包含 expected 中定义的字段，并返回缺失字段。
func RequireObjectKeys(object map[string]JSONValue, expected ...string) error {
	allowed := make(map[string]struct{}, len(expected))
	for _, key := range expected {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return protocolerror.New(protocolerror.UnknownField, fmt.Sprintf("未知字段 %q", key))
		}
	}
	return nil
}

// RequireField 返回字段值，并严格区分缺字段与字段值为 null。
func RequireField(object map[string]JSONValue, key string) (JSONValue, error) {
	value, ok := object[key]
	if !ok {
		return nil, protocolerror.New(protocolerror.InvalidJSON, fmt.Sprintf("缺少必需字段 %q", key))
	}
	return value, nil
}

// IsNull 判断 JSON null。
func IsNull(value JSONValue) bool { return value == nil }

// CloneBytes 返回输入字节的防御性复制。
func CloneBytes(input []byte) []byte { return bytes.Clone(input) }
