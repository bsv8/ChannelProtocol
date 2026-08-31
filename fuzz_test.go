package channels_test

import (
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
)

// FuzzStrictJSONParser 证明严格 JSON 入口面对任意字节只返回值或错误，不 panic。
func FuzzStrictJSONParser(f *testing.F) {
	f.Add([]byte(`{"a":[1,true,null]}`))
	f.Add([]byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = channels.CanonicalizeJSON(input)
	})
}

// FuzzHashRequestParser 以公开协议入口覆盖随机 JSON、字段和签名解析。
func FuzzHashRequestParser(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"from_public_key":"bad"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = hashrequest.ParseAndVerify(channels.HashRequestChannel, input, 0)
	})
}

// FuzzEnvelopeParser 以固定合法 channel 覆盖随机信封输入，不执行网络和解密。
func FuzzEnvelopeParser(f *testing.F) {
	channel := "bsv8.inbox.02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"envelope_version":1,"from_public_key":"bad"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = inbox.ParseEnvelope(channel, input)
	})
}
