package channels_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bsv8/ChannelProtocol"
)

func TestCanonicalJSONUsesECMAScriptNumberAndUTF16Rules(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "key order", input: `{"b":2,"a":1}`, expected: `{"a":1,"b":2}`},
		{name: "number boundaries", input: `{"numbers":[1e21,1e20,1e-7,1e-6,0,-0,4.50,2.0]}`, expected: `{"numbers":[1e+21,100000000000000000000,1e-7,0.000001,0,0,4.5,2]}`},
		{name: "unicode", input: `{"é":"é","😀":"x"}`, expected: `{"é":"é","😀":"x"}`},
		{name: "UTF-16 key order", input: `{"\ue000":2,"\ud83d\ude00":1}`, expected: `{"😀":1,"":2}`},
		{name: "scalar", input: `123`, expected: `123`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := channels.CanonicalizeJSON([]byte(testCase.input))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, []byte(testCase.expected)) {
				t.Fatalf("JCS 不一致: got %s, want %s", actual, testCase.expected)
			}
		})
	}
}

func TestStrictJSONRejectsDuplicateAndUnpairedSurrogate(t *testing.T) {
	for _, input := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`} {
		if _, err := channels.CanonicalizeJSON([]byte(input)); err == nil {
			t.Fatalf("非法 JSON 未被拒绝: %s", input)
		}
	}
}

func TestJSONResourceLimits(t *testing.T) {
	tooDeep := bytes.Repeat([]byte{'['}, channels.MaxJSONDepth+1)
	tooDeep = append(tooDeep, '0')
	tooDeep = append(tooDeep, bytes.Repeat([]byte{']'}, channels.MaxJSONDepth+1)...)
	if _, err := channels.CanonicalizeJSON(tooDeep); !errors.Is(err, channels.ErrMessageTooLarge) {
		t.Fatalf("过深 JSON 未返回 MESSAGE_TOO_LARGE: %v", err)
	}
	tooLarge := append([]byte{'"'}, bytes.Repeat([]byte{'x'}, channels.MaxJSONBytes)...)
	tooLarge = append(tooLarge, '"')
	if _, err := channels.CanonicalizeJSON(tooLarge); !errors.Is(err, channels.ErrMessageTooLarge) {
		t.Fatalf("超大 JSON 未返回 MESSAGE_TOO_LARGE: %v", err)
	}
	tooManyNodes := []byte{'['}
	for index := 0; index < channels.MaxJSONNodes; index++ {
		if index > 0 {
			tooManyNodes = append(tooManyNodes, ',')
		}
		tooManyNodes = append(tooManyNodes, '0')
	}
	tooManyNodes = append(tooManyNodes, ']')
	if _, err := channels.CanonicalizeJSON(tooManyNodes); !errors.Is(err, channels.ErrMessageTooLarge) {
		t.Fatalf("超多节点 JSON 未返回 MESSAGE_TOO_LARGE: %v", err)
	}
}
