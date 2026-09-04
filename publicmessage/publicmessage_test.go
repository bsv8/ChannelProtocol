package publicmessage_test

import (
	"bytes"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
	"github.com/bsv8/ChannelProtocol/publicmessage"
)

type publicMessageValidFixture struct {
	PrivateKey string                   `json:"test_only_private_key_hex"`
	PublicKey  string                   `json:"public_key"`
	MessageID  string                   `json:"message_id"`
	Cases      []publicMessageValidCase `json:"cases"`
}

type publicMessageValidCase struct {
	Name      string                    `json:"name"`
	Channel   string                    `json:"channel"`
	IssuedAt  int64                     `json:"issued_at_ms"`
	ExpiresAt int64                     `json:"expires_at_ms"`
	Now       int64                     `json:"now_ms"`
	Body      stdjson.RawMessage        `json:"body"`
	Expected  publicMessageExpectedCase `json:"expected"`
}

type publicMessageExpectedCase struct {
	JSON      string   `json:"json"`
	Digest    string   `json:"digest_hex"`
	Signature string   `json:"signature"`
	DedupKey  []string `json:"dedup_key"`
}

type publicMessageInvalidFixture struct {
	Cases []publicMessageInvalidCase `json:"cases"`
}

type publicMessageInvalidCase struct {
	Name          string `json:"name"`
	Operation     string `json:"operation"`
	Channel       string `json:"channel"`
	ChannelRepeat int    `json:"channel_repeat"`
	Now           int64  `json:"now_ms"`
	Mutation      string `json:"mutation"`
	JSON          string `json:"json"`
	Generator     string `json:"generator"`
	Existing      string `json:"existing"`
	Incoming      string `json:"incoming"`
	Expected      string `json:"expected_code"`
}

func TestSharedPublicMessageValidFixture(t *testing.T) {
	fixture := readPublicMessageValidFixture(t)
	privateKey := parseFixturePrivateKey(t, fixture.PrivateKey)
	publicKey, err := channels.ParsePublicKey(fixture.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := channels.ParseMessageID(fixture.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if publicmessage.MaxLifetimeMs() != 600_000 || publicmessage.MaxFutureSkewMs() != 60_000 {
		t.Fatalf("公开消息时间常量不匹配: lifetime=%d skew=%d", publicmessage.MaxLifetimeMs(), publicmessage.MaxFutureSkewMs())
	}

	for _, item := range fixture.Cases {
		body, err := strictjson.Parse(item.Body)
		if err != nil {
			t.Fatalf("%s body: %v", item.Name, err)
		}
		signed, err := publicmessage.Sign(publicmessage.UnsignedMessage{
			Channel:       item.Channel,
			FromPublicKey: publicKey,
			MessageID:     messageID,
			IssuedAtMs:    item.IssuedAt,
			ExpiresAtMs:   item.ExpiresAt,
			Body:          body,
		}, privateKey)
		if err != nil {
			t.Fatalf("%s Sign: %v", item.Name, err)
		}
		wire, err := publicmessage.Marshal(signed)
		if err != nil {
			t.Fatalf("%s Marshal: %v", item.Name, err)
		}
		if string(wire) != item.Expected.JSON {
			t.Fatalf("%s JSON 不一致:\nexpected %s\nactual   %s", item.Name, item.Expected.JSON, wire)
		}
		signedDigest, err := signed.SignedDigest()
		if err != nil {
			t.Fatalf("%s SignedDigest: %v", item.Name, err)
		}
		if signed.Signature.String() != item.Expected.Signature || signedDigest.String() != item.Expected.Digest {
			t.Fatalf("%s 签名或摘要不一致", item.Name)
		}

		verified, err := publicmessage.ParseAndVerify(item.Channel, wire, item.Now)
		if err != nil {
			t.Fatalf("%s ParseAndVerify: %v", item.Name, err)
		}
		if !verified.IsVerified() || verified.Digest().String() != item.Expected.Digest || verified.Signature().String() != item.Expected.Signature {
			t.Fatalf("%s 验证结果不一致", item.Name)
		}
		key := verified.DedupKey()
		actualKey := []string{key.Channel, key.FromPublicKey.String(), key.MessageID.String()}
		if fmt.Sprint(actualKey) != fmt.Sprint(item.Expected.DedupKey) {
			t.Fatalf("%s 去重键不一致: expected %v actual %v", item.Name, item.Expected.DedupKey, actualKey)
		}
	}
}

func TestPublicMessageInvalidFixture(t *testing.T) {
	valid := readPublicMessageValidFixture(t)
	invalid := publicMessageInvalidFixture{}
	readFixture(t, "public-message-invalid.json", &invalid)
	base := valid.Cases[0].Expected.JSON
	for _, item := range invalid.Cases {
		t.Run(item.Name, func(t *testing.T) {
			if item.Operation == "conflict" {
				existing, err := channels.ParseSHA256Hash(item.Existing)
				if err != nil {
					t.Fatal(err)
				}
				incoming, err := channels.ParseSHA256Hash(item.Incoming)
				if err != nil {
					t.Fatal(err)
				}
				err = publicmessage.CheckDigestConflict(existing, incoming)
				if got := publicMessageErrorCode(err); got != item.Expected {
					t.Fatalf("expected %s got %s (%v)", item.Expected, got, err)
				}
				return
			}

			var err error
			switch item.Operation {
			case "parse_raw":
				_, err = publicmessage.ParseAndVerify(item.Channel, []byte(item.JSON), item.Now)
			case "generated":
				err = parseGeneratedInvalid(item, base)
			default:
				input := mutatePublicMessage(t, base, item.Mutation)
				channel := item.Channel
				if item.ChannelRepeat != 0 {
					channel += strings.Repeat("a", item.ChannelRepeat)
				}
				_, err = publicmessage.ParseAndVerify(channel, input, item.Now)
			}
			if got := publicMessageErrorCode(err); got != item.Expected {
				t.Fatalf("expected %s got %s (%v)", item.Expected, got, err)
			}
		})
	}

	if got := publicMessageErrorCode(publicmessage.ValidateChannel(string([]byte{0xff}))); got != string(channels.ErrInvalidChannel.Code) {
		t.Fatalf("非法 UTF-8 channel expected INVALID_CHANNEL got %s", got)
	}
}

func TestPublicMessageVerifiedSnapshotsAreDefensive(t *testing.T) {
	privateKey := parseFixturePrivateKey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	publicKey, err := channels.PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	nested := map[string]any{
		"number": stdjson.Number("9007199254740991"),
		"nested": map[string]any{"items": []any{stdjson.Number("1e-7"), "before"}},
	}
	signed, err := publicmessage.Sign(publicmessage.UnsignedMessage{
		Channel:       "bsv8.public.snapshot.v1",
		FromPublicKey: publicKey,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          nested,
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	originalWire, err := publicmessage.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest, err := signed.SignedDigest()
	if err != nil {
		t.Fatal(err)
	}
	nested["number"] = stdjson.Number("1")
	nested["nested"].(map[string]any)["items"].([]any)[1] = "after"
	wireAfterInputMutation, err := publicmessage.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	afterDigest, err := signed.SignedDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalWire, wireAfterInputMutation) || !originalDigest.Equal(afterDigest) {
		t.Fatal("修改 Sign 输入后的原始嵌套 map/slice 改变了已签名快照")
	}
	broken := signed
	broken.Body = make(chan int)
	if _, err := broken.SignedDigest(); err == nil {
		t.Fatal("无法 JCS 化的 SignedMessage body 必须返回摘要错误")
	}

	verified, err := publicmessage.ParseAndVerify("bsv8.public.snapshot.v1", originalWire, 1500)
	if err != nil {
		t.Fatal(err)
	}
	bodyCopy := verified.Body().(map[string]strictjson.JSONValue)
	bodyCopy["number"] = stdjson.Number("1")
	bodyCopy["nested"].(map[string]strictjson.JSONValue)["items"].([]strictjson.JSONValue)[1] = "after"
	signedCopy := verified.SignedMessage()
	signedCopy.Body.(map[string]strictjson.JSONValue)["number"] = stdjson.Number("1")
	if !bytes.Equal(originalWire, mustMarshalPublic(t, verified.SignedMessage())) {
		t.Fatal("修改验签结果副本后规范 JSON 发生变化")
	}
	if verified.Body().(map[string]strictjson.JSONValue)["number"] != stdjson.Number("9007199254740991") {
		t.Fatal("验签结果内部 body 被副本修改")
	}
	if verified.Digest().String() != originalDigest.String() || verified.Signature().String() != signed.Signature.String() {
		t.Fatal("验签结果摘要或签名被副本修改")
	}
	if (publicmessage.VerifiedMessage{}).IsVerified() {
		t.Fatal("零值 VerifiedMessage 不应通过 IsVerified")
	}
}

func readPublicMessageValidFixture(t *testing.T) publicMessageValidFixture {
	t.Helper()
	var fixture publicMessageValidFixture
	readFixture(t, "public-message-valid.json", &fixture)
	return fixture
}

func readFixture(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile("../testdata/v1/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := stdjson.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func parseFixturePrivateKey(t *testing.T, value string) channels.PrivateKey {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	key, err := channels.ParsePrivateKey(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mutatePublicMessage(t *testing.T, base, mutation string) []byte {
	t.Helper()
	if mutation == "none" {
		return []byte(base)
	}
	var object map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal([]byte(base), &object); err != nil {
		t.Fatal(err)
	}
	set := func(field string, value any) {
		raw, err := stdjson.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		object[field] = raw
	}
	switch mutation {
	case "missing_body":
		delete(object, "body")
	case "missing_signature":
		delete(object, "signature")
	case "unknown_field":
		set("unknown", 1)
	case "content_old_shape":
		delete(object, "body")
		set("content", map[string]any{"legacy": true})
	case "wrong_public_key_type":
		set("from_public_key", 1)
	case "issued_equals_expires":
		set("issued_at_ms", 2000)
	case "lifetime_over_max":
		set("expires_at_ms", 601001)
	case "future_skew_over_max":
		set("issued_at_ms", 61001)
		set("expires_at_ms", 661001)
	case "wrong_public_key":
		set("from_public_key", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	case "wrong_signature":
		set("signature", "AAAA")
	case "high_s_signature":
		set("signature", "MEYCIQCxjq-UdL-zqecurQmubV2d3utTgDMA2IDsiMy6u5hlNwIhAPnZHMoNmmiRZouM9yy6amfqHJmlDd9SDYcXXForlxYe")
	case "tampered_body":
		set("body", map[string]any{"tampered": true})
	case "tampered_message_id":
		set("message_id", "AQ"+strings.Repeat("A", 41))
	case "tampered_time":
		set("issued_at_ms", 1001)
	default:
		t.Fatalf("unknown public-message mutation %q", mutation)
	}
	result, err := stdjson.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func parseGeneratedInvalid(item publicMessageInvalidCase, base string) error {
	switch item.Generator {
	case "oversized":
		var object map[string]stdjson.RawMessage
		if err := stdjson.Unmarshal([]byte(base), &object); err != nil {
			return err
		}
		body, err := stdjson.Marshal(strings.Repeat("x", strictjson.MaxJSONBytes))
		if err != nil {
			return err
		}
		object["body"] = body
		input, err := stdjson.Marshal(object)
		if err != nil {
			return err
		}
		_, err = publicmessage.ParseAndVerify(item.Channel, input, item.Now)
		return err
	case "too_deep":
		input := []byte(strings.Repeat("[", strictjson.MaxJSONDepth+1) + "0" + strings.Repeat("]", strictjson.MaxJSONDepth+1))
		_, err := publicmessage.ParseAndVerify(item.Channel, input, item.Now)
		return err
	case "too_many_nodes":
		input := []byte("[" + strings.TrimSuffix(strings.Repeat("0,", strictjson.MaxJSONNodes), ",") + "]")
		_, err := publicmessage.ParseAndVerify(item.Channel, input, item.Now)
		return err
	default:
		return fmt.Errorf("unknown invalid generator %q", item.Generator)
	}
}

func mustMarshalPublic(t *testing.T, message publicmessage.SignedMessage) []byte {
	t.Helper()
	result, err := publicmessage.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func publicMessageErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var structured *channels.ChannelProtocolError
	if errors.As(err, &structured) {
		return string(structured.Code)
	}
	return "UNKNOWN"
}
