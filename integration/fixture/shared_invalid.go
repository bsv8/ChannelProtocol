package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

// 这些结构对应 testdata/v1 中的完整非法输入；Go 和 TypeScript 驱动器按同一文件顺序执行。
type sharedNamedCase struct {
	Name         string `json:"name"`
	JSON         string `json:"json"`
	ExpectedCode string `json:"expected_code"`
}

type sharedJCSInvalidFixture struct {
	Cases []sharedNamedCase `json:"cases"`
}

type sharedPrimitiveCase struct {
	Name         string          `json:"name"`
	Operation    string          `json:"operation"`
	Value        json.RawMessage `json:"value"`
	ExpectedCode string          `json:"expected_code"`
}

type sharedPrimitiveInvalidFixture struct {
	Cases []sharedPrimitiveCase `json:"cases"`
}

type sharedHashInvalidCase struct {
	Name         string `json:"name"`
	Channel      string `json:"channel"`
	NowMs        int64  `json:"now_ms"`
	JSON         string `json:"json"`
	ExpectedCode string `json:"expected_code"`
}

type sharedHashInvalidFixture struct {
	Cases []sharedHashInvalidCase `json:"cases"`
}

type sharedAppInvalidFixture struct {
	Cases []sharedNamedCase `json:"cases"`
}

type sharedWebRTCInvalidCase struct {
	Name         string `json:"name"`
	Operation    string `json:"operation"`
	JSON         string `json:"json"`
	ExpectedCode string `json:"expected_code"`
}

type sharedWebRTCInvalidFixture struct {
	Cases []sharedWebRTCInvalidCase `json:"cases"`
}

type sharedInboxInvalidCase struct {
	Name                string          `json:"name"`
	Operation           string          `json:"operation"`
	Channel             string          `json:"channel"`
	RecipientPrivateKey string          `json:"recipient_private_key_hex"`
	Envelope            json.RawMessage `json:"envelope"`
	ExpectedCode        string          `json:"expected_code"`
}

type sharedInboxInvalidFixture struct {
	Cases []sharedInboxInvalidCase `json:"cases"`
}

// validateSharedValidFixtures 让跨语言 driver 也读取所有合法 fixture，而不只验证 interop happy path。
func validateSharedValidFixtures(input fixture) error {
	read := func(name string, target any) error {
		data, err := os.ReadFile("testdata/v1/" + name)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target)
	}

	var jcsValid struct {
		Cases []struct {
			Name string `json:"name"`
			JSON string `json:"input"`
			Hex  string `json:"expected_utf8_hex"`
		} `json:"cases"`
	}
	if err := read("jcs-valid.json", &jcsValid); err != nil {
		return err
	}
	for _, item := range jcsValid.Cases {
		canonical, err := channels.CanonicalizeJSON([]byte(item.JSON))
		if err != nil {
			return fmt.Errorf("JCS valid fixture %s: %w", item.Name, err)
		}
		if got := hex.EncodeToString(canonical); got != item.Hex {
			return fmt.Errorf("JCS valid fixture %s expected %s got %s", item.Name, item.Hex, got)
		}
	}

	var primitives struct {
		PublicKey  string      `json:"public_key"`
		MessageID  string      `json:"message_id"`
		SessionID  string      `json:"session_id"`
		SHA256     string      `json:"sha256"`
		UnixMillis json.Number `json:"unix_millis"`
	}
	if err := read("primitives-valid.json", &primitives); err != nil {
		return err
	}
	if _, err := channels.ParsePublicKey(primitives.PublicKey); err != nil {
		return err
	}
	if _, err := channels.ParseMessageID(primitives.MessageID); err != nil {
		return err
	}
	if _, err := channels.ParseSessionID(primitives.SessionID); err != nil {
		return err
	}
	if _, err := channels.ParseSHA256Hash(primitives.SHA256); err != nil {
		return err
	}
	if _, err := channels.ParseUnixMillis(primitives.UnixMillis); err != nil {
		return err
	}

	var hashValid struct {
		MultiaddrCases []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"multiaddr_cases"`
	}
	if err := read("hash-request-valid.json", &hashValid); err != nil {
		return err
	}
	for _, item := range hashValid.MultiaddrCases {
		if _, err := hashrequest.NewMultiaddrLocator(item.Address); err != nil {
			return fmt.Errorf("multiaddr valid fixture %s: %w", item.Name, err)
		}
	}

	var appValid struct {
		Deliver json.RawMessage `json:"deliver"`
		Ack     json.RawMessage `json:"ack"`
	}
	if err := read("app-message-valid.json", &appValid); err != nil {
		return err
	}
	if _, err := appmessage.ParseBody(appValid.Deliver); err != nil {
		return err
	}
	if _, err := appmessage.ParseBody(appValid.Ack); err != nil {
		return err
	}

	var webRTCValid struct {
		RequestMessageID string            `json:"request_message_id"`
		SessionID        string            `json:"session_id"`
		Signals          []json.RawMessage `json:"signals"`
	}
	if err := read("webrtc-signal-valid.json", &webRTCValid); err != nil {
		return err
	}
	for _, signal := range webRTCValid.Signals {
		body := map[string]any{
			"request_message_id": webRTCValid.RequestMessageID,
			"session_id":         webRTCValid.SessionID,
			"signal":             signal,
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if _, err := webrtcsignal.ParseBody(bodyJSON); err != nil {
			return err
		}
	}

	return nil
}

func sharedInvalidResults(input fixture) ([]errorResult, error) {
	results := make([]errorResult, 0)
	appendResult := func(prefix, name, expected string, err error) error {
		actual := errorCode(err)
		if actual != expected {
			return fmt.Errorf("shared fixture %s/%s expected %s got %s", prefix, name, expected, actual)
		}
		results = append(results, errorResult{Name: prefix + "/" + name, Code: actual})
		return nil
	}
	read := func(name string, target any) error {
		data, err := os.ReadFile("testdata/v1/" + name)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target)
	}

	var jcsInvalid sharedJCSInvalidFixture
	if err := read("jcs-invalid.json", &jcsInvalid); err != nil {
		return nil, err
	}
	for _, item := range jcsInvalid.Cases {
		if err := appendResult("jcs-invalid", item.Name, item.ExpectedCode, canonicalizeJSONError([]byte(item.JSON))); err != nil {
			return nil, err
		}
	}

	var primitiveInvalid sharedPrimitiveInvalidFixture
	if err := read("primitives-invalid.json", &primitiveInvalid); err != nil {
		return nil, err
	}
	for _, item := range primitiveInvalid.Cases {
		itemErr, err := sharedPrimitiveError(item)
		if err != nil {
			return nil, err
		}
		if err := appendResult("primitives-invalid", item.Name, item.ExpectedCode, itemErr); err != nil {
			return nil, err
		}
	}

	var hashInvalid sharedHashInvalidFixture
	if err := read("hash-request-invalid.json", &hashInvalid); err != nil {
		return nil, err
	}
	for _, item := range hashInvalid.Cases {
		if err := appendResult("hash-request-invalid", item.Name, item.ExpectedCode, hashRequestFixtureError(item.Channel, []byte(item.JSON), item.NowMs)); err != nil {
			return nil, err
		}
	}

	var appInvalid sharedAppInvalidFixture
	if err := read("app-message-invalid.json", &appInvalid); err != nil {
		return nil, err
	}
	for _, item := range appInvalid.Cases {
		if err := appendResult("app-message-invalid", item.Name, item.ExpectedCode, appBodyFixtureError([]byte(item.JSON))); err != nil {
			return nil, err
		}
	}

	publicA, err := channels.ParsePublicKey(input.PublicKeyA)
	if err != nil {
		return nil, err
	}
	publicB, err := channels.ParsePublicKey(input.PublicKeyB)
	if err != nil {
		return nil, err
	}
	messageID, err := channels.ParseMessageID(input.MessageID)
	if err != nil {
		return nil, err
	}
	sessionID, err := channels.ParseSessionID(input.SessionID)
	if err != nil {
		return nil, err
	}
	offer, err := webrtcsignal.NewOffer(messageID, sessionID, "v=0")
	if err != nil {
		return nil, err
	}
	context, err := webrtcsignal.NewSessionContext(offer, publicA, publicB)
	if err != nil {
		return nil, err
	}

	var webrtcInvalid sharedWebRTCInvalidFixture
	if err := read("webrtc-signal-invalid.json", &webrtcInvalid); err != nil {
		return nil, err
	}
	for _, item := range webrtcInvalid.Cases {
		var itemErr error
		switch item.Operation {
		case "parse":
			itemErr = webrtcBodyFixtureError([]byte(item.JSON))
		case "relation":
			body, parseErr := webrtcsignal.ParseBody([]byte(item.JSON))
			if parseErr != nil {
				return nil, fmt.Errorf("WebRTC relation fixture %s 无法先解析: %w", item.Name, parseErr)
			}
			itemErr = webrtcsignal.ValidateRelation(body, context, publicB)
		default:
			return nil, fmt.Errorf("未知 WebRTC fixture operation: %s", item.Operation)
		}
		if err := appendResult("webrtc-signal-invalid", item.Name, item.ExpectedCode, itemErr); err != nil {
			return nil, err
		}
	}

	var inboxInvalid sharedInboxInvalidFixture
	if err := read("inbox-crypto-invalid.json", &inboxInvalid); err != nil {
		return nil, err
	}
	for _, item := range inboxInvalid.Cases {
		var itemErr error
		switch item.Operation {
		case "parse":
			itemErr = parseEnvelopeFixtureError(item.Channel, item.Envelope)
		case "open", "open_dispatch":
			privateBytes, decodeErr := hex.DecodeString(item.RecipientPrivateKey)
			if decodeErr != nil {
				return nil, fmt.Errorf("inbox fixture %s 私钥不是 hex: %w", item.Name, decodeErr)
			}
			privateKey, keyErr := channels.ParsePrivateKey(privateBytes)
			if keyErr != nil {
				return nil, fmt.Errorf("inbox fixture %s 私钥无效: %w", item.Name, keyErr)
			}
			opened, openErr := inbox.Open(item.Channel, item.Envelope, privateKey, 1500)
			if openErr != nil {
				itemErr = openErr
			} else if item.Operation == "open_dispatch" {
				_, itemErr = inbox.Dispatch(opened)
			}
		default:
			return nil, fmt.Errorf("未知 inbox fixture operation: %s", item.Operation)
		}
		if err := appendResult("inbox-crypto-invalid", item.Name, item.ExpectedCode, itemErr); err != nil {
			return nil, err
		}
	}

	return results, nil
}

func sharedPrimitiveError(item sharedPrimitiveCase) (error, error) {
	var value string
	switch item.Operation {
	case "public_key":
		if err := json.Unmarshal(item.Value, &value); err != nil {
			return nil, err
		}
		_, err := channels.ParsePublicKey(value)
		return err, nil
	case "message_id":
		if err := json.Unmarshal(item.Value, &value); err != nil {
			return nil, err
		}
		_, err := channels.ParseMessageID(value)
		return err, nil
	case "session_id":
		if err := json.Unmarshal(item.Value, &value); err != nil {
			return nil, err
		}
		_, err := channels.ParseSessionID(value)
		return err, nil
	case "sha256":
		if err := json.Unmarshal(item.Value, &value); err != nil {
			return nil, err
		}
		_, err := channels.ParseSHA256Hash(value)
		return err, nil
	case "private_key_hex":
		if err := json.Unmarshal(item.Value, &value); err != nil {
			return nil, err
		}
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return err, nil
		}
		_, err = channels.ParsePrivateKey(decoded)
		return err, nil
	case "unix_millis":
		_, err := channels.ParseUnixMillis(json.Number(string(item.Value)))
		return err, nil
	default:
		return nil, fmt.Errorf("未知 primitive fixture operation: %s", item.Operation)
	}
}

func canonicalizeJSONError(input []byte) error {
	_, err := channels.CanonicalizeJSON(input)
	return err
}

func hashRequestFixtureError(channel string, input []byte, nowMs int64) error {
	_, err := hashrequest.ParseAndVerify(channel, input, nowMs)
	return err
}

func appBodyFixtureError(input []byte) error {
	_, err := appmessage.ParseBody(input)
	return err
}

func webrtcBodyFixtureError(input []byte) error {
	_, err := webrtcsignal.ParseBody(input)
	return err
}

func parseEnvelopeFixtureError(channel string, input []byte) error {
	_, err := inbox.ParseEnvelope(channel, input)
	return err
}
