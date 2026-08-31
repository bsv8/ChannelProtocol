package channels_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/internal/canonicaljson"
	"github.com/bsv8/ChannelProtocol/internal/cryptobox"
	"github.com/bsv8/ChannelProtocol/internal/secp256k1"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

func readFixture[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile("testdata/v1/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSharedJCSAndPrimitiveFixtures(t *testing.T) {
	var valid struct {
		Cases []struct {
			Input string `json:"input"`
			Hex   string `json:"expected_utf8_hex"`
		} `json:"cases"`
	}
	valid = readFixture[struct {
		Cases []struct {
			Input string `json:"input"`
			Hex   string `json:"expected_utf8_hex"`
		} `json:"cases"`
	}](t, "jcs-valid.json")
	for _, item := range valid.Cases {
		actual, err := channels.CanonicalizeJSON([]byte(item.Input))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmtHex(actual); got != item.Hex {
			t.Fatalf("JCS fixture got %s want %s", got, item.Hex)
		}
	}
	var invalid struct {
		Cases []struct {
			JSON string `json:"json"`
			Code string `json:"expected_code"`
		} `json:"cases"`
	}
	invalid = readFixture[struct {
		Cases []struct {
			JSON string `json:"json"`
			Code string `json:"expected_code"`
		} `json:"cases"`
	}](t, "jcs-invalid.json")
	for _, item := range invalid.Cases {
		if err := mustErrorValue(canonicalizeError([]byte(item.JSON)), item.Code); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSharedPrimitiveInvalidFixtures(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Name      string          `json:"name"`
			Operation string          `json:"operation"`
			Value     json.RawMessage `json:"value"`
			Code      string          `json:"expected_code"`
		} `json:"cases"`
	}
	fixture = readFixture[struct {
		Cases []struct {
			Name      string          `json:"name"`
			Operation string          `json:"operation"`
			Value     json.RawMessage `json:"value"`
			Code      string          `json:"expected_code"`
		} `json:"cases"`
	}](t, "primitives-invalid.json")
	for _, item := range fixture.Cases {
		var err error
		switch item.Operation {
		case "public_key":
			var value string
			if unmarshalErr := json.Unmarshal(item.Value, &value); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			_, err = channels.ParsePublicKey(value)
		case "message_id":
			var value string
			if unmarshalErr := json.Unmarshal(item.Value, &value); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			_, err = channels.ParseMessageID(value)
		case "session_id":
			var value string
			if unmarshalErr := json.Unmarshal(item.Value, &value); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			_, err = channels.ParseSessionID(value)
		case "sha256":
			var value string
			if unmarshalErr := json.Unmarshal(item.Value, &value); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			_, err = channels.ParseSHA256Hash(value)
		case "private_key_hex":
			var value string
			if unmarshalErr := json.Unmarshal(item.Value, &value); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			decoded, decodeErr := hex.DecodeString(value)
			if decodeErr != nil {
				err = decodeErr
			} else {
				_, err = channels.ParsePrivateKey(decoded)
			}
		case "unix_millis":
			_, err = channels.ParseUnixMillis(json.Number(string(item.Value)))
		default:
			t.Fatalf("未知 primitive operation: %s", item.Operation)
		}
		if err == nil || !channels.IsErrorCode(err, channels.ErrorCode(item.Code)) {
			t.Fatalf("primitive fixture %s expected %s got %v", item.Name, item.Code, err)
		}
	}
}

func TestSharedNamedInvalidFixtures(t *testing.T) {
	var hashFixture struct {
		Cases []struct {
			Channel string `json:"channel"`
			JSON    string `json:"json"`
			NowMs   int64  `json:"now_ms"`
			Code    string `json:"expected_code"`
		} `json:"cases"`
	}
	hashFixture = readFixture[struct {
		Cases []struct {
			Channel string `json:"channel"`
			JSON    string `json:"json"`
			NowMs   int64  `json:"now_ms"`
			Code    string `json:"expected_code"`
		} `json:"cases"`
	}](t, "hash-request-invalid.json")
	for _, item := range hashFixture.Cases {
		if err := mustErrorValue(hashRequestError(item.Channel, []byte(item.JSON), item.NowMs), item.Code); err != nil {
			t.Fatal(err)
		}
	}

	var appFixture struct {
		Cases []struct {
			JSON string `json:"json"`
			Code string `json:"expected_code"`
		} `json:"cases"`
	}
	appFixture = readFixture[struct {
		Cases []struct {
			JSON string `json:"json"`
			Code string `json:"expected_code"`
		} `json:"cases"`
	}](t, "app-message-invalid.json")
	for _, item := range appFixture.Cases {
		if err := mustErrorValue(appBodyError([]byte(item.JSON)), item.Code); err != nil {
			t.Fatal(err)
		}
	}

	var webrtcFixture struct {
		Cases []struct {
			Name      string `json:"name"`
			Operation string `json:"operation"`
			JSON      string `json:"json"`
			Code      string `json:"expected_code"`
		} `json:"cases"`
	}
	webrtcFixture = readFixture[struct {
		Cases []struct {
			Name      string `json:"name"`
			Operation string `json:"operation"`
			JSON      string `json:"json"`
			Code      string `json:"expected_code"`
		} `json:"cases"`
	}](t, "webrtc-signal-invalid.json")
	for _, item := range webrtcFixture.Cases {
		switch item.Operation {
		case "parse":
			if err := mustErrorValue(webrtcBodyError([]byte(item.JSON)), item.Code); err != nil {
				t.Fatalf("WebRTC fixture %s: %v", item.Name, err)
			}
		case "relation":
			messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			if err != nil {
				t.Fatal(err)
			}
			sessionID, err := channels.ParseSessionID("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk")
			if err != nil {
				t.Fatal(err)
			}
			offer, err := webrtcsignal.NewOffer(messageID, sessionID, "v=0")
			if err != nil {
				t.Fatal(err)
			}
			context, err := webrtcsignal.NewSessionContext(offer, testPublicKey(t, 1), testPublicKey(t, 2))
			if err != nil {
				t.Fatal(err)
			}
			answer, err := webrtcsignal.ParseBody([]byte(item.JSON))
			if err != nil {
				t.Fatal(err)
			}
			if err := mustErrorValue(webrtcsignal.ValidateRelation(answer, context, testPublicKey(t, 2)), item.Code); err != nil {
				t.Fatalf("WebRTC fixture %s: %v", item.Name, err)
			}
		default:
			t.Fatalf("未知 WebRTC fixture operation: %s", item.Operation)
		}
	}

	var hashValid struct {
		MultiaddrCases []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"multiaddr_cases"`
	}
	hashValid = readFixture[struct {
		MultiaddrCases []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"multiaddr_cases"`
	}](t, "hash-request-valid.json")
	for _, item := range hashValid.MultiaddrCases {
		if _, err := hashrequest.NewMultiaddrLocator(item.Address); err != nil {
			t.Fatalf("multiaddr fixture %s: %v", item.Name, err)
		}
	}

	var signaturePublic struct {
		Digest    string `json:"digest_hex"`
		Signature string `json:"signature"`
	}
	signaturePublic = readFixture[struct {
		Digest    string `json:"digest_hex"`
		Signature string `json:"signature"`
	}](t, "signature-public.json")
	message := fixedHashMessageForFixture(t)
	if message.SignedDigest().String() != signaturePublic.Digest || message.Signature.String() != signaturePublic.Signature {
		t.Fatal("公开签名 fixture 与 Go 结果不一致")
	}
}

func TestSharedInboxCryptoFixtureAndInvalidCases(t *testing.T) {
	valid := readFixture[struct {
		SharedSecret string `json:"shared_secret_hex"`
		Info         string `json:"hkdf_info_hex"`
		MessageKey   string `json:"message_key_hex"`
		Salt         string `json:"kdf_salt"`
		Nonce        string `json:"nonce"`
		AAD          string `json:"aad_hex"`
		Plaintext    string `json:"plaintext_json"`
		Ciphertext   string `json:"ciphertext_hex"`
		Tag          string `json:"tag_hex"`
		EnvelopeHash string `json:"envelope_json_sha256_hex"`
	}](t, "inbox-crypto-valid.json")
	if valid.SharedSecret == "" || valid.Info == "" || valid.MessageKey == "" || valid.Salt == "" || valid.Nonce == "" || valid.AAD == "" || valid.Plaintext == "" || valid.Ciphertext == "" || valid.Tag == "" || valid.EnvelopeHash == "" {
		t.Fatal("私密加密 fixture 缺少固定密码学字段")
	}
	envelope, senderPrivate, recipientPrivate, _ := fixedEnvelopeForFixture(t)
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := inbox.Open(envelope.Channel, envelopeJSON, recipientPrivate, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Digest().String() == "" || !bytes.Equal(envelope.KDFSalt(), bytes.Repeat([]byte{0}, inbox.KDFSaltBytes)) {
		t.Fatal("固定信封没有使用预期 salt")
	}
	if got := fmtHex(envelope.Ciphertext()[:len(envelope.Ciphertext())-inbox.GCMTagBytes]); got != valid.Ciphertext || fmtHex(envelope.Ciphertext()[len(envelope.Ciphertext())-inbox.GCMTagBytes:]) != valid.Tag {
		t.Fatal("固定密文或 GCM tag 与 fixture 不一致")
	}
	envelopeDigest := sha256.Sum256(envelopeJSON)
	if fmtHex(envelopeDigest[:]) != valid.EnvelopeHash {
		t.Fatal("固定信封 JSON 摘要与 fixture 不一致")
	}

	// 独立重建 info、AAD、ECDH 和 HKDF，确认 fixture 不是运行时被测实现自生成的期望值。
	_, senderPublic := testKey(t, 1)
	recipientPublic := testPublicKey(t, 2)
	shared, err := secp256k1.ECDH(senderPrivate, recipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptobox.Clear(shared)
	if fmtHex(shared) != valid.SharedSecret {
		t.Fatal("ECDH shared secret 与 fixture 不一致")
	}
	salt, err := base64.RawURLEncoding.Strict().DecodeString(valid.Salt)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(valid.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	info, err := canonicaljson.CanonicalizeValue(map[string]any{"scope": "bsv8.inbox.envelope.v1", "channel": envelope.Channel, "from_public_key": senderPublic.String()})
	if err != nil {
		t.Fatal(err)
	}
	if fmtHex(info) != valid.Info {
		t.Fatalf("HKDF info 与 fixture 不一致: got %s want %s", fmtHex(info), valid.Info)
	}
	aad, err := canonicaljson.CanonicalizeValue(map[string]any{"channel": envelope.Channel, "envelope_version": channels.InboxEnvelopeVersion, "from_public_key": senderPublic.String(), "kdf_salt": valid.Salt, "nonce": valid.Nonce})
	if err != nil {
		t.Fatal(err)
	}
	if fmtHex(aad) != valid.AAD {
		t.Fatal("AAD 与 fixture 不一致")
	}
	key, err := cryptobox.DeriveKey(shared, salt, info)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptobox.Clear(key)
	if fmtHex(key) != valid.MessageKey {
		t.Fatal("HKDF message key 与 fixture 不一致")
	}
	ciphertext, err := cryptobox.Encrypt(key, nonce, []byte(valid.Plaintext), aad)
	if err != nil {
		t.Fatal(err)
	}
	if fmtHex(ciphertext) != valid.Ciphertext+valid.Tag {
		t.Fatal("独立 AES-GCM 结果与 fixture 不一致")
	}

	var invalid struct {
		Cases []struct {
			Name                string         `json:"name"`
			Operation           string         `json:"operation"`
			Channel             string         `json:"channel"`
			RecipientPrivateKey string         `json:"recipient_private_key_hex"`
			Envelope            map[string]any `json:"envelope"`
			Code                string         `json:"expected_code"`
		} `json:"cases"`
	}
	invalid = readFixture[struct {
		Cases []struct {
			Name                string         `json:"name"`
			Operation           string         `json:"operation"`
			Channel             string         `json:"channel"`
			RecipientPrivateKey string         `json:"recipient_private_key_hex"`
			Envelope            map[string]any `json:"envelope"`
			Code                string         `json:"expected_code"`
		} `json:"cases"`
	}](t, "inbox-crypto-invalid.json")
	_ = envelopeJSON
	for _, item := range invalid.Cases {
		channel := item.Channel
		var err error
		envelopeInput := mustJSON(item.Envelope)
		switch item.Operation {
		case "parse":
			err = envelopeError(channel, envelopeInput)
		case "open", "open_dispatch":
			privateBytes, decodeErr := hex.DecodeString(item.RecipientPrivateKey)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			privateKey, keyErr := channels.ParsePrivateKey(privateBytes)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			opened, openErr := inbox.Open(channel, envelopeInput, privateKey, 1500)
			if openErr != nil {
				err = openErr
			} else if item.Operation == "open_dispatch" {
				_, err = inbox.Dispatch(opened)
			}
		default:
			t.Fatalf("未知 inbox fixture operation: %s", item.Operation)
		}
		if err := mustErrorValue(err, item.Code); err != nil {
			t.Fatalf("inbox fixture %s: %v", item.Name, err)
		}
	}
}

func fixedHashMessageForFixture(t *testing.T) hashrequest.SignedMessage {
	t.Helper()
	privateKey, publicKey := testKey(t, 1)
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := channels.ParseSHA256Hash("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	message, err := hashrequest.Sign(hashrequest.UnsignedMessage{FromPublicKey: publicKey, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: hashrequest.HashRequestBody{Hash: hash, Locators: []hashrequest.Locator{hashrequest.NewWebRTCSDPLocator()}}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func fixedEnvelopeForFixture(t *testing.T) (inbox.EncryptedEnvelopeV1, channels.PrivateKey, channels.PrivateKey, channels.PublicKey) {
	t.Helper()
	senderPrivate, senderPublic := testKey(t, 1)
	recipientPrivate, recipientPublic := testKey(t, 2)
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := channels.ParseSessionID("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk")
	if err != nil {
		t.Fatal(err)
	}
	body, err := webrtcsignal.NewOffer(messageID, sessionID, "v=0")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(recipientPublic), FromPublicKey: senderPublic, Protocol: channels.WebRTCSignalProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: body}, senderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return mustEnvelope(inbox.SealSigned(signed, senderPrivate, bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x21}, 12)...)))), senderPrivate, recipientPrivate, recipientPublic
}

func mustEnvelope(value inbox.EncryptedEnvelopeV1, err error) inbox.EncryptedEnvelopeV1 {
	if err != nil {
		panic(err)
	}
	return value
}

func testPublicKey(t *testing.T, value byte) channels.PublicKey {
	_, publicKey := testKey(t, value)
	return publicKey
}

func cloneObject(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func mustJSON(value any) []byte {
	result, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return result
}

func fmtHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&15]
	}
	return string(result)
}

func canonicalizeError(input []byte) error {
	_, err := channels.CanonicalizeJSON(input)
	return err
}

func hashRequestError(channel string, input []byte, nowMs int64) error {
	_, err := hashrequest.ParseAndVerify(channel, input, nowMs)
	return err
}

func appBodyError(input []byte) error {
	_, err := appmessage.ParseBody(input)
	return err
}

func webrtcBodyError(input []byte) error {
	_, err := webrtcsignal.ParseBody(input)
	return err
}

func envelopeError(channel string, input []byte) error {
	_, err := inbox.ParseEnvelope(channel, input)
	return err
}

func openError(channel string, input []byte, privateKey channels.PrivateKey, nowMs int64) error {
	_, err := inbox.Open(channel, input, privateKey, nowMs)
	return err
}

func mustErrorValue(err error, expected string) error {
	if err == nil {
		return &fixtureError{message: "expected error " + expected}
	}
	if !channels.IsErrorCode(err, channels.ErrorCode(expected)) {
		return &fixtureError{message: "expected " + expected + " got " + err.Error()}
	}
	return nil
}

type fixtureError struct{ message string }

func (e *fixtureError) Error() string { return e.message }
