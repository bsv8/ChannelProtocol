// Command fixture 读取 testdata/v1 固定向量，独立构造 Go 结果供跨语言比较。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
	"github.com/bsv8/ChannelProtocol/publicmessage"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

type fixture struct {
	JCS                 []jcsCase       `json:"jcs"`
	TestOnlyPrivateKeyA string          `json:"test_only_private_key_a_hex"`
	TestOnlyPrivateKeyB string          `json:"test_only_private_key_b_hex"`
	PublicKeyA          string          `json:"public_key_a"`
	PublicKeyB          string          `json:"public_key_b"`
	MessageID           string          `json:"message_id"`
	SessionID           string          `json:"session_id"`
	Hash                string          `json:"hash"`
	Channel             string          `json:"channel"`
	IssuedAtMs          int64           `json:"issued_at_ms"`
	ExpiresAtMs         int64           `json:"expires_at_ms"`
	HashRequest         hashExpected    `json:"hash_request"`
	PrivateMessage      privateExpected `json:"private_message"`
	InvalidErrorCodes   []invalidCase   `json:"invalid_error_codes"`
}

type jcsCase struct {
	Name            string `json:"name"`
	Input           string `json:"input"`
	ExpectedUTF8Hex string `json:"expected_utf8_hex"`
}

type hashExpected struct {
	DigestHex string `json:"digest_hex"`
	Signature string `json:"signature"`
}

type privateExpected struct {
	DigestHex string         `json:"digest_hex"`
	Signature string         `json:"signature"`
	Salt      string         `json:"salt"`
	Nonce     string         `json:"nonce"`
	Plaintext map[string]any `json:"plaintext"`
	Envelope  map[string]any `json:"envelope"`
}

type invalidCase struct {
	Name         string `json:"name"`
	JSON         string `json:"json"`
	ExpectedCode string `json:"expected_code"`
}

type result struct {
	JCS            []jcsResult          `json:"jcs"`
	HashRequest    hashResult           `json:"hash_request"`
	PrivateMessage privateResult        `json:"private_message"`
	PublicMessage  publicMessageResult  `json:"public_message"`
	DedupRelations dedupRelationsResult `json:"dedup_relations"`
	Invalid        []errorResult        `json:"invalid"`
}

type jcsResult struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
}

type hashResult struct {
	JSON      string `json:"json"`
	DigestHex string `json:"digest_hex"`
	Signature string `json:"signature"`
}

type privateResult struct {
	PlaintextJSON  string `json:"plaintext_json"`
	EnvelopeJSON   string `json:"envelope_json"`
	DigestHex      string `json:"digest_hex"`
	Signature      string `json:"signature"`
	OpenedProtocol string `json:"opened_protocol"`
	OpenedBody     string `json:"opened_body"`
}

type publicMessageResult struct {
	Cases   []publicMessageCaseResult `json:"cases"`
	Invalid []errorResult             `json:"invalid"`
}

type publicMessageCaseResult struct {
	Name      string   `json:"name"`
	JSON      string   `json:"json"`
	DigestHex string   `json:"digest_hex"`
	Signature string   `json:"signature"`
	BodyJSON  string   `json:"body_json"`
	DedupKey  []string `json:"dedup_key"`
}

type publicMessageValidFixture struct {
	PrivateKey string                   `json:"test_only_private_key_hex"`
	PublicKey  string                   `json:"public_key"`
	MessageID  string                   `json:"message_id"`
	Cases      []publicMessageValidCase `json:"cases"`
}

type publicMessageValidCase struct {
	Name      string                `json:"name"`
	Channel   string                `json:"channel"`
	IssuedAt  int64                 `json:"issued_at_ms"`
	ExpiresAt int64                 `json:"expires_at_ms"`
	Now       int64                 `json:"now_ms"`
	Body      json.RawMessage       `json:"body"`
	Expected  publicMessageExpected `json:"expected"`
}

type publicMessageExpected struct {
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

type errorResult struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

func main() {
	var input fixture
	data, err := os.ReadFile("testdata/v1/interop-v1.json")
	if err != nil {
		fatal(err)
	}
	if err := json.Unmarshal(data, &input); err != nil {
		fatal(err)
	}
	output, err := build(input)
	if err != nil {
		fatal(err)
	}
	if len(os.Args) == 3 && os.Args[1] == "--verify-ts" {
		foreign, err := os.ReadFile(os.Args[2])
		if err != nil {
			fatal(err)
		}
		if err := verifyForeignResult(input, foreign); err != nil {
			fatal(err)
		}
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(encoded))
}

// verifyForeignResult 读取 TypeScript 构造的 JSON，验证 Go 能独立解析、验签和解密。
func verifyForeignResult(input fixture, data []byte) error {
	var foreign result
	if err := json.Unmarshal(data, &foreign); err != nil {
		return fmt.Errorf("TypeScript fixture 输出不是 result JSON: %w", err)
	}
	privateB, err := parsePrivateKey(input.TestOnlyPrivateKeyB)
	if err != nil {
		return err
	}
	publicJSON := []byte(foreign.HashRequest.JSON)
	verifiedPublic, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, publicJSON, input.IssuedAtMs+500)
	if err != nil {
		return fmt.Errorf("Go 无法验签 TypeScript 公开消息: %w", err)
	}
	if verifiedPublic.Signature().String() != input.HashRequest.Signature || verifiedPublic.Digest().String() != input.HashRequest.DigestHex {
		return errors.New("TypeScript 公开消息摘要或签名不匹配")
	}
	envelopeJSON := []byte(foreign.PrivateMessage.EnvelopeJSON)
	opened, err := inbox.Open(input.Channel, envelopeJSON, privateB, input.IssuedAtMs+500)
	if err != nil {
		return fmt.Errorf("Go 无法解密 TypeScript 私密信封: %w", err)
	}
	if opened.Signature().String() != input.PrivateMessage.Signature || opened.Digest().String() != input.PrivateMessage.DigestHex {
		return errors.New("TypeScript 私密消息摘要或签名不匹配")
	}
	if _, ok := opened.WebRTCSignal(); !ok {
		return errors.New("TypeScript 私密消息未返回 WebRTC body")
	}
	expectedPublicMessage, err := buildPublicMessageResult()
	if err != nil {
		return err
	}
	if err := verifyForeignPublicMessage(foreign.PublicMessage, expectedPublicMessage); err != nil {
		return err
	}
	if !reflect.DeepEqual(foreign.PublicMessage, expectedPublicMessage) {
		return fmt.Errorf("TypeScript public-message 结果与 Go 不一致: expected %v got %v", expectedPublicMessage, foreign.PublicMessage)
	}
	expectedDedupRelations, err := buildDedupRelations(input)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(foreign.DedupRelations, expectedDedupRelations) {
		return fmt.Errorf("TypeScript dedup/relations 结果与 Go 不一致: expected %v got %v", expectedDedupRelations, foreign.DedupRelations)
	}
	expectedInvalid, err := invalidResults(input)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(foreign.Invalid, expectedInvalid) {
		return fmt.Errorf("TypeScript invalid fixture 结果与 Go 不一致: expected %v got %v", expectedInvalid, foreign.Invalid)
	}
	return nil
}

func build(input fixture) (result, error) {
	output := result{}
	for _, item := range input.JCS {
		canonical, err := channels.CanonicalizeJSON([]byte(item.Input))
		if err != nil {
			return result{}, fmt.Errorf("JCS fixture %s: %w", item.Name, err)
		}
		actual := hex.EncodeToString(canonical)
		if actual != item.ExpectedUTF8Hex {
			return result{}, fmt.Errorf("JCS fixture %s expected %s got %s", item.Name, item.ExpectedUTF8Hex, actual)
		}
		output.JCS = append(output.JCS, jcsResult{Name: item.Name, Hex: actual})
	}

	privateA, err := parsePrivateKey(input.TestOnlyPrivateKeyA)
	if err != nil {
		return result{}, err
	}
	privateB, err := parsePrivateKey(input.TestOnlyPrivateKeyB)
	if err != nil {
		return result{}, err
	}
	publicA, err := channels.ParsePublicKey(input.PublicKeyA)
	if err != nil {
		return result{}, err
	}
	publicB, err := channels.ParsePublicKey(input.PublicKeyB)
	if err != nil {
		return result{}, err
	}
	derivedA, err := channels.PublicKeyFromPrivate(privateA)
	if err != nil || !derivedA.Equal(publicA) {
		return result{}, errors.New("fixture A 私钥与公钥不匹配")
	}
	derivedB, err := channels.PublicKeyFromPrivate(privateB)
	if err != nil || !derivedB.Equal(publicB) || input.Channel != channels.InboxChannel(publicB) {
		return result{}, errors.New("fixture B 私钥、公钥或 channel 不匹配")
	}
	messageID, err := channels.ParseMessageID(input.MessageID)
	if err != nil {
		return result{}, err
	}
	sessionID, err := channels.ParseSessionID(input.SessionID)
	if err != nil {
		return result{}, err
	}
	hash, err := channels.ParseSHA256Hash(input.Hash)
	if err != nil {
		return result{}, err
	}

	publicMessage, err := hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: publicA,
		MessageID:     messageID,
		IssuedAtMs:    input.IssuedAtMs,
		ExpiresAtMs:   input.ExpiresAtMs,
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: []hashrequest.Locator{hashrequest.NewWebRTCSDPLocator()}},
	}, privateA)
	if err != nil {
		return result{}, err
	}
	publicJSON, err := hashrequest.Marshal(publicMessage)
	if err != nil {
		return result{}, err
	}
	if publicMessage.Signature.String() != input.HashRequest.Signature || publicMessage.SignedDigest().String() != input.HashRequest.DigestHex {
		return result{}, errors.New("公开 Hash fixture 与 Go 构造结果不一致")
	}
	verifiedPublic, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, publicJSON, input.IssuedAtMs)
	if err != nil {
		return result{}, err
	}
	output.HashRequest = hashResult{JSON: string(publicJSON), DigestHex: verifiedPublic.Digest().String(), Signature: verifiedPublic.Signature().String()}

	body, err := webrtcsignal.NewOffer(messageID, sessionID, "v=0")
	if err != nil {
		return result{}, err
	}
	unsignedPrivate := inbox.UnsignedPrivateMessage{
		Channel:       input.Channel,
		FromPublicKey: publicA,
		Protocol:      channels.WebRTCSignalProtocol,
		MessageID:     messageID,
		IssuedAtMs:    input.IssuedAtMs,
		ExpiresAtMs:   input.ExpiresAtMs,
		Body:          body,
	}
	signedPrivate, err := inbox.SignPrivateMessage(unsignedPrivate, privateA)
	if err != nil {
		return result{}, err
	}
	plaintext, err := inbox.MarshalPrivateMessage(signedPrivate)
	if err != nil {
		return result{}, err
	}
	expectedPlaintext, err := channels.CanonicalizeValue(input.PrivateMessage.Plaintext)
	if err != nil {
		return result{}, err
	}
	if !bytes.Equal(plaintext, expectedPlaintext) || signedPrivate.Signature.String() != input.PrivateMessage.Signature || signedPrivate.SignedDigest().String() != input.PrivateMessage.DigestHex {
		return result{}, errors.New("私密明文 fixture 与 Go 构造结果不一致")
	}
	random := bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x21}, 12)...))
	envelope, err := inbox.SealSigned(signedPrivate, privateA, random)
	if err != nil {
		return result{}, err
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		return result{}, err
	}
	expectedEnvelope, err := channels.CanonicalizeValue(input.PrivateMessage.Envelope)
	if err != nil {
		return result{}, err
	}
	if !bytes.Equal(envelopeJSON, expectedEnvelope) {
		return result{}, fmt.Errorf("私密信封 fixture 与 Go 构造结果不一致")
	}
	opened, err := inbox.Open(input.Channel, envelopeJSON, privateB, input.IssuedAtMs)
	if err != nil {
		return result{}, err
	}
	bodyType := "unknown"
	if _, ok := opened.WebRTCSignal(); ok {
		bodyType = "webrtc.signal.offer"
	}
	output.PrivateMessage = privateResult{PlaintextJSON: string(plaintext), EnvelopeJSON: string(envelopeJSON), DigestHex: opened.Digest().String(), Signature: opened.Signature().String(), OpenedProtocol: opened.Protocol(), OpenedBody: bodyType}
	output.PublicMessage, err = buildPublicMessageResult()
	if err != nil {
		return result{}, err
	}

	output.DedupRelations, err = buildDedupRelations(input)
	if err != nil {
		return result{}, err
	}
	if err := validateSharedValidFixtures(input); err != nil {
		return result{}, err
	}
	output.Invalid, err = invalidResults(input)
	if err != nil {
		return result{}, err
	}
	return output, nil
}

func buildPublicMessageResult() (publicMessageResult, error) {
	validData, err := os.ReadFile("testdata/v1/public-message-valid.json")
	if err != nil {
		return publicMessageResult{}, err
	}
	var valid publicMessageValidFixture
	if err := json.Unmarshal(validData, &valid); err != nil {
		return publicMessageResult{}, err
	}
	privateKey, err := parsePrivateKey(valid.PrivateKey)
	if err != nil {
		return publicMessageResult{}, err
	}
	publicKey, err := channels.ParsePublicKey(valid.PublicKey)
	if err != nil {
		return publicMessageResult{}, err
	}
	messageID, err := channels.ParseMessageID(valid.MessageID)
	if err != nil {
		return publicMessageResult{}, err
	}
	result := publicMessageResult{
		Cases:   make([]publicMessageCaseResult, 0, len(valid.Cases)),
		Invalid: nil,
	}
	for _, item := range valid.Cases {
		body, err := strictjson.Parse(item.Body)
		if err != nil {
			return publicMessageResult{}, fmt.Errorf("public-message fixture %s body: %w", item.Name, err)
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
			return publicMessageResult{}, fmt.Errorf("public-message fixture %s sign: %w", item.Name, err)
		}
		wire, err := publicmessage.Marshal(signed)
		if err != nil {
			return publicMessageResult{}, fmt.Errorf("public-message fixture %s marshal: %w", item.Name, err)
		}
		verified, err := publicmessage.ParseAndVerify(item.Channel, wire, item.Now)
		if err != nil {
			return publicMessageResult{}, fmt.Errorf("public-message fixture %s verify: %w", item.Name, err)
		}
		bodyJSON, err := channels.CanonicalizeValue(verified.Body())
		if err != nil {
			return publicMessageResult{}, err
		}
		key := verified.DedupKey()
		actual := publicMessageCaseResult{
			Name:      item.Name,
			JSON:      string(wire),
			DigestHex: verified.Digest().String(),
			Signature: verified.Signature().String(),
			BodyJSON:  string(bodyJSON),
			DedupKey:  []string{key.Channel, key.FromPublicKey.String(), key.MessageID.String()},
		}
		if actual.JSON != item.Expected.JSON || actual.DigestHex != item.Expected.Digest || actual.Signature != item.Expected.Signature || !reflect.DeepEqual(actual.DedupKey, item.Expected.DedupKey) {
			return publicMessageResult{}, fmt.Errorf("public-message fixture %s expected 与 Go 构造结果不一致", item.Name)
		}
		result.Cases = append(result.Cases, actual)
	}
	invalidData, err := os.ReadFile("testdata/v1/public-message-invalid.json")
	if err != nil {
		return publicMessageResult{}, err
	}
	var invalid publicMessageInvalidFixture
	if err := json.Unmarshal(invalidData, &invalid); err != nil {
		return publicMessageResult{}, err
	}
	base := valid.Cases[0].Expected.JSON
	result.Invalid = make([]errorResult, 0, len(invalid.Cases))
	for _, item := range invalid.Cases {
		err := publicMessageInvalidError(item, base)
		code := errorCode(err)
		if code != item.Expected {
			return publicMessageResult{}, fmt.Errorf("public-message invalid fixture %s expected %s got %s", item.Name, item.Expected, code)
		}
		result.Invalid = append(result.Invalid, errorResult{Name: "public-message/" + item.Name, Code: code})
	}
	return result, nil
}

func publicMessageInvalidError(item publicMessageInvalidCase, base string) error {
	if item.Operation == "conflict" {
		existing, err := channels.ParseSHA256Hash(item.Existing)
		if err != nil {
			return err
		}
		incoming, err := channels.ParseSHA256Hash(item.Incoming)
		if err != nil {
			return err
		}
		return publicmessage.CheckDigestConflict(existing, incoming)
	}
	if item.Operation == "parse_raw" {
		_, err := publicmessage.ParseAndVerify(item.Channel, []byte(item.JSON), item.Now)
		return err
	}
	if item.Operation == "generated" {
		return publicMessageGeneratedInvalidError(item, base)
	}
	channel := item.Channel
	if item.ChannelRepeat != 0 {
		channel += strings.Repeat("a", item.ChannelRepeat)
	}
	input, err := mutatePublicMessage(base, item.Mutation)
	if err != nil {
		return err
	}
	_, err = publicmessage.ParseAndVerify(channel, input, item.Now)
	return err
}

func mutatePublicMessage(base, mutation string) ([]byte, error) {
	if mutation == "none" {
		return []byte(base), nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &object); err != nil {
		return nil, err
	}
	set := func(field string, value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		object[field] = raw
		return nil
	}
	switch mutation {
	case "missing_body":
		delete(object, "body")
	case "missing_signature":
		delete(object, "signature")
	case "unknown_field":
		if err := set("unknown", 1); err != nil {
			return nil, err
		}
	case "content_old_shape":
		delete(object, "body")
		if err := set("content", map[string]any{"legacy": true}); err != nil {
			return nil, err
		}
	case "wrong_public_key_type":
		if err := set("from_public_key", 1); err != nil {
			return nil, err
		}
	case "issued_equals_expires":
		if err := set("issued_at_ms", 2000); err != nil {
			return nil, err
		}
	case "lifetime_over_max":
		if err := set("expires_at_ms", 601001); err != nil {
			return nil, err
		}
	case "future_skew_over_max":
		if err := set("issued_at_ms", 61001); err != nil {
			return nil, err
		}
		if err := set("expires_at_ms", 661001); err != nil {
			return nil, err
		}
	case "wrong_public_key":
		if err := set("from_public_key", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"); err != nil {
			return nil, err
		}
	case "wrong_signature":
		if err := set("signature", "AAAA"); err != nil {
			return nil, err
		}
	case "high_s_signature":
		if err := set("signature", "MEYCIQCxjq-UdL-zqecurQmubV2d3utTgDMA2IDsiMy6u5hlNwIhAPnZHMoNmmiRZouM9yy6amfqHJmlDd9SDYcXXForlxYe"); err != nil {
			return nil, err
		}
	case "tampered_body":
		if err := set("body", map[string]any{"tampered": true}); err != nil {
			return nil, err
		}
	case "tampered_message_id":
		if err := set("message_id", "AQ"+strings.Repeat("A", 41)); err != nil {
			return nil, err
		}
	case "tampered_time":
		if err := set("issued_at_ms", 1001); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown public-message mutation %q", mutation)
	}
	return json.Marshal(object)
}

func publicMessageGeneratedInvalidError(item publicMessageInvalidCase, base string) error {
	switch item.Generator {
	case "oversized":
		var object map[string]json.RawMessage
		if err := json.Unmarshal([]byte(base), &object); err != nil {
			return err
		}
		body, err := json.Marshal(strings.Repeat("x", strictjson.MaxJSONBytes))
		if err != nil {
			return err
		}
		object["body"] = body
		input, err := json.Marshal(object)
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
		return fmt.Errorf("unknown public-message generator %q", item.Generator)
	}
}

func verifyForeignPublicMessage(foreign, expected publicMessageResult) error {
	validData, err := os.ReadFile("testdata/v1/public-message-valid.json")
	if err != nil {
		return err
	}
	var valid publicMessageValidFixture
	if err := json.Unmarshal(validData, &valid); err != nil {
		return err
	}
	if len(foreign.Cases) != len(expected.Cases) {
		return fmt.Errorf("foreign public-message case 数量不一致")
	}
	for index, actual := range foreign.Cases {
		item := valid.Cases[index]
		verified, err := publicmessage.ParseAndVerify(item.Channel, []byte(actual.JSON), item.Now)
		if err != nil {
			return fmt.Errorf("Go 无法验签 TypeScript public-message %s: %w", item.Name, err)
		}
		bodyJSON, err := channels.CanonicalizeValue(verified.Body())
		if err != nil {
			return err
		}
		key := verified.DedupKey()
		if actual.Name != item.Name || actual.JSON != expected.Cases[index].JSON || actual.DigestHex != verified.Digest().String() || actual.Signature != verified.Signature().String() || actual.BodyJSON != string(bodyJSON) || !reflect.DeepEqual(actual.DedupKey, []string{key.Channel, key.FromPublicKey.String(), key.MessageID.String()}) {
			return fmt.Errorf("foreign public-message %s 内容、摘要、签名、body 或去重键不一致", item.Name)
		}
	}
	if !reflect.DeepEqual(foreign.Invalid, expected.Invalid) {
		return fmt.Errorf("foreign public-message invalid 结果不一致")
	}
	return nil
}

func invalidResults(input fixture) ([]errorResult, error) {
	results := make([]errorResult, 0, len(input.InvalidErrorCodes))
	for _, item := range input.InvalidErrorCodes {
		var code string
		var err error
		if item.Name == "unknown public field" {
			_, err = hashrequest.ParseAndVerify(channels.HashRequestChannel, []byte(item.JSON), input.IssuedAtMs)
		} else {
			_, err = channels.CanonicalizeJSON([]byte(item.JSON))
		}
		code = errorCode(err)
		if code != item.ExpectedCode {
			return nil, fmt.Errorf("invalid fixture %s expected %s got %s", item.Name, item.ExpectedCode, code)
		}
		results = append(results, errorResult{Name: item.Name, Code: code})
	}
	shared, err := sharedInvalidResults(input)
	if err != nil {
		return nil, err
	}
	return append(results, shared...), nil
}

func parsePrivateKey(value string) (channels.PrivateKey, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return channels.PrivateKey{}, err
	}
	return channels.ParsePrivateKey(decoded)
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	var structured *channels.ChannelProtocolError
	if errors.As(err, &structured) {
		return string(structured.Code)
	}
	return "UNKNOWN"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
