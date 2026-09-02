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

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
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
