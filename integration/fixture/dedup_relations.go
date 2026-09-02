package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

// dedupRelationsFixture 是公开/私密去重和关联验收的完整输入。
type dedupRelationsFixture struct {
	TestOnlyPrivateKeyA string                     `json:"test_only_private_key_a_hex"`
	TestOnlyPrivateKeyB string                     `json:"test_only_private_key_b_hex"`
	PublicKeyA          string                     `json:"public_key_a"`
	PublicKeyB          string                     `json:"public_key_b"`
	PublicHashRequest   dedupHashRequestFixture    `json:"public_hash_request"`
	PrivateDeliver      dedupPrivateDeliverFixture `json:"private_deliver"`
	SessionKey          dedupSessionKeyFixture     `json:"session_key"`
	Ack                 dedupAckFixture            `json:"ack"`
	Conflict            dedupConflictFixture       `json:"conflict"`
	Expected            dedupRelationsExpected     `json:"expected"`
}

type dedupHashRequestFixture struct {
	Channel       string               `json:"channel"`
	FromPublicKey string               `json:"from_public_key"`
	MessageID     string               `json:"message_id"`
	IssuedAtMs    int64                `json:"issued_at_ms"`
	ExpiresAtMs   int64                `json:"expires_at_ms"`
	Body          dedupHashBodyFixture `json:"body"`
}

type dedupHashBodyFixture struct {
	Hash     string                `json:"hash"`
	Locators []dedupLocatorFixture `json:"locators"`
}

type dedupLocatorFixture struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
}

type dedupPrivateDeliverFixture struct {
	Channel       string          `json:"channel"`
	FromPublicKey string          `json:"from_public_key"`
	ToPublicKey   string          `json:"to_public_key"`
	Protocol      string          `json:"protocol"`
	MessageID     string          `json:"message_id"`
	IssuedAtMs    int64           `json:"issued_at_ms"`
	ExpiresAtMs   int64           `json:"expires_at_ms"`
	Body          json.RawMessage `json:"body"`
}

type dedupSessionKeyFixture struct {
	RequestMessageID string `json:"request_message_id"`
	OffererPublicKey string `json:"offerer_public_key"`
	SessionID        string `json:"session_id"`
	Separator        string `json:"separator"`
}

type dedupAckFixture struct {
	Delivery dedupDeliveryFixture `json:"delivery"`
	Valid    dedupAckCase         `json:"valid"`
	Invalid  []dedupAckCase       `json:"invalid"`
}

type dedupDeliveryFixture struct {
	FromPublicKey string `json:"from_public_key"`
	ToPublicKey   string `json:"to_public_key"`
	MessageID     string `json:"message_id"`
}

type dedupAckCase struct {
	Name                  string  `json:"name"`
	FromPublicKey         string  `json:"from_public_key"`
	ToPublicKey           string  `json:"to_public_key"`
	AcknowledgedMessageID string  `json:"acknowledged_message_id"`
	ExpectedCode          *string `json:"expected_code"`
}

type dedupConflictFixture struct {
	SameDigest            string  `json:"same_digest"`
	DifferentDigest       string  `json:"different_digest"`
	ExpectedSameCode      *string `json:"expected_same_code"`
	ExpectedDifferentCode string  `json:"expected_different_code"`
}

type dedupRelationsExpected struct {
	PublicDedupKey  []string      `json:"public_dedup_key"`
	PrivateDedupKey []string      `json:"private_dedup_key"`
	SessionKey      string        `json:"session_key"`
	AckValid        bool          `json:"ack_valid"`
	AckInvalid      []errorResult `json:"ack_invalid"`
	ConflictCode    string        `json:"conflict_code"`
}

type dedupRelationsResult struct {
	PublicDedupKey      []string      `json:"public_dedup_key"`
	PrivateDedupKey     []string      `json:"private_dedup_key"`
	SessionKey          string        `json:"session_key"`
	SessionKeySeparator string        `json:"session_key_separator"`
	AckValid            bool          `json:"ack_valid"`
	AckInvalid          []errorResult `json:"ack_invalid"`
	ConflictCode        string        `json:"conflict_code"`
}

func readDedupRelationsFixture() (dedupRelationsFixture, error) {
	data, err := os.ReadFile("testdata/v1/dedup-and-relations.json")
	if err != nil {
		return dedupRelationsFixture{}, err
	}
	var fixture dedupRelationsFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return dedupRelationsFixture{}, err
	}
	return fixture, nil
}

// buildDedupRelations 从共享 fixture 构造并验证去重键、SessionKey、ACK 和冲突结果。
func buildDedupRelations(input fixture) (dedupRelationsResult, error) {
	fixtureValue, err := readDedupRelationsFixture()
	if err != nil {
		return dedupRelationsResult{}, err
	}
	if fixtureValue.TestOnlyPrivateKeyA != input.TestOnlyPrivateKeyA ||
		fixtureValue.TestOnlyPrivateKeyB != input.TestOnlyPrivateKeyB ||
		fixtureValue.PublicKeyA != input.PublicKeyA ||
		fixtureValue.PublicKeyB != input.PublicKeyB {
		return dedupRelationsResult{}, fmt.Errorf("dedup fixture 身份输入与 interop fixture 不一致")
	}

	privateA, err := parsePrivateKey(fixtureValue.TestOnlyPrivateKeyA)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	privateB, err := parsePrivateKey(fixtureValue.TestOnlyPrivateKeyB)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	publicA, err := channels.ParsePublicKey(fixtureValue.PublicKeyA)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	publicB, err := channels.ParsePublicKey(fixtureValue.PublicKeyB)
	if err != nil {
		return dedupRelationsResult{}, err
	}

	publicHash, err := buildDedupHashRequest(fixtureValue.PublicHashRequest, privateA, publicA)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	publicJSON, err := hashrequest.Marshal(publicHash)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	verifiedPublic, err := hashrequest.ParseAndVerify(fixtureValue.PublicHashRequest.Channel, publicJSON, fixtureValue.PublicHashRequest.IssuedAtMs+500)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	publicKey := verifiedPublic.DedupKey()
	publicDedupKey := []string{publicKey.FromPublicKey.String(), publicKey.MessageID.String()}

	privateBodyValue, err := appmessage.ParseBody(fixtureValue.PrivateDeliver.Body)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	deliver, ok := privateBodyValue.(appmessage.DeliverBody)
	if !ok {
		return dedupRelationsResult{}, fmt.Errorf("dedup fixture private body 不是 Deliver")
	}
	messageID, err := channels.ParseMessageID(fixtureValue.PrivateDeliver.MessageID)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	if fixtureValue.PrivateDeliver.Protocol != channels.AppMessageProtocol ||
		fixtureValue.PrivateDeliver.FromPublicKey != fixtureValue.PublicKeyA ||
		fixtureValue.PrivateDeliver.ToPublicKey != fixtureValue.PublicKeyB ||
		fixtureValue.PrivateDeliver.Channel != channels.InboxChannel(publicB) {
		return dedupRelationsResult{}, fmt.Errorf("dedup fixture 私密 Deliver 身份或 protocol 不一致")
	}
	signedPrivate, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       fixtureValue.PrivateDeliver.Channel,
		FromPublicKey: publicA,
		Protocol:      channels.AppMessageProtocol,
		MessageID:     messageID,
		IssuedAtMs:    fixtureValue.PrivateDeliver.IssuedAtMs,
		ExpiresAtMs:   fixtureValue.PrivateDeliver.ExpiresAtMs,
		Body:          deliver,
	}, privateA)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	random := bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x32}, 12)...))
	envelope, err := inbox.SealSigned(signedPrivate, privateA, random)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	opened, err := inbox.Open(fixtureValue.PrivateDeliver.Channel, envelopeJSON, privateB, fixtureValue.PrivateDeliver.IssuedAtMs+500)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	privateKey := opened.DedupKey()
	privateDedupKey := []string{privateKey.Protocol, privateKey.FromPublicKey.String(), privateKey.MessageID.String()}

	requestID, err := channels.ParseMessageID(fixtureValue.SessionKey.RequestMessageID)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	offerer, err := channels.ParsePublicKey(fixtureValue.SessionKey.OffererPublicKey)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	sessionID, err := channels.ParseSessionID(fixtureValue.SessionKey.SessionID)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	if fixtureValue.SessionKey.Separator != "\x00" {
		return dedupRelationsResult{}, fmt.Errorf("session_key separator 必须是一个 NUL 字节")
	}
	session, err := webrtcsignal.NewSessionKey(requestID, offerer, sessionID)
	if err != nil {
		return dedupRelationsResult{}, err
	}

	if err := validateDedupAckCase(opened, fixtureValue.Ack.Valid, privateA, publicA, privateB, publicB); err != nil {
		return dedupRelationsResult{}, fmt.Errorf("dedup fixture ACK valid expected success got %s", errorCode(err))
	}
	ackInvalid := make([]errorResult, 0, len(fixtureValue.Ack.Invalid))
	for _, item := range fixtureValue.Ack.Invalid {
		err := validateDedupAckCase(opened, item, privateA, publicA, privateB, publicB)
		code := errorCode(err)
		expected := ""
		if item.ExpectedCode != nil {
			expected = *item.ExpectedCode
		}
		if code != expected {
			return dedupRelationsResult{}, fmt.Errorf("dedup fixture ACK %s expected %s got %s", item.Name, expected, code)
		}
		ackInvalid = append(ackInvalid, errorResult{Name: item.Name, Code: code})
	}

	sameDigest, err := channels.ParseSHA256Hash(fixtureValue.Conflict.SameDigest)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	differentDigest, err := channels.ParseSHA256Hash(fixtureValue.Conflict.DifferentDigest)
	if err != nil {
		return dedupRelationsResult{}, err
	}
	if err := validateConflictCode(inbox.CheckDigestConflict(sameDigest, sameDigest), fixtureValue.Conflict.ExpectedSameCode, "same digest"); err != nil {
		return dedupRelationsResult{}, err
	}
	conflictErr := inbox.CheckDigestConflict(sameDigest, differentDigest)
	conflictCode := errorCode(conflictErr)
	if conflictCode != fixtureValue.Conflict.ExpectedDifferentCode {
		return dedupRelationsResult{}, fmt.Errorf("dedup fixture conflict expected %s got %s", fixtureValue.Conflict.ExpectedDifferentCode, conflictCode)
	}

	actual := dedupRelationsResult{
		PublicDedupKey:      publicDedupKey,
		PrivateDedupKey:     privateDedupKey,
		SessionKey:          session.String(),
		SessionKeySeparator: fixtureValue.SessionKey.Separator,
		AckValid:            true,
		AckInvalid:          ackInvalid,
		ConflictCode:        conflictCode,
	}
	if !reflect.DeepEqual(actual.PublicDedupKey, fixtureValue.Expected.PublicDedupKey) ||
		!reflect.DeepEqual(actual.PrivateDedupKey, fixtureValue.Expected.PrivateDedupKey) ||
		actual.SessionKey != fixtureValue.Expected.SessionKey ||
		actual.AckValid != fixtureValue.Expected.AckValid ||
		!reflect.DeepEqual(actual.AckInvalid, fixtureValue.Expected.AckInvalid) ||
		actual.ConflictCode != fixtureValue.Expected.ConflictCode {
		return dedupRelationsResult{}, fmt.Errorf("dedup fixture expected 与 Go 结果不一致: expected=%v actual=%v", fixtureValue.Expected, actual)
	}
	return actual, nil
}

func buildDedupHashRequest(value dedupHashRequestFixture, privateKey channels.PrivateKey, publicKey channels.PublicKey) (hashrequest.SignedMessage, error) {
	from, err := channels.ParsePublicKey(value.FromPublicKey)
	if err != nil {
		return hashrequest.SignedMessage{}, err
	}
	if !from.Equal(publicKey) {
		return hashrequest.SignedMessage{}, fmt.Errorf("dedup fixture Hash from_public_key 与私钥不一致")
	}
	messageID, err := channels.ParseMessageID(value.MessageID)
	if err != nil {
		return hashrequest.SignedMessage{}, err
	}
	hash, err := channels.ParseSHA256Hash(value.Body.Hash)
	if err != nil {
		return hashrequest.SignedMessage{}, err
	}
	locators := make([]hashrequest.Locator, 0, len(value.Body.Locators))
	for _, item := range value.Body.Locators {
		switch item.Kind {
		case string(hashrequest.LocatorWebRTCSDP):
			if item.Address != "" {
				return hashrequest.SignedMessage{}, fmt.Errorf("dedup fixture webrtc-sdp locator 不应有 address")
			}
			locators = append(locators, hashrequest.NewWebRTCSDPLocator())
		case string(hashrequest.LocatorMultiaddr):
			locator, err := hashrequest.NewMultiaddrLocator(item.Address)
			if err != nil {
				return hashrequest.SignedMessage{}, err
			}
			locators = append(locators, locator)
		default:
			return hashrequest.SignedMessage{}, fmt.Errorf("dedup fixture 未知 locator kind: %s", item.Kind)
		}
	}
	return hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: from,
		MessageID:     messageID,
		IssuedAtMs:    value.IssuedAtMs,
		ExpiresAtMs:   value.ExpiresAtMs,
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: locators},
	}, privateKey)
}

func validateDedupAckCase(delivery inbox.VerifiedPrivateMessage, value dedupAckCase, privateA channels.PrivateKey, publicA channels.PublicKey, privateB channels.PrivateKey, publicB channels.PublicKey) error {
	from, err := channels.ParsePublicKey(value.FromPublicKey)
	if err != nil {
		return err
	}
	to, err := channels.ParsePublicKey(value.ToPublicKey)
	if err != nil {
		return err
	}
	acknowledgedMessageID, err := channels.ParseMessageID(value.AcknowledgedMessageID)
	if err != nil {
		return err
	}
	ack, err := appmessage.NewAck(acknowledgedMessageID)
	if err != nil {
		return err
	}
	var senderPrivate, recipientPrivate channels.PrivateKey
	if from.Equal(publicA) {
		senderPrivate = privateA
	} else if from.Equal(publicB) {
		senderPrivate = privateB
	} else {
		return fmt.Errorf("ACK sender 不在 fixture 身份中")
	}
	if to.Equal(publicA) {
		recipientPrivate = privateA
	} else if to.Equal(publicB) {
		recipientPrivate = privateB
	} else {
		return fmt.Errorf("ACK recipient 不在 fixture 身份中")
	}
	ackID, err := channels.ParseMessageID("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	if err != nil {
		return err
	}
	envelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(to),
		FromPublicKey: from,
		Protocol:      channels.AppMessageProtocol,
		MessageID:     ackID,
		IssuedAtMs:    delivery.IssuedAtMs(),
		ExpiresAtMs:   delivery.ExpiresAtMs(),
		Body:          ack,
	}, senderPrivate)
	if err != nil {
		return err
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		return err
	}
	ackMessage, err := inbox.Open(envelope.Channel, envelopeJSON, recipientPrivate, delivery.IssuedAtMs()+500)
	if err != nil {
		return err
	}
	return inbox.ValidateAckRelation(delivery, ackMessage)
}

func validateConflictCode(err error, expected *string, label string) error {
	actual := errorCode(err)
	expectedCode := ""
	if expected != nil {
		expectedCode = *expected
	}
	if actual != expectedCode {
		return fmt.Errorf("dedup fixture %s expected %s got %s", label, expectedCode, actual)
	}
	return nil
}
