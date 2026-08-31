package channels_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

type dedupRelationsTestFixture struct {
	TestOnlyPrivateKeyA string                         `json:"test_only_private_key_a_hex"`
	TestOnlyPrivateKeyB string                         `json:"test_only_private_key_b_hex"`
	PublicKeyA          string                         `json:"public_key_a"`
	PublicKeyB          string                         `json:"public_key_b"`
	PublicHashRequest   dedupHashRequestTestFixture    `json:"public_hash_request"`
	PrivateDeliver      dedupPrivateDeliverTestFixture `json:"private_deliver"`
	SessionKey          dedupSessionKeyTestFixture     `json:"session_key"`
	Ack                 dedupAckTestFixture            `json:"ack"`
	Conflict            dedupConflictTestFixture       `json:"conflict"`
	Expected            dedupRelationsExpectedFixture  `json:"expected"`
}

type dedupHashRequestTestFixture struct {
	Channel       string                   `json:"channel"`
	FromPublicKey string                   `json:"from_public_key"`
	MessageID     string                   `json:"message_id"`
	IssuedAtMs    int64                    `json:"issued_at_ms"`
	ExpiresAtMs   int64                    `json:"expires_at_ms"`
	Body          dedupHashBodyTestFixture `json:"body"`
}

type dedupHashBodyTestFixture struct {
	Hash     string                    `json:"hash"`
	Locators []dedupLocatorTestFixture `json:"locators"`
}

type dedupLocatorTestFixture struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
}

type dedupPrivateDeliverTestFixture struct {
	Channel       string          `json:"channel"`
	FromPublicKey string          `json:"from_public_key"`
	ToPublicKey   string          `json:"to_public_key"`
	Protocol      string          `json:"protocol"`
	MessageID     string          `json:"message_id"`
	IssuedAtMs    int64           `json:"issued_at_ms"`
	ExpiresAtMs   int64           `json:"expires_at_ms"`
	Body          json.RawMessage `json:"body"`
}

type dedupSessionKeyTestFixture struct {
	RequestMessageID string `json:"request_message_id"`
	OffererPublicKey string `json:"offerer_public_key"`
	SessionID        string `json:"session_id"`
	Separator        string `json:"separator"`
}

type dedupAckTestFixture struct {
	Delivery dedupDeliveryTestFixture `json:"delivery"`
	Valid    dedupAckCaseFixture      `json:"valid"`
	Invalid  []dedupAckCaseFixture    `json:"invalid"`
}

type dedupDeliveryTestFixture struct {
	FromPublicKey string `json:"from_public_key"`
	ToPublicKey   string `json:"to_public_key"`
	MessageID     string `json:"message_id"`
}

type dedupAckCaseFixture struct {
	Name                  string  `json:"name"`
	FromPublicKey         string  `json:"from_public_key"`
	ToPublicKey           string  `json:"to_public_key"`
	AcknowledgedMessageID string  `json:"acknowledged_message_id"`
	ExpectedCode          *string `json:"expected_code"`
}

type dedupConflictTestFixture struct {
	SameDigest            string  `json:"same_digest"`
	DifferentDigest       string  `json:"different_digest"`
	ExpectedSameCode      *string `json:"expected_same_code"`
	ExpectedDifferentCode string  `json:"expected_different_code"`
}

type dedupRelationsExpectedFixture struct {
	PublicDedupKey  []string       `json:"public_dedup_key"`
	PrivateDedupKey []string       `json:"private_dedup_key"`
	SessionKey      string         `json:"session_key"`
	AckValid        bool           `json:"ack_valid"`
	AckInvalid      []errorFixture `json:"ack_invalid"`
	ConflictCode    string         `json:"conflict_code"`
}

type errorFixture struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

func TestSharedDedupAndRelationsFixture(t *testing.T) {
	value := readFixture[dedupRelationsTestFixture](t, "dedup-and-relations.json")
	privateA, publicA := testKey(t, 1)
	privateB, publicB := testKey(t, 2)
	if value.TestOnlyPrivateKeyA != "0000000000000000000000000000000000000000000000000000000000000001" ||
		value.TestOnlyPrivateKeyB != "0000000000000000000000000000000000000000000000000000000000000002" ||
		value.PublicKeyA != publicA.String() || value.PublicKeyB != publicB.String() {
		t.Fatal("dedup fixture 测试身份不是预期固定向量")
	}

	publicInput := value.PublicHashRequest
	if publicInput.Channel != channels.HashRequestChannel || publicInput.FromPublicKey != publicA.String() {
		t.Fatal("dedup fixture 公开 Hash 输入身份或 channel 不一致")
	}
	messageID, err := channels.ParseMessageID(publicInput.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := channels.ParseSHA256Hash(publicInput.Body.Hash)
	if err != nil {
		t.Fatal(err)
	}
	locators := make([]hashrequest.Locator, 0, len(publicInput.Body.Locators))
	for _, item := range publicInput.Body.Locators {
		switch item.Kind {
		case string(hashrequest.LocatorWebRTCSDP):
			if item.Address != "" {
				t.Fatal("webrtc-sdp locator 不应有 address")
			}
			locators = append(locators, hashrequest.NewWebRTCSDPLocator())
		case string(hashrequest.LocatorMultiaddr):
			locator, locatorErr := hashrequest.NewMultiaddrLocator(item.Address)
			if locatorErr != nil {
				t.Fatal(locatorErr)
			}
			locators = append(locators, locator)
		default:
			t.Fatalf("未知 locator kind: %s", item.Kind)
		}
	}
	publicMessage, err := hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: publicA,
		MessageID:     messageID,
		IssuedAtMs:    publicInput.IssuedAtMs,
		ExpiresAtMs:   publicInput.ExpiresAtMs,
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: locators},
	}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := hashrequest.Marshal(publicMessage)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPublic, err := hashrequest.ParseAndVerify(publicInput.Channel, publicJSON, publicInput.IssuedAtMs+500)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := verifiedPublic.DedupKey()
	actualPublicDedupKey := []string{publicKey.Channel, publicKey.FromPublicKey.String(), publicKey.MessageID.String()}
	if !reflect.DeepEqual(actualPublicDedupKey, value.Expected.PublicDedupKey) {
		t.Fatalf("公开去重键不一致: got %v want %v", actualPublicDedupKey, value.Expected.PublicDedupKey)
	}

	privateInput := value.PrivateDeliver
	if privateInput.Channel != channels.InboxChannel(publicB) ||
		privateInput.FromPublicKey != publicA.String() ||
		privateInput.ToPublicKey != publicB.String() ||
		privateInput.Protocol != channels.AppMessageProtocol {
		t.Fatal("dedup fixture 私密 Deliver 输入身份或 protocol 不一致")
	}
	privateBody, err := appmessage.ParseBody(privateInput.Body)
	if err != nil {
		t.Fatal(err)
	}
	deliver, ok := privateBody.(appmessage.DeliverBody)
	if !ok {
		t.Fatal("dedup fixture body 不是 Deliver")
	}
	privateMessageID, err := channels.ParseMessageID(privateInput.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{
		Channel:       privateInput.Channel,
		FromPublicKey: publicA,
		Protocol:      channels.AppMessageProtocol,
		MessageID:     privateMessageID,
		IssuedAtMs:    privateInput.IssuedAtMs,
		ExpiresAtMs:   privateInput.ExpiresAtMs,
		Body:          deliver,
	}, privateA, bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x32}, 12)...)))
	if err != nil {
		t.Fatal(err)
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := inbox.Open(privateInput.Channel, envelopeJSON, privateB, privateInput.IssuedAtMs+500)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := opened.DedupKey()
	actualPrivateDedupKey := []string{privateKey.Protocol, privateKey.FromPublicKey.String(), privateKey.MessageID.String()}
	if !reflect.DeepEqual(actualPrivateDedupKey, value.Expected.PrivateDedupKey) {
		t.Fatalf("私密去重键不一致: got %v want %v", actualPrivateDedupKey, value.Expected.PrivateDedupKey)
	}

	if value.SessionKey.Separator != "\x00" {
		t.Fatal("SessionKey separator 不是单个 NUL 字节")
	}
	session, err := webrtcsignal.NewSessionKey(
		mustMessageID(t, value.SessionKey.RequestMessageID),
		mustPublicKey(t, value.SessionKey.OffererPublicKey),
		mustSessionID(t, value.SessionKey.SessionID),
	)
	if err != nil {
		t.Fatal(err)
	}
	if session.String() != value.Expected.SessionKey {
		t.Fatalf("SessionKey 不一致: got %q want %q", session.String(), value.Expected.SessionKey)
	}

	delivery := appmessage.DeliveryContext{
		FromPublicKey: mustPublicKey(t, value.Ack.Delivery.FromPublicKey),
		ToPublicKey:   mustPublicKey(t, value.Ack.Delivery.ToPublicKey),
		MessageID:     mustMessageID(t, value.Ack.Delivery.MessageID),
	}
	if value.Ack.Valid.ExpectedCode != nil {
		t.Fatalf("ACK valid expected_code 应为 null，got %s", *value.Ack.Valid.ExpectedCode)
	}
	if err := validateFixtureAck(delivery, value.Ack.Valid); err != nil {
		t.Fatalf("ACK 正例失败: %v", err)
	}
	actualAckInvalid := make([]errorFixture, 0, len(value.Ack.Invalid))
	for _, item := range value.Ack.Invalid {
		err := validateFixtureAck(delivery, item)
		if err == nil || !channels.IsErrorCode(err, channels.ErrorCode(*item.ExpectedCode)) {
			t.Fatalf("ACK 反例 %s expected %s got %v", item.Name, *item.ExpectedCode, err)
		}
		actualAckInvalid = append(actualAckInvalid, errorFixture{Name: item.Name, Code: *item.ExpectedCode})
	}

	sameDigest := mustHash(t, value.Conflict.SameDigest)
	differentDigest := mustHash(t, value.Conflict.DifferentDigest)
	if value.Conflict.ExpectedSameCode != nil {
		t.Fatalf("same digest expected_code 应为 null，got %s", *value.Conflict.ExpectedSameCode)
	}
	if err := appmessage.CheckDigestConflict(sameDigest, sameDigest); err != nil {
		t.Fatal(err)
	}
	if err := inbox.CheckDigestConflict(sameDigest, sameDigest); err != nil {
		t.Fatal(err)
	}
	conflictErr := appmessage.CheckDigestConflict(sameDigest, differentDigest)
	if conflictErr == nil || !channels.IsErrorCode(conflictErr, channels.ErrorCode(value.Conflict.ExpectedDifferentCode)) {
		t.Fatalf("公开冲突错误码错误: expected %s got %v", value.Conflict.ExpectedDifferentCode, conflictErr)
	}
	privateConflictErr := inbox.CheckDigestConflict(sameDigest, differentDigest)
	if privateConflictErr == nil || !channels.IsErrorCode(privateConflictErr, channels.ErrorCode(value.Conflict.ExpectedDifferentCode)) {
		t.Fatalf("私密冲突错误码错误: expected %s got %v", value.Conflict.ExpectedDifferentCode, privateConflictErr)
	}
	if value.Expected.AckValid != true || !reflect.DeepEqual(actualAckInvalid, value.Expected.AckInvalid) || value.Expected.ConflictCode != value.Conflict.ExpectedDifferentCode {
		t.Fatal("dedup fixture expected 结构不完整")
	}
}

func validateFixtureAck(delivery appmessage.DeliveryContext, value dedupAckCaseFixture) error {
	ack, err := appmessage.NewAck(mustMessageIDValue(value.AcknowledgedMessageID))
	if err != nil {
		return err
	}
	return appmessage.ValidateAckRelation(delivery, appmessage.AckContext{
		FromPublicKey: mustPublicKeyValue(value.FromPublicKey),
		ToPublicKey:   mustPublicKeyValue(value.ToPublicKey),
		Body:          ack,
	})
}

func mustPublicKey(t *testing.T, value string) channels.PublicKey {
	t.Helper()
	result, err := channels.ParsePublicKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustPublicKeyValue(value string) channels.PublicKey {
	result, err := channels.ParsePublicKey(value)
	if err != nil {
		panic(err)
	}
	return result
}

func mustMessageID(t *testing.T, value string) channels.MessageID {
	t.Helper()
	result, err := channels.ParseMessageID(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustMessageIDValue(value string) channels.MessageID {
	result, err := channels.ParseMessageID(value)
	if err != nil {
		panic(err)
	}
	return result
}

func mustSessionID(t *testing.T, value string) channels.SessionID {
	t.Helper()
	result, err := channels.ParseSessionID(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustHash(t *testing.T, value string) channels.SHA256Hash {
	t.Helper()
	result, err := channels.ParseSHA256Hash(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
