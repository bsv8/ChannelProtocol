package channels_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/ping"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

func TestPublicPrimitivesAndDefensiveCopies(t *testing.T) {
	privateKey, publicKey := testKey(t, 1)
	privateBytes := privateKey.Bytes()
	privateBytes[31] = 2
	if derived, err := channels.PublicKeyFromPrivate(privateKey); err != nil || !derived.Equal(publicKey) {
		t.Fatal("PrivateKey.Bytes 返回了可改变原值的引用")
	}
	publicBytes := publicKey.Bytes()
	publicBytes[0] = 3
	if parsed, err := channels.ParsePublicKey(publicKey.String()); err != nil || !parsed.Equal(publicKey) {
		t.Fatal("PublicKey.Bytes 返回了可改变原值的引用")
	}
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	idBytes := messageID.Bytes()
	idBytes[0] = 1
	if messageID.String() != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatal("MessageID.Bytes 返回了可改变原值的引用")
	}
	if !errors.Is(channels.ErrInvalidPrivateKey, channels.ErrInvalidPrivateKey) {
		t.Fatal("Go sentinel error 未实现 errors.Is")
	}
}

func TestProtocolErrorCodesAndSecurityBoundaries(t *testing.T) {
	if _, err := channels.ParsePublicKey(strings.ToUpper("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")); !errors.Is(err, channels.ErrInvalidPublicKey) {
		t.Fatalf("大写公钥错误码错误: %v", err)
	}
	if _, err := channels.CanonicalizeJSON([]byte(`{"a":1,"a":2}`)); !errors.Is(err, channels.ErrInvalidJSON) {
		t.Fatalf("重复字段错误码错误: %v", err)
	}
	if _, err := channels.CanonicalizeValue(map[string]any{"bad": string([]byte{0xff})}); !errors.Is(err, channels.ErrInvalidJSON) {
		t.Fatalf("非法 UTF-8 值错误码错误: %v", err)
	}
	if _, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, []byte(`{"unknown":1}`), 0); !errors.Is(err, channels.ErrUnknownField) {
		t.Fatalf("公开入口错误码错误: %v", err)
	}
	if _, err := inbox.ParseEnvelope(channels.InboxChannelPrefix+"bad", []byte(`{}`)); !errors.Is(err, channels.ErrInvalidChannel) {
		t.Fatalf("私密入口错误码错误: %v", err)
	}
}

func TestWebRTCRelationAndAppAckRelation(t *testing.T) {
	privateA, publicA := testKey(t, 1)
	privateB, publicB := testKey(t, 2)
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
	answer, err := webrtcsignal.NewAnswer(messageID, sessionID, "v=0")
	if err != nil {
		t.Fatal(err)
	}
	offerEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicB), FromPublicKey: publicA, Protocol: channels.WebRTCSignalProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: offer}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	answerEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicA), FromPublicKey: publicB, Protocol: channels.WebRTCSignalProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: answer}, privateB)
	if err != nil {
		t.Fatal(err)
	}
	openOffer, err := inbox.Open(offerEnvelope.Channel, mustMarshalEnvelope(t, offerEnvelope), privateB, 1500)
	if err != nil {
		t.Fatal(err)
	}
	openAnswer, err := inbox.Open(answerEnvelope.Channel, mustMarshalEnvelope(t, answerEnvelope), privateA, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidateWebRTCRelation(openOffer, openAnswer); err != nil {
		t.Fatal(err)
	}
	wrongAnswerEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicB), FromPublicKey: publicA, Protocol: channels.WebRTCSignalProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: answer}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	wrongAnswer, err := inbox.Open(wrongAnswerEnvelope.Channel, mustMarshalEnvelope(t, wrongAnswerEnvelope), privateB, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidateWebRTCRelation(openOffer, wrongAnswer); !errors.Is(err, channels.ErrInvalidRelation) {
		t.Fatalf("错误 answer 发送者未返回 INVALID_RELATION: %v", err)
	}

	deliver, err := appmessage.NewDeliver(map[string]any{"sdp": "仍然只是应用数据"})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := appmessage.NewAck(messageID)
	if err != nil {
		t.Fatal(err)
	}
	deliverEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicB), FromPublicKey: publicA, Protocol: channels.AppMessageProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: deliver}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	deliverMessage, err := inbox.Open(deliverEnvelope.Channel, mustMarshalEnvelope(t, deliverEnvelope), privateB, 1500)
	if err != nil {
		t.Fatal(err)
	}
	ackEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicA), FromPublicKey: publicB, Protocol: channels.AppMessageProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: ack}, privateB)
	if err != nil {
		t.Fatal(err)
	}
	ackMessage, err := inbox.Open(ackEnvelope.Channel, mustMarshalEnvelope(t, ackEnvelope), privateA, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidateAckRelation(deliverMessage, ackMessage); err != nil {
		t.Fatal(err)
	}
	badAck, err := appmessage.NewAck(messageID)
	if err != nil {
		t.Fatal(err)
	}
	badAckEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicB), FromPublicKey: publicA, Protocol: channels.AppMessageProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: badAck}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	badAckMessage, err := inbox.Open(badAckEnvelope.Channel, mustMarshalEnvelope(t, badAckEnvelope), privateB, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidateAckRelation(deliverMessage, badAckMessage); !errors.Is(err, channels.ErrInvalidRelation) {
		t.Fatalf("错误 ACK 关系未返回 INVALID_RELATION: %v", err)
	}
}

func mustMarshalEnvelope(t *testing.T, envelope inbox.EncryptedEnvelopeV1) []byte {
	t.Helper()
	encoded, err := inbox.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestInboxOpenFailureIsUniform(t *testing.T) {
	privateA, publicA := testKey(t, 1)
	privateB, publicB := testKey(t, 2)
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	body, err := webrtcsignal.NewOffer(messageID, messageIDToSessionID(t), "v=0")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicB),
		FromPublicKey: publicA,
		Protocol:      channels.WebRTCSignalProtocol,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          body,
	}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := inbox.SealSigned(signed, privateA, bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x21}, 12)...)))
	if err != nil {
		t.Fatal(err)
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Open(envelope.Channel, envelopeJSON, privateA, 1500); !errors.Is(err, channels.ErrOpenFailed) {
		t.Fatalf("收件者私钥不匹配未统一为 OPEN_FAILED: %v", err)
	}
	tampered := append([]byte(nil), envelopeJSON...)
	tampered[len(tampered)-3] ^= 1
	if _, err := inbox.Open(envelope.Channel, tampered, privateB, 1500); !errors.Is(err, channels.ErrOpenFailed) {
		t.Fatalf("tag/密文篡改未统一为 OPEN_FAILED: %v", err)
	}
}

func TestPingPongRoundTripAndRelation(t *testing.T) {
	privateA, publicA := testKey(t, 1)
	privateB, publicB := testKey(t, 2)
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	pingBody := ping.NewPing()
	pongBody, err := ping.NewPong(messageID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ping.ParseBody([]byte(`{"type":"ping"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ping.ParseBody([]byte(`{"type":"pong","ping_message_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := ping.ParseBody([]byte(`{"type":"ping","ping_message_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)); !errors.Is(err, channels.ErrUnknownField) {
		t.Fatalf("Ping 重复 message_id 未返回 UNKNOWN_FIELD: %v", err)
	}

	pingEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicB), FromPublicKey: publicA, Protocol: channels.PingProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: pingBody}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	pongEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{Channel: channels.InboxChannel(publicA), FromPublicKey: publicB, Protocol: channels.PingProtocol, MessageID: messageID, IssuedAtMs: 1000, ExpiresAtMs: 2000, Body: pongBody}, privateB)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPing, err := inbox.Open(pingEnvelope.Channel, mustMarshalEnvelope(t, pingEnvelope), privateB, 1500)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPong, err := inbox.Open(pongEnvelope.Channel, mustMarshalEnvelope(t, pongEnvelope), privateA, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidatePongRelation(verifiedPing, verifiedPong); err != nil {
		t.Fatal(err)
	}
	body, ok := verifiedPong.Ping()
	if !ok || body.Type != ping.TypePong || !body.PingMessageID.Equal(messageID) {
		t.Fatal("Open 未返回正确 Pong body")
	}
}

func messageIDToSessionID(t *testing.T) channels.SessionID {
	t.Helper()
	id, err := channels.ParseSessionID("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
