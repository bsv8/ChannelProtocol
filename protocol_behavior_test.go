package channels_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/inbox"
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
	if _, err := channels.ParsePublicKey(strings.ToUpper("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")); !channels.IsErrorCode(err, channels.InvalidPublicKeyCode) {
		t.Fatalf("大写公钥错误码错误: %v", err)
	}
	if _, err := channels.CanonicalizeJSON([]byte(`{"a":1,"a":2}`)); !channels.IsErrorCode(err, channels.InvalidJSONCode) {
		t.Fatalf("重复字段错误码错误: %v", err)
	}
	if _, err := channels.CanonicalizeValue(map[string]any{"bad": string([]byte{0xff})}); !channels.IsErrorCode(err, channels.InvalidJSONCode) {
		t.Fatalf("非法 UTF-8 值错误码错误: %v", err)
	}
	if _, err := channels.DecodeChannel(channels.HashRequestChannel, []byte(`{"unknown":1}`), nil, 0); !channels.IsErrorCode(err, channels.UnknownFieldCode) {
		t.Fatalf("公开根入口错误码错误: %v", err)
	}
	if _, err := channels.DecodeChannel(channels.InboxChannelPrefix+"bad", []byte(`{}`), nil, 0); !channels.IsErrorCode(err, channels.InvalidChannelCode) {
		t.Fatalf("私密根入口缺少私钥错误码错误: %v", err)
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
	context, err := webrtcsignal.NewSessionContext(offer, publicA, publicB)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := webrtcsignal.NewAnswer(messageID, sessionID, "v=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := webrtcsignal.ValidateRelation(answer, context, publicB); err != nil {
		t.Fatal(err)
	}
	if err := webrtcsignal.ValidateRelation(answer, context, publicA); !channels.IsErrorCode(err, channels.InvalidRelationCode) {
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
	if err := appmessage.ValidateAckRelation(
		appmessage.DeliveryContext{FromPublicKey: publicA, ToPublicKey: publicB, MessageID: messageID},
		appmessage.AckContext{FromPublicKey: publicB, ToPublicKey: publicA, Body: ack},
	); err != nil {
		t.Fatal(err)
	}
	badAck, err := appmessage.NewAck(messageID)
	if err != nil {
		t.Fatal(err)
	}
	if err := appmessage.ValidateAckRelation(
		appmessage.DeliveryContext{FromPublicKey: publicA, ToPublicKey: publicB, MessageID: messageID},
		appmessage.AckContext{FromPublicKey: publicA, ToPublicKey: publicB, Body: badAck},
	); !channels.IsErrorCode(err, channels.InvalidRelationCode) {
		t.Fatalf("错误 ACK 关系未返回 INVALID_RELATION: %v", err)
	}
	_ = privateA
	_ = privateB
	_ = deliver
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
	if _, err := inbox.Open(envelope.Channel, envelopeJSON, privateA, 1500); !channels.IsErrorCode(err, channels.OpenFailedCode) {
		t.Fatalf("收件者私钥不匹配未统一为 OPEN_FAILED: %v", err)
	}
	tampered := append([]byte(nil), envelopeJSON...)
	tampered[len(tampered)-3] ^= 1
	if _, err := inbox.Open(envelope.Channel, tampered, privateB, 1500); !channels.IsErrorCode(err, channels.OpenFailedCode) {
		t.Fatalf("tag/密文篡改未统一为 OPEN_FAILED: %v", err)
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
