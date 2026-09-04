package channels_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/ping"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

func TestVerifySignedPrivateMessageAndTTL(t *testing.T) {
	privateA, publicA := testKey(t, 1)
	privateB, publicB := testKey(t, 2)
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}

	if got := inbox.PrivateMessageMaxLifetimeMs(channels.PingProtocol); got != ping.MaxLifetimeMs() {
		t.Fatalf("Ping TTL 不一致: %d", got)
	}
	if got := inbox.PrivateMessageMaxLifetimeMs(channels.WebRTCSignalProtocol); got != webrtcsignal.MaxLifetimeMs() {
		t.Fatalf("WebRTC TTL 不一致: %d", got)
	}
	if got := inbox.PrivateMessageMaxLifetimeMs(channels.AppMessageProtocol); got != 24*60*60*1000 {
		t.Fatalf("App Message TTL 不一致: %d", got)
	}
	if got := inbox.PrivateMessageMaxLifetimeMs("bsv8.unknown.v1"); got != 24*60*60*1000 {
		t.Fatalf("未知私密协议 TTL 不一致: %d", got)
	}

	localPing, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicB),
		FromPublicKey: publicA,
		Protocol:      channels.PingProtocol,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          ping.NewPing(),
	}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPing, err := inbox.VerifySignedPrivateMessage(localPing, 1500)
	if err != nil || !verifiedPing.IsVerified() {
		t.Fatalf("本地 Ping 验签失败: %v", err)
	}

	pongBody, err := ping.NewPong(messageID)
	if err != nil {
		t.Fatal(err)
	}
	signedPong, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicA),
		FromPublicKey: publicB,
		Protocol:      channels.PingProtocol,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          pongBody,
	}, privateB)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPong, err := inbox.VerifySignedPrivateMessage(signedPong, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidatePongRelation(verifiedPing, verifiedPong); err != nil {
		t.Fatalf("本地 Ping 与本地 Pong 关系校验失败: %v", err)
	}

	badSignature := localPing
	badSignature.Signature = channels.Signature{}
	if _, err := inbox.VerifySignedPrivateMessage(badSignature, 1500); !errors.Is(err, channels.ErrInvalidSignature) {
		t.Fatalf("错误签名未返回 INVALID_SIGNATURE: %v", err)
	}
	wrongSender := localPing
	wrongSender.FromPublicKey = publicB
	if _, err := inbox.VerifySignedPrivateMessage(wrongSender, 1500); !errors.Is(err, channels.ErrInvalidSignature) {
		t.Fatalf("错误发送者未返回 INVALID_SIGNATURE: %v", err)
	}
	badChannel := localPing
	badChannel.Channel = "bsv8.inbox.invalid"
	if _, err := inbox.VerifySignedPrivateMessage(badChannel, 1500); !errors.Is(err, channels.ErrInvalidChannel) {
		t.Fatalf("非法 channel 未返回 INVALID_CHANNEL: %v", err)
	}
	if _, err := inbox.VerifySignedPrivateMessage(localPing, 2000); !errors.Is(err, channels.ErrMessageExpired) {
		t.Fatalf("now_ms == expires_at_ms 未返回 MESSAGE_EXPIRED: %v", err)
	}

	futurePing, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicB),
		FromPublicKey: publicA,
		Protocol:      channels.PingProtocol,
		MessageID:     messageID,
		IssuedAtMs:    61001,
		ExpiresAtMs:   62001,
		Body:          ping.NewPing(),
	}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.VerifySignedPrivateMessage(futurePing, 1000); !errors.Is(err, channels.ErrInvalidTime) {
		t.Fatalf("超过未来时钟容差未返回 INVALID_TIME: %v", err)
	}
	tooLong := localPing
	tooLong.ExpiresAtMs = tooLong.IssuedAtMs + ping.MaxLifetimeMs() + 1
	if _, err := inbox.VerifySignedPrivateMessage(tooLong, 1500); !errors.Is(err, channels.ErrInvalidTime) {
		t.Fatalf("超过 Ping TTL 未返回 INVALID_TIME: %v", err)
	}

	webrtcMessageID, err := channels.ParseMessageID("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := channels.ParseSessionID("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk")
	if err != nil {
		t.Fatal(err)
	}
	offer, err := webrtcsignal.NewOffer(webrtcMessageID, sessionID, "v=0")
	if err != nil {
		t.Fatal(err)
	}
	answer, err := webrtcsignal.NewAnswer(webrtcMessageID, sessionID, "v=0")
	if err != nil {
		t.Fatal(err)
	}
	signedOffer, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicB),
		FromPublicKey: publicA,
		Protocol:      channels.WebRTCSignalProtocol,
		MessageID:     webrtcMessageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          offer,
	}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	signedAnswer, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicA),
		FromPublicKey: publicB,
		Protocol:      channels.WebRTCSignalProtocol,
		MessageID:     webrtcMessageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          answer,
	}, privateB)
	if err != nil {
		t.Fatal(err)
	}
	verifiedOffer, err := inbox.VerifySignedPrivateMessage(signedOffer, 1500)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAnswer, err := inbox.VerifySignedPrivateMessage(signedAnswer, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidateWebRTCRelation(verifiedOffer, verifiedAnswer); err != nil {
		t.Fatalf("本地 WebRTC offer/answer 关系校验失败: %v", err)
	}
	answerEnvelope, err := inbox.SealSigned(signedAnswer, privateB, bytes.NewReader(make([]byte, inbox.KDFSaltBytes+inbox.NonceBytes)))
	if err != nil {
		t.Fatal(err)
	}
	remoteAnswer, err := inbox.Open(channels.InboxChannel(publicA), mustMarshalEnvelope(t, answerEnvelope), privateA, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.ValidateWebRTCRelation(verifiedOffer, remoteAnswer); err != nil {
		t.Fatalf("本地 WebRTC offer 与远端 answer 关系校验失败: %v", err)
	}
}
