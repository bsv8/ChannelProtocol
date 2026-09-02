package channels_test

import (
	"bytes"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

func testKey(t *testing.T, value byte) (channels.PrivateKey, channels.PublicKey) {
	t.Helper()
	bytesValue := make([]byte, 32)
	bytesValue[31] = value
	privateKey, err := channels.ParsePrivateKey(bytesValue)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBytes := func() []byte {
		// 通过内部推导不可见，使用已知 secp256k1 私钥的公钥字符串作为跨语言固定值。
		known := map[byte]string{
			1: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			2: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		}
		value, ok := known[value]
		if !ok {
			t.Fatal("test key missing")
		}
		parsed, err := channels.ParsePublicKey(value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Bytes()
	}()
	publicKey, err := channels.NewPublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey
}

func TestHashAndInboxRoundTrip(t *testing.T) {
	senderPrivate, senderPublic := testKey(t, 1)
	recipientPrivate, recipientPublic := testKey(t, 2)
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := channels.ParseSHA256Hash("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	public, err := hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: senderPublic,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: []hashrequest.Locator{hashrequest.NewWebRTCSDPLocator()}},
	}, senderPrivate)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := hashrequest.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPublic, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, publicBytes, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if !verifiedPublic.IsVerified() {
		t.Fatal("公开消息未完成验签")
	}

	sessionID, err := channels.ParseSessionID("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk")
	if err != nil {
		t.Fatal(err)
	}
	body, err := webrtcsignal.NewOffer(messageID, sessionID, "v=0")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(recipientPublic),
		FromPublicKey: senderPublic,
		Protocol:      channels.WebRTCSignalProtocol,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          body,
	}, senderPrivate, bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x21}, 12)...)))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := inbox.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := inbox.Open(envelope.Channel, envelopeBytes, recipientPrivate, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Protocol() != channels.WebRTCSignalProtocol {
		t.Fatalf("unexpected protocol: %s", opened.Protocol())
	}
	if _, ok := opened.WebRTCSignal(); !ok {
		t.Fatal("open did not return WebRTC body")
	}

	content, err := appmessage.NewDeliver(map[string]any{"sdp": "application data", "n": 1})
	if err != nil {
		t.Fatal(err)
	}
	_ = content
}
