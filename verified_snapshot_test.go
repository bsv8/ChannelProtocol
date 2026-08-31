package channels_test

import (
	"bytes"
	"testing"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/internal/strictjson"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

func TestVerifiedSnapshotsCannotBeMutated(t *testing.T) {
	privateA, publicA := testKey(t, 1)
	privateB, publicB := testKey(t, 2)
	messageID, err := channels.ParseMessageID("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := channels.ParseSHA256Hash("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	signedPublic, err := hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: publicA,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: []hashrequest.Locator{hashrequest.NewWebRTCSDPLocator()}},
	}, privateA)
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := hashrequest.Marshal(signedPublic)
	if err != nil {
		t.Fatal(err)
	}
	verifiedPublic, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, publicJSON, 1500)
	if err != nil {
		t.Fatal(err)
	}

	bodyCopy := verifiedPublic.Body()
	bodyCopy.Locators[0].Kind = hashrequest.LocatorMultiaddr
	bodyCopy.Locators[0].Address = "/ip4/127.0.0.1/tcp/443"
	signedCopy := verifiedPublic.SignedMessage()
	signedCopy.Body.Locators[0].Kind = hashrequest.LocatorMultiaddr
	if got := verifiedPublic.Body().Locators[0].Kind; got != hashrequest.LocatorWebRTCSDP {
		t.Fatalf("验签后的 Hash body 被外部副本改写: %s", got)
	}
	reviewed, err := hashrequest.ReviewAdmission(verifiedPublic, publicA)
	if err != nil || !reviewed.IsReviewed() {
		t.Fatalf("AdmissionReviewed 构造失败: %v", err)
	}
	reviewedBody := reviewed.Message().Body()
	reviewedBody.Locators[0].Kind = hashrequest.LocatorMultiaddr
	if got := reviewed.Message().Body().Locators[0].Kind; got != hashrequest.LocatorWebRTCSDP {
		t.Fatalf("AdmissionReviewed body 被外部副本改写: %s", got)
	}

	content, err := appmessage.NewDeliver(map[string]any{"nested": map[string]any{"value": "before"}})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicB),
		FromPublicKey: publicA,
		Protocol:      channels.AppMessageProtocol,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          content,
	}, privateA, bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x21}, 12)...)))
	if err != nil {
		t.Fatal(err)
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := inbox.Open(envelope.Channel, envelopeJSON, privateB, 1500)
	if err != nil {
		t.Fatal(err)
	}
	originalBodyJSON := opened.BodyJSON()
	bodyJSONCopy := opened.BodyJSON()
	bodyJSONCopy[bytes.Index(bodyJSONCopy, []byte("before"))] = 'x'
	if !bytes.Equal(opened.BodyJSON(), originalBodyJSON) {
		t.Fatal("Open 后 body JSON 返回了内部可写引用")
	}

	dispatched, err := inbox.Dispatch(opened)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := dispatched.AppMessage()
	if !ok {
		t.Fatal("Dispatch 没有返回应用 body")
	}
	delivered, ok := decoded.(appmessage.DeliverBody)
	if !ok {
		t.Fatalf("Dispatch 返回了错误应用分支: %T", decoded)
	}
	nested, ok := delivered.Content.(map[string]strictjson.JSONValue)
	if !ok {
		t.Fatalf("解析后的嵌套 content 类型错误: %T", delivered.Content)
	}
	nestedValue, ok := nested["nested"].(map[string]strictjson.JSONValue)
	if !ok {
		t.Fatalf("解析后的嵌套对象类型错误: %T", nested["nested"])
	}
	nestedValue["value"] = "after"
	decodedAgain, ok := dispatched.AppMessage()
	if !ok {
		t.Fatal("第二次读取应用 body 失败")
	}
	deliveredAgain := decodedAgain.(appmessage.DeliverBody)
	nestedAgain := deliveredAgain.Content.(map[string]strictjson.JSONValue)["nested"].(map[string]strictjson.JSONValue)
	if nestedAgain["value"] != "before" {
		t.Fatal("Dispatch 返回的嵌套 content 改写了已验证快照")
	}
	if _, err := inbox.Dispatch(inbox.VerifiedPrivateMessage{}); !channels.IsErrorCode(err, channels.InvalidSignatureCode) {
		t.Fatalf("伪造 VerifiedPrivateMessage 未被拒绝: %v", err)
	}
}

func TestReviewOfferForHashRequest(t *testing.T) {
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
	hash, err := channels.ParseSHA256Hash("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	request, err := hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: publicB,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: []hashrequest.Locator{hashrequest.NewWebRTCSDPLocator()}},
	}, privateB)
	if err != nil {
		t.Fatal(err)
	}
	requestJSON, err := hashrequest.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	verifiedRequest, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, requestJSON, 1500)
	if err != nil {
		t.Fatal(err)
	}
	offerBody, err := webrtcsignal.NewOffer(messageID, sessionID, "v=0")
	if err != nil {
		t.Fatal(err)
	}
	offerEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(publicB),
		FromPublicKey: publicA,
		Protocol:      channels.WebRTCSignalProtocol,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          offerBody,
	}, privateA, bytes.NewReader(append(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0x21}, 12)...)))
	if err != nil {
		t.Fatal(err)
	}
	offerJSON, err := inbox.Marshal(offerEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	verifiedOffer, err := inbox.Open(offerEnvelope.Channel, offerJSON, privateB, 1500)
	if err != nil {
		t.Fatal(err)
	}
	key, err := channels.ReviewOfferForHashRequest(verifiedRequest, verifiedOffer, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if !key.RequestMessageID.Equal(messageID) || !key.OffererPublicKey.Equal(publicA) || !key.SessionID.Equal(sessionID) {
		t.Fatal("统一 offer/Hash 关系审查返回了错误 SessionKey")
	}

	noWebRTC, err := hashrequest.NewMultiaddrLocator("/ip4/127.0.0.1/tcp/443")
	if err != nil {
		t.Fatal(err)
	}
	noWebRTCRequest, err := hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: publicB,
		MessageID:     messageID,
		IssuedAtMs:    1000,
		ExpiresAtMs:   2000,
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: []hashrequest.Locator{noWebRTC}},
	}, privateB)
	if err != nil {
		t.Fatal(err)
	}
	noWebRTCJSON, err := hashrequest.Marshal(noWebRTCRequest)
	if err != nil {
		t.Fatal(err)
	}
	verifiedNoWebRTC, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, noWebRTCJSON, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channels.ReviewOfferForHashRequest(verifiedNoWebRTC, verifiedOffer, 1500); !channels.IsErrorCode(err, channels.InvalidRelationCode) {
		t.Fatalf("缺少 webrtc-sdp locator 未被拒绝: %v", err)
	}
	if _, err := channels.ReviewOfferForHashRequest(verifiedRequest, verifiedOffer, 2000); !channels.IsErrorCode(err, channels.MessageExpiredCode) {
		t.Fatalf("过期 Hash 请求未被拒绝: %v", err)
	}
}
