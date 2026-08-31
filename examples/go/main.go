// 示例只使用 channels SDK 的本地纯函数，不启动网络连接。
package main

import (
	"fmt"
	"time"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

func main() {
	if err := hashRequestExample(); err != nil {
		panic(err)
	}
	if err := webRTCExample(); err != nil {
		panic(err)
	}
	if err := deliverAckRetryExample(); err != nil {
		panic(err)
	}
}

// hashRequestExample 构造、签名并审查公开 Hash 请求。
func hashRequestExample() error {
	privateKey, err := channels.GeneratePrivateKey()
	if err != nil {
		return err
	}
	publicKey, err := channels.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return err
	}
	messageID, err := channels.NewMessageID(nil)
	if err != nil {
		return err
	}
	hash, err := channels.ParseSHA256Hash("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		return err
	}
	message, err := hashrequest.Sign(hashrequest.UnsignedMessage{
		FromPublicKey: publicKey,
		MessageID:     messageID,
		IssuedAtMs:    time.Now().UnixMilli(),
		ExpiresAtMs:   time.Now().Add(10 * time.Minute).UnixMilli(),
		Body:          hashrequest.HashRequestBody{Hash: hash, Locators: []hashrequest.Locator{hashrequest.NewWebRTCSDPLocator()}},
	}, privateKey)
	if err != nil {
		return err
	}
	encoded, err := hashrequest.Marshal(message)
	if err != nil {
		return err
	}
	verified, err := hashrequest.ParseAndVerify(channels.HashRequestChannel, encoded, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	_, err = verified.ReviewAdmission(publicKey)
	if err == nil {
		fmt.Println("Hash 请求：签名和发布入口身份审查通过")
	}
	return err
}

// webRTCExample 签名、长期密钥加密、解密并强类型分派 WebRTC offer。
func webRTCExample() error {
	senderPrivate, err := channels.GeneratePrivateKey()
	if err != nil {
		return err
	}
	recipientPrivate, err := channels.GeneratePrivateKey()
	if err != nil {
		return err
	}
	senderPublic, err := channels.PublicKeyFromPrivate(senderPrivate)
	if err != nil {
		return err
	}
	recipientPublic, err := channels.PublicKeyFromPrivate(recipientPrivate)
	if err != nil {
		return err
	}
	requestID, err := channels.NewMessageID(nil)
	if err != nil {
		return err
	}
	sessionID, err := channels.NewSessionID(nil)
	if err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	body, err := webrtcsignal.NewOffer(requestID, sessionID, "v=0")
	if err != nil {
		return err
	}
	envelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(recipientPublic),
		FromPublicKey: senderPublic,
		Protocol:      channels.WebRTCSignalProtocol,
		MessageID:     requestID,
		IssuedAtMs:    now,
		ExpiresAtMs:   now + webrtcsignal.MaxLifetimeMs(),
		Body:          body,
	}, senderPrivate)
	if err != nil {
		return err
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		return err
	}
	decoded, err := channels.DecodeInboxChannel(envelope.Channel, envelopeJSON, recipientPrivate, now)
	if err != nil {
		return err
	}
	if _, ok := decoded.WebRTCSignal(); !ok {
		return fmt.Errorf("未分派为 WebRTC body")
	}
	fmt.Println("WebRTC：长期密钥加解密和强类型分派通过")
	return nil
}

// deliverAckRetryExample 展示可靠保存后的 ACK 关系校验和同一签名消息重新加密。
func deliverAckRetryExample() error {
	senderPrivate, err := channels.GeneratePrivateKey()
	if err != nil {
		return err
	}
	recipientPrivate, err := channels.GeneratePrivateKey()
	if err != nil {
		return err
	}
	senderPublic, err := channels.PublicKeyFromPrivate(senderPrivate)
	if err != nil {
		return err
	}
	recipientPublic, err := channels.PublicKeyFromPrivate(recipientPrivate)
	if err != nil {
		return err
	}
	deliverID, err := channels.NewMessageID(nil)
	if err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	deliverBody, err := appmessage.NewDeliver(map[string]any{"kind": "local-demo", "value": 1})
	if err != nil {
		return err
	}
	signedDeliver, err := inbox.SignPrivateMessage(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(recipientPublic),
		FromPublicKey: senderPublic,
		Protocol:      channels.AppMessageProtocol,
		MessageID:     deliverID,
		IssuedAtMs:    now,
		ExpiresAtMs:   now + appmessage.MaxLifetimeMs(),
		Body:          deliverBody,
	}, senderPrivate)
	if err != nil {
		return err
	}
	envelope, err := inbox.SealSigned(signedDeliver, senderPrivate)
	if err != nil {
		return err
	}
	envelopeJSON, err := inbox.Marshal(envelope)
	if err != nil {
		return err
	}
	received, err := inbox.Open(envelope.Channel, envelopeJSON, recipientPrivate, now)
	if err != nil {
		return err
	}
	if _, err := inbox.Dispatch(received); err != nil {
		return err
	}
	ackBody, err := appmessage.NewAck(received.MessageID())
	if err != nil {
		return err
	}
	ackID, err := channels.NewMessageID(nil)
	if err != nil {
		return err
	}
	ackEnvelope, err := inbox.SignAndSeal(inbox.UnsignedPrivateMessage{
		Channel:       channels.InboxChannel(senderPublic),
		FromPublicKey: recipientPublic,
		Protocol:      channels.AppMessageProtocol,
		MessageID:     ackID,
		IssuedAtMs:    now,
		ExpiresAtMs:   now + appmessage.MaxLifetimeMs(),
		Body:          ackBody,
	}, recipientPrivate)
	if err != nil {
		return err
	}
	ackJSON, err := inbox.Marshal(ackEnvelope)
	if err != nil {
		return err
	}
	ackReceived, err := inbox.Open(ackEnvelope.Channel, ackJSON, senderPrivate, now)
	if err != nil {
		return err
	}
	ackDecoded, err := inbox.Dispatch(ackReceived)
	if err != nil {
		return err
	}
	ack, ok := ackDecoded.AppMessage()
	if !ok {
		return fmt.Errorf("ACK 未分派为应用 body")
	}
	ackValue, ok := ack.(appmessage.AckBody)
	if !ok {
		return fmt.Errorf("应用 body 不是 ACK")
	}
	if err := appmessage.ValidateAckRelation(
		appmessage.DeliveryContext{FromPublicKey: received.FromPublicKey(), ToPublicKey: received.ToPublicKey(), MessageID: received.MessageID()},
		appmessage.AckContext{FromPublicKey: ackReceived.FromPublicKey(), ToPublicKey: ackReceived.ToPublicKey(), Body: ackValue},
	); err != nil {
		return err
	}
	if _, err := inbox.SealSigned(signedDeliver, senderPrivate); err != nil {
		return err
	}
	fmt.Println("Deliver/ACK：可靠接收、关系校验和重新加密重试通过")
	return nil
}
