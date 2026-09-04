// 示例只使用 channels SDK 的本地纯函数，不启动网络连接。
package main

import (
	"fmt"
	"time"

	"github.com/bsv8/ChannelProtocol"
	"github.com/bsv8/ChannelProtocol/appmessage"
	"github.com/bsv8/ChannelProtocol/hashrequest"
	"github.com/bsv8/ChannelProtocol/inbox"
	"github.com/bsv8/ChannelProtocol/publicmessage"
	"github.com/bsv8/ChannelProtocol/webrtcsignal"
)

func main() {
	if err := hashRequestExample(); err != nil {
		panic(err)
	}
	if err := publicMessageExample(); err != nil {
		panic(err)
	}
	if err := webRTCExample(); err != nil {
		panic(err)
	}
	if err := deliverAckRetryExample(); err != nil {
		panic(err)
	}
}

// publicMessageExample 构造、签名、规范序列化并验签任意精确频道上的公开消息。
func publicMessageExample() error {
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
	channel := "bsv8.public.example.v1"
	now := time.Now().UnixMilli()
	signed, err := publicmessage.Sign(publicmessage.UnsignedMessage{
		Channel:       channel,
		FromPublicKey: publicKey,
		MessageID:     messageID,
		IssuedAtMs:    now,
		ExpiresAtMs:   now + publicmessage.MaxLifetimeMs(),
		Body:          map[string]any{"kind": "local-demo", "value": 1},
	}, privateKey)
	if err != nil {
		return err
	}
	encoded, err := publicmessage.Marshal(signed)
	if err != nil {
		return err
	}
	verified, err := publicmessage.ParseAndVerify(channel, encoded, now)
	if err != nil {
		return err
	}
	key := verified.DedupKey()
	fmt.Printf("通用公开消息：%s/%s/%s 签名和验签通过\n", key.Channel, key.FromPublicKey.String(), key.MessageID.String())
	return nil
}

// hashRequestExample 构造、签名并验签公开 Hash 请求。
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
	if !verified.IsVerified() {
		return fmt.Errorf("Hash 请求未完成验签")
	}
	fmt.Println("Hash 请求：签名和验签通过")
	return nil
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
	decoded, err := inbox.Open(envelope.Channel, envelopeJSON, recipientPrivate, now)
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
	ack, ok := ackReceived.AppMessage()
	if !ok {
		return fmt.Errorf("ACK 未分派为应用 body")
	}
	if _, ok := ack.(appmessage.AckBody); !ok {
		return fmt.Errorf("应用 body 不是 ACK")
	}
	if err := inbox.ValidateAckRelation(received, ackReceived); err != nil {
		return err
	}
	if _, err := inbox.SealSigned(signedDeliver, senderPrivate); err != nil {
		return err
	}
	fmt.Println("Deliver/ACK：可靠接收、关系校验和重新加密重试通过")
	return nil
}
