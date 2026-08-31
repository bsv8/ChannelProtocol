// 示例只使用 channels SDK 的本地纯函数，不启动网络连接。
import * as channels from "../dist/index.js";
import * as appmessage from "../dist/app-message/index.js";
import * as hashrequest from "../dist/hash-request/index.js";
import * as inbox from "../dist/inbox/index.js";
import * as webrtc from "../dist/webrtc-signal/index.js";

const zeroHash = channels.sha256HashFromBytes(new Uint8Array(32));

// 示例一：构造、签名并审查公开 Hash 请求。
function hashRequestExample() {
  const privateKey = channels.generatePrivateKey();
  const publicKey = channels.publicKeyFromPrivate(privateKey);
  const message = hashrequest.sign({
    from_public_key: publicKey,
    message_id: channels.newMessageID(),
    issued_at_ms: 1_000,
    expires_at_ms: 2_000,
    body: { hash: zeroHash, locators: [hashrequest.newWebRTCSDPLocator()] },
  }, privateKey);
  const verified = hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, hashrequest.marshal(message), 1_500);
  hashrequest.reviewAdmission(verified, publicKey);
  console.log("Hash 请求：签名和发布入口身份审查通过");
}

// 示例二：签名、长期密钥加密、解密并强类型分派 WebRTC offer。
async function webRTCExample() {
  const senderPrivate = channels.generatePrivateKey();
  const recipientPrivate = channels.generatePrivateKey();
  const senderPublic = channels.publicKeyFromPrivate(senderPrivate);
  const recipientPublic = channels.publicKeyFromPrivate(recipientPrivate);
  const requestID = channels.newMessageID();
  const body = webrtc.newOffer(requestID, channels.newSessionID(), "v=0");
  const envelope = await inbox.signAndSeal({
    channel: channels.inboxChannel(recipientPublic),
    from_public_key: senderPublic,
    protocol: channels.WEBRTC_SIGNAL_PROTOCOL,
    message_id: requestID,
    issued_at_ms: 1_000,
    expires_at_ms: 2_000,
    body,
  }, senderPrivate);
  const decoded = await channels.decodePrivateChannel(envelope.channel, inbox.marshalEnvelope(envelope), recipientPrivate, 1_500);
  if (decoded.body.signal.type !== "offer") throw new Error("WebRTC body 分派类型错误");
  console.log("WebRTC：长期密钥加解密和强类型分派通过");
}

// 示例三：Deliver、可靠保存后的 ACK 关系校验和同一签名消息重新加密。
async function deliverAckRetryExample() {
  const senderPrivate = channels.generatePrivateKey();
  const recipientPrivate = channels.generatePrivateKey();
  const senderPublic = channels.publicKeyFromPrivate(senderPrivate);
  const recipientPublic = channels.publicKeyFromPrivate(recipientPrivate);
  const deliverID = channels.newMessageID();
  const signedDeliver = inbox.signPrivateMessage({
    channel: channels.inboxChannel(recipientPublic),
    from_public_key: senderPublic,
    protocol: channels.APP_MESSAGE_PROTOCOL,
    message_id: deliverID,
    issued_at_ms: 1_000,
    expires_at_ms: 2_000,
    body: appmessage.newDeliver({ kind: "local-demo", value: 1 }),
  }, senderPrivate);
  const envelope = await inbox.sealSigned(signedDeliver, senderPrivate);
  const received = await inbox.openAndDispatch(envelope.channel, inbox.marshalEnvelope(envelope), recipientPrivate, 1_500);
  const ackID = channels.newMessageID();
  const ackEnvelope = await inbox.signAndSeal({
    channel: channels.inboxChannel(senderPublic),
    from_public_key: recipientPublic,
    protocol: channels.APP_MESSAGE_PROTOCOL,
    message_id: ackID,
    issued_at_ms: 1_000,
    expires_at_ms: 2_000,
    body: appmessage.newAck(received.message_id),
  }, recipientPrivate);
  const ack = await inbox.openAndDispatch(ackEnvelope.channel, inbox.marshalEnvelope(ackEnvelope), senderPrivate, 1_500);
  if (ack.body.type !== "ack") throw new Error("ACK body 分派类型错误");
  appmessage.validateAckRelation(
    { from_public_key: received.from_public_key, to_public_key: received.to_public_key, message_id: received.message_id },
    { from_public_key: ack.from_public_key, to_public_key: ack.to_public_key, body: ack.body },
  );
  await inbox.sealSigned(signedDeliver, senderPrivate);
  console.log("Deliver/ACK：可靠接收、关系校验和重新加密重试通过");
}

hashRequestExample();
await webRTCExample();
await deliverAckRetryExample();
