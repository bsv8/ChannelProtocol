import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import * as channels from "../dist/index.js";
import * as appmessage from "../dist/app-message/index.js";
import * as hashrequest from "../dist/hash-request/index.js";
import * as inbox from "../dist/inbox/index.js";
import * as webrtc from "../dist/webrtc-signal/index.js";

const fixture = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/interop-v1.json", import.meta.url), "utf8"));
const textDecoder = new TextDecoder();

function bytesFromHex(value) {
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return result;
}

function codeIs(code) {
  return (error) => error?.code === code;
}

function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fixedKeys() {
  const privateA = channels.parsePrivateKey(bytesFromHex(fixture.test_only_private_key_a_hex));
  const privateB = channels.parsePrivateKey(bytesFromHex(fixture.test_only_private_key_b_hex));
  return { privateA, privateB, publicA: channels.parsePublicKey(fixture.public_key_a), publicB: channels.parsePublicKey(fixture.public_key_b) };
}

function fixedHashMessage() {
  const { privateA, publicA } = fixedKeys();
  return hashrequest.sign({
    from_public_key: publicA,
    message_id: channels.parseMessageID(fixture.message_id),
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: { hash: channels.parseSHA256Hash(fixture.hash), locators: [hashrequest.newWebRTCSDPLocator()] },
  }, privateA);
}

async function fixedPrivateEnvelope() {
  const { privateA, publicA, publicB } = fixedKeys();
  const messageId = channels.parseMessageID(fixture.message_id);
  const body = webrtc.newOffer(messageId, channels.parseSessionID(fixture.session_id), "v=0");
  const signed = inbox.signPrivateMessage({
    channel: channels.inboxChannel(publicB),
    from_public_key: publicA,
    protocol: channels.WEBRTC_SIGNAL_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body,
  }, privateA);
  const random = new Uint8Array(44);
  random.fill(0x21, 32);
  return { privateA, privateB: fixedKeys().privateB, publicA, publicB, signed, envelope: await inbox.sealSigned(signed, privateA, channels.fixedRandom(random)) };
}

test("共享 JCS fixture 与非法 JSON 全量执行", () => {
  const valid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/jcs-valid.json", import.meta.url), "utf8"));
  for (const item of valid.cases) assert.equal(hex(channels.canonicalizeJSON(item.input)), item.expected_utf8_hex, item.input);
  const invalid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/jcs-invalid.json", import.meta.url), "utf8"));
  for (const item of invalid.cases) assert.throws(() => channels.canonicalizeJSON(item.json), codeIs(item.expected_code), item.name);
  assert.throws(() => channels.canonicalizeJSON(`${"[".repeat(channels.MAX_JSON_DEPTH + 1)}0${"]".repeat(channels.MAX_JSON_DEPTH + 1)}`), codeIs("MESSAGE_TOO_LARGE"));
  assert.throws(() => channels.canonicalizeJSON(`"${"x".repeat(channels.MAX_JSON_BYTES)}"`), codeIs("MESSAGE_TOO_LARGE"));
  assert.throws(() => channels.canonicalizeJSON(`[${Array(channels.MAX_JSON_NODES).fill("0").join(",")}]`), codeIs("MESSAGE_TOO_LARGE"));
});

test("原语、时间和 Hash 请求严格校验", () => {
  const valid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/primitives-valid.json", import.meta.url), "utf8"));
  assert.equal(channels.parsePublicKey(valid.public_key), valid.public_key);
  assert.equal(channels.parseMessageID(valid.message_id), valid.message_id);
  assert.equal(channels.parseSessionID(valid.session_id), valid.session_id);
  assert.equal(channels.parseSHA256Hash(valid.sha256), valid.sha256);
  assert.equal(channels.parseUnixMillis(valid.unix_millis), valid.unix_millis);
  const invalid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/primitives-invalid.json", import.meta.url), "utf8"));
  for (const item of invalid.cases) {
    const action = item.operation === "public_key" ? () => channels.parsePublicKey(item.value)
      : item.operation === "message_id" ? () => channels.parseMessageID(item.value)
        : item.operation === "session_id" ? () => channels.parseSessionID(item.value)
          : item.operation === "sha256" ? () => channels.parseSHA256Hash(item.value)
            : item.operation === "private_key_hex" ? () => channels.parsePrivateKey(bytesFromHex(item.value))
              : () => channels.parseUnixMillis(item.value);
    assert.throws(action, codeIs(item.expected_code), item.name);
  }

  const message = fixedHashMessage();
  const encoded = hashrequest.marshal(message);
  const verified = hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, encoded, 1500);
  assert.equal(verified.digest, fixture.hash_request.digest_hex);
  assert.equal(verified.signature, fixture.hash_request.signature);
  assert(Object.isFrozen(verified));
  assert(Object.isFrozen(verified.body));
  assert(Object.isFrozen(verified.body.locators));
  assert(Object.isFrozen(verified.body.locators[0]));
  assert.throws(() => { verified.body.locators[0].kind = "multiaddr"; }, TypeError);
  assert.equal(verified.body.locators[0].kind, "webrtc-sdp");
  assert.equal(hashrequest.reviewAdmission(verified, verified.from_public_key).authenticated_public_key, verified.from_public_key);
  assert.throws(() => hashrequest.reviewAdmission({ ...verified }, verified.from_public_key), codeIs("INVALID_SIGNATURE"));

  const hashValid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/hash-request-valid.json", import.meta.url), "utf8"));
  for (const item of hashValid.multiaddr_cases) assert.equal(hashrequest.newMultiaddrLocator(item.address).address, item.address, item.name);
  assert.throws(() => hashrequest.parseAndVerify("bsv8.hash.request.v2", encoded, 1500), codeIs("INVALID_CHANNEL"));
  assert.throws(() => hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, encoded, 2000), codeIs("MESSAGE_EXPIRED"));
  assert.throws(() => hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, JSON.stringify({ ...JSON.parse(textDecoder.decode(encoded)), unknown: 1 }), 1500), codeIs("UNKNOWN_FIELD"));
});

test("私密信封固定向量、统一 OPEN_FAILED 和强类型分派", async () => {
  const { privateA, privateB, publicB, envelope } = await fixedPrivateEnvelope();
  const envelopeJSON = inbox.marshalEnvelope(envelope);
  assert.deepEqual(JSON.parse(textDecoder.decode(envelopeJSON)), fixture.private_message.envelope);
  const parsed = inbox.parseEnvelope(channels.inboxChannel(publicB), envelopeJSON);
  assert.equal(parsed.from_public_key, fixture.public_key_a);
  const opened = await inbox.open(channels.inboxChannel(publicB), envelopeJSON, privateB, 1500);
  assert(Object.isFrozen(opened));
  assert(Object.isFrozen(opened.body));
  assert(Object.isFrozen(opened.body.signal));
  assert.throws(() => { opened.body.signal.sdp = "tampered"; }, TypeError);
  assert.equal(opened.body.signal.sdp, "v=0");
  const dispatched = inbox.dispatch(opened);
  assert.equal(dispatched.protocol, channels.WEBRTC_SIGNAL_PROTOCOL);
  assert.equal(dispatched.body.signal.type, "offer");
  assert.throws(() => inbox.dispatch({ ...opened }), codeIs("INVALID_SIGNATURE"));
  await assert.rejects(() => inbox.open(channels.inboxChannel(publicB), envelopeJSON, privateA, 1500), codeIs("OPEN_FAILED"));
  const tampered = JSON.parse(textDecoder.decode(envelopeJSON));
  const ciphertext = atob(tampered.ciphertext.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (tampered.ciphertext.length % 4)) % 4));
  const ciphertextBytes = Uint8Array.from(ciphertext, (character) => character.charCodeAt(0));
  ciphertextBytes[ciphertextBytes.length - 1] ^= 1;
  tampered.ciphertext = channels.base64urlEncode(ciphertextBytes);
  await assert.rejects(() => inbox.open(channels.inboxChannel(publicB), JSON.stringify(tampered), privateB, 1500), codeIs("OPEN_FAILED"));
  assert.throws(() => inbox.parseEnvelope(channels.inboxChannel(publicB), JSON.stringify({ ...tampered, envelope_version: 2 })), codeIs("INVALID_ENVELOPE"));
});

test("统一审查 WebRTC offer 与 Hash 请求关联", async () => {
  const { privateA, privateB, publicA, publicB } = fixedKeys();
  const messageId = channels.parseMessageID(fixture.message_id);
  const sessionId = channels.parseSessionID(fixture.session_id);
  const hash = channels.parseSHA256Hash(fixture.hash);
  const request = hashrequest.sign({
    from_public_key: publicB,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: { hash, locators: [hashrequest.newWebRTCSDPLocator()] },
  }, privateB);
  const verifiedRequest = hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, textDecoder.decode(hashrequest.marshal(request)), 1500);
  const offerBody = webrtc.newOffer(messageId, sessionId, "v=0");
  const signedOffer = inbox.signPrivateMessage({
    channel: channels.inboxChannel(publicB),
    from_public_key: publicA,
    protocol: channels.WEBRTC_SIGNAL_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: offerBody,
  }, privateA);
  const random = new Uint8Array(44);
  random.fill(0x21, 32);
  const envelope = await inbox.sealSigned(signedOffer, privateA, channels.fixedRandom(random));
  const verifiedOffer = await inbox.open(channels.inboxChannel(publicB), inbox.marshalEnvelope(envelope), privateB, 1500);
  const key = inbox.reviewOfferForHashRequest(verifiedRequest, verifiedOffer, 1500);
  assert.equal(key.request_message_id, messageId);
  assert.equal(key.offerer_public_key, publicA);
  assert.equal(key.session_id, sessionId);

  const noWebRTC = hashrequest.sign({
    from_public_key: publicB,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: { hash, locators: [hashrequest.newMultiaddrLocator("/ip4/127.0.0.1/tcp/443")] },
  }, privateB);
  const verifiedNoWebRTC = hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, hashrequest.marshal(noWebRTC), 1500);
  assert.throws(() => inbox.reviewOfferForHashRequest(verifiedNoWebRTC, verifiedOffer, 1500), codeIs("INVALID_RELATION"));
  assert.throws(() => inbox.reviewOfferForHashRequest(verifiedRequest, verifiedOffer, 2000), codeIs("MESSAGE_EXPIRED"));
});

test("共享 dedup-and-relations fixture 全量校验去重与关联结果", async () => {
  const value = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/dedup-and-relations.json", import.meta.url), "utf8"));
  const { privateA, privateB, publicA, publicB } = fixedKeys();
  assert.equal(value.public_key_a, publicA);
  assert.equal(value.public_key_b, publicB);
  assert.equal(value.session_key.separator.length, 1);
  assert.equal(value.session_key.separator.charCodeAt(0), 0);

  const publicInput = value.public_hash_request;
  const publicMessage = hashrequest.sign({
    from_public_key: publicA,
    message_id: channels.parseMessageID(publicInput.message_id),
    issued_at_ms: publicInput.issued_at_ms,
    expires_at_ms: publicInput.expires_at_ms,
    body: {
      hash: channels.parseSHA256Hash(publicInput.body.hash),
      locators: publicInput.body.locators.map((item) => item.kind === "webrtc-sdp"
        ? hashrequest.newWebRTCSDPLocator()
        : hashrequest.newMultiaddrLocator(item.address)),
    },
  }, privateA);
  const verifiedPublic = hashrequest.parseAndVerify(publicInput.channel, hashrequest.marshal(publicMessage), publicInput.issued_at_ms + 500);
  const publicKey = hashrequest.dedupKey(verifiedPublic);
  assert.deepEqual([publicKey.channel, publicKey.from_public_key, publicKey.message_id], value.expected.public_dedup_key);

  const privateInput = value.private_deliver;
  assert.equal(privateInput.channel, channels.inboxChannel(publicB));
  const privateBody = appmessage.parseBody(JSON.stringify(privateInput.body));
  const signedPrivate = inbox.signPrivateMessage({
    channel: privateInput.channel,
    from_public_key: publicA,
    protocol: privateInput.protocol,
    message_id: channels.parseMessageID(privateInput.message_id),
    issued_at_ms: privateInput.issued_at_ms,
    expires_at_ms: privateInput.expires_at_ms,
    body: privateBody,
  }, privateA);
  const random = new Uint8Array(44);
  random.fill(0x32, 32);
  const envelope = await inbox.sealSigned(signedPrivate, privateA, channels.fixedRandom(random));
  const opened = await inbox.open(privateInput.channel, inbox.marshalEnvelope(envelope), privateB, privateInput.issued_at_ms + 500);
  const privateKey = inbox.dedupKey(opened);
  assert.deepEqual([privateKey.protocol, privateKey.from_public_key, privateKey.message_id], value.expected.private_dedup_key);

  const session = webrtc.sessionKey(
    channels.parseMessageID(value.session_key.request_message_id),
    channels.parsePublicKey(value.session_key.offerer_public_key),
    channels.parseSessionID(value.session_key.session_id),
  );
  assert.equal(session.key, value.expected.session_key);

  const delivery = {
    from_public_key: channels.parsePublicKey(value.ack.delivery.from_public_key),
    to_public_key: channels.parsePublicKey(value.ack.delivery.to_public_key),
    message_id: channels.parseMessageID(value.ack.delivery.message_id),
  };
  const ackContext = (item) => ({
    from_public_key: channels.parsePublicKey(item.from_public_key),
    to_public_key: channels.parsePublicKey(item.to_public_key),
    body: appmessage.newAck(channels.parseMessageID(item.acknowledged_message_id)),
  });
  assert.equal(value.ack.valid.expected_code, null);
  assert.doesNotThrow(() => appmessage.validateAckRelation(delivery, ackContext(value.ack.valid)));
  const ackInvalid = value.ack.invalid.map((item) => {
    assert.throws(() => appmessage.validateAckRelation(delivery, ackContext(item)), codeIs(item.expected_code), item.name);
    return { name: item.name, code: item.expected_code };
  });
  assert.deepEqual(ackInvalid, value.expected.ack_invalid);

  const sameDigest = channels.parseSHA256Hash(value.conflict.same_digest);
  const differentDigest = channels.parseSHA256Hash(value.conflict.different_digest);
  assert.equal(value.conflict.expected_same_code, null);
  assert.doesNotThrow(() => appmessage.checkDigestConflict(sameDigest, sameDigest));
  assert.doesNotThrow(() => inbox.checkDigestConflict(sameDigest, sameDigest));
  assert.throws(() => appmessage.checkDigestConflict(sameDigest, differentDigest), codeIs(value.conflict.expected_different_code));
  assert.throws(() => inbox.checkDigestConflict(sameDigest, differentDigest), codeIs(value.conflict.expected_different_code));
  assert.equal(value.expected.conflict_code, value.conflict.expected_different_code);
});

test("WebRTC 四分支、SessionKey 和 ACK 关系保持隔离", () => {
  const requestId = channels.parseMessageID(fixture.message_id);
  const sessionId = channels.parseSessionID(fixture.session_id);
  const signals = [
    webrtc.newOffer(requestId, sessionId, "v=0"),
    webrtc.newAnswer(requestId, sessionId, "v=0"),
    webrtc.newICECandidate(requestId, sessionId, { candidate: "candidate:1", sdp_mid: null, sdp_m_line_index: 0 }),
    webrtc.newEndOfCandidates(requestId, sessionId),
  ];
  for (const signal of signals) assert.deepEqual(webrtc.parseBody(textDecoder.decode(channels.canonicalizeValue(signal))), signal);
  const { publicA, publicB } = fixedKeys();
  const context = webrtc.newSessionContext(signals[0], publicA, publicB);
  webrtc.validateRelation(signals[1], context, publicB);
  assert.throws(() => webrtc.validateRelation(signals[1], context, publicA), codeIs("INVALID_RELATION"));
  const app = appmessage.newDeliver({ sdp: { application: true } });
  assert.equal(app.type, "deliver");
  const ack = appmessage.newAck(requestId);
  appmessage.validateAckRelation({ from_public_key: publicA, to_public_key: publicB, message_id: requestId }, { from_public_key: publicB, to_public_key: publicA, body: ack });
  assert.throws(() => appmessage.validateAckRelation({ from_public_key: publicA, to_public_key: publicB, message_id: requestId }, { from_public_key: publicA, to_public_key: publicB, body: ack }), codeIs("INVALID_RELATION"));
  assert.throws(() => appmessage.checkDigestConflict(channels.parseSHA256Hash("0".repeat(64)), channels.parseSHA256Hash("1".repeat(64))), codeIs("MESSAGE_ID_CONFLICT"));
});

test("注册表与机器可读映射一致", () => {
  const source = JSON.parse(fs.readFileSync(new URL("../../protocols.json", import.meta.url), "utf8"));
  assert.equal(source.protocols.length, channels.PROTOCOL_REGISTRY.length);
  for (const [index, item] of source.protocols.entries()) {
    assert.equal(channels.PROTOCOL_REGISTRY[index].identifier, item.identifier);
    assert.equal(channels.PROTOCOL_REGISTRY[index].exportPath, item.typescript_export);
  }
});

test("共享协议 invalid fixture 全量返回冻结错误码", async () => {
  const hashInvalid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/hash-request-invalid.json", import.meta.url), "utf8"));
  const hashCases = hashInvalid.cases;
  for (const item of hashCases) {
    assert.throws(() => hashrequest.parseAndVerify(item.channel, item.json, item.now_ms), codeIs(item.expected_code), item.name);
  }

  const appInvalid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/app-message-invalid.json", import.meta.url), "utf8"));
  for (const item of appInvalid.cases) assert.throws(() => appmessage.parseBody(item.json), codeIs(item.expected_code), item.name);

  const webrtcInvalid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/webrtc-signal-invalid.json", import.meta.url), "utf8"));
  for (const item of webrtcInvalid.cases) {
    if (item.operation === "parse") {
      assert.throws(() => webrtc.parseBody(item.json), codeIs(item.expected_code), item.name);
    } else if (item.operation === "relation") {
      const { publicA, publicB } = fixedKeys();
      const validOffer = webrtc.newOffer(channels.parseMessageID(fixture.message_id), channels.parseSessionID(fixture.session_id), "v=0");
      const context = webrtc.newSessionContext(validOffer, publicA, publicB);
      const answer = webrtc.parseBody(item.json);
      assert.throws(() => webrtc.validateRelation(answer, context, publicB), codeIs(item.expected_code), item.name);
    } else {
      assert.fail(`unknown WebRTC fixture operation: ${item.operation}`);
    }
  }

  const envelopeInvalid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/inbox-crypto-invalid.json", import.meta.url), "utf8"));
  for (const item of envelopeInvalid.cases) {
    const envelopeJSON = JSON.stringify(item.envelope);
    if (item.operation === "parse") {
      assert.throws(() => inbox.parseEnvelope(item.channel, envelopeJSON), codeIs(item.expected_code), item.name);
      continue;
    }
    const privateKey = channels.parsePrivateKey(bytesFromHex(item.recipient_private_key_hex));
    if (item.operation === "open_dispatch") {
      const opened = await inbox.open(item.channel, envelopeJSON, privateKey, 1500);
      assert.throws(() => inbox.dispatch(opened), codeIs(item.expected_code), item.name);
      continue;
    }
    await assert.rejects(() => inbox.open(item.channel, envelopeJSON, privateKey, 1500), codeIs(item.expected_code), item.name);
  }

  const publicSignature = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/signature-public.json", import.meta.url), "utf8"));
  const privateSignature = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/signature-private.json", import.meta.url), "utf8"));
  assert.equal(hashrequest.signedDigest(fixedHashMessage()), publicSignature.digest_hex);
  assert.equal((await fixedPrivateEnvelope()).signed.signature, privateSignature.signature);
});
