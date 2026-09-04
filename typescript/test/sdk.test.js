import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import * as channels from "../dist/index.js";
import * as appmessage from "../dist/app-message/index.js";
import * as hashrequest from "../dist/hash-request/index.js";
import * as inbox from "../dist/inbox/index.js";
import * as ping from "../dist/ping/index.js";
import * as publicmessage from "../dist/public-message/index.js";
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

function publicMessageValidFixture() {
  return JSON.parse(fs.readFileSync(new URL("../../testdata/v1/public-message-valid.json", import.meta.url), "utf8"));
}

function publicMessageInvalidFixture() {
  return JSON.parse(fs.readFileSync(new URL("../../testdata/v1/public-message-invalid.json", import.meta.url), "utf8"));
}

function mutatePublicMessage(baseJSON, mutation) {
  if (mutation === "none") return baseJSON;
  const object = JSON.parse(baseJSON);
  switch (mutation) {
    case "missing_body": delete object.body; break;
    case "missing_signature": delete object.signature; break;
    case "unknown_field": object.unknown = 1; break;
    case "content_old_shape": delete object.body; object.content = { legacy: true }; break;
    case "wrong_public_key_type": object.from_public_key = 1; break;
    case "issued_equals_expires": object.issued_at_ms = 2000; break;
    case "lifetime_over_max": object.expires_at_ms = 601001; break;
    case "future_skew_over_max": object.issued_at_ms = 61001; object.expires_at_ms = 661001; break;
    case "wrong_public_key": object.from_public_key = fixture.public_key_b; break;
    case "wrong_signature": object.signature = "AAAA"; break;
    case "high_s_signature": object.signature = "MEYCIQCxjq-UdL-zqecurQmubV2d3utTgDMA2IDsiMy6u5hlNwIhAPnZHMoNmmiRZouM9yy6amfqHJmlDd9SDYcXXForlxYe"; break;
    case "tampered_body": object.body = { tampered: true }; break;
    case "tampered_message_id": object.message_id = `AQ${"A".repeat(41)}`; break;
    case "tampered_time": object.issued_at_ms = 1001; break;
    default: assert.fail(`unknown public-message mutation ${mutation}`);
  }
  return JSON.stringify(object);
}

function generatedPublicMessageInvalid(item, baseJSON) {
  if (item.generator === "oversized") {
    const object = JSON.parse(baseJSON);
    object.body = "x".repeat(channels.MAX_JSON_BYTES);
    return JSON.stringify(object);
  }
  if (item.generator === "too_deep") return `${"[".repeat(channels.MAX_JSON_DEPTH + 1)}0${"]".repeat(channels.MAX_JSON_DEPTH + 1)}`;
  if (item.generator === "too_many_nodes") return `[${Array(channels.MAX_JSON_NODES).fill("0").join(",")}]`;
  assert.fail(`unknown public-message generator ${item.generator}`);
}

function expectPublicMessageError(item, baseJSON) {
  if (item.operation === "conflict") {
    const existing = channels.parseSHA256Hash(item.existing);
    const incoming = channels.parseSHA256Hash(item.incoming);
    assert.throws(() => publicmessage.checkDigestConflict(existing, incoming), codeIs(item.expected_code), item.name);
    return;
  }
  if (item.operation === "parse_raw") {
    assert.throws(() => publicmessage.parseAndVerify(item.channel, item.json, item.now_ms), codeIs(item.expected_code), item.name);
    return;
  }
  if (item.operation === "generated") {
    const input = generatedPublicMessageInvalid(item, baseJSON);
    assert.throws(() => publicmessage.parseAndVerify(item.channel, input, item.now_ms), codeIs(item.expected_code), item.name);
    return;
  }
  const channel = item.channel + (item.channel_repeat ? "a".repeat(item.channel_repeat) : "");
  const input = mutatePublicMessage(baseJSON, item.mutation);
  assert.throws(() => publicmessage.parseAndVerify(channel, input, item.now_ms), codeIs(item.expected_code), item.name);
}

test("通用公开消息共享 fixture、body 形状和跨频道三元去重", () => {
  const value = publicMessageValidFixture();
  const privateKey = channels.parsePrivateKey(bytesFromHex(value.test_only_private_key_hex));
  const publicKey = channels.parsePublicKey(value.public_key);
  const messageID = channels.parseMessageID(value.message_id);
  assert.equal(publicmessage.PUBLIC_MESSAGE_MAX_LIFETIME_MS, 600000);
  assert.equal(publicmessage.MAX_FUTURE_SKEW_MS, 60000);
  assert.equal(publicmessage.PUBLIC_MESSAGE_SCOPE, "bsv8.public-message.v1");
  assert.equal("MAX_LIFETIME_MS" in publicmessage, false);
  assert.equal("sign" in channels, false);
  assert.equal("marshal" in channels, false);
  assert.equal("dedupKey" in channels, false);

  for (const item of value.cases) {
    const signed = publicmessage.sign({
      channel: item.channel,
      from_public_key: publicKey,
      message_id: messageID,
      issued_at_ms: item.issued_at_ms,
      expires_at_ms: item.expires_at_ms,
      body: item.body,
    }, privateKey);
    const wire = publicmessage.marshal(signed);
    assert.equal(textDecoder.decode(wire), item.expected.json, item.name);
    assert.equal(signed.signature, item.expected.signature, item.name);
    assert.equal(publicmessage.signedDigest(signed), item.expected.digest_hex, item.name);
    const verified = publicmessage.parseAndVerify(item.channel, wire, item.now_ms);
    assert(publicmessage.isVerifiedPublicMessage(verified));
    assert(Object.isFrozen(verified));
    assert(Object.isFrozen(verified.body));
    if (verified.body && typeof verified.body === "object") {
      for (const nested of Object.values(verified.body)) {
        if (nested && typeof nested === "object") assert(Object.isFrozen(nested));
      }
    }
    assert.deepEqual(publicmessage.dedupKey(verified), {
      channel: item.expected.dedup_key[0],
      from_public_key: item.expected.dedup_key[1],
      message_id: item.expected.dedup_key[2],
    });
  }

  const first = value.cases[0];
  const original = publicmessage.sign({
    channel: first.channel,
    from_public_key: publicKey,
    message_id: messageID,
    issued_at_ms: first.issued_at_ms,
    expires_at_ms: first.expires_at_ms,
    body: first.body,
  }, privateKey);
  const verified = publicmessage.parseAndVerify(first.channel, publicmessage.marshal(original), first.now_ms);
  const forged = { ...verified, digest: verified.digest };
  const recursivelyFrozenForged = { ...forged, body: { ...forged.body } };
  Object.freeze(recursivelyFrozenForged.body);
  Object.freeze(recursivelyFrozenForged);
  const expanded = { ...verified, body: { ...verified.body } };
  const roundTripped = JSON.parse(JSON.stringify(verified));
  for (const candidate of [forged, recursivelyFrozenForged, expanded, roundTripped]) {
    assert.throws(() => publicmessage.dedupKey(candidate), codeIs("INVALID_SIGNATURE"));
  }
  assert.throws(() => publicmessage.sign({ ...{
    channel: first.channel,
    from_public_key: publicKey,
    message_id: messageID,
    issued_at_ms: first.issued_at_ms,
    expires_at_ms: first.expires_at_ms,
    body: first.body,
  }, extra: true }, privateKey), codeIs("UNKNOWN_FIELD"));

  const otherChannel = "bsv8.public.other.v1";
  const otherSigned = publicmessage.sign({
    channel: otherChannel,
    from_public_key: publicKey,
    message_id: messageID,
    issued_at_ms: first.issued_at_ms,
    expires_at_ms: first.expires_at_ms,
    body: first.body,
  }, privateKey);
  const otherVerified = publicmessage.parseAndVerify(otherChannel, publicmessage.marshal(otherSigned), first.now_ms);
  assert.notEqual(publicmessage.dedupKey(verified).channel, publicmessage.dedupKey(otherVerified).channel);
});

test("通用公开消息非法和篡改共享 fixture 全量返回稳定错误码", () => {
  const value = publicMessageValidFixture();
  const invalid = publicMessageInvalidFixture();
  for (const item of invalid.cases) expectPublicMessageError(item, value.cases[0].expected.json);
  assert.throws(() => publicmessage.validateChannel("\ud800"), codeIs("INVALID_CHANNEL"));
});

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

  const hashValid = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/hash-request-valid.json", import.meta.url), "utf8"));
  for (const item of hashValid.multiaddr_cases) assert.equal(hashrequest.newMultiaddrLocator(item.address).address, item.address, item.name);
  for (const item of hashValid.time_boundary_cases) {
    if (item.expected === "ACCEPT") {
      assert.doesNotThrow(() => hashrequest.parseAndVerify(item.channel, item.json, item.now_ms), item.name);
    } else {
      assert.throws(() => hashrequest.parseAndVerify(item.channel, item.json, item.now_ms), codeIs(item.expected), item.name);
    }
  }
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
  assert.equal(opened.protocol, channels.WEBRTC_SIGNAL_PROTOCOL);
  assert.equal(opened.body.signal.type, "offer");
  await assert.rejects(() => inbox.open(channels.inboxChannel(publicB), envelopeJSON, privateA, 1500), codeIs("OPEN_FAILED"));
  const tampered = JSON.parse(textDecoder.decode(envelopeJSON));
  const ciphertext = atob(tampered.ciphertext.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (tampered.ciphertext.length % 4)) % 4));
  const ciphertextBytes = Uint8Array.from(ciphertext, (character) => character.charCodeAt(0));
  ciphertextBytes[ciphertextBytes.length - 1] ^= 1;
  tampered.ciphertext = channels.base64urlEncode(ciphertextBytes);
  await assert.rejects(() => inbox.open(channels.inboxChannel(publicB), JSON.stringify(tampered), privateB, 1500), codeIs("OPEN_FAILED"));
  assert.throws(() => inbox.parseEnvelope(channels.inboxChannel(publicB), JSON.stringify({ ...tampered, envelope_version: 2 })), codeIs("INVALID_ENVELOPE"));
});

test("Ping/Pong 复用私密消息外层并按 message_id 关联", async () => {
  const { privateA, privateB, publicA, publicB } = fixedKeys();
  const messageId = channels.parseMessageID(fixture.message_id);
  const pingBody = ping.newPing();
  const pongBody = ping.newPong(messageId);
  assert.deepEqual(ping.parseBody('{"type":"ping"}'), pingBody);
  assert.deepEqual(ping.parseBody(JSON.stringify(pongBody)), pongBody);
  assert.throws(() => ping.parseBody('{"type":"ping","ping_message_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'), codeIs("UNKNOWN_FIELD"));

  const pingEnvelope = await inbox.signAndSeal({
    channel: channels.inboxChannel(publicB),
    from_public_key: publicA,
    protocol: channels.PING_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: pingBody,
  }, privateA);
  const pongEnvelope = await inbox.signAndSeal({
    channel: channels.inboxChannel(publicA),
    from_public_key: publicB,
    protocol: channels.PING_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: pongBody,
  }, privateB);
  const signedPing = inbox.signPrivateMessage({
    channel: channels.inboxChannel(publicB),
    from_public_key: publicA,
    protocol: channels.PING_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: pingBody,
  }, privateA);
  const localPing = inbox.verifySignedPrivateMessage(signedPing, 1500);
  const verifiedPing = await inbox.open(pingEnvelope.channel, inbox.marshalEnvelope(pingEnvelope), privateB, 1500);
  const verifiedPong = await inbox.open(pongEnvelope.channel, inbox.marshalEnvelope(pongEnvelope), privateA, 1500);
  inbox.validatePongRelation(localPing, verifiedPong);
  inbox.validatePongRelation(verifiedPing, verifiedPong);
  assert.equal(verifiedPong.body.type, "pong");
  assert.equal(verifiedPong.body.ping_message_id, messageId);
});

test("本地私密明文验签复用 verified 边界并使用单一 TTL 查询", async () => {
  const { privateA, privateB, publicA, publicB } = fixedKeys();
  const messageId = channels.parseMessageID(fixture.message_id);
  assert.equal(inbox.privateMessageMaxLifetimeMs(channels.PING_PROTOCOL), inbox.PING_PRIVATE_MESSAGE_MAX_LIFETIME_MS);
  assert.equal(inbox.privateMessageMaxLifetimeMs(channels.WEBRTC_SIGNAL_PROTOCOL), inbox.WEBRTC_PRIVATE_MESSAGE_MAX_LIFETIME_MS);
  assert.equal(inbox.privateMessageMaxLifetimeMs(channels.APP_MESSAGE_PROTOCOL), inbox.PRIVATE_MESSAGE_DEFAULT_MAX_LIFETIME_MS);
  assert.equal(inbox.privateMessageMaxLifetimeMs("bsv8.unknown.v1"), inbox.PRIVATE_MESSAGE_DEFAULT_MAX_LIFETIME_MS);
  assert.equal(inbox.PING_PRIVATE_MESSAGE_MAX_LIFETIME_MS, 60000);
  assert.equal(inbox.WEBRTC_PRIVATE_MESSAGE_MAX_LIFETIME_MS, 120000);
  assert.equal(inbox.PRIVATE_MESSAGE_DEFAULT_MAX_LIFETIME_MS, 86400000);

  const signedPing = inbox.signPrivateMessage({
    channel: channels.inboxChannel(publicB),
    from_public_key: publicA,
    protocol: channels.PING_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: ping.newPing(),
  }, privateA);
  const localPing = inbox.verifySignedPrivateMessage(signedPing, 1500);
  assert(Object.isFrozen(localPing));
  assert(Object.isFrozen(localPing.body));

  const badSignature = { ...signedPing, signature: "AAAA" };
  assert.throws(() => inbox.verifySignedPrivateMessage(badSignature, 1500), codeIs("INVALID_SIGNATURE"));
  const wrongSender = { ...signedPing, from_public_key: publicB };
  assert.throws(() => inbox.verifySignedPrivateMessage(wrongSender, 1500), codeIs("INVALID_SIGNATURE"));
  const badChannel = { ...signedPing, channel: "bsv8.inbox.invalid" };
  assert.throws(() => inbox.verifySignedPrivateMessage(badChannel, 1500), codeIs("INVALID_CHANNEL"));
  assert.throws(() => inbox.verifySignedPrivateMessage(signedPing, 2000), codeIs("MESSAGE_EXPIRED"));

  const futurePing = inbox.signPrivateMessage({
    channel: channels.inboxChannel(publicB),
    from_public_key: publicA,
    protocol: channels.PING_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 61001,
    expires_at_ms: 62001,
    body: ping.newPing(),
  }, privateA);
  assert.throws(() => inbox.verifySignedPrivateMessage(futurePing, 1000), codeIs("INVALID_TIME"));
  const tooLong = { ...signedPing, expires_at_ms: signedPing.issued_at_ms + inbox.PING_PRIVATE_MESSAGE_MAX_LIFETIME_MS + 1 };
  assert.throws(() => inbox.verifySignedPrivateMessage(tooLong, 1500), codeIs("INVALID_TIME"));

  const pongEnvelope = await inbox.signAndSeal({
    channel: channels.inboxChannel(publicA),
    from_public_key: publicB,
    protocol: channels.PING_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: ping.newPong(messageId),
  }, privateB);
  const verifiedPong = await inbox.open(pongEnvelope.channel, inbox.marshalEnvelope(pongEnvelope), privateA, 1500);
  inbox.validatePongRelation(localPing, verifiedPong);
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

  const localOffer = inbox.verifySignedPrivateMessage(signedOffer, 1500);
  const signedAnswer = inbox.signPrivateMessage({
    channel: channels.inboxChannel(publicA),
    from_public_key: publicB,
    protocol: channels.WEBRTC_SIGNAL_PROTOCOL,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body: webrtc.newAnswer(messageId, sessionId, "v=0"),
  }, privateB);
  const answerRandom = new Uint8Array(44);
  answerRandom.fill(0x22, 32);
  const answerEnvelope = await inbox.sealSigned(signedAnswer, privateB, channels.fixedRandom(answerRandom));
  const remoteAnswer = await inbox.open(channels.inboxChannel(publicA), inbox.marshalEnvelope(answerEnvelope), privateA, 1500);
  inbox.validateWebRTCRelation(localOffer, remoteAnswer);

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
  assert.deepEqual([publicKey.from_public_key, publicKey.message_id], value.expected.public_dedup_key);

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

  const ackMessage = async (item) => {
    const from = channels.parsePublicKey(item.from_public_key);
    const to = channels.parsePublicKey(item.to_public_key);
    const senderPrivate = from === publicA ? privateA : privateB;
    const recipientPrivate = to === publicA ? privateA : privateB;
    const envelope = await inbox.signAndSeal({
      channel: channels.inboxChannel(to),
      from_public_key: from,
      protocol: channels.APP_MESSAGE_PROTOCOL,
      message_id: channels.newMessageID(),
      issued_at_ms: 1000,
      expires_at_ms: 2000,
      body: appmessage.newAck(channels.parseMessageID(item.acknowledged_message_id)),
    }, senderPrivate);
    return inbox.open(envelope.channel, inbox.marshalEnvelope(envelope), recipientPrivate, 1500);
  };
  assert.equal(value.ack.valid.expected_code, null);
  const validAck = await ackMessage(value.ack.valid);
  assert.doesNotThrow(() => inbox.validateAckRelation(opened, validAck));
  const ackInvalid = [];
  for (const item of value.ack.invalid) {
    const invalidAck = await ackMessage(item);
    assert.throws(() => inbox.validateAckRelation(opened, invalidAck), codeIs(item.expected_code), item.name);
    ackInvalid.push({ name: item.name, code: item.expected_code });
  }
  assert.deepEqual(ackInvalid, value.expected.ack_invalid);

  const sameDigest = channels.parseSHA256Hash(value.conflict.same_digest);
  const differentDigest = channels.parseSHA256Hash(value.conflict.different_digest);
  assert.equal(value.conflict.expected_same_code, null);
  assert.doesNotThrow(() => inbox.checkDigestConflict(sameDigest, sameDigest));
  assert.throws(() => inbox.checkDigestConflict(sameDigest, differentDigest), codeIs(value.conflict.expected_different_code));
  assert.equal(value.expected.conflict_code, value.conflict.expected_different_code);
});

test("WebRTC 四分支、SessionKey 和 ACK 关系保持隔离", async () => {
  const requestId = channels.parseMessageID(fixture.message_id);
  const sessionId = channels.parseSessionID(fixture.session_id);
  const signals = [
    webrtc.newOffer(requestId, sessionId, "v=0"),
    webrtc.newAnswer(requestId, sessionId, "v=0"),
    webrtc.newICECandidate(requestId, sessionId, { candidate: "candidate:1", sdp_mid: null, sdp_m_line_index: 0 }),
    webrtc.newEndOfCandidates(requestId, sessionId),
  ];
  for (const signal of signals) assert.deepEqual(webrtc.parseBody(textDecoder.decode(channels.canonicalizeValue(signal))), signal);
  const { privateA, privateB, publicA, publicB } = fixedKeys();
  const offerEnvelope = await inbox.signAndSeal({ channel: channels.inboxChannel(publicB), from_public_key: publicA, protocol: channels.WEBRTC_SIGNAL_PROTOCOL, message_id: requestId, issued_at_ms: 1000, expires_at_ms: 2000, body: signals[0] }, privateA);
  const answerEnvelope = await inbox.signAndSeal({ channel: channels.inboxChannel(publicA), from_public_key: publicB, protocol: channels.WEBRTC_SIGNAL_PROTOCOL, message_id: requestId, issued_at_ms: 1000, expires_at_ms: 2000, body: signals[1] }, privateB);
  const verifiedOffer = await inbox.open(offerEnvelope.channel, inbox.marshalEnvelope(offerEnvelope), privateB, 1500);
  const verifiedAnswer = await inbox.open(answerEnvelope.channel, inbox.marshalEnvelope(answerEnvelope), privateA, 1500);
  inbox.validateWebRTCRelation(verifiedOffer, verifiedAnswer);
  const app = appmessage.newDeliver({ sdp: { application: true } });
  assert.equal(app.type, "deliver");
  const ack = appmessage.newAck(requestId);
  assert.equal(ack.type, "ack");
  assert.throws(() => inbox.validateWebRTCRelation(verifiedOffer, verifiedOffer), codeIs("INVALID_RELATION"));
  assert.throws(() => inbox.checkDigestConflict(channels.parseSHA256Hash("0".repeat(64)), channels.parseSHA256Hash("1".repeat(64))), codeIs("MESSAGE_ID_CONFLICT"));
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
      const { privateA, privateB, publicA, publicB } = fixedKeys();
      const validOffer = webrtc.newOffer(channels.parseMessageID(fixture.message_id), channels.parseSessionID(fixture.session_id), "v=0");
      const answer = webrtc.parseBody(item.json);
      const offerEnvelope = await inbox.signAndSeal({ channel: channels.inboxChannel(publicB), from_public_key: publicA, protocol: channels.WEBRTC_SIGNAL_PROTOCOL, message_id: channels.parseMessageID(fixture.message_id), issued_at_ms: 1000, expires_at_ms: 2000, body: validOffer }, privateA);
      const answerEnvelope = await inbox.signAndSeal({ channel: channels.inboxChannel(publicA), from_public_key: publicB, protocol: channels.WEBRTC_SIGNAL_PROTOCOL, message_id: channels.parseMessageID(fixture.message_id), issued_at_ms: 1000, expires_at_ms: 2000, body: answer }, privateB);
      const offerMessage = await inbox.open(offerEnvelope.channel, inbox.marshalEnvelope(offerEnvelope), privateB, 1500);
      const answerMessage = await inbox.open(answerEnvelope.channel, inbox.marshalEnvelope(answerEnvelope), privateA, 1500);
      assert.throws(() => inbox.validateWebRTCRelation(offerMessage, answerMessage), codeIs(item.expected_code), item.name);
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
    await assert.rejects(() => inbox.open(item.channel, envelopeJSON, privateKey, 1500), codeIs(item.expected_code), item.name);
  }

  const publicSignature = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/signature-public.json", import.meta.url), "utf8"));
  const privateSignature = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/signature-private.json", import.meta.url), "utf8"));
  assert.equal(hashrequest.signedDigest(fixedHashMessage()), publicSignature.digest_hex);
  assert.equal((await fixedPrivateEnvelope()).signed.signature, privateSignature.signature);
});
