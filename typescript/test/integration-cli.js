// 跨语言 fixture 驱动器：TypeScript 独立构造，并可验证 Go 的构造结果。
import assert from "node:assert/strict";
import fs from "node:fs";

import * as channels from "../dist/index.js";
import * as appmessage from "../dist/app-message/index.js";
import * as hashrequest from "../dist/hash-request/index.js";
import * as inbox from "../dist/inbox/index.js";
import * as ping from "../dist/ping/index.js";
import * as publicmessage from "../dist/public-message/index.js";
import * as webrtc from "../dist/webrtc-signal/index.js";

const fixture = JSON.parse(fs.readFileSync(new URL("../../testdata/v1/interop-v1.json", import.meta.url), "utf8"));
const textDecoder = new TextDecoder();

function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesFromHex(value) {
  assert.equal(value.length % 2, 0);
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return result;
}

function fixedKeys() {
  const privateABytes = bytesFromHex(fixture.test_only_private_key_a_hex);
  const privateBBytes = bytesFromHex(fixture.test_only_private_key_b_hex);
  return {
    privateA: channels.parsePrivateKey(privateABytes),
    privateB: channels.parsePrivateKey(privateBBytes),
    publicA: channels.parsePublicKey(fixture.public_key_a),
    publicB: channels.parsePublicKey(fixture.public_key_b),
  };
}

function errorCode(error) {
  return error && typeof error === "object" && typeof error.code === "string" ? error.code : "UNKNOWN";
}

function expectCode(fn, expected) {
  try {
    fn();
  } catch (error) {
    assert.equal(errorCode(error), expected);
    return expected;
  }
  assert.fail(`expected ${expected}`);
}

async function expectCodeAsync(fn, expected) {
  try {
    await fn();
  } catch (error) {
    assert.equal(errorCode(error), expected);
    return expected;
  }
  assert.fail(`expected ${expected}`);
}

function readTestFixture(name) {
  return JSON.parse(fs.readFileSync(new URL(`../../testdata/v1/${name}`, import.meta.url), "utf8"));
}

async function sharedInvalidResults() {
  const results = [];
  const append = (prefix, item, code) => results.push({ name: `${prefix}/${item.name}`, code });

  const jcsInvalid = readTestFixture("jcs-invalid.json");
  for (const item of jcsInvalid.cases) append("jcs-invalid", item, expectCode(() => channels.canonicalizeJSON(item.json), item.expected_code));

  const primitiveInvalid = readTestFixture("primitives-invalid.json");
  for (const item of primitiveInvalid.cases) {
    const action = item.operation === "public_key" ? () => channels.parsePublicKey(item.value)
      : item.operation === "message_id" ? () => channels.parseMessageID(item.value)
        : item.operation === "session_id" ? () => channels.parseSessionID(item.value)
          : item.operation === "sha256" ? () => channels.parseSHA256Hash(item.value)
            : item.operation === "private_key_hex" ? () => channels.parsePrivateKey(bytesFromHex(item.value))
              : item.operation === "unix_millis" ? () => channels.parseUnixMillis(item.value)
                : assert.fail(`unknown primitive fixture operation: ${item.operation}`);
    append("primitives-invalid", item, expectCode(action, item.expected_code));
  }

  const hashInvalid = readTestFixture("hash-request-invalid.json");
  for (const item of hashInvalid.cases) append("hash-request-invalid", item, expectCode(() => hashrequest.parseAndVerify(item.channel, item.json, item.now_ms), item.expected_code));

  const appInvalid = readTestFixture("app-message-invalid.json");
  for (const item of appInvalid.cases) append("app-message-invalid", item, expectCode(() => appmessage.parseBody(item.json), item.expected_code));

  const pingInvalid = readTestFixture("ping-invalid.json");
  for (const item of pingInvalid.cases) append("ping-invalid", item, expectCode(() => ping.parseBody(item.json), item.expected_code));

  const webRTCInvalid = readTestFixture("webrtc-signal-invalid.json");
  for (const item of webRTCInvalid.cases) {
    if (item.operation === "parse") {
      append("webrtc-signal-invalid", item, expectCode(() => webrtc.parseBody(item.json), item.expected_code));
    } else if (item.operation === "relation") {
      const { privateA, privateB, publicA, publicB } = fixedKeys();
      const validOffer = webrtc.newOffer(channels.parseMessageID(fixture.message_id), channels.parseSessionID(fixture.session_id), "v=0");
      const answer = webrtc.parseBody(item.json);
      const offerEnvelope = await inbox.signAndSeal({ channel: channels.inboxChannel(publicB), from_public_key: publicA, protocol: channels.WEBRTC_SIGNAL_PROTOCOL, message_id: channels.parseMessageID(fixture.message_id), issued_at_ms: 1000, expires_at_ms: 2000, body: validOffer }, privateA);
      const answerEnvelope = await inbox.signAndSeal({ channel: channels.inboxChannel(publicA), from_public_key: publicB, protocol: channels.WEBRTC_SIGNAL_PROTOCOL, message_id: channels.parseMessageID(fixture.message_id), issued_at_ms: 1000, expires_at_ms: 2000, body: answer }, privateB);
      const offerMessage = await inbox.open(offerEnvelope.channel, inbox.marshalEnvelope(offerEnvelope), privateB, 1500);
      const answerMessage = await inbox.open(answerEnvelope.channel, inbox.marshalEnvelope(answerEnvelope), privateA, 1500);
      append("webrtc-signal-invalid", item, expectCode(() => inbox.validateWebRTCRelation(offerMessage, answerMessage), item.expected_code));
    } else {
      assert.fail(`unknown WebRTC fixture operation: ${item.operation}`);
    }
  }

  const inboxInvalid = readTestFixture("inbox-crypto-invalid.json");
  for (const item of inboxInvalid.cases) {
    const envelopeJSON = JSON.stringify(item.envelope);
    if (item.operation === "parse") {
      append("inbox-crypto-invalid", item, expectCode(() => inbox.parseEnvelope(item.channel, envelopeJSON), item.expected_code));
    } else if (item.operation === "open" || item.operation === "open_dispatch") {
      const privateKey = channels.parsePrivateKey(bytesFromHex(item.recipient_private_key_hex));
      append("inbox-crypto-invalid", item, await expectCodeAsync(() => inbox.open(item.channel, envelopeJSON, privateKey, 1500), item.expected_code));
    } else {
      assert.fail(`unknown inbox fixture operation: ${item.operation}`);
    }
  }
  return results;
}

function validateSharedValidFixtures() {
  const jcsValid = readTestFixture("jcs-valid.json");
  for (const item of jcsValid.cases) assert.equal(hex(channels.canonicalizeJSON(item.input)), item.expected_utf8_hex, `JCS valid fixture ${item.name}`);

  const primitives = readTestFixture("primitives-valid.json");
  channels.parsePublicKey(primitives.public_key);
  channels.parseMessageID(primitives.message_id);
  channels.parseSessionID(primitives.session_id);
  channels.parseSHA256Hash(primitives.sha256);
  channels.parseUnixMillis(primitives.unix_millis);

  const hashValid = readTestFixture("hash-request-valid.json");
  for (const item of hashValid.multiaddr_cases) assert.equal(hashrequest.newMultiaddrLocator(item.address).address, item.address, `multiaddr valid fixture ${item.name}`);
  for (const item of hashValid.time_boundary_cases) {
    if (item.expected === "ACCEPT") {
      assert.doesNotThrow(() => hashrequest.parseAndVerify(item.channel, item.json, item.now_ms), item.name);
    } else {
      expectCode(() => hashrequest.parseAndVerify(item.channel, item.json, item.now_ms), item.expected);
    }
  }

  const appValid = readTestFixture("app-message-valid.json");
  appmessage.parseBody(JSON.stringify(appValid.deliver));
  appmessage.parseBody(JSON.stringify(appValid.ack));

  const pingValid = readTestFixture("ping-valid.json");
  ping.parseBody(JSON.stringify(pingValid.ping));
  ping.parseBody(JSON.stringify(pingValid.pong));

  const webRTCValid = readTestFixture("webrtc-signal-valid.json");
  for (const signal of webRTCValid.signals) webrtc.parseBody(JSON.stringify({ request_message_id: webRTCValid.request_message_id, session_id: webRTCValid.session_id, signal }));
}

async function buildDedupRelations() {
  const value = readTestFixture("dedup-and-relations.json");
  const privateA = channels.parsePrivateKey(bytesFromHex(value.test_only_private_key_a_hex));
  const privateB = channels.parsePrivateKey(bytesFromHex(value.test_only_private_key_b_hex));
  const publicA = channels.parsePublicKey(value.public_key_a);
  const publicB = channels.parsePublicKey(value.public_key_b);
  assert.equal(value.session_key.separator.length, 1);
  assert.equal(value.session_key.separator.charCodeAt(0), 0);

  const publicInput = value.public_hash_request;
  assert.equal(publicInput.channel, channels.HASH_REQUEST_CHANNEL);
  assert.equal(publicInput.from_public_key, value.public_key_a);
  const publicMessage = hashrequest.sign({
    from_public_key: publicA,
    message_id: channels.parseMessageID(publicInput.message_id),
    issued_at_ms: publicInput.issued_at_ms,
    expires_at_ms: publicInput.expires_at_ms,
    body: {
      hash: channels.parseSHA256Hash(publicInput.body.hash),
      locators: publicInput.body.locators.map((item) => {
        if (item.kind === "webrtc-sdp") return hashrequest.newWebRTCSDPLocator();
        if (item.kind === "multiaddr") return hashrequest.newMultiaddrLocator(item.address);
        assert.fail("unknown dedup locator kind: " + item.kind);
      }),
    },
  }, privateA);
  const verifiedPublic = hashrequest.parseAndVerify(publicInput.channel, hashrequest.marshal(publicMessage), publicInput.issued_at_ms + 500);
  const publicKey = hashrequest.dedupKey(verifiedPublic);
  const publicDedupKey = [publicKey.from_public_key, publicKey.message_id];

  const privateInput = value.private_deliver;
  assert.equal(privateInput.channel, channels.inboxChannel(publicB));
  assert.equal(privateInput.from_public_key, value.public_key_a);
  assert.equal(privateInput.to_public_key, value.public_key_b);
  assert.equal(privateInput.protocol, channels.APP_MESSAGE_PROTOCOL);
  const privateBody = appmessage.parseBody(JSON.stringify(privateInput.body));
  assert.equal(privateBody.type, "deliver");
  const signedPrivate = inbox.signPrivateMessage({
    channel: privateInput.channel,
    from_public_key: publicA,
    protocol: channels.APP_MESSAGE_PROTOCOL,
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
  const privateDedupKey = [privateKey.protocol, privateKey.from_public_key, privateKey.message_id];

  const sessionInput = value.session_key;
  assert.equal(sessionInput.request_message_id, publicInput.message_id);
  const session = webrtc.sessionKey(
    channels.parseMessageID(sessionInput.request_message_id),
    channels.parsePublicKey(sessionInput.offerer_public_key),
    channels.parseSessionID(sessionInput.session_id),
  );

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
  inbox.validateAckRelation(opened, validAck);
  const ackInvalid = [];
  for (const item of value.ack.invalid) {
    const invalidAck = await ackMessage(item);
    ackInvalid.push({ name: item.name, code: expectCode(() => inbox.validateAckRelation(opened, invalidAck), item.expected_code) });
  }

  const sameDigest = channels.parseSHA256Hash(value.conflict.same_digest);
  const differentDigest = channels.parseSHA256Hash(value.conflict.different_digest);
  assert.equal(value.conflict.expected_same_code, null);
  assert.doesNotThrow(() => inbox.checkDigestConflict(sameDigest, sameDigest));
  const conflictCode = expectCode(() => inbox.checkDigestConflict(sameDigest, differentDigest), value.conflict.expected_different_code);

  const result = {
    public_dedup_key: publicDedupKey,
    private_dedup_key: privateDedupKey,
    session_key: session.key,
    session_key_separator: sessionInput.separator,
    ack_valid: true,
    ack_invalid: ackInvalid,
    conflict_code: conflictCode,
  };
  assert.deepEqual(result.public_dedup_key, value.expected.public_dedup_key);
  assert.deepEqual(result.private_dedup_key, value.expected.private_dedup_key);
  assert.equal(result.session_key, value.expected.session_key);
  assert.equal(result.ack_valid, value.expected.ack_valid);
  assert.deepEqual(result.ack_invalid, value.expected.ack_invalid);
  assert.equal(result.conflict_code, value.expected.conflict_code);
  return result;
}

async function expectedInvalid() {
  const invalid = fixture.invalid_error_codes.map((item) => ({
    name: item.name,
    code: item.name === "unknown public field"
      ? expectCode(() => hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, item.json, fixture.issued_at_ms + 500), item.expected_code)
      : expectCode(() => channels.canonicalizeJSON(item.json), item.expected_code),
  }));
  return invalid.concat(await sharedInvalidResults());
}

function publicMessageInvalidInput(item, baseJSON) {
  if (item.operation === "parse_raw") return item.json;
  if (item.operation === "generated") {
    if (item.generator === "oversized") {
      const object = JSON.parse(baseJSON);
      object.body = "x".repeat(channels.MAX_JSON_BYTES);
      return JSON.stringify(object);
    }
    if (item.generator === "too_deep") return `${"[".repeat(channels.MAX_JSON_DEPTH + 1)}0${"]".repeat(channels.MAX_JSON_DEPTH + 1)}`;
    if (item.generator === "too_many_nodes") return `[${Array(channels.MAX_JSON_NODES).fill("0").join(",")}]`;
    throw new Error(`unknown public-message generator ${item.generator}`);
  }
  if (item.mutation === "none") return baseJSON;
  const object = JSON.parse(baseJSON);
  switch (item.mutation) {
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
    default: throw new Error(`unknown public-message mutation ${item.mutation}`);
  }
  return JSON.stringify(object);
}

function buildPublicMessage() {
  const valid = readTestFixture("public-message-valid.json");
  const privateKey = channels.parsePrivateKey(bytesFromHex(valid.test_only_private_key_hex));
  const publicKey = channels.parsePublicKey(valid.public_key);
  const messageID = channels.parseMessageID(valid.message_id);
  const cases = valid.cases.map((item) => {
    const signed = publicmessage.sign({
      channel: item.channel,
      from_public_key: publicKey,
      message_id: messageID,
      issued_at_ms: item.issued_at_ms,
      expires_at_ms: item.expires_at_ms,
      body: item.body,
    }, privateKey);
    const json = textDecoder.decode(publicmessage.marshal(signed));
    const verified = publicmessage.parseAndVerify(item.channel, json, item.now_ms);
    const key = publicmessage.dedupKey(verified);
    const actual = {
      name: item.name,
      json,
      digest_hex: verified.digest,
      signature: verified.signature,
      body_json: textDecoder.decode(channels.canonicalizeValue(verified.body)),
      dedup_key: [key.channel, key.from_public_key, key.message_id],
    };
    assert.equal(actual.json, item.expected.json, `public-message fixture ${item.name}`);
    assert.equal(actual.digest_hex, item.expected.digest_hex, `public-message fixture ${item.name}`);
    assert.equal(actual.signature, item.expected.signature, `public-message fixture ${item.name}`);
    assert.deepEqual(actual.dedup_key, item.expected.dedup_key, `public-message fixture ${item.name}`);
    return actual;
  });

  const invalid = readTestFixture("public-message-invalid.json").cases.map((item) => {
    let code;
    if (item.operation === "conflict") {
      code = expectCode(() => publicmessage.checkDigestConflict(channels.parseSHA256Hash(item.existing), channels.parseSHA256Hash(item.incoming)), item.expected_code);
    } else {
      const channel = item.channel + (item.channel_repeat ? "a".repeat(item.channel_repeat) : "");
      const input = publicMessageInvalidInput(item, valid.cases[0].expected.json);
      code = expectCode(() => publicmessage.parseAndVerify(channel, input, item.now_ms), item.expected_code);
    }
    return { name: `public-message/${item.name}`, code };
  });
  return { cases, invalid };
}

function verifyForeignPublicMessage(foreign, expected) {
  const valid = readTestFixture("public-message-valid.json");
  assert.equal(foreign.cases.length, expected.cases.length);
  for (let index = 0; index < foreign.cases.length; index += 1) {
    const item = valid.cases[index];
    const actual = foreign.cases[index];
    const verified = publicmessage.parseAndVerify(item.channel, actual.json, item.now_ms);
    const key = publicmessage.dedupKey(verified);
    assert.equal(actual.name, item.name);
    assert.equal(actual.json, expected.cases[index].json);
    assert.equal(actual.digest_hex, verified.digest);
    assert.equal(actual.signature, verified.signature);
    assert.equal(actual.body_json, textDecoder.decode(channels.canonicalizeValue(verified.body)));
    assert.deepEqual(actual.dedup_key, [key.channel, key.from_public_key, key.message_id]);
  }
  assert.deepEqual(foreign.invalid, expected.invalid);
}

async function build() {
  const jcs = fixture.jcs.map((item) => {
    const actual = hex(channels.canonicalizeJSON(item.input));
    assert.equal(actual, item.expected_utf8_hex, `JCS fixture ${item.name}`);
    return { name: item.name, hex: actual };
  });

  const privateA = channels.parsePrivateKey(bytesFromHex(fixture.test_only_private_key_a_hex));
  const privateB = channels.parsePrivateKey(bytesFromHex(fixture.test_only_private_key_b_hex));
  const publicA = channels.parsePublicKey(fixture.public_key_a);
  const publicB = channels.parsePublicKey(fixture.public_key_b);
  assert.equal(channels.publicKeyFromPrivate(privateA), publicA);
  assert.equal(channels.publicKeyFromPrivate(privateB), publicB);

  const messageId = channels.parseMessageID(fixture.message_id);
  const sessionId = channels.parseSessionID(fixture.session_id);
  const hash = channels.parseSHA256Hash(fixture.hash);

  const publicMessage = hashrequest.sign({
    from_public_key: publicA,
    message_id: messageId,
    issued_at_ms: fixture.issued_at_ms,
    expires_at_ms: fixture.expires_at_ms,
    body: { hash, locators: [hashrequest.newWebRTCSDPLocator()] },
  }, privateA);
  const publicJSON = textDecoder.decode(hashrequest.marshal(publicMessage));
  const verifiedPublic = hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, publicJSON, fixture.issued_at_ms + 500);
  assert.equal(verifiedPublic.signature, fixture.hash_request.signature);
  assert.equal(verifiedPublic.digest, fixture.hash_request.digest_hex);

  const body = webrtc.newOffer(messageId, sessionId, "v=0");
  const unsignedPrivate = {
    channel: fixture.channel,
    from_public_key: publicA,
    protocol: channels.WEBRTC_SIGNAL_PROTOCOL,
    message_id: messageId,
    issued_at_ms: fixture.issued_at_ms,
    expires_at_ms: fixture.expires_at_ms,
    body,
  };
  const signedPrivate = inbox.signPrivateMessage(unsignedPrivate, privateA);
  const plaintextJSON = textDecoder.decode(inbox.marshalPrivateMessage(signedPrivate));
  assert.deepEqual(JSON.parse(plaintextJSON), fixture.private_message.plaintext);
  assert.equal(inbox.signedDigest(signedPrivate), fixture.private_message.digest_hex);
  assert.equal(signedPrivate.signature, fixture.private_message.signature);
  const fixed = new Uint8Array(44);
  fixed.fill(0x21, 32);
  const envelope = await inbox.sealSigned(signedPrivate, privateA, channels.fixedRandom(fixed));
  const envelopeJSON = textDecoder.decode(inbox.marshalEnvelope(envelope));
  assert.deepEqual(JSON.parse(envelopeJSON), fixture.private_message.envelope);
  const opened = await inbox.open(fixture.channel, envelopeJSON, privateB, fixture.issued_at_ms + 500);
  assert.equal(opened.protocol, channels.WEBRTC_SIGNAL_PROTOCOL);
  assert.equal(opened.body.signal.type, "offer");

  validateSharedValidFixtures();
  const public_message = buildPublicMessage();
  const dedup_relations = await buildDedupRelations();
  const invalid = await expectedInvalid();

  return {
    jcs,
    hash_request: {
      json: publicJSON,
      digest_hex: verifiedPublic.digest,
      signature: verifiedPublic.signature,
    },
    private_message: {
      plaintext_json: plaintextJSON,
      envelope_json: envelopeJSON,
      digest_hex: opened.digest,
      signature: opened.signature,
      opened_protocol: opened.protocol,
      opened_body: "webrtc.signal.offer",
    },
    public_message,
    dedup_relations,
    invalid,
  };
}

async function verifyGo(path) {
  const foreign = JSON.parse(fs.readFileSync(path, "utf8"));
  const privateB = channels.parsePrivateKey(bytesFromHex(fixture.test_only_private_key_b_hex));
  const publicMessage = hashrequest.parseAndVerify(channels.HASH_REQUEST_CHANNEL, foreign.hash_request.json, fixture.issued_at_ms + 500);
  assert.equal(publicMessage.signature, fixture.hash_request.signature);
  assert.equal(publicMessage.digest, fixture.hash_request.digest_hex);
  const opened = await inbox.open(fixture.channel, foreign.private_message.envelope_json, privateB, fixture.issued_at_ms + 500);
  assert.equal(opened.signature, fixture.private_message.signature);
  assert.equal(opened.digest, fixture.private_message.digest_hex);
  assert.equal(opened.protocol, channels.WEBRTC_SIGNAL_PROTOCOL);
  const expectedPublicMessage = buildPublicMessage();
  verifyForeignPublicMessage(foreign.public_message, expectedPublicMessage);
  assert.deepEqual(foreign.public_message, expectedPublicMessage);
  assert.deepEqual(foreign.dedup_relations, await buildDedupRelations());
  assert.deepEqual(foreign.invalid, await expectedInvalid());
}

const verifyGoPath = process.argv[2] === "--verify-go" ? process.argv[3] : undefined;
if (verifyGoPath) await verifyGo(verifyGoPath);
process.stdout.write(`${JSON.stringify(await build())}\n`);
