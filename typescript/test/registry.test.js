import assert from "node:assert/strict";
import test from "node:test";

import {
  APP_MESSAGE_PROTOCOL,
  HASH_REQUEST_CHANNEL,
  INBOX_CHANNEL_PREFIX,
  INBOX_ENVELOPE_VERSION,
  PROTOCOL_REGISTRY,
  WEBRTC_SIGNAL_PROTOCOL,
} from "../dist/index.js";

test("协议注册表与 V1 文档一一对应", () => {
  assert.equal(HASH_REQUEST_CHANNEL, "bsv8.hash.request.v1");
  assert.equal(INBOX_CHANNEL_PREFIX, "bsv8.inbox.");
  assert.equal(INBOX_ENVELOPE_VERSION, 1);
  assert.equal(WEBRTC_SIGNAL_PROTOCOL, "bsv8.webrtc.signal.v1");
  assert.equal(APP_MESSAGE_PROTOCOL, "bsv8.message.v1");
  assert.equal(PROTOCOL_REGISTRY.length, 4);
});
