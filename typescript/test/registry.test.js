import assert from "node:assert/strict";
import test from "node:test";

import {
  APP_MESSAGE_PROTOCOL,
  HASH_REQUEST_CHANNEL,
  INBOX_CHANNEL_PREFIX,
  INBOX_ENVELOPE_VERSION,
  PING_PROTOCOL,
  WEBRTC_SIGNAL_PROTOCOL,
} from "../dist/index.js";

test("协议常量与 V1 文档一致", () => {
  assert.equal(HASH_REQUEST_CHANNEL, "bsv8.hash.request.v1");
  assert.equal(INBOX_CHANNEL_PREFIX, "bsv8.inbox.");
  assert.equal(INBOX_ENVELOPE_VERSION, 1);
  assert.equal(WEBRTC_SIGNAL_PROTOCOL, "bsv8.webrtc.signal.v1");
  assert.equal(APP_MESSAGE_PROTOCOL, "bsv8.message.v1");
  assert.equal(PING_PROTOCOL, "bsv8.ping.v1");
});
