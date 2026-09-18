import assert from "node:assert/strict";
import test from "node:test";

import * as channels from "../dist/index.js";
import * as bsvprice from "../dist/bsv-price/index.js";

const bytes = (value) => {
  const result = new Uint8Array(32);
  result.fill(value);
  return result;
};

function fixedKey(value = 1) {
  const privateKey = channels.generatePrivateKey(channels.fixedRandom(bytes(value)));
  return { privateKey, publicKey: channels.publicKeyFromPrivate(privateKey) };
}

test("BSV 价格频道和多市场快照可以签名、序列化并验签", () => {
  const { privateKey, publicKey } = fixedKey();
  const messageId = channels.newMessageID(channels.fixedRandom(bytes(2)));
  const body = bsvprice.newBody(1000, {
    gate: { bsvusdt: "45.1200", bsvcny: "321.85" },
    okx: { bsvusdt: "45.0900" },
  });
  const signed = bsvprice.sign({
    from_public_key: publicKey,
    message_id: messageId,
    issued_at_ms: 1000,
    expires_at_ms: 2000,
    body,
  }, privateKey);
  const wire = bsvprice.marshal(signed);
  assert.equal(new TextDecoder().decode(wire), `{"body":{"markets":{"gate":{"bsvcny":"321.85","bsvusdt":"45.1200"},"okx":{"bsvusdt":"45.0900"}},"protocol":"bsv8.bsv-price.v1","snapshot_at_ms":1000},"expires_at_ms":2000,"from_public_key":"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f","issued_at_ms":1000,"message_id":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","signature":"MEQCIF3iRwrJqHm9iBVIbBsp5_tgTANil1ed2Zj9GjdcUyioAiBOr0mkhWwROWoenKE5vq1v6SnCvE7UFnhOMd0sJDRh7g"}`);
  assert.equal(bsvprice.signedDigest(signed), "fc19ee6bfbc7c15720da52bacca8cea912c4a2e34b2484755b9f29c7ee844104");
  const channel = bsvprice.bsvPriceChannel(publicKey);
  const verified = bsvprice.parseAndVerify(channel, wire);

  assert.equal(channel, `bsvprice.${publicKey}`);
  assert.equal(bsvprice.parseBSVPriceChannel(channel), publicKey);
  assert.equal(verified.body.markets.gate.bsvcny, "321.85");
  assert.equal(verified.body.snapshot_at_ms, 1000);
  assert(bsvprice.isVerifiedBSVPriceMessage(verified));
  assert(Object.isFrozen(verified));
  assert(Object.isFrozen(verified.body));
  assert(Object.isFrozen(verified.body.markets.gate));
  assert.deepEqual(bsvprice.dedupKey(verified), { from_public_key: publicKey, message_id: messageId });
});

test("BSV 价格正文拒绝浮点价格和非法编号", () => {
  assert.throws(() => bsvprice.parseBody({
    protocol: bsvprice.BSV_PRICE_PROTOCOL,
    snapshot_at_ms: 1,
    markets: { gate: { bsvusdt: 1 } },
  }), (error) => error?.code === "INVALID_BODY");
  assert.throws(() => bsvprice.parseBody({
    protocol: bsvprice.BSV_PRICE_PROTOCOL,
    snapshot_at_ms: 1,
    markets: { Gate: { bsvusdt: "1" } },
  }), (error) => error?.code === "INVALID_BODY");
  assert.throws(() => bsvprice.parseBSVPriceChannel("bsvprice.bad"), (error) => error?.code === "INVALID_CHANNEL");
});

test("BSV 价格正文拒绝标点作为市场或交易对首字符", () => {
  for (const invalid of [".gate", "-gate", "_gate"]) {
    assert.throws(() => bsvprice.parseBody({
      protocol: bsvprice.BSV_PRICE_PROTOCOL,
      snapshot_at_ms: 1,
      markets: { [invalid]: { bsvusdt: "1" } },
    }), (error) => error?.code === "INVALID_BODY", invalid);
    assert.throws(() => bsvprice.parseBody({
      protocol: bsvprice.BSV_PRICE_PROTOCOL,
      snapshot_at_ms: 1,
      markets: { gate: { [invalid]: "1" } },
    }), (error) => error?.code === "INVALID_BODY", invalid);
  }
});

test("BSV 价格正文允许空市场快照", () => {
  const body = bsvprice.newBody(1, {});
  assert.deepEqual(body.markets, {});
  assert.deepEqual(bsvprice.parseBody({
    protocol: bsvprice.BSV_PRICE_PROTOCOL,
    snapshot_at_ms: 1,
    markets: {},
  }).markets, {});
});
