# `bsv8-channel-protocol`

Channel Protocol V1 的 TypeScript SDK，待发布项目包版本为 `0.3.0`。

目标边界：

- libp2p 公钥是 SSP 调用者和付款身份，不进入本包；
- CP 消息自己携带作者公钥、message_id、时间和签名；
- SSP 身份 A 可以提交 CP 作者 B 的报文；
- 本包不依赖 SSP package。

公开子路径：

| 导入路径 | 职责 |
|---|---|
| `bsv8-channel-protocol/public-message` | 任意精确公开频道的通用签名 JSON 消息 |
| `bsv8-channel-protocol/hash-request` | 自包含签名 Hash 消息 |
| `bsv8-channel-protocol/inbox` | 带唯一发送者公钥的信封、私密签名消息和加解密 |
| `bsv8-channel-protocol/webrtc-signal` | WebRTC SDP/ICE body |
| `bsv8-channel-protocol/app-message` | Deliver/ACK body |
| `bsv8-channel-protocol/ping` | Ping/Pong body |

通用公开消息的线上字段固定为 `from_public_key/message_id/issued_at_ms/expires_at_ms/body/signature`；
`channel` 不写入 JSON，但会绑定到签名和 `(channel, from_public_key, message_id)` 去重键。

```js
import { sign, marshal, parseAndVerify, dedupKey } from "bsv8-channel-protocol/public-message";
import { generatePrivateKey, publicKeyFromPrivate, newMessageID } from "bsv8-channel-protocol";

const privateKey = generatePrivateKey();
const message = sign({
  channel: "bsv8.public.example.v1",
  from_public_key: publicKeyFromPrivate(privateKey),
  message_id: newMessageID(),
  issued_at_ms: 1_000,
  expires_at_ms: 2_000,
  body: { kind: "local-demo", value: 1 },
}, privateKey);
const verified = parseAndVerify(message.channel, marshal(message), 1_500);
console.log(dedupKey(verified));
```

Inbox 信封包含 `envelope_version/from_public_key/kdf_salt/nonce/ciphertext`；解密后的
PrivateMessage 包含 `protocol/message_id/issued_at_ms/expires_at_ms/body/signature`。
发送者公钥只在完整信封出现一次。

发送方已经生成的本地明文只能使用 `verifySignedPrivateMessage(message, nowMs)` 验证；
它不会解密远端数据。远端 Inbox 信封仍必须调用 `open`，去重键也必须使用包含 channel
的已验证结果。

```sh
npm ci
npm test
npm pack --dry-run
```
