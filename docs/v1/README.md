# Channel Protocol V1

待发布项目包/API 版本为 `0.3.0`；线上 channel、protocol 和 envelope 版本仍为 V1。

## 1. 分层

```text
libp2p authenticated public key
  └─ SSP caller / payer / request_id / billing
       └─ exact CP content_json
            ├─ PublicMessage<arbitrary JSON body>
            ├─ HashRequest<HashRequestBody>
            └─ EncryptedEnvelopeV1
                 └─ PrivateMessage<Protocol, Body>
                      ├─ WebRTCSignalV1Body
                      ├─ MessageV1Body
                      └─ PingPongBody
```

SSP 不携带身份公钥或业务签名。CP 是独立可验证内容，拥有自己的作者公钥、message_id、
时间和签名。SSP 身份 A 可以提交 CP 作者 B 的消息，不要求 A 等于 B。

## 2. 公开消息壳

```json
{
  "from_public_key": "02...",
  "message_id": "base64url-32-byte",
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {},
  "signature": "base64url-der"
}
```

公开 channel 决定固定频道的 body 协议，因此不重复 `protocol`。当前
`bsv8.hash.request.v1` 使用该外壳；任意精确公开频道也可以使用通用公开消息原语，详见
[通用公开消息](./06-通用公开消息.md)。

## 3. 私密消息壳

SSP `content_json` 是：

```json
{
  "envelope_version": 1,
  "from_public_key": "02...",
  "kdf_salt": "base64url-32-byte",
  "nonce": "base64url-12-byte",
  "ciphertext": "base64url-ciphertext-and-tag"
}
```

解密后的消息是：

```json
{
  "protocol": "bsv8.message.v1",
  "message_id": "base64url-32-byte",
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {},
  "signature": "base64url-der"
}
```

发送者公钥只在完整 Inbox 信封出现一次。PrivateMessage 不重复公钥；解密后使用信封的
`from_public_key` 验证唯一业务签名。接收者公钥只取 inbox channel 后缀。

## 4. 身份规则

```text
libp2p public key → SSP caller/payer
CP from_public_key → CP author/signature
```

- SSP Wire 不增加 sender/publisher/payer 公钥；
- CP 不读取 libp2p 公钥作为作者；
- Supplier 不执行 `SSP caller == CP from_public_key`；
- 账本只向已认证 SSP caller 扣费；
- CP 作者策略和 SSP 付款策略可以分别检查。

## 5. 两种编号

| 编号 | 作用 |
|---|---|
| SSP `request_id` | 请求/ActionResult 与收费幂等 |
| CP `message_id` | 签名内容去重、重试和子协议关联 |

两者不能合并。公开去重键为 `(channel, from_public_key, message_id)`；私密去重键为
`(protocol, from_public_key, message_id)`。

## 6. 签名

每条完整 CP 业务消息只有一个 `signature`：

- 公开消息使用 `bsv8.public-message.v1` domain；
- 私密消息使用 `bsv8.private-message.v1` domain，并绑定实际 inbox channel；
- 输入使用 RFC 8785 JCS、SHA-256 和 secp256k1 ECDSA；
- 签名必须 strict DER、low-S；
- SSP request_id、libp2p 身份和付款账户不进入签名输入。

AES-GCM tag 是密文完整性标签，不是第二个业务签名。

## 7. 子协议

| 标识 | body |
|---|---|
| `bsv8.webrtc.signal.v1` | offer/answer/ICE |
| `bsv8.message.v1` | Deliver/ACK |
| `bsv8.ping.v1` | Ping/Pong |

子协议只定义 body，不重复公钥、message_id、时间或签名。解密后必须先按 `protocol`
分派，不能从 body 字段猜测类型。

## 8. Supplier 转发

Supplier 必须使用相同 channel，并逐字节交付收到的 CP `content_json`，不得
parse/stringify、重签或重新加密。第一跳与第二跳使用各自的 SSP request_id，完整 SSP
Wire 不要求相同；CP 验签不依赖 SSP 外壳字节。

## 9. 安全边界

Inbox 使用长期 secp256k1 ECDH、HKDF-SHA256 和 AES-256-GCM，不承诺前向安全。Supplier
没有接收者私钥时，只能检查可见信封，不能验证密文内的 CP 签名。

## 10. 文档

- [Hash 请求频道](./01-Hash请求频道.md)
- [私密收件箱](./02-私密收件箱.md)
- [WebRTC SDP](./03-WebRTC-SDP子协议.md)
- [应用消息与 ACK](./04-应用消息子协议.md)
- [Ping/Pong](./05-Ping-Pong子协议.md)
- [通用公开消息](./06-通用公开消息.md)
- [跨仓库消融设计](../SSP-CP协议族消融设计.md)
