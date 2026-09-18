# Hash 请求频道 V1

频道：

```text
bsv8.hash.request.v1
```

## 1. 完整 CP 消息

```json
{
  "from_public_key": "02...",
  "message_id": "base64url-32-byte",
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {
    "hash": "64-char-lowercase-hex",
    "locators": [
      {"kind":"multiaddr","address":"/dns4/node.example/tcp/4001/p2p/..."},
      {"kind":"webrtc-sdp"}
    ]
  },
  "signature": "base64url-der"
}
```

这是完整的 SSP `content_json`。所有字段必需；公开 channel 已决定协议，不增加
`protocol` 字段。

## 2. 字段

- `from_public_key`：CP Hash 请求作者，33 字节压缩 secp256k1 公钥；
- `message_id`：CP 内容编号；
- 有效期不得超过 10 分钟（结构约束，与本地时钟无关）；
- SDK 只校验结构时间（合法整数、`issued_at_ms < expires_at_ms`、有效期不超过上限）和签名；
  消息是否过期、是否接受未来或迟到消息由调用方按自己的时钟与业务边界判断；
- `body.hash`：目标文件字节的 SHA-256；
- `body.locators`：至少一个，按数组顺序建议尝试；
- `signature`：覆盖 channel、作者、message_id、时间和 body 的唯一 CP 签名。

`multiaddr` locator 使用标准 multiaddr；`webrtc-sdp` locator 不允许额外字段。
libp2p locator 中的 Peer ID、SSP 付款人和 CP 作者可以分别不同。

## 3. SSP 组合

libp2p/SSP 身份 A 提交作者 B 的 Hash 请求时：

- Supplier 按 A 的连接账户准入和扣费；
- Hash 的 `from_public_key = B`；
- CP 使用 B 验证签名；
- 不检查 A == B；
- Supplier 逐字节转发完整 Hash `content_json`。

公开 Hash 可以由 Supplier 在扣费前完成全部 CP 结构、时间字段和签名验证；SDK 不使用本地
时钟判断过期，是否接受过期或未来消息属于调用方的业务边界。

## 4. 去重与 WebRTC

接收方按：

```text
(channel, from_public_key, message_id)
```

去重。若包含 `webrtc-sdp` locator，WebRTC offer 的
`request_message_id` 引用本 Hash 消息的 `message_id`。

## 5. 非目标

本频道不定义 SSP request_id、付款、广播、文件传输、离线队列或 WebRTC 状态机。
