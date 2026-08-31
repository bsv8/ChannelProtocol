# SSP 三方频道 V1

## 1. 协议分层

V1 在 SSP `Publish` 之上定义一个公开频道和一个私密收件箱：

| 名称 | 类型 | 中文含义 |
|---|---|---|
| `bsv8.hash.request.v1` | 公开 SSP 频道 | 广播文件 Hash 需求以及请求者连接位置 |
| `bsv8.inbox.<public_key_hex>` | 私密 SSP 频道 | 向目标公钥投递端到端加密信封 |
| `bsv8.webrtc.signal.v1` | 收件箱子协议 | 交换 WebRTC SDP 和 ICE 信令 |
| `bsv8.message.v1` | 收件箱子协议 | 投递应用消息并返回接收 ACK |

```text
SSP Publish
├── bsv8.hash.request.v1
│     └── PublicMessage<HashRequestBody>
└── bsv8.inbox.<目标公钥>
      └── EncryptedEnvelopeV1
            └── PrivateMessage<Protocol, Body>
                  ├── WebRTCSignalV1Body
                  └── MessageV1Body
```

公开消息和加密消息是两种不同的壳，不能合并成一个包含大量可选字段的通用结构。

## 2. 公开消息壳

公开频道使用以下结构：

```jsonc
{
  "from_public_key": "02...",        // 发送者公钥，必须等于 SSP remote_public_key
  "message_id": "base64url-32-byte", // 公开消息编号
  "issued_at_ms": 0,                  // 发布时间
  "expires_at_ms": 0,                 // 过期时间
  "body": {},                         // 由 SSP channel 唯一确定的强类型正文
  "signature": "base64url-der"       // 整条公开消息唯一签名
}
```

公开消息不需要 `protocol` 字段，精确 SSP channel 已经确定协议和版本。V1 当前只有
`bsv8.hash.request.v1` 使用公开消息壳。

## 3. 加密消息壳

私密收件箱的 SSP `content_json` 是加密信封：

```jsonc
{
  "envelope_version": 1,             // 加密信封版本
  "from_public_key": "02...",        // 发送者公钥，必须等于 SSP remote_public_key
  "kdf_salt": "base64url-32-byte",  // 每条消息的新随机盐
  "nonce": "base64url-12-byte",     // 每条消息的新 AES-GCM nonce
  "ciphertext": "base64url..."      // 密文和 16 字节 GCM tag
}
```

解密后的私密消息：

```jsonc
{
  "protocol": "bsv8.message.v1",     // 收件箱子协议和版本
  "message_id": "base64url-32-byte", // 私密消息编号
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {},                         // 由 protocol 唯一确定的强类型正文
  "signature": "base64url-der"       // 整条私密消息唯一签名
}
```

发送者身份只取加密信封的 `from_public_key`，接收者身份只取
`bsv8.inbox.<public_key_hex>` 的频道后缀。密文内和子协议 `body` 不再重复公钥或签名。

## 4. 身份规则

三方频道使用 33 字节压缩 secp256k1 公钥作为身份，编码固定为 66 位小写十六进制，不带
`0x`，并且必须是有效曲线点。

发布入口必须检查：

```text
SSP remote_public_key == message.from_public_key
```

- 公开消息从公开壳读取 `from_public_key`；
- 加密消息从加密信封读取 `from_public_key`，不需要解密即可比较；
- 不相等时必须在进入 SSP 广播前拒绝；
- SSP Core 不解析三方协议，该比较由接入 SSP 的三方频道 SDK 或应用适配层执行；
- libp2p Peer ID 或连接公钥可以与三方频道/SSP 公钥不同，由后续连接协议自行认证。

## 5. 公共编码

| 数据 | V1 固定编码 | 中文说明 |
|---|---|---|
| `message_id` | 32 字节随机值的无填充 base64url，固定 43 个字符 | 消息去重和关联编号 |
| `session_id` | 32 字节随机值的无填充 base64url，固定 43 个字符 | 一次 WebRTC 会话编号 |
| 公钥 | 33 字节压缩 secp256k1 公钥的小写 hex | SSP 与三方报文共用身份 |
| 文件 Hash | 32 字节 SHA-256 的小写 hex，固定 64 个字符 | 请求的文件内容标识 |
| 时间 | JSON 安全整数形式的 Unix 毫秒 | 不允许小数、字符串或超过安全整数范围 |
| 签名 | 严格 DER、low-S ECDSA 签名的无填充 base64url | secp256k1 ECDSA + SHA-256 |

所有消息必须符合 RFC 8785 JCS 可规范化的 JSON 约束，并拒绝重复字段名。

## 6. 单次签名规则

每条业务消息只包含一个 `signature`。子协议 `body` 不能再次携带签名。

### 6.1 公开消息签名输入

删除公开消息的 `signature` 后，构造：

```jsonc
{
  "scope": "bsv8.public-message.v1",
  "channel": "实际 Publish channel",
  "from_public_key": "公开壳中的发送者公钥",
  "message": {
    "message_id": "...",
    "issued_at_ms": 0,
    "expires_at_ms": 0,
    "body": {}
  }
}
```

### 6.2 私密消息签名输入

删除解密后消息的 `signature`，并结合加密信封及实际频道构造：

```jsonc
{
  "scope": "bsv8.private-message.v1",
  "channel": "bsv8.inbox.<接收者公钥>",
  "from_public_key": "加密信封中的发送者公钥",
  "message": {
    "protocol": "...",
    "message_id": "...",
    "issued_at_ms": 0,
    "expires_at_ms": 0,
    "body": {}
  }
}
```

两种签名输入都按以下流程处理：

1. 使用 RFC 8785 JCS 生成 UTF-8 字节；
2. 对字节计算 SHA-256；
3. 使用 `from_public_key` 对应的长期私钥和 RFC 6979 确定性 nonce 执行 secp256k1 ECDSA；
4. 将 `s` 规范化为 low-S，严格 DER 编码后再转为无填充 base64url。

验证方必须拒绝非严格 DER、high-S、无效曲线签名或尾随字节，不能自行宽松修正后接受。

不同 `scope` 防止公开消息和私密消息之间复用签名。AES-GCM tag 只验证密文完整性，不是
第二个业务签名。

## 7. 重复消息检测

公开消息检测键：

```text
(channel, from_public_key, message_id)
```

私密消息检测键：

```text
(protocol, from_public_key, message_id)
```

收件箱只报告消息是否重复；忽略、重新回应或其他处理由具体子协议决定。

## 8. 强类型子协议

解密后必须先读取 `protocol`，再使用对应结构解析 `body`：

```text
bsv8.message.v1       → MessageV1Body
bsv8.webrtc.signal.v1 → WebRTCSignalV1Body
```

子协议文档只定义 `body`，不能重新定义公共消息头、公钥、时间、`message_id` 或
`signature`。不能根据 `body` 中碰巧存在的字段猜测协议。

## 9. V1 基础安全级别

V1 私密收件箱使用双方长期 secp256k1 密钥执行 ECDH，再通过 HKDF-SHA256 派生每条消息的
AES-256-GCM 密钥。

V1 提供内容加密、发送者签名、密文完整性和身份一致性，但不承诺：

- 前向安全；
- 长期私钥泄露后的历史密文保护；
- 隐藏发送者和接收者之间的通信关系；
- Double Ratchet、预密钥或一次性身份。

更高隐私级别应作为新产品或新的 `envelope_version` 定义，不能改变 V1 语义。

## 10. 版本和兼容性

- `bsv8.inbox.<公钥>` 是稳定寻址频道；
- 加密格式由 `envelope_version` 选择；
- 子协议在 `protocol` 名称中独立携带版本；
- 破坏性修改使用新频道、子协议版本或信封版本；
- 不能在同一版本中改变已有字段含义。

## 11. 协议责任

| 层级 | 负责 | 不负责 |
|---|---|---|
| SSP | 身份认证、在线订阅匹配和尽力广播 | 解析三方消息、端到端加密、业务 ACK |
| 三方接入层 | 检查 SSP `remote_public_key` 等于报文发送者公钥 | libp2p 身份绑定 |
| 私密收件箱 | 长期密钥 ECDH、加解密、单次签名、子协议分派 | 离线队列、前向安全 |
| WebRTC 子协议 | Offer、Answer、ICE 和会话关联 | 应用消息 ACK、文件传输 |
| 应用消息子协议 | Deliver、可靠接收 ACK、去重重试 | 已读和业务执行结果 |

## 12. 文档

- [Hash 请求频道](./01-Hash请求频道.md)
- [私密收件箱](./02-私密收件箱.md)
- [WebRTC SDP 子协议](./03-WebRTC-SDP子协议.md)
- [应用消息子协议](./04-应用消息子协议.md)

## 13. 参考

- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 5869 HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [libp2p Addressing](https://github.com/libp2p/specs/blob/master/addressing/README.md)
