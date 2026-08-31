# Hash 请求频道 V1

频道名称：

```text
bsv8.hash.request.v1
```

本频道使用 V1 公开消息壳。精确 channel 已经确定协议，不再重复 `protocol` 字段。

## 1. 业务语义

请求者广播一个文件内容的 SHA-256 Hash，表示：

> 我需要取得与这个 Hash 严格对应的文件字节；拥有该内容的节点可以通过我提供的 locator
> 与我建立连接。

本频道不定义文件类型。文件 MIME、扩展名、业务 kind 或上层用途不能改变 Hash 含义。

## 2. 完整公开消息

```jsonc
{
  "from_public_key": "02...",        // 请求者公钥，必须等于 SSP remote_public_key
  "message_id": "base64url-32-byte", // 本次 Hash 请求编号
  "issued_at_ms": 0,                  // 发布时间
  "expires_at_ms": 0,                 // 最长不超过 10 分钟

  "body": {
    "hash": "64-char-lowercase-hex",  // 文件字节 SHA-256
    "locators": [
      {
        "kind": "multiaddr",
        "address": "/dns4/node.example/tcp/4001/p2p/12D3KooW..."
      },
      {
        "kind": "multiaddr",
        "address": "/dns4/node.example/tcp/443/wss/p2p/12D3KooW..."
      },
      {
        "kind": "webrtc-sdp"
      }
    ]
  },

  "signature": "base64url-der-signature" // 整条公开消息唯一签名
}
```

所有字段必需。`locators` 至少包含一个元素，数组顺序就是建议尝试顺序。

## 3. 字段规则

| 字段 | 类型 | 中文含义和约束 |
|---|---|---|
| `from_public_key` | string | 请求者压缩 secp256k1 公钥，小写 hex；等于 SSP `remote_public_key` |
| `message_id` | string | 32 字节随机编号，无填充 base64url |
| `issued_at_ms` | number | 发布时间，Unix 毫秒安全整数 |
| `expires_at_ms` | number | 晚于发布时间且有效期不超过 10 分钟 |
| `body.hash` | string | 文件字节 SHA-256 的 64 位小写 hex |
| `body.locators` | array | 请求者连接位置，按数组顺序尝试 |
| `signature` | string | 按 `bsv8.public-message.v1` 作用域生成的唯一签名 |

`body.hash` 是唯一资源真值。不提供 `resource.kind`、`hash_algorithm` 或
`hash_encoding`。

## 4. Locator

### 4.1 Multiaddr

`address` 直接使用标准 multiaddr，不增加 `multiaddr:` URI 前缀：

```text
/dns4/example.com/tcp/4001/p2p/<peer-id>
/ip4/203.0.113.10/tcp/4001/p2p/<peer-id>
/ip6/2001:db8::10/tcp/4001/p2p/<peer-id>
/dns4/example.com/tcp/443/wss/p2p/<peer-id>
/ip4/203.0.113.10/udp/4002/webrtc-direct/certhash/<hash>/p2p/<peer-id>
```

libp2p Peer ID 可以与 `from_public_key` 不同。定位器只负责描述如何建立后续连接。

### 4.2 WebRTC SDP

```jsonc
{
  "kind": "webrtc-sdp"
}
```

该 locator 表示请求者可以通过私密收件箱接收 WebRTC offer。请求者固定作为 answerer；
每个 offerer 为自己的连接生成独立 `session_id`。

## 5. 发布入口检查

在调用 SSP Publish 前必须：

1. 严格解析公开消息结构；
2. 检查 `from_public_key` 是有效 secp256k1 公钥；
3. 检查 `SSP remote_public_key == from_public_key`；
4. 检查时间、Hash 和 locator；
5. 按公开消息签名规则验证唯一 `signature`。

任意一步失败都不能进入 SSP 广播。

## 6. 提供者处理

提供者收到广播后：

1. 再次验证消息结构、时间和签名；
2. 按 `(channel, from_public_key, message_id)` 检测重复；
3. 查询自己能否提供 `body.hash` 对应的文件；
4. 按 `body.locators` 顺序选择连接方式；
5. 选择 `webrtc-sdp` 时，通过请求者私密收件箱发送 WebRTC 子协议 offer；
6. 连接建立后，本频道职责结束。

## 7. 交互流程

```text
请求者 A                    SSP 广播                    资源提供者 B
   │                           │                            │
   │── 已验签公开消息 ────────>│                            │
   │   bsv8.hash.request.v1    │── 广播请求 ──────────────>│
   │                           │                再次验签、查询 Hash
   │                           │                按顺序选择 locator
   │<──────────── 后续连接业务根据 locator 建立连接 ───────│
```

## 8. 非目标

本频道不传输文件字节，也不定义文件传输 Protocol ID、Stream 方向、分帧、断点续传、
提供者列表、计费、送达确认、失败广播或离线队列。
