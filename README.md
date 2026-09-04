# BSV8 Channel Protocol SDK

待发布项目包/API 版本：`0.3.0`。协议标识仍保持 `bsv8.*.v1`。

ChannelProtocol（CP）是独立于 libp2p/SSP 的内容协议：

- libp2p 已认证公钥是 SSP 调用者和付款身份；
- SSP Wire 不重复携带身份公钥或业务签名；
- CP 报文自己携带作者公钥、message_id、时间和签名；
- libp2p/SSP 身份 A 可以代发 CP 作者 B 的报文；
- CP 离开原 SSP 连接后仍可验签、过期检查、去重和关联。

跨仓库边界与验收记录见
[`SSP + CP 协议族消融设计`](./docs/SSP-CP协议族消融设计.md)和
[`施工单 004`](./施工单/20260902/004-SSP-CP协议族消融施工单.md)。

> CP 自包含作者公钥、编号、时间和签名的实现已经恢复并冻结在当前 V1 API；Go/TypeScript
> SDK、共享 fixture 和固定向量已完成验收。SatSubscription 的 A 代发 B、持久化收费幂等和
> 两跳交付组合也有生产仓库集成测试；BitFSHello、keymaster.cc 等外部消费者仍需各自验收。

## 协议与模块

| 线上标识 | Go package | TypeScript export | 职责 |
|---|---|---|---|
| `bsv8.public-message.v1` | `publicmessage` | `./public-message` | 任意精确公开频道的通用签名 JSON 原语 |
| `bsv8.hash.request.v1` | `hashrequest` | `./hash-request` | 固定频道的强类型签名 Hash 请求 |
| `bsv8.inbox.<public_key_hex>` | `inbox` | `./inbox` | 自包含发送者公钥的端到端加密信封 |
| `bsv8.webrtc.signal.v1` | `webrtcsignal` | `./webrtc-signal` | SDP/ICE body |
| `bsv8.message.v1` | `appmessage` | `./app-message` | Deliver/ACK body |
| `bsv8.ping.v1` | `ping` | `./ping` | Ping/Pong body |

协议说明见 [docs/v1](./docs/v1/README.md)，机器清单见 [protocols.json](./protocols.json)。

## 独立发布单元

```text
Go module: github.com/bsv8/ChannelProtocol
npm package: bsv8-channel-protocol
```

```text
go get github.com/bsv8/ChannelProtocol@v0.3.0
npm install bsv8-channel-protocol@0.3.0
```

CP Go module 和 TypeScript package 均不得依赖 SSP package。

## 目标公共原语

| 类型 | 含义 | 线上格式 |
|---|---|---|
| `PublicKey` | CP 作者/加密身份公钥 | 33 字节压缩 secp256k1，小写 hex |
| `PrivateKey` | CP 作者/解密私钥 | 32 字节，只作 API 输入 |
| `MessageID` | CP 消息去重与关联编号 | 32 字节无填充 base64url |
| `SessionID` | WebRTC 会话编号 | 32 字节无填充 base64url |
| `SHA256Hash` | 文件内容摘要 | 32 字节小写 hex |
| `Signature` | CP 唯一业务签名 | strict DER、low-S、无填充 base64url |

每条完整 CP 消息只出现一个发送者公钥和一个业务签名。SSP request_id、libp2p 公钥和
付款账户不进入 CP 签名输入。

## 目标消息外壳

通用公开消息（channel 不进入 JSON，但进入签名逻辑对象）：

```json
{
  "from_public_key": "02...",
  "message_id": "...",
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {"kind":"local-demo","value":1},
  "signature": "..."
}
```

固定频道的公开 Hash 消息：

```json
{
  "from_public_key": "02...",
  "message_id": "...",
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {"hash":"...","locators":[]},
  "signature": "..."
}
```

Inbox 信封：

```json
{
  "envelope_version": 1,
  "from_public_key": "02...",
  "kdf_salt": "...",
  "nonce": "...",
  "ciphertext": "..."
}
```

解密后的 PrivateMessage：

```json
{
  "protocol": "bsv8.message.v1",
  "message_id": "...",
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {},
  "signature": "..."
}
```

Inbox 的发送者公钥只在信封出现一次；明文签名使用该公钥验证。发送方保留的本地已签名
Ping/WebRTC 明文可调用 `VerifySignedPrivateMessage`（TypeScript 为
`verifySignedPrivateMessage`）进入相同的 verified 关系校验边界；远端密文仍必须调用
`Open`/`open`。

## SDK 消融边界

保留具体 Hash/Inbox/WebRTC/Message/Ping 模块、严格 JSON、JCS、签名、加密和已验证结果。

删除根级自动 channel decoder、runtime registry、重复命名别名、调用方手填 Context 和
无真实替换价值的 Validator/Router/Middleware。不得以 SDK 表面消融为由删除 CP 作者公钥、
message_id、时间或签名。

## 验证

```text
go test ./...
go test -race ./...
go vet ./...
cd typescript && npm ci && npm test && npm pack --dry-run
cd .. && ./scripts/test-integration.sh
```

本施工单只准备 `0.3.0`，不执行 npm publish、Git tag 或 push。
