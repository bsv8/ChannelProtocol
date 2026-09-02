# libp2p + SSP / CP 协议族消融设计

状态：CP/SSP SDK 消融已施工并完成仓库验收；SatSubscription 生产组合已接入并完成 A 代发 B、
跨 Stream 收费幂等和两跳交付集成验收；外部消费者仍需各自验收。

完整施工顺序见
[`004-SSP-CP协议族消融施工单`](../施工单/20260902/004-SSP-CP协议族消融施工单.md)。

## 1. 最终分层

```text
连接与付费域                         可独立验证的内容域
┌──────────────────────┐            ┌─────────────────────────┐
│ libp2p authenticated │            │ CP signed message       │
│ public key           │            │ publisher_public_key    │
│          ↓           │            │ message_id / time       │
│ SSP request/billing  │ contains → │ body / signature        │
└──────────────────────┘            └─────────────────────────┘
```

- libp2p 和 SSP 是一体：libp2p 已认证公钥就是 SSP 调用者、付款人和连接身份；
- CP 是另一体：CP 报文自己携带作者公钥、消息编号、时间和签名；
- SSP 把 CP JSON 当作 `content_json`，不拥有 CP 作者身份；
- CP 不依赖 SSP，也不能依赖某条连接才能验签。

因此撤销此前“把 CP 公共头上移到 SSP”的设计。

## 2. 两个身份，各自只有一个真值

假设 libp2p 身份 A 提交作者 B 的 CP 报文：

```text
libp2p/SSP identity = A   → 连接认证、请求准入、扣费
CP publisher       = B   → 内容作者、CP 签名和内容去重
```

Supplier 的处理：

1. 从 libp2p 连接取得 A 的已认证公钥；
2. SSP 用 A 作为调用者和付款人，不从 SSP Wire 再读一个发送者公钥；
3. 从 `content_json` 读取 CP 作者 B；
4. 按 CP 规则验证 B 的签名，或在无法解密时只验证可见信封；
5. 不要求 A 等于 B；
6. 按 A 的账户扣费；
7. 把 CP 原始内容交付订阅者，订阅者使用 B 验签。

“唯一公钥”应精确理解为：

- SSP 身份只有一个来源：libp2p 已认证连接；
- 每条 CP 完整报文只有一个 `publisher_public_key`；
- 两层身份可以不同，不能为了字段更少把它们合并。

## 3. SSP 不携带公钥

SSP Wire 只表达订阅/发布服务所需字段，例如：

- `request_id`；
- `channel`；
- exact `content_json`；
- ActionResult、金额和订阅操作。

SSP 不增加：

- `sender_public_key`；
- `publisher_public_key`；
- `payer_public_key`；
- SSP 业务签名。

SSP Session/Dispatcher 从调用参数或连接上下文接收已认证 libp2p 公钥。账本扣费 key 只能
来自该上下文，不能由 Wire 或 CP 字段自报。

## 4. CP 保留独立公共头

CP 需要在 Supplier 转发、离线保存或脱离原连接后仍能验真，因此保留：

- `publisher_public_key`：CP 作者；
- `message_id`：CP 逻辑消息编号；
- `issued_at_ms` / `expires_at_ms`：CP 消息有效期；
- `signature`：作者签名；
- 严格 JSON、JCS、secp256k1、SHA-256、strict DER 和 low-S。

签名输入由 CP 自己定义，不能引用 libp2p 连接身份或 SSP `request_id`。否则 CP 报文
换一条连接、由代理代发或离线验证时就会失效。

## 5. SSP request_id 与 CP message_id 不合并

两个编号属于不同生命周期：

| 编号 | 所属层 | 作用 |
|---|---|---|
| SSP `request_id` | libp2p/SSP 请求 | 在调用者与 Supplier 之间关联 ActionResult、防止重复扣费 |
| CP `message_id` | CP 签名内容 | 内容去重、重试和 WebRTC/ACK/Pong 等跨消息关联 |

A 可以多次提交 B 的同一 CP 报文，也可以在不同 SSP 连接上提交。SSP 是否收费由 A 的
请求幂等规则决定；订阅者是否重复消费由 `(B, message_id)` 决定。

把两个编号合并会让 CP 签名内容依赖一次特定的 SSP 付费请求，因此拒绝消融。

## 6. CP 报文的唯一公钥和唯一签名

### 6.1 公开 Hash

完整 CP 消息保留当前方向：

```json
{
  "publisher_public_key": "02...",
  "message_id": "...",
  "issued_at_ms": 0,
  "expires_at_ms": 0,
  "body": {
    "hash": "...",
    "locators": ["..."]
  },
  "signature": "..."
}
```

字段实际命名是否继续使用现有 `from_public_key`，由 SDK API 迁移成本决定；语义上只有
一个 CP 作者公钥，不再增加别名。

### 6.2 私密 Inbox

完整私密报文同样只出现一次发送者公钥。它位于可见加密信封，用于 ECDH、KDF/AAD 和
解密后的签名验证：

```json
{
  "envelope_version": 1,
  "from_public_key": "02...",
  "kdf_salt": "...",
  "nonce": "...",
  "ciphertext": "..."
}
```

解密后的 PrivateMessage 保留：

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

明文不再重复 `from_public_key`；验签公钥取自外层信封。这样完整 Inbox 报文仍只有一个
发送者公钥和一个 CP 签名。

Supplier 无接收者私钥，不能验证密文内的签名。它只能检查 channel、信封字段、公钥形状、
大小和 Supplier 策略；最终作者签名由接收者解密后验证。

## 7. Ping/Pong

Ping/Pong 继续作为独立私密 CP 子协议：

```json
{"type":"ping"}
```

```json
{"type":"pong","ping_message_id":"..."}
```

它复用 PrivateMessage 的作者公钥、`message_id`、时间和唯一签名，不在 body 中增加
第二套公钥、编号、时间、nonce 或签名。

## 8. Supplier 原样转发的准确边界

“原样转发”只指 CP 字节，不指完整 SSP Wire：

```text
inbound.channel              == outbound.channel
inbound.content_json bytes   == outbound.content_json bytes
```

S 不得 parse/stringify CP JSON，不得替换作者、重签或重新加密。channel 也必须保持相同，
因为 CP 签名域绑定实际 channel。

SSP 两跳各自拥有传输外壳：

- A → S：使用 A 在原 SSP Stream 上的 `request_id`，S 用它返回 ActionResult；
- S → R：S 按订阅者 Stream 生成新的 delivery `request_id`，包装相同 channel 和 exact
  `content_json`；
- R 根据“来自 Supplier 的订阅交付路径”把该 Publish 当成事件，不返回 ActionResult；
- delivery `request_id` 不是 CP message_id，也不参与 CP 签名、去重或 ACK/Pong 关联；
- 两跳继续使用同一个 Publish Kind 和同一种 SSP document 形状，不新增 Publication Kind。

因此完整 SSP Wire 通常不同，这是正确行为；第一跳收费请求编号不得泄漏到另一条 Stream。

## 9. Dispatcher 组合边界

不增加 `ReviewPublishAdmission`、Validator、Router 或 Middleware。生产 Supplier 在现有
具体 Dispatcher 中组合：

```text
从 libp2p 连接取得 SSP caller/payer A
  → SSP 严格解析 request_id/channel/exact content_json
  → CP 按 channel 做 Supplier 能完成的检查
  → 用 deterministic SSP Wire 摘要查询已完成收费
  → 新请求才执行当前 CP 时间、结构和签名检查
  → Supplier 策略
  → 按 A 幂等和扣费
  → 交付 exact CP content_json
  → 向 A 的原 SSP 请求返回 ActionResult
```

SSP Core 不导入 CP；CP 也不导入 SSP。具体生产程序同时调用两个库。

## 10. 重试和去重

- SSP 请求重试以“已认证 libp2p 身份 + SSP request_id”为持久化索引；Session 只在当前
  Stream 内做快速抑制。收费记录还必须保存 deterministic SSP Wire 的 SHA-256
  `request_digest`，只有 `(payer_id, request_id, request_digest)` 全部相同才是重试；
- 生产 Backend/Dispatcher 对相同摘要返回第一次保存的收费结果，不再次扣费或广播；同一
  `(payer_id, request_id)` 但摘要不同必须返回 `REJECTED`，不得复用旧金额或旧业务结果；
- 相同 SSP 请求重试不得重复扣费；
- CP 报文重试复用同一签名内容和 `message_id`；
- CP 是否重新加密取决于 Deliver/离线转发的既有语义，不能由 SSP 擅自决定；
- 订阅者以 `(publisher_public_key, message_id)` 去重；
- 不建立跨 SSP/CP 的统一编号或统一幂等表。

不同 libp2p 身份提交同一 CP 报文是否分别收费，是 Supplier 计费策略，不属于 CP 协议，
也不能通过 CP `message_id` 自动决定。

## 11. SDK 表面消融

仍然成立的删除项：

- CP 根级自动解码联合和公共 runtime registry；
- Go/TypeScript 重复命名别名；
- 无后续类型约束价值的包装结果；
- 调用方手工拼装的 Relation/Context；
- 通用 Command/RPC/Capability/生命周期框架；
- 只增加接口、不形成真实替换点的 Validator/Router/Middleware。

仍然保留：

- SSP Wire、Session、Backend、Dispatcher、RequestEnvelope 和 ActionResult；
- CP 公钥、消息编号、时间、签名和独立加密；
- Hash、Inbox、WebRTC、Deliver/ACK、Ping/Pong 的具体模块；
- 原始 CP JSON 字节、严格验证和跨语言固定向量。

此前计划删除 CP 公共头、把 CP 依赖到 SSP、把两层编号/签名合并，全部撤销。

## 12. 版本决议

两个项目尚未正式发布：

- 项目包/SDK 版本升级为 `0.2.0`；
- SSP `wire_version = 1` 不变；
- SSP Kind 数值不变；
- CP `bsv8.*.v1` 不变；
- `envelope_version = 1` 不变；
- 不建立未发布旧形状的兼容层。

项目包版本与协议版本继续分开管理。

## 13. 完成判据

- SSP Wire 没有发送者/付款人公钥，身份只来自已认证 libp2p 连接；
- 账本始终向 SSP 连接身份扣费；
- A 可以提交 B 的合法 CP 报文，系统不要求 A 等于 B；
- 每条 CP 完整报文只有一个作者公钥和一个签名；
- CP 离开原 SSP 连接后仍可验签、过期检查、去重和关联；
- Supplier 交付的 channel 相同，CP `content_json` 与收到的字节完全相同；
- SSP 收费操作保存并比较 deterministic Wire 的 32 字节 SHA-256 `request_digest`；同付款人
  同 request_id 的不同 channel、content 或 Kind 返回 `REJECTED`；
- SSP `request_id` 与 CP `message_id` 各自保留；
- Ping/Pong 不重复公共 CP 字段；
- 项目包版本为 `0.2.0`，所有协议版本号保持原值；
- 第一跳与第二跳 SSP request_id 独立，完整 SSP Wire 不要求相同；

## 14. 实施状态

- `ChannelProtocol`：CP 自包含公钥、message_id、时间、签名、Inbox 加密和 Ping/Pong 已落地；
  Go/TypeScript、固定向量和 race/vet 验收通过。
- `SatSubscriptionProtocol`：SSP V1 Wire、Session、付款身份参数、精简 PublishEvent、
  Go/TypeScript SDK 表面和跨语言验收已落地；Session 内抑制与持久化收费幂等的边界已写入接口契约。
- `SatSubscription`：入站请求经 Session 返回提交者 ActionResult；Dispatcher 直接向订阅者
  Sink 写入新 request_id 的 Publish 交付，保持 channel 和 CP content_json 字节，订阅者路径
  不生成 ActionResult；PostgreSQL 已覆盖 `(payer_id, request_id, request_digest)` 跨 Stream
  收费幂等及摘要冲突拒绝，完全相同的历史 Publish 会在 CP 过期后重放原收费结果。
- `BitFSHello`、`keymaster.cc`：属于外部消费者责任，尚未在本次三个仓库范围内验收。

本文和施工单现在记录已实施边界；后续改动必须以本文、代码和固定向量共同验收，不得恢复已撤销
的 SSP 公共身份字段、完整 Wire 原样转发或旧 SDK 兼容别名。
