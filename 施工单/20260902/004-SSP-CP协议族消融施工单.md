# 004 - libp2p + SSP / CP 协议族消融施工单

状态：已施工；CP/SSP SDK 与 SatSubscription 生产组合已完成本仓库验收，外部消费者待验收。

设计真值：
[`docs/SSP-CP协议族消融设计.md`](../../docs/SSP-CP协议族消融设计.md)。

## 1. 施工目标

- libp2p 已认证公钥作为 SSP 唯一调用者和付款身份；
- SSP Wire 不重复携带公钥或签名；
- CP 独立携带作者公钥、message_id、时间和签名；
- libp2p/SSP 身份 A 可以提交 CP 作者 B 的报文；
- Supplier 按 A 扣费，CP 按 B 验签；
- Supplier 至少逐字节保留 CP `content_json`；
- 加入 Ping/Pong，但不复制 CP 公共字段；
- 删除没有独立约束价值的 SDK 抽象；
- 项目包升至 `0.2.0`，所有协议版本号保持原值。

## 2. 禁止事项

1. 不要求 SSP/libp2p 公钥等于 CP 作者公钥。
2. 不在 SSP Wire 增加 sender/publisher/payer 公钥或 SSP 业务签名。
3. 不从 CP `publisher_public_key` 选择扣费账户。
4. 不把 SSP `request_id` 与 CP `message_id` 合并。
5. 不把 CP 公共头上移 SSP，不让 CP 依赖 SSP。
6. 不增加 `ReviewPublishAdmission`、Validator、Router、Middleware 或 runtime registry。
7. 不通过 parse/stringify、重新签名或重新加密改变转发的 CP 内容。
8. 不修改 SSP WireVersion、Kind、CP protocol 或 envelope 版本号。
9. 不回退当前工作区已经完成的局部代码消融。

## 3. 仓库责任

| 仓库 | 责任 |
|---|---|
| `SatSubscriptionProtocol` | SSP Wire、request_id、Session、付款身份参数、Backend/Dispatcher |
| `ChannelProtocol` | CP 作者身份、message_id、时间、签名、加密和具体子协议 |
| `SatSubscription` | 从 libp2p 连接取得付款人，组合 SSP/CP、扣费和广播 |
| `BitFSHello` | Hash 与 WebRTC 消费者验收 |
| `keymaster.cc` | Inbox、Deliver/ACK、Ping/Pong 和 TypeScript 消费者验收 |

SSP 与 CP 两个协议仓库不得互相依赖；生产程序是组合位置。

## 4. 阶段 0：冻结现状和身份流

只读盘点：

- libp2p 公钥如何认证并传给 SSP Session；
- Backend/Dispatcher 当前用哪个值选择扣费账户；
- SSP Wire/CDDL 是否存在任何公钥或签名字段；
- CP Hash、Inbox 的公钥与签名位置；
- A 提交 B 报文时当前在哪一层被拒绝；
- Supplier 当前在哪一处为订阅者重新包装 SSP Wire，以及是否保持 channel 和 CP 字节；
- Go/TypeScript 导出表面、固定向量和所有生产消费者。

必须绘制两条独立数据流：

```text
libp2p public key → SSP caller/payer → ledger
CP public key → CP signature verify → CP dedup/relation
```

## 5. 阶段 1：冻结边界不变量

先写测试向量和接口约束：

- SSP Session 的 caller/payer 只能由连接参数注入；
- Wire 中不存在可覆盖 caller/payer 的字段；
- CP 签名输入不包含 SSP request_id、libp2p 公钥或连接信息；
- A 与 B 相同合法；
- A 与 B 不同也合法；
- B 签名错误时按 CP 规则失败，但账本仍不得改向 B；
- SSP request_id 只关联 A 与 Supplier 的 ActionResult；
- CP message_id 只关联 B 的内容和 CP 子协议；
- exact content_json 跨 Supplier 保持逐字节一致。

验收向量至少覆盖：

- A 提交 A 签名的公开 CP 报文；
- A 提交 B 签名的公开 CP 报文；
- A 提交伪造 B 签名的报文；
- A 提交 B 的合法 Inbox 信封；
- Supplier 无私钥时只完成 Inbox 可见字段检查；
- 接收者解密后用信封中的 B 公钥验签；
- 同一个 CP message_id 经不同 SSP request_id 提交。

## 6. 阶段 2：SSP 身份和扣费审计

范围：`SatSubscriptionProtocol`。

任务：

1. 保持 SSP Wire 无公钥、无业务签名；
2. Session/服务入口显式接收已认证 libp2p 公钥或账户身份；
3. Backend/Dispatcher 付款参数只从 Session 上下文产生；
4. Publish 继续把 `content_json` 当 exact bytes；
5. SSP 不解析 CP 作者，也不执行 A == B 比较；
6. request_id 去重域必须同时受已认证 SSP 会话/付款身份约束；
7. PublishEvent 删除只为完整 Wire 透传保留的入站 Wire 字段；
8. 增加“Wire 字段不能改变付款人”的负面测试。

如果现有实现已经满足，只补充证明，不为了施工单重写。

## 7. 阶段 3：CP 独立验真审计

范围：`ChannelProtocol`。

### 7.1 公共 Hash

- 保留一个作者公钥、message_id、issued/expires 和一个 signature；
- 签名覆盖 CP 自身的公共字段与 body；
- 不引用 SSP request_id 或连接身份；
- A 代发 B 的报文时仍能仅凭 CP JSON 验证 B。

### 7.2 Inbox

- 加密信封只出现一次 `from_public_key`；
- PrivateMessage 明文不重复公钥；
- message_id、issued/expires、protocol、body 和 signature 保持 CP 自有；
- ECDH、KDF/AAD 与解密后验签都使用同一信封发送者公钥；
- Supplier 只检查可见信封，接收者负责最终解密和验签。

### 7.3 独立性

- CP Go module 不导入 SSP；
- CP TypeScript package 不导入 SSP；
- CP fixture 不需要构造 SSP Wire；
- 保存到文件后仍可完成验签、过期、去重和关联检查。

## 8. 阶段 4：Ping/Pong

范围：`ChannelProtocol`。

- 使用独立 inner protocol `bsv8.ping.v1`；
- Ping body 只保留 `type: "ping"`；
- Pong body 只保留 `type: "pong"` 与 `ping_message_id`；
- 复用 PrivateMessage 的作者公钥、message_id、时间和 signature；
- 不增加 nonce、session_id、第二签名或通用 Request/Response；
- Pong 关联只接受两条已经验签的 CP 消息；
- 最大有效期和错误码用 Go/TypeScript 共享 fixture 冻结。

## 9. 阶段 5：SDK 表面消融

继续审查当前工作区已有差异：

- 删除根级自动 channel decoder；
- 删除公共 runtime protocol registry；
- 删除 Go/TypeScript 重复命名别名；
- 删除无类型门槛价值的 admission 包装；
- 合并重复 raw/decoded 快照；
- 关联审查直接接受已验证消息，删除调用方手填 Context；
- 不引入 Command/RPC/Capability/Lifecycle 框架。

硬性验收：

- 不得删除 CP 作者公钥、message_id、时间或 signature；
- 不得把 CP 类型替换成 SSP Publish 类型；
- 所有当前 CP JSON/JCS/签名/密文固定向量保持有效，除明确冻结的未发布 API 调整。

## 10. 阶段 6：生产 Supplier 组合

范围：`SatSubscription`。

```text
libp2p authenticates A
  → SSP parses request_id/channel/exact content_json
  → CP performs channel-specific checks possible at Supplier
  → Supplier policy
  → idempotency and debit account A
  → deliver exact CP content_json
  → ActionResult for A's SSP request
```

要求：

- 账本 key 来自 libp2p/SSP 上下文 A；
- CP 验签公钥来自 CP 报文 B；
- A != B 合法；
- 公开 Hash 可在新请求扣费前完整验签；完全相同的历史收费请求先查摘要，CP 当前已过期时
  仍返回首次收费结果；
- Inbox 只能在扣费前检查可见信封，不能伪称已验证密文内签名；
- CP 错误不改变付款主体；
- 转发前后 `content_json` 摘要完全相同。

## 11. 阶段 7：两层幂等

SSP 付费请求：

- key 至少包含已认证调用者 A 与 SSP request_id；
- Session 只做当前 Stream 的快速抑制；生产 Backend/Dispatcher 必须保存 deterministic
  SSP Wire 的 SHA-256 `request_digest`；
- 同一 `(A, request_id, request_digest)` 跨 Stream 重试返回第一次保存的收费结果；同一
  `(A, request_id)` 但 channel、content 或 Kind 不同，返回 `REJECTED`，不得再次执行；
- 同一 SSP 请求重试不重复扣费；
- 不用 CP message_id 代替 request_id。

CP 内容：

- key 为 `(publisher_public_key, message_id)`；
- 重发同一签名 CP 报文由订阅者去重；
- 不用 SSP request_id 代替 message_id。

不同 SSP 身份提交同一 CP 报文是否分别收费，由生产 Supplier 策略决定并单独测试，不写入
CP 协议。

## 12. 阶段 8：SSP 两跳重新包装与 CP 原字节交付

已确定不转发完整 SSP Wire。施工规则：

1. A → S 的 SSP Publish 使用 A 原 Stream 的 request_id；
2. S 用该 request_id 向 A 返回收费 ActionResult；
3. S → R 为每个订阅者 Stream 生成新的 delivery request_id；
4. 两跳使用相同 Publish Kind 和相同 document 形状；
5. 第二跳 channel 必须与第一跳完全相同；
6. 第二跳 content_json 必须复用第一跳原始字节切片/不可变副本，不得重新序列化；
7. R 把 Supplier 订阅交付路径上的 Publish 当作事件，不返回 SSP ActionResult；
8. delivery request_id 只用于 SSP 传输边界，不进入 CP 验签、去重或关联。

必须增加以下断言：

```text
outbound.delivery_request_id is newly generated, not copied from inbound.request_id
inbound.channel == outbound.channel
inbound.content_json bytes == outbound.content_json bytes
inbound SSP Wire bytes != outbound SSP Wire bytes   # 正常且允许
```

禁止增加 Publication Kind、第二种 CP 报文或 V2 协议号。

## 13. 阶段 9：消费者迁移

- SSP 调用方从 libp2p 认证上下文传入付款身份；
- CP 调用方继续构造和验证自包含签名消息；
- 删除所有 A == B 假设；
- 分别使用 SSP request_id 与 CP message_id；
- 验收 Hash、Inbox、WebRTC、Deliver/ACK、Ping/Pong；
- 按阶段 8 的固定规则迁移订阅事件处理。

## 14. 版本与最终冻结

项目包：

- ChannelProtocol npm / Go tag：`0.2.0` / `v0.2.0`；
- SatSubscriptionProtocol npm、Go/TS SDKVersion：`0.2.0`。

协议版本保持：

- SSP WireVersion = 1；
- SSP Kind 数值不变；
- CP `bsv8.*.v1` 不变；
- Inbox envelope_version = 1；
- 不增加未发布旧形状的兼容分支。

## 15. 验收命令

### ChannelProtocol

```text
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
cd typescript && npm ci && npm test && npm pack --dry-run
cd .. && ./scripts/test-integration.sh
```

### SatSubscriptionProtocol

```text
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
cd typescript && npm ci && npm test && npm run build && npm pack --dry-run
cd .. && ./scripts/validate-cddl.sh
./scripts/test-integration.sh
./scripts/test-examples.sh
```

生产集成必须额外覆盖 A 代发 B、账本向 A 扣费、CP 用 B 验签和 exact content_json。

## 16. 停工条件

- SSP Wire 新增了身份公钥或签名；
- 付款账户来自 CP 字段；
- A != B 被当成非法；
- CP 签名输入依赖 SSP/libp2p；
- SSP request_id 与 CP message_id 被合并；
- Supplier 声称验证了其无法解密的 Inbox 内层签名；
- 转发的 CP content_json 字节改变；
- 为组合重新引入通用 admission/router/middleware；
- 任一协议版本号被修改；
- 第一跳 request_id 被直接带入订阅者 Stream；
- 以完整 SSP Wire 在两跳逐字节相同为要求（当前规则是新 delivery request_id、相同 channel
  和完全相同的 CP content_json 字节）。

## 17. 实施结果

- [x] ChannelProtocol 已恢复 CP 自包含作者公钥、message_id、时间、签名、Inbox 信封和 Ping/Pong。
- [x] SatSubscriptionProtocol 已删除本次 SDK 表面重复别名，并保留 SSP Wire 的版本与 Kind 数值。
- [x] SatSubscription 已组合 libp2p 付款身份、CP 校验、PostgreSQL `(payer_id, request_id, request_digest)` 收费幂等和两跳交付；摘要冲突返回 `REJECTED`。
- [x] 两跳使用新 delivery request_id、相同 channel、完全相同的 CP `content_json` 字节；完整 SSP Wire 不要求相同。
- [ ] BitFSHello、keymaster.cc 等外部消费者的最终验收。
