# 论坛 reply 报价 V1

协议：

```text
bsv8.bbs.quote.v1
```

本协议只定义 PrivateMessage body。message_id、时间和签名由壳提供，身份公钥由 Inbox 信封提供。

## 1. 参与者

| 角色 | 身份来源 | inbox |
| --- | --- | --- |
| 客户端（回复者） | ask 信封 `from_public_key` | `bsv8.inbox.<索引服务公钥>` |
| BBS 索引服务 | answer 信封 `from_public_key` | `bsv8.inbox.<客户端公钥>` |

ask 由客户端投给索引服务，不是投给原帖作者。`reply_price` 由发帖者申请、索引服务签发。

## 2. 标识规则

- `to_post`：原帖所在交易的 txid。帖子 id 用 txid，不用 masterseed hash，因此同一
  masterseed hash 可以在多处 post 或 reply；
- `reply_masterseedhash`：本次回复内容的 masterseed hash；
- 父帖由 `to_post` 唯一确定，回复可再被回复，形成树。

## 3. ask body

```json
{
  "type": "reply.price.ask",
  "to_post": "hex-txid",
  "reply_masterseedhash": "hex-64-char",
  "reply_price": 5
}
```

| 字段 | 含义 | 约束 |
| --- | --- | --- |
| `type` | 报价分量 + 方向 | 固定 `reply.price.ask` |
| `to_post` | 被回复内容所在交易的 txid | 32 字节 hex，小写 |
| `reply_masterseedhash` | 本次回复内容的 masterseed hash | 32 字节 hex，小写 |
| `reply_price` | 客户端愿意支付的回复价 | sat，uint64 |

## 4. 报价 CBOR

索引服务对下列 CBOR 字节签名，域字符串 `BSV8:QUOTE:1.0`：

```text
{ version: 1, type: "reply.price.answer", ask_message_id, price, reply_to_public_key, last_block_height }
```

| 字段 | 来源 |
| --- | --- |
| `version` | 固定 1，协议版本 |
| `type` | answer 的 `type`，逐字复制 |
| `ask_message_id` | ask 的 CP message_id |
| `price` | 索引服务出 |
| `reply_to_public_key` | 索引服务出，收款公钥 |
| `last_block_height` | 索引服务出 |

编码为 canonical CBOR（CTAP2），规则同 `1-post 报价` 第 4 节。四个价格分量共用域
字符串，由 CBOR 内 `type` 区分。

## 5. answer body

```json
{
  "type": "reply.price.answer",
  "ask_message_id": "hex-64-char",
  "price": 5,
  "reply_to_public_key": "02...",
  "last_block_height": 900000,
  "sign": "hex-der"
}
```

`reply_to_public_key` 是被回复内容的作者公钥，也是本报价的收款方；收款方是第三方，所以
必须在报价内写明。answer 不重述 ask 的 `to_post`、`reply_masterseedhash` 和
`reply_price`，一律按 `ask_message_id` 关联取回。`type` 的合法值只有
`reply.price.ask` 和 `reply.price.answer`。

## 6. 链上体现

CBOR 字节不上链。支付交易必须体现：

- op_return 携带 `reply_masterseedhash`，并以 `to_post` 为父帖；
- 存在指向 `reply_to_public_key` 的 `price` sat 输出；
- 确认高度不晚于 `last_block_height`。

持有 ask 的一方可以用自己的 ask 加上交易内容重建同一份 CBOR 字节并验签；没有 ask 的
第三方无法重建。

## 7. 索引服务签发前校验

1. `to_post` 是本索引服务已索引的 post；
2. `reply_masterseedhash` 以 `to_post` 为父帖，可被唯一推导；
3. `reply_to_public_key` 等于 `to_post` 交易中声明的作者公钥；
4. `reply_price` 等于该 post 在发帖时登记的 `reply_price`，不一致直接拒签。

## 8. 收件人校验

1. answer 的 inbox 接收者等于 ask 的信封发送者；
2. `ask_message_id` 能取到已解密验签的 ask，其 `type` 与本 answer 的 `type` 只差结尾的
   `ask` / `answer`；
3. 按第 4 节重建 CBOR，`sign` 用 answer 信封 `from_public_key` 验证通过；
4. `current_block_height <= last_block_height`，否则重新 ask；
5. 付款目标必须是 `reply_to_public_key`，付错公钥的报价立即作废。

CP 消息有效期最多 10 分钟。

## 9. 待定

- 回复树深度上限未定义；
- IndexedMasterseedHash 派生算法未写入规范，Go 与 TypeScript 必须共用同一份测试向量；
- 每层 `reply_price` 付给被回复那一层的作者，根帖作者不参与；此规则需确认。
