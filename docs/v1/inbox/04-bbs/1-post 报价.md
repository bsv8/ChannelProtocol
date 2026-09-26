# 论坛 post 报价 V1

协议：

```text
bsv8.bbs.quote.v1
```

本协议只定义 PrivateMessage body。message_id、时间和签名由壳提供，身份公钥由 Inbox 信封提供。

## 1. 参与者

| 角色 | 身份来源 | inbox |
| --- | --- | --- |
| 客户端（发帖者） | ask 信封 `from_public_key` | `bsv8.inbox.<索引服务公钥>` |
| BBS 索引服务 | answer 信封 `from_public_key` | `bsv8.inbox.<客户端公钥>` |

## 2. 四个价格分量

| 分量 | 定价方 | 收款方 | 报价方式 |
| --- | --- | --- | --- |
| post | 索引服务 | 索引服务 | 本协议 |
| reply | 发帖者申请，索引服务签发 | 被回复内容的作者 | `2-reply 报价` |
| like | 索引服务 | 索引服务 | `3-like-dislike 报价` |
| dislike | 索引服务 | 索引服务 | `3-like-dislike 报价` |

post、like、dislike 的收款方都是索引服务，即签名者自己，报价内不含收款公钥；客户端从
索引服务的公开信息取。只有 reply 的收款方是第三方，必须在报价内写明。

## 3. ask body

```json
{
  "type": "post.price.ask",
  "post_masterseedhash": "hex-64-char",
  "reply_price": 5
}
```

| 字段 | 含义 | 约束 |
| --- | --- | --- |
| `type` | 报价分量 + 方向 | 固定 `post.price.ask` |
| `post_masterseedhash` | 待发布内容的 masterseed hash | 32 字节 hex，小写 |
| `reply_price` | 发帖者登记的每次回复价 | sat，uint64；`0` = 免费回复 |

## 4. 报价 CBOR

索引服务签发前校验 `post_masterseedhash` 是本索引服务可索引的内容，然后对下列 CBOR
字节签名，域字符串 `BSV8:QUOTE:1.0`：

```text
{ version: 1, type: "post.price.answer", ask_message_id, price, last_block_height }
```

| 字段 | 来源 |
| --- | --- |
| `version` | 固定 1，协议版本 |
| `type` | answer 的 `type`，逐字复制 |
| `ask_message_id` | ask 的 CP message_id |
| `price` | 索引服务出 |
| `last_block_height` | 索引服务出 |

编码为 canonical CBOR（CTAP2）：定长小端整数、公钥和 32 字节哈希用小写 hex 字符串、
map key 长度优先字节序升序、禁止 indefinite length。

## 5. answer body

```json
{
  "type": "post.price.answer",
  "ask_message_id": "hex-64-char",
  "price": 5,
  "last_block_height": 900000,
  "sign": "hex-der"
}
```

answer 不重述 ask 的 `post_masterseedhash` 和 `reply_price`，一律按 `ask_message_id`
关联取回，保证单真值。收件人按第 4 节字段来源表重建 CBOR 字节。`type` 的合法值只有
`post.price.ask` 和 `post.price.answer`。

`ask_message_id` 与 `post_masterseedhash` 同为 32 字节小写 hex，与 `2-reply 报价` 的
`to_post` 同格式；它是 ask 的 CP `message_id` 字节的 hex 编码，壳内表示为 base64url，
两者一一对应。

`sign` 是索引服务对第 4 节 CBOR 字节的 strict DER、low-S 签名，小写 hex。它与壳内
`bsv8.private-message.v1` 的 CP message 签名是两个不同签名，后者仍为 base64url。

## 6. 链上体现

CBOR 字节不上链，但其字段都能在链上交易或链下 ask 中找到：

| CBOR 字段 | 来源 |
| --- | --- |
| `type` | 交易 op_return 的内容类型：post |
| `price` | 交易中指向索引服务收款公钥的输出金额，该公钥由索引服务公布 |
| `last_block_height` | 交易确认高度不晚于它 |
| `ask_message_id` | 仅链下 ask |

持有 ask 的一方可以用自己的 ask 加上交易内容重建同一份 CBOR 字节并验签。没有 ask 的
第三方无法重建，因此链上不提供独立审计。

## 7. 校验

1. answer 的 inbox 接收者等于 ask 的信封发送者；
2. `ask_message_id` 能取到已解密验签的 ask，其 `type` 与本 answer 的 `type` 只差结尾的
   `ask` / `answer`；
3. 按第 4 节重建 CBOR，`sign` 用 answer 信封 `from_public_key` 验证通过；
4. `current_block_height <= last_block_height`，否则重新 ask；
5. 付款目标是索引服务自己，付给其他公钥等于未付费。

CP 消息有效期最多 10 分钟。
