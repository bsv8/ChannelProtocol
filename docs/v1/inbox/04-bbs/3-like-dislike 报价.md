# 论坛 like / dislike 报价 V1

协议：

```text
bsv8.bbs.quote.v1
```

本协议只定义 PrivateMessage body。message_id、时间和签名由壳提供，身份公钥由 Inbox 信封提供。

## 1. 参与者

| 角色 | 身份来源 | inbox |
| --- | --- | --- |
| 客户端（投票者） | ask 信封 `from_public_key` | `bsv8.inbox.<索引服务公钥>` |
| BBS 索引服务 | answer 信封 `from_public_key` | `bsv8.inbox.<客户端公钥>` |

like 和 dislike 都由索引服务定价并收款，投票者不是收款方，所以报价里没有收款公钥：
收款方就是签名者自己，客户端从索引服务的公开信息取收款公钥。投票者同样不是收款方，
ask 不需要价格字段。被投票的内容一定已经上链，因此目标统一用 `target_txid`，post 和
reply 同一写法。

## 2. type

| 消息 | `type` |
| --- | --- |
| like 询价 | `like.price.ask` |
| like 报价 | `like.price.answer` |
| dislike 询价 | `dislike.price.ask` |
| dislike 报价 | `dislike.price.answer` |

除 `type` 外，四个值共用同一 body 结构。

## 3. ask body

```json
{
  "type": "like.price.ask",
  "target_txid": "hex-txid"
}
```

| 字段 | 含义 | 约束 |
| --- | --- | --- |
| `type` | 报价分量 + 方向 | 见第 2 节 |
| `target_txid` | 被投票内容所在交易的 txid | 32 字节 hex，小写 |

## 4. 报价 CBOR

索引服务签发前校验 `target_txid` 是本索引服务已索引的 post 或 reply，然后对下列 CBOR
字节签名，域字符串 `BSV8:QUOTE:1.0`：

```text
{ version: 1, type: "like.price.answer", ask_message_id, price, last_block_height }
```

| 字段 | 来源 |
| --- | --- |
| `version` | 固定 1，协议版本 |
| `type` | answer 的 `type`，逐字复制 |
| `ask_message_id` | ask 的 CP message_id |
| `price` | 索引服务出 |
| `last_block_height` | 索引服务出 |

CBOR 结构、canonical CBOR 规则与 `1-post 报价` 第 4 节完全相同。

## 5. answer body

```json
{
  "type": "like.price.answer",
  "ask_message_id": "hex-64-char",
  "price": 1,
  "last_block_height": 900000,
  "sign": "hex-der"
}
```

answer 不重述 `target_txid`，一律按 `ask_message_id` 关联取回。字段表示规则同
`1-post 报价` 第 5 节：`ask_message_id` 为 CP `message_id` 字节的 hex 编码，`sign` 为
CBOR 字节的 strict DER、low-S 签名小写 hex。

## 6. 链上体现

CBOR 字节不上链。支付交易必须体现：

- 存在指向索引服务收款公钥的 `price` sat 输出，该公钥由索引服务公布，不在报价内；
- op_return 记录 `target_txid`、投票方向和投票者公钥；
- 确认高度不晚于 `last_block_height`。

持有 ask 的一方可以用自己的 ask 加上交易内容重建同一份 CBOR 字节并验签；没有 ask 的
第三方无法重建。

## 7. 校验

索引服务签发前：

1. `target_txid` 是本索引服务已索引的 post 或 reply。

收件人：

1. answer 的 inbox 接收者等于 ask 的信封发送者；
2. `ask_message_id` 能取到已解密验签的 ask，其 `type` 与本 answer 的 `type` 只差结尾的
   `ask` / `answer`；
3. 按第 4 节重建 CBOR，`sign` 用 answer 信封 `from_public_key` 验证通过；
4. `current_block_height <= last_block_height`，否则重新 ask；
5. 付款目标是索引服务自己，付给其他公钥等于未付费。

CP 消息有效期最多 10 分钟。

## 8. 待定

- 同一 `target_txid` 能否重复投票、能否改票，协议未定义；
- `price` 是否允许 `0`（免费投票）未定义；
- 索引服务收款公钥的公布方式未定义。
