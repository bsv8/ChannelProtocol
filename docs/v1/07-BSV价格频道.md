# BSV 价格频道 V1

`bsv8.bsv-price.v1` 是面向行情喂价端和网页订阅端的公开价格快照协议。
它运行在 ChannelProtocol 的通用公开消息壳中；广播服务器只按精确频道转发
`content_json`，不解析或改写价格正文。

## 1. 频道

价格发布者公钥为 `02...` 或 `03...` 的压缩 secp256k1 公钥小写 hex 时，频道为：

```text
bsvprice.<from_public_key>
```

例如：

```text
bsvprice.02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

频道后缀公钥必须和公开消息壳的 `from_public_key` 完全相同。网页端应只订阅配置的
可信喂价公钥对应的一个精确频道，不使用 wildcard。

## 2. 完整消息

消息壳使用 [通用公开消息 V1](./06-通用公开消息.md)：

```json
{
  "from_public_key": "02...",
  "message_id": "base64url-32-byte",
  "issued_at_ms": 1789344000000,
  "expires_at_ms": 1789344060000,
  "body": {
    "protocol": "bsv8.bsv-price.v1",
    "snapshot_at_ms": 1789344000000,
    "markets": {
      "gate": {
        "bsvusdt": "45.1200",
        "bsvcny": "321.85"
      },
      "okx": {
        "bsvusdt": "45.0900"
      }
    }
  },
  "signature": "base64url-der"
}
```

公开壳的 `channel` 不进入 JSON，但进入 `bsv8.public-message.v1` 的签名逻辑对象。
价格正文的 `protocol` 仍然必须固定为 `bsv8.bsv-price.v1`，用于业务分派和版本校验。

## 3. 正文字段

| 字段 | 含义 | 约束 |
| --- | --- | --- |
| `protocol` | 价格业务协议标识 | 固定 `bsv8.bsv-price.v1` |
| `snapshot_at_ms` | 行情源生成完整快照的 Unix 毫秒 | 非负 JSON safe integer |
| `markets` | 市场到交易对价格的映射 | 0 至 100 个市场；空对象用于明确清除全部行情 |
| 市场 key | 市场编号 | 小写字母、数字、点、短横线、下划线；最多 64 UTF-8 字节 |
| 交易对 key | 交易对编号 | 与市场 key 相同的字符规则；每个市场至少一个、最多 100 个 |
| 价格 value | 十进制价格字符串 | `^(0|[1-9][0-9]*)(\\.[0-9]+)?$`，最多 128 UTF-8 字节 |

价格必须是字符串，不能使用 JSON 浮点数；这样可以保留小数位并避免跨语言浮点精度差异。
禁止指数形式、负数、千分位、货币符号和前导零（`0.5` 合法，`00.5` 不合法）。

## 4. 快照语义

每条消息都是完整快照，不是增量更新。订阅端收到新消息后整体替换 `markets`；缺少的
市场或交易对不应继续沿用上一条消息的旧值。`markets: {}` 是合法的完整快照，用于发布端
明确表示当前没有任何可用行情，订阅端收到后应清除已展示价格并进入等待/无报价状态。订阅端
应按 `snapshot_at_ms` 忽略更旧或相同的快照，以抵抗网络乱序。

公开消息仍遵守通用壳的 10 分钟最长有效期和 60 秒未来时钟偏差规则。`snapshot_at_ms`
表达行情源生成时间，不能用接收端本地时间代替。

## 5. 身份与转发

- 喂价端使用发布者长期私钥签名完整公开消息。
- 广播服务器原样转发 CP `content_json`，不重签、不 stringify/parse、不修改字段。
- 订阅端先完成公开消息验签，再检查频道后缀公钥和 `from_public_key` 一致。
- SSP 连接公钥、request_id、付款身份不进入价格签名。

## 6. SDK

- Go：`github.com/bsv8/ChannelProtocol/bsvprice`
- TypeScript：`bsv8-channel-protocol/bsv-price`

SDK 提供固定频道构造/解析、正文校验、签名、规范 JSON 序列化和严格解析验签；不负责
行情采集、广播服务器状态、网页展示或价格持久化。
