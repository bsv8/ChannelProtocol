# 三方频道协议 Go / TypeScript 双语 SDK 施工单

> 状态：已归档（2026-09-02），保留为初版实现记录。CP 独立公共头、公钥、message_id、
> 时间和签名的边界继续成立；身份绑定、Ping/Pong、SDK 表面消融及 SSP 转发规则以
> [SSP + CP 协议族消融施工单](../20260902/004-SSP-CP协议族消融施工单.md) 为准。
> 当前工作区曾移除部分 CP 公共字段，该实验方向已撤销，但现有代码按约定不在设计阶段回退。
>
> 协议真值：
>
> - [V1 总览](../../docs/v1/README.md)
> - [Hash 请求频道](../../docs/v1/01-Hash请求频道.md)
> - [私密收件箱](../../docs/v1/02-私密收件箱.md)
> - [WebRTC SDP 子协议](../../docs/v1/03-WebRTC-SDP子协议.md)
> - [应用消息子协议](../../docs/v1/04-应用消息子协议.md)
>
> 本施工单只实现 ChannelProtocol 项目，不修改 SSP Wire、SSP Core、订阅状态或网络传输。

## 0. 当前基线和接续规则

已经存在并必须保留、调整后继续使用的内容：

- 独立 Go module：`go.mod`；
- 独立 npm package：`typescript/package.json`；
- 四份协议与模块的机器可读映射：`protocols.json`；
- Go 根注册表、四个协议 package 目录；
- TypeScript 根注册表、四个子路径 export 目录；
- `testdata/v1/` 共享向量目录；
- 注册表的 Go 和 TypeScript 基础测试。

施工开始时的已知基线：

```text
go test ./...                      # 已通过，仅覆盖注册表骨架
typescript/node_modules            # 尚不存在，TypeScript 测试尚未安装依赖执行
```

接续规则：

1. 不删除已有实现后重新生成项目；
2. 不改变已经确定的 Go module、npm package 和四个公开子路径名称；
3. 可以重构现有 `registry.go` 和 TypeScript `registry.ts`，但注册结果必须保持一致；
4. 已有 README 指向本施工单，施工完成后把“当前骨架”状态改为实际完成状态；
5. 发现当前代码和正式 V1 文档冲突时，以正式文档为准，同时补测试防止回退；
6. 发现正式文档存在无法唯一实现的歧义时先停止该项，修改协议文档并确认，不能让 Go 和
   TypeScript 各自猜测。

## 1. 施工目标

提供 Go 与 TypeScript 两套同义 SDK，统一完成：

1. 严格 JSON 解析，拒绝重复字段、未知字段和错误联合类型；
2. 字段格式、时间、频道、公钥、消息编号和子协议结构审查；
3. RFC 8785 JCS 规范化；
4. secp256k1 ECDSA 的统一签名和验签；
5. 长期 secp256k1 密钥 ECDH、HKDF-SHA256、AES-256-GCM 加解密；
6. 私密消息的强类型子协议分派；
7. 去重键、内容冲突、ACK 关联和 WebRTC 会话关联辅助校验；
8. 使用同一套 fixture 证明 Go 与 TypeScript 的规范字节、摘要、签名、密文、错误分类和
   类型分派完全一致。

最终使用者不再自行拼接签名对象、选择规范化算法、解释加密字段或重复实现验证顺序。

## 2. 硬性边界

### 2.1 必须做

- 四份 V1 文档与四个公开模块一一对应；
- 所有构造器输出规范 JCS JSON UTF-8；
- 所有解析器接受合法但非规范字段顺序的 JSON，再按 JCS 进行签名验证；
- 解码前先检查总字节上限，解码时限制嵌套深度和节点数量；
- 严格拒绝 JSON 重复字段，不能依赖 Go `encoding/json` 或 JavaScript `JSON.parse` 的覆盖行为；
- 所有 object 除文档明确允许的字段外都拒绝未知字段；
- 所有 ID、公钥、Hash、base64url、时间和联合类型在进入业务层前转换为强类型；
- 当前时间由调用方注入，测试不能依赖系统时钟；
- 随机源可注入，生产默认值必须来自密码学安全随机源；
- Go sentinel error 与 TypeScript error code 一一对应；
- 所有公开字段、类型、函数、错误码都提供中文说明；
- 输入和输出的 `[]byte` / `Uint8Array` 执行防御性复制；
- 加解密、签名和验签使用共享内部实现，协议 package 不得各写一套密码学逻辑。

### 2.2 不能做

- 不得 import 主 SSP Go module 或主 SSP TypeScript package；
- 不得解析、构造或修改 SSP Wire；
- 不得实现 Publish、Subscribe、Dispatcher、Backend、计费或在线连接表；
- 不得实现 libp2p Host/Transport、WebRTC 连接、ICE Server、HTTP、WebSocket 或文件传输；
- 不得把 `remote_public_key`、连接对象或 SSP 类型写进三方消息；
- 不得加入一次性 ECDH 公钥、Ratchet、预密钥或新的安全级别；
- 不得在私密明文和子协议 body 中重复加入发送者、接收者或第二个签名；
- 不得给公开 Hash 消息增加 `protocol`、`resource.kind`、`priority` 或 `multiaddr:` 包装；
- 不得把 AES-GCM tag 称为第二个业务签名；
- 不得内置历史库、离线队列、自动重试、永久去重数据库或业务状态机；
- 不得因某个密码学库 API 不方便而改变线上格式。

“与 SSP 无关”表示本 SDK 没有 SSP 代码依赖。调用方仍可把外层认证得到的 33 字节公钥作为
普通 `authenticatedPublicKey` 参数传入身份一致性校验；SDK 不关心该公钥来自 SSP、其他
传输层还是测试代码。

## 3. 目录和模块定稿

```text
ChannelProtocol/
  README.md
  protocols.json
  go.mod
  go.sum
  registry.go

  internal/                    # Go 非公开共享实现
    strictjson/                # token 级严格 JSON、重复字段和资源上限
    canonicaljson/             # RFC 8785 JCS
    encoding/                  # hex、base64url、ID、时间的严格编码
    secp256k1/                 # 公钥、ECDSA、ECDH 的唯一实现
    cryptobox/                 # HKDF、AES-GCM、AAD

  hashrequest/                 # 对应 01-Hash请求频道.md
  inbox/                       # 对应 02-私密收件箱.md
  webrtcsignal/                # 对应 03-WebRTC-SDP子协议.md
  appmessage/                  # 对应 04-应用消息子协议.md

  testdata/v1/                 # Go/TypeScript 共用、人工审阅并冻结的 JSON fixture
  integration/                # 跨语言 fixture 驱动器，不含网络
  scripts/test-integration.sh

  typescript/
    package.json
    package-lock.json
    tsconfig.json
    src/
      internal/               # 与 Go internal 同义，不从 npm exports 暴露
      hash-request/
      inbox/
      webrtc-signal/
      app-message/
      registry.ts
      index.ts
    test/
```

公开发布单元保持：

```text
Go module: github.com/bsv8/ChannelProtocol
npm package: bsv8-channel-protocol
```

四个协议模块是公开业务 API。`internal/` 只是统一实现层，不是第五种线上协议，也不能由
外部调用者直接依赖。

## 4. C01：公共原语、严格 JSON 和错误分类

### 4.1 强类型原语

Go 与 TypeScript 定义同义的不可变值：

| 类型 | 中文含义 | 线上格式 |
|---|---|---|
| `PublicKey` | 33 字节压缩 secp256k1 公钥 | 66 位小写 hex |
| `PrivateKey` | 32 字节 secp256k1 私钥 | 只作为 API 输入，不 JSON 序列化 |
| `MessageID` | 消息编号 | 32 字节无填充 base64url，固定 43 字符 |
| `SessionID` | WebRTC 会话编号 | 32 字节无填充 base64url，固定 43 字符 |
| `SHA256Hash` | 文件字节 Hash | 32 字节、64 位小写 hex |
| `Signature` | 唯一业务签名 | strict DER、low-S、无填充 base64url |
| `UnixMillis` | Unix 毫秒时间 | JSON 安全整数 |

固定规则：

- base64url 只允许 RFC 4648 URL-safe 字母表，不允许 `=` padding、空白和非规范重编码；
- hex 只允许小写，不接受 `0x`、大写、奇数长度或无效曲线点；
- 时间必须是 `0..Number.MAX_SAFE_INTEGER` 范围内的整数；
- TypeScript 线上时间使用 `number`，进入类型前先执行 safe-integer 检查；
- Go 不向外暴露可变底层 byte slice；TypeScript 不使用 `Buffer` 作为公开类型。

### 4.2 严格 JSON

实现单一严格解析入口，所有四个模块必须复用。至少满足：

- 输入必须是一份完整 UTF-8 JSON，前后 JSON whitespace 可以存在；
- object 中重复 key 必须在绑定结构体前报错；
- 拒绝 `NaN`、`Infinity`、无法表示为有限 IEEE 754 double 的数字和非法 surrogate；普通
  数字按 RFC 8785/ECMAScript 规则规范化，时间字段另外执行安全整数检查；
- 严格区分缺字段、字段为 `null` 和字段类型错误；
- 联合类型先读 discriminator，再只允许该分支字段；
- 解析失败不能返回部分可用业务对象；
- 最大输入为 `1_048_000` UTF-8 字节、最大嵌套深度为 64、最大 JSON 节点数为 100_000；
- 构造后的加密信封也必须小于等于最大输入，超限时在输出前失败。

这三个资源上限作为 `channels` Go package 自身常量在两种语言公开，并同步补充到 `README.md`。
它们不从 SSP package import。

### 4.3 JCS

- JCS 必须完整符合 RFC 8785，不能用“递归排序 key + 普通 JSON stringify”替代；
- 特别覆盖 Unicode、转义、负零、指数、小数边界和 UTF-16 key 排序；
- 构造器输出 JCS bytes；
- 签名、HKDF `info`、AAD 和私密明文全部调用同一个 JCS 实现；
- Go 与 TypeScript 对每个 JCS fixture 必须逐字节相等。

### 4.4 稳定错误分类

至少冻结以下跨语言错误码：

```text
INVALID_JSON             JSON、UTF-8、重复字段或资源限制不合法
UNKNOWN_FIELD            出现当前结构未定义字段
INVALID_CHANNEL          频道名称或 inbox 目标公钥不合法
INVALID_PUBLIC_KEY       公钥编码、长度或曲线点不合法
INVALID_PRIVATE_KEY      私钥范围不合法
IDENTITY_MISMATCH        外层已认证公钥与 from_public_key 不同
INVALID_MESSAGE_ID       message_id 或 session_id 不合法
INVALID_TIME             时间类型、顺序、有效期或时钟偏移不合法
MESSAGE_EXPIRED          当前时间已经达到或超过 expires_at_ms
INVALID_BODY             当前协议 body 结构或字段值不合法
UNSUPPORTED_PROTOCOL     私密消息 protocol 不是 V1 已注册子协议
INVALID_SIGNATURE        签名编码、low-S 或验签结果不合法
INVALID_ENVELOPE         信封版本、salt、nonce 或 ciphertext 格式不合法
OPEN_FAILED              ECDH、HKDF、AES-GCM、明文解析或私密验签失败
MESSAGE_ID_CONFLICT      同一去重键对应不同已签名内容
INVALID_RELATION         ACK 或 WebRTC 会话关联不成立
MESSAGE_TOO_LARGE        输入或构造结果超过固定字节上限
```

Go 使用可 `errors.Is` 的稳定错误分类；TypeScript 使用
`ChannelProtocolError { code, cause? }`。错误文本可以提供中文上下文，但调用方只能依赖
code。私密 `Open` 对外统一返回 `OPEN_FAILED`，不能暴露“公钥存在、tag 错误、明文格式错误、
签名错误”中的具体阶段，原始密文和明文不得进入错误文本。

## 5. C02：统一签名和身份校验

内部签名模块只暴露给协议 package，严格实现 V1 总览中的两种签名上下文：

```text
bsv8.public-message.v1
bsv8.private-message.v1
```

签名步骤固定：

1. 按正式文档构造逻辑签名对象，不签 JSON 输入的原始字段顺序；
2. RFC 8785 JCS → UTF-8；
3. SHA-256 一次；
4. secp256k1 ECDSA，nonce 使用 RFC 6979；
5. 将 `s` 规范化为 low-S；
6. strict DER；
7. 无填充 base64url。

验签必须拒绝：

- high-S；
- 非 strict DER、尾随字节、负整数、多余前导零；
- 无效公钥或无效 `r/s` 范围；
- 签名作用域、channel、发送者或任意已签名字段被替换。

统一身份辅助函数接收两个 33 字节公钥并做 exact bytes 比较：

```text
authenticated_public_key == from_public_key
```

SDK 不获取连接身份。调用方必须显式传入已经认证的公钥；不传时只能完成结构和签名验证，
不能把结果标记为“已通过发布入口身份检查”。公开结果类型要区分：

```text
VerifiedMessage          已完成结构、时间和签名验证
AdmissionReviewedMessage 在 VerifiedMessage 基础上完成外层身份一致性检查
```

不得使用一个容易误认为已经完成全部检查的布尔值代替这两个状态。

## 6. C03：Hash 请求公开频道模块

对应：`hashrequest` / `./hash-request`。

### 6.1 类型

```text
HashRequestMessage
├── from_public_key
├── message_id
├── issued_at_ms
├── expires_at_ms
├── body
│   ├── hash
│   └── locators[]
└── signature

Locator
├── MultiaddrLocator { kind: "multiaddr", address }
└── WebRTCSDPLocator { kind: "webrtc-sdp" }
```

### 6.2 API 语义

两种语言提供同义能力，命名遵循各自语言惯例：

- `Sign`：从无签名强类型消息和长期私钥构造唯一签名；
- `Marshal`：输出规范 JCS JSON；
- `ParseAndVerify`：严格解析、检查 channel、时间和唯一签名；
- `ReviewAdmission`：再检查调用方传入的认证公钥等于 `from_public_key`；
- `DedupKey`：返回 `(channel, from_public_key, message_id)`；
- `SignedDigest`：返回已签名逻辑消息的稳定 SHA-256，用于识别编号冲突。

### 6.3 校验

- channel 必须精确等于 `bsv8.hash.request.v1`；
- 不允许 `protocol`、`resource`、`resource.kind` 或其他未知字段；
- `issued_at_ms < expires_at_ms`；
- `expires_at_ms - issued_at_ms <= 10 分钟`；
- `now_ms >= expires_at_ms` 时返回 `MESSAGE_EXPIRED`；
- `locators` 至少一个元素并保留数组优先顺序；
- `multiaddr.address` 必须能被标准 multiaddr 语法解析，不发起连接；
- `webrtc-sdp` locator 不能携带 `address`、`session_id` 或其他字段；
- 相同去重键、相同摘要是重复副本；相同去重键、不同摘要是
  `MESSAGE_ID_CONFLICT`。

本模块到收到合法广播、选择 locator 为止，不实现 Hash 文件查询和文件传输。

## 7. C04：私密收件箱公共壳和长期密钥加密

对应：`inbox` / `./inbox`。

### 7.1 加密信封和私密消息类型

```text
EncryptedEnvelopeV1
├── envelope_version
├── from_public_key
├── kdf_salt
├── nonce
└── ciphertext

PrivateMessage<Protocol, Body>
├── protocol
├── message_id
├── issued_at_ms
├── expires_at_ms
├── body
└── signature
```

代码中只能在 `inbox` 公共类型定义一次私密消息 `signature`。WebRTC 和应用消息模块只定义
body，不能再次展开公共头。

### 7.2 分层 API

必须同时提供以下层次，支持首次发送和重新加密重试：

1. `ParseEnvelope`：不解密，严格解析信封和 inbox channel；
2. `ReviewEnvelopeAdmission`：检查认证公钥等于信封 `from_public_key`；
3. `SignPrivateMessage`：生成一次唯一私密业务签名，返回不可变
   `SignedPrivateMessage`；
4. `SealSigned`：把已经签名的同一私密消息用新的 salt/nonce 重新加密；
5. `SignAndSeal`：首次发送的便利组合；
6. `Open`：解密、严格解析、时间检查和唯一验签，返回已验证私密消息；
7. `Dispatch`：按 `protocol` 返回强类型 WebRTC 或应用消息联合类型。

`SignedPrivateMessage` 必须绑定原始 channel 和发送者，调用方不能把 A→B 的已签名消息改为
A→C 后继续 Seal。重试时保持私密消息 JCS 明文完全相同，只重新生成 `kdf_salt`、`nonce`
和 ciphertext。

### 7.3 长期密钥 ECDH

严格按正式文档实现：

```text
shared_secret = secp256k1 ECDH X 坐标的 32 字节大端编码
message_key   = HKDF-SHA256(shared_secret, 32-byte kdf_salt, JCS(info), 32 bytes)
ciphertext    = AES-256-GCM(message_key, 12-byte nonce, JCS(plaintext), JCS(AAD))
线上字段       = ciphertext || 16-byte GCM tag
```

- 发送者公钥由发送者长期私钥推导，不能由调用方传入另一个值；
- 接收者公钥取实际 inbox channel 后缀；
- `Open` 必须先确认接收者长期私钥推导出的公钥等于 channel 后缀；
- 每次 `SealSigned` 都生成新的 32 字节 salt 和 12 字节 nonce；
- 测试通过注入固定随机源得到可复现密文，生产 API 默认使用安全随机源；
- HKDF `info`、AAD 的字段和 JCS 字节必须逐字节等于文档；
- 信封不允许 `to_public_key`、一次性公钥或外层 signature；
- 派生密钥和共享秘密用后尽力清零；TypeScript 文档明确 JavaScript 运行时不能保证完整内存擦除。

### 7.4 时间、去重和结果

- `issued_at_ms < expires_at_ms`；
- `issued_at_ms <= now_ms + 60 秒`；
- `now_ms < expires_at_ms`；
- 私密去重键是 `(protocol, from_public_key, message_id)`；
- 摘要相同视为重复副本，摘要不同返回 `MESSAGE_ID_CONFLICT`；
- SDK 只计算去重键和摘要，不保存永久去重状态；
- `Open` 返回的发送者只能取信封 `from_public_key`，接收者只能取 channel 后缀，不能从
  body 推导身份。

## 8. C05：WebRTC SDP 强类型子协议

对应：`webrtcsignal` / `./webrtc-signal`。

只实现 `WebRTCSignalV1Body`：

```text
request_message_id
session_id
signal
├── offer { sdp }
├── answer { sdp }
├── ice-candidate { candidate { candidate, sdp_mid, sdp_m_line_index } }
└── end-of-candidates {}
```

校验要求：

- 私密 `protocol` 必须精确等于 `bsv8.webrtc.signal.v1`；
- 私密消息有效期不能超过 2 分钟；
- 四种 `signal.type` 严格互斥，拒绝其他分支字段和未知字段；
- `sdp_mid`、`sdp_m_line_index` 只在文档允许处接受 `null`；
- body 不能包含公钥、公共消息头、应用 `content`、ACK 字段或 signature；
- 提供 `SessionKey(request_message_id, offerer_public_key, session_id)` 强类型辅助值；
- offer 的 offerer 是该私密信封发送者；
- answer/ICE 校验必须由调用方传入已保存的 offer 会话上下文，不能只凭 `session_id`；
- 提供纯函数检查 offer、answer、ICE 与会话上下文的关系，不创建 RTCPeerConnection；
- 另提供 `ReviewOfferForHashRequest`，统一检查已验证 Hash 请求、offer 的 request ID、有效期、
  `webrtc-sdp` locator 和 offer 接收者，并返回规范 `SessionKey`；
- SDK 不保存 SDP/ICE 队列，不实现 ICE 提前到达缓存。

## 9. C06：应用消息和 ACK 强类型子协议

对应：`appmessage` / `./app-message`。

只实现以下 body 联合类型：

```text
DeliverBody { type: "deliver", content: 任意 JCS 兼容 JSON 值 }
AckBody     { type: "ack", acknowledged_message_id }
```

校验和辅助 API：

- 私密 `protocol` 必须精确等于 `bsv8.message.v1`；
- Deliver 和 ACK 的私密消息有效期不能超过 24 小时；
- Deliver 只允许 `type`、`content`；ACK 只允许 `type`、`acknowledged_message_id`；
- body 不重复公钥、时间、message_id 或 signature；
- `content` 即使含有名为 `sdp` 的应用数据，也不能被分派到 WebRTC 协议；
- `ValidateAckRelation` 必须检查 ACK 发送者、接收者和
  `acknowledged_message_id` 与原 Deliver 的关系；
- ACK 只证明协议文档规定的可靠接收，不实现已读、业务成功或 ACK-of-ACK；
- SDK 不自动发送 ACK。应用可靠持久化 Deliver 后，自行调用 ACK 构造 API；
- 重复 Deliver 辅助结果必须允许应用“不重复执行业务，但重新生成一条新 ACK”。

## 10. C07：统一强类型分派入口

Go 根 package 和 TypeScript 根 export 提供同义高层入口：

```text
公开频道：channel + content_json
  → HashRequest 或 INVALID_CHANNEL

私密频道：channel + envelope_json + recipient_private_key + now_ms
  → 解密并验签
  → protocol
     ├── bsv8.webrtc.signal.v1 → VerifiedWebRTCSignal
     ├── bsv8.message.v1       → VerifiedAppMessage
     └── 其他                  → UNSUPPORTED_PROTOCOL
```

TypeScript 返回 discriminated union。Go 返回一个 `DecodedInboxMessage`，其中
`Protocol` 与强类型 body 一一对应，并通过构造器保证不可能同时存在两个 body。禁止把
私密 body 直接暴露成 `map[string]any` / `Record<string, unknown>` 让业务再次猜测协议。

低层 `inbox.Open` 可以保留只读 raw body，用于完成分层实现，但 raw API 必须明确标为低层，
高层调用示例一律使用强类型分派入口。

## 11. C08：共享 fixture 和跨语言一致性

`testdata/v1/` 是两种实现共同读取的唯一固定向量，不复制到 TypeScript 目录。

至少提交：

```text
jcs-valid.json
jcs-invalid.json
primitives-valid.json
primitives-invalid.json
signature-public.json
signature-private.json
hash-request-valid.json
hash-request-invalid.json
inbox-crypto-valid.json
inbox-crypto-invalid.json
webrtc-signal-valid.json
webrtc-signal-invalid.json
app-message-valid.json
app-message-invalid.json
dedup-and-relations.json
```

每个密码学有效向量至少包含：

- `test_only_private_key` 和对应压缩公钥；
- 逻辑签名对象；
- JCS UTF-8 的 hex；
- SHA-256 digest；
- RFC 6979 strict-DER low-S signature；
- 私密向量另含双方长期公钥、ECDH X、salt、HKDF info、message key、nonce、AAD、明文、
  ciphertext、tag 和最终信封；
- 中文说明该向量验证的规则。

无效向量必须固定预期错误码，并覆盖：

- 重复字段、未知字段、错误 JSON 类型、非法 Unicode、过深和超限；
- 非规范 hex/base64url、无效公钥、错误 ID、错误时间；
- high-S、坏 DER、错误 scope、错误 channel、错误发送者和内容篡改；
- 错误信封版本、salt/nonce 长度、tag 篡改、channel 接收者不匹配；
- 私密明文重复公钥/签名、未知 protocol、错误强类型 body；
- WebRTC 联合分支混用、ACK 关系错误；
- 重复副本和同编号内容冲突。

fixture 生成规则：

1. 可以提供生成工具，但 fixture 合入后视为人工审阅的冻结真值；
2. 正式测试不能在运行时用被测实现重新生成 expected 值；
3. Go 和 TypeScript 各自独立读取 expected 值并比较；
4. 测试私钥只能出现在 `testdata`，字段名必须带 `test_only_`；
5. 测试日志不能输出真实调用者的私钥、明文或完整密文。

跨语言脚本至少证明：

1. Go 构造和签名 → TypeScript 解析验签；
2. TypeScript 构造和签名 → Go 解析验签；
3. 双方对同一逻辑对象产生相同 JCS、digest 和确定性签名；
4. 双方用固定 salt/nonce 加密得到相同信封；
5. Go 加密 → TypeScript 解密，TypeScript 加密 → Go 解密；
6. 双方对所有 invalid fixture 返回相同错误码；
7. 双方得到相同的去重键、摘要、ACK 关系和 WebRTC SessionKey。

## 12. C09：依赖、安全和质量门禁

### 12.1 依赖选择

- 密码学依赖必须是维护中的专用实现，支持 secp256k1、strict DER、low-S 和 ECDH X；
- 若依赖的 ECDH 输出不是文档规定的 32 字节 X 坐标，必须显式转换并由 fixture 证明；
- JCS 依赖必须通过 RFC 8785 边界向量，不能只凭包名认定合规；
- Go 依赖写入 `go.sum`；npm 必须提交 `package-lock.json` 并使用 `npm ci`；
- 正式依赖不能引入 SSP、libp2p Host/Transport、WebRTC、HTTP server、WebSocket 或数据库；
- 允许使用只负责字符串编解码的轻量 multiaddr codec/parser；它不得创建 Peer、Host、
  Transport、socket 或网络连接；
- TypeScript 运行时代码不得依赖 Node-only `Buffer` 公开语义，至少支持 Node ESM；V1 当前只承诺
  Node.js 20+，未声明浏览器运行时支持。

### 12.2 密钥和错误安全

- 私钥不实现 JSON marshal/stringify，不提供会自动打印私钥的 `String()`；
- 不缓存长期私钥、ECDH shared secret 或 message key；
- Go 在可控 byte slice 上尽力清零中间秘密；
- 解密失败不区分 tag、明文、签名等远程可观察原因；
- 所有比较使用规范解码后的 exact bytes；秘密相关比较使用库提供的安全实现；
- 示例和测试不得建议 nonce 固定或 salt 复用；
- API 文档明确 V1 没有前向安全。

### 12.3 测试质量

- Go 为严格 JSON、Hash 和 Envelope parser 增加 fuzz target，种子来自共享 fixture；
- TypeScript 对共享 invalid fixture 全量执行无崩溃测试；
- parser 对任何输入只能返回强类型成功值或稳定错误，不能 panic；
- `go test -race` 不允许共享可变全局状态；
- 测试不访问网络、不打开端口、不读取生产密钥和系统账户目录。

## 13. C10：文档、示例和发布

### 文档

- 更新 `README.md`，说明四个模块、高低层 API、错误码和安全边界；
- Go doc 和 `.d.ts` 的所有英文导出名旁边有中文含义；
- Go 与 TypeScript 各提供三个纯本地示例：
  1. 构造、签名和审查 Hash 请求；
  2. 签名、长期密钥加密、解密并强类型分派 WebRTC；
  3. Deliver、可靠保存后生成 ACK、验证 ACK 关系和重新加密重试；
- 示例只调用 `channels` SDK，不构造 SSP Wire，不启动任何连接；
- `protocols.json`、README、Go 注册表和 TypeScript 注册表由测试证明一致；
- 正式 API 和协议字段变化必须同步修改对应 `docs/v1/` 文档。

### 发布

- Go 和 npm 从相同语义版本开始，首个完整实现建议为 `0.1.0`；
- npm exports 保持根入口及四个现有子路径；
- npm 包不包含测试私钥、integration 临时文件、源码之外的生成日志；
- 未通过全部跨语言 fixture 前不能 tag 或 publish；
- V1 线上格式变化必须先修改正式协议并选择新频道、`protocol` 或
  `envelope_version`，不能只升级 SDK 后静默改变。

## 14. 实施顺序和提交边界

```text
现有脚手架
  → C01 公共原语、严格 JSON、JCS、错误码
      → C02 统一签名和身份校验
          → C03 Hash 请求公开频道
          → C04 私密收件箱和长期密钥加密
              → C05 WebRTC body
              → C06 应用消息和 ACK body
                  → C07 强类型分派
                      → C08 共享 fixture 与跨语言集成
                          → C09 安全和质量门禁
                              → C10 文档、示例和发布检查
```

建议每个 Cxx 一个可审阅提交。每个提交必须：

- 在已有项目代码上增量修改；
- 同时更新受影响的 Go、TypeScript、共享 fixture 和中文文档；
- 保持此前阶段测试通过；
- 不混入主 SSP SDK 改造；
- 不提交 `node_modules/`、`dist/`、coverage、临时密钥或调试日志。

## 15. 最终验收命令

仓库根目录快捷入口：

```text
./scripts/test-channels.sh
```

```text
go test ./...
go test -race ./...
go vet ./...

cd typescript
npm ci
npm test
npm run build
npm pack --dry-run

cd ..
./scripts/test-integration.sh
```

另做依赖和边界检查：

```text
Go 依赖树不包含主 SSP module、libp2p Host/Transport、HTTP server 或 WebRTC 实现
npm dependency tree 不包含主 SSP package、libp2p Host/Transport、WebSocket 或 HTTP server
普通测试不打开网络端口
git status 中没有 dist、node_modules、临时 fixture 或测试日志
```

## 16. 完成标准

以下条件必须全部满足：

- 四份协议文档与四个公开模块一一对应；
- Go 和 TypeScript 的公开类型、字段含义、错误码和校验顺序同义；
- 公开消息壳和加密消息壳保持分离；
- SSP/外层认证公钥与报文发送者公钥的比较只有一个公共实现；
- 每条业务消息只存在一个 ECDSA 签名；
- 私密收件箱只使用双方长期私钥 ECDH，信封中没有一次性公钥；
- JCS、digest、签名、ECDH、HKDF、AAD、密文和 tag 全部有跨语言固定向量；
- Hash、WebRTC、Deliver、ACK 的合法和非法结构都有共享验收；
- 重复消息与同编号内容冲突可以被调用方可靠区分；
- SDK 中不存在 SSP Wire、网络连接、文件传输、离线队列或永久业务状态；
- 所有验收命令通过，README 与实际导出 API 一致。
