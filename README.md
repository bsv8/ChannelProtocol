# BSV8 三方频道协议 SDK

本仓库是独立于 SSP Core 的三方频道协议项目，负责：

- 严格解析协议 JSON；
- 校验字段、时间、公钥和子协议结构；
- RFC 8785 JCS 规范化；
- secp256k1 ECDSA 统一签名与验签；
- 私密收件箱的统一加密与解密；
- 将收件箱消息分派为强类型子协议；
- 使用共享向量保证 Go 与 TypeScript 字节级一致。

本项目不导入 SSP Go module，也不导入主 TypeScript package。调用方只需要把 SSP
`content_json` 原始字节和实际 channel 名称交给本 SDK。

## 协议与模块映射

| 协议文档 | 线上标识 | Go package | TypeScript export |
|---|---|---|---|
| `01-Hash请求频道.md` | `bsv8.hash.request.v1` | `hashrequest` | `./hash-request` |
| `02-私密收件箱.md` | `bsv8.inbox.<public_key_hex>` | `inbox` | `./inbox` |
| `03-WebRTC-SDP子协议.md` | `bsv8.webrtc.signal.v1` | `webrtcsignal` | `./webrtc-signal` |
| `04-应用消息子协议.md` | `bsv8.message.v1` | `appmessage` | `./app-message` |

机器可读映射见 [protocols.json](./protocols.json)。协议真值仍然是
[docs/v1](./docs/v1/README.md)。

## 独立发布单元

```text
Go module: github.com/bsv8/ChannelProtocol
npm package: bsv8-channel-protocol
```

仓库根目录是独立 Go module，`typescript/` 是独立的无 scope npm package；两种实现
共享协议文档、fixture 和跨语言验收。

发布后分别安装：

```text
go get github.com/bsv8/ChannelProtocol@v0.1.0
npm install bsv8-channel-protocol@0.1.0
```

## 实现状态

V1 Go / TypeScript SDK 已实现并通过仓库级验收：严格 JSON、RFC 8785 JCS、secp256k1 RFC6979 low-S
ECDSA、长期密钥 ECDH/HKDF/AES-256-GCM、WebRTC/应用强类型 body、去重/关联校验和跨语言
fixture 集成。实现范围严格限定在本仓库，不包含 Publish、Subscribe、网络连接、
WebRTC peer、文件传输、离线队列或永久去重存储。

协议真值和施工边界见 [三方频道协议 Go/TypeScript 双语 SDK 施工单](./施工单/20260831/003-三方频道协议Go-TypeScript双语SDK施工单.md)。

## 公共原语和固定限制

| API 类型 | 中文含义 | 线上格式 |
|---|---|---|
| `PublicKey` | 长期身份公钥 | 33 字节压缩 secp256k1，小写 66 位 hex |
| `PrivateKey` | 长期身份私钥 | 32 字节，仅作 API 输入，不进入 JSON |
| `MessageID` | 消息去重编号 | 32 字节无填充 base64url，43 字符 |
| `SessionID` | WebRTC 会话编号 | 32 字节无填充 base64url，43 字符 |
| `SHA256Hash` | 文件内容摘要 | 32 字节小写 64 位 hex |
| `Signature` | 唯一业务签名 | strict DER、low-S、无填充 base64url |

两种语言都公开以下限制常量：`MaxJSONBytes` / `MAX_JSON_BYTES`（1,048,000 字节）、
`MaxJSONDepth` / `MAX_JSON_DEPTH`（64 层）、`MaxJSONNodes` / `MAX_JSON_NODES`（100,000
节点）。所有输入先执行 UTF-8、重复字段、未知字段和资源限制检查；构造输出也执行字节
上限检查。

## API 入口

| 能力 | Go | TypeScript | 说明 |
|---|---|---|---|
| Hash 签名 | `hashrequest.Sign` | `hash-request.sign` | 构造唯一公开签名 |
| Hash 编码 | `hashrequest.Marshal` | `hash-request.marshal` | 输出 JCS UTF-8 |
| Hash 验签 | `hashrequest.ParseAndVerify` | `hash-request.parseAndVerify` | 结构、时间、签名验证 |
| 外层身份审查 | `ReviewAdmission` | `reviewAdmission` | 比较认证公钥与 `from_public_key` |
| 信封解析 | `inbox.ParseEnvelope` | `inbox.parseEnvelope` | 不解密检查版本和密文字段 |
| 私密签名 | `inbox.SignPrivateMessage` | `inbox.signPrivateMessage` | 只生成一次业务签名 |
| 重新加密 | `inbox.SealSigned` | `inbox.sealSigned` | 保持明文/签名不变，仅换 salt/nonce |
| 首次发送 | `inbox.SignAndSeal` | `inbox.signAndSeal` | 签名加密便利组合 |
| 解密 | `inbox.Open` | `inbox.open` | 返回低层已验签消息 |
| 强类型分派 | `inbox.Dispatch` | `inbox.dispatch` | WebRTC 或应用联合类型 |
| WebRTC/Hash 关联审查 | `channels.ReviewOfferForHashRequest` | `inbox.reviewOfferForHashRequest` | 校验 request ID、有效期、`webrtc-sdp` locator 和接收者 |
| 根入口 | `channels.DecodeChannel` | `decodeChannel` | 按 channel 选择公开/私密流程 |

TypeScript `sealSigned`、`signAndSeal`、`open` 和根私密入口返回 `Promise`，因为 AES-GCM
使用 Web Crypto。V1 当前只承诺 Node.js 20+ 运行时，不声明浏览器运行时兼容性。

`ParseAndVerify` / `Open` 返回的 Verified 结果是 SDK 内部创建的快照：Go 使用私有字段和
复制访问器，TypeScript 使用递归 clone/deep-freeze 与运行时 brand。`Dispatch` 和跨协议
关联审查拒绝调用方自行拼出的同名对象；读取嵌套 body 后得到的副本也不会回写验签快照。
Go 的 `DecodeChannel` 返回 `DecodedChannel` tagged union，通过 `IsPublic` / `IsInbox` 和
`Public` / `Inbox` 访问分支，不返回 `any`。

## 签名与加密语义

- 公开 Hash 消息只签 `bsv8.public-message.v1` 作用域和逻辑消息对象；不添加 `protocol`
  或 `resource` 包装。
- 私密消息只签 `bsv8.private-message.v1` 作用域和实际 inbox channel；`signature` 只在
  私密消息公共壳定义一次。
- 私密信封使用双方长期 secp256k1 ECDH 的 X 坐标、HKDF-SHA256 和 AES-256-GCM；
  `ciphertext` 字段是密文拼接 16 字节 tag，不包含 `to_public_key` 或一次性公钥。
- `Open` 对 ECDH、HKDF、GCM、明文解析和私密验签失败统一返回 `OPEN_FAILED`；不把阶段
  细节写入错误文本。V1 不提供前向安全。
- `now_ms` / `nowMs` 必须由调用方注入，测试不读取系统时钟；随机源可注入，生产默认使用
  操作系统密码学安全随机源。

## 稳定错误码

Go 使用 `errors.Is(err, channels.ErrInvalidJSON)` 或 `channels.IsErrorCode`；TypeScript
使用 `ChannelProtocolError.code`。错误文本是中文上下文，不是兼容性接口。

```text
INVALID_JSON        UNKNOWN_FIELD       INVALID_CHANNEL      INVALID_PUBLIC_KEY
INVALID_PRIVATE_KEY IDENTITY_MISMATCH   INVALID_MESSAGE_ID   INVALID_TIME
MESSAGE_EXPIRED     INVALID_BODY        UNSUPPORTED_PROTOCOL INVALID_SIGNATURE
INVALID_ENVELOPE    OPEN_FAILED         MESSAGE_ID_CONFLICT INVALID_RELATION
MESSAGE_TOO_LARGE
```

## 本地示例和验证

Go 示例包含 Hash、WebRTC、Deliver/ACK 重试三段流程：
`go run ./examples/go`。TypeScript 示例先构建再运行：
`cd typescript && npm run build && node examples/main.mjs`。

从仓库根目录执行完整检查：

```text
./scripts/test-channels.sh
```

也可以从仓库根目录执行分项检查：

```text
go test ./...
go test -race ./...
go vet ./...
cd typescript && npm ci && npm test && npm pack --dry-run
cd .. && ./scripts/test-integration.sh
```

`scripts/test-integration.sh` 读取 `interop-v1.json` 和 `dedup-and-relations.json`，并遍历全部
共享非法 fixture，验证 Go 构造→TypeScript 验签/解密、TypeScript 构造→Go 验签/解密，以及
JCS、digest、签名、固定密文、去重键、SessionKey、ACK 关系和错误码。
