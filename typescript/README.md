# `bsv8-channel-protocol`

BSV8 三方频道 V1 的 TypeScript SDK。协议字段采用 snake_case，并在源码与生成的 `.d.ts`
旁边提供中文注释：例如 `from_public_key` 是发送者长期压缩公钥，`message_id` 是消息去重
编号，`issued_at_ms` / `expires_at_ms` 是 Unix 毫秒，`body` 是对应子协议正文。

公开子路径：

| 导入路径 | 中文职责 |
|---|---|
| `bsv8-channel-protocol/hash-request` | 公开 Hash 请求签名、验签和 locator |
| `bsv8-channel-protocol/inbox` | 私密信封、签名、长期密钥加密和解密 |
| `bsv8-channel-protocol/webrtc-signal` | WebRTC offer、answer、ICE、会话关系 |
| `bsv8-channel-protocol/app-message` | Deliver、ACK、去重和 ACK 关系 |

`sealSigned`、`signAndSeal`、`open` 使用 Web Crypto，因此返回 `Promise`。SDK 的公开类型
使用 `Uint8Array`，不使用 Node-only `Buffer` 语义；生产随机源是 `crypto.getRandomValues`，
测试可传入 `fixedRandom`。V1 当前只承诺 Node.js 20+，尚未声明浏览器运行时支持。
`parseAndVerify`、`open` 的 Verified 结果会递归复制并冻结；`dispatch`、外层 admission 和
WebRTC/Hash 关联审查还会检查 SDK 运行时 brand，不能用普通对象冒充已验证结果。
V1 使用长期密钥 ECDH，不承诺前向安全。

```sh
npm ci
npm test
npm pack --dry-run
```

跨语言固定向量位于上一级 `../testdata/v1/`，不要复制到 npm 包内。完整协议说明见
`../docs/v1/`。
