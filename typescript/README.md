# `bsv8-channel-protocol`

Channel Protocol V1 的 TypeScript SDK，项目包版本为 `0.2.0`。

目标边界：

- libp2p 公钥是 SSP 调用者和付款身份，不进入本包；
- CP 消息自己携带作者公钥、message_id、时间和签名；
- SSP 身份 A 可以提交 CP 作者 B 的报文；
- 本包不依赖 SSP package。

公开子路径：

| 导入路径 | 职责 |
|---|---|
| `bsv8-channel-protocol/hash-request` | 自包含签名 Hash 消息 |
| `bsv8-channel-protocol/inbox` | 带唯一发送者公钥的信封、私密签名消息和加解密 |
| `bsv8-channel-protocol/webrtc-signal` | WebRTC SDP/ICE body |
| `bsv8-channel-protocol/app-message` | Deliver/ACK body |
| `bsv8-channel-protocol/ping` | Ping/Pong body |

Inbox 信封包含 `envelope_version/from_public_key/kdf_salt/nonce/ciphertext`；解密后的
PrivateMessage 包含 `protocol/message_id/issued_at_ms/expires_at_ms/body/signature`。
发送者公钥只在完整信封出现一次。

> 当前工作区仍含“CP 公共头上移 SSP”的早期实验实现。按约定不回退；后续施工应按总设计
> 恢复上述 CP 自包含边界。本说明描述目标 API。

```sh
npm ci
npm test
npm pack --dry-run
```
