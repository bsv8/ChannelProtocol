# V1 共享测试向量

目标 V1 fixture 应由 Go 与 TypeScript 共同验证：

- CP 通用公开消息的作者公钥、message_id、时间、body、channel 绑定和签名；
- Inbox 的唯一发送者公钥、ECDH/HKDF/AAD/AES-GCM 和已签名 PrivateMessage；
- WebRTC 的 `request_message_id`；
- ACK 的 `acknowledged_message_id`；
- Pong 的 `ping_message_id`；
- `(channel, CP author, message_id)` 去重和强类型关联；
- 严格 JSON、JCS、大小限制和稳定错误码。

当前目录中的 fixture 是 CP V1 自包含报文的发布向量：通用公开消息保留作者公钥、message_id、
时间和签名，Inbox 信封只保留一次发送者公钥，Ping/Pong 复用同一私密消息公共头。Go 与
TypeScript 会共同验证这些向量；它们不需要构造 SSP Wire。fixture 私钥只能用于测试，日志
不得输出私钥。
