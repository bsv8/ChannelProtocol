# WebRTC SDP 子协议 V1

子协议名称：

```text
bsv8.webrtc.signal.v1
```

本协议只定义私密消息的 `body`。公共 `protocol`、`message_id`、时间和唯一 `signature`
由 [私密收件箱](./02-私密收件箱.md) 统一定义。

对应类型：

```ts
PrivateMessage<"bsv8.webrtc.signal.v1", WebRTCSignalV1Body>
```

## 1. Body 结构

```jsonc
{
  "request_message_id": "hash-request-id", // 所属 Hash 请求编号
  "session_id": "base64url-32-byte-id",    // offerer 创建的会话编号
  "signal": {
    "type": "offer",                       // 信令类型
    "sdp": "v=0..."                        // offer 或 answer 使用
  }
}
```

Body 只包含 WebRTC 会话关联和信令字段，不能包含：

- `from_public_key` 或 `to_public_key`；
- `message_id`、时间或 `signature`；
- 应用消息的 `content`、`acknowledged_message_id`。

Offerer 身份取加密信封的 `from_public_key`，Answerer 身份取 inbox channel 后缀。

## 2. `signal` 结构

| `signal.type` | 必需字段 | 中文规则 |
|---|---|---|
| `offer` | `sdp` | 资源提供者发送 offer，并创建新的 `session_id` |
| `answer` | `sdp` | 请求者返回 answer，沿用 offer 的 `session_id` |
| `ice-candidate` | `candidate` | 双方发送一个 ICE candidate |
| `end-of-candidates` | 无 | 表示发送方当前候选发送结束 |

ICE candidate：

```jsonc
{
  "type": "ice-candidate",
  "candidate": {
    "candidate": "candidate:...", // ICE candidate 字符串
    "sdp_mid": "0",               // media section，可以为 null
    "sdp_m_line_index": 0          // media 行索引，可以为 null
  }
}
```

不同类型不能混用字段。`offer`、`answer` 只能包含 `sdp`；`ice-candidate` 只能包含
`candidate`；`end-of-candidates` 两者都不包含。

## 3. Session 所有权

Hash 请求的 `webrtc-sdp` locator 不携带 `session_id`。每个准备发送 offer 的资源提供者
必须生成自己的随机 `session_id`。

会话唯一键：

```text
(request_message_id, offerer_public_key, session_id)
```

其中 `offerer_public_key` 取 offer 加密信封的 `from_public_key`。多个提供者可以针对同一
Hash 请求创建互不影响的 RTCPeerConnection。

## 4. 接收规则

私密收件箱完成解密和唯一签名验证后，WebRTC 处理器检查：

- `protocol` 严格等于 `bsv8.webrtc.signal.v1`；
- 私密消息有效期不超过 2 分钟；
- `request_message_id` 对应接收者尚未过期的 Hash 请求；
- 该 Hash 请求包含 `webrtc-sdp` locator；
- `session_id` 尚未被同一 offerer 使用。

SDK 提供 `channels.ReviewOfferForHashRequest` / `inbox.reviewOfferForHashRequest` 统一执行
前四项关联审查并返回 `(request_message_id, offerer_public_key, session_id)` 的 `SessionKey`；
`session_id` 是否已使用仍由调用方保存状态并判断。

Answer 或 ICE 必须匹配本地已有会话三元组，不能仅凭 `session_id` 查找。ICE 早于对应
offer/answer 到达时，可以短暂缓存；会话过期后必须删除缓存和 SDP/ICE 明文。

相同 `(from_public_key, message_id)` 的有效信令副本不重复交给 RTCPeerConnection；编号
相同但已签名内容不同时，按编号冲突拒绝。

## 5. 回应和生命周期

WebRTC 使用自身 offer/answer 交互，不使用应用消息 ACK：

```text
offer  → 期望 answer
answer → 完成 SDP 回应
ICE    → 按 RTCPeerConnection 状态处理
```

- 每条信令使用新的私密消息 `message_id`；
- 每次加密使用新的 `kdf_salt` 和 `nonce`；
- `session_id` 不能跨连接复用；
- 失败重试由 offerer 创建新的 `session_id`；
- 连接建立、失败或过期后停止该会话信令；
- WebRTC Direct 不经过本子协议。

## 6. 交互流程

当资源提供者 B 选择请求者 A 的 `webrtc-sdp` locator：

1. B 生成新的 `session_id = S`；
2. B 构造 WebRTC body，并包装成一条私密消息；
3. B 使用自己的长期私钥签名，并通过长期密钥 ECDH 加密给 A；
4. B 发布到 `bsv8.inbox.<A_public_key_hex>`；
5. A 解密和验签后生成 answer；
6. A 使用自己的长期私钥签名并加密给 B；
7. 双方以相同方式交换 ICE。

```text
A                         私密收件箱                          B
│                                                            │
│<── WebRTC body：offer(request_message_id, session_id=S) ───│
│─── WebRTC body：answer(request_message_id, session_id=S) ─>│
│<──── WebRTC body：ICE / end-of-candidates ────────────────>│
│                                                            │
│<──────── WebRTC 连接建立；信令子协议职责结束 ─────────────│
```

连接建立后，身份认证、Stream 和文件交付由其他项目定义。libp2p 身份不要求等于 SSP/
三方消息身份。
