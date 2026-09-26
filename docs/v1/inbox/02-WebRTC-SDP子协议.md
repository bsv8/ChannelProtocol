# WebRTC SDP 子协议 V1

协议：

```text
bsv8.webrtc.signal.v1
```

本协议只定义 PrivateMessage 的 `body`；message_id、时间和签名由 CP PrivateMessage 提供，
作者公钥由 Inbox 信封提供。

## 1. Body

```json
{
  "request_message_id": "hash-request-message-id",
  "session_id": "base64url-32-byte",
  "signal": {"type":"offer","sdp":"v=0..."}
}
```

- offer 的 `request_message_id` 引用 Hash CP 消息的 message_id；
- answer/ICE 继续使用相同请求编号和 session_id；
- body 不携带公钥、自己的 message_id、时间或签名。

## 2. Signal

| type | 字段 |
|---|---|
| `offer` | `sdp` |
| `answer` | `sdp` |
| `ice-candidate` | `candidate` |
| `end-of-candidates` | 无额外字段 |

不同分支不得混用字段。WebRTC 消息有效期最多 2 分钟。

## 3. 关联

会话键：

```text
(request_message_id, offerer_public_key, session_id)
```

`offerer_public_key` 取已验证 offer 的 Inbox 信封公钥。关联审查只接受已验证 Hash 消息
和已解密验签的 offer，不接受调用方手填作者或 Context。

## 4. 身份与 SSP

libp2p/SSP 付款身份不进入 WebRTC body 或 CP 签名。A 可以替 B 提交 offer；接收者仍使用
Inbox 信封中的 B 公钥完成 ECDH 和验签，Supplier 按 A 扣费。

每条信令拥有自己的 CP PrivateMessage message_id。重试、ICE 缓存、RTCPeerConnection
状态和 session_id 生命周期由应用层处理。
