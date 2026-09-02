# Ping/Pong 子协议 V1

协议：

```text
bsv8.ping.v1
```

Ping/Pong 是独立的私密 CP 子协议，复用 PrivateMessage 的 message_id、时间和签名，以及
Inbox 信封唯一的发送者公钥。

## 1. Body

Ping：

```json
{"type":"ping"}
```

Pong：

```json
{"type":"pong","ping_message_id":"ping-message-id"}
```

Pong 自己是另一条 PrivateMessage，拥有自己的 message_id；`ping_message_id` 只引用原
Ping 的 CP message_id。两种 body 都拒绝未知字段，不增加 payload、时间、公钥、签名、
session_id 或第二个 nonce。

## 2. 关联

关联检查只接受两条已经解密和验签的 Inbox 消息：

1. protocol 都是 `bsv8.ping.v1`；
2. 原消息是 ping，响应是 pong；
3. Pong 发送者等于 Ping 的 inbox 接收者；
4. Pong inbox 接收者等于 Ping 发送者；
5. `pong.ping_message_id == ping.message_id`。

不能使用 SSP request_id、libp2p 公钥或调用方手填身份完成该关联。

## 3. 生命周期

- Ping/Pong PrivateMessage 有效期最多 60 秒；
- RTT 使用本地单调时钟，不使用远端 issued_at_ms；
- 重试保持同一已签名 PrivateMessage，可重新加密；
- 接收者按 CP 作者 + message_id 去重；
- 是否响应、速率限制和未完成探测集合属于应用层；
- Pong 不等于 Deliver ACK，也不证明持久化、业务健康或后续网络可用。
