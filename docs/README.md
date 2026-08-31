# SSP 三方频道约定

这里记录运行在 SSP V1 `Publish` 之上的第三方频道约定。

SSP Core 仍然只负责：

- `Publish`、`Subscribe` 和 `Unsubscribe`；
- deterministic CBOR Wire；
- `content_json` 的 JSON 合法性检查和原始字节传递；
- 频道订阅和广播分发。

本目录只约定 `content_json` 中的 JSON 消息含义，不修改 SSP V1 Wire，也不实现
HTTP、WebSocket、WebRTC 或 libp2p 连接。

## 文档目录

```text
docs/
├── README.md                    # 目录说明和轻量治理规则
└── v1/
    ├── README.md                # V1 总览、公共字段和频道列表
    ├── 01-Hash请求频道.md         # bsv8.hash.request.v1
    ├── 02-私密收件箱.md           # 长期密钥 ECDH 加密信封与私密消息公共壳
    ├── 03-WebRTC-SDP子协议.md     # bsv8.webrtc.signal.v1
    └── 04-应用消息子协议.md       # bsv8.message.v1 和接收 ACK
```

已归档的临时讨论稿保留在：

```text
docs/三方频道规划-临时.md
```

## 轻量治理

1. 讨论和约定修改直接落到对应的版本目录。
2. 临时稿只记录尚未决定且影响多个文档的问题，不再复制消息结构。
3. 代码和测试以 `v1/` 文档为准。
4. Hash 请求的破坏性修改使用新频道；私密信封和子协议分别使用自己的版本字段。
5. 不使用额外的编号分配、委员会审批或复杂状态流转。

## 当前状态

`v1` 已实现 Go 与 TypeScript SDK，并通过共享 fixture 和跨语言验收。同一版本中
不应改变已发布字段语义；破坏性变更必须使用新版本标识。文件传输协议不属于本约定。
