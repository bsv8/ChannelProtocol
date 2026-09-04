# SSP 三方频道约定

CP 运行在 SSP V1 `Publish.content_json` 中，但属于独立内容域。libp2p + SSP 负责连接身份、
计费、ActionResult 和传输；CP 自己负责作者公钥、message_id、时间、签名、加密和业务关联。
两层身份可以不同。

本目录的目标设计和施工记录：

- [SSP + CP 协议族消融设计](./SSP-CP协议族消融设计.md)
- [SSP + CP 协议族消融施工单](../施工单/20260902/004-SSP-CP协议族消融施工单.md)

## V1 文档

```text
docs/v1/
├── README.md
├── 01-Hash请求频道.md
├── 02-私密收件箱.md
├── 03-WebRTC-SDP子协议.md
├── 04-应用消息子协议.md
├── 05-Ping-Pong子协议.md
├── 06-通用公开消息.md
├── PrivateMessage-消融规划.md
└── 协议族-消融实验.md
```

协议标识和字段版本保持 V1；待发布项目包/API 版本为 `0.3.0`。CP 不实现 HTTP、WebSocket、
libp2p、SSP、WebRTC Peer、付款账本或持久化去重表。
